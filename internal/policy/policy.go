// Package policy turns Gate's bindings into Kubernetes RBAC, and keeps it so.
//
// Each binding becomes a ClusterRoleBinding (cluster scope) or one
// RoleBinding per namespace, labelled kuberoam.dev/managed-by=roam-gate. A
// reconcile creates what is missing, repairs what was edited by hand, and
// deletes Gate objects no binding asks for. Objects without the label are
// never touched.
package policy

import (
	"context"
	"log/slog"
	"maps"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/validate/content"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"

	"github.com/kuberoam/roam-gate/internal/identity"
	"github.com/kuberoam/roam-gate/internal/kube"
	"github.com/kuberoam/roam-gate/internal/msg"
	"github.com/kuberoam/roam-gate/internal/store"
)

// ObjectPrefix starts the name of every RBAC object Gate creates.
const ObjectPrefix = "roam-gate-"

// Status is the last reconcile's outcome for one binding.
type Status struct {
	OK      bool      `json:"ok"`
	Message string    `json:"message,omitempty"` // the problems, in English; see Localized
	Objects []string  `json:"objects,omitempty"` // what exists for it in the cluster
	Checked time.Time `json:"checked"`
	errs    []error
}

// Localized is the status with its message in lang.
func (s Status) Localized(lang string) Status {
	parts := make([]string, len(s.errs))
	for i, e := range s.errs {
		parts[i] = msg.Localize(lang, e)
	}
	s.Message = strings.Join(parts, "; ")
	return s
}

type Reconciler struct {
	kc       *kube.Client
	st       *store.Store
	interval time.Duration
	kick     chan struct{}

	mu      sync.Mutex
	status  map[string]Status
	last    time.Time
	lastErr string
}

func New(kc *kube.Client, st *store.Store, interval time.Duration) *Reconciler {
	return &Reconciler{kc: kc, st: st, interval: interval, kick: make(chan struct{}, 1), status: map[string]Status{}}
}

// Trigger asks for a reconcile soon (after a binding changed).
func (r *Reconciler) Trigger() {
	select {
	case r.kick <- struct{}{}:
	default:
	}
}

// Run reconciles on a timer and on Trigger until ctx ends.
func (r *Reconciler) Run(ctx context.Context) {
	t := time.NewTicker(r.interval)
	defer t.Stop()
	for {
		if err := r.Reconcile(ctx); err != nil && ctx.Err() == nil {
			slog.Error("reconcile failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-r.kick:
		}
	}
}

// Statuses returns each binding's last reconcile outcome.
func (r *Reconciler) Statuses() (map[string]Status, time.Time, string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return maps.Clone(r.status), r.last, r.lastErr
}

// Subject is the RBAC subject a binding grants to.
func Subject(b *store.Binding) (rbacv1.Subject, error) {
	s := rbacv1.Subject{APIGroup: rbacv1.GroupName}
	if strings.TrimSpace(b.Subject) == "" {
		return s, msg.New(msg.SubjectRequired)
	}
	switch b.SubjectKind {
	case store.SubjectUser:
		s.Kind, s.Name = rbacv1.UserKind, identity.KubeUser(b.Subject)
	case store.SubjectGroup:
		s.Kind, s.Name = rbacv1.GroupKind, identity.KubeGroup(b.Subject)
	case store.SubjectAWS:
		s.Kind, s.Name = rbacv1.GroupKind, AWSGroup(b.ID)
	case store.SubjectK8sUser:
		s.Kind, s.Name = rbacv1.UserKind, b.Subject
	case store.SubjectK8sGroup:
		s.Kind, s.Name = rbacv1.GroupKind, b.Subject
	default:
		return s, msg.New(msg.SubjectKindUnknown, "kind", b.SubjectKind)
	}
	return s, nil
}

// Validate checks a binding before it is saved.
func Validate(b *store.Binding) error {
	if _, err := Subject(b); err != nil {
		return err
	}
	if err := checkSubject(b); err != nil {
		return err
	}
	b.Role = strings.TrimSpace(b.Role)
	if b.Role == "" {
		return msg.New(msg.RoleRequired)
	}
	if len(content.IsPathSegmentName(b.Role)) > 0 {
		return msg.New(msg.RoleInvalid, "role", b.Role)
	}
	switch b.Scope {
	case store.ScopeCluster:
		b.Namespaces = nil
	case store.ScopeNamespaces:
		b.Namespaces = slices.Compact(slices.Sorted(slices.Values(b.Namespaces)))
		if len(b.Namespaces) == 0 {
			return msg.New(msg.NamespacesRequired)
		}
		for _, ns := range b.Namespaces {
			if len(validation.IsDNS1123Label(ns)) > 0 {
				return msg.New(msg.NamespaceInvalid, "namespace", ns)
			}
		}
	default:
		return msg.New(msg.ScopeInvalid)
	}
	if b.SubjectKind == store.SubjectAWS {
		if _, _, err := parseARN(b.Subject); err != nil {
			return err
		}
	}
	return nil
}

// reservedSubjects are Kubernetes users and groups that stand for far more
// than a person or team: granting them a role through Gate would open the
// cluster to everyone they cover.
var reservedSubjects = map[string]string{
	"system:unauthenticated": "anyone, without signing in",
	"system:anonymous":       "anyone, without signing in",
	"system:authenticated":   "every user and service account of the cluster",
	"system:serviceaccounts": "every service account of the cluster",
	"system:masters":         "the cluster's built-in administrators",
}

func checkSubject(b *store.Binding) error {
	if b.SubjectKind != store.SubjectK8sUser && b.SubjectKind != store.SubjectK8sGroup {
		return nil
	}
	if who, ok := reservedSubjects[b.Subject]; ok {
		return msg.New(msg.SubjectReserved, "subject", b.Subject, "who", who)
	}
	if strings.HasPrefix(b.Subject, identity.KubePrefix) {
		return msg.New(msg.SubjectUseGateKind, "subject", b.Subject)
	}
	return nil
}

func meta(b *store.Binding, name, ns string) metav1.ObjectMeta {
	annos := map[string]string{kube.AnnoSubject: b.SubjectKind + ":" + b.Subject}
	if b.Note != "" {
		annos[kube.AnnoNote] = b.Note
	}
	return metav1.ObjectMeta{
		Name: name, Namespace: ns, Annotations: annos,
		Labels: map[string]string{kube.LabelManagedBy: kube.ManagedBy, kube.LabelBinding: b.ID, "app.kubernetes.io/part-of": "roam"},
	}
}

func sameMeta(a, b metav1.ObjectMeta) bool {
	for k, v := range b.Labels {
		if a.Labels[k] != v {
			return false
		}
	}
	for k, v := range b.Annotations {
		if a.Annotations[k] != v {
			return false
		}
	}
	return true
}

// Reconcile makes the cluster's Gate RBAC match the stored bindings.
func (r *Reconciler) Reconcile(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	bindings, err := r.st.Bindings(ctx)
	if err != nil {
		return err
	}
	status := map[string]Status{}
	now := time.Now()
	note := func(id, obj string, err error) {
		s := status[id]
		s.Checked = now
		if err != nil {
			s.errs = append(s.errs, err)
		} else if obj != "" {
			s.Objects = append(s.Objects, obj)
		}
		status[id] = s
	}

	wantCRB := map[string]*rbacv1.ClusterRoleBinding{}
	wantRB := map[string]*rbacv1.RoleBinding{} // "ns/name"
	owner := map[string]string{}               // object key → binding ID
	for _, b := range bindings {
		subj, err := Subject(b)
		if err != nil {
			note(b.ID, "", err)
			continue
		}
		ref := rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: b.Role}
		name := ObjectPrefix + b.ID
		if b.Scope == store.ScopeCluster {
			wantCRB[name] = &rbacv1.ClusterRoleBinding{ObjectMeta: meta(b, name, ""), RoleRef: ref, Subjects: []rbacv1.Subject{subj}}
			owner["crb/"+name] = b.ID
			continue
		}
		for _, ns := range b.Namespaces {
			key := ns + "/" + name
			wantRB[key] = &rbacv1.RoleBinding{ObjectMeta: meta(b, name, ns), RoleRef: ref, Subjects: []rbacv1.Subject{subj}}
			owner["rb/"+key] = b.ID
		}
	}

	sel := metav1.ListOptions{LabelSelector: kube.ManagedSelector()}
	crbs, err := r.kc.RBAC.ClusterRoleBindings().List(ctx, sel)
	if err != nil {
		return r.fail(msg.Wrap(msg.RBACListFailed, err, "what", "ClusterRoleBindings"))
	}
	crbAPI := r.kc.RBAC.ClusterRoleBindings()
	syncObjects(ctx, "ClusterRoleBinding", "crb/", crbs.Items, wantCRB, owner, note, rbacOps[rbacv1.ClusterRoleBinding]{
		key:      func(o *rbacv1.ClusterRoleBinding) string { return o.Name },
		meta:     func(o *rbacv1.ClusterRoleBinding) *metav1.ObjectMeta { return &o.ObjectMeta },
		roleRef:  func(o *rbacv1.ClusterRoleBinding) rbacv1.RoleRef { return o.RoleRef },
		subjects: func(o *rbacv1.ClusterRoleBinding) *[]rbacv1.Subject { return &o.Subjects },
		create: func(ctx context.Context, o *rbacv1.ClusterRoleBinding) error {
			_, err := crbAPI.Create(ctx, o, metav1.CreateOptions{})
			return err
		},
		update: func(ctx context.Context, o *rbacv1.ClusterRoleBinding) error {
			_, err := crbAPI.Update(ctx, o, metav1.UpdateOptions{})
			return err
		},
		delete: func(ctx context.Context, o *rbacv1.ClusterRoleBinding) error {
			return crbAPI.Delete(ctx, o.Name, metav1.DeleteOptions{})
		},
	})

	rbs, err := r.kc.RBAC.RoleBindings("").List(ctx, sel)
	if err != nil {
		return r.fail(msg.Wrap(msg.RBACListFailed, err, "what", "RoleBindings"))
	}
	syncObjects(ctx, "RoleBinding", "rb/", rbs.Items, wantRB, owner, note, rbacOps[rbacv1.RoleBinding]{
		key:      func(o *rbacv1.RoleBinding) string { return o.Namespace + "/" + o.Name },
		meta:     func(o *rbacv1.RoleBinding) *metav1.ObjectMeta { return &o.ObjectMeta },
		roleRef:  func(o *rbacv1.RoleBinding) rbacv1.RoleRef { return o.RoleRef },
		subjects: func(o *rbacv1.RoleBinding) *[]rbacv1.Subject { return &o.Subjects },
		create: func(ctx context.Context, o *rbacv1.RoleBinding) error {
			_, err := r.kc.RBAC.RoleBindings(o.Namespace).Create(ctx, o, metav1.CreateOptions{})
			if apierrors.IsNotFound(err) {
				return msg.New(msg.NamespaceMissing, "namespace", o.Namespace)
			}
			return err
		},
		update: func(ctx context.Context, o *rbacv1.RoleBinding) error {
			_, err := r.kc.RBAC.RoleBindings(o.Namespace).Update(ctx, o, metav1.UpdateOptions{})
			return err
		},
		delete: func(ctx context.Context, o *rbacv1.RoleBinding) error {
			return r.kc.RBAC.RoleBindings(o.Namespace).Delete(ctx, o.Name, metav1.DeleteOptions{})
		},
	})

	if err := r.reconcileAWSAuth(ctx, bindings, note); err != nil {
		slog.Warn("aws-auth", "err", err)
	}

	for _, b := range bindings {
		s := status[b.ID]
		s.Checked = now
		s.OK = len(s.errs) == 0
		sort.Strings(s.Objects)
		status[b.ID] = s.Localized(msg.DefaultLang)
	}
	r.mu.Lock()
	r.status, r.last, r.lastErr = status, now, ""
	r.mu.Unlock()
	return nil
}

// rbacOps adapts ClusterRoleBindings and RoleBindings to one sync routine.
type rbacOps[T any] struct {
	key                    func(*T) string
	meta                   func(*T) *metav1.ObjectMeta
	roleRef                func(*T) rbacv1.RoleRef
	subjects               func(*T) *[]rbacv1.Subject
	create, update, delete func(context.Context, *T) error
}

// syncObjects makes the existing Gate objects of one kind match want: stale
// ones are deleted, edited ones repaired (a changed roleRef is immutable, so
// recreated), missing ones created. want is consumed.
func syncObjects[T any](ctx context.Context, kind, ownerPrefix string, have []T, want map[string]*T, owner map[string]string,
	note func(id, obj string, err error), ops rbacOps[T]) {
	for i := range have {
		obj := &have[i]
		key := ops.key(obj)
		w, ok := want[key]
		if !ok {
			if err := ops.delete(ctx, obj); err != nil && !apierrors.IsNotFound(err) {
				slog.Warn("deleting stale "+kind, "key", key, "err", err)
			}
			continue
		}
		delete(want, key)
		var err error
		switch {
		case ops.roleRef(obj) != ops.roleRef(w):
			if err = ops.delete(ctx, obj); err == nil {
				err = ops.create(ctx, w)
			}
		case !slices.Equal(*ops.subjects(obj), *ops.subjects(w)) || !sameMeta(*ops.meta(obj), *ops.meta(w)):
			m, wm := ops.meta(obj), ops.meta(w)
			*ops.subjects(obj), m.Labels, m.Annotations = *ops.subjects(w), wm.Labels, wm.Annotations
			err = ops.update(ctx, obj)
		}
		note(owner[ownerPrefix+key], kind+"/"+key, err)
	}
	for _, key := range slices.Sorted(maps.Keys(want)) {
		note(owner[ownerPrefix+key], kind+"/"+key, ops.create(ctx, want[key]))
	}
}

func (r *Reconciler) fail(err error) error {
	r.mu.Lock()
	r.last, r.lastErr = time.Now(), err.Error()
	r.mu.Unlock()
	return err
}

// ManagedObjects lists every RBAC object Gate owns (for uninstall checks and the UI).
func (r *Reconciler) ManagedObjects(ctx context.Context) ([]string, error) {
	sel := metav1.ListOptions{LabelSelector: kube.ManagedSelector()}
	var out []string
	crbs, err := r.kc.RBAC.ClusterRoleBindings().List(ctx, sel)
	if err != nil {
		return nil, err
	}
	for _, x := range crbs.Items {
		out = append(out, "ClusterRoleBinding/"+x.Name)
	}
	rbs, err := r.kc.RBAC.RoleBindings("").List(ctx, sel)
	if err != nil {
		return nil, err
	}
	for _, x := range rbs.Items {
		out = append(out, "RoleBinding/"+x.Namespace+"/"+x.Name)
	}
	return out, nil
}
