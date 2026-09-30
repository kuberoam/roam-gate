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
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/kuberoam/roam-gate/internal/identity"
	"github.com/kuberoam/roam-gate/internal/kube"
	"github.com/kuberoam/roam-gate/internal/store"
)

// ObjectPrefix starts the name of every RBAC object Gate creates.
const ObjectPrefix = "roam-gate-"

// Status is the last reconcile's outcome for one binding.
type Status struct {
	OK      bool      `json:"ok"`
	Message string    `json:"message,omitempty"`
	Objects []string  `json:"objects,omitempty"` // what exists for it in the cluster
	Checked time.Time `json:"checked"`
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
		return s, errors.New("subject is required")
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
		return s, fmt.Errorf("unknown subject kind %q", b.SubjectKind)
	}
	return s, nil
}

// Validate checks a binding before it is saved.
func Validate(b *store.Binding) error {
	if _, err := Subject(b); err != nil {
		return err
	}
	if strings.TrimSpace(b.Role) == "" {
		return errors.New("role is required")
	}
	switch b.Scope {
	case store.ScopeCluster:
		b.Namespaces = nil
	case store.ScopeNamespaces:
		if len(b.Namespaces) == 0 {
			return errors.New("pick at least one namespace, or use cluster scope")
		}
	default:
		return fmt.Errorf("scope must be %q or %q", store.ScopeCluster, store.ScopeNamespaces)
	}
	if b.SubjectKind == store.SubjectAWS {
		if _, _, err := parseARN(b.Subject); err != nil {
			return err
		}
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
			if s.Message != "" {
				s.Message += "; "
			}
			s.Message += err.Error()
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
		return r.fail(fmt.Errorf("listing ClusterRoleBindings: %w", err))
	}
	for i := range crbs.Items {
		have := &crbs.Items[i]
		want, ok := wantCRB[have.Name]
		if !ok {
			err := r.kc.RBAC.ClusterRoleBindings().Delete(ctx, have.Name, metav1.DeleteOptions{})
			if err != nil && !apierrors.IsNotFound(err) {
				slog.Warn("deleting stale ClusterRoleBinding", "name", have.Name, "err", err)
			}
			continue
		}
		delete(wantCRB, have.Name)
		id := owner["crb/"+have.Name]
		switch {
		case have.RoleRef != want.RoleRef: // immutable: recreate
			err = r.kc.RBAC.ClusterRoleBindings().Delete(ctx, have.Name, metav1.DeleteOptions{})
			if err == nil {
				_, err = r.kc.RBAC.ClusterRoleBindings().Create(ctx, want, metav1.CreateOptions{})
			}
		case !slices.Equal(have.Subjects, want.Subjects) || !sameMeta(have.ObjectMeta, want.ObjectMeta):
			have.Subjects, have.Labels, have.Annotations = want.Subjects, want.Labels, want.Annotations
			_, err = r.kc.RBAC.ClusterRoleBindings().Update(ctx, have, metav1.UpdateOptions{})
		}
		note(id, "ClusterRoleBinding/"+have.Name, err)
	}
	for name, want := range wantCRB {
		_, err := r.kc.RBAC.ClusterRoleBindings().Create(ctx, want, metav1.CreateOptions{})
		note(owner["crb/"+name], "ClusterRoleBinding/"+name, err)
	}

	rbs, err := r.kc.RBAC.RoleBindings("").List(ctx, sel)
	if err != nil {
		return r.fail(fmt.Errorf("listing RoleBindings: %w", err))
	}
	for i := range rbs.Items {
		have := &rbs.Items[i]
		key := have.Namespace + "/" + have.Name
		want, ok := wantRB[key]
		if !ok {
			err := r.kc.RBAC.RoleBindings(have.Namespace).Delete(ctx, have.Name, metav1.DeleteOptions{})
			if err != nil && !apierrors.IsNotFound(err) {
				slog.Warn("deleting stale RoleBinding", "key", key, "err", err)
			}
			continue
		}
		delete(wantRB, key)
		id := owner["rb/"+key]
		switch {
		case have.RoleRef != want.RoleRef:
			err = r.kc.RBAC.RoleBindings(have.Namespace).Delete(ctx, have.Name, metav1.DeleteOptions{})
			if err == nil {
				_, err = r.kc.RBAC.RoleBindings(have.Namespace).Create(ctx, want, metav1.CreateOptions{})
			}
		case !slices.Equal(have.Subjects, want.Subjects) || !sameMeta(have.ObjectMeta, want.ObjectMeta):
			have.Subjects, have.Labels, have.Annotations = want.Subjects, want.Labels, want.Annotations
			_, err = r.kc.RBAC.RoleBindings(have.Namespace).Update(ctx, have, metav1.UpdateOptions{})
		}
		note(id, "RoleBinding/"+key, err)
	}
	keys := slices.Sorted(maps.Keys(wantRB))
	for _, key := range keys {
		want := wantRB[key]
		_, err := r.kc.RBAC.RoleBindings(want.Namespace).Create(ctx, want, metav1.CreateOptions{})
		if apierrors.IsNotFound(err) {
			err = fmt.Errorf("namespace %s does not exist", want.Namespace)
		}
		note(owner["rb/"+key], "RoleBinding/"+key, err)
	}

	if err := r.reconcileAWSAuth(ctx, bindings, note); err != nil {
		slog.Warn("aws-auth", "err", err)
	}

	for _, b := range bindings {
		s := status[b.ID]
		s.Checked = now
		s.OK = s.Message == ""
		sort.Strings(s.Objects)
		status[b.ID] = s
	}
	r.mu.Lock()
	r.status, r.last, r.lastErr = status, now, ""
	r.mu.Unlock()
	return nil
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
