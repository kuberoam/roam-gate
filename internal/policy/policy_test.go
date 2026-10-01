package policy

import (
	"context"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	"sigs.k8s.io/yaml"

	"github.com/kuberoam/roam-gate/internal/kube"
	"github.com/kuberoam/roam-gate/internal/store"
)

func setup(t *testing.T, objs ...any) (*Reconciler, *store.Store, *fake.Clientset) {
	t.Helper()
	st, err := store.Open(t.TempDir(), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	cs := fake.NewSimpleClientset()
	for _, o := range objs {
		switch x := o.(type) {
		case *corev1.ConfigMap:
			cs.CoreV1().ConfigMaps(x.Namespace).Create(context.Background(), x, metav1.CreateOptions{})
		case *corev1.Namespace:
			cs.CoreV1().Namespaces().Create(context.Background(), x, metav1.CreateOptions{})
		case *rbacv1.RoleBinding:
			cs.RbacV1().RoleBindings(x.Namespace).Create(context.Background(), x, metav1.CreateOptions{})
		case *rbacv1.ClusterRoleBinding:
			cs.RbacV1().ClusterRoleBindings().Create(context.Background(), x, metav1.CreateOptions{})
		}
	}
	kc := &kube.Client{RBAC: cs.RbacV1(), Core: cs.CoreV1()}
	return New(kc, st, time.Minute), st, cs
}

func TestReconcileCreatesRepairsAndCleansUp(t *testing.T) {
	foreign := &rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "someone-elses", Namespace: "prod"},
		RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "view"}}
	// Gate's own install binding carries Gate's label but no binding ID.
	install := &rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "roam-gate", Labels: map[string]string{kube.LabelManagedBy: kube.ManagedBy}},
		RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "roam-gate"}}
	r, st, cs := setup(t, foreign, install)
	ctx := context.Background()
	st.SaveBinding(ctx, &store.Binding{ID: "b1", SubjectKind: store.SubjectGroup, Subject: "github:acme/platform", Role: "admin", Scope: store.ScopeCluster})
	st.SaveBinding(ctx, &store.Binding{ID: "b2", SubjectKind: store.SubjectUser, Subject: "alice@corp.com", Role: "edit", Scope: store.ScopeNamespaces, Namespaces: []string{"prod", "staging"}})
	if err := r.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	crb, err := cs.RbacV1().ClusterRoleBindings().Get(ctx, "roam-gate-b1", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if crb.Subjects[0].Name != "roam:github:acme/platform" || crb.Subjects[0].Kind != "Group" || crb.RoleRef.Name != "admin" {
		t.Fatalf("crb: %+v", crb)
	}
	if crb.Labels[kube.LabelManagedBy] != kube.ManagedBy || crb.Labels[kube.LabelBinding] != "b1" {
		t.Fatalf("labels: %v", crb.Labels)
	}
	for _, ns := range []string{"prod", "staging"} {
		rb, err := cs.RbacV1().RoleBindings(ns).Get(ctx, "roam-gate-b2", metav1.GetOptions{})
		if err != nil || rb.Subjects[0].Name != "roam:alice@corp.com" || rb.Subjects[0].Kind != "User" {
			t.Fatalf("rb %s: %v %+v", ns, err, rb)
		}
	}
	statuses, _, _ := r.Statuses()
	if !statuses["b1"].OK || !statuses["b2"].OK || len(statuses["b2"].Objects) != 2 {
		t.Fatalf("statuses: %+v", statuses)
	}

	// Someone edits Gate's binding by hand: the next reconcile puts it back.
	crb.Subjects[0].Name = "system:anonymous"
	cs.RbacV1().ClusterRoleBindings().Update(ctx, crb, metav1.UpdateOptions{})
	// Changing the role (immutable roleRef) means delete + create.
	st.SaveBinding(ctx, &store.Binding{ID: "b2", SubjectKind: store.SubjectUser, Subject: "alice@corp.com", Role: "view", Scope: store.ScopeNamespaces, Namespaces: []string{"prod"}})
	if err := r.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	crb, _ = cs.RbacV1().ClusterRoleBindings().Get(ctx, "roam-gate-b1", metav1.GetOptions{})
	if crb.Subjects[0].Name != "roam:github:acme/platform" {
		t.Fatalf("drift not repaired: %+v", crb.Subjects)
	}
	rb, _ := cs.RbacV1().RoleBindings("prod").Get(ctx, "roam-gate-b2", metav1.GetOptions{})
	if rb.RoleRef.Name != "view" {
		t.Fatalf("role not changed: %+v", rb.RoleRef)
	}
	if _, err := cs.RbacV1().RoleBindings("staging").Get(ctx, "roam-gate-b2", metav1.GetOptions{}); err == nil {
		t.Fatal("RoleBinding for a removed namespace should be gone")
	}

	// Deleting bindings removes Gate's objects, never anyone else's.
	st.DeleteBinding(ctx, "b1")
	st.DeleteBinding(ctx, "b2")
	if err := r.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	objs, _ := r.ManagedObjects(ctx)
	if len(objs) != 0 {
		t.Fatalf("left behind: %v", objs)
	}
	if _, err := cs.RbacV1().RoleBindings("prod").Get(ctx, "someone-elses", metav1.GetOptions{}); err != nil {
		t.Fatal("a RoleBinding Gate doesn't own was touched")
	}
	if _, err := cs.RbacV1().ClusterRoleBindings().Get(ctx, "roam-gate", metav1.GetOptions{}); err != nil {
		t.Fatal("Gate removed its own install binding")
	}
}

func TestAWSAuthKeepsOtherEntries(t *testing.T) {
	nodes := `- rolearn: arn:aws:iam::111122223333:role/eks-nodes
  username: system:node:{{EC2PrivateDNSName}}
  groups:
  - system:bootstrappers
  - system:nodes
`
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "aws-auth", Namespace: "kube-system"}, Data: map[string]string{"mapRoles": nodes}}
	r, st, cs := setup(t, cm)
	ctx := context.Background()
	st.SaveBinding(ctx, &store.Binding{ID: "aw1", SubjectKind: store.SubjectAWS, Subject: "arn:aws:iam::111122223333:role/team/Developers", Role: "edit", Scope: store.ScopeCluster})
	if err := r.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	got, _ := cs.CoreV1().ConfigMaps("kube-system").Get(ctx, "aws-auth", metav1.GetOptions{})
	var roles []mapEntry
	if err := yaml.Unmarshal([]byte(got.Data["mapRoles"]), &roles); err != nil {
		t.Fatal(err)
	}
	if len(roles) != 2 || roles[0].Username != "system:node:{{EC2PrivateDNSName}}" {
		t.Fatalf("node mapping changed: %+v", roles)
	}
	// The role path is dropped: aws-auth matches roles without it.
	if roles[1].RoleARN != "arn:aws:iam::111122223333:role/Developers" || roles[1].Groups[0] != "roam:aws:aw1" {
		t.Fatalf("gate mapping: %+v", roles[1])
	}
	crb, err := cs.RbacV1().ClusterRoleBindings().Get(ctx, "roam-gate-aw1", metav1.GetOptions{})
	if err != nil || crb.Subjects[0].Name != "roam:aws:aw1" {
		t.Fatalf("crb: %v %+v", err, crb)
	}

	st.DeleteBinding(ctx, "aw1")
	if err := r.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	got, _ = cs.CoreV1().ConfigMaps("kube-system").Get(ctx, "aws-auth", metav1.GetOptions{})
	if strings.Contains(got.Data["mapRoles"], "roam:") || !strings.Contains(got.Data["mapRoles"], "eks-nodes") {
		t.Fatalf("after delete: %s", got.Data["mapRoles"])
	}
}

func TestValidate(t *testing.T) {
	bad := []store.Binding{
		{SubjectKind: "robot", Subject: "x", Role: "view", Scope: store.ScopeCluster},
		{SubjectKind: store.SubjectUser, Subject: "", Role: "view", Scope: store.ScopeCluster},
		{SubjectKind: store.SubjectUser, Subject: "a", Role: "", Scope: store.ScopeCluster},
		{SubjectKind: store.SubjectUser, Subject: "a", Role: "view", Scope: store.ScopeNamespaces},
		{SubjectKind: store.SubjectAWS, Subject: "arn:aws:sts::111122223333:assumed-role/x/y", Role: "view", Scope: store.ScopeCluster},
		{SubjectKind: store.SubjectK8sGroup, Subject: "system:authenticated", Role: "view", Scope: store.ScopeCluster},   // everyone
		{SubjectKind: store.SubjectK8sGroup, Subject: "system:unauthenticated", Role: "view", Scope: store.ScopeCluster}, // even anonymous
		{SubjectKind: store.SubjectK8sUser, Subject: "roam:alice@corp.com", Role: "view", Scope: store.ScopeCluster},     // use kind user
		{SubjectKind: store.SubjectUser, Subject: "a", Role: "view", Scope: store.ScopeNamespaces, Namespaces: []string{"Prod_1"}},
		{SubjectKind: store.SubjectUser, Subject: "a", Role: "../admin", Scope: store.ScopeCluster},
	}
	for _, b := range bad {
		if err := Validate(&b); err == nil {
			t.Errorf("accepted %+v", b)
		}
	}
	ok := store.Binding{SubjectKind: store.SubjectK8sGroup, Subject: "devs@corp.com", Role: "view", Scope: store.ScopeCluster, Namespaces: []string{"x"}}
	if err := Validate(&ok); err != nil || ok.Namespaces != nil {
		t.Fatalf("%v %v", err, ok.Namespaces)
	}
	dup := store.Binding{SubjectKind: store.SubjectUser, Subject: "a", Role: " system:aggregate-to-view ", Scope: store.ScopeNamespaces, Namespaces: []string{"b", "a", "b"}}
	if err := Validate(&dup); err != nil || len(dup.Namespaces) != 2 || dup.Role != "system:aggregate-to-view" {
		t.Fatalf("normalised: %v %+v", err, dup)
	}
}
