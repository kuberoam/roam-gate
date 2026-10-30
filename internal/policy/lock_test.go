package policy

import (
	"context"
	"maps"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/kuberoam/roam-gate/internal/kube"
	"github.com/kuberoam/roam-gate/internal/store"
)

// A second Gate on the same cluster changes nothing while the first holds
// the lock: before, each deleted the other's objects every reconcile.
func TestSecondGateStandsBy(t *testing.T) {
	ctx := context.Background()
	a, stA, cs := setup(t)
	stB, err := store.Open(t.TempDir(), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stB.Close() })
	b := New(&kube.Client{RBAC: cs.RbacV1(), Core: cs.CoreV1(), WatchListSemantics: cs}, stB, time.Minute, "https://other.test")

	stA.SaveBinding(ctx, &store.Binding{ID: "a1", SubjectKind: store.SubjectUser, Subject: "alice@corp.com", Role: "view", Scope: store.ScopeCluster})
	stB.SaveBinding(ctx, &store.Binding{ID: "b1", SubjectKind: store.SubjectUser, Subject: "bob@corp.com", Role: "edit", Scope: store.ScopeCluster})
	if err := a.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		err := b.Reconcile(ctx)
		if err == nil || !strings.Contains(err.Error(), "Another Roam Gate (https://gate.test)") {
			t.Fatalf("second Gate: %v", err)
		}
		if err := a.Reconcile(ctx); err != nil {
			t.Fatalf("first Gate keeps its lock: %v", err)
		}
	}
	if _, _, lastErr := b.Statuses(); !strings.Contains(lastErr, "already manages") {
		t.Fatalf("status says why: %q", lastErr)
	}
	if _, err := cs.RbacV1().ClusterRoleBindings().Get(ctx, "roam-gate-a1", metav1.GetOptions{}); err != nil {
		t.Fatalf("the first Gate's binding is left alone: %v", err)
	}
	if _, err := cs.RbacV1().ClusterRoleBindings().Get(ctx, "roam-gate-b1", metav1.GetOptions{}); err == nil {
		t.Fatal("the second Gate created nothing")
	}

	// The lock grants nothing and isn't one of Gate's binding objects.
	l, _ := cs.RbacV1().ClusterRoleBindings().Get(ctx, LockName, metav1.GetOptions{})
	if len(l.Subjects) != 0 || l.Labels[kube.LabelBinding] != "" {
		t.Fatalf("lock: %+v", l)
	}
	if objs, _ := a.ManagedObjects(ctx); len(objs) != 1 {
		t.Fatalf("managed objects: %v", objs)
	}

	// The first Gate stops without giving the lock up: once it expires the
	// second takes over, and its bindings rule.
	l.Annotations[annoRenewed] = time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	cs.RbacV1().ClusterRoleBindings().Update(ctx, l, metav1.UpdateOptions{})
	if err := b.Reconcile(ctx); err != nil {
		t.Fatalf("takeover: %v", err)
	}
	if _, err := cs.RbacV1().ClusterRoleBindings().Get(ctx, "roam-gate-b1", metav1.GetOptions{}); err != nil {
		t.Fatalf("after takeover: %v", err)
	}
	if err := a.Reconcile(ctx); err == nil || !strings.Contains(err.Error(), "https://other.test") {
		t.Fatalf("the first Gate now stands by: %v", err)
	}

	// Shutting down gives the lock up; a Gate that doesn't hold it leaves it.
	a.release(ctx)
	if _, err := cs.RbacV1().ClusterRoleBindings().Get(ctx, LockName, metav1.GetOptions{}); err != nil {
		t.Fatalf("released by a Gate that doesn't hold it: %v", err)
	}
	b.release(ctx)
	if _, err := cs.RbacV1().ClusterRoleBindings().Get(ctx, LockName, metav1.GetOptions{}); err == nil {
		t.Fatal("not released")
	}
	if err := a.Reconcile(ctx); err != nil {
		t.Fatalf("free again: %v", err)
	}
}

func TestInstanceIDIsStable(t *testing.T) {
	_, st, _ := setup(t)
	ctx := context.Background()
	id1, err := st.InstanceID(ctx)
	id2, _ := st.InstanceID(ctx)
	if err != nil || len(id1) != 16 || id1 != id2 {
		t.Fatalf("%q %q %v", id1, id2, err)
	}
}

// Even if two Gates acted at once (the lock is the guard; this is the second
// line), a Gate deletes only objects it made itself, and adopts objects from
// before instance IDs only when they belong to its own bindings.
func TestGateTouchesOnlyItsOwnObjects(t *testing.T) {
	ctx := context.Background()
	crb := func(name string, labels map[string]string) *rbacv1.ClusterRoleBinding {
		l := map[string]string{kube.LabelManagedBy: kube.ManagedBy, kube.LabelBinding: strings.TrimPrefix(name, ObjectPrefix)}
		maps.Copy(l, labels)
		return &rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: l},
			RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "view"}}
	}
	roles := `- rolearn: arn:aws:iam::123456789012:role/other
  username: roam:aws:x1:{{SessionName}}
  groups: [roam:aws:x1, "kuberoam.dev/gate-instance:other"]
- rolearn: arn:aws:iam::123456789012:role/old
  username: roam:aws:a1:{{SessionName}}
  groups: [roam:aws:a1]
- rolearn: arn:aws:iam::123456789012:role/gone
  username: roam:aws:gone:{{SessionName}}
  groups: [roam:aws:gone]
`
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "aws-auth", Namespace: "kube-system"}, Data: map[string]string{"mapRoles": roles}}
	r, st, cs := setup(t,
		crb("roam-gate-other", map[string]string{kube.LabelInstance: "other"}), // another Gate's
		crb("roam-gate-b1", nil),     // before instance IDs, one of ours: adopted
		crb("roam-gate-legacy", nil), // before instance IDs, not ours: left alone
		cm)
	id, _ := st.InstanceID(ctx)
	cs.RbacV1().ClusterRoleBindings().Create(ctx, crb("roam-gate-stale", map[string]string{kube.LabelInstance: id}), metav1.CreateOptions{})
	st.SaveBinding(ctx, &store.Binding{ID: "b1", SubjectKind: store.SubjectUser, Subject: "alice@corp.com", Role: "view", Scope: store.ScopeCluster})
	st.SaveBinding(ctx, &store.Binding{ID: "a1", SubjectKind: store.SubjectAWS, Subject: "arn:aws:iam::123456789012:role/old", Role: "view", Scope: store.ScopeCluster})
	if err := r.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	get := func(name string) *rbacv1.ClusterRoleBinding {
		o, err := cs.RbacV1().ClusterRoleBindings().Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return nil
		}
		return o
	}
	if get("roam-gate-other") == nil || get("roam-gate-legacy") == nil {
		t.Fatal("deleted objects that aren't this Gate's")
	}
	if get("roam-gate-stale") != nil {
		t.Fatal("this Gate's stale object stays")
	}
	if b1 := get("roam-gate-b1"); b1 == nil || b1.Labels[kube.LabelInstance] != id {
		t.Fatalf("not adopted: %+v", b1)
	}
	if objs, _ := r.ManagedObjects(ctx); len(objs) != 2 { // b1 and a1's
		t.Fatalf("managed objects: %v", objs)
	}
	got, _ := cs.CoreV1().ConfigMaps("kube-system").Get(ctx, "aws-auth", metav1.GetOptions{})
	m := got.Data["mapRoles"]
	if !strings.Contains(m, "roam:aws:x1") || !strings.Contains(m, "roam:aws:gone") {
		t.Fatalf("another Gate's (or an unknown) aws-auth entry was removed:\n%s", m)
	}
	if strings.Count(m, "roam:aws:a1:") != 1 || !strings.Contains(m, "kuberoam.dev/gate-instance:"+id) {
		t.Fatalf("own entry not adopted once:\n%s", m)
	}
}
