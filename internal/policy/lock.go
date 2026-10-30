package policy

import (
	"context"
	"strconv"
	"time"

	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/kuberoam/roam-gate/internal/kube"
	"github.com/kuberoam/roam-gate/internal/msg"
)

// One Gate per cluster. Each Gate keeps the RBAC for its own bindings and
// deletes Gate objects no binding of its asks for, so a second Gate on the
// same cluster (a second release, an old one never uninstalled) would delete
// the first one's objects every reconcile, and the first would put them back:
// people's access would flicker between allowed and 403.
//
// So a Gate claims the cluster before it reconciles: a ClusterRoleBinding
// named LockName, annotated with the holder's instance ID (store.InstanceID)
// and renewed on every reconcile. It binds a ClusterRole that doesn't exist
// to nobody, so it grants nothing; Gate already may manage
// ClusterRoleBindings and bind any ClusterRole, so the chart needs nothing
// new. A Gate that finds the lock held by another, recently renewed, changes
// nothing and says so (Status). A lock not renewed for its TTL is taken over:
// the other Gate is gone.

const (
	LockName      = "roam-gate-lock"
	annoHolder    = "kuberoam.dev/lock-holder"
	annoHolderURL = "kuberoam.dev/lock-holder-url"
	annoRenewed   = "kuberoam.dev/lock-renewed"
	annoTTL       = "kuberoam.dev/lock-ttl-seconds"
)

// lockTTL is how long a lock lasts unrenewed: a few reconcile intervals, so
// one slow or failed reconcile doesn't hand the cluster over.
func lockTTL(interval time.Duration) time.Duration {
	return max(5*time.Minute, 3*interval)
}

// claim takes or renews the cluster lock for this Gate. It returns a
// msg.LockHeld error while another Gate holds it.
func (r *Reconciler) claim(ctx context.Context, now time.Time) error {
	var err error
	for range 3 { // a race with another Gate: read again and decide again
		var retry bool
		if retry, err = r.claimOnce(ctx, now); !retry {
			return err
		}
	}
	return msg.Wrap(msg.LockFailed, err)
}

func (r *Reconciler) claimOnce(ctx context.Context, now time.Time) (retry bool, _ error) {
	id, err := r.st.InstanceID(ctx)
	if err != nil {
		return false, msg.Wrap(msg.LockFailed, err)
	}
	ttl := lockTTL(r.interval)
	want := func(l *rbacv1.ClusterRoleBinding) {
		l.Annotations = map[string]string{
			annoHolder: id, annoHolderURL: r.self,
			annoRenewed: now.UTC().Format(time.RFC3339), annoTTL: strconv.Itoa(int(ttl.Seconds())),
		}
	}
	api := r.kc.RBAC.ClusterRoleBindings()
	l, err := api.Get(ctx, LockName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		l = &rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{Name: LockName, Labels: map[string]string{kube.LabelManagedBy: kube.ManagedBy, "app.kubernetes.io/part-of": "roam"}},
			RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: LockName},
		}
		want(l)
		_, err = api.Create(ctx, l, metav1.CreateOptions{})
		if apierrors.IsAlreadyExists(err) {
			return true, err // another Gate just made it: read whose it is
		}
		if err != nil {
			return false, msg.Wrap(msg.LockFailed, err)
		}
		return false, nil
	}
	if err != nil {
		return false, msg.Wrap(msg.LockFailed, err)
	}
	if holder := l.Annotations[annoHolder]; holder != id && holder != "" && !lockExpired(l, now) {
		who := l.Annotations[annoHolderURL]
		if who == "" {
			who = holder
		}
		left, _ := strconv.Atoi(l.Annotations[annoTTL])
		return false, msg.New(msg.LockHeld, "holder", who, "ttl", (time.Duration(left) * time.Second).String())
	}
	want(l)
	// The resourceVersion read above makes this a compare-and-swap: of two
	// Gates taking over an expired lock, one gets a conflict.
	if _, err := api.Update(ctx, l, metav1.UpdateOptions{}); err != nil {
		if apierrors.IsConflict(err) {
			return true, err
		}
		return false, msg.Wrap(msg.LockFailed, err)
	}
	return false, nil
}

func lockExpired(l *rbacv1.ClusterRoleBinding, now time.Time) bool {
	renewed, err := time.Parse(time.RFC3339, l.Annotations[annoRenewed])
	ttl, err2 := strconv.Atoi(l.Annotations[annoTTL])
	if err != nil || err2 != nil {
		return true // unreadable: nobody keeps it up
	}
	return now.Sub(renewed) > time.Duration(ttl)*time.Second
}

// release gives the lock up if this Gate holds it (on shutdown), so a Gate
// uninstalled leaves nothing behind and another can take over at once.
func (r *Reconciler) release(ctx context.Context) {
	id, err := r.st.InstanceID(ctx)
	if err != nil {
		return
	}
	api := r.kc.RBAC.ClusterRoleBindings()
	l, err := api.Get(ctx, LockName, metav1.GetOptions{})
	if err != nil || l.Annotations[annoHolder] != id {
		return
	}
	rv := l.ResourceVersion
	_ = api.Delete(ctx, LockName, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{ResourceVersion: &rv}})
}
