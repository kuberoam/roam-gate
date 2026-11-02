package policy

import (
	"context"
	"log/slog"
	"sync/atomic"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/tools/cache"
	watchtools "k8s.io/client-go/tools/watch"

	"github.com/kuberoam/roam-gate/internal/kube"
)

// RBACWatch counts changes to the cluster's RBAC — every ClusterRoleBinding,
// RoleBinding and ClusterRole, Gate's or not — so what the proxy learnt about
// a person's access (proxy/spread.go) is dropped the moment it may no longer
// hold. It only counts events and keeps no copy of the objects, so Gate's
// memory stays flat however big the cluster is.
type RBACWatch struct {
	changes atomic.Uint64
	healthy [3]atomic.Bool
}

// WatchRBAC watches until ctx ends.
func WatchRBAC(ctx context.Context, kc *kube.Client) *RBACWatch {
	w := &RBACWatch{}
	crb, rb, cr := kc.RBAC.ClusterRoleBindings(), kc.RBAC.RoleBindings(""), kc.RBAC.ClusterRoles()
	kinds := []struct {
		name  string
		list  func(context.Context, metav1.ListOptions) (string, error)
		watch func(context.Context, metav1.ListOptions) (watch.Interface, error)
	}{
		{"ClusterRoleBindings", func(ctx context.Context, o metav1.ListOptions) (string, error) {
			l, err := crb.List(ctx, o)
			if err != nil {
				return "", err
			}
			return l.ResourceVersion, nil
		}, crb.Watch},
		{"RoleBindings", func(ctx context.Context, o metav1.ListOptions) (string, error) {
			l, err := rb.List(ctx, o)
			if err != nil {
				return "", err
			}
			return l.ResourceVersion, nil
		}, rb.Watch},
		{"ClusterRoles", func(ctx context.Context, o metav1.ListOptions) (string, error) {
			l, err := cr.List(ctx, o)
			if err != nil {
				return "", err
			}
			return l.ResourceVersion, nil
		}, cr.Watch},
	}
	for i, k := range kinds {
		go w.run(ctx, k.name, &w.healthy[i], k.list, k.watch)
	}
	return w
}

// Version changes with every change to RBAC; ok is false while any of it
// isn't being watched (then nobody may rely on what was learnt).
func (w *RBACWatch) Version() (uint64, bool) {
	for i := range w.healthy {
		if !w.healthy[i].Load() {
			return 0, false
		}
	}
	return w.changes.Load(), true
}

const rbacWatchRetry = 5 * time.Second

func (w *RBACWatch) run(ctx context.Context, kind string, healthy *atomic.Bool,
	list func(context.Context, metav1.ListOptions) (string, error), watchFn func(context.Context, metav1.ListOptions) (watch.Interface, error)) {
	defer healthy.Store(false)
	for ctx.Err() == nil {
		rv, err := list(ctx, metav1.ListOptions{Limit: 1})
		if apierrors.IsForbidden(err) || apierrors.IsUnauthorized(err) {
			slog.Warn("can't watch "+kind+"; access learnt across namespaces isn't remembered", "err", err)
			return
		}
		if err != nil {
			healthy.Store(false)
			select {
			case <-ctx.Done():
			case <-time.After(rbacWatchRetry):
			}
			continue
		}
		rw, err := watchtools.NewRetryWatcherWithContext(ctx, rv, &cache.ListWatch{WatchFuncWithContext: watchFn})
		if err != nil {
			slog.Warn("watching "+kind, "err", err)
			select {
			case <-ctx.Done():
			case <-time.After(rbacWatchRetry):
			}
			continue
		}
		w.changes.Add(1) // anything may have changed while it wasn't watched
		healthy.Store(true)
		var refused error
		for ev := range rw.ResultChan() {
			if ev.Type == watch.Error {
				if err := apierrors.FromObject(ev.Object); apierrors.IsForbidden(err) || apierrors.IsUnauthorized(err) {
					refused = err
				}
				break // can't resume (too old, or refused)
			}
			if ev.Type != watch.Bookmark {
				w.changes.Add(1)
			}
		}
		healthy.Store(false)
		w.changes.Add(1)
		rw.Stop()
		if refused != nil {
			slog.Warn("can't watch "+kind+"; access learnt across namespaces isn't remembered", "err", refused)
			return
		}
		select {
		case <-ctx.Done():
		case <-time.After(time.Second):
		}
	}
}
