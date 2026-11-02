package policy

import (
	"context"
	"slices"
	"sync"

	rbacv1 "k8s.io/api/rbac/v1"

	"github.com/kuberoam/roam-gate/internal/store"
)

// Grants answers which namespaces a person was granted one by one, for the
// proxy's lists across namespaces (proxy/spread.go). It keeps a copy of the
// bindings, read again whenever one is saved or deleted.
type Grants struct {
	st   *store.Store
	rbac *RBACWatch // nil: nothing learnt is remembered

	mu       sync.Mutex
	version  uint64
	loaded   bool
	bindings []*store.Binding
}

func NewGrants(st *store.Store, rbac *RBACWatch) *Grants { return &Grants{st: st, rbac: rbac} }

// Version changes whenever Gate's bindings or the cluster's RBAC do; ok is
// false while RBAC isn't watched. A binding saved changes it at once, before
// the reconcile writes its RoleBindings — which change it again.
func (g *Grants) Version() (uint64, bool) {
	if g.rbac == nil {
		return 0, false
	}
	v, ok := g.rbac.Version()
	return v + g.st.BindingsVersion(), ok
}

// Namespaces lists the namespaces the bindings of scope "namespaces" grant
// to the Kubernetes user or any of the groups Gate impersonates.
func (g *Grants) Namespaces(ctx context.Context, user string, groups []string) ([]string, error) {
	bindings, err := g.current(ctx)
	if err != nil {
		return nil, err
	}
	return GrantedNamespaces(bindings, user, groups), nil
}

func (g *Grants) current(ctx context.Context) ([]*store.Binding, error) {
	// The version is read before the bindings: a change made while they are
	// read leaves the copy marked older, so the next call reads them again.
	v := g.st.BindingsVersion()
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.loaded && g.version == v {
		return g.bindings, nil
	}
	bindings, err := g.st.Bindings(ctx)
	if err != nil {
		return nil, err
	}
	g.bindings, g.version, g.loaded = bindings, v, true
	return bindings, nil
}

// GrantedNamespaces is Namespaces over the given bindings.
func GrantedNamespaces(bindings []*store.Binding, user string, groups []string) []string {
	var out []string
	for _, b := range bindings {
		if b.Scope != store.ScopeNamespaces {
			continue
		}
		s, err := Subject(b)
		if err != nil {
			continue
		}
		if (s.Kind == rbacv1.UserKind && s.Name == user) || (s.Kind == rbacv1.GroupKind && slices.Contains(groups, s.Name)) {
			out = append(out, b.Namespaces...)
		}
	}
	return slices.Compact(slices.Sorted(slices.Values(out)))
}
