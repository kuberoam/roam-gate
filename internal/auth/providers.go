// Package auth signs people in (SSO providers) and resolves their sessions.
package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/kuberoam/roam-gate/internal/identity"
	"github.com/kuberoam/roam-gate/internal/store"
)

// Provider types.
const (
	TypeOIDC   = "oidc"
	TypeGitHub = "github"
	TypeGitLab = "gitlab"
	TypeGoogle = "google"
	TypeLDAP   = "ldap"
)

// Types lists the provider types Gate supports.
var Types = []string{TypeGitHub, TypeGitLab, TypeGoogle, TypeOIDC, TypeLDAP}

// Provider is a configured SSO connection.
type Provider interface {
	Info() *store.Provider
}

// Redirector signs in through the browser (OAuth2 / OIDC).
type Redirector interface {
	Provider
	// AuthURL is where to send the browser; state and pkceVerifier are Gate's.
	AuthURL(state, nonce, pkceVerifier string) string
	// Finish completes the sign-in from the callback request.
	Finish(ctx context.Context, r *http.Request, nonce, pkceVerifier string) (*identity.Identity, error)
}

// PasswordLogin signs in with a username and password (LDAP).
type PasswordLogin interface {
	Provider
	Login(ctx context.Context, username, password string) (*identity.Identity, error)
}

// Restrictions every provider type supports: who may sign in at all.
type Restrictions struct {
	AllowedDomains []string `json:"allowedDomains,omitempty"` // email domains
	AllowedGroups  []string `json:"allowedGroups,omitempty"`  // groups at the provider (any one)
}

// Check applies the restrictions to an identity.
func (r Restrictions) Check(id *identity.Identity) error {
	if len(r.AllowedDomains) > 0 {
		at := strings.LastIndexByte(id.Email, '@')
		if at < 0 || !slices.ContainsFunc(r.AllowedDomains, func(d string) bool { return strings.EqualFold(d, id.Email[at+1:]) }) {
			return errors.New("your email domain is not allowed to sign in")
		}
	}
	if len(r.AllowedGroups) > 0 && !slices.ContainsFunc(id.Groups, func(g string) bool {
		return slices.ContainsFunc(r.AllowedGroups, func(a string) bool { return strings.EqualFold(a, g) })
	}) {
		return errors.New("you are not in a group that is allowed to sign in")
	}
	return nil
}

// Registry builds providers from the store and caches them (OIDC discovery
// is a network call) until the provider's settings change.
type Registry struct {
	st          *store.Store
	callbackURL func(providerID string) string
	mu          sync.Mutex
	cache       map[string]cached
}

type cached struct {
	updated time.Time
	p       Provider
}

func NewRegistry(st *store.Store, callbackURL func(string) string) *Registry {
	return &Registry{st: st, callbackURL: callbackURL, cache: map[string]cached{}}
}

var ErrProviderDisabled = errors.New("this sign-in method is turned off")

// Get returns an enabled provider.
func (r *Registry) Get(ctx context.Context, id string) (Provider, error) {
	sp, err := r.st.Provider(ctx, id)
	if err != nil {
		return nil, err
	}
	if !sp.Enabled {
		return nil, ErrProviderDisabled
	}
	r.mu.Lock()
	c, ok := r.cache[id]
	r.mu.Unlock()
	if ok && c.updated.Equal(sp.Updated) {
		return c.p, nil
	}
	p, err := Build(ctx, sp, r.callbackURL(id))
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	r.cache[id] = cached{updated: sp.Updated, p: p}
	r.mu.Unlock()
	return p, nil
}

// Build makes a provider from its stored settings (and checks them).
func Build(ctx context.Context, sp *store.Provider, callbackURL string) (Provider, error) {
	dec := func(v any) error {
		if err := json.Unmarshal(sp.Config, v); err != nil {
			return fmt.Errorf("provider %s settings: %w", sp.ID, err)
		}
		return nil
	}
	switch sp.Type {
	case TypeOIDC, TypeGitLab, TypeGoogle:
		var c OIDCConfig
		if err := dec(&c); err != nil {
			return nil, err
		}
		return newOIDC(ctx, sp, c, callbackURL)
	case TypeGitHub:
		var c GitHubConfig
		if err := dec(&c); err != nil {
			return nil, err
		}
		return newGitHub(sp, c, callbackURL)
	case TypeLDAP:
		var c LDAPConfig
		if err := dec(&c); err != nil {
			return nil, err
		}
		return newLDAP(sp, c)
	}
	return nil, fmt.Errorf("unknown provider type %q", sp.Type)
}

// Redacted returns a provider's settings with secrets replaced, for the API.
func Redacted(sp *store.Provider) json.RawMessage {
	var m map[string]any
	if json.Unmarshal(sp.Config, &m) != nil {
		return nil
	}
	for _, k := range []string{"clientSecret", "bindPassword"} {
		if v, ok := m[k].(string); ok && v != "" {
			m[k] = SecretPlaceholder
		}
	}
	b, _ := json.Marshal(m)
	return b
}

// SecretPlaceholder stands for a stored secret in the API; sending it back
// keeps the stored value.
const SecretPlaceholder = "••••••••"

// MergeSecrets keeps stored secrets where an update sends the placeholder.
func MergeSecrets(old, updated json.RawMessage) json.RawMessage {
	var o, n map[string]any
	if json.Unmarshal(old, &o) != nil || json.Unmarshal(updated, &n) != nil {
		return updated
	}
	for _, k := range []string{"clientSecret", "bindPassword"} {
		if n[k] == SecretPlaceholder {
			n[k] = o[k]
		}
	}
	b, _ := json.Marshal(n)
	return b
}
