package auth

import (
	"context"
	"net/http"
	"slices"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/kuberoam/roam-gate/internal/identity"
	"github.com/kuberoam/roam-gate/internal/msg"
	"github.com/kuberoam/roam-gate/internal/store"
)

// OIDCConfig configures an OpenID Connect provider. The "gitlab" and "google"
// types are OIDC with defaults filled in.
type OIDCConfig struct {
	Issuer        string   `json:"issuer"` // gitlab: the GitLab URL (default https://gitlab.com)
	ClientID      string   `json:"clientId"`
	ClientSecret  string   `json:"clientSecret"`
	Scopes        []string `json:"scopes,omitempty"`
	UsernameClaim string   `json:"usernameClaim,omitempty"` // default preferred_username
	GroupsClaim   string   `json:"groupsClaim,omitempty"`   // default groups
	// InsecureSkipEmailVerified accepts emails the provider hasn't verified.
	InsecureSkipEmailVerified bool `json:"insecureSkipEmailVerified,omitempty"`
	Restrictions
}

type oidcProvider struct {
	info     *store.Provider
	cfg      OIDCConfig
	oauth    oauth2.Config
	provider *oidc.Provider
	verifier *oidc.IDTokenVerifier
	// unlisted are configured scopes the provider's discovery doesn't offer.
	unlisted, offered []string
}

// defaultScopes are what Gate asks for when a provider sets none. They are what
// the README and Roam tell people to allow: GitLab applications and Keycloak or
// Okta clients refuse a sign-in that asks for more (invalid_scope). GitLab sends
// groups from userinfo with openid alone; other providers only when offered.
var defaultScopes = map[string][]string{
	TypeGitLab: {oidc.ScopeOpenID, "profile", "email"},
	TypeGoogle: {oidc.ScopeOpenID, "profile", "email"},
	TypeOIDC:   {oidc.ScopeOpenID, "profile", "email", "groups"},
}

func newOIDC(ctx context.Context, sp *store.Provider, c OIDCConfig, callbackURL string) (*oidcProvider, error) {
	switch sp.Type {
	case TypeGitLab:
		if c.Issuer == "" {
			c.Issuer = "https://gitlab.com"
		}
		if c.UsernameClaim == "" {
			c.UsernameClaim = "nickname"
		}
	case TypeGoogle:
		c.Issuer = "https://accounts.google.com"
		// Google sends no groups: allowedGroups would let nobody in.
		if len(c.AllowedGroups) > 0 {
			return nil, msg.New(msg.GroupsUnsupported, "provider", "Google")
		}
	}
	if c.UsernameClaim == "" {
		c.UsernameClaim = "preferred_username"
	}
	if c.GroupsClaim == "" {
		c.GroupsClaim = "groups"
	}
	if c.Issuer == "" || c.ClientID == "" {
		return nil, msg.New(msg.ProviderRequired, "fields", "issuer, clientId")
	}
	c.Issuer = strings.TrimRight(c.Issuer, "/")
	p, err := oidc.NewProvider(oidc.ClientContext(ctx, httpClient), c.Issuer)
	if err != nil {
		return nil, msg.Wrap(msg.OIDCDiscovery, err, "issuer", c.Issuer)
	}
	var disc struct {
		ScopesSupported []string `json:"scopes_supported"`
	}
	_ = p.Claims(&disc)
	scopes, unlisted := pickScopes(c.Scopes, defaultScopes[sp.Type], disc.ScopesSupported)
	c.Scopes = scopes
	return &oidcProvider{
		info: sp,
		cfg:  c,
		oauth: oauth2.Config{
			ClientID: c.ClientID, ClientSecret: c.ClientSecret, Endpoint: p.Endpoint(),
			RedirectURL: callbackURL, Scopes: c.Scopes,
		},
		provider: p,
		verifier: p.Verifier(&oidc.Config{ClientID: c.ClientID}),
		unlisted: unlisted,
		offered:  disc.ScopesSupported,
	}, nil
}

// pickScopes returns the scopes to ask for. Configured scopes are used as they
// are, plus openid (without it there is no ID token); those the provider
// doesn't offer are returned as unlisted. Without configured scopes, the
// defaults the provider offers are used (all but groups when it lists none).
func pickScopes(configured, defaults, offered []string) (scopes, unlisted []string) {
	if len(configured) > 0 {
		scopes = slices.Clone(configured)
		if !slices.Contains(scopes, oidc.ScopeOpenID) {
			scopes = append([]string{oidc.ScopeOpenID}, scopes...)
		}
		if len(offered) > 0 {
			for _, s := range scopes {
				if !slices.Contains(offered, s) {
					unlisted = append(unlisted, s)
				}
			}
		}
		return scopes, unlisted
	}
	for _, s := range defaults {
		if s == oidc.ScopeOpenID || slices.Contains(offered, s) || (len(offered) == 0 && s != "groups") {
			scopes = append(scopes, s)
		}
	}
	return scopes, nil
}

func (p *oidcProvider) Info() *store.Provider { return p.info }

// Scopes are the scopes Gate asks the provider for.
func (p *oidcProvider) Scopes() []string { return p.oauth.Scopes }

// Warnings are configured scopes the provider doesn't say it offers.
func (p *oidcProvider) Warnings() []error {
	if len(p.unlisted) == 0 {
		return nil
	}
	return []error{msg.New(msg.ScopesUnlisted, "scopes", strings.Join(p.unlisted, ", "), "offered", strings.Join(p.offered, ", "))}
}

func (p *oidcProvider) AuthURL(state, nonce, verifier string) string {
	return p.oauth.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier))
}

func (p *oidcProvider) Finish(ctx context.Context, r *http.Request, nonce, verifier string) (*identity.Identity, error) {
	if e := r.URL.Query().Get("error"); e == "invalid_scope" {
		return nil, msg.New(msg.ScopeRefused, "scopes", strings.Join(p.oauth.Scopes, ", "))
	} else if e != "" {
		return nil, providerRefused(e, r.URL.Query().Get("error_description"))
	}
	ctx = oidc.ClientContext(ctx, httpClient)
	tok, err := p.oauth.Exchange(ctx, r.URL.Query().Get("code"), oauth2.VerifierOption(verifier))
	if err != nil {
		return nil, msg.Wrap(msg.CodeExchange, err)
	}
	raw, _ := tok.Extra("id_token").(string)
	if raw == "" {
		return nil, msg.New(msg.NoIDToken)
	}
	idt, err := p.verifier.Verify(ctx, raw)
	if err != nil {
		return nil, msg.Wrap(msg.IDTokenInvalid, err)
	}
	if idt.Nonce != nonce {
		return nil, msg.New(msg.NonceMismatch)
	}
	claims := map[string]any{}
	if err := idt.Claims(&claims); err != nil {
		return nil, err
	}
	// Some providers (GitLab) put groups only in userinfo.
	if _, ok := claims[p.cfg.GroupsClaim]; !ok {
		if ui, err := p.provider.UserInfo(ctx, oauth2.StaticTokenSource(tok)); err == nil {
			extra := map[string]any{}
			if ui.Claims(&extra) == nil {
				for k, v := range extra {
					if _, exists := claims[k]; !exists {
						claims[k] = v
					}
				}
			}
		}
	}
	id := &identity.Identity{Provider: p.info.ID, Subject: idt.Subject, Name: str(claims["name"])}
	if email := str(claims["email"]); email != "" {
		// Only verified emails identify people: an unverified one could be anyone's.
		if verified, ok := claims["email_verified"].(bool); (ok && verified) || p.cfg.InsecureSkipEmailVerified {
			id.Email = email
		}
	}
	id.Login = str(claims[p.cfg.UsernameClaim])
	if id.Login == "" {
		id.Login = idt.Subject
	}
	id.Groups = strList(claims[p.cfg.GroupsClaim])
	if err := p.cfg.Restrictions.Check(id); err != nil {
		return nil, err
	}
	return id, nil
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

func strList(v any) []string {
	switch x := v.(type) {
	case []any:
		out := make([]string, 0, len(x))
		for _, e := range x {
			if s, ok := e.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	case string:
		if x != "" {
			return []string{x}
		}
	}
	return nil
}
