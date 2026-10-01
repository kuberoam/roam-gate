package auth

import (
	"context"
	"net/http"
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
}

func newOIDC(ctx context.Context, sp *store.Provider, c OIDCConfig, callbackURL string) (*oidcProvider, error) {
	switch sp.Type {
	case TypeGitLab:
		if c.Issuer == "" {
			c.Issuer = "https://gitlab.com"
		}
		if len(c.Scopes) == 0 {
			c.Scopes = []string{"openid", "profile", "email", "read_user"}
		}
		if c.UsernameClaim == "" {
			c.UsernameClaim = "nickname"
		}
	case TypeGoogle:
		c.Issuer = "https://accounts.google.com"
		if len(c.Scopes) == 0 {
			c.Scopes = []string{"openid", "profile", "email"}
		}
	}
	if len(c.Scopes) == 0 {
		c.Scopes = []string{oidc.ScopeOpenID, "profile", "email", "groups"}
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
	return &oidcProvider{
		info: sp,
		cfg:  c,
		oauth: oauth2.Config{
			ClientID: c.ClientID, ClientSecret: c.ClientSecret, Endpoint: p.Endpoint(),
			RedirectURL: callbackURL, Scopes: c.Scopes,
		},
		provider: p,
		verifier: p.Verifier(&oidc.Config{ClientID: c.ClientID}),
	}, nil
}

func (p *oidcProvider) Info() *store.Provider { return p.info }

func (p *oidcProvider) AuthURL(state, nonce, verifier string) string {
	return p.oauth.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier))
}

func (p *oidcProvider) Finish(ctx context.Context, r *http.Request, nonce, verifier string) (*identity.Identity, error) {
	if e := r.URL.Query().Get("error"); e != "" {
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
