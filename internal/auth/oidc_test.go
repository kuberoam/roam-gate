package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"testing"

	"github.com/kuberoam/roam-gate/internal/msg"
	"github.com/kuberoam/roam-gate/internal/store"
)

func TestPickScopes(t *testing.T) {
	gitlab := []string{"api", "read_api", "read_user", "openid", "profile", "email"}
	keycloak := []string{"openid", "profile", "email", "roles", "web-origins", "microprofile-jwt"}
	dex := []string{"openid", "email", "groups", "profile", "offline_access"}
	for _, tc := range []struct {
		name                         string
		configured, defaults, offers []string
		want, unlisted               []string
	}{
		{"gitlab defaults are what Roam says to allow", nil, defaultScopes[TypeGitLab], gitlab, []string{"openid", "profile", "email"}, nil},
		{"google defaults", nil, defaultScopes[TypeGoogle], []string{"openid", "email", "profile"}, []string{"openid", "profile", "email"}, nil},
		{"groups only when offered (Keycloak)", nil, defaultScopes[TypeOIDC], keycloak, []string{"openid", "profile", "email"}, nil},
		{"groups when offered (Dex)", nil, defaultScopes[TypeOIDC], dex, []string{"openid", "profile", "email", "groups"}, nil},
		{"no list: no groups", nil, defaultScopes[TypeOIDC], nil, []string{"openid", "profile", "email"}, nil},
		{"configured kept, openid added", []string{"email", "read_user"}, defaultScopes[TypeGitLab], gitlab, []string{"openid", "email", "read_user"}, nil},
		{"configured but not offered", []string{"openid", "groups"}, defaultScopes[TypeOIDC], keycloak, []string{"openid", "groups"}, []string{"groups"}},
		{"configured, no list to check", []string{"openid", "groups"}, defaultScopes[TypeOIDC], nil, []string{"openid", "groups"}, nil},
	} {
		got, unlisted := pickScopes(tc.configured, tc.defaults, tc.offers)
		if !slices.Equal(got, tc.want) || !slices.Equal(unlisted, tc.unlisted) {
			t.Errorf("%s: got %v (unlisted %v), want %v (unlisted %v)", tc.name, got, unlisted, tc.want, tc.unlisted)
		}
	}
}

// discovery serves an OpenID configuration offering the given scopes.
func discovery(t *testing.T, scopes []string) *httptest.Server {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"issuer": srv.URL, "authorization_endpoint": srv.URL + "/authorize", "token_endpoint": srv.URL + "/token",
			"jwks_uri": srv.URL + "/keys", "scopes_supported": scopes,
		})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func build(t *testing.T, typ string, cfg map[string]any) (Provider, error) {
	t.Helper()
	b, _ := json.Marshal(cfg)
	return Build(context.Background(), &store.Provider{ID: typ, Type: typ, Config: b}, "https://gate.example.com/auth/"+typ+"/callback")
}

func TestGitLabAsksForWhatTheAppAllows(t *testing.T) {
	gl := discovery(t, []string{"api", "read_user", "openid", "profile", "email"})
	p, err := build(t, TypeGitLab, map[string]any{"issuer": gl.URL, "clientId": "c", "clientSecret": "s"})
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(p.(Redirector).AuthURL("st", "n", "verifier-verifier-verifier-verifier-verifier"))
	if got := u.Query().Get("scope"); got != "openid profile email" {
		t.Fatalf("scope = %q", got)
	}
	if got := p.(Scoped).Scopes(); !slices.Equal(got, []string{"openid", "profile", "email"}) {
		t.Fatal(got)
	}

	// A refused scope says which scopes to allow.
	req := httptest.NewRequest("GET", "/auth/gitlab/callback?error=invalid_scope&error_description=nope", nil)
	_, err = p.(Redirector).Finish(context.Background(), req, "n", "v")
	if m, ok := errors.AsType[*msg.Error](err); !ok || m.Code != msg.ScopeRefused {
		t.Fatalf("got %v", err)
	}
	if got := msg.Localize("en", err); got != "The sign-in provider refused the scopes Gate asked for (openid, profile, email). Allow them in the app or client registered at the provider, or set this sign-in method's scopes in Gate." {
		t.Fatal(got)
	}
}

func TestOIDCWarnsAboutScopesNotOffered(t *testing.T) {
	kc := discovery(t, []string{"openid", "profile", "email", "roles"})
	p, err := build(t, TypeOIDC, map[string]any{"issuer": kc.URL, "clientId": "c", "scopes": []string{"profile", "groups"}})
	if err != nil {
		t.Fatal(err)
	}
	if got := p.(Scoped).Scopes(); !slices.Equal(got, []string{"openid", "profile", "groups"}) {
		t.Fatal(got)
	}
	ws := p.(Warner).Warnings()
	if len(ws) != 1 || msg.Localize("en", ws[0]) != "The provider doesn't list groups among the scopes it offers (openid, profile, email, roles): sign-in fails with invalid_scope unless it accepts them anyway." {
		t.Fatal(ws)
	}
}

func TestGoogleRejectsAllowedGroups(t *testing.T) {
	_, err := build(t, TypeGoogle, map[string]any{"clientId": "c", "clientSecret": "s", "allowedGroups": []string{"eng"}})
	if m, ok := errors.AsType[*msg.Error](err); !ok || m.Code != msg.GroupsUnsupported {
		t.Fatalf("got %v", err)
	}
}
