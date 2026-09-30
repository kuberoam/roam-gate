package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"golang.org/x/oauth2"

	"github.com/kuberoam/roam-gate/internal/identity"
	"github.com/kuberoam/roam-gate/internal/store"
)

// httpClient is used for calls to identity providers.
var httpClient = &http.Client{Timeout: 20 * time.Second}

// GitHubConfig configures GitHub (or GitHub Enterprise Server) sign-in.
// Groups are the user's organizations ("acme") and teams ("acme/platform").
type GitHubConfig struct {
	URL          string   `json:"url,omitempty"` // GitHub Enterprise Server, e.g. https://github.acme.com
	ClientID     string   `json:"clientId"`
	ClientSecret string   `json:"clientSecret"`
	AllowedOrgs  []string `json:"allowedOrgs,omitempty"` // only members of these orgs may sign in
	Restrictions
}

type gitHub struct {
	info  *store.Provider
	cfg   GitHubConfig
	oauth oauth2.Config
	api   string
}

func newGitHub(sp *store.Provider, c GitHubConfig, callbackURL string) (*gitHub, error) {
	if c.ClientID == "" || c.ClientSecret == "" {
		return nil, errors.New("clientId and clientSecret are required")
	}
	web, api := "https://github.com", "https://api.github.com"
	if c.URL != "" {
		web = strings.TrimRight(c.URL, "/")
		api = web + "/api/v3"
	}
	return &gitHub{info: sp, cfg: c, api: api, oauth: oauth2.Config{
		ClientID: c.ClientID, ClientSecret: c.ClientSecret, RedirectURL: callbackURL,
		Scopes:   []string{"read:user", "user:email", "read:org"},
		Endpoint: oauth2.Endpoint{AuthURL: web + "/login/oauth/authorize", TokenURL: web + "/login/oauth/access_token"},
	}}, nil
}

func (g *gitHub) Info() *store.Provider { return g.info }

func (g *gitHub) AuthURL(state, _, verifier string) string {
	return g.oauth.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier))
}

func (g *gitHub) get(ctx context.Context, c *http.Client, path string, out any) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, g.api+path, nil)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GitHub %s: %s", path, resp.Status)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (g *gitHub) Finish(ctx context.Context, r *http.Request, _, verifier string) (*identity.Identity, error) {
	if e := r.URL.Query().Get("error"); e != "" {
		return nil, fmt.Errorf("%s: %s", e, r.URL.Query().Get("error_description"))
	}
	ctx = context.WithValue(ctx, oauth2.HTTPClient, httpClient)
	tok, err := g.oauth.Exchange(ctx, r.URL.Query().Get("code"), oauth2.VerifierOption(verifier))
	if err != nil {
		return nil, fmt.Errorf("exchanging the code: %w", err)
	}
	c := g.oauth.Client(ctx, tok)
	var user struct {
		ID    int64  `json:"id"`
		Login string `json:"login"`
		Name  string `json:"name"`
	}
	if err := g.get(ctx, c, "/user", &user); err != nil {
		return nil, err
	}
	id := &identity.Identity{Provider: g.info.ID, Subject: fmt.Sprint(user.ID), Login: user.Login, Name: user.Name}
	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	if g.get(ctx, c, "/user/emails", &emails) == nil {
		for _, e := range emails {
			if e.Primary && e.Verified {
				id.Email = e.Email
			}
		}
	}
	var orgs []struct {
		Login string `json:"login"`
	}
	if err := g.get(ctx, c, "/user/orgs?per_page=100", &orgs); err != nil {
		return nil, err
	}
	for _, o := range orgs {
		id.Groups = append(id.Groups, o.Login)
	}
	var teams []struct {
		Slug string `json:"slug"`
		Org  struct {
			Login string `json:"login"`
		} `json:"organization"`
	}
	if g.get(ctx, c, "/user/teams?per_page=100", &teams) == nil {
		for _, t := range teams {
			id.Groups = append(id.Groups, t.Org.Login+"/"+t.Slug)
		}
	}
	if len(g.cfg.AllowedOrgs) > 0 && !slices.ContainsFunc(orgs, func(o struct {
		Login string `json:"login"`
	}) bool {
		return slices.ContainsFunc(g.cfg.AllowedOrgs, func(a string) bool { return strings.EqualFold(a, o.Login) })
	}) {
		return nil, errors.New("you are not a member of an organization that may sign in (check the app's organization access on GitHub)")
	}
	if err := g.cfg.Restrictions.Check(id); err != nil {
		return nil, err
	}
	return id, nil
}
