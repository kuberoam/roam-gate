package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/oauth2"

	"github.com/kuberoam/roam-gate/internal/identity"
	"github.com/kuberoam/roam-gate/internal/msg"
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
		return nil, msg.New(msg.ProviderRequired, "fields", "clientId, clientSecret")
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

// maxPages bounds paging through orgs and teams (100 per page).
const maxPages = 10

func (g *gitHub) get(ctx context.Context, c *http.Client, path string, out any) (next string, err error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, g.api+path, nil)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := c.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", msg.New(msg.GitHubAPI, "path", path, "status", resp.Status)
	}
	return nextPage(resp.Header.Get("Link"), g.api), json.NewDecoder(resp.Body).Decode(out)
}

// nextPage is the path of the rel="next" link in a GitHub Link header.
func nextPage(link, api string) string {
	for _, part := range strings.Split(link, ",") {
		if strings.Contains(part, `rel="next"`) {
			u := strings.Trim(strings.TrimSpace(strings.SplitN(part, ";", 2)[0]), "<>")
			return strings.TrimPrefix(u, api)
		}
	}
	return ""
}

// getAll follows the pages of a list endpoint.
func getAll[T any](ctx context.Context, g *gitHub, c *http.Client, path string) ([]T, error) {
	var all []T
	for i := 0; path != "" && i < maxPages; i++ {
		var page []T
		next, err := g.get(ctx, c, path, &page)
		if err != nil {
			return nil, err
		}
		all, path = append(all, page...), next
	}
	return all, nil
}

func (g *gitHub) Finish(ctx context.Context, r *http.Request, _, verifier string) (*identity.Identity, error) {
	if e := r.URL.Query().Get("error"); e != "" {
		return nil, providerRefused(e, r.URL.Query().Get("error_description"))
	}
	ctx = context.WithValue(ctx, oauth2.HTTPClient, httpClient)
	tok, err := g.oauth.Exchange(ctx, r.URL.Query().Get("code"), oauth2.VerifierOption(verifier))
	if err != nil {
		return nil, msg.Wrap(msg.CodeExchange, err)
	}
	c := g.oauth.Client(ctx, tok)
	var user struct {
		ID    int64  `json:"id"`
		Login string `json:"login"`
		Name  string `json:"name"`
	}
	if _, err := g.get(ctx, c, "/user", &user); err != nil {
		return nil, err
	}
	id := &identity.Identity{Provider: g.info.ID, Subject: strconv.FormatInt(user.ID, 10), Login: user.Login, Name: user.Name}
	type email struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	if emails, err := getAll[email](ctx, g, c, "/user/emails?per_page=100"); err == nil {
		for _, e := range emails {
			if e.Primary && e.Verified {
				id.Email = e.Email
			}
		}
	}
	// GitHub names are case-insensitive, Kubernetes RBAC names are not:
	// groups are lowercase so "Acme/Platform" and "acme/platform" match.
	type org struct {
		Login string `json:"login"`
	}
	orgs, err := getAll[org](ctx, g, c, "/user/orgs?per_page=100")
	if err != nil {
		return nil, err
	}
	for _, o := range orgs {
		id.Groups = append(id.Groups, strings.ToLower(o.Login))
	}
	type team struct {
		Slug string `json:"slug"`
		Org  org    `json:"organization"`
	}
	if teams, err := getAll[team](ctx, g, c, "/user/teams?per_page=100"); err == nil {
		for _, t := range teams {
			id.Groups = append(id.Groups, strings.ToLower(t.Org.Login+"/"+t.Slug))
		}
	}
	if len(g.cfg.AllowedOrgs) > 0 && !slices.ContainsFunc(orgs, func(o org) bool {
		return slices.ContainsFunc(g.cfg.AllowedOrgs, func(a string) bool { return strings.EqualFold(a, o.Login) })
	}) {
		return nil, msg.New(msg.GitHubOrgDenied)
	}
	if err := g.cfg.Restrictions.Check(id); err != nil {
		return nil, err
	}
	return id, nil
}
