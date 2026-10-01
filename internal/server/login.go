package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2"

	"github.com/kuberoam/roam-gate/internal/auth"
	"github.com/kuberoam/roam-gate/internal/identity"
	"github.com/kuberoam/roam-gate/internal/msg"
	"github.com/kuberoam/roam-gate/internal/proxy"
	"github.com/kuberoam/roam-gate/internal/secure"
	"github.com/kuberoam/roam-gate/internal/store"
)

const (
	flowCookie      = "rg_flow"
	flowTTL         = 10 * time.Minute
	loginRequestTTL = 10 * time.Minute
)

// flow is what Gate remembers between sending the browser to a provider and
// the callback; it rides in a signed, HttpOnly cookie.
type flow struct {
	State    string `json:"s"`
	Nonce    string `json:"n"`
	Verifier string `json:"v"`
	Provider string `json:"p"`
	Request  string `json:"r,omitempty"` // app login request to complete
	Expires  int64  `json:"e"`
}

func (s *Server) setFlow(w http.ResponseWriter, f flow) {
	b, _ := json.Marshal(f)
	http.SetCookie(w, &http.Cookie{
		Name: flowCookie, Value: s.signer.Sign(base64.RawURLEncoding.EncodeToString(b)), Path: "/auth/",
		HttpOnly: true, Secure: strings.HasPrefix(s.cfg.ExternalURL, "https://"), SameSite: http.SameSiteLaxMode,
		MaxAge: int(flowTTL.Seconds()),
	})
}

func (s *Server) readFlow(r *http.Request) (*flow, error) {
	c, err := r.Cookie(flowCookie)
	if err != nil {
		return nil, msg.New(msg.FlowMissing)
	}
	v, ok := s.signer.Verify(c.Value)
	if !ok {
		return nil, msg.New(msg.FlowAltered)
	}
	raw, err := base64.RawURLEncoding.DecodeString(v)
	if err != nil {
		return nil, err
	}
	var f flow
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, err
	}
	if time.Now().Unix() > f.Expires {
		return nil, msg.New(msg.FlowExpired)
	}
	return &f, nil
}

func clearFlow(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: flowCookie, Value: "", Path: "/auth/", MaxAge: -1, HttpOnly: true})
}

// providerView is a provider as the login page and /info show it.
type providerView struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Type     string `json:"type"`
	Password bool   `json:"password"` // signs in with a username and password form
}

func (s *Server) enabledProviders(ctx context.Context) ([]providerView, error) {
	ps, err := s.st.Providers(ctx)
	if err != nil {
		return nil, err
	}
	var out []providerView
	for _, p := range ps {
		if p.Enabled {
			out = append(out, providerView{ID: p.ID, Name: p.Name, Type: p.Type, Password: p.Type == auth.TypeLDAP})
		}
	}
	return out, nil
}

func (s *Server) loginPage(w http.ResponseWriter, r *http.Request) {
	v := viewFor(r)
	ps, err := s.enabledProviders(r.Context())
	if err != nil {
		s.page(w, v, http.StatusInternalServerError, msg.PageTitleError, errorBody(v, err))
		return
	}
	s.page(w, v, http.StatusOK, msg.PageTitleSignIn, loginBody(v, ps, s.pendingRequest(r, r.URL.Query().Get("req")), s.signer.Sign(strconv.FormatInt(time.Now().Unix(), 10))))
}

// pendingRequest keeps an app login request ID only while it is pending.
func (s *Server) pendingRequest(r *http.Request, id string) string {
	if id == "" {
		return ""
	}
	if _, err := s.st.LoginRequest(r.Context(), id); err != nil {
		return ""
	}
	return id
}

func (s *Server) authStart(w http.ResponseWriter, r *http.Request) {
	v := viewFor(r)
	id := r.PathValue("provider")
	req := s.pendingRequest(r, r.URL.Query().Get("req"))
	p, err := s.registry.Get(r.Context(), id)
	if err != nil {
		s.page(w, v, http.StatusBadRequest, msg.PageTitleUnavailable, errorBody(v, msg.Wrap(msg.ProviderUnavailable, err)))
		return
	}
	rd, ok := p.(auth.Redirector)
	if !ok {
		http.Redirect(w, r, "/login?req="+url.QueryEscape(req), http.StatusFound)
		return
	}
	f := flow{State: secure.ID(), Nonce: secure.ID(), Verifier: oauth2.GenerateVerifier(), Provider: id,
		Request: req, Expires: time.Now().Add(flowTTL).Unix()}
	s.setFlow(w, f)
	http.Redirect(w, r, rd.AuthURL(f.State, f.Nonce, f.Verifier), http.StatusFound)
}

func (s *Server) authCallback(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("provider")
	f, err := s.readFlow(r)
	clearFlow(w)
	if err == nil && (f.Provider != id || !secure.Equal(f.State, r.URL.Query().Get("state"))) {
		err = msg.New(msg.FlowMismatch)
	}
	var ident *identity.Identity
	if err == nil {
		var p auth.Provider
		if p, err = s.registry.Get(r.Context(), id); err == nil {
			rd, ok := p.(auth.Redirector)
			if !ok {
				err = msg.New(msg.NotRedirect)
			} else {
				ident, err = rd.Finish(r.Context(), r, f.Nonce, f.Verifier)
			}
		}
	}
	req := ""
	if f != nil {
		req = f.Request
	}
	s.completeLogin(w, r, id, req, ident, err)
}

func (s *Server) passwordLogin(w http.ResponseWriter, r *http.Request) {
	v := viewFor(r)
	id := r.PathValue("provider")
	ip := proxy.ClientIP(r)
	if !s.limiter.allow(ip) {
		s.page(w, v, http.StatusTooManyRequests, msg.PageTitleTooMany, errorBody(v, msg.New(msg.TooManyAttempts)))
		return
	}
	// The form carries a signed timestamp: posts from elsewhere or stale pages fail.
	ts, ok := s.signer.Verify(r.PostFormValue("t"))
	n, _ := strconv.ParseInt(ts, 10, 64)
	if !ok || time.Since(time.Unix(n, 0)) > flowTTL {
		s.page(w, v, http.StatusBadRequest, msg.PageTitleSignIn, errorBody(v, msg.New(msg.FormExpired)))
		return
	}
	var ident *identity.Identity
	p, err := s.registry.Get(r.Context(), id)
	if err == nil {
		pl, ok := p.(auth.PasswordLogin)
		if !ok {
			err = msg.New(msg.NotPassword)
		} else {
			ident, err = pl.Login(r.Context(), r.PostFormValue("username"), r.PostFormValue("password"))
		}
	}
	if err != nil {
		// Name the attempted user in the audit trail even though sign-in failed.
		s.rec.Record(&store.Event{Kind: store.KindLogin, User: id + ":" + strings.ToLower(strings.TrimSpace(r.PostFormValue("username"))),
			Verb: store.VerbLogin, Allowed: false, IP: ip, UA: r.UserAgent(), Detail: detail(map[string]any{"provider": id, "error": msg.Localize(msg.DefaultLang, err)})})
		s.page(w, v, http.StatusUnauthorized, msg.PageTitleFailed, errorBody(v, err))
		return
	}
	s.completeLogin(w, r, id, s.pendingRequest(r, r.PostFormValue("req")), ident, nil)
}

func detail(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// completeLogin records the outcome, starts the session, and either sends
// the browser back to the waiting app or shows the kubeconfig.
func (s *Server) completeLogin(w http.ResponseWriter, r *http.Request, providerID, req string, ident *identity.Identity, err error) {
	v := viewFor(r)
	ip := proxy.ClientIP(r)
	var lr *store.LoginRequest
	if req != "" {
		lr, _ = s.st.LoginRequest(r.Context(), req)
	}
	var token string
	var sess *store.Session
	if err == nil {
		token, sess, err = s.sessions.Start(r.Context(), ident, ip, r.UserAgent())
	}
	if err != nil {
		e := &store.Event{Kind: store.KindLogin, Verb: store.VerbLogin, Allowed: false, IP: ip, UA: r.UserAgent(),
			Detail: detail(map[string]any{"provider": providerID, "error": msg.Localize(msg.DefaultLang, err)})}
		if ident != nil {
			e.User = ident.UserID()
		}
		s.rec.Record(e)
		if lr != nil {
			// The app learns it failed from collect; the person reads why here.
			_, _ = s.st.FinishLoginRequest(r.Context(), lr.ID, "", msg.Localize(v.lang, err))
		}
		s.page(w, v, http.StatusUnauthorized, msg.PageTitleFailed, errorBody(v, err))
		return
	}
	s.rec.Record(&store.Event{Kind: store.KindLogin, User: sess.User, Groups: sess.Groups, Session: sess.ID, Verb: store.VerbLogin, Allowed: true,
		IP: ip, UA: r.UserAgent(), Detail: detail(map[string]any{"provider": providerID, "expires": sess.Expires, "app": lr != nil})})
	if lr != nil {
		if code, err := s.st.FinishLoginRequest(r.Context(), lr.ID, token, ""); err == nil {
			http.Redirect(w, r, returnTo(lr, "code", code), http.StatusFound)
			return
		}
		// The app stopped waiting; fall back to showing the kubeconfig.
	}
	s.page(w, v, http.StatusOK, msg.PageTitleSignedIn, kubeconfigBody(v, sess.User, sess.Expires, s.kubeconfigYAML(sess, token)))
}

// returnTo is the app's loopback address with the request ID and the one-time code.
func returnTo(lr *store.LoginRequest, key, value string) string {
	u, _ := url.Parse(lr.ReturnURL)
	q := u.Query()
	q.Set("req", lr.ID)
	q.Set(key, value)
	u.RawQuery = q.Encode()
	return u.String()
}

// ------------------------------------------------------ app login requests

// loopbackURL accepts only http://127.0.0.1, [::1] or localhost with a port:
// the app's own listener on the computer where the person signs in (RFC 8252).
func loopbackURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" || u.User != nil || u.Port() == "" || u.Fragment != "" {
		return false
	}
	h := u.Hostname()
	return h == "localhost" || h == "127.0.0.1" || h == "::1"
}

func (s *Server) startLoginRequest(w http.ResponseWriter, r *http.Request) {
	if !s.limiter.allow("lr:" + proxy.ClientIP(r)) {
		fail(w, r, http.StatusTooManyRequests, msg.New(msg.TooManyRequests))
		return
	}
	var body struct {
		ReturnURL string `json:"returnURL"`
	}
	if err := readJSON(r, &body); err != nil {
		badRequest(w, r, err)
		return
	}
	if !loopbackURL(body.ReturnURL) {
		fail(w, r, http.StatusBadRequest, msg.New(msg.ReturnURLInvalid))
		return
	}
	id, secret := secure.ID(), secure.Token("rgp_")
	if err := s.st.CreateLoginRequest(r.Context(), id, secret, body.ReturnURL, loginRequestTTL); err != nil {
		fail(w, r, 0, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"id": id, "pollSecret": secret, "url": s.cfg.ExternalURL + "/login?req=" + url.QueryEscape(id),
		"expires": time.Now().Add(loginRequestTTL),
	})
}

func (s *Server) collectLoginRequest(w http.ResponseWriter, r *http.Request) {
	var body struct {
		PollSecret string `json:"pollSecret"`
		Code       string `json:"code"`
	}
	if err := readJSON(r, &body); err != nil {
		badRequest(w, r, err)
		return
	}
	token, state, failure, err := s.st.CollectLogin(r.Context(), r.PathValue("id"), body.PollSecret, body.Code)
	if err != nil {
		fail(w, r, 0, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"state": state, "token": token, "error": failure})
}

// ------------------------------------------------------------ rate limiting

// rateLimiter allows n attempts per window per key (client IP), in memory.
type rateLimiter struct {
	mu     sync.Mutex
	n      int
	window time.Duration
	hits   map[string][]time.Time
}

func newRateLimiter(n int, window time.Duration) *rateLimiter {
	return &rateLimiter{n: n, window: window, hits: map[string][]time.Time{}}
}

func (l *rateLimiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	h := l.hits[key]
	i := 0
	for i < len(h) && now.Sub(h[i]) > l.window {
		i++
	}
	h = h[i:]
	if len(h) >= l.n {
		l.hits[key] = h
		return false
	}
	l.hits[key] = append(h, now)
	if len(l.hits) > 50000 {
		l.hits = map[string][]time.Time{}
	}
	return true
}

// ------------------------------------------------------------------ kubeconfig

func (s *Server) kubeconfigYAML(sess *store.Session, token string) string {
	cluster := s.cfg.ClusterName
	var ca string
	if len(s.caPEM) > 0 {
		ca = "\n    certificate-authority-data: " + base64.StdEncoding.EncodeToString(s.caPEM)
	}
	user := sess.User + "@" + cluster
	return fmt.Sprintf(`apiVersion: v1
kind: Config
clusters:
- name: %[1]s
  cluster:
    server: %[2]s%[3]s
contexts:
- name: %[1]s
  context:
    cluster: %[1]s
    user: %[4]q
current-context: %[1]s
users:
- name: %[4]q
  user:
    token: %[5]s
# Issued by Roam Gate for %[6]s; valid until %[7]s. Sign in again at %[8]s/login to renew.
`, cluster, s.cfg.ExternalURL, proxy.Prefix+ca, user, token, sess.User, sess.Expires.UTC().Format(time.RFC3339), s.cfg.ExternalURL)
}
