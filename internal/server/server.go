// Package server is Gate's HTTP surface: the Kubernetes proxy, the sign-in
// pages, the JSON API Roam uses to manage Gate, and health checks.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/kuberoam/roam-gate/internal/audit"
	"github.com/kuberoam/roam-gate/internal/auth"
	"github.com/kuberoam/roam-gate/internal/config"
	"github.com/kuberoam/roam-gate/internal/kube"
	"github.com/kuberoam/roam-gate/internal/policy"
	"github.com/kuberoam/roam-gate/internal/proxy"
	"github.com/kuberoam/roam-gate/internal/secure"
	"github.com/kuberoam/roam-gate/internal/store"
)

// Version is set at build time.
var Version = "dev"

type Server struct {
	cfg      *config.Config
	st       *store.Store
	kc       *kube.Client
	rec      *audit.Recorder
	sessions *auth.Sessions
	registry *auth.Registry
	policy   *policy.Reconciler
	signer   *secure.Signer
	caPEM    []byte
	limiter  *rateLimiter
	mux      *http.ServeMux
}

type Deps struct {
	Config   *config.Config
	Store    *store.Store
	Kube     *kube.Client
	Recorder *audit.Recorder
	Sessions *auth.Sessions
	Policy   *policy.Reconciler
	Proxy    *proxy.Proxy
	CAPEM    []byte // CA for Gate's TLS certificate, put in kubeconfigs
}

func New(d Deps) *Server {
	s := &Server{
		cfg: d.Config, st: d.Store, kc: d.Kube, rec: d.Recorder, sessions: d.Sessions, policy: d.Policy,
		signer: secure.NewSigner(d.Config.SecretKey), caPEM: d.CAPEM, limiter: newRateLimiter(10, time.Minute),
		mux: http.NewServeMux(),
	}
	s.registry = auth.NewRegistry(d.Store, func(id string) string { return d.Config.ExternalURL + "/auth/" + id + "/callback" })
	m := s.mux

	m.Handle(proxy.Prefix+"/", d.Proxy)
	m.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })
	m.HandleFunc("GET /readyz", s.ready)

	// Browser sign-in.
	m.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/login", http.StatusFound) })
	m.HandleFunc("GET /login", s.loginPage)
	m.HandleFunc("GET /auth/{provider}/start", s.authStart)
	m.HandleFunc("GET /auth/{provider}/callback", s.authCallback)
	m.HandleFunc("POST /auth/{provider}/login", s.passwordLogin)

	// Public API.
	m.HandleFunc("GET /api/v1/info", s.info)
	m.HandleFunc("POST /api/v1/login-requests", s.startLoginRequest)
	m.HandleFunc("POST /api/v1/login-requests/{id}/collect", s.collectLoginRequest)

	// Signed-in API.
	m.HandleFunc("GET /api/v1/me", s.user(s.me))
	m.HandleFunc("POST /api/v1/logout", s.user(s.logout))
	m.HandleFunc("GET /api/v1/kubeconfig", s.user(s.kubeconfig))

	// Admin API.
	m.HandleFunc("GET /api/v1/providers", s.admin(s.listProviders))
	m.HandleFunc("POST /api/v1/providers", s.admin(s.saveProvider))
	m.HandleFunc("PUT /api/v1/providers/{id}", s.admin(s.saveProvider))
	m.HandleFunc("DELETE /api/v1/providers/{id}", s.admin(s.deleteProvider))
	m.HandleFunc("POST /api/v1/providers/{id}/test", s.admin(s.testProvider))
	m.HandleFunc("GET /api/v1/users", s.admin(s.listUsers))
	m.HandleFunc("PATCH /api/v1/users/{id}", s.admin(s.patchUser))
	m.HandleFunc("GET /api/v1/groups", s.admin(s.listGroups))
	m.HandleFunc("GET /api/v1/bindings", s.admin(s.listBindings))
	m.HandleFunc("POST /api/v1/bindings", s.admin(s.saveBinding))
	m.HandleFunc("PUT /api/v1/bindings/{id}", s.admin(s.saveBinding))
	m.HandleFunc("DELETE /api/v1/bindings/{id}", s.admin(s.deleteBinding))
	m.HandleFunc("GET /api/v1/sessions", s.admin(s.listSessions))
	m.HandleFunc("DELETE /api/v1/sessions/{id}", s.admin(s.revokeSession))
	m.HandleFunc("GET /api/v1/audit", s.admin(s.queryAudit))
	m.HandleFunc("GET /api/v1/cluster/roles", s.admin(s.clusterRoles))
	m.HandleFunc("GET /api/v1/cluster/namespaces", s.admin(s.namespaces))
	m.HandleFunc("GET /api/v1/status", s.admin(s.status))
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !strings.HasPrefix(r.URL.Path, proxy.Prefix+"/") {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self' https:; frame-ancestors 'none'")
	}
	s.mux.ServeHTTP(w, r)
}

func (s *Server) ready(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	if _, err := s.st.Bindings(ctx); err != nil {
		http.Error(w, "database: "+err.Error(), http.StatusServiceUnavailable)
		return
	}
	w.Write([]byte("ok"))
}

// ------------------------------------------------------------------ helpers

type apiError struct {
	Error string `json:"error"`
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, code int, msg string) { writeJSON(w, code, apiError{msg}) }

func failErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		fail(w, http.StatusNotFound, "not found")
	default:
		slog.Error("request failed", "err", err)
		fail(w, http.StatusInternalServerError, err.Error())
	}
}

func readJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

type handler func(w http.ResponseWriter, r *http.Request, p *auth.Principal)

func (s *Server) user(h handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, err := s.sessions.Principal(r)
		if err != nil {
			fail(w, http.StatusUnauthorized, "sign in to Roam Gate first")
			return
		}
		h(w, r, p)
	}
}

func (s *Server) admin(h handler) http.HandlerFunc {
	return s.user(func(w http.ResponseWriter, r *http.Request, p *auth.Principal) {
		if !p.Admin {
			fail(w, http.StatusForbidden, "only Roam Gate admins can do this")
			return
		}
		h(w, r, p)
	})
}

// adminEvent records a change made through the admin API.
func (s *Server) adminEvent(r *http.Request, p *auth.Principal, action, target string, detail any) {
	e := &store.Event{Kind: store.KindAdmin, User: p.Name(), Verb: action, Name: target, Allowed: true,
		IP: proxy.ClientIP(r), UA: r.UserAgent()}
	if p.Session != nil {
		e.Groups, e.Session = p.Session.Groups, p.Session.ID
	}
	if detail != nil {
		b, _ := json.Marshal(detail)
		e.Detail = string(b)
	}
	s.rec.Record(e)
}
