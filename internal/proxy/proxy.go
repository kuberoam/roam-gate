// Package proxy forwards Kubernetes API calls from signed-in users to the API
// server as those users: Gate authenticates with its own service account and
// adds Impersonate-User / Impersonate-Group, so the API server applies the
// user's RBAC — Gate never decides access itself.
package proxy

import (
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/kuberoam/roam-gate/internal/audit"
	"github.com/kuberoam/roam-gate/internal/auth"
	"github.com/kuberoam/roam-gate/internal/config"
	"github.com/kuberoam/roam-gate/internal/identity"
	"github.com/kuberoam/roam-gate/internal/msg"
	"github.com/kuberoam/roam-gate/internal/store"
)

// Prefix is where the proxy is served; issued kubeconfigs point at it.
const Prefix = "/k8s"

// ExtraSession is the impersonated "extra" carrying Gate's session ID, so the
// API server's own audit log can be joined with Gate's.
const ExtraSession = "roam-gate-session"

// Sessions resolves bearer tokens.
type Sessions interface {
	Authenticate(r *http.Request) (*store.Session, error)
}

type Proxy struct {
	rp       *httputil.ReverseProxy
	sessions Sessions
	rec      *audit.Recorder
	level    config.AuditLevel
}

// New proxies to apiServer through transport (which authenticates as Gate).
func New(apiServer string, transport http.RoundTripper, sessions Sessions, rec *audit.Recorder, level config.AuditLevel) (*Proxy, error) {
	target, err := url.Parse(apiServer)
	if err != nil {
		return nil, err
	}
	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.Out.URL.Path = strings.TrimPrefix(pr.In.URL.Path, Prefix)
			pr.Out.URL.RawPath = ""
			pr.Out.Host = target.Host
		},
		Transport:     transport,
		FlushInterval: -1, // watches and log streams go out as they arrive
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			slog.Warn("proxy error", "path", r.URL.Path, "err", err)
			writeStatus(w, http.StatusBadGateway, msg.T(msg.Lang(r), msg.APIServerUnreachable))
		},
	}
	return &Proxy{rp: rp, sessions: sessions, rec: rec, level: level}, nil
}

// statusReasons are the metav1.StatusReason values kubectl expects.
var statusReasons = map[int]string{
	http.StatusUnauthorized: "Unauthorized",
	http.StatusForbidden:    "Forbidden",
	http.StatusBadGateway:   "ServiceUnavailable",
}

// writeStatus answers the way the API server does, so kubectl prints it well.
func writeStatus(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	reason := statusReasons[code]
	json.NewEncoder(w).Encode(map[string]any{
		"kind": "Status", "apiVersion": "v1", "status": "Failure", "message": msg, "reason": reason, "code": code,
	})
}

// statusWriter remembers the response code; Unwrap keeps flushing and
// connection upgrades (exec, port-forward) working through it.
type statusWriter struct {
	http.ResponseWriter
	code int
}

func (s *statusWriter) WriteHeader(code int) {
	if s.code == 0 {
		s.code = code
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusWriter) Write(b []byte) (int, error) {
	if s.code == 0 {
		s.code = http.StatusOK
	}
	return s.ResponseWriter.Write(b)
}

func (s *statusWriter) Unwrap() http.ResponseWriter { return s.ResponseWriter }

// ClientIP is the caller's address. Behind a proxy on a private address (an
// ingress), it is the rightmost X-Forwarded-For entry that isn't one too: the
// entries to its left were written by the client and can say anything.
func ClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if !internal(net.ParseIP(host)) {
		return host
	}
	hops := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		h := strings.TrimSpace(hops[i])
		if ip := net.ParseIP(h); ip != nil && !internal(ip) {
			return h
		}
	}
	return host
}

func internal(ip net.IP) bool { return ip != nil && (ip.IsPrivate() || ip.IsLoopback()) }

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	path := strings.TrimPrefix(r.URL.Path, Prefix)
	info := ParseRequest(r, path)
	sess, err := p.sessions.Authenticate(r)
	if err != nil {
		p.rec.Record(&store.Event{Kind: store.KindRequest, Verb: info.Verb, Resource: info.Resource, Subresource: info.Subresource,
			Namespace: info.Namespace, Name: info.Name, Path: path, Status: http.StatusUnauthorized, Allowed: false,
			IP: ClientIP(r), UA: r.UserAgent(), Detail: `{"reason":"invalid or expired token"}`})
		writeStatus(w, http.StatusUnauthorized, msg.T(msg.Lang(r), msg.NotSignedIn))
		return
	}

	// Never let a client impersonate on its own or reuse its Gate token upstream.
	for k := range r.Header {
		if strings.HasPrefix(strings.ToLower(k), "impersonate-") {
			r.Header.Del(k)
		}
	}
	r.Header.Del("Authorization")
	r.Header.Del(auth.TokenHeader)
	r.Header.Del(auth.ActorHeader)
	r.Header.Set("Impersonate-User", identity.KubeUser(sess.User))
	for _, g := range identity.KubeGroups(sess.Groups) {
		r.Header.Add("Impersonate-Group", g)
	}
	r.Header.Set("Impersonate-Extra-"+ExtraSession, sess.ID)

	sw := &statusWriter{ResponseWriter: w}
	p.rp.ServeHTTP(sw, r)

	code := sw.code
	if code == 0 && r.Header.Get("Upgrade") != "" {
		code = http.StatusSwitchingProtocols // hijacked: exec/attach/port-forward ran
	}
	denied := code == http.StatusUnauthorized || code == http.StatusForbidden
	if p.level != config.AuditAll && !info.Sensitive() && !denied {
		return
	}
	e := &store.Event{Kind: store.KindRequest, User: sess.User, Groups: sess.Groups, Session: sess.ID, Verb: info.Verb,
		Resource: info.Resource, Subresource: info.Subresource, Namespace: info.Namespace, Name: info.Name, Path: path,
		Status: code, Allowed: !denied && code < 500, IP: ClientIP(r), UA: r.UserAgent(), DurationMs: time.Since(start).Milliseconds()}
	if sessionSubresources[info.Subresource] {
		q := r.URL.Query()
		d := map[string]any{"container": q.Get("container")}
		if cmd := q["command"]; len(cmd) > 0 {
			d["command"] = cmd
		}
		if ports := q["ports"]; len(ports) > 0 {
			d["ports"] = ports
		}
		b, _ := json.Marshal(d)
		e.Detail = string(b)
	}
	p.rec.Record(e)
}
