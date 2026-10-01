package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"

	"github.com/kuberoam/roam-gate/internal/audit"
	"github.com/kuberoam/roam-gate/internal/auth"
	"github.com/kuberoam/roam-gate/internal/config"
	"github.com/kuberoam/roam-gate/internal/kube"
	"github.com/kuberoam/roam-gate/internal/msg"
	"github.com/kuberoam/roam-gate/internal/policy"
	"github.com/kuberoam/roam-gate/internal/proxy"
	"github.com/kuberoam/roam-gate/internal/store"
)

// mockIdP is a minimal OpenID Connect provider that signs everyone in as alice.
type mockIdP struct {
	*httptest.Server
	key    *rsa.PrivateKey
	mu     sync.Mutex
	nonces map[string]string // code → nonce
}

func newIdP(t *testing.T) *mockIdP {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	m := &mockIdP{key: key, nonces: map[string]string{}}
	mux := http.NewServeMux()
	m.Server = httptest.NewServer(mux)
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"issuer": m.URL, "authorization_endpoint": m.URL + "/authorize", "token_endpoint": m.URL + "/token",
			"jwks_uri": m.URL + "/keys", "userinfo_endpoint": m.URL + "/userinfo", "id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}}})
	})
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("code_challenge") == "" {
			http.Error(w, "PKCE required", 400)
			return
		}
		m.mu.Lock()
		m.nonces["code1"] = q.Get("nonce")
		m.mu.Unlock()
		http.Redirect(w, r, q.Get("redirect_uri")+"?code=code1&state="+url.QueryEscape(q.Get("state")), http.StatusFound)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		if r.Form.Get("code_verifier") == "" {
			http.Error(w, "missing verifier", 400)
			return
		}
		m.mu.Lock()
		nonce := m.nonces[r.Form.Get("code")]
		m.mu.Unlock()
		signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithHeader("kid", "k1"))
		idt, _ := jwt.Signed(signer).Claims(map[string]any{
			"iss": m.URL, "sub": "u-1", "aud": "gate", "exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(),
			"nonce": nonce, "email": "Alice@Corp.com", "email_verified": true, "name": "Alice", "groups": []string{"devs", "ops"},
		}).Serialize()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "token_type": "Bearer", "id_token": idt, "expires_in": 3600})
	})
	t.Cleanup(m.Close)
	return m
}

type seen struct {
	mu      sync.Mutex
	headers []http.Header
	paths   []string
}

func TestSignInProxyAndAudit(t *testing.T) {
	ctx := context.Background()
	idp := newIdP(t)

	// A stand-in API server: it records what Gate sends and forbids deleting in kube-system.
	var got seen
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.mu.Lock()
		got.headers = append(got.headers, r.Header.Clone())
		got.paths = append(got.paths, r.URL.Path)
		got.mu.Unlock()
		if r.Method == http.MethodDelete && strings.Contains(r.URL.Path, "/namespaces/kube-system/") {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.Write([]byte(`{"kind":"PodList","items":[]}`))
	}))
	defer api.Close()

	st, err := store.Open(t.TempDir(), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	gate := httptest.NewUnstartedServer(nil)
	cfg := &config.Config{ExternalURL: "http://" + gate.Listener.Addr().String(), SecretKey: make([]byte, 32), ClusterName: "test",
		AdminToken: "bootstrap-admin-token", SessionTTL: time.Hour, AuditLevel: config.AuditWrites}
	rec := audit.New(st, nil)
	sessions := auth.NewSessions(st, cfg.SessionTTL, cfg.AdminToken, nil, []string{"mock:ops"})
	px, err := proxy.New(api.URL, http.DefaultTransport, sessions, rec, cfg.AuditLevel)
	if err != nil {
		t.Fatal(err)
	}
	cs := fake.NewSimpleClientset()
	kc := &kube.Client{Config: &rest.Config{Host: api.URL}, RBAC: cs.RbacV1(), Core: cs.CoreV1()}
	gate.Config.Handler = New(Deps{Config: cfg, Store: st, Kube: kc, Recorder: rec, Sessions: sessions, Policy: policy.New(kc, st, time.Minute), Proxy: px})
	gate.Start()
	defer gate.Close()

	call := func(method, path, token, body string) (*http.Response, []byte) {
		t.Helper()
		req, _ := http.NewRequest(method, gate.URL+path, strings.NewReader(body))
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp, b
	}

	// The bootstrap admin sets up the provider.
	if resp, b := call("POST", "/api/v1/providers", "bootstrap-admin-token",
		`{"id":"mock","type":"oidc","name":"Mock SSO","enabled":true,"config":{"issuer":"`+idp.URL+`","clientId":"gate","clientSecret":"shh"}}`); resp.StatusCode != 200 {
		t.Fatalf("create provider: %d %s", resp.StatusCode, b)
	}
	if resp, b := call("GET", "/api/v1/providers", "bootstrap-admin-token", ""); !strings.Contains(string(b), auth.SecretPlaceholder) || strings.Contains(string(b), "shh") {
		t.Fatalf("secrets must be redacted: %d %s", resp.StatusCode, b)
	}
	// Through the API server's service proxy Authorization is dropped, so Roam
	// sends the token in its own header, with who is behind the call.
	hreq, _ := http.NewRequest("POST", gate.URL+"/api/v1/bindings", strings.NewReader(`{"subjectKind":"group","subject":"mock:ops","role":"view","scope":"cluster"}`))
	hreq.Header.Set(auth.TokenHeader, "bootstrap-admin-token")
	hreq.Header.Set(auth.ActorHeader, "roam: kind-admin\t")
	if hr, err := http.DefaultClient.Do(hreq); err != nil || hr.StatusCode != 200 {
		t.Fatalf("token header: %v %v", err, hr)
	}
	if resp, _ := call("GET", "/api/v1/providers", "", ""); resp.StatusCode != 401 {
		t.Fatalf("admin API without a token: %d", resp.StatusCode)
	}

	// Only a loopback address can receive the sign-in code.
	if resp, b := call("POST", "/api/v1/login-requests", "", `{"returnURL":"https://evil.example/cb"}`); resp.StatusCode != 400 || !strings.Contains(string(b), string(msg.ReturnURLInvalid)) {
		t.Fatalf("non-loopback return: %d %s", resp.StatusCode, b)
	}

	// An app signs in: it listens on loopback, starts a request, the browser
	// signs in and comes back to the app with a one-time code.
	codes := make(chan string, 1)
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		codes <- r.URL.Query().Get("code")
		w.Write([]byte("back in the app"))
	}))
	defer app.Close()
	_, b := call("POST", "/api/v1/login-requests", "", `{"returnURL":"`+app.URL+`/cb"}`)
	var lr struct{ ID, PollSecret, URL string }
	json.Unmarshal(b, &lr)
	jar, _ := cookiejar.New(nil)
	browser := &http.Client{Jar: jar}
	resp, err := browser.Get(gate.URL + "/auth/mock/start?req=" + lr.ID)
	if err != nil {
		t.Fatal(err)
	}
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(page) != "back in the app" {
		t.Fatalf("return to app: %d %s", resp.StatusCode, page)
	}
	code := <-codes
	// Whoever only has the poll secret (someone who sent the link) gets nothing.
	if resp, _ := call("POST", "/api/v1/login-requests/"+lr.ID+"/collect", "", `{"pollSecret":"`+lr.PollSecret+`","code":"guess"}`); resp.StatusCode != 400 {
		t.Fatalf("collect without the code: %d", resp.StatusCode)
	}
	_, b = call("POST", "/api/v1/login-requests/"+lr.ID+"/collect", "", `{"pollSecret":"`+lr.PollSecret+`","code":"`+code+`"}`)
	var col struct{ State, Token string }
	json.Unmarshal(b, &col)
	if col.State != store.LoginDone || !strings.HasPrefix(col.Token, auth.TokenPrefix) {
		t.Fatalf("collect: %s", b)
	}
	token := col.Token

	_, b = call("GET", "/api/v1/me", token, "")
	var me struct {
		User   string
		Admin  bool
		Groups []string
	}
	json.Unmarshal(b, &me)
	if me.User != "alice@corp.com" || !me.Admin || strings.Join(me.Groups, ",") != "mock:devs,mock:ops,authenticated" {
		t.Fatalf("me: %s", b)
	}

	// Through the proxy, as alice — even when the client tries to impersonate someone else.
	req, _ := http.NewRequest("GET", gate.URL+"/k8s/api/v1/namespaces/default/pods", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Impersonate-User", "system:admin")
	req.Header.Add("Impersonate-Group", "system:masters")
	r2, err := http.DefaultClient.Do(req)
	if err != nil || r2.StatusCode != 200 {
		t.Fatalf("proxy get: %v %v", err, r2)
	}
	r2.Body.Close()
	got.mu.Lock()
	h := got.headers[len(got.headers)-1]
	path := got.paths[len(got.paths)-1]
	got.mu.Unlock()
	if path != "/api/v1/namespaces/default/pods" {
		t.Fatalf("path: %s", path)
	}
	if h.Get("Impersonate-User") != "roam:alice@corp.com" {
		t.Fatalf("Impersonate-User: %q", h.Get("Impersonate-User"))
	}
	if g := strings.Join(h.Values("Impersonate-Group"), ","); g != "roam:mock:devs,roam:mock:ops,roam:authenticated" {
		t.Fatalf("Impersonate-Group: %q", g)
	}
	if h.Get("Authorization") != "" {
		t.Fatal("the user's Gate token must not reach the API server")
	}
	if h.Get("Impersonate-Extra-"+proxy.ExtraSession) == "" {
		t.Fatal("missing session extra")
	}

	if resp, _ := call("DELETE", "/k8s/api/v1/namespaces/kube-system/pods/x", token, ""); resp.StatusCode != 403 {
		t.Fatalf("expected the API server's 403, got %d", resp.StatusCode)
	}
	if resp, _ := call("GET", "/k8s/api/v1/pods", "rg_forged", ""); resp.StatusCode != 401 {
		t.Fatalf("forged token: %d", resp.StatusCode)
	}

	// A kubeconfig for the session points at the proxy.
	_, kc2 := call("GET", "/api/v1/kubeconfig", token, "")
	if !strings.Contains(string(kc2), cfg.ExternalURL+"/k8s") || !strings.Contains(string(kc2), token) {
		t.Fatalf("kubeconfig: %s", kc2)
	}

	// The audit trail has the sign-in, the denied delete and the forged token,
	// but not the plain read (level "writes").
	time.Sleep(1300 * time.Millisecond)
	events, err := st.Audit(ctx, store.AuditQuery{})
	if err != nil {
		t.Fatal(err)
	}
	var kinds []string
	for _, e := range events {
		kinds = append(kinds, e.Kind+"/"+e.Verb+"/"+e.Resource+"/"+map[bool]string{true: "ok", false: "denied"}[e.Allowed])
	}
	joined := strings.Join(kinds, " ")
	for _, want := range []string{"login/login//ok", "request/delete/pods/denied", "request/list/pods/denied", "admin/provider.create//ok"} {
		if !strings.Contains(joined, want) {
			t.Errorf("audit is missing %s: %s", want, joined)
		}
	}
	actorSeen := false
	for _, e := range events {
		if e.User == "admin (bootstrap token) · roam: kind-admin" {
			actorSeen = true
		}
	}
	if !actorSeen {
		t.Errorf("the actor header should show in the audit trail")
	}
	if strings.Contains(joined, "request/list/pods/ok") {
		t.Errorf("reads should not be recorded at level writes: %s", joined)
	}

	// Errors come in the caller's language, with a stable code.
	vreq, _ := http.NewRequest("POST", gate.URL+"/api/v1/bindings", strings.NewReader(`{"subjectKind":"group","subject":"x","role":"view","scope":"namespaces"}`))
	vreq.Header.Set("Authorization", "Bearer bootstrap-admin-token")
	vreq.Header.Set("Accept-Language", "vi-VN,vi;q=0.9")
	vresp, err := http.DefaultClient.Do(vreq)
	if err != nil {
		t.Fatal(err)
	}
	var ve struct{ Error, Code string }
	json.NewDecoder(vresp.Body).Decode(&ve)
	vresp.Body.Close()
	if vresp.StatusCode != 400 || ve.Code != string(msg.NamespacesRequired) || !strings.Contains(ve.Error, "namespace") || !strings.HasPrefix(ve.Error, "Chọn") {
		t.Fatalf("localized error: %d %+v", vresp.StatusCode, ve)
	}

	// Logging out ends the token.
	if resp, _ := call("POST", "/api/v1/logout", token, ""); resp.StatusCode != 204 {
		t.Fatalf("logout: %d", resp.StatusCode)
	}
	if resp, _ := call("GET", "/k8s/api/v1/pods", token, ""); resp.StatusCode != 401 {
		t.Fatalf("after logout: %d", resp.StatusCode)
	}

	// Deleting the sign-in method ends the sessions it started, right away.
	now := time.Now()
	st.CreateSession(ctx, &store.Session{ID: "other", User: "bob@corp.com", Provider: "mock", Created: now, Expires: now.Add(time.Hour)}, "rg_other")
	if resp, _ := call("GET", "/k8s/api/v1/pods", "rg_other", ""); resp.StatusCode != 200 {
		t.Fatalf("before deleting the provider: %d", resp.StatusCode)
	}
	if resp, _ := call("DELETE", "/api/v1/providers/mock", "bootstrap-admin-token", ""); resp.StatusCode != 204 {
		t.Fatalf("delete provider: %d", resp.StatusCode)
	}
	if resp, _ := call("GET", "/k8s/api/v1/pods", "rg_other", ""); resp.StatusCode != 401 {
		t.Fatalf("after deleting the provider: %d", resp.StatusCode)
	}
}
