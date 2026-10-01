package store

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func open(t *testing.T) *Store {
	t.Helper()
	st, err := Open(t.TempDir(), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func TestProvidersAreEncrypted(t *testing.T) {
	st := open(t)
	ctx := context.Background()
	p := &Provider{ID: "github", Type: "github", Name: "GitHub", Enabled: true, Config: json.RawMessage(`{"clientSecret":"s3cret"}`)}
	if err := st.SaveProvider(ctx, p); err != nil {
		t.Fatal(err)
	}
	var raw []byte
	if err := st.db.QueryRow(`SELECT config FROM providers WHERE id = 'github'`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if string(raw) == string(p.Config) || json.Valid(raw) {
		t.Fatal("provider settings are stored in the clear")
	}
	got, err := st.Provider(ctx, "github")
	if err != nil || string(got.Config) != `{"clientSecret":"s3cret"}` {
		t.Fatalf("round trip: %v %s", err, got.Config)
	}
}

func TestSessions(t *testing.T) {
	st := open(t)
	ctx := context.Background()
	now := time.Now()
	s := &Session{ID: "s1", User: "alice@corp.com", Groups: []string{"github:acme"}, Provider: "github", Created: now, Expires: now.Add(time.Hour)}
	if err := st.CreateSession(ctx, s, "rg_token"); err != nil {
		t.Fatal(err)
	}
	got, err := st.SessionByToken(ctx, "rg_token")
	if err != nil || got.User != "alice@corp.com" || got.Groups[0] != "github:acme" {
		t.Fatalf("lookup: %v %+v", err, got)
	}
	if _, err := st.SessionByToken(ctx, "rg_other"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown token: %v", err)
	}
	// Disabling the user revokes their sessions.
	if err := st.SeenUser(ctx, &User{ID: "alice@corp.com", Provider: "github"}); err != nil {
		t.Fatal(err)
	}
	if err := st.SetUserDisabled(ctx, "alice@corp.com", true); err != nil {
		t.Fatal(err)
	}
	if _, err := st.SessionByToken(ctx, "rg_token"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("session should be revoked: %v", err)
	}
	// Expired sessions don't authenticate.
	old := &Session{ID: "s2", User: "bob", Created: now.Add(-2 * time.Hour), Expires: now.Add(-time.Hour)}
	st.CreateSession(ctx, old, "rg_old")
	if _, err := st.SessionByToken(ctx, "rg_old"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired session: %v", err)
	}
}

func TestLoginRequest(t *testing.T) {
	st := open(t)
	ctx := context.Background()
	if err := st.CreateLoginRequest(ctx, "r1", "poll", "http://127.0.0.1:5555/cb", time.Minute); err != nil {
		t.Fatal(err)
	}
	if r, err := st.LoginRequest(ctx, "r1"); err != nil || r.ReturnURL != "http://127.0.0.1:5555/cb" {
		t.Fatalf("lookup: %v %+v", err, r)
	}
	if _, state, _, err := st.CollectLogin(ctx, "r1", "poll", ""); err != nil || state != LoginPending {
		t.Fatalf("pending: %v %s", err, state)
	}
	if _, _, _, err := st.CollectLogin(ctx, "r1", "wrong", ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("wrong secret must not reveal anything: %v", err)
	}
	code, err := st.FinishLoginRequest(ctx, "r1", "rg_tok", "")
	if err != nil || code == "" {
		t.Fatalf("finish: %v %q", err, code)
	}
	if _, err := st.LoginRequest(ctx, "r1"); !errors.Is(err, ErrNotFound) {
		t.Fatal("a finished request is no longer pending")
	}
	// The poll secret alone is not enough: the code went to the app's own computer.
	if tok, _, _, err := st.CollectLogin(ctx, "r1", "poll", "guess"); err == nil || tok != "" {
		t.Fatalf("wrong code: %v %q", err, tok)
	}
	tok, state, _, err := st.CollectLogin(ctx, "r1", "poll", code)
	if err != nil || state != LoginDone || tok != "rg_tok" {
		t.Fatalf("collect: %v %s %s", err, state, tok)
	}
	// The token can only be collected once.
	if _, _, _, err := st.CollectLogin(ctx, "r1", "poll", code); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second collect: %v", err)
	}
	// A failed sign-in has no code and says why.
	st.CreateLoginRequest(ctx, "r2", "poll", "http://127.0.0.1:5555/cb", time.Minute)
	if code, err := st.FinishLoginRequest(ctx, "r2", "", "denied"); err != nil || code != "" {
		t.Fatalf("fail: %v %q", err, code)
	}
	if _, state, failure, _ := st.CollectLogin(ctx, "r2", "poll", ""); state != LoginFailed || failure != "denied" {
		t.Fatalf("failed state: %s %s", state, failure)
	}
}

func TestRevokeProviderSessions(t *testing.T) {
	st := open(t)
	ctx := context.Background()
	now := time.Now()
	st.CreateSession(ctx, &Session{ID: "a", User: "u", Provider: "github", Created: now, Expires: now.Add(time.Hour)}, "rg_a")
	st.CreateSession(ctx, &Session{ID: "b", User: "u", Provider: "ldap", Created: now, Expires: now.Add(time.Hour)}, "rg_b")
	if n, err := st.RevokeProviderSessions(ctx, "github"); err != nil || n != 1 {
		t.Fatalf("revoke: %d %v", n, err)
	}
	if _, err := st.SessionByToken(ctx, "rg_a"); !errors.Is(err, ErrNotFound) {
		t.Fatal("github session should be revoked")
	}
	if _, err := st.SessionByToken(ctx, "rg_b"); err != nil {
		t.Fatal("ldap session must stay")
	}
}

func TestAuditQueryAndPrune(t *testing.T) {
	st := open(t)
	ctx := context.Background()
	old := time.Now().Add(-100 * 24 * time.Hour)
	events := []*Event{
		{Time: old, Kind: KindRequest, User: "alice", Verb: "delete", Resource: "pods", Namespace: "prod", Name: "web-1", Allowed: true},
		{Time: time.Now(), Kind: KindRequest, User: "alice", Verb: "create", Resource: "pods", Subresource: "exec", Namespace: "prod", Name: "web-2", Allowed: true, Detail: `{"command":["sh"]}`},
		{Time: time.Now(), Kind: KindRequest, User: "bob", Verb: "get", Resource: "secrets", Namespace: "kube-system", Name: "token", Status: 403, Allowed: false},
		{Time: time.Now(), Kind: KindLogin, User: "carol", Verb: "login", Allowed: false},
	}
	if err := st.InsertEvents(ctx, events); err != nil {
		t.Fatal(err)
	}
	check := func(q AuditQuery, want int) {
		t.Helper()
		got, err := st.Audit(ctx, q)
		if err != nil || len(got) != want {
			t.Fatalf("%+v: got %d events (%v), want %d", q, len(got), err, want)
		}
	}
	check(AuditQuery{}, 4)
	check(AuditQuery{User: "alice"}, 2)
	check(AuditQuery{Namespace: "prod", Verb: "create"}, 1)
	check(AuditQuery{Denied: true}, 2)
	check(AuditQuery{Text: "sh"}, 1)
	check(AuditQuery{Text: "100%"}, 0) // LIKE wildcards are escaped
	check(AuditQuery{Since: time.Now().Add(-time.Hour)}, 3)
	first, _ := st.Audit(ctx, AuditQuery{Limit: 2})
	check(AuditQuery{Before: first[1].ID}, 2) // paging
	n, err := st.Prune(ctx, 90*24*time.Hour)
	if err != nil || n != 1 {
		t.Fatalf("prune: %d %v", n, err)
	}
	check(AuditQuery{}, 3)
}
