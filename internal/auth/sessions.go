package auth

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/kuberoam/roam-gate/internal/identity"
	"github.com/kuberoam/roam-gate/internal/msg"
	"github.com/kuberoam/roam-gate/internal/secure"
	"github.com/kuberoam/roam-gate/internal/store"
)

// TokenPrefix marks Gate session tokens ("rg_…").
const TokenPrefix = "rg_"

var ErrUnauthenticated = msg.New(msg.NotSignedIn)

// Sessions issues and checks session tokens.
type Sessions struct {
	st          *store.Store
	ttl         time.Duration
	adminToken  string
	adminUsers  map[string]bool
	adminGroups map[string]bool
	touched     touchLimiter
}

func NewSessions(st *store.Store, ttl time.Duration, adminToken string, adminUsers, adminGroups []string) *Sessions {
	set := func(xs []string) map[string]bool {
		m := map[string]bool{}
		for _, x := range xs {
			m[strings.ToLower(x)] = true
		}
		return m
	}
	return &Sessions{st: st, ttl: ttl, adminToken: adminToken, adminUsers: set(adminUsers), adminGroups: set(adminGroups)}
}

// BearerToken reads "Authorization: Bearer …".
func BearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) > 7 && strings.EqualFold(h[:7], "bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return strings.TrimSpace(r.Header.Get(TokenHeader))
}

// TokenHeader carries the token when Authorization can't: the Kubernetes API
// server's service proxy (how Roam reaches Gate) drops Authorization.
const TokenHeader = "X-Roam-Gate-Token"

// ActorHeader names who is behind a bootstrap-token call (Roam sends the
// person's cluster identity), for the audit trail. Only holders of the
// bootstrap token can set it, and they are admins anyway.
const ActorHeader = "X-Roam-Gate-Actor"

// Start signs someone in: records the user and returns a new session token.
func (s *Sessions) Start(ctx context.Context, id *identity.Identity, ip, ua string) (string, *store.Session, error) {
	userID := id.UserID()
	if u, err := s.st.User(ctx, userID); err == nil && u.Disabled {
		return "", nil, msg.New(msg.AccountDisabled)
	}
	groups := id.GroupIDs()
	if err := s.st.SeenUser(ctx, &store.User{ID: userID, Provider: id.Provider, Name: id.Name, Email: id.Email, Groups: groups}); err != nil {
		return "", nil, err
	}
	now := time.Now()
	sess := &store.Session{ID: secure.ID(), User: userID, Groups: groups, Provider: id.Provider, Created: now, Expires: now.Add(s.ttl), IP: ip, UA: ua}
	token := secure.Token(TokenPrefix)
	if err := s.st.CreateSession(ctx, sess, token); err != nil {
		return "", nil, err
	}
	return token, sess, nil
}

// Authenticate resolves the request's bearer token to a live session.
func (s *Sessions) Authenticate(r *http.Request) (*store.Session, error) {
	token := BearerToken(r)
	if !strings.HasPrefix(token, TokenPrefix) {
		return nil, ErrUnauthenticated
	}
	sess, err := s.st.SessionByToken(r.Context(), token)
	if err != nil {
		return nil, ErrUnauthenticated
	}
	if s.touched.due(sess.ID) {
		_ = s.st.TouchSession(r.Context(), sess.ID)
	}
	return sess, nil
}

// Principal is whoever calls Gate's API: a session, or the bootstrap admin.
type Principal struct {
	Session *store.Session // nil for the bootstrap admin
	Admin   bool
	Actor   string // bootstrap admin only: who said they are behind the call
}

// Name is how the principal appears in the audit trail.
func (p *Principal) Name() string {
	if p.Session == nil {
		if p.Actor != "" {
			return "admin (bootstrap token) · " + p.Actor
		}
		return "admin (bootstrap token)"
	}
	return p.Session.User
}

// Principal authenticates an API call.
func (s *Sessions) Principal(r *http.Request) (*Principal, error) {
	token := BearerToken(r)
	if s.adminToken != "" && token != "" && secure.Equal(token, s.adminToken) {
		actor := strings.Map(func(r rune) rune {
			if r < 0x20 || r == 0x7f {
				return -1
			}
			return r
		}, strings.TrimSpace(r.Header.Get(ActorHeader)))
		if len(actor) > 120 {
			actor = actor[:120]
		}
		return &Principal{Admin: true, Actor: actor}, nil
	}
	sess, err := s.Authenticate(r)
	if err != nil {
		return nil, err
	}
	return &Principal{Session: sess, Admin: s.IsAdmin(sess)}, nil
}

// IsAdmin says whether a session may administer Gate.
func (s *Sessions) IsAdmin(sess *store.Session) bool {
	if s.adminUsers[strings.ToLower(sess.User)] {
		return true
	}
	for _, g := range sess.Groups {
		if s.adminGroups[strings.ToLower(g)] {
			return true
		}
	}
	return false
}

// touchLimiter spaces out last-used updates so busy clients don't write per request.
type touchLimiter struct {
	mu   sync.Mutex
	last map[string]time.Time
}

func (t *touchLimiter) due(id string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.last == nil {
		t.last = map[string]time.Time{}
	}
	if time.Since(t.last[id]) < time.Minute {
		return false
	}
	t.last[id] = time.Now()
	if len(t.last) > 10000 {
		t.last = map[string]time.Time{} // bounded; a reset only costs a few extra writes
	}
	return true
}
