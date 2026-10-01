// Package store keeps Gate's state in one SQLite file: SSO providers, users
// seen at login, sessions, access bindings and the audit trail.
//
// Access itself lives in Kubernetes RBAC (see package policy); this database
// is what Gate needs to issue sessions and what people need to investigate.
package store

import (
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/kuberoam/roam-gate/internal/msg"
	"github.com/kuberoam/roam-gate/internal/secure"
	_ "modernc.org/sqlite"
)

//go:embed migrations/*.sql
var migrations embed.FS

var ErrNotFound = errors.New("not found")

type Store struct {
	db  *sql.DB
	box *secure.Box
}

// Open opens (and migrates) the database in dir. key encrypts provider secrets.
func Open(dir string, key []byte) (*Store, error) {
	box, err := secure.NewBox(key)
	if err != nil {
		return nil, err
	}
	dsn := "file:" + filepath.Join(dir, "gate.db") +
		"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(ON)&_pragma=synchronous(NORMAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// SQLite allows one writer at a time; a small pool avoids lock churn.
	db.SetMaxOpenConns(4)
	s := &Store{db: db, box: box}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

// Ping checks the database answers (readiness).
func (s *Store) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }

func (s *Store) migrate() error {
	if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (name TEXT PRIMARY KEY, applied INTEGER NOT NULL)`); err != nil {
		return err
	}
	names, err := fs.Glob(migrations, "migrations/*.sql")
	if err != nil {
		return err
	}
	sort.Strings(names)
	for _, n := range names {
		var x int
		if err := s.db.QueryRow(`SELECT 1 FROM schema_migrations WHERE name = ?`, n).Scan(&x); err == nil {
			continue
		}
		body, _ := migrations.ReadFile(n)
		tx, err := s.db.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(string(body)); err != nil {
			tx.Rollback()
			return fmt.Errorf("migration %s: %w", n, err)
		}
		if _, err := tx.Exec(`INSERT INTO schema_migrations (name, applied) VALUES (?, ?)`, n, time.Now().Unix()); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

func ms(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixMilli()
}

func fromMs(v int64) time.Time {
	if v == 0 {
		return time.Time{}
	}
	return time.UnixMilli(v)
}

func toJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func strs(v string) []string {
	var out []string
	_ = json.Unmarshal([]byte(v), &out)
	return out
}

// ---------------------------------------------------------------- providers

// Provider is an SSO connection. Config holds its settings, secrets included;
// it is stored encrypted.
type Provider struct {
	ID      string          `json:"id"`
	Type    string          `json:"type"`
	Name    string          `json:"name"`
	Enabled bool            `json:"enabled"`
	Config  json.RawMessage `json:"config,omitempty"`
	Created time.Time       `json:"created"`
	Updated time.Time       `json:"updated"`
}

func (s *Store) SaveProvider(ctx context.Context, p *Provider) error {
	now := time.Now()
	if p.Created.IsZero() {
		p.Created = now
	}
	p.Updated = now
	_, err := s.db.ExecContext(ctx, `INSERT INTO providers (id, type, name, enabled, config, created, updated) VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET type = excluded.type, name = excluded.name, enabled = excluded.enabled, config = excluded.config, updated = excluded.updated`,
		p.ID, p.Type, p.Name, p.Enabled, s.box.Seal(p.Config), ms(p.Created), ms(p.Updated))
	return err
}

func (s *Store) scanProvider(row interface{ Scan(...any) error }) (*Provider, error) {
	var p Provider
	var sealed []byte
	var created, updated int64
	if err := row.Scan(&p.ID, &p.Type, &p.Name, &p.Enabled, &sealed, &created, &updated); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	cfg, err := s.box.Open(sealed)
	if err != nil {
		return nil, msg.New(msg.ProviderDecrypt, "id", p.ID)
	}
	p.Config, p.Created, p.Updated = cfg, fromMs(created), fromMs(updated)
	return &p, nil
}

func (s *Store) Provider(ctx context.Context, id string) (*Provider, error) {
	return s.scanProvider(s.db.QueryRowContext(ctx, `SELECT id, type, name, enabled, config, created, updated FROM providers WHERE id = ?`, id))
}

func (s *Store) Providers(ctx context.Context) ([]*Provider, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, type, name, enabled, config, created, updated FROM providers ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Provider
	for rows.Next() {
		p, err := s.scanProvider(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Store) DeleteProvider(ctx context.Context, id string) error {
	return one(s.db.ExecContext(ctx, `DELETE FROM providers WHERE id = ?`, id))
}

func one(r sql.Result, err error) error {
	if err != nil {
		return err
	}
	if n, _ := r.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// -------------------------------------------------------------------- users

// User is someone who signed in, with the groups their provider reported.
type User struct {
	ID        string    `json:"id"` // Gate user ID, e.g. alice@corp.com or github:alice
	Provider  string    `json:"provider"`
	Name      string    `json:"name"`
	Email     string    `json:"email"`
	Groups    []string  `json:"groups"`
	FirstSeen time.Time `json:"firstSeen"`
	LastSeen  time.Time `json:"lastSeen"`
	Disabled  bool      `json:"disabled"`
}

// SeenUser records a login, keeping Disabled as it was.
func (s *Store) SeenUser(ctx context.Context, u *User) error {
	now := ms(time.Now())
	_, err := s.db.ExecContext(ctx, `INSERT INTO users (id, provider, name, email, groups, first_seen, last_seen, disabled) VALUES (?, ?, ?, ?, ?, ?, ?, 0)
		ON CONFLICT(id) DO UPDATE SET provider = excluded.provider, name = excluded.name, email = excluded.email, groups = excluded.groups, last_seen = excluded.last_seen`,
		u.ID, u.Provider, u.Name, u.Email, toJSON(u.Groups), now, now)
	return err
}

const userCols = `id, provider, name, email, groups, first_seen, last_seen, disabled`

func scanUser(row interface{ Scan(...any) error }) (*User, error) {
	var u User
	var groups string
	var first, last int64
	if err := row.Scan(&u.ID, &u.Provider, &u.Name, &u.Email, &groups, &first, &last, &u.Disabled); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	u.Groups, u.FirstSeen, u.LastSeen = strs(groups), fromMs(first), fromMs(last)
	return &u, nil
}

func (s *Store) User(ctx context.Context, id string) (*User, error) {
	return scanUser(s.db.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE id = ?`, id))
}

func (s *Store) Users(ctx context.Context) ([]*User, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+userCols+` FROM users ORDER BY last_seen DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// SetUserDisabled blocks (or unblocks) a user; disabling also revokes their sessions.
func (s *Store) SetUserDisabled(ctx context.Context, id string, disabled bool) error {
	if err := one(s.db.ExecContext(ctx, `UPDATE users SET disabled = ? WHERE id = ?`, disabled, id)); err != nil {
		return err
	}
	if disabled {
		_, err := s.db.ExecContext(ctx, `UPDATE sessions SET revoked = 1 WHERE user = ?`, id)
		return err
	}
	return nil
}

// Groups lists every group seen on a user, with how many users are in it.
func (s *Store) Groups(ctx context.Context) (map[string]int, error) {
	users, err := s.Users(ctx)
	if err != nil {
		return nil, err
	}
	out := map[string]int{}
	for _, u := range users {
		for _, g := range u.Groups {
			out[g]++
		}
	}
	return out, nil
}

// ----------------------------------------------------------------- sessions

// Session is a signed-in user's credential for the proxy and the API. Only
// the token's hash is stored.
type Session struct {
	ID       string    `json:"id"`
	User     string    `json:"user"`
	Groups   []string  `json:"groups"`
	Provider string    `json:"provider"`
	Created  time.Time `json:"created"`
	Expires  time.Time `json:"expires"`
	LastUsed time.Time `json:"lastUsed"`
	IP       string    `json:"ip"`
	UA       string    `json:"userAgent"`
	Revoked  bool      `json:"revoked"`
}

func (s *Store) CreateSession(ctx context.Context, sess *Session, token string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO sessions (id, token_hash, user, groups, provider, created, expires, last_used, ip, ua, revoked) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)`,
		sess.ID, secure.Hash(token), sess.User, toJSON(sess.Groups), sess.Provider, ms(sess.Created), ms(sess.Expires), ms(sess.Created), sess.IP, sess.UA)
	return err
}

const sessionCols = `id, user, groups, provider, created, expires, last_used, ip, ua, revoked`

func scanSession(row interface{ Scan(...any) error }) (*Session, error) {
	var x Session
	var groups string
	var c, e, l int64
	if err := row.Scan(&x.ID, &x.User, &groups, &x.Provider, &c, &e, &l, &x.IP, &x.UA, &x.Revoked); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	x.Groups, x.Created, x.Expires, x.LastUsed = strs(groups), fromMs(c), fromMs(e), fromMs(l)
	return &x, nil
}

// SessionByToken returns a live session for a token, or ErrNotFound when it is
// unknown, expired or revoked.
func (s *Store) SessionByToken(ctx context.Context, token string) (*Session, error) {
	x, err := scanSession(s.db.QueryRowContext(ctx, `SELECT `+sessionCols+` FROM sessions WHERE token_hash = ?`, secure.Hash(token)))
	if err != nil {
		return nil, err
	}
	if x.Revoked || time.Now().After(x.Expires) {
		return nil, ErrNotFound
	}
	return x, nil
}

// TouchSession notes use; called at most once a minute per session.
func (s *Store) TouchSession(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE sessions SET last_used = ? WHERE id = ?`, ms(time.Now()), id)
	return err
}

func (s *Store) Sessions(ctx context.Context, user string, includeEnded bool) ([]*Session, error) {
	q := `SELECT ` + sessionCols + ` FROM sessions WHERE 1 = 1`
	var args []any
	if user != "" {
		q += ` AND user = ?`
		args = append(args, user)
	}
	if !includeEnded {
		q += ` AND revoked = 0 AND expires > ?`
		args = append(args, ms(time.Now()))
	}
	rows, err := s.db.QueryContext(ctx, q+` ORDER BY created DESC LIMIT 500`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Session
	for rows.Next() {
		x, err := scanSession(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, rows.Err()
}

func (s *Store) RevokeSession(ctx context.Context, id string) error {
	return one(s.db.ExecContext(ctx, `UPDATE sessions SET revoked = 1 WHERE id = ?`, id))
}

// RevokeProviderSessions ends every live session started through a provider
// (it was deleted or turned off) and returns how many.
func (s *Store) RevokeProviderSessions(ctx context.Context, provider string) (int64, error) {
	r, err := s.db.ExecContext(ctx, `UPDATE sessions SET revoked = 1 WHERE provider = ? AND revoked = 0 AND expires > ?`, provider, ms(time.Now()))
	if err != nil {
		return 0, err
	}
	return r.RowsAffected()
}

// ------------------------------------------------------------ login requests

// Login request states.
const (
	LoginPending = "pending"
	LoginDone    = "done"
	LoginFailed  = "failed"
	LoginExpired = "expired"
)

// LoginRequest lets an app on the user's computer (Roam, a CLI) sign in
// through the browser: the app starts a request with its loopback address,
// the user signs in, Gate sends the browser back to that address with a
// one-time code, and the app collects the token with the code and its poll
// secret. Someone who starts a request and tricks another person into
// signing in never gets the code: it goes to that person's own computer.
type LoginRequest struct {
	ID        string
	ReturnURL string
	Expires   time.Time
	State     string
	Error     string
}

func (s *Store) CreateLoginRequest(ctx context.Context, id, pollSecret, returnURL string, ttl time.Duration) error {
	now := time.Now()
	_, err := s.db.ExecContext(ctx, `INSERT INTO login_requests (id, poll_hash, created, expires, state, token, error, return_url, code_hash) VALUES (?, ?, ?, ?, ?, NULL, '', ?, '')`,
		id, secure.Hash(pollSecret), ms(now), ms(now.Add(ttl)), LoginPending, returnURL)
	return err
}

// LoginRequest returns a pending, unexpired request.
func (s *Store) LoginRequest(ctx context.Context, id string) (*LoginRequest, error) {
	var r LoginRequest
	var exp int64
	err := s.db.QueryRowContext(ctx, `SELECT id, return_url, expires, state, error FROM login_requests WHERE id = ?`, id).Scan(&r.ID, &r.ReturnURL, &exp, &r.State, &r.Error)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	r.Expires = fromMs(exp)
	if r.State != LoginPending || time.Now().After(r.Expires) {
		return nil, ErrNotFound
	}
	return &r, nil
}

// FinishLoginRequest stores the session token (encrypted) and returns the
// one-time code the app needs to collect it; failure marks it failed.
func (s *Store) FinishLoginRequest(ctx context.Context, id, token, failure string) (code string, err error) {
	state, sealed, codeHash := LoginDone, s.box.Seal([]byte(token)), ""
	if failure != "" {
		state, sealed = LoginFailed, nil
	} else {
		code = secure.Token("")
		codeHash = secure.Hash(code)
	}
	err = one(s.db.ExecContext(ctx, `UPDATE login_requests SET state = ?, token = ?, error = ?, code_hash = ? WHERE id = ? AND state = ? AND expires > ?`,
		state, sealed, failure, codeHash, id, LoginPending, ms(time.Now())))
	return code, err
}

// CollectLogin hands the token over once, to the holder of the poll secret
// and the one-time code; state says where the request is otherwise.
func (s *Store) CollectLogin(ctx context.Context, id, pollSecret, code string) (token, state, failure string, err error) {
	var hash string
	var exp int64
	err = s.db.QueryRowContext(ctx, `SELECT poll_hash, state, error, expires FROM login_requests WHERE id = ?`, id).Scan(&hash, &state, &failure, &exp)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && !secure.Equal(hash, secure.Hash(pollSecret))) {
		return "", "", "", ErrNotFound
	}
	if err != nil {
		return "", "", "", err
	}
	if state == LoginPending && time.Now().After(fromMs(exp)) {
		return "", LoginExpired, "", nil
	}
	if state != LoginDone {
		return "", state, failure, nil
	}
	// Deleting and reading in one statement hands the token out exactly once.
	var sealed []byte
	err = s.db.QueryRowContext(ctx, `DELETE FROM login_requests WHERE id = ? AND state = ? AND code_hash = ? RETURNING token`,
		id, LoginDone, secure.Hash(code)).Scan(&sealed)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", "", msg.New(msg.LoginCodeInvalid)
	}
	if err != nil {
		return "", "", "", err
	}
	plain, err := s.box.Open(sealed)
	if err != nil {
		return "", "", "", err
	}
	return string(plain), LoginDone, "", nil
}

// ----------------------------------------------------------------- bindings

// Subject kinds of a binding.
const (
	SubjectUser     = "user"      // a Gate user ID
	SubjectGroup    = "group"     // a Gate group ID "<provider>:<group>"
	SubjectAWS      = "aws"       // an IAM role or user ARN, mapped through aws-auth
	SubjectK8sUser  = "k8s-user"  // a raw Kubernetes user (Google email on GKE, Entra object ID on AKS…)
	SubjectK8sGroup = "k8s-group" // a raw Kubernetes group
)

// Scopes of a binding.
const (
	ScopeCluster    = "cluster"
	ScopeNamespaces = "namespaces"
)

// Binding grants a role to a subject, cluster-wide or in some namespaces.
type Binding struct {
	ID          string    `json:"id"`
	SubjectKind string    `json:"subjectKind"`
	Subject     string    `json:"subject"`
	Role        string    `json:"role"` // a ClusterRole name: view, edit, admin, cluster-admin, or any other
	Scope       string    `json:"scope"`
	Namespaces  []string  `json:"namespaces,omitempty"`
	Note        string    `json:"note,omitempty"`
	CreatedBy   string    `json:"createdBy"`
	Created     time.Time `json:"created"`
}

func (s *Store) SaveBinding(ctx context.Context, b *Binding) error {
	if b.Created.IsZero() {
		b.Created = time.Now()
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO bindings (id, subject_kind, subject, role, scope, namespaces, note, created_by, created) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET subject_kind = excluded.subject_kind, subject = excluded.subject, role = excluded.role, scope = excluded.scope, namespaces = excluded.namespaces, note = excluded.note`,
		b.ID, b.SubjectKind, b.Subject, b.Role, b.Scope, toJSON(b.Namespaces), b.Note, b.CreatedBy, ms(b.Created))
	return err
}

func scanBinding(row interface{ Scan(...any) error }) (*Binding, error) {
	var b Binding
	var ns string
	var created int64
	if err := row.Scan(&b.ID, &b.SubjectKind, &b.Subject, &b.Role, &b.Scope, &ns, &b.Note, &b.CreatedBy, &created); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	b.Namespaces, b.Created = strs(ns), fromMs(created)
	return &b, nil
}

const bindingCols = `id, subject_kind, subject, role, scope, namespaces, note, created_by, created`

func (s *Store) Binding(ctx context.Context, id string) (*Binding, error) {
	return scanBinding(s.db.QueryRowContext(ctx, `SELECT `+bindingCols+` FROM bindings WHERE id = ?`, id))
}

func (s *Store) Bindings(ctx context.Context) ([]*Binding, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+bindingCols+` FROM bindings ORDER BY created`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Binding
	for rows.Next() {
		b, err := scanBinding(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

func (s *Store) DeleteBinding(ctx context.Context, id string) error {
	return one(s.db.ExecContext(ctx, `DELETE FROM bindings WHERE id = ?`, id))
}

// -------------------------------------------------------------------- audit

// Event kinds in the audit trail.
const (
	KindRequest = "request" // a Kubernetes API call through the proxy
	KindLogin   = "login"   // a sign-in, successful or not
	KindSession = "session" // a session ended (logout, revoke, expiry)
	KindAdmin   = "admin"   // a change to Gate's settings, users or bindings
)

// Verbs of events that aren't Kubernetes requests.
const (
	VerbLogin            = "login"
	VerbLogout           = "logout"
	ActionProviderCreate = "provider.create"
	ActionProviderUpdate = "provider.update"
	ActionProviderDelete = "provider.delete"
	ActionUserEnable     = "user.enable"
	ActionUserDisable    = "user.disable"
	ActionBindingCreate  = "binding.create"
	ActionBindingUpdate  = "binding.update"
	ActionBindingDelete  = "binding.delete"
	ActionSessionRevoke  = "session.revoke"
)

// Event is one line of the audit trail.
type Event struct {
	ID          int64     `json:"id"`
	Time        time.Time `json:"time"`
	Kind        string    `json:"kind"`
	User        string    `json:"user,omitempty"`
	Groups      []string  `json:"groups,omitempty"`
	Session     string    `json:"session,omitempty"`
	Verb        string    `json:"verb,omitempty"` // Kubernetes verb, or the action for other kinds
	Resource    string    `json:"resource,omitempty"`
	Subresource string    `json:"subresource,omitempty"`
	Namespace   string    `json:"namespace,omitempty"`
	Name        string    `json:"name,omitempty"`
	Path        string    `json:"path,omitempty"`
	Status      int       `json:"status,omitempty"`
	Allowed     bool      `json:"allowed"`
	IP          string    `json:"ip,omitempty"`
	UA          string    `json:"userAgent,omitempty"`
	DurationMs  int64     `json:"durationMs,omitempty"`
	Detail      string    `json:"detail,omitempty"` // free-form JSON: an admin change's before/after, an exec command…
}

// InsertEvents writes a batch of audit events in one transaction.
func (s *Store) InsertEvents(ctx context.Context, events []*Event) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	stmt, err := tx.PrepareContext(ctx, `INSERT INTO audit (ts, kind, user, groups, session, verb, resource, subresource, namespace, name, path, status, allowed, ip, ua, duration_ms, detail)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		tx.Rollback()
		return err
	}
	for _, e := range events {
		if _, err := stmt.ExecContext(ctx, ms(e.Time), e.Kind, e.User, toJSON(e.Groups), e.Session, e.Verb, e.Resource, e.Subresource, e.Namespace, e.Name,
			e.Path, e.Status, e.Allowed, e.IP, e.UA, e.DurationMs, e.Detail); err != nil {
			stmt.Close()
			tx.Rollback()
			return err
		}
	}
	stmt.Close()
	return tx.Commit()
}

// AuditQuery filters the trail. Results come newest first; pass the last ID
// as Before to page back.
type AuditQuery struct {
	User      string
	Kind      string
	Verb      string
	Namespace string
	Resource  string
	Text      string // matched against name, path and detail
	Denied    bool   // only denied requests and failed logins
	Since     time.Time
	Until     time.Time
	Before    int64
	Limit     int
}

func (s *Store) Audit(ctx context.Context, q AuditQuery) ([]*Event, error) {
	where := []string{"1 = 1"}
	var args []any
	add := func(cond string, v any) {
		where = append(where, cond)
		args = append(args, v)
	}
	if q.User != "" {
		add("user = ?", q.User)
	}
	if q.Kind != "" {
		add("kind = ?", q.Kind)
	}
	if q.Verb != "" {
		add("verb = ?", q.Verb)
	}
	if q.Namespace != "" {
		add("namespace = ?", q.Namespace)
	}
	if q.Resource != "" {
		add("resource = ?", q.Resource)
	}
	if q.Denied {
		where = append(where, "allowed = 0")
	}
	if !q.Since.IsZero() {
		add("ts >= ?", ms(q.Since))
	}
	if !q.Until.IsZero() {
		add("ts < ?", ms(q.Until))
	}
	if q.Before > 0 {
		add("id < ?", q.Before)
	}
	if q.Text != "" {
		like := "%" + strings.NewReplacer(`\`, `\\`, "%", `\%`, "_", `\_`).Replace(q.Text) + "%"
		where = append(where, `(name LIKE ? ESCAPE '\' OR path LIKE ? ESCAPE '\' OR detail LIKE ? ESCAPE '\')`)
		args = append(args, like, like, like)
	}
	if q.Limit <= 0 || q.Limit > 1000 {
		q.Limit = 200
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, ts, kind, user, groups, session, verb, resource, subresource, namespace, name, path, status, allowed, ip, ua, duration_ms, detail
		FROM audit WHERE `+strings.Join(where, " AND ")+` ORDER BY id DESC LIMIT ?`, append(args, q.Limit)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Event
	for rows.Next() {
		var e Event
		var ts int64
		var groups string
		if err := rows.Scan(&e.ID, &ts, &e.Kind, &e.User, &groups, &e.Session, &e.Verb, &e.Resource, &e.Subresource, &e.Namespace, &e.Name,
			&e.Path, &e.Status, &e.Allowed, &e.IP, &e.UA, &e.DurationMs, &e.Detail); err != nil {
			return nil, err
		}
		e.Time, e.Groups = fromMs(ts), strs(groups)
		out = append(out, &e)
	}
	return out, rows.Err()
}

const pruneBatch = 5000

// Prune drops audit events older than the retention, and sessions and login
// requests that ended more than a day ago.
func (s *Store) Prune(ctx context.Context, retention time.Duration) (int64, error) {
	cutoff := ms(time.Now().Add(-retention))
	// In batches: one huge DELETE would hold the write lock while new events wait.
	var n int64
	for {
		r, err := s.db.ExecContext(ctx, `DELETE FROM audit WHERE id IN (SELECT id FROM audit WHERE ts < ? LIMIT ?)`, cutoff, pruneBatch)
		if err != nil {
			return n, err
		}
		k, _ := r.RowsAffected()
		n += k
		if k < pruneBatch {
			break
		}
	}
	day := ms(time.Now().Add(-24 * time.Hour))
	if _, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires < ? OR (revoked = 1 AND last_used < ?)`, day, day); err != nil {
		return n, err
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM login_requests WHERE expires < ?`, day)
	return n, err
}
