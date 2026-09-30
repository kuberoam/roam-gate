package server

import (
	"context"
	"encoding/json"
	"net/http"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/kuberoam/roam-gate/internal/auth"
	"github.com/kuberoam/roam-gate/internal/policy"
	"github.com/kuberoam/roam-gate/internal/proxy"
	"github.com/kuberoam/roam-gate/internal/secure"
	"github.com/kuberoam/roam-gate/internal/store"
)

// ------------------------------------------------------------------- public

func (s *Server) info(w http.ResponseWriter, r *http.Request) {
	ps, err := s.enabledProviders(r.Context())
	if err != nil {
		failErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"name": "roam-gate", "version": Version, "cluster": s.cfg.ClusterName, "externalURL": s.cfg.ExternalURL,
		"providers": ps, "providerTypes": auth.Types,
	})
}

// ---------------------------------------------------------------- signed in

func (s *Server) me(w http.ResponseWriter, r *http.Request, p *auth.Principal) {
	out := map[string]any{"user": p.Name(), "admin": p.Admin}
	if p.Session != nil {
		out["groups"], out["expires"], out["session"] = p.Session.Groups, p.Session.Expires, p.Session.ID
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request, p *auth.Principal) {
	if p.Session == nil {
		fail(w, http.StatusBadRequest, "the bootstrap admin token has no session")
		return
	}
	if err := s.st.RevokeSession(r.Context(), p.Session.ID); err != nil {
		failErr(w, err)
		return
	}
	s.rec.Record(&store.Event{Kind: store.KindSession, User: p.Session.User, Groups: p.Session.Groups, Session: p.Session.ID,
		Verb: "logout", Allowed: true, IP: proxy.ClientIP(r), UA: r.UserAgent()})
	w.WriteHeader(http.StatusNoContent)
}

// kubeconfig returns a kubeconfig for the calling session (Roam writes it for the user).
func (s *Server) kubeconfig(w http.ResponseWriter, r *http.Request, p *auth.Principal) {
	if p.Session == nil {
		fail(w, http.StatusBadRequest, "sign in with SSO to get a kubeconfig")
		return
	}
	w.Header().Set("Content-Type", "application/yaml")
	w.Write([]byte(s.kubeconfigYAML(p.Session, auth.BearerToken(r))))
}

// ---------------------------------------------------------------- providers

type providerOut struct {
	*store.Provider
	CallbackURL string `json:"callbackURL"`
}

func (s *Server) listProviders(w http.ResponseWriter, r *http.Request, _ *auth.Principal) {
	ps, err := s.st.Providers(r.Context())
	if err != nil {
		failErr(w, err)
		return
	}
	out := make([]providerOut, 0, len(ps))
	for _, p := range ps {
		p.Config = auth.Redacted(p)
		out = append(out, providerOut{p, s.cfg.ExternalURL + "/auth/" + p.ID + "/callback"})
	}
	writeJSON(w, http.StatusOK, out)
}

var idRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,39}$`)

func (s *Server) saveProvider(w http.ResponseWriter, r *http.Request, pr *auth.Principal) {
	var in store.Provider
	if err := readJSON(r, &in); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	ctx := r.Context()
	action := "provider.create"
	var before *store.Provider
	if id := r.PathValue("id"); id != "" {
		old, err := s.st.Provider(ctx, id)
		if err != nil {
			failErr(w, err)
			return
		}
		in.ID, in.Created, action, before = id, old.Created, "provider.update", old
		in.Config = auth.MergeSecrets(old.Config, in.Config)
	} else {
		if in.ID == "" {
			in.ID = in.Type
		}
		if _, err := s.st.Provider(ctx, in.ID); err == nil {
			fail(w, http.StatusConflict, "a provider with ID "+in.ID+" already exists")
			return
		}
	}
	if !idRe.MatchString(in.ID) {
		fail(w, http.StatusBadRequest, "ID must be lowercase letters, digits and dashes (it becomes part of group names)")
		return
	}
	if !slices.Contains(auth.Types, in.Type) {
		fail(w, http.StatusBadRequest, "type must be one of "+strings.Join(auth.Types, ", "))
		return
	}
	if strings.TrimSpace(in.Name) == "" {
		in.Name = in.ID
	}
	if len(in.Config) == 0 {
		in.Config = json.RawMessage("{}")
	}
	// Check the settings now (discovery, required fields) rather than at the first sign-in.
	if _, err := auth.Build(ctx, &in, s.cfg.ExternalURL+"/auth/"+in.ID+"/callback"); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.st.SaveProvider(ctx, &in); err != nil {
		failErr(w, err)
		return
	}
	d := map[string]any{"after": map[string]any{"type": in.Type, "name": in.Name, "enabled": in.Enabled, "config": auth.Redacted(&in)}}
	if before != nil {
		d["before"] = map[string]any{"type": before.Type, "name": before.Name, "enabled": before.Enabled, "config": auth.Redacted(before)}
	}
	s.adminEvent(r, pr, action, in.ID, d)
	in.Config = auth.Redacted(&in)
	writeJSON(w, http.StatusOK, providerOut{&in, s.cfg.ExternalURL + "/auth/" + in.ID + "/callback"})
}

func (s *Server) deleteProvider(w http.ResponseWriter, r *http.Request, p *auth.Principal) {
	id := r.PathValue("id")
	if err := s.st.DeleteProvider(r.Context(), id); err != nil {
		failErr(w, err)
		return
	}
	s.adminEvent(r, p, "provider.delete", id, nil)
	w.WriteHeader(http.StatusNoContent)
}

// testProvider checks a provider's settings: discovery for OIDC, and for LDAP
// a sign-in when a username and password are given.
func (s *Server) testProvider(w http.ResponseWriter, r *http.Request, _ *auth.Principal) {
	sp, err := s.st.Provider(r.Context(), r.PathValue("id"))
	if err != nil {
		failErr(w, err)
		return
	}
	p, err := auth.Build(r.Context(), sp, s.cfg.ExternalURL+"/auth/"+sp.ID+"/callback")
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	_ = json.NewDecoder(http.MaxBytesReader(nil, r.Body, 1<<16)).Decode(&body)
	if pl, ok := p.(auth.PasswordLogin); ok && body.Username != "" {
		id, err := pl.Login(r.Context(), body.Username, body.Password)
		if err != nil {
			writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "user": id.UserID(), "groups": id.GroupIDs()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// -------------------------------------------------------------------- users

func (s *Server) listUsers(w http.ResponseWriter, r *http.Request, _ *auth.Principal) {
	us, err := s.st.Users(r.Context())
	if err != nil {
		failErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, us)
}

func (s *Server) patchUser(w http.ResponseWriter, r *http.Request, p *auth.Principal) {
	var body struct {
		Disabled *bool `json:"disabled"`
	}
	if err := readJSON(r, &body); err != nil || body.Disabled == nil {
		fail(w, http.StatusBadRequest, `send {"disabled": true|false}`)
		return
	}
	id := r.PathValue("id")
	if err := s.st.SetUserDisabled(r.Context(), id, *body.Disabled); err != nil {
		failErr(w, err)
		return
	}
	action := "user.enable"
	if *body.Disabled {
		action = "user.disable"
	}
	s.adminEvent(r, p, action, id, nil)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) listGroups(w http.ResponseWriter, r *http.Request, _ *auth.Principal) {
	gs, err := s.st.Groups(r.Context())
	if err != nil {
		failErr(w, err)
		return
	}
	type group struct {
		ID    string `json:"id"`
		Users int    `json:"users"`
	}
	out := make([]group, 0, len(gs))
	for id, n := range gs {
		out = append(out, group{id, n})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	writeJSON(w, http.StatusOK, out)
}

// ----------------------------------------------------------------- bindings

type bindingOut struct {
	*store.Binding
	Status *policy.Status `json:"status,omitempty"`
}

func (s *Server) listBindings(w http.ResponseWriter, r *http.Request, _ *auth.Principal) {
	bs, err := s.st.Bindings(r.Context())
	if err != nil {
		failErr(w, err)
		return
	}
	statuses, _, _ := s.policy.Statuses()
	out := make([]bindingOut, 0, len(bs))
	for _, b := range bs {
		o := bindingOut{Binding: b}
		if st, ok := statuses[b.ID]; ok {
			o.Status = &st
		}
		out = append(out, o)
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) saveBinding(w http.ResponseWriter, r *http.Request, p *auth.Principal) {
	var in store.Binding
	if err := readJSON(r, &in); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	ctx := r.Context()
	action := "binding.create"
	var before *store.Binding
	if id := r.PathValue("id"); id != "" {
		old, err := s.st.Binding(ctx, id)
		if err != nil {
			failErr(w, err)
			return
		}
		in.ID, in.Created, in.CreatedBy, action, before = id, old.Created, old.CreatedBy, "binding.update", old
	} else {
		in.ID, in.CreatedBy, in.Created = secure.Name(), p.Name(), time.Time{}
	}
	in.Subject = strings.TrimSpace(in.Subject)
	if err := policy.Validate(&in); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.st.SaveBinding(ctx, &in); err != nil {
		failErr(w, err)
		return
	}
	s.adminEvent(r, p, action, in.ID, map[string]any{"before": before, "after": in})
	s.policy.Trigger()
	writeJSON(w, http.StatusOK, in)
}

func (s *Server) deleteBinding(w http.ResponseWriter, r *http.Request, p *auth.Principal) {
	ctx := r.Context()
	id := r.PathValue("id")
	old, err := s.st.Binding(ctx, id)
	if err == nil {
		err = s.st.DeleteBinding(ctx, id)
	}
	if err != nil {
		failErr(w, err)
		return
	}
	s.adminEvent(r, p, "binding.delete", id, map[string]any{"before": old})
	s.policy.Trigger()
	w.WriteHeader(http.StatusNoContent)
}

// ----------------------------------------------------------------- sessions

func (s *Server) listSessions(w http.ResponseWriter, r *http.Request, _ *auth.Principal) {
	ss, err := s.st.Sessions(r.Context(), r.URL.Query().Get("user"), r.URL.Query().Get("all") == "true")
	if err != nil {
		failErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, ss)
}

func (s *Server) revokeSession(w http.ResponseWriter, r *http.Request, p *auth.Principal) {
	id := r.PathValue("id")
	if err := s.st.RevokeSession(r.Context(), id); err != nil {
		failErr(w, err)
		return
	}
	s.adminEvent(r, p, "session.revoke", id, nil)
	w.WriteHeader(http.StatusNoContent)
}

// -------------------------------------------------------------------- audit

func (s *Server) queryAudit(w http.ResponseWriter, r *http.Request, _ *auth.Principal) {
	q := r.URL.Query()
	parseTime := func(k string) (time.Time, error) {
		v := q.Get(k)
		if v == "" {
			return time.Time{}, nil
		}
		return time.Parse(time.RFC3339, v)
	}
	var aq store.AuditQuery
	var err error
	if aq.Since, err = parseTime("since"); err != nil {
		fail(w, http.StatusBadRequest, "since: use RFC 3339, e.g. 2026-10-01T00:00:00Z")
		return
	}
	if aq.Until, err = parseTime("until"); err != nil {
		fail(w, http.StatusBadRequest, "until: use RFC 3339")
		return
	}
	aq.User, aq.Kind, aq.Verb, aq.Namespace, aq.Resource, aq.Text = q.Get("user"), q.Get("kind"), q.Get("verb"), q.Get("namespace"), q.Get("resource"), q.Get("q")
	aq.Denied = q.Get("denied") == "true"
	aq.Before, _ = strconv.ParseInt(q.Get("before"), 10, 64)
	aq.Limit, _ = strconv.Atoi(q.Get("limit"))
	events, err := s.st.Audit(r.Context(), aq)
	if err != nil {
		failErr(w, err)
		return
	}
	if events == nil {
		events = []*store.Event{}
	}
	writeJSON(w, http.StatusOK, events)
}

// ------------------------------------------------------------------ cluster

// clusterRoles lists ClusterRoles a binding can grant (system ones hidden).
func (s *Server) clusterRoles(w http.ResponseWriter, r *http.Request, _ *auth.Principal) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	list, err := s.kc.RBAC.ClusterRoles().List(ctx, metav1.ListOptions{})
	if err != nil {
		failErr(w, err)
		return
	}
	out := []string{}
	for _, x := range list.Items {
		if !strings.HasPrefix(x.Name, "system:") {
			out = append(out, x.Name)
		}
	}
	sort.Strings(out)
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) namespaces(w http.ResponseWriter, r *http.Request, _ *auth.Principal) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	list, err := s.kc.Core.Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		failErr(w, err)
		return
	}
	out := make([]string, 0, len(list.Items))
	for _, x := range list.Items {
		out = append(out, x.Name)
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) status(w http.ResponseWriter, r *http.Request, _ *auth.Principal) {
	_, last, lastErr := s.policy.Statuses()
	objs, err := s.policy.ManagedObjects(r.Context())
	out := map[string]any{"version": Version, "reconciled": last, "reconcileError": lastErr, "managedObjects": objs}
	if err != nil {
		out["managedObjectsError"] = err.Error()
	}
	writeJSON(w, http.StatusOK, out)
}
