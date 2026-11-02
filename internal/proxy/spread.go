package proxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"

	"github.com/kuberoam/roam-gate/internal/identity"
	"github.com/kuberoam/roam-gate/internal/store"
)

// A binding of scope "namespaces" is a RoleBinding in each namespace, so the
// API server refuses its person every list and watch across all namespaces
// (GET /api/v1/pods, /api/v1/namespaces) — which is how apps, Roam's
// included, and `kubectl -A` read a cluster. When the API server refuses one,
// Gate asks again in each namespace the person was granted, still as them,
// and answers with the results together: the API server still decides
// everything, and namespaces it refuses are left out.

// Granted lists the namespaces granted one by one to a Kubernetes user or
// any of its groups.
type Granted interface {
	Namespaces(ctx context.Context, user string, groups []string) ([]string, error)
	// Version changes whenever Gate's bindings or the cluster's RBAC do; ok
	// is false while Gate can't tell, and then nothing is remembered.
	Version() (v uint64, ok bool)
}

// spreadLimit is how many namespaces are asked at once for one request.
const spreadLimit = 8

// spreadMemo remembers the sessions whose list or watch of a resource the API
// server refused across namespaces and Gate answered from namespaces, so the
// next one (an app's refresh, a watch again after each disconnect) skips the
// refused request. An entry holds while the RBAC version it was learnt under
// does: any change to bindings or RBAC, and the request is tried again.
type spreadMemo struct {
	mu sync.Mutex
	m  map[memoKey]uint64 // → the version
}

type memoKey struct{ session, group, resource string }

// memoMax bounds the memo; past it, it starts over.
const memoMax = 50000

func (m *spreadMemo) known(k memoKey, version uint64) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.m[k]
	return ok && v == version
}

func (m *spreadMemo) set(k memoKey, version uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.m == nil || len(m.m) >= memoMax {
		m.m = map[memoKey]uint64{}
	}
	m.m[k] = version
}

func (m *spreadMemo) forget(k memoKey) {
	m.mu.Lock()
	delete(m.m, k)
	m.mu.Unlock()
}

// prune drops what was learnt under another version than the current one.
func (m *spreadMemo) prune(version uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	maps.DeleteFunc(m.m, func(_ memoKey, v uint64) bool { return v != version })
}

// outcome is what asking each namespace came to.
type outcome int

const (
	answered   outcome = iota // the merged result, or an error, was sent
	refusedAll                // refused in every namespace: nothing was sent
)

// spreadable: a list or watch across all namespaces (or of the namespaces).
func spreadable(r *http.Request, info RequestInfo) bool {
	return r.Method == http.MethodGet && info.IsResource && info.Resource != "" && info.Namespace == "" && info.Name == "" &&
		info.Subresource == "" && (info.Verb == "list" || info.Verb == "watch") && r.Header.Get("Upgrade") == ""
}

func (p *Proxy) spread(w http.ResponseWriter, r *http.Request, info RequestInfo, path string, sess *store.Session) {
	if info.Resource != "namespaces" {
		if namespaced, known := p.namespaced(r.Context(), apiPrefix(path), info.Resource); known && !namespaced {
			p.rp.ServeHTTP(w, r) // nodes, PersistentVolumes…: no namespace to ask in
			return
		}
	}
	key := memoKey{sess.ID, info.APIGroup, info.Resource}
	version, remember := p.granted.Version()
	if remember && p.memo.known(key, version) {
		if nss := p.grantedTo(r.Context(), sess); len(nss) > 0 && p.each(w, r, info, path, nss, nil) == answered {
			return
		}
		p.memo.forget(key) // granted no more: ask across namespaces again
	}

	refused := &refusal{w: w, h: http.Header{}}
	p.rp.ServeHTTP(refused, r)
	if refused.code != http.StatusForbidden {
		return
	}
	learnt := func() {
		if remember {
			p.memo.set(key, version)
		}
	}
	if nss := p.grantedTo(r.Context(), sess); len(nss) > 0 && p.each(w, r, info, path, nss, learnt) == answered {
		return
	}
	refused.replay()
}

func (p *Proxy) grantedTo(ctx context.Context, sess *store.Session) []string {
	nss, err := p.granted.Namespaces(ctx, identity.KubeUser(sess.User), identity.KubeGroups(sess.Groups))
	if err != nil {
		slog.Warn("granted namespaces", "err", err)
	}
	return nss
}

// each answers from the namespaces; ok, if given, is called once some of
// them answered.
func (p *Proxy) each(w http.ResponseWriter, r *http.Request, info RequestInfo, path string, nss []string, ok func()) outcome {
	if ok == nil {
		ok = func() {}
	}
	q := r.URL.Query()
	q.Del("limit") // pages can't be continued across namespaces
	q.Del("continue")
	var sel *nsSelector
	if info.Resource == "namespaces" {
		var err error
		if sel, nss, err = namespaceSelector(q, nss); err != nil {
			writeStatus(w, http.StatusBadRequest, err.Error())
			return answered
		}
		if len(nss) == 0 {
			return refusedAll
		}
	}
	if info.Verb == "watch" {
		return p.watchEach(w, r, info, path, q, nss, ok)
	}
	return p.listEach(w, r, info, path, q, nss, sel, ok)
}

// askEach asks every namespace, spreadLimit at a time.
func (p *Proxy) askEach(ctx context.Context, r *http.Request, info RequestInfo, path string, q url.Values, nss []string, read bool) []answer {
	answers := make([]answer, len(nss))
	sem := make(chan struct{}, spreadLimit)
	var wg sync.WaitGroup
	for i, ns := range nss {
		wg.Go(func() {
			sem <- struct{}{}
			defer func() { <-sem }()
			a := &answers[i]
			if a.resp, a.err = p.ask(ctx, r, info, path, q, ns); a.err == nil && read {
				a.body, a.err = io.ReadAll(a.resp.Body)
				a.resp.Body.Close()
			}
		})
	}
	wg.Wait()
	return answers
}

// refusal passes a response through, except a 403, which it keeps.
type refusal struct {
	w    http.ResponseWriter
	h    http.Header
	code int
	body bytes.Buffer
}

func (f *refusal) Header() http.Header { return f.h }

func (f *refusal) WriteHeader(code int) {
	if f.code != 0 {
		return
	}
	f.code = code
	if code != http.StatusForbidden {
		maps.Copy(f.w.Header(), f.h)
		f.w.WriteHeader(code)
	}
}

func (f *refusal) Write(b []byte) (int, error) {
	if f.code == 0 {
		f.WriteHeader(http.StatusOK)
	}
	if f.code == http.StatusForbidden {
		return f.body.Write(b)
	}
	return f.w.Write(b)
}

func (f *refusal) Flush() {
	if f.code != 0 && f.code != http.StatusForbidden {
		http.NewResponseController(f.w).Flush()
	}
}

// replay sends the kept 403.
func (f *refusal) replay() {
	maps.Copy(f.w.Header(), f.h)
	f.w.WriteHeader(http.StatusForbidden)
	f.w.Write(f.body.Bytes())
}

// apiPrefix is the group version a request path is under: "api/v1" or
// "apis/group/version".
func apiPrefix(path string) string {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	n := 2
	if parts[0] == "apis" {
		n = 3
	}
	return strings.Join(parts[:min(n, len(parts))], "/")
}

// inNamespace is path asked in namespace ns: /api/v1/pods →
// /api/v1/namespaces/ns/pods; the namespaces themselves → /api/v1/namespaces/ns,
// which a RoleBinding in ns lets its person get and watch.
func inNamespace(path string, info RequestInfo, ns string) string {
	prefix := apiPrefix(path)
	out := []string{prefix}
	legacyWatch := strings.HasPrefix(strings.TrimPrefix(strings.Trim(path, "/"), prefix), "/watch/")
	if legacyWatch || (info.Resource == "namespaces" && info.Verb == "watch") {
		out = append(out, "watch") // one namespace is watched only on the legacy path
	}
	out = append(out, "namespaces", ns)
	if info.Resource != "namespaces" {
		out = append(out, info.Resource)
	}
	return "/" + strings.Join(out, "/")
}

// upstream is a GET of path on the API server, as Gate unless the caller adds
// impersonation headers.
func (p *Proxy) upstream(ctx context.Context, path string, q url.Values) (*http.Request, error) {
	u := *p.target
	u.Path = strings.TrimRight(u.Path, "/") + path
	u.RawPath = ""
	u.RawQuery = q.Encode()
	return http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
}

// ask sends the request again, in namespace ns, as the same person.
func (p *Proxy) ask(ctx context.Context, r *http.Request, info RequestInfo, path string, q url.Values, ns string) (*http.Response, error) {
	accept := jsonOnly(r.Header.Get("Accept"))
	if info.Resource == "namespaces" {
		q = maps.Clone(q)
		q.Del("watch") // the path says it
		q.Del("fieldSelector")
		if info.Verb == "list" {
			q.Del("labelSelector") // a GET ignores it; listEach applies it
		}
		// A namespace is one object: metadata-only clients get it as one.
		accept = strings.ReplaceAll(accept, "as=PartialObjectMetadataList", "as=PartialObjectMetadata")
	}
	req, err := p.upstream(ctx, inNamespace(path, info, ns), q)
	if err != nil {
		return nil, err
	}
	req.Header = r.Header.Clone()
	for _, h := range []string{"Accept-Encoding", "Connection", "Keep-Alive", "Te", "Upgrade", "Content-Length"} {
		req.Header.Del(h)
	}
	req.Header.Set("Accept", accept)
	return p.client.Do(req)
}

// jsonOnly drops protobuf from an Accept header: Gate merges JSON. Clients
// that take protobuf take JSON too.
func jsonOnly(accept string) string {
	var keep []string
	for _, a := range strings.Split(accept, ",") {
		if a = strings.TrimSpace(a); a != "" && !strings.Contains(a, "protobuf") {
			keep = append(keep, a)
		}
	}
	if len(keep) == 0 {
		return "application/json"
	}
	return strings.Join(keep, ",")
}

// skipped: the API server refuses this namespace too.
func skipped(code int) bool { return code == http.StatusForbidden || code == http.StatusNotFound }

// nsSelector is a list of namespaces' selectors, applied by Gate: each
// namespace is got as one object, and a GET ignores selectors.
type nsSelector struct {
	labels labels.Selector
	fields fields.Selector
}

// namespaceSelector reads the selectors of a list or watch of namespaces, and
// narrows nss to the one metadata.name asks for.
func namespaceSelector(q url.Values, nss []string) (*nsSelector, []string, error) {
	sel := &nsSelector{labels: labels.Everything(), fields: fields.Everything()}
	var err error
	if s := q.Get("labelSelector"); s != "" {
		if sel.labels, err = labels.Parse(s); err != nil {
			return nil, nil, err
		}
	}
	if s := q.Get("fieldSelector"); s != "" {
		if sel.fields, err = fields.ParseSelector(s); err != nil {
			return nil, nil, err
		}
		if name, ok := sel.fields.RequiresExactMatch("metadata.name"); ok {
			if !slices.Contains(nss, name) {
				return sel, nil, nil
			}
			nss = []string{name}
		}
	}
	return sel, nss, nil
}

// matches says whether a namespace (a Namespace, its metadata or a table of
// one row) passes the selectors.
func (s *nsSelector) matches(body []byte) bool {
	var obj struct {
		Kind     string                 `json:"kind"`
		Metadata nsMeta                 `json:"metadata"`
		Status   struct{ Phase string } `json:"status"`
		Rows     []struct {
			Object struct {
				Metadata nsMeta `json:"metadata"`
			} `json:"object"`
		} `json:"rows"`
	}
	if json.Unmarshal(body, &obj) != nil {
		return true
	}
	m := obj.Metadata
	if obj.Kind == "Table" {
		if len(obj.Rows) != 1 {
			return true
		}
		m = obj.Rows[0].Object.Metadata
	}
	return s.labels.Matches(labels.Set(m.Labels)) &&
		s.fields.Matches(fields.Set{"metadata.name": m.Name, "status.phase": obj.Status.Phase})
}

type nsMeta struct {
	Name   string            `json:"name"`
	Labels map[string]string `json:"labels"`
}

type answer struct {
	resp *http.Response
	body []byte
	err  error
}

func (p *Proxy) listEach(w http.ResponseWriter, r *http.Request, info RequestInfo, path string, q url.Values, nss []string, sel *nsSelector, ok func()) outcome {
	var rv *string
	if info.Resource == "namespaces" {
		// Got one by one, the namespaces carry only when each last changed: a
		// watch from there would be told it's too old, again and again. The
		// cluster's revision, read before them, misses no change after it.
		cur := p.revision(r.Context())
		rv = &cur
	}
	answers := p.askEach(r.Context(), r, info, path, q, nss, true)
	var got []answer
	for _, a := range answers {
		switch {
		case a.err != nil:
			writeStatus(w, http.StatusBadGateway, a.err.Error())
			return answered
		case skipped(a.resp.StatusCode):
		case a.resp.StatusCode >= 300:
			copyHeader(w, a.resp)
			w.WriteHeader(a.resp.StatusCode)
			w.Write(a.body)
			return answered
		default:
			got = append(got, a)
		}
	}
	if len(got) == 0 {
		return refusedAll
	}
	l, err := parseAnswers(got, sel)
	if err != nil {
		writeStatus(w, http.StatusBadGateway, err.Error())
		return answered
	}
	ok()
	copyHeader(w, got[0].resp)
	w.WriteHeader(http.StatusOK)
	l.write(w, rv)
	return answered
}

func copyHeader(w http.ResponseWriter, resp *http.Response) {
	if ct := resp.Header.Get("Content-Type"); ct != "" {
		w.Header().Set("Content-Type", ct)
	}
}

// merged is the namespaces' answers as one list: the items of lists, the rows
// of tables (kubectl), and single objects (a namespace) as the items of a list.
type merged struct {
	head   map[string]json.RawMessage // the first answer, without its items
	field  string                     // "items" or "rows"
	items  [][]byte                   // each answer's items, without the brackets
	oldest uint64                     // the oldest of their resourceVersions
}

func parseAnswers(got []answer, sel *nsSelector) (*merged, error) {
	l := &merged{field: "items"}
	for _, a := range got {
		var m map[string]json.RawMessage
		if err := json.Unmarshal(a.body, &m); err != nil {
			return nil, err
		}
		var kind string
		json.Unmarshal(m["kind"], &kind)
		var meta struct {
			ResourceVersion string `json:"resourceVersion"`
		}
		json.Unmarshal(m["metadata"], &meta)
		single := kind != "Table" && m["items"] == nil
		if n, err := strconv.ParseUint(meta.ResourceVersion, 10, 64); err == nil && !single && (l.oldest == 0 || n < l.oldest) {
			// The oldest, so the watch that follows misses no namespace's
			// changes (it may send some twice; clients take that).
			l.oldest = n
		}
		if sel != nil && !sel.matches(a.body) {
			continue
		}
		var part json.RawMessage
		switch {
		case kind == "Table":
			l.field, part = "rows", m["rows"]
		case !single:
			part = m["items"]
		default:
			part = a.body
			m = map[string]json.RawMessage{"kind": json.RawMessage(strconv.Quote(kind + "List")), "apiVersion": m["apiVersion"]}
		}
		if l.head == nil {
			l.head = m
		}
		if !single {
			part = bytes.TrimSpace(part)
			part = bytes.TrimSpace(bytes.TrimSuffix(bytes.TrimPrefix(part, []byte("[")), []byte("]")))
		}
		if len(part) > 0 && !bytes.Equal(part, []byte("null")) {
			l.items = append(l.items, part)
		}
	}
	if l.head == nil { // all filtered out: a list of the first answer's kind
		l.head = map[string]json.RawMessage{}
		var m map[string]json.RawMessage
		json.Unmarshal(got[0].body, &m)
		var kind string
		json.Unmarshal(m["kind"], &kind)
		if kind != "Table" && !strings.HasSuffix(kind, "List") {
			kind += "List"
		}
		l.head["kind"], l.head["apiVersion"] = json.RawMessage(strconv.Quote(kind)), m["apiVersion"]
	}
	return l, nil
}

// write sends the list; rv, when given, is its resourceVersion ("" for none),
// otherwise the oldest of the answers'.
func (l *merged) write(w io.Writer, rv *string) {
	meta := map[string]json.RawMessage{}
	json.Unmarshal(l.head["metadata"], &meta)
	delete(meta, "continue")
	delete(meta, "remainingItemCount")
	delete(meta, "resourceVersion")
	v := ""
	if rv != nil {
		v = *rv
	} else if l.oldest > 0 {
		v = strconv.FormatUint(l.oldest, 10)
	}
	if v != "" {
		meta["resourceVersion"] = json.RawMessage(strconv.Quote(v))
	}
	bw := bufio.NewWriter(w)
	defer bw.Flush()
	bw.WriteByte('{')
	for _, k := range slices.Sorted(maps.Keys(l.head)) {
		if k == l.field || k == "metadata" || k == "items" || k == "rows" {
			continue
		}
		key, _ := json.Marshal(k)
		bw.Write(key)
		bw.WriteByte(':')
		bw.Write(l.head[k])
		bw.WriteByte(',')
	}
	m, _ := json.Marshal(meta)
	bw.WriteString(`"metadata":`)
	bw.Write(m)
	bw.WriteString(`,"` + l.field + `":[`)
	for i, part := range l.items {
		if i > 0 {
			bw.WriteByte(',')
		}
		bw.Write(part)
	}
	bw.WriteString("]}")
}

// revision is the cluster's current resourceVersion, asked as Gate (which may
// list namespaces), or "" if it can't be had.
func (p *Proxy) revision(ctx context.Context) string {
	req, err := p.upstream(ctx, "/api/v1/namespaces", url.Values{"limit": {"1"}})
	if err != nil {
		return ""
	}
	req.Header.Set("Accept", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	var l struct {
		Metadata struct {
			ResourceVersion string `json:"resourceVersion"`
		} `json:"metadata"`
	}
	if resp.StatusCode != http.StatusOK || json.NewDecoder(resp.Body).Decode(&l) != nil {
		return ""
	}
	return l.Metadata.ResourceVersion
}

// expired ends a merged watch: events of several namespaces can't be put in
// resourceVersion order, so resuming from the last one sent could skip
// another namespace's. 410 makes clients list again instead.
const expired = `{"type":"ERROR","object":{"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"watch across namespaces ended; list again","reason":"Expired","code":410}}` + "\n"

// watchEach watches every namespace and sends their events as one stream,
// which ends when any of them does.
func (p *Proxy) watchEach(w http.ResponseWriter, r *http.Request, info RequestInfo, path string, q url.Values, nss []string, ok func()) outcome {
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	answers := p.askEach(ctx, r, info, path, q, nss, false)

	var open []*http.Response
	defer func() {
		for _, a := range answers {
			if a.err == nil {
				a.resp.Body.Close()
			}
		}
	}()
	for _, a := range answers {
		switch {
		case a.err != nil:
			writeStatus(w, http.StatusBadGateway, a.err.Error())
			return answered
		case skipped(a.resp.StatusCode):
			a.resp.Body.Close() // not kept open for as long as the watch lasts
		case a.resp.StatusCode >= 300:
			copyHeader(w, a.resp)
			w.WriteHeader(a.resp.StatusCode)
			io.Copy(w, a.resp.Body)
			return answered
		default:
			open = append(open, a.resp)
		}
	}
	if len(open) == 0 {
		return refusedAll
	}
	ok()
	copyHeader(w, open[0])
	w.WriteHeader(http.StatusOK)
	flush := http.NewResponseController(w).Flush
	flush()

	b := &bookmarks{initial: q.Get("sendInitialEvents") == "true", pending: len(open)}
	var mu sync.Mutex
	clientGone := false
	var streams sync.WaitGroup
	for _, resp := range open {
		streams.Go(func() {
			defer cancel()
			br := bufio.NewReaderSize(resp.Body, 64<<10)
			for {
				line, err := br.ReadBytes('\n')
				if len(line) > 0 {
					if line = b.filter(line); line != nil {
						mu.Lock()
						_, werr := w.Write(line)
						flush()
						clientGone = clientGone || werr != nil
						mu.Unlock()
						if werr != nil {
							return
						}
					}
				}
				if err != nil {
					return
				}
			}
		})
	}
	<-ctx.Done()
	for _, resp := range open {
		resp.Body.Close() // unblocks the readers
	}
	streams.Wait()
	if r.Context().Err() == nil && !clientGone {
		w.Write([]byte(expired))
		flush()
	}
	return answered
}

// bookmarks filters a merged watch's bookmarks. One namespace's would let the
// client resume past events of another it hasn't been sent yet, so they are
// dropped — except, with sendInitialEvents, the bookmark that ends the
// initial events: the client waits for one, so it is sent once every
// namespace has sent its own, at the oldest of their resourceVersions.
type bookmarks struct {
	initial bool
	mu      sync.Mutex
	pending int
	oldest  uint64
}

func (b *bookmarks) filter(line []byte) []byte {
	if !bytes.Contains(line, []byte(`"BOOKMARK"`)) {
		return line
	}
	var e struct {
		Type   string                     `json:"type"`
		Object map[string]json.RawMessage `json:"object"`
	}
	if json.Unmarshal(line, &e) != nil || e.Type != "BOOKMARK" {
		return line
	}
	var meta struct {
		ResourceVersion string            `json:"resourceVersion"`
		Annotations     map[string]string `json:"annotations"`
	}
	json.Unmarshal(e.Object["metadata"], &meta)
	if !b.initial || meta.Annotations["k8s.io/initial-events-end"] != "true" {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if n, err := strconv.ParseUint(meta.ResourceVersion, 10, 64); err == nil && (b.oldest == 0 || n < b.oldest) {
		b.oldest = n
	}
	if b.pending--; b.pending > 0 {
		return nil
	}
	var m map[string]json.RawMessage
	json.Unmarshal(e.Object["metadata"], &m)
	m["resourceVersion"] = json.RawMessage(strconv.Quote(strconv.FormatUint(b.oldest, 10)))
	e.Object["metadata"], _ = json.Marshal(m)
	out, err := json.Marshal(e)
	if err != nil {
		return line
	}
	return append(out, '\n')
}

// Whether a resource is namespaced, from the API server's discovery (asked
// as Gate). A resource not found there is asked again, at most every
// discoveryRetry; what is found is read again after discoveryTTL.
const (
	discoveryRetry = 10 * time.Second
	discoveryTTL   = 5 * time.Minute
)

type scopes struct {
	mu sync.Mutex
	gv map[string]*gvScope // by apiPrefix
}

type gvScope struct {
	namespaced map[string]bool
	fetched    time.Time
}

// namespaced says whether resource under prefix is namespaced; known is false
// when discovery doesn't say.
func (p *Proxy) namespaced(ctx context.Context, prefix, resource string) (namespaced, known bool) {
	p.scopes.mu.Lock()
	s := p.scopes.gv[prefix]
	if s != nil {
		n, found := s.namespaced[resource]
		age := time.Since(s.fetched)
		if (found && age < discoveryTTL) || (!found && age < discoveryRetry) {
			p.scopes.mu.Unlock()
			return n, found
		}
	}
	p.scopes.mu.Unlock()

	fetched, err := p.discover(ctx, prefix)
	p.scopes.mu.Lock()
	defer p.scopes.mu.Unlock()
	if p.scopes.gv == nil {
		p.scopes.gv = map[string]*gvScope{}
	}
	if err != nil {
		if s == nil {
			return false, false
		}
		fetched = s.namespaced // keep what was known; asked again after discoveryRetry
	}
	p.scopes.gv[prefix] = &gvScope{namespaced: fetched, fetched: time.Now()}
	n, found := fetched[resource]
	return n, found
}

func (p *Proxy) discover(ctx context.Context, prefix string) (map[string]bool, error) {
	req, err := p.upstream(ctx, "/"+prefix, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("discovery of %s: %s", prefix, resp.Status)
	}
	var l struct {
		Resources []struct {
			Name       string `json:"name"`
			Namespaced bool   `json:"namespaced"`
		} `json:"resources"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&l); err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, r := range l.Resources {
		if !strings.Contains(r.Name, "/") { // not a subresource
			out[r.Name] = r.Namespaced
		}
	}
	return out, nil
}
