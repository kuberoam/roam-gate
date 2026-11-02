package proxy

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kuberoam/roam-gate/internal/audit"
	"github.com/kuberoam/roam-gate/internal/config"
	"github.com/kuberoam/roam-gate/internal/store"
)

type fakeGranted []string

func (f fakeGranted) Namespaces(context.Context, string, []string) ([]string, error) { return f, nil }
func (f fakeGranted) Version() (uint64, bool)                                        { return 0, true }

// changingGrants is fakeGranted whose bindings change when version is bumped.
type changingGrants struct {
	nss     atomic.Pointer[[]string]
	version atomic.Uint64
	blind   atomic.Bool // RBAC isn't watched
}

func (g *changingGrants) Namespaces(context.Context, string, []string) ([]string, error) {
	return *g.nss.Load(), nil
}
func (g *changingGrants) Version() (uint64, bool) { return g.version.Load(), !g.blind.Load() }

func grants(nss ...string) *changingGrants {
	g := &changingGrants{}
	g.nss.Store(&nss)
	return g
}

// rbacAPI is an API server where roam:alice@corp.com may read namespaces a
// and b one by one (b's pods too, but not its secrets), and nothing across
// them; Gate itself may list namespaces and read discovery.
func rbacAPI(t *testing.T, calls *sync.Map) *httptest.Server {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls != nil {
			n, _ := calls.LoadOrStore(r.URL.Path, new(atomic.Int32))
			n.(*atomic.Int32).Add(1)
		}
		user := r.Header.Get("Impersonate-User")
		q := r.URL.Query()
		forbid := func() {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"kind":"Status","code":403,"reason":"Forbidden"}`))
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case user == "" && r.URL.Path == "/api/v1":
			w.Write([]byte(`{"kind":"APIResourceList","groupVersion":"v1","resources":[{"name":"pods","namespaced":true},{"name":"pods/log","namespaced":true},
				{"name":"secrets","namespaced":true},{"name":"nodes","namespaced":false},{"name":"namespaces","namespaced":false}]}`))
		case user == "" && r.URL.Path == "/api/v1/namespaces":
			w.Write([]byte(`{"kind":"NamespaceList","apiVersion":"v1","metadata":{"resourceVersion":"900"},"items":[]}`))
		case user != "roam:alice@corp.com":
			forbid()
		case r.URL.Path == "/api/v1/namespaces/a/pods" || r.URL.Path == "/api/v1/namespaces/b/pods":
			ns := strings.Split(r.URL.Path, "/")[4]
			if q.Has("limit") {
				t.Errorf("limit sent on: %s", r.URL)
			}
			if q.Get("watch") == "1" {
				w.Write([]byte(`{"type":"ADDED","object":{"metadata":{"name":"p-` + ns + `"}}}` + "\n"))
				rv := map[string]string{"a": "20", "b": "25"}[ns]
				w.Write([]byte(`{"type":"BOOKMARK","object":{"metadata":{"resourceVersion":"` + rv + `"}}}` + "\n"))
				if q.Get("sendInitialEvents") == "true" {
					w.Write([]byte(`{"type":"BOOKMARK","object":{"metadata":{"resourceVersion":"` + rv + `","annotations":{"k8s.io/initial-events-end":"true"}}}}` + "\n"))
				}
				w.(http.Flusher).Flush()
				if q.Get("timeoutSeconds") == "1" && ns == "a" {
					return // a's watch times out
				}
				<-r.Context().Done()
				return
			}
			w.Write([]byte(`{"kind":"PodList","apiVersion":"v1","metadata":{"resourceVersion":"` + map[string]string{"a": "10", "b": "12"}[ns] +
				`","continue":"x"},"items":[{"metadata":{"name":"p-` + ns + `","namespace":"` + ns + `"}}]}`))
		case r.URL.Path == "/api/v1/namespaces/a" || r.URL.Path == "/api/v1/namespaces/b":
			ns := strings.TrimPrefix(r.URL.Path, "/api/v1/namespaces/")
			labels := map[string]string{"a": `{"team":"x"}`, "b": `{"team":"y"}`}[ns]
			switch accept := r.Header.Get("Accept"); {
			case strings.Contains(accept, "as=PartialObjectMetadataList"):
				w.WriteHeader(http.StatusNotAcceptable) // a single object isn't a list
			case strings.Contains(accept, "as=PartialObjectMetadata"):
				w.Write([]byte(`{"kind":"PartialObjectMetadata","apiVersion":"meta.k8s.io/v1","metadata":{"name":"` + ns + `","labels":` + labels + `}}`))
			default:
				w.Write([]byte(`{"kind":"Namespace","apiVersion":"v1","metadata":{"name":"` + ns + `","resourceVersion":"3","labels":` + labels + `},"status":{"phase":"Active"}}`))
			}
		case r.URL.Path == "/api/v1/namespaces/a/secrets":
			w.Write([]byte(`{"kind":"SecretList","apiVersion":"v1","metadata":{},"items":[]}`))
		default:
			forbid()
		}
	}))
	t.Cleanup(api.CloseClientConnections)
	t.Cleanup(api.Close)
	return api
}

func spreadingGate(t *testing.T, granted Granted) *httptest.Server {
	return countingGate(t, granted, nil)
}

func countingGate(t *testing.T, granted Granted, calls *sync.Map) *httptest.Server {
	t.Helper()
	st, err := store.Open(t.TempDir(), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	rec := audit.New(st, nil)
	t.Cleanup(rec.Close)
	f := &fakeSessions{expires: time.Now().Add(time.Hour)}
	f.live.Store(true)
	p, err := New(rbacAPI(t, calls).URL, http.DefaultTransport, f, granted, rec, config.AuditWrites)
	if err != nil {
		t.Fatal(err)
	}
	gate := httptest.NewServer(p)
	t.Cleanup(gate.Close)
	return gate
}

func getJSON(t *testing.T, url string, accept ...string) (int, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	if len(accept) > 0 {
		req.Header.Set("Accept", accept[0])
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var m map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, m
}

func names(m map[string]any) []string {
	var out []string
	for _, it := range m["items"].([]any) {
		out = append(out, it.(map[string]any)["metadata"].(map[string]any)["name"].(string))
	}
	return out
}

func callsTo(calls *sync.Map, path string) int32 {
	n, ok := calls.Load(path)
	if !ok {
		return 0
	}
	return n.(*atomic.Int32).Load()
}

func TestListAcrossGrantedNamespaces(t *testing.T) {
	gate := spreadingGate(t, fakeGranted{"a", "b", "c"})
	code, m := getJSON(t, gate.URL+Prefix+"/api/v1/pods?limit=500")
	if code != http.StatusOK || m["kind"] != "PodList" || m["apiVersion"] != "v1" {
		t.Fatalf("%d %v", code, m)
	}
	if got := names(m); !slices.Equal(got, []string{"p-a", "p-b"}) {
		t.Fatalf("items %v", got)
	}
	// The oldest resourceVersion: a watch from it misses none of a's changes.
	meta := m["metadata"].(map[string]any)
	if meta["resourceVersion"] != "10" || meta["continue"] != nil {
		t.Fatalf("metadata %v", meta)
	}

	// Refused in b, still shown from a.
	code, m = getJSON(t, gate.URL+Prefix+"/api/v1/secrets")
	if code != http.StatusOK || m["kind"] != "SecretList" || len(m["items"].([]any)) != 0 {
		t.Fatalf("%d %v", code, m)
	}
}

func TestNamespacesAcrossGrantedOnes(t *testing.T) {
	gate := spreadingGate(t, fakeGranted{"a", "b", "c"})
	code, m := getJSON(t, gate.URL+Prefix+"/api/v1/namespaces")
	if code != http.StatusOK || m["kind"] != "NamespaceList" || !slices.Equal(names(m), []string{"a", "b"}) {
		t.Fatalf("%d %v", code, m)
	}
	if rv := m["metadata"].(map[string]any)["resourceVersion"]; rv != "900" {
		t.Fatalf("resourceVersion %v, want the cluster's", rv)
	}

	// Selectors are applied, though each namespace is got as one object.
	for sel, want := range map[string][]string{
		"labelSelector=team%3Dx":            {"a"},
		"fieldSelector=metadata.name%3Db":   {"b"},
		"fieldSelector=metadata.name%3Dc":   nil, // granted, but refused
		"fieldSelector=status.phase%3DGone": nil,
	} {
		code, m := getJSON(t, gate.URL+Prefix+"/api/v1/namespaces?"+sel)
		if want == nil {
			if code == http.StatusOK && len(m["items"].([]any)) != 0 {
				t.Errorf("%s: %v", sel, m)
			}
			continue
		}
		if code != http.StatusOK || !slices.Equal(names(m), want) {
			t.Errorf("%s: %d %v", sel, code, m)
		}
	}

	// Metadata-only clients ask for a list of metadata.
	code, m = getJSON(t, gate.URL+Prefix+"/api/v1/namespaces", "application/json;as=PartialObjectMetadataList;g=meta.k8s.io;v=v1")
	if code != http.StatusOK || m["kind"] != "PartialObjectMetadataList" || !slices.Equal(names(m), []string{"a", "b"}) {
		t.Fatalf("metadata only: %d %v", code, m)
	}
}

func TestClusterScopedIsNotSpread(t *testing.T) {
	var calls sync.Map
	gate := countingGate(t, fakeGranted{"a", "b"}, &calls)
	for range 2 {
		if code, m := getJSON(t, gate.URL+Prefix+"/api/v1/nodes"); code != http.StatusForbidden || m["reason"] != "Forbidden" {
			t.Fatalf("%d %v", code, m)
		}
	}
	if n := callsTo(&calls, "/api/v1/namespaces/a/nodes"); n != 0 {
		t.Fatalf("nodes asked in a namespace %d times", n)
	}
	if n := callsTo(&calls, "/api/v1"); n != 1 {
		t.Fatalf("discovery read %d times, want once", n)
	}
	// Granted nothing one by one: nothing to spread over.
	if code, _ := getJSON(t, spreadingGate(t, fakeGranted{}).URL+Prefix+"/api/v1/pods"); code != http.StatusForbidden {
		t.Fatalf("%d", code)
	}
}

// Once refused across namespaces, a session's next list goes straight to its
// namespaces, until the bindings or RBAC change.
func TestSpreadIsRemembered(t *testing.T) {
	var calls sync.Map
	g := grants("a", "b")
	gate := countingGate(t, g, &calls)
	for range 3 {
		if code, m := getJSON(t, gate.URL+Prefix+"/api/v1/pods"); code != http.StatusOK || len(names(m)) != 2 {
			t.Fatalf("%d %v", code, m)
		}
	}
	if n := callsTo(&calls, "/api/v1/pods"); n != 1 {
		t.Fatalf("asked across namespaces %d times, want once", n)
	}
	if n := callsTo(&calls, "/api/v1/namespaces/a/pods"); n != 3 {
		t.Fatalf("asked namespace a %d times", n)
	}

	// RBAC changed: asked across namespaces again, then remembered again.
	only := []string{"a"}
	g.nss.Store(&only)
	g.version.Add(1)
	for range 2 {
		if code, m := getJSON(t, gate.URL+Prefix+"/api/v1/pods"); code != http.StatusOK || !slices.Equal(names(m), []string{"p-a"}) {
			t.Fatalf("%d %v", code, m)
		}
	}
	if n := callsTo(&calls, "/api/v1/pods"); n != 2 {
		t.Fatalf("asked across namespaces %d times, want twice", n)
	}

	// Granted nothing any more: the API server's 403, not an empty list.
	none := []string{}
	g.nss.Store(&none)
	if code, _ := getJSON(t, gate.URL+Prefix+"/api/v1/pods"); code != http.StatusForbidden {
		t.Fatalf("%d", code)
	}
}

// While RBAC isn't watched nothing is remembered: every list asks across
// namespaces first.
func TestNothingRememberedUnwatched(t *testing.T) {
	var calls sync.Map
	g := grants("a", "b")
	g.blind.Store(true)
	gate := countingGate(t, g, &calls)
	for range 2 {
		if code, _ := getJSON(t, gate.URL+Prefix+"/api/v1/pods"); code != http.StatusOK {
			t.Fatalf("%d", code)
		}
	}
	if n := callsTo(&calls, "/api/v1/pods"); n != 2 {
		t.Fatalf("asked across namespaces %d times, want every time", n)
	}
}

func readEvents(t *testing.T, br *bufio.Reader, n int) []string {
	t.Helper()
	var out []string
	for range n {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("after %v: %v", out, err)
		}
		out = append(out, strings.TrimSpace(line))
	}
	return out
}

func TestWatchAcrossGrantedNamespaces(t *testing.T) {
	gate := spreadingGate(t, fakeGranted{"a", "b"})
	resp, err := http.Get(gate.URL + Prefix + "/api/v1/pods?watch=1")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	br := bufio.NewReader(resp.Body)
	var got []string
	for _, line := range readEvents(t, br, 2) {
		if strings.Contains(line, "BOOKMARK") {
			t.Fatalf("a namespace's bookmark was sent: %s", line)
		}
		var e struct {
			Object struct{ Metadata struct{ Name string } }
		}
		json.Unmarshal([]byte(line), &e)
		got = append(got, e.Object.Metadata.Name)
	}
	slices.Sort(got)
	if !slices.Equal(got, []string{"p-a", "p-b"}) {
		t.Fatalf("events %v", got)
	}
	go func() { time.Sleep(200 * time.Millisecond); resp.Body.Close() }()
	if b, _ := io.ReadAll(br); strings.Contains(string(b), "BOOKMARK") {
		t.Fatalf("a namespace's bookmark was sent: %s", b)
	}
}

// One initial-events-end bookmark, once every namespace sent its own, at the
// oldest of their resourceVersions.
func TestWatchInitialEventsEnd(t *testing.T) {
	gate := spreadingGate(t, fakeGranted{"a", "b"})
	resp, err := http.Get(gate.URL + Prefix + "/api/v1/pods?watch=1&sendInitialEvents=true&allowWatchBookmarks=true")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	events := readEvents(t, bufio.NewReader(resp.Body), 3)
	last := events[2]
	if !strings.Contains(last, "initial-events-end") || !strings.Contains(last, `"resourceVersion":"20"`) {
		t.Fatalf("events %v", events)
	}
	for _, e := range events[:2] {
		if strings.Contains(e, "BOOKMARK") {
			t.Fatalf("bookmark before every namespace's initial events: %v", events)
		}
	}
}

// When one namespace's watch ends, the merged one ends telling the client to
// list again: resuming from its last event could skip another namespace's.
func TestMergedWatchEndsExpired(t *testing.T) {
	gate := spreadingGate(t, fakeGranted{"a", "b"})
	resp, err := http.Get(gate.URL + Prefix + "/api/v1/pods?watch=1&timeoutSeconds=1")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if last := lines[len(lines)-1]; !strings.Contains(last, `"type":"ERROR"`) || !strings.Contains(last, `"code":410`) {
		t.Fatalf("ended with %s", last)
	}
}

func TestInNamespace(t *testing.T) {
	for _, c := range []struct{ method, path, ns, want string }{
		{"GET", "/api/v1/pods", "a", "/api/v1/namespaces/a/pods"},
		{"GET", "/apis/apps/v1/deployments", "a", "/apis/apps/v1/namespaces/a/deployments"},
		{"GET", "/apis/apps/v1/watch/deployments", "a", "/apis/apps/v1/watch/namespaces/a/deployments"},
		{"GET", "/api/v1/namespaces", "a", "/api/v1/namespaces/a"},
		{"GET", "/api/v1/namespaces?watch=true", "a", "/api/v1/watch/namespaces/a"},
	} {
		r := httptest.NewRequest(c.method, c.path, nil)
		path, _, _ := strings.Cut(c.path, "?")
		if got := inNamespace(path, ParseRequest(r, path), c.ns); got != c.want {
			t.Errorf("%s: %s, want %s", c.path, got, c.want)
		}
	}
}

func TestJSONOnly(t *testing.T) {
	for in, want := range map[string]string{
		"":                                    "application/json",
		"application/vnd.kubernetes.protobuf": "application/json",
		"application/vnd.kubernetes.protobuf,application/json":          "application/json",
		"application/json;as=Table;v=v1;g=meta.k8s.io,application/json": "application/json;as=Table;v=v1;g=meta.k8s.io,application/json",
	} {
		if got := jsonOnly(in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}

func TestMemoPrune(t *testing.T) {
	var m spreadMemo
	a, b := memoKey{"s", "", "pods"}, memoKey{"s", "apps", "deployments"}
	m.set(a, 1)
	m.set(b, 2)
	if !m.known(a, 1) || m.known(a, 2) {
		t.Fatal("known under the wrong version")
	}
	m.prune(2)
	if m.known(a, 1) || !m.known(b, 2) {
		t.Fatal("pruned the wrong one")
	}
}
