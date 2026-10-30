package proxy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kuberoam/roam-gate/internal/audit"
	"github.com/kuberoam/roam-gate/internal/config"
	"github.com/kuberoam/roam-gate/internal/store"
)

type fakeSessions struct {
	expires time.Time
	live    atomic.Bool
}

func (f *fakeSessions) Authenticate(*http.Request) (*store.Session, error) {
	return &store.Session{ID: "s1", User: "alice@corp.com", Expires: f.expires}, nil
}
func (f *fakeSessions) Live(context.Context, string) bool { return f.live.Load() }

// watchUntilCut opens a stream through the proxy and returns how long it lasted.
func watchUntilCut(t *testing.T, p *Proxy, during func()) time.Duration {
	t.Helper()
	gate := httptest.NewServer(p)
	defer gate.Close()
	start := time.Now()
	resp, err := http.Get(gate.URL + Prefix + "/api/v1/pods?watch=1")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if _, err := bufio.NewReader(resp.Body).ReadString('\n'); err != nil {
		t.Fatal(err)
	}
	during()
	done := make(chan struct{})
	go func() {
		io.Copy(io.Discard, resp.Body)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the stream outlived its session")
	}
	return time.Since(start)
}

func streamingProxy(t *testing.T, f *fakeSessions) *Proxy {
	t.Helper()
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("{\"type\":\"ADDED\"}\n"))
		w.(http.Flusher).Flush()
		<-r.Context().Done() // a watch stays open until someone ends it
	}))
	t.Cleanup(api.CloseClientConnections)
	t.Cleanup(api.Close)
	st, err := store.Open(t.TempDir(), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	rec := audit.New(st, nil)
	t.Cleanup(rec.Close)
	p, err := New(api.URL, http.DefaultTransport, f, rec, config.AuditWrites)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestStreamEndsWhenItsSessionExpires(t *testing.T) {
	f := &fakeSessions{expires: time.Now().Add(400 * time.Millisecond)}
	f.live.Store(true)
	if d := watchUntilCut(t, streamingProxy(t, f), func() {}); d < 300*time.Millisecond {
		t.Fatalf("ended early: %v", d)
	}
}

func TestStreamEndsWhenItsSessionIsRevoked(t *testing.T) {
	f := &fakeSessions{expires: time.Now().Add(time.Hour)}
	f.live.Store(true)
	p := streamingProxy(t, f)
	watchUntilCut(t, p, func() {
		// A sweep with the session live leaves it; revoked, it goes.
		p.open.sweep(context.Background(), f.Live)
		f.live.Store(false)
		p.open.sweep(context.Background(), f.Live)
	})
	if len(p.open.live) != 0 {
		t.Fatalf("still tracked: %d", len(p.open.live))
	}
}

// exec and port-forward are upgraded connections, not streamed responses: they
// must end with their session too.
func TestUpgradedConnectionEndsWithItsSession(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: SPDY/3.1\r\n\r\n")
		rw.Flush()
		io.Copy(io.Discard, conn) // a shell stays open until someone closes it
	}))
	t.Cleanup(api.CloseClientConnections)
	t.Cleanup(api.Close)
	f := &fakeSessions{expires: time.Now().Add(time.Hour)}
	f.live.Store(true)
	st, err := store.Open(t.TempDir(), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	rec := audit.New(st, nil)
	t.Cleanup(rec.Close)
	p, err := New(api.URL, http.DefaultTransport, f, rec, config.AuditWrites)
	if err != nil {
		t.Fatal(err)
	}
	gate := httptest.NewServer(p)
	t.Cleanup(gate.Close)
	conn, err := net.Dial("tcp", gate.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "POST %s/api/v1/namespaces/a/pods/p/exec HTTP/1.1\r\nHost: gate\r\nConnection: Upgrade\r\nUpgrade: SPDY/3.1\r\n\r\n", Prefix)
	br := bufio.NewReader(conn)
	line, err := br.ReadString('\n')
	if err != nil || !strings.Contains(line, "101") {
		t.Fatalf("upgrade: %q %v", line, err)
	}
	f.live.Store(false)
	p.open.sweep(context.Background(), f.Live)
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.Copy(io.Discard, br); err != nil {
		t.Fatalf("the shell outlived its session: %v", err)
	}
}
