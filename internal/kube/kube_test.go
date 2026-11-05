package kube

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"k8s.io/client-go/rest"
)

// TestTransportStaysHTTP1 guards against the 502 that hit exec, attach,
// portforward and the raw subresource proxy in production: golang.org/x/net/http2's
// Transport refuses any request carrying "Connection: Upgrade" ("http2: invalid
// Upgrade request header"), so if client-go is left to auto-negotiate HTTP/2 with
// the API server, all four subresources break once the pooled connection picks h2.
func TestTransportStaysHTTP1(t *testing.T) {
	var gotProto string
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotProto = r.Proto
		w.WriteHeader(http.StatusOK)
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()

	c := &Client{Config: &rest.Config{
		Host:            srv.URL,
		TLSClientConfig: rest.TLSClientConfig{Insecure: true},
	}}
	rt, err := c.Transport()
	if err != nil {
		t.Fatalf("Transport: %v", err)
	}
	req, err := http.NewRequest(http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	resp.Body.Close()

	if gotProto != "HTTP/1.1" {
		t.Fatalf("API server saw proto %q, want HTTP/1.1 (h2 breaks exec/attach/portforward/proxy's SPDY upgrade)", gotProto)
	}
}
