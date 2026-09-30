package proxy

import (
	"net/http/httptest"
	"testing"
)

func TestParseRequest(t *testing.T) {
	cases := []struct {
		method, url                                 string
		verb, group, resource, sub, namespace, name string
		sensitive                                   bool
	}{
		{"GET", "/api/v1/namespaces/default/pods", "list", "", "pods", "", "default", "", false},
		{"GET", "/api/v1/namespaces/default/pods?watch=true", "watch", "", "pods", "", "default", "", false},
		{"GET", "/api/v1/watch/namespaces/default/pods", "watch", "", "pods", "", "default", "", false},
		{"GET", "/api/v1/namespaces/default/pods/web", "get", "", "pods", "", "default", "web", false},
		{"POST", "/api/v1/namespaces/default/pods/web/exec?command=sh", "create", "", "pods", "exec", "default", "web", true},
		{"GET", "/api/v1/namespaces/default/pods/web/log", "get", "", "pods", "log", "default", "web", false},
		{"PATCH", "/apis/apps/v1/namespaces/prod/deployments/api", "patch", "apps", "deployments", "", "prod", "api", true},
		{"DELETE", "/apis/apps/v1/namespaces/prod/deployments", "deletecollection", "apps", "deployments", "", "prod", "", true},
		{"GET", "/api/v1/namespaces/prod/secrets", "list", "", "secrets", "", "prod", "", true},
		{"GET", "/api/v1/namespaces/prod", "get", "", "namespaces", "", "", "prod", false},
		{"GET", "/apis/rbac.authorization.k8s.io/v1/clusterroles", "list", "rbac.authorization.k8s.io", "clusterroles", "", "", "", false},
		{"GET", "/api/v1/nodes/n1/proxy/metrics", "get", "", "nodes", "proxy", "", "n1", true},
	}
	for _, c := range cases {
		r := httptest.NewRequest(c.method, c.url, nil)
		got := ParseRequest(r, r.URL.Path)
		if !got.IsResource || got.Verb != c.verb || got.APIGroup != c.group || got.Resource != c.resource ||
			got.Subresource != c.sub || got.Namespace != c.namespace || got.Name != c.name {
			t.Errorf("%s %s: got %+v", c.method, c.url, got)
		}
		if got.Sensitive() != c.sensitive {
			t.Errorf("%s %s: sensitive = %v, want %v", c.method, c.url, got.Sensitive(), c.sensitive)
		}
	}
	for _, p := range []string{"/version", "/apis", "/apis/apps", "/openapi/v2"} {
		if got := ParseRequest(httptest.NewRequest("GET", p, nil), p); got.IsResource {
			t.Errorf("%s: not a resource, got %+v", p, got)
		}
	}
}
