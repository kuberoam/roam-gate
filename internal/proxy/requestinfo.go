package proxy

import (
	"net/http"
	"strings"
)

// RequestInfo is what an API request does, read from its path the way the
// API server does (a trimmed-down k8s.io/apiserver RequestInfoFactory).
type RequestInfo struct {
	IsResource  bool
	Verb        string
	APIGroup    string
	Resource    string
	Subresource string
	Namespace   string
	Name        string
}

var methodVerbs = map[string]string{
	http.MethodGet: "get", http.MethodHead: "get", http.MethodPost: "create",
	http.MethodPut: "update", http.MethodPatch: "patch", http.MethodDelete: "delete",
}

// ParseRequest reads a request path relative to the API server root
// (e.g. /api/v1/namespaces/default/pods/web/exec).
func ParseRequest(r *http.Request, path string) RequestInfo {
	info := RequestInfo{Verb: strings.ToLower(r.Method)}
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) < 2 || (parts[0] != "api" && parts[0] != "apis") {
		return info // /version, /openapi, /healthz…: not a resource
	}
	if parts[0] == "api" {
		parts = parts[2:] // api/v1
	} else {
		if len(parts) < 3 {
			return info // discovery
		}
		info.APIGroup = parts[1]
		parts = parts[3:] // apis/group/version
	}
	info.IsResource = true
	verb := methodVerbs[r.Method]
	if verb == "" {
		verb = strings.ToLower(r.Method)
	}
	// Watches: ?watch=true or the legacy /watch/ prefix.
	if len(parts) > 0 && parts[0] == "watch" {
		verb, parts = "watch", parts[1:]
	}
	if len(parts) >= 2 && parts[0] == "namespaces" {
		if len(parts) == 2 {
			// /namespaces/foo is the Namespace object itself.
			info.Resource, info.Name = "namespaces", parts[1]
		} else {
			info.Namespace = parts[1]
			parts = parts[2:]
		}
	}
	if info.Resource == "" {
		if len(parts) > 0 {
			info.Resource = parts[0]
		}
		if len(parts) > 1 {
			info.Name = parts[1]
		}
		if len(parts) > 2 {
			info.Subresource = parts[2]
		}
	}
	if r.URL.Query().Get("watch") == "true" || r.URL.Query().Get("watch") == "1" {
		verb = "watch"
	}
	if info.Name == "" {
		switch verb {
		case "get":
			verb = "list"
		case "delete":
			verb = "deletecollection"
		}
	}
	info.Verb = verb
	return info
}

// sessionSubresources open interactive sessions; they are always recorded.
var sessionSubresources = map[string]bool{"exec": true, "attach": true, "portforward": true, "proxy": true}

var writeVerbs = map[string]bool{"create": true, "update": true, "patch": true, "delete": true, "deletecollection": true}

// Sensitive says whether a request is recorded at the "writes" audit level.
func (i RequestInfo) Sensitive() bool {
	if !i.IsResource {
		return false
	}
	return writeVerbs[i.Verb] || sessionSubresources[i.Subresource] || i.Resource == "secrets"
}
