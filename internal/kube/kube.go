// Package kube is Gate's access to the Kubernetes API: the transport the
// proxy forwards with, and the few typed clients the RBAC reconciler needs.
//
// Only the RBAC and core clients are built (not the whole Clientset), and the
// only things watched are Gate's own (Cluster)RoleBindings, by label — so
// Gate's memory stays flat however big the cluster is.
package kube

import (
	"fmt"
	"net/http"

	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	rbacv1client "k8s.io/client-go/kubernetes/typed/rbac/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// Labels and annotations on everything Gate creates, so Roam (and people)
// can tell Gate's objects apart and clean them up.
const (
	LabelManagedBy = "kuberoam.dev/managed-by"
	ManagedBy      = "roam-gate"
	LabelBinding   = "kuberoam.dev/binding"
	AnnoSubject    = "kuberoam.dev/subject"
	AnnoNote       = "kuberoam.dev/note"
)

// Client holds the REST config and the typed clients Gate uses.
type Client struct {
	Config *rest.Config
	RBAC   rbacv1client.RbacV1Interface
	Core   corev1client.CoreV1Interface
	// WatchListSemantics is what tells informers whether the client can
	// stream an initial list (cache.ToListWatcherWithWatchListSemantics):
	// nil for a real cluster, the fake clientset in tests.
	WatchListSemantics any
}

// New connects with the service account, or with a kubeconfig outside the
// cluster (development).
func New(kubeconfig string) (*Client, error) {
	var cfg *rest.Config
	var err error
	if kubeconfig != "" {
		cfg, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
	} else {
		cfg, err = rest.InClusterConfig()
	}
	if err != nil {
		return nil, fmt.Errorf("kubernetes config: %w", err)
	}
	cfg.UserAgent = "roam-gate"
	// Gate's own calls are few; keep client-side throttling out of the way
	// of the reconciler without letting a bug hammer the API server.
	cfg.QPS, cfg.Burst = 20, 40
	rb, err := rbacv1client.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}
	core, err := corev1client.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}
	return &Client{Config: cfg, RBAC: rb, Core: core}, nil
}

// Transport authenticates as Gate's service account (the token file is
// re-read as it rotates) for the proxy, which adds impersonation headers.
func (c *Client) Transport() (http.RoundTripper, error) {
	cfg := rest.CopyConfig(c.Config)
	// The proxy passes client requests through untouched apart from auth;
	// client-go's own rate limiter and user agent don't belong on them.
	cfg.UserAgent = ""
	return rest.TransportFor(cfg)
}

// Host is the API server's base URL.
func (c *Client) Host() string { return c.Config.Host }

// ManagedSelector selects the objects Gate created for bindings — never
// Gate's own install objects, which carry no binding label.
func ManagedSelector() string { return LabelManagedBy + "=" + ManagedBy + "," + LabelBinding }
