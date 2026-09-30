// Package config reads Roam Gate's settings from the environment (the Helm
// chart sets them) — one place, no config file to template.
package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// AuditLevel says which proxied requests are recorded. Logins, sessions and
// admin changes are always recorded.
type AuditLevel string

const (
	// AuditWrites records changes (create/update/patch/delete), exec, attach,
	// port-forward, proxy, any access to Secrets, and every denied request.
	AuditWrites AuditLevel = "writes"
	// AuditAll records every request, reads included.
	AuditAll AuditLevel = "all"
)

type Config struct {
	Listen      string // address to serve on, e.g. ":8443"
	TLSCert     string // PEM files; serve plain HTTP when empty (TLS terminated in front)
	TLSKey      string
	CAFile      string // CA that signed TLSCert, embedded in issued kubeconfigs
	ExternalURL string // how users reach Gate, e.g. https://gate.example.com
	DataDir     string // SQLite lives here (a PVC in the chart)
	Namespace   string // Gate's own namespace
	ClusterName string // shown to users and used in issued kubeconfigs

	// SecretKey encrypts stored provider secrets and signs login state.
	SecretKey []byte
	// AdminToken is the bootstrap admin credential (a Secret in the chart);
	// Roam uses it right after install to configure Gate.
	AdminToken  string
	AdminUsers  []string // Gate user IDs that may administer Gate
	AdminGroups []string // Gate group IDs ("<provider>:<group>") that may administer Gate

	SessionTTL        time.Duration
	AuditLevel        AuditLevel
	AuditRetention    time.Duration
	ReconcileInterval time.Duration

	// Kubeconfig is only for running Gate outside a cluster (development);
	// in the cluster Gate uses its service account.
	Kubeconfig string
}

func env(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}

func list(k string) []string {
	var out []string
	for _, p := range strings.Split(os.Getenv(k), ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func duration(k string, def time.Duration) (time.Duration, error) {
	v := env(k, "")
	if v == "" {
		return def, nil
	}
	// Plain numbers of days read naturally for retention ("90d").
	if strings.HasSuffix(v, "d") {
		n, err := strconv.Atoi(strings.TrimSuffix(v, "d"))
		if err != nil {
			return 0, fmt.Errorf("%s: %q is not a duration", k, v)
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("%s: %q is not a duration", k, v)
	}
	return d, nil
}

// Load reads the configuration and checks what Gate can't run without.
func Load() (*Config, error) {
	c := &Config{
		Listen:      env("GATE_LISTEN", ":8443"),
		TLSCert:     env("GATE_TLS_CERT", ""),
		TLSKey:      env("GATE_TLS_KEY", ""),
		CAFile:      env("GATE_CA_FILE", ""),
		ExternalURL: strings.TrimRight(env("GATE_EXTERNAL_URL", ""), "/"),
		DataDir:     env("GATE_DATA_DIR", "/data"),
		Namespace:   env("POD_NAMESPACE", "roam-system"),
		ClusterName: env("GATE_CLUSTER_NAME", "roam-gate"),
		AdminToken:  env("GATE_ADMIN_TOKEN", ""),
		AdminUsers:  list("GATE_ADMIN_USERS"),
		AdminGroups: list("GATE_ADMIN_GROUPS"),
		AuditLevel:  AuditLevel(env("GATE_AUDIT_LEVEL", string(AuditWrites))),
		Kubeconfig:  env("GATE_KUBECONFIG", ""),
	}
	var err error
	if c.SessionTTL, err = duration("GATE_SESSION_TTL", 12*time.Hour); err != nil {
		return nil, err
	}
	if c.AuditRetention, err = duration("GATE_AUDIT_RETENTION", 90*24*time.Hour); err != nil {
		return nil, err
	}
	if c.ReconcileInterval, err = duration("GATE_RECONCILE_INTERVAL", 2*time.Minute); err != nil {
		return nil, err
	}
	if c.AuditLevel != AuditWrites && c.AuditLevel != AuditAll {
		return nil, fmt.Errorf("GATE_AUDIT_LEVEL: %q (use %q or %q)", c.AuditLevel, AuditWrites, AuditAll)
	}
	key := env("GATE_SECRET_KEY", "")
	if key == "" {
		return nil, errors.New("GATE_SECRET_KEY is required (32 random bytes, base64)")
	}
	if c.SecretKey, err = base64.StdEncoding.DecodeString(key); err != nil || len(c.SecretKey) != 32 {
		return nil, errors.New("GATE_SECRET_KEY must be 32 bytes, base64-encoded")
	}
	if c.ExternalURL == "" {
		return nil, errors.New("GATE_EXTERNAL_URL is required: the address users open to sign in")
	}
	if (c.TLSCert == "") != (c.TLSKey == "") {
		return nil, errors.New("GATE_TLS_CERT and GATE_TLS_KEY go together")
	}
	return c, nil
}
