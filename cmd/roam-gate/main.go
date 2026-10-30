// Command roam-gate is Roam's access control service for a Kubernetes
// cluster: SSO sign-in, user/group access through RBAC, and an audit trail.
package main

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/kuberoam/roam-gate/internal/audit"
	"github.com/kuberoam/roam-gate/internal/auth"
	"github.com/kuberoam/roam-gate/internal/config"
	"github.com/kuberoam/roam-gate/internal/kube"
	"github.com/kuberoam/roam-gate/internal/policy"
	"github.com/kuberoam/roam-gate/internal/proxy"
	"github.com/kuberoam/roam-gate/internal/server"
	"github.com/kuberoam/roam-gate/internal/store"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))
	if len(os.Args) > 1 && (os.Args[1] == "version" || os.Args[1] == "--version") {
		os.Stdout.WriteString(server.Version + "\n")
		return
	}
	if err := run(); err != nil {
		slog.Error("roam-gate stopped", "err", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	st, err := store.Open(cfg.DataDir, cfg.SecretKey)
	if err != nil {
		return err
	}
	defer st.Close()
	kc, err := kube.New(cfg.Kubeconfig)
	if err != nil {
		return err
	}
	transport, err := kc.Transport()
	if err != nil {
		return err
	}
	// Audit lines go to stdout; Gate's own logs go to stderr.
	rec := audit.New(st, os.Stdout)
	defer rec.Close()

	sessions := auth.NewSessions(st, cfg.SessionTTL, cfg.AdminToken, cfg.AdminUsers, cfg.AdminGroups)
	px, err := proxy.New(kc.Host(), transport, sessions, rec, cfg.AuditLevel)
	if err != nil {
		return err
	}
	rc := policy.New(kc, st, cfg.ReconcileInterval, cfg.ExternalURL)
	rcDone := make(chan struct{})
	go func() {
		rc.Run(ctx) // gives the cluster lock up on its way out
		close(rcDone)
	}()
	go prune(ctx, st, cfg.AuditRetention)

	var caPEM []byte
	if cfg.CAFile != "" {
		// A cert-manager Secret has no ca.crt for ACME issuers: then kubeconfigs
		// carry no CA and rely on the system's.
		if caPEM, err = os.ReadFile(cfg.CAFile); errors.Is(err, fs.ErrNotExist) || (err == nil && len(bytes.TrimSpace(caPEM)) == 0) {
			slog.Warn("no CA certificate to put in kubeconfigs", "file", cfg.CAFile)
			caPEM = nil
		} else if err != nil {
			return err
		}
	}
	srv := &http.Server{
		Addr: cfg.Listen,
		Handler: server.New(server.Deps{Config: cfg, Store: st, Kube: kc, Recorder: rec, Sessions: sessions,
			Policy: rc, Proxy: px, CAPEM: caPEM}),
		ReadHeaderTimeout: 10 * time.Second,
		// No write timeout: watches, logs and exec sessions stream for as long as they last.
		IdleTimeout: 2 * time.Minute,
	}
	errc := make(chan error, 1)
	go func() {
		slog.Info("roam-gate listening", "addr", cfg.Listen, "tls", cfg.TLSCert != "", "version", server.Version, "url", cfg.ExternalURL)
		if cfg.TLSCert != "" {
			errc <- srv.ListenAndServeTLS(cfg.TLSCert, cfg.TLSKey)
		} else {
			errc <- srv.ListenAndServe()
		}
	}()
	select {
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case <-ctx.Done():
	}
	stop() // a server error ends the reconciler too
	shutdown, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	err = srv.Shutdown(shutdown)
	// Wait for the reconciler to release the cluster lock, so another Gate
	// can take over at once instead of after the lock's TTL.
	select {
	case <-rcDone:
	case <-time.After(10 * time.Second):
	}
	return err
}

// prune applies the audit retention once an hour.
func prune(ctx context.Context, st *store.Store, retention time.Duration) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		if n, err := st.Prune(ctx, retention); err != nil {
			slog.Warn("pruning failed", "err", err)
		} else if n > 0 {
			slog.Info("pruned audit events", "count", n)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
