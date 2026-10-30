package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"net/http"
	"net/url"
	"strings"

	"github.com/kuberoam/roam-gate/internal/secure"
)

// Handing a browser sign-in over to the Roam desktop app. The signed-in page
// links to roam://gate/signin with a one-time code for the session just
// started: a login request that is already done, which Roam collects like any
// app sign-in. A browser that opened Roam once (a cookie) opens it by itself
// after later sign-ins; others get a button, because browsers without Roam
// show an error page for an unknown scheme.

const (
	roamCookie     = "rg_roam"
	roamLinkPrefix = "roam://gate/signin?"
)

// roamLink is the roam:// link that hands token to Roam, or "" if the
// one-time code couldn't be stored.
func (s *Server) roamLink(ctx context.Context, token string) string {
	id, secret := secure.ID(), secure.Token("rgp_")
	if err := s.st.CreateLoginRequest(ctx, id, secret, "", loginRequestTTL); err != nil {
		return ""
	}
	code, err := s.st.FinishLoginRequest(ctx, id, token, "")
	if err != nil {
		return ""
	}
	q := url.Values{"server": {s.cfg.ExternalURL}, "req": {id}, "secret": {secret}, "code": {code}}
	if fp := s.caFingerprint(); fp != "" {
		q.Set("ca", fp)
	}
	return roamLinkPrefix + q.Encode()
}

// caFingerprint is the SHA-256 of the CA that kubeconfigs embed, so Roam can
// pin /ca.crt when the certificate isn't publicly trusted.
func (s *Server) caFingerprint() string {
	b, _ := pem.Decode(s.caPEM)
	if b == nil {
		return ""
	}
	sum := sha256.Sum256(b.Bytes)
	return hex.EncodeToString(sum[:])
}

// caCert serves the CA that kubeconfigs embed (public: it is a certificate).
func (s *Server) caCert(w http.ResponseWriter, r *http.Request) {
	if len(s.caPEM) == 0 {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Write(s.caPEM)
}

// openRoam remembers that this browser has Roam, then opens the link.
func (s *Server) openRoam(w http.ResponseWriter, r *http.Request) {
	link := r.PostFormValue("link")
	if !strings.HasPrefix(link, roamLinkPrefix) {
		http.Error(w, "not a Roam sign-in link", http.StatusBadRequest)
		return
	}
	s.rememberRoam(w)
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, link, http.StatusSeeOther)
}

func (s *Server) rememberRoam(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: roamCookie, Value: "1", Path: "/", MaxAge: 365 * 24 * 3600, HttpOnly: true,
		Secure: strings.HasPrefix(s.cfg.ExternalURL, "https://"), SameSite: http.SameSiteLaxMode})
}

// opensRoam reports whether this browser opened Roam before.
func opensRoam(r *http.Request) bool {
	_, err := r.Cookie(roamCookie)
	return err == nil
}
