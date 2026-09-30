// Package secure has the small crypto helpers Gate needs: random tokens,
// token hashes for storage, AES-GCM for stored provider secrets, and HMAC
// for values that round-trip through the browser.
package secure

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
)

var b64 = base64.RawURLEncoding

// Token returns a random URL-safe token with a prefix that says what it is
// (e.g. "rg_" for sessions), so leaked tokens are easy to recognise.
func Token(prefix string) string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err) // the OS random source never fails in practice
	}
	return prefix + b64.EncodeToString(b)
}

// ID is a short random identifier for rows.
func ID() string {
	b := make([]byte, 9)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b64.EncodeToString(b)
}

// Hash is how tokens are stored: a leaked database doesn't leak credentials.
func Hash(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// Equal compares secrets in constant time.
func Equal(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// Box seals and opens small secrets with a 32-byte key.
type Box struct{ aead cipher.AEAD }

func NewBox(key []byte) (*Box, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Box{aead: g}, nil
}

func (b *Box) Seal(plain []byte) []byte {
	nonce := make([]byte, b.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		panic(err)
	}
	return b.aead.Seal(nonce, nonce, plain, nil)
}

func (b *Box) Open(sealed []byte) ([]byte, error) {
	n := b.aead.NonceSize()
	if len(sealed) < n {
		return nil, errors.New("sealed value too short")
	}
	return b.aead.Open(nil, sealed[:n], sealed[n:], nil)
}

// Signer signs short values that come back from the browser (OAuth state).
type Signer struct{ key []byte }

func NewSigner(key []byte) *Signer {
	// Derive a separate key so the encryption key is never used for MACs.
	m := hmac.New(sha256.New, key)
	m.Write([]byte("roam-gate/signer"))
	return &Signer{key: m.Sum(nil)}
}

func (s *Signer) mac(v string) string {
	m := hmac.New(sha256.New, s.key)
	m.Write([]byte(v))
	return b64.EncodeToString(m.Sum(nil))
}

// Sign returns "value.mac".
func (s *Signer) Sign(v string) string { return v + "." + s.mac(v) }

// Verify returns the value of a signed string, or false if it was altered.
func (s *Signer) Verify(signed string) (string, bool) {
	i := strings.LastIndexByte(signed, '.')
	if i < 0 {
		return "", false
	}
	v, m := signed[:i], signed[i+1:]
	return v, hmac.Equal([]byte(m), []byte(s.mac(v)))
}

// Name is a short random lowercase ID usable in Kubernetes object names.
func Name() string {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}
