// Package vault implements hardened at-rest encryption for secrets using
// envelope encryption: each secret is sealed with a fresh random data key
// (AES-256-GCM, random nonce, AAD bound to the owning record), and that data
// key is wrapped by a Key Encryption Key (KEK). The KEK is pluggable — a local
// key for dev/test, or a KMS/HSM (e.g. HashiCorp Vault Transit) in production,
// so the root key never lives beside the ciphertext. Tokens are versioned
// ("v2:") to allow the format and keys to evolve.
package vault

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

const (
	tokenPrefix = "v2:"
	dekSize     = 32 // AES-256 data key
	nonceSize   = 12 // GCM nonce
)

var ErrInvalidToken = errors.New("vault: invalid or tampered token")

type Vault struct {
	kek KEK
}

// GenerateMasterKey returns a fresh 256-bit key, urlsafe-base64 encoded,
// suitable for PAM_MASTER_KEY with the local KEK (dev/test).
func GenerateMasterKey() (string, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(key), nil
}

// New builds a vault with a local KEK from masterKey. Convenience for dev/test;
// production wiring should build a KEK via NewKEK and call NewWithKEK.
func New(masterKey string) (*Vault, error) {
	kek, err := NewLocalKEK(masterKey)
	if err != nil {
		return nil, err
	}
	return &Vault{kek: kek}, nil
}

// NewWithKEK builds a vault over any KEK provider.
func NewWithKEK(kek KEK) *Vault { return &Vault{kek: kek} }

// KEKID reports the underlying KEK/provider identifier (for logging).
func (v *Vault) KEKID() string { return v.kek.ID() }

// Encrypt seals plaintext bound to aad (e.g. "target:42") under a fresh data
// key wrapped by the KEK. The token only decrypts with the same aad, so a token
// copied onto another record fails authentication.
//
// Token layout (after the "v2:" prefix, base64url):
//
//	uint16(len(wrappedDEK)) || wrappedDEK || nonce(12) || ciphertext
func (v *Vault) Encrypt(ctx context.Context, plaintext, aad string) (string, error) {
	dek := make([]byte, dekSize)
	if _, err := rand.Read(dek); err != nil {
		return "", err
	}
	defer zero(dek)

	aead, err := newGCM(dek)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ct := aead.Seal(nil, nonce, []byte(plaintext), []byte(aad))

	wrapped, err := v.kek.Wrap(ctx, dek)
	if err != nil {
		return "", fmt.Errorf("vault: wrap data key: %w", err)
	}
	if len(wrapped) > 0xffff {
		return "", errors.New("vault: wrapped data key too large")
	}

	buf := make([]byte, 2+len(wrapped)+nonceSize+len(ct))
	binary.BigEndian.PutUint16(buf, uint16(len(wrapped)))
	n := 2
	n += copy(buf[n:], wrapped)
	n += copy(buf[n:], nonce)
	copy(buf[n:], ct)
	return tokenPrefix + base64.RawURLEncoding.EncodeToString(buf), nil
}

// Decrypt reverses Encrypt: it unwraps the data key via the KEK and opens the
// AES-256-GCM ciphertext bound to aad. Any failure — unknown version, tampered
// token, wrong aad, or a KEK/unwrap error — returns ErrInvalidToken without
// distinguishing the cause.
func (v *Vault) Decrypt(ctx context.Context, token, aad string) (string, error) {
	raw, ok := strings.CutPrefix(token, tokenPrefix)
	if !ok {
		return "", fmt.Errorf("%w: unknown token version", ErrInvalidToken)
	}
	blob, err := decodeB64(raw)
	if err != nil || len(blob) < 2 {
		return "", ErrInvalidToken
	}
	wl := int(binary.BigEndian.Uint16(blob))
	if len(blob) < 2+wl+nonceSize+1 {
		return "", ErrInvalidToken
	}
	wrapped := blob[2 : 2+wl]
	nonce := blob[2+wl : 2+wl+nonceSize]
	ct := blob[2+wl+nonceSize:]

	dek, err := v.kek.Unwrap(ctx, wrapped)
	if err != nil {
		return "", ErrInvalidToken
	}
	defer zero(dek)

	aead, err := newGCM(dek)
	if err != nil {
		return "", ErrInvalidToken
	}
	pt, err := aead.Open(nil, nonce, ct, []byte(aad))
	if err != nil {
		return "", ErrInvalidToken
	}
	return string(pt), nil
}

// newGCM builds an AES-256-GCM AEAD from a 32-byte key.
func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// zero overwrites b with zeros; used to wipe transient key material.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// decodeB64 decodes raw-urlsafe base64, tolerating any stray "=" padding.
func decodeB64(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
}
