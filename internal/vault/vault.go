// Package vault implements hardened at-rest encryption for secrets:
// AES-256-GCM with a random nonce per secret and AAD binding to the owning
// record, using a versioned token format ("v1:") so the master key can be
// rotated in a later phase without breaking stored ciphertexts.
package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

const tokenPrefix = "v1:"

var ErrInvalidToken = errors.New("vault: invalid or tampered token")

type Vault struct {
	aead cipher.AEAD
}

// GenerateMasterKey returns a fresh 256-bit key, urlsafe-base64 encoded,
// suitable for PAM_MASTER_KEY.
func GenerateMasterKey() (string, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(key), nil
}

func New(masterKey string) (*Vault, error) {
	key, err := decodeB64(masterKey)
	if err != nil || len(key) != 32 {
		return nil, errors.New("vault: PAM_MASTER_KEY must be 32 bytes, urlsafe-base64 encoded")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Vault{aead: aead}, nil
}

// Encrypt seals plaintext bound to aad (e.g. "target:42"); the returned
// token only decrypts with the same aad, so a token copied onto another
// record fails authentication.
func (v *Vault) Encrypt(plaintext, aad string) (string, error) {
	nonce := make([]byte, v.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ct := v.aead.Seal(nonce, nonce, []byte(plaintext), []byte(aad))
	return tokenPrefix + base64.RawURLEncoding.EncodeToString(ct), nil
}

func (v *Vault) Decrypt(token, aad string) (string, error) {
	raw, ok := strings.CutPrefix(token, tokenPrefix)
	if !ok {
		return "", fmt.Errorf("%w: unknown token version", ErrInvalidToken)
	}
	data, err := decodeB64(raw)
	if err != nil || len(data) <= v.aead.NonceSize() {
		return "", ErrInvalidToken
	}
	n := v.aead.NonceSize()
	pt, err := v.aead.Open(nil, data[:n], data[n:], []byte(aad))
	if err != nil {
		return "", ErrInvalidToken
	}
	return string(pt), nil
}

func decodeB64(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
}
