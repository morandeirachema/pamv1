package vault

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
)

// KEK is a Key Encryption Key: it wraps (encrypts) and unwraps the per-secret
// data keys used by the vault. This is the standard envelope-encryption pattern
// that PAM/KMS vendors use — the KEK can be a local key (dev/test) or, in
// production, live in a KMS/HSM that the wrapped data keys are round-tripped
// through (so the KEK never leaves the KMS).
type KEK interface {
	// Wrap encrypts a data key; Unwrap reverses it.
	Wrap(ctx context.Context, dek []byte) ([]byte, error)
	Unwrap(ctx context.Context, wrapped []byte) ([]byte, error)
	// ID identifies the KEK/provider for logging.
	ID() string
}

// kekAAD binds wrapped data keys to this application.
const kekAAD = "pamv1/kek/v1"

// LocalKEK wraps data keys with an AES-256-GCM key held in process, derived
// from PAM_MASTER_KEY. It is intended for development and tests only — the key
// sits in an environment variable. For production use a KMS-backed KEK
// (see TransitKEK) so the key material never leaves the KMS/HSM.
type LocalKEK struct {
	aead cipher.AEAD
}

// NewLocalKEK builds a LocalKEK from masterKey, which must be a 32-byte key
// encoded as urlsafe base64 (as produced by GenerateMasterKey).
func NewLocalKEK(masterKey string) (*LocalKEK, error) {
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
	return &LocalKEK{aead: aead}, nil
}

// Wrap seals the data key with AES-256-GCM under the local key, prepending a
// fresh random nonce to the returned blob.
func (k *LocalKEK) Wrap(_ context.Context, dek []byte) ([]byte, error) {
	nonce := make([]byte, k.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return k.aead.Seal(nonce, nonce, dek, []byte(kekAAD)), nil
}

// Unwrap reverses Wrap, returning ErrInvalidToken if the blob is too short or
// fails GCM authentication.
func (k *LocalKEK) Unwrap(_ context.Context, wrapped []byte) ([]byte, error) {
	n := k.aead.NonceSize()
	if len(wrapped) <= n {
		return nil, ErrInvalidToken
	}
	dek, err := k.aead.Open(nil, wrapped[:n], wrapped[n:], []byte(kekAAD))
	if err != nil {
		return nil, ErrInvalidToken
	}
	return dek, nil
}

// ID reports the provider identifier ("local").
func (k *LocalKEK) ID() string { return "local" }

// KEKOptions selects and configures a KEK provider.
type KEKOptions struct {
	Provider  string // "local" (default, dev/test) | "vault-transit" | "aws-kms"
	MasterKey string // local provider

	TransitAddr  string // vault-transit provider
	TransitToken string
	TransitKey   string

	AWSRegion   string // aws-kms provider
	AWSKMSKeyID string

	// pkcs11 provider (on-prem HSM; only in builds tagged "pkcs11").
	PKCS11Module     string // path to the vendor PKCS#11 module (.so)
	PKCS11Pin        string // user PIN
	PKCS11KeyLabel   string // CKA_LABEL of the AES wrapping key in the HSM
	PKCS11TokenLabel string // token label (optional; first token if empty)
}

// NewKEK builds a KEK from options. "local" uses PAM_MASTER_KEY (dev/test);
// "vault-transit" uses HashiCorp Vault's Transit engine; "aws-kms" uses AWS KMS
// (both production, the key never leaves the KMS).
func NewKEK(o KEKOptions) (KEK, error) {
	switch o.Provider {
	case "", "local":
		return NewLocalKEK(o.MasterKey)
	case "vault-transit":
		return NewTransitKEK(o.TransitAddr, o.TransitToken, o.TransitKey)
	case "aws-kms":
		return NewAWSKMSKEK(context.Background(), o.AWSRegion, o.AWSKMSKeyID)
	case "pkcs11":
		// Real implementation lives in pkcs11.go (build tag "pkcs11"); the
		// default build returns a helpful "not built in" error from the stub.
		return NewPKCS11KEK(o.PKCS11Module, o.PKCS11Pin, o.PKCS11KeyLabel, o.PKCS11TokenLabel)
	default:
		return nil, fmt.Errorf("vault: unknown KEK provider %q (want local|vault-transit|aws-kms|pkcs11)", o.Provider)
	}
}
