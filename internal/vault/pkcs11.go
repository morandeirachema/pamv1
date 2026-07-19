//go:build pkcs11

// Package vault — PKCS#11 (on-prem HSM) KEK provider. Built only with the
// "pkcs11" tag because it needs cgo and dlopens a vendor PKCS#11 module at
// runtime (incompatible with the default CGO_ENABLED=0 static/distroless image).
//
// The wrapping key is an AES key that lives *inside* the HSM (found by its
// CKA_LABEL); data keys are wrapped/unwrapped with **CKM_AES_GCM** so the KEK
// never leaves the token AND the wrap is authenticated: a tampered wrapped-DEK
// fails the HSM's GCM tag check rather than decrypting to a wrong DEK, which
// avoids the padding-oracle exposure an unauthenticated CBC-PAD wrap would have
// (the inner AES-256-GCM layer still binds the whole token to its AAD).
package vault

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/miekg/pkcs11"
)

const (
	pkcs11GCMNonceSize = 12  // AES-GCM nonce
	pkcs11GCMTagBits   = 128 // AES-GCM tag length
)

// PKCS11KEK wraps data keys with an AES key held in a PKCS#11 token.
type PKCS11KEK struct {
	ctx      *pkcs11.Ctx
	session  pkcs11.SessionHandle
	key      pkcs11.ObjectHandle
	keyLabel string
	mu       sync.Mutex // PKCS#11 session ops on one session must be serialized
}

// NewPKCS11KEK loads the module, opens a session on the selected token, logs in
// with the user PIN, and locates the AES wrapping key by label.
func NewPKCS11KEK(module, pin, keyLabel, tokenLabel string) (KEK, error) {
	if module == "" || keyLabel == "" {
		return nil, errors.New("vault: pkcs11 requires PAM_KEK_PKCS11_MODULE and PAM_KEK_PKCS11_KEY_LABEL")
	}
	ctx := pkcs11.New(module)
	if ctx == nil {
		return nil, fmt.Errorf("vault: cannot load PKCS#11 module %q", module)
	}
	if err := ctx.Initialize(); err != nil && !isAlreadyInit(err) {
		ctx.Destroy()
		return nil, fmt.Errorf("vault: pkcs11 initialize: %w", err)
	}
	slot, err := selectSlot(ctx, tokenLabel)
	if err != nil {
		ctx.Finalize()
		ctx.Destroy()
		return nil, err
	}
	session, err := ctx.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		ctx.Finalize()
		ctx.Destroy()
		return nil, fmt.Errorf("vault: pkcs11 open session: %w", err)
	}
	if err := ctx.Login(session, pkcs11.CKU_USER, pin); err != nil && !isAlreadyLoggedIn(err) {
		ctx.CloseSession(session)
		ctx.Finalize()
		ctx.Destroy()
		return nil, fmt.Errorf("vault: pkcs11 login: %w", err)
	}
	key, err := findKey(ctx, session, keyLabel)
	if err != nil {
		ctx.CloseSession(session)
		ctx.Finalize()
		ctx.Destroy()
		return nil, err
	}
	return &PKCS11KEK{ctx: ctx, session: session, key: key, keyLabel: keyLabel}, nil
}

// Wrap encrypts the data key inside the HSM with CKM_AES_GCM under a fresh random
// nonce, returning nonce||ciphertext||tag. The actual nonce is read back from the
// mechanism params after the operation, so tokens that generate their own IV
// (e.g. CloudHSM) are handled too. Session ops are serialized by mu.
func (k *PKCS11KEK) Wrap(_ context.Context, dek []byte) ([]byte, error) {
	nonce := make([]byte, pkcs11GCMNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	gcm := pkcs11.NewGCMParams(nonce, nil, pkcs11GCMTagBits)
	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_GCM, gcm)}
	k.mu.Lock()
	defer k.mu.Unlock()
	defer gcm.Free()
	if err := k.ctx.EncryptInit(k.session, mech, k.key); err != nil {
		return nil, fmt.Errorf("vault: pkcs11 wrap init: %w", err)
	}
	ct, err := k.ctx.Encrypt(k.session, dek)
	if err != nil {
		return nil, fmt.Errorf("vault: pkcs11 wrap: %w", err)
	}
	usedNonce := gcm.IV() // the token may have generated its own
	if len(usedNonce) == 0 {
		usedNonce = nonce
	}
	return append(append(make([]byte, 0, len(usedNonce)+len(ct)), usedNonce...), ct...), nil
}

// Unwrap splits the leading nonce from the ciphertext+tag and GCM-decrypts it in
// the HSM. A tampered blob fails the GCM tag check; any failure returns
// ErrInvalidToken.
func (k *PKCS11KEK) Unwrap(_ context.Context, wrapped []byte) ([]byte, error) {
	if len(wrapped) <= pkcs11GCMNonceSize {
		return nil, ErrInvalidToken
	}
	nonce, ct := wrapped[:pkcs11GCMNonceSize], wrapped[pkcs11GCMNonceSize:]
	gcm := pkcs11.NewGCMParams(nonce, nil, pkcs11GCMTagBits)
	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_GCM, gcm)}
	k.mu.Lock()
	defer k.mu.Unlock()
	defer gcm.Free()
	if err := k.ctx.DecryptInit(k.session, mech, k.key); err != nil {
		return nil, ErrInvalidToken
	}
	dek, err := k.ctx.Decrypt(k.session, ct)
	if err != nil {
		return nil, ErrInvalidToken
	}
	return dek, nil
}

// ID reports the provider identifier, "pkcs11:<keyLabel>".
func (k *PKCS11KEK) ID() string { return "pkcs11:" + k.keyLabel }

// --- helpers ---

// selectSlot returns the slot with a present token: the first one if tokenLabel
// is empty, otherwise the slot whose token label matches (error if none match).
func selectSlot(ctx *pkcs11.Ctx, tokenLabel string) (uint, error) {
	slots, err := ctx.GetSlotList(true)
	if err != nil {
		return 0, fmt.Errorf("vault: pkcs11 slot list: %w", err)
	}
	if len(slots) == 0 {
		return 0, errors.New("vault: pkcs11 no token present")
	}
	if tokenLabel == "" {
		return slots[0], nil
	}
	for _, s := range slots {
		if ti, err := ctx.GetTokenInfo(s); err == nil && strings.TrimSpace(ti.Label) == tokenLabel {
			return s, nil
		}
	}
	return 0, fmt.Errorf("vault: pkcs11 token %q not found", tokenLabel)
}

// findKey locates the AES secret key with the given CKA_LABEL in the session,
// erroring if no such key exists.
func findKey(ctx *pkcs11.Ctx, session pkcs11.SessionHandle, label string) (pkcs11.ObjectHandle, error) {
	tmpl := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_AES),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
	}
	if err := ctx.FindObjectsInit(session, tmpl); err != nil {
		return 0, fmt.Errorf("vault: pkcs11 find init: %w", err)
	}
	objs, _, err := ctx.FindObjects(session, 1)
	_ = ctx.FindObjectsFinal(session)
	if err != nil {
		return 0, fmt.Errorf("vault: pkcs11 find: %w", err)
	}
	if len(objs) == 0 {
		return 0, fmt.Errorf("vault: pkcs11 AES key labelled %q not found", label)
	}
	return objs[0], nil
}

// isAlreadyInit reports whether err is the benign "cryptoki already initialized"
// PKCS#11 error (a shared module may already be initialized).
func isAlreadyInit(err error) bool {
	var e pkcs11.Error
	return errors.As(err, &e) && e == pkcs11.CKR_CRYPTOKI_ALREADY_INITIALIZED
}

// isAlreadyLoggedIn reports whether err is the benign "user already logged in"
// PKCS#11 error (the session may already hold a login).
func isAlreadyLoggedIn(err error) bool {
	var e pkcs11.Error
	return errors.As(err, &e) && e == pkcs11.CKR_USER_ALREADY_LOGGED_IN
}
