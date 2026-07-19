//go:build pkcs11

package vault

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"testing"

	"github.com/miekg/pkcs11"
)

// TestPKCS11RoundTrip runs against a real PKCS#11 module (SoftHSM2 in CI). It
// generates a throwaway AES-256 wrapping key in the token, builds a PKCS11KEK
// over it, and proves wrap→unwrap is an identity and end-to-end Encrypt/Decrypt
// works. Skips unless PAM_TEST_PKCS11_MODULE is set.
//
// Required env (CI sets these after `softhsm2-util --init-token`):
//
//	PAM_TEST_PKCS11_MODULE  path to the module .so
//	PAM_TEST_PKCS11_PIN     user PIN
//	PAM_TEST_PKCS11_TOKEN   token label (optional)
func TestPKCS11RoundTrip(t *testing.T) {
	module := os.Getenv("PAM_TEST_PKCS11_MODULE")
	if module == "" {
		t.Skip("PAM_TEST_PKCS11_MODULE not set; skipping HSM test")
	}
	pin := os.Getenv("PAM_TEST_PKCS11_PIN")
	tokenLabel := os.Getenv("PAM_TEST_PKCS11_TOKEN")

	label := "pamv1-test-" + randLabel(t)
	destroy := generateAESKey(t, module, pin, tokenLabel, label)
	defer destroy()

	kek, err := NewPKCS11KEK(module, pin, label, tokenLabel)
	if err != nil {
		t.Fatalf("NewPKCS11KEK: %v", err)
	}
	if kek.ID() != "pkcs11:"+label {
		t.Fatalf("ID = %q", kek.ID())
	}

	// Wrap/unwrap identity for a 32-byte data key.
	dek := make([]byte, 32)
	rand.Read(dek)
	wrapped, err := kek.Wrap(context.Background(), dek)
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	if bytes.Equal(wrapped, dek) {
		t.Fatal("wrapped blob equals plaintext DEK")
	}
	got, err := kek.Unwrap(context.Background(), wrapped)
	if err != nil {
		t.Fatalf("unwrap: %v", err)
	}
	if !bytes.Equal(got, dek) {
		t.Fatalf("round-trip mismatch: %x != %x", got, dek)
	}

	// Authenticated wrap: a tampered blob must fail the HSM's GCM tag check, not
	// decrypt to a wrong DEK (which is what CBC-PAD would have done).
	tampered := append([]byte(nil), wrapped...)
	tampered[len(tampered)-1] ^= 0xFF
	if _, err := kek.Unwrap(context.Background(), tampered); err == nil {
		t.Fatal("unwrap of a tampered blob should fail (GCM tag)")
	}

	// End-to-end: a full vault Encrypt/Decrypt with the HSM-backed KEK.
	v := NewWithKEK(kek)
	tok, err := v.Encrypt(context.Background(), "s3cr3t", "target:1")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	pt, err := v.Decrypt(context.Background(), tok, "target:1")
	if err != nil || pt != "s3cr3t" {
		t.Fatalf("decrypt: %q err=%v", pt, err)
	}
	// Wrong AAD must fail (proves the AEAD binding survives the HSM KEK layer).
	if _, err := v.Decrypt(context.Background(), tok, "target:2"); err == nil {
		t.Fatal("decrypt with wrong AAD should fail")
	}
}

// randLabel returns a short random hex string for a throwaway key label.
func randLabel(t *testing.T) string {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

// generateAESKey creates a token AES-256 key with the given label and returns a
// cleanup func that destroys it.
func generateAESKey(t *testing.T, module, pin, tokenLabel, label string) func() {
	t.Helper()
	ctx := pkcs11.New(module)
	if ctx == nil {
		t.Fatalf("load module %q", module)
	}
	if err := ctx.Initialize(); err != nil && !isAlreadyInit(err) {
		t.Fatalf("initialize: %v", err)
	}
	slot, err := selectSlot(ctx, tokenLabel)
	if err != nil {
		t.Fatal(err)
	}
	sess, err := ctx.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		t.Fatalf("open session: %v", err)
	}
	if err := ctx.Login(sess, pkcs11.CKU_USER, pin); err != nil && !isAlreadyLoggedIn(err) {
		t.Fatalf("login: %v", err)
	}
	tmpl := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_AES),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, 32),
	}
	obj, err := ctx.GenerateKey(sess, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_KEY_GEN, nil)}, tmpl)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return func() {
		_ = ctx.DestroyObject(sess, obj)
		_ = ctx.Logout(sess)
		_ = ctx.CloseSession(sess)
		_ = ctx.Finalize()
		ctx.Destroy()
	}
}
