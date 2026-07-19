package maint

import (
	"context"
	"testing"

	"github.com/morandeirachema/pamv1/internal/store"
	"github.com/morandeirachema/pamv1/internal/store/memstore"
	"github.com/morandeirachema/pamv1/internal/vault"
)

// newVault builds a vault with a fresh random master key for the test.
func newVault(t *testing.T) *vault.Vault {
	t.Helper()
	key, err := vault.GenerateMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	v, err := vault.New(key)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// TestRotateVaultKEK checks re-encryption moves every secret from the old vault
// to the new one, preserving plaintext, AAD binding, and the confirmed flag.
func TestRotateVaultKEK(t *testing.T) {
	ctx := context.Background()
	st := memstore.New()
	from, to := newVault(t), newVault(t)

	// Seed a credential and an MFA enrollment encrypted under `from`.
	target := &store.Target{Name: "web", Host: "h", Port: 22, OSType: "linux", Protocol: "ssh"}
	if err := st.CreateTarget(ctx, target); err != nil {
		t.Fatal(err)
	}
	cred := &store.Credential{TargetID: target.ID, Username: "root", SecretType: "password"}
	if err := st.CreateCredential(ctx, cred); err != nil {
		t.Fatal(err)
	}
	credEnc, _ := from.Encrypt(ctx, "cred-secret", store.CredentialAAD(target.ID, cred.ID))
	if err := st.UpdateCredentialSecretEnc(ctx, cred.ID, credEnc); err != nil {
		t.Fatal(err)
	}
	mfaEnc, _ := from.Encrypt(ctx, "TOTPSECRET", store.MFAAAD("alice"))
	if err := st.UpsertMFAEnrollment(ctx, &store.MFAEnrollment{Username: "alice", SecretEnc: mfaEnc, Confirmed: true}); err != nil {
		t.Fatal(err)
	}

	n, err := RotateVaultKEK(ctx, st, from, to)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if n != 2 {
		t.Fatalf("rotated %d secrets, want 2", n)
	}

	// The secrets now decrypt with the new vault, not the old one.
	got, _ := st.GetCredential(ctx, cred.ID)
	if pt, err := to.Decrypt(ctx, got.SecretEnc, store.CredentialAAD(target.ID, cred.ID)); err != nil || pt != "cred-secret" {
		t.Fatalf("new vault should decrypt credential: %q %v", pt, err)
	}
	if _, err := from.Decrypt(ctx, got.SecretEnc, store.CredentialAAD(target.ID, cred.ID)); err == nil {
		t.Fatal("old vault must no longer decrypt the rotated credential")
	}

	enr, _ := st.GetMFAEnrollment(ctx, "alice")
	if !enr.Confirmed {
		t.Fatal("rotation must preserve the confirmed flag")
	}
	if pt, err := to.Decrypt(ctx, enr.SecretEnc, store.MFAAAD("alice")); err != nil || pt != "TOTPSECRET" {
		t.Fatalf("new vault should decrypt MFA secret: %q %v", pt, err)
	}

	// Idempotent/resumable: re-running against the same store must not fail on the
	// already-rotated rows (it would strand a partially-rotated store otherwise).
	n2, err := RotateVaultKEK(ctx, st, from, to)
	if err != nil {
		t.Fatalf("re-run after full rotation should be a no-op, got: %v", err)
	}
	if n2 != 0 {
		t.Fatalf("re-run rotated %d secrets, want 0 (all already rotated)", n2)
	}
}

// TestCredentialAADBindsToCredential proves a vaulted secret is bound to its
// specific credential row: a ciphertext for one credential cannot be decrypted
// as another credential, even on the same target.
func TestCredentialAADBindsToCredential(t *testing.T) {
	ctx := context.Background()
	v := newVault(t)
	const targetID = int64(7)
	encA, err := v.Encrypt(ctx, "secret-A", store.CredentialAAD(targetID, 1))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Decrypt(ctx, encA, store.CredentialAAD(targetID, 2)); err == nil {
		t.Fatal("ciphertext for cred 1 must not decrypt as cred 2 on the same target")
	}
	if pt, err := v.Decrypt(ctx, encA, store.CredentialAAD(targetID, 1)); err != nil || pt != "secret-A" {
		t.Fatalf("correct AAD should decrypt: %q %v", pt, err)
	}
}

// TestRotateVaultKEKResumesPartial proves a rotation interrupted partway can be
// resumed: rows already under the new KEK are skipped, and the remaining ones
// are rotated, without either KEK having to decrypt the whole store.
func TestRotateVaultKEKResumesPartial(t *testing.T) {
	ctx := context.Background()
	st := memstore.New()
	from, to := newVault(t), newVault(t)
	target := &store.Target{Name: "web", Host: "h", Port: 22, OSType: "linux", Protocol: "ssh"}
	if err := st.CreateTarget(ctx, target); err != nil {
		t.Fatal(err)
	}
	// Two credentials: one already under the NEW KEK (as if a prior run rotated it
	// before crashing), one still under the OLD KEK.
	credA := &store.Credential{TargetID: target.ID, Username: "a", SecretType: "password"}
	if err := st.CreateCredential(ctx, credA); err != nil {
		t.Fatal(err)
	}
	rotatedEnc, _ := to.Encrypt(ctx, "already", store.CredentialAAD(target.ID, credA.ID))
	if err := st.UpdateCredentialSecretEnc(ctx, credA.ID, rotatedEnc); err != nil {
		t.Fatal(err)
	}
	credB := &store.Credential{TargetID: target.ID, Username: "b", SecretType: "password"}
	if err := st.CreateCredential(ctx, credB); err != nil {
		t.Fatal(err)
	}
	pendingEnc, _ := from.Encrypt(ctx, "pending", store.CredentialAAD(target.ID, credB.ID))
	if err := st.UpdateCredentialSecretEnc(ctx, credB.ID, pendingEnc); err != nil {
		t.Fatal(err)
	}

	n, err := RotateVaultKEK(ctx, st, from, to)
	if err != nil {
		t.Fatalf("resume should not fail on the already-rotated row: %v", err)
	}
	if n != 1 {
		t.Fatalf("rotated %d, want 1 (only the pending row)", n)
	}
	creds, _ := st.ListCredentials(ctx, target.ID)
	for _, c := range creds {
		if _, err := to.Decrypt(ctx, c.SecretEnc, store.CredentialAAD(target.ID, c.ID)); err != nil {
			t.Fatalf("credential %q should decrypt under the new KEK after resume: %v", c.Username, err)
		}
	}
}
