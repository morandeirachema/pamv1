package maint

import (
	"context"
	"testing"

	"github.com/morandeirachema/pamv1/internal/store"
	"github.com/morandeirachema/pamv1/internal/store/memstore"
	"github.com/morandeirachema/pamv1/internal/vault"
)

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

func TestRotateVaultKEK(t *testing.T) {
	ctx := context.Background()
	st := memstore.New()
	from, to := newVault(t), newVault(t)

	// Seed a credential and an MFA enrollment encrypted under `from`.
	target := &store.Target{Name: "web", Host: "h", Port: 22, OSType: "linux", Protocol: "ssh"}
	if err := st.CreateTarget(ctx, target); err != nil {
		t.Fatal(err)
	}
	credEnc, _ := from.Encrypt(ctx, "cred-secret", store.CredentialAAD(target.ID))
	cred := &store.Credential{TargetID: target.ID, Username: "root", SecretType: "password", SecretEnc: credEnc}
	if err := st.CreateCredential(ctx, cred); err != nil {
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
	if pt, err := to.Decrypt(ctx, got.SecretEnc, store.CredentialAAD(target.ID)); err != nil || pt != "cred-secret" {
		t.Fatalf("new vault should decrypt credential: %q %v", pt, err)
	}
	if _, err := from.Decrypt(ctx, got.SecretEnc, store.CredentialAAD(target.ID)); err == nil {
		t.Fatal("old vault must no longer decrypt the rotated credential")
	}

	enr, _ := st.GetMFAEnrollment(ctx, "alice")
	if !enr.Confirmed {
		t.Fatal("rotation must preserve the confirmed flag")
	}
	if pt, err := to.Decrypt(ctx, enr.SecretEnc, store.MFAAAD("alice")); err != nil || pt != "TOTPSECRET" {
		t.Fatalf("new vault should decrypt MFA secret: %q %v", pt, err)
	}
}
