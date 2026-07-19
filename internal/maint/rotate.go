// Package maint holds offline maintenance operations for pamv1.
package maint

import (
	"context"
	"fmt"

	"github.com/morandeirachema/pamv1/internal/store"
	"github.com/morandeirachema/pamv1/internal/vault"
)

// RotateVaultKEK re-encrypts every vaulted secret (credentials and TOTP
// enrollments) from the `from` vault to the `to` vault, preserving each secret's
// AAD binding. It returns the number of secrets re-encrypted. Run it offline
// (nothing else writing secrets), then switch the server to the new key.
func RotateVaultKEK(ctx context.Context, st store.Store, from, to *vault.Vault) (int, error) {
	n := 0

	creds, err := st.ListCredentials(ctx, 0)
	if err != nil {
		return n, fmt.Errorf("list credentials: %w", err)
	}
	for _, c := range creds {
		aad := store.CredentialAAD(c.TargetID, c.ID)
		// Idempotent/resumable: if this secret already decrypts under the new KEK
		// (a prior run rotated it before crashing), skip it rather than failing on
		// the `from` decrypt and stranding the store in a mixed-key state.
		if _, err := to.Decrypt(ctx, c.SecretEnc, aad); err == nil {
			continue
		}
		plain, err := from.Decrypt(ctx, c.SecretEnc, aad)
		if err != nil {
			return n, fmt.Errorf("credential %d decrypt: %w", c.ID, err)
		}
		enc, err := to.Encrypt(ctx, plain, aad)
		if err != nil {
			return n, fmt.Errorf("credential %d encrypt: %w", c.ID, err)
		}
		if err := st.UpdateCredentialSecretEnc(ctx, c.ID, enc); err != nil {
			return n, fmt.Errorf("credential %d update: %w", c.ID, err)
		}
		n++
	}

	enrollments, err := st.ListMFAEnrollments(ctx)
	if err != nil {
		return n, fmt.Errorf("list mfa: %w", err)
	}
	for _, e := range enrollments {
		aad := store.MFAAAD(e.Username)
		if _, err := to.Decrypt(ctx, e.SecretEnc, aad); err == nil {
			continue // already rotated under the new KEK
		}
		plain, err := from.Decrypt(ctx, e.SecretEnc, aad)
		if err != nil {
			return n, fmt.Errorf("mfa %s decrypt: %w", e.Username, err)
		}
		enc, err := to.Encrypt(ctx, plain, aad)
		if err != nil {
			return n, fmt.Errorf("mfa %s encrypt: %w", e.Username, err)
		}
		e.SecretEnc = enc
		if err := st.UpsertMFAEnrollment(ctx, &e); err != nil {
			return n, fmt.Errorf("mfa %s update: %w", e.Username, err)
		}
		n++
	}

	return n, nil
}
