package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/morandeirachema/pamv1/internal/rotate"
	"github.com/morandeirachema/pamv1/internal/store"
)

// ErrUnsupported marks a rotation that cannot be attempted (wrong secret type or
// a protocol with no rotator) — a client precondition, not a target failure.
var ErrUnsupported = errors.New("rotation unsupported")

// --- credential rotation ---

// rotateCredentialHandler generates a fresh strong secret, sets it on the target
// over the target's protocol (SSH/WinRM), then re-vaults it and stamps
// rotated_at. The new secret is never returned — it lives only in the vault, to
// be injected just-in-time by the proxy.
func (s *Server) rotateCredentialHandler(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	cred, target, ok := s.loadCredentialTarget(w, r, id)
	if !ok {
		return
	}
	rotatedAt, err := s.rotateCredential(r.Context(), cred, target)
	if errors.Is(err, ErrUnsupported) {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	if err != nil {
		s.audit(r.Context(), "credential.rotate_failed",
			fmt.Sprintf("credential:%d target:%s error:%v", cred.ID, target.Name, err))
		s.log.Error("credential rotation failed", "credential", cred.ID, "target", target.Name, "err", err)
		writeError(w, http.StatusBadGateway, "rotation failed: "+err.Error())
		return
	}
	s.audit(r.Context(), "credential.rotate",
		fmt.Sprintf("credential:%d target:%s user:%s", cred.ID, target.Name, cred.Username))
	writeJSON(w, http.StatusOK, map[string]any{
		"id": cred.ID, "target": target.Name, "username": cred.Username,
		"rotated": true, "rotated_at": rotatedAt,
	})
}

// rotateCredential performs the rotation and vault update. Shared by the manual
// endpoint and reconciliation remediation.
func (s *Server) rotateCredential(ctx context.Context, cred *store.Credential, target *store.Target) (time.Time, error) {
	rotator, ok := s.rotators[target.Protocol]
	if !ok {
		return time.Time{}, fmt.Errorf("%w: no rotator for protocol %q", ErrUnsupported, target.Protocol)
	}
	oldSecret, err := s.vault.Decrypt(ctx, cred.SecretEnc, store.CredentialAAD(target.ID))
	if err != nil {
		return time.Time{}, fmt.Errorf("vault decrypt failed")
	}

	// Generate the new secret and apply it on the target. Passwords use the
	// Rotator; ssh_key credentials install a fresh keypair via a KeyRotator.
	var newSecret string
	switch cred.SecretType {
	case "password":
		newSecret, err = rotate.GeneratePassword(24)
		if err != nil {
			return time.Time{}, fmt.Errorf("password generation failed")
		}
		if err := rotator.Rotate(ctx, *target, cred.Username, oldSecret, newSecret); err != nil {
			return time.Time{}, err
		}
	case "ssh_key":
		kr, ok := rotator.(rotate.KeyRotator)
		if !ok {
			return time.Time{}, fmt.Errorf("%w: key rotation not supported for protocol %q", ErrUnsupported, target.Protocol)
		}
		newSecret, err = rotate.GenerateSSHKey()
		if err != nil {
			return time.Time{}, fmt.Errorf("ssh key generation failed")
		}
		if err := kr.RotateKey(ctx, *target, cred.Username, oldSecret, newSecret); err != nil {
			return time.Time{}, err
		}
	default:
		return time.Time{}, fmt.Errorf("%w: unknown secret type %q", ErrUnsupported, cred.SecretType)
	}

	enc, err := s.vault.Encrypt(ctx, newSecret, store.CredentialAAD(target.ID))
	if err != nil {
		// The target now has a password the vault does not hold — loud failure.
		return time.Time{}, fmt.Errorf("re-encrypt after rotation failed: %w", err)
	}
	now := time.Now().UTC()
	if err := s.store.RotateCredentialSecret(ctx, cred.ID, enc, now); err != nil {
		return time.Time{}, fmt.Errorf("persist rotated secret failed: %w", err)
	}
	return now, nil
}

// --- credential checkout / check-in (exclusive time-boxed lease) ---

type checkoutIn struct {
	Reason string `json:"reason"`
}

// checkoutCredential grants an exclusive, time-boxed lease on a credential and
// returns the secret to the holder. Only one holder may have a credential
// checked out at a time. On check-in the credential is rotated, so the password
// the holder saw can no longer be used. Honors the reveal-disabled policy
// (break-glass excepted), since a checkout reveals the secret.
func (s *Server) checkoutCredential(w http.ResponseWriter, r *http.Request) {
	if s.revealDisabled && !principalFrom(r.Context()).BreakGlass {
		s.audit(r.Context(), "credential.checkout_denied", "reason:reveal-disabled-by-policy")
		writeError(w, http.StatusForbidden, "credential checkout is disabled by policy; connect through the proxy")
		return
	}
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	cred, target, ok := s.loadCredentialTarget(w, r, id)
	if !ok {
		return
	}
	var in checkoutIn
	if r.ContentLength != 0 {
		if !readJSON(w, r, &in) {
			return
		}
	}
	now := time.Now()
	co := store.Checkout{
		CredentialID: cred.ID, TargetID: target.ID, Holder: actorFrom(r.Context()),
		Reason: in.Reason, ExpiresAt: now.Add(s.checkoutTTL).UTC(),
	}
	if err := s.store.CreateCheckout(r.Context(), &co, now); err != nil {
		if errors.Is(err, store.ErrConflict) {
			writeError(w, http.StatusConflict, "credential is already checked out")
			return
		}
		storeError(w, err)
		return
	}
	secret, err := s.vault.Decrypt(r.Context(), cred.SecretEnc, store.CredentialAAD(target.ID))
	if err != nil {
		s.audit(r.Context(), "credential.decrypt_failed", fmt.Sprintf("credential:%d target:%s op:checkout", cred.ID, target.Name))
		writeError(w, http.StatusInternalServerError, "decryption failed")
		return
	}
	s.audit(r.Context(), "credential.checkout",
		fmt.Sprintf("checkout:%d credential:%d target:%s until:%s", co.ID, cred.ID, target.Name, co.ExpiresAt.Format(time.RFC3339)))
	writeJSON(w, http.StatusCreated, map[string]any{
		"checkout_id": co.ID, "credential_id": cred.ID, "target": target.Name,
		"username": cred.Username, "secret": secret, "expires_at": co.ExpiresAt,
		"note": "Returned automatically on check-in, which rotates this secret.",
	})
}

// checkinCredential ends a checkout and rotates the credential so the revealed
// secret is invalidated. If rotation is unsupported/fails the check-in still
// succeeds but the response flags that the secret was not rotated.
func (s *Server) checkinCredential(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	cred, target, ok := s.loadCredentialTarget(w, r, id)
	if !ok {
		return
	}
	co, err := s.store.GetActiveCheckout(r.Context(), cred.ID, time.Now())
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusConflict, "credential is not checked out")
			return
		}
		storeError(w, err)
		return
	}
	if err := s.store.CheckinCheckout(r.Context(), co.ID, time.Now()); err != nil {
		storeError(w, err)
		return
	}
	s.audit(r.Context(), "credential.checkin", fmt.Sprintf("checkout:%d credential:%d target:%s", co.ID, cred.ID, target.Name))

	rotated := true
	rotateNote := "secret rotated on check-in"
	if _, rerr := s.rotateCredential(r.Context(), cred, target); rerr != nil {
		rotated = false
		rotateNote = "WARNING: secret was NOT rotated on check-in (" + rerr.Error() + ") — rotate it manually"
		s.audit(r.Context(), "credential.checkin_rotate_failed", fmt.Sprintf("credential:%d error:%v", cred.ID, rerr))
	} else {
		s.audit(r.Context(), "credential.rotate", fmt.Sprintf("credential:%d target:%s reason:checkin", cred.ID, target.Name))
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"checkout_id": co.ID, "credential_id": cred.ID, "returned": true,
		"rotated": rotated, "note": rotateNote,
	})
}

// listCheckouts reports checkouts (activeOnly via ?active=true).
func (s *Server) listCheckouts(w http.ResponseWriter, r *http.Request) {
	activeOnly := r.URL.Query().Get("active") == "true"
	cos, err := s.store.ListCheckouts(r.Context(), activeOnly, time.Now())
	if err != nil {
		storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, cos)
}

// --- account reconciliation (out-of-sync detection & remediation) ---

type reconcileResult struct {
	CredentialID int64  `json:"credential_id"`
	TargetID     int64  `json:"target_id"`
	Target       string `json:"target"`
	Username     string `json:"username"`
	Status       string `json:"status"` // in_sync | out_of_sync | unsupported
	Detail       string `json:"detail,omitempty"`
	Remediated   bool   `json:"remediated,omitempty"`
}

// reconcileCredentialHandler checks whether one credential's vaulted secret still
// authenticates to its target. With ?remediate=true, an out-of-sync password
// credential is reset to a fresh PAM-managed secret (rotation).
func (s *Server) reconcileCredentialHandler(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	cred, target, ok := s.loadCredentialTarget(w, r, id)
	if !ok {
		return
	}
	remediate := r.URL.Query().Get("remediate") == "true"
	res := s.reconcileOne(r.Context(), cred, target, remediate)
	writeJSON(w, http.StatusOK, res)
}

// reconcileAllHandler reconciles every credential and reports drift. It is a
// read-only scan (no remediation) so it is safe to run on a schedule.
func (s *Server) reconcileAllHandler(w http.ResponseWriter, r *http.Request) {
	creds, err := s.store.ListCredentials(r.Context(), 0)
	if err != nil {
		storeError(w, err)
		return
	}
	results := make([]reconcileResult, 0, len(creds))
	var drift int
	for i := range creds {
		cred := &creds[i]
		target, terr := s.store.GetTarget(r.Context(), cred.TargetID)
		if terr != nil {
			continue
		}
		res := s.reconcileOne(r.Context(), cred, target, false)
		if res.Status == "out_of_sync" {
			drift++
		}
		results = append(results, res)
	}
	s.audit(r.Context(), "credential.reconcile_scan", fmt.Sprintf("checked:%d out_of_sync:%d", len(results), drift))
	writeJSON(w, http.StatusOK, map[string]any{
		"checked": len(results), "out_of_sync": drift, "results": results,
	})
}

// reconcileOne verifies a single credential and, when asked and drifted,
// remediates by rotating to a PAM-managed secret. Every check is audited.
func (s *Server) reconcileOne(ctx context.Context, cred *store.Credential, target *store.Target, remediate bool) reconcileResult {
	res := reconcileResult{
		CredentialID: cred.ID, TargetID: target.ID, Target: target.Name, Username: cred.Username,
	}
	verifier, ok := s.verifiers[target.Protocol]
	if !ok {
		res.Status = "unsupported"
		res.Detail = "no verifier for protocol " + target.Protocol
		return res
	}
	secret, err := s.vault.Decrypt(ctx, cred.SecretEnc, store.CredentialAAD(target.ID))
	if err != nil {
		res.Status = "out_of_sync"
		res.Detail = "vault decrypt failed"
		s.audit(ctx, "credential.reconcile", fmt.Sprintf("credential:%d target:%s status:out_of_sync detail:vault", cred.ID, target.Name))
		return res
	}
	if verr := verifier.Verify(ctx, *target, cred.Username, secret); verr != nil {
		res.Status = "out_of_sync"
		res.Detail = verr.Error()
		s.audit(ctx, "credential.reconcile", fmt.Sprintf("credential:%d target:%s status:out_of_sync", cred.ID, target.Name))
		if remediate {
			if _, rerr := s.rotateCredential(ctx, cred, target); rerr != nil {
				res.Detail += "; remediation failed: " + rerr.Error()
			} else {
				res.Remediated = true
				res.Detail += "; remediated (rotated to a PAM-managed secret)"
				s.audit(ctx, "credential.remediate", fmt.Sprintf("credential:%d target:%s", cred.ID, target.Name))
			}
		}
		return res
	}
	res.Status = "in_sync"
	s.audit(ctx, "credential.reconcile", fmt.Sprintf("credential:%d target:%s status:in_sync", cred.ID, target.Name))
	return res
}

// loadCredentialTarget fetches a credential and its target, writing the
// appropriate error response and returning ok=false on failure.
func (s *Server) loadCredentialTarget(w http.ResponseWriter, r *http.Request, id int64) (*store.Credential, *store.Target, bool) {
	cred, err := s.store.GetCredential(r.Context(), id)
	if err != nil {
		storeError(w, err)
		return nil, nil, false
	}
	target, err := s.store.GetTarget(r.Context(), cred.TargetID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusUnprocessableEntity, "credential's target no longer exists")
		} else {
			storeError(w, err)
		}
		return nil, nil, false
	}
	return cred, target, true
}
