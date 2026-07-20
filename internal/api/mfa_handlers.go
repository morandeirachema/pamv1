package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/morandeirachema/pamv1/internal/mfa"
	"github.com/morandeirachema/pamv1/internal/store"
)

func (s *Server) mfaEnroll(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	// Replacing a CONFIRMED second factor requires proving the current one, so a
	// stolen session token cannot silently swap MFA to an attacker's device. The
	// first enrollment (none or unconfirmed) needs no code.
	var body struct {
		OTP string `json:"otp"`
	}
	if r.Body != nil {
		_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body)
	}
	if existing, gerr := s.store.GetMFAEnrollment(r.Context(), p.Name); gerr == nil && existing.Confirmed {
		if body.OTP == "" || !s.checkSecondFactor(r.Context(), p.Name, existing, body.OTP) {
			writeError(w, http.StatusUnauthorized, "current multi-factor code required to re-enroll")
			return
		}
	} else if gerr != nil && !errors.Is(gerr, store.ErrNotFound) {
		storeError(w, gerr)
		return
	}
	secret, err := mfa.GenerateSecret()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "secret generation failed")
		return
	}
	enc, err := s.vault.Encrypt(r.Context(), secret, store.MFAAAD(p.Name))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "encryption failed")
		return
	}
	if err := s.store.UpsertMFAEnrollment(r.Context(), &store.MFAEnrollment{
		Username: p.Name, SecretEnc: enc, Confirmed: false,
	}); err != nil {
		storeError(w, err)
		return
	}
	s.audit(r.Context(), "mfa.enroll", "user:"+p.Name)
	writeJSON(w, http.StatusCreated, map[string]any{
		"secret":       secret,
		"otpauth_uri":  mfa.ProvisioningURI(secret, p.Name, "pamv1"),
		"instructions": "Add this to your authenticator app, then confirm a code at POST /api/mfa/verify.",
	})
}

// mfaVerify confirms an enrollment (or checks a code) for the caller.
func (s *Server) mfaVerify(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	var in struct {
		OTP string `json:"otp"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	e, err := s.store.GetMFAEnrollment(r.Context(), p.Name)
	if err != nil {
		writeError(w, http.StatusBadRequest, "no MFA enrollment; call /api/mfa/enroll first")
		return
	}
	secret, err := s.vault.Decrypt(r.Context(), e.SecretEnc, store.MFAAAD(p.Name))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "decryption failed")
		return
	}
	// Validate without consuming the time-step: verify is a session-authenticated
	// enrollment check, and confirming here then logging in with the same in-window
	// code is a legitimate flow. The login path (checkSecondFactor) is what enforces
	// single-use against replay.
	if !mfa.Validate(secret, in.OTP, time.Now()) {
		writeError(w, http.StatusUnauthorized, "invalid multi-factor code")
		return
	}
	if !e.Confirmed {
		e.Confirmed = true
		if err := s.store.UpsertMFAEnrollment(r.Context(), e); err != nil {
			storeError(w, err)
			return
		}
		s.audit(r.Context(), "mfa.confirm", "user:"+p.Name)
	}
	writeJSON(w, http.StatusOK, map[string]any{"confirmed": true})
}

// mfaStatus reports whether the caller has enrolled/confirmed MFA.
func (s *Server) mfaStatus(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	e, err := s.store.GetMFAEnrollment(r.Context(), p.Name)
	if errors.Is(err, store.ErrNotFound) {
		writeJSON(w, http.StatusOK, map[string]any{"enrolled": false, "confirmed": false})
		return
	}
	if err != nil {
		storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"enrolled": true, "confirmed": e.Confirmed})
}

// mfaDisable removes the caller's TOTP enrollment (and recovery codes). Removing
// a confirmed factor requires proving the current one, so a stolen session cannot
// strip a victim's MFA.
func (s *Server) mfaDisable(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	existing, gerr := s.store.GetMFAEnrollment(r.Context(), p.Name)
	if gerr != nil && !errors.Is(gerr, store.ErrNotFound) {
		storeError(w, gerr)
		return
	}
	if gerr == nil && existing.Confirmed {
		var body struct {
			OTP string `json:"otp"`
		}
		if r.Body != nil {
			_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body)
		}
		if body.OTP == "" || !s.checkSecondFactor(r.Context(), p.Name, existing, body.OTP) {
			writeError(w, http.StatusUnauthorized, "current multi-factor code required to disable MFA")
			return
		}
	}
	if err := s.store.DeleteMFAEnrollment(r.Context(), p.Name); err != nil && !errors.Is(err, store.ErrNotFound) {
		storeError(w, err)
		return
	}
	s.audit(r.Context(), "mfa.disable", "user:"+p.Name)
	w.WriteHeader(http.StatusNoContent)
}

// mfaRecoveryCodes generates a fresh set of single-use recovery codes and
// returns them once, replacing any previous set. Requires confirmed MFA.
func (s *Server) mfaRecoveryCodes(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	if p.EnrollOnly {
		writeError(w, http.StatusForbidden, "complete MFA enrollment first")
		return
	}
	enr, err := s.store.GetMFAEnrollment(r.Context(), p.Name)
	if err != nil || !enr.Confirmed {
		writeError(w, http.StatusBadRequest, "confirm MFA before generating recovery codes")
		return
	}
	codes, err := mfa.GenerateRecoveryCodes(10)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "code generation failed")
		return
	}
	hashes := make([]string, len(codes))
	for i, c := range codes {
		hashes[i] = hashHex(c)
	}
	if err := s.store.ReplaceMFARecoveryCodes(r.Context(), p.Name, hashes); err != nil {
		storeError(w, err)
		return
	}
	s.audit(r.Context(), "mfa.recovery_generated", "user:"+p.Name)
	writeJSON(w, http.StatusCreated, map[string]any{
		"recovery_codes": codes,
		"note":           "Store these now — each works once in place of your MFA code. This is the only time they are shown.",
	})
}

// --- users (RBAC administration) ---
