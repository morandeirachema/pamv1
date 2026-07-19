package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/mfa"
	"github.com/morandeirachema/pamv1/internal/store"
	"github.com/morandeirachema/pamv1/internal/winrm"
)

var (
	validOS       = map[string]bool{"linux": true, "windows": true}
	validProtocol = map[string]bool{"ssh": true, "winrm": true, "rdp": true}
	validSecret   = map[string]bool{"password": true, "ssh_key": true}
)

// --- targets ---

type targetIn struct {
	Name            string `json:"name"`
	Host            string `json:"host"`
	Port            int    `json:"port"`
	OSType          string `json:"os_type"`
	Protocol        string `json:"protocol"`
	RequireApproval bool   `json:"require_approval"`
}

// createTarget validates and persists a new target (defaulting the port to 22),
// then audits the creation.
func (s *Server) createTarget(w http.ResponseWriter, r *http.Request) {
	var in targetIn
	if !readJSON(w, r, &in) {
		return
	}
	if in.Port == 0 {
		in.Port = 22
	}
	switch {
	case in.Name == "" || in.Host == "":
		writeError(w, http.StatusUnprocessableEntity, "name and host are required")
		return
	case in.Port < 1 || in.Port > 65535:
		writeError(w, http.StatusUnprocessableEntity, "port must be 1-65535")
		return
	case !validOS[in.OSType]:
		writeError(w, http.StatusUnprocessableEntity, `os_type must be "linux" or "windows"`)
		return
	case !validProtocol[in.Protocol]:
		writeError(w, http.StatusUnprocessableEntity, `protocol must be "ssh", "winrm" or "rdp"`)
		return
	}
	t := store.Target{Name: in.Name, Host: in.Host, Port: in.Port, OSType: in.OSType, Protocol: in.Protocol, RequireApproval: in.RequireApproval}
	if err := s.store.CreateTarget(r.Context(), &t); err != nil {
		storeError(w, err)
		return
	}
	s.audit(r.Context(), "target.create", t.Name)
	writeJSON(w, http.StatusCreated, t)
}

// listTargets returns all targets in the inventory.
func (s *Server) listTargets(w http.ResponseWriter, r *http.Request) {
	targets, err := s.store.ListTargets(r.Context())
	if err != nil {
		storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, targets)
}

// getTarget returns a single target by its {id} path value.
func (s *Server) getTarget(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	t, err := s.store.GetTarget(r.Context(), id)
	if err != nil {
		storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, t)
}

// deleteTarget removes a target by id (its credentials cascade in the store) and
// audits the deletion.
func (s *Server) deleteTarget(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	if err := s.store.DeleteTarget(r.Context(), id); err != nil {
		storeError(w, err)
		return
	}
	s.audit(r.Context(), "target.delete", strconv.FormatInt(id, 10))
	w.WriteHeader(http.StatusNoContent)
}

// --- target access grants (per-target authorization) ---

type grantIn struct {
	SubjectType string `json:"subject_type"`
	Subject     string `json:"subject"`
}

// createTargetGrant adds a per-target access grant for a user or role (validating
// the subject, and that a role subject is a known role) and audits it.
func (s *Server) createTargetGrant(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	var in grantIn
	if !readJSON(w, r, &in) {
		return
	}
	switch {
	case in.SubjectType != "user" && in.SubjectType != "role":
		writeError(w, http.StatusUnprocessableEntity, `subject_type must be "user" or "role"`)
		return
	case in.Subject == "":
		writeError(w, http.StatusUnprocessableEntity, "subject is required")
		return
	}
	if in.SubjectType == "role" {
		if _, err := auth.ParseRole(in.Subject); err != nil {
			writeError(w, http.StatusUnprocessableEntity, "subject must be a valid role")
			return
		}
	}
	g := store.TargetGrant{TargetID: id, SubjectType: in.SubjectType, Subject: in.Subject}
	if err := s.store.CreateTargetGrant(r.Context(), &g); err != nil {
		storeError(w, err)
		return
	}
	s.audit(r.Context(), "grant.create", fmt.Sprintf("target:%d %s:%s", id, in.SubjectType, in.Subject))
	writeJSON(w, http.StatusCreated, g)
}

// listTargetGrants returns the access grants for a target.
func (s *Server) listTargetGrants(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	grants, err := s.store.ListTargetGrants(r.Context(), id)
	if err != nil {
		storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, grants)
}

// deleteTargetGrant removes a target access grant by its {gid} path value and
// audits it.
func (s *Server) deleteTargetGrant(w http.ResponseWriter, r *http.Request) {
	gid, err := strconv.ParseInt(r.PathValue("gid"), 10, 64)
	if err != nil || gid < 1 {
		writeError(w, http.StatusUnprocessableEntity, "invalid grant id")
		return
	}
	if err := s.store.DeleteTargetGrant(r.Context(), gid); err != nil {
		storeError(w, err)
		return
	}
	s.audit(r.Context(), "grant.delete", strconv.FormatInt(gid, 10))
	w.WriteHeader(http.StatusNoContent)
}

// authorizedForTarget reports whether the caller may connect to a target under
// its access grants.
func (s *Server) authorizedForTarget(ctx context.Context, targetID int64) (bool, error) {
	grants, err := s.store.ListTargetGrants(ctx, targetID)
	if err != nil {
		return false, err
	}
	return auth.CanConnectTarget(principalFrom(ctx), grants), nil
}

// --- credentials ---

type credentialIn struct {
	TargetID   int64  `json:"target_id"`
	Username   string `json:"username"`
	Secret     string `json:"secret"`
	SecretType string `json:"secret_type"`
}

// createCredential vaults a secret for a target, encrypting it under the target's
// AAD (defaulting the type to password), and audits it. The stored ciphertext is
// never returned to the client.
func (s *Server) createCredential(w http.ResponseWriter, r *http.Request) {
	var in credentialIn
	if !readJSON(w, r, &in) {
		return
	}
	if in.SecretType == "" {
		in.SecretType = "password"
	}
	switch {
	case in.Username == "" || in.Secret == "":
		writeError(w, http.StatusUnprocessableEntity, "username and secret are required")
		return
	case !validSecret[in.SecretType]:
		writeError(w, http.StatusUnprocessableEntity, `secret_type must be "password" or "ssh_key"`)
		return
	}
	target, err := s.store.GetTarget(r.Context(), in.TargetID)
	if err != nil {
		storeError(w, err)
		return
	}
	enc, err := s.vault.Encrypt(r.Context(), in.Secret, store.CredentialAAD(target.ID))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "encryption failed")
		return
	}
	c := store.Credential{TargetID: target.ID, Username: in.Username, SecretType: in.SecretType, SecretEnc: enc}
	if err := s.store.CreateCredential(r.Context(), &c); err != nil {
		storeError(w, err)
		return
	}
	s.audit(r.Context(), "credential.create", fmt.Sprintf("%s/%s", target.Name, c.Username))
	writeJSON(w, http.StatusCreated, c)
}

// listCredentials returns credentials, optionally scoped to ?target_id=. Secret
// material is never included in the response.
func (s *Server) listCredentials(w http.ResponseWriter, r *http.Request) {
	var targetID int64
	if q := r.URL.Query().Get("target_id"); q != "" {
		id, err := strconv.ParseInt(q, 10, 64)
		if err != nil {
			writeError(w, http.StatusUnprocessableEntity, "target_id must be an integer")
			return
		}
		targetID = id
	}
	creds, err := s.store.ListCredentials(r.Context(), targetID)
	if err != nil {
		storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, creds)
}

// revealCredential decrypts a secret on demand and audits who asked for it.
// Once the JIT-injection proxy lands, reveal becomes the exception (recorded
// proxy sessions inject the secret without ever showing it).
func (s *Server) revealCredential(w http.ResponseWriter, r *http.Request) {
	// When reveal is disabled by policy, only break-glass may still reveal —
	// everyone else must go through the recorded, JIT-injecting proxy.
	if s.revealDisabled && !principalFrom(r.Context()).BreakGlass {
		s.audit(r.Context(), "credential.reveal_denied", "reason:reveal-disabled-by-policy")
		writeError(w, http.StatusForbidden, "credential reveal is disabled by policy; connect through the proxy")
		return
	}
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	c, err := s.store.GetCredential(r.Context(), id)
	if err != nil {
		storeError(w, err)
		return
	}
	secret, err := s.vault.Decrypt(r.Context(), c.SecretEnc, store.CredentialAAD(c.TargetID))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "decryption failed")
		return
	}
	s.audit(r.Context(), "credential.reveal", fmt.Sprintf("credential:%d target:%d user:%s", c.ID, c.TargetID, c.Username))
	writeJSON(w, http.StatusOK, map[string]any{
		"id":          c.ID,
		"target_id":   c.TargetID,
		"username":    c.Username,
		"secret_type": c.SecretType,
		"secret":      secret,
	})
}

// deleteCredential removes a credential by id and audits it.
func (s *Server) deleteCredential(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	if err := s.store.DeleteCredential(r.Context(), id); err != nil {
		storeError(w, err)
		return
	}
	s.audit(r.Context(), "credential.delete", strconv.FormatInt(id, 10))
	w.WriteHeader(http.StatusNoContent)
}

// --- Windows targets (WinRM command execution) ---

type winrmRunIn struct {
	Command string `json:"command"`
}

// runWinRM executes a command on a Windows target over WinRM, injecting the
// target's vaulted credential just-in-time (the caller never sees it). The
// command + output are recorded and the run is audited.
func (s *Server) runWinRM(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	var in winrmRunIn
	if !readJSON(w, r, &in) {
		return
	}
	if in.Command == "" {
		writeError(w, http.StatusUnprocessableEntity, "command is required")
		return
	}
	target, err := s.store.GetTarget(r.Context(), id)
	if err != nil {
		storeError(w, err)
		return
	}
	if target.Protocol != "winrm" {
		writeError(w, http.StatusUnprocessableEntity, "target protocol is not winrm")
		return
	}
	if ok, err := s.authorizedForTarget(r.Context(), target.ID); err != nil {
		storeError(w, err)
		return
	} else if !ok {
		s.audit(r.Context(), "winrm.denied", "target:"+target.Name+" reason:target-policy")
		writeError(w, http.StatusForbidden, "not authorized for this target")
		return
	}
	if ok, err := s.enforceApproval(r.Context(), target); err != nil {
		storeError(w, err)
		return
	} else if !ok {
		s.audit(r.Context(), "access.denied", "target:"+target.Name+" reason:approval-required")
		writeError(w, http.StatusForbidden, "connection requires an approved access request")
		return
	}
	creds, err := s.store.ListCredentials(r.Context(), target.ID)
	if err != nil {
		storeError(w, err)
		return
	}
	if len(creds) == 0 {
		writeError(w, http.StatusUnprocessableEntity, "target has no credential")
		return
	}
	cred := creds[0]

	// Just-in-time: the secret exists only for this call.
	secret, err := s.vault.Decrypt(r.Context(), cred.SecretEnc, store.CredentialAAD(target.ID))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "decryption failed")
		return
	}
	res, err := s.winrm.Run(r.Context(), target.Host, target.Port, cred.Username, secret, in.Command)
	if err != nil {
		s.log.Error("winrm run failed", "target", target.Name, "err", err)
		s.audit(r.Context(), "winrm.error", fmt.Sprintf("target:%s cred_user:%s error:%v", target.Name, cred.Username, err))
		writeError(w, http.StatusBadGateway, "winrm execution failed")
		return
	}

	file, sum := s.recordWinRM(target, cred.Username, actorFrom(r.Context()), in.Command, res)
	s.audit(r.Context(), "winrm.run",
		fmt.Sprintf("target:%s cred_user:%s exit:%d file:%s sha256:%s", target.Name, cred.Username, res.ExitCode, file, sum))
	writeJSON(w, http.StatusOK, map[string]any{
		"target":    target.Name,
		"exit_code": res.ExitCode,
		"stdout":    res.Stdout,
		"stderr":    res.Stderr,
	})
}

// recordWinRM writes a transcript of the command and its output, returning the
// file path and its SHA-256 (tamper evidence in the audit trail). Best-effort:
// a recording failure is logged but does not fail the request.
func (s *Server) recordWinRM(target *store.Target, credUser, actor, command string, res winrm.Result) (string, string) {
	if s.recordingDir == "" {
		return "", ""
	}
	if err := os.MkdirAll(s.recordingDir, 0o700); err != nil {
		s.log.Error("winrm recording dir", "err", err)
		return "", ""
	}
	ts := time.Now()
	name := fmt.Sprintf("%d_%s_%s.winrm.log", ts.UnixNano(), sanitizeName(target.Name), sanitizeName(actor))
	path := filepath.Join(s.recordingDir, name)
	transcript := fmt.Sprintf(
		"# pamv1 WinRM session\n# target: %s (%s:%d)\n# user: %s\n# actor: %s\n# time: %s\n\n$ %s\n\n--- stdout ---\n%s\n--- stderr ---\n%s\n--- exit: %d ---\n",
		target.Name, target.Host, target.Port, credUser, actor, ts.Format(time.RFC3339),
		command, res.Stdout, res.Stderr, res.ExitCode)
	data := []byte(transcript)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		s.log.Error("winrm recording write", "err", err)
		return "", ""
	}
	return path, hashHex(transcript)
}

// sanitizeName reduces a string to filename-safe characters (alphanumerics and
// -_.@), replacing anything else with a dash.
func sanitizeName(s string) string {
	var b strings.Builder
	for _, c := range s {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_', c == '.', c == '@':
			b.WriteRune(c)
		default:
			b.WriteByte('-')
		}
	}
	return b.String()
}

// --- login sessions (Active Directory / password identities) ---

// sessionTTL is how long a login session token is valid.
const sessionTTL = 12 * time.Hour

type loginIn struct {
	Username string `json:"username"`
	Password string `json:"password"`
	OTP      string `json:"otp"`
}

// login verifies a username + password against the configured identity source
// (e.g. Active Directory) and issues a short-lived session token. The token is
// used as X-API-Key (portal) or the SSH proxy password, exactly like a per-user
// token — its role comes from the user's directory groups.
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if s.authn == nil {
		writeError(w, http.StatusServiceUnavailable, "password login is not configured")
		return
	}
	var in loginIn
	if !readJSON(w, r, &in) {
		return
	}
	principal, err := s.authn.Authenticate(r.Context(), in.Username, in.Password)
	if err != nil {
		s.log.Warn("login failed", "user", in.Username, "remote", r.RemoteAddr)
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	enr, mfaErr := s.store.GetMFAEnrollment(r.Context(), principal.Name)
	switch {
	case mfaErr == nil && enr.Confirmed:
		// User has MFA — require a valid code (or a single-use recovery code).
		if in.OTP == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]any{
				"error": "multi-factor code required", "mfa_required": true,
			})
			return
		}
		if !s.checkSecondFactor(r.Context(), principal.Name, enr, in.OTP) {
			s.log.Warn("mfa failed", "user", principal.Name, "remote", r.RemoteAddr)
			writeError(w, http.StatusUnauthorized, "invalid multi-factor code")
			return
		}
	case s.mfaRequired:
		// Policy requires MFA but the user has none yet: issue an
		// enrollment-only session so they can set it up, nothing else.
		token, _, err := s.issueSession(r.Context(), principal, auth.SessionScopeEnroll)
		if err != nil {
			storeError(w, err)
			return
		}
		setActor(r.Context(), principal.Name)
		s.audit(withPrincipal(r.Context(), principal), "login", "user:"+principal.Name+" scope:enroll")
		writeJSON(w, http.StatusOK, map[string]any{
			"mfa_enrollment_required": true,
			"token":                   token,
			"username":                principal.Name,
			"role":                    principal.Role,
		})
		return
	}

	token, sess, err := s.issueSession(r.Context(), principal, "")
	if err != nil {
		storeError(w, err)
		return
	}
	setActor(r.Context(), principal.Name)
	s.audit(withPrincipal(r.Context(), principal), "login",
		fmt.Sprintf("user:%s role:%s", principal.Name, principal.Role))
	writeJSON(w, http.StatusCreated, map[string]any{
		"token":      token,
		"username":   principal.Name,
		"role":       principal.Role,
		"expires_at": sess.ExpiresAt,
	})
}

// issueSession mints a session token (scope "" = full, "enroll" = MFA setup only).
func (s *Server) issueSession(ctx context.Context, p *auth.Principal, scope string) (string, store.Session, error) {
	return s.issueSessionTTL(ctx, p, scope, sessionTTL)
}

// issueSessionTTL mints a session token with an explicit lifetime (break-glass
// sessions use a short TTL).
func (s *Server) issueSessionTTL(ctx context.Context, p *auth.Principal, scope string, ttl time.Duration) (string, store.Session, error) {
	token, err := generateToken()
	if err != nil {
		return "", store.Session{}, err
	}
	sess := store.Session{
		Username:  p.Name,
		Role:      string(p.Role),
		Scope:     scope,
		TokenHash: hashHex(token),
		ExpiresAt: time.Now().Add(ttl).UTC(),
	}
	if err := s.store.CreateSession(ctx, &sess); err != nil {
		return "", store.Session{}, err
	}
	return token, sess, nil
}

// checkSecondFactor accepts a valid TOTP code or a single-use recovery code.
func (s *Server) checkSecondFactor(ctx context.Context, username string, enr *store.MFAEnrollment, otp string) bool {
	if secret, err := s.vault.Decrypt(ctx, enr.SecretEnc, store.MFAAAD(username)); err == nil {
		if mfa.Validate(secret, otp, time.Now()) {
			return true
		}
	}
	code := strings.ToLower(strings.TrimSpace(otp))
	if consumed, err := s.store.ConsumeMFARecoveryCode(ctx, username, hashHex(code)); err == nil && consumed {
		s.audit(ctx, "mfa.recovery_used", "user:"+username)
		return true
	}
	return false
}

// hashHex returns the hex-encoded SHA-256 of s. Used to derive the lookup hashes
// stored for session/user tokens and recovery codes (plaintext is never stored).
func hashHex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// logout revokes the caller's own session token.
func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	// Best-effort: only session tokens exist in the table; other identities
	// (bootstrap/token) simply have nothing to delete.
	_ = s.store.DeleteSession(r.Context(), hashHex(r.Header.Get("X-API-Key")))
	s.audit(r.Context(), "logout", actorFrom(r.Context()))
	w.WriteHeader(http.StatusNoContent)
}

// --- multi-factor authentication (TOTP) ---

// mfaEnroll generates a new TOTP secret for the caller and returns it once
// (plus an otpauth:// URI for the authenticator app). The enrollment is
// unconfirmed until the user proves a code via mfaVerify.
func (s *Server) mfaEnroll(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
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

// mfaDisable removes the caller's TOTP enrollment (and recovery codes).
func (s *Server) mfaDisable(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
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

type userIn struct {
	Username string `json:"username"`
	Role     string `json:"role"`
}

// createUser mints a new local identity and returns its access token exactly
// once. Only the token's SHA-256 is stored; the plaintext is never persisted.
func (s *Server) createUser(w http.ResponseWriter, r *http.Request) {
	var in userIn
	if !readJSON(w, r, &in) {
		return
	}
	role, err := auth.ParseRole(in.Role)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, `role must be "admin", "user", "auditor" or "approver"`)
		return
	}
	if in.Username == "" {
		writeError(w, http.StatusUnprocessableEntity, "username is required")
		return
	}
	token, err := generateToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "token generation failed")
		return
	}
	u := store.User{Username: in.Username, Role: string(role), TokenHash: hashHex(token)}
	if err := s.store.CreateUser(r.Context(), &u); err != nil {
		storeError(w, err)
		return
	}
	s.audit(r.Context(), "user.create", fmt.Sprintf("%s role:%s", u.Username, u.Role))
	writeJSON(w, http.StatusCreated, map[string]any{
		"id":       u.ID,
		"username": u.Username,
		"role":     u.Role,
		"token":    token, // shown once; store it now
	})
}

// listUsers returns all local users; token hashes are never serialized.
func (s *Server) listUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.store.ListUsers(r.Context())
	if err != nil {
		storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, users)
}

// deleteUser removes a user by id and audits it.
func (s *Server) deleteUser(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	if err := s.store.DeleteUser(r.Context(), id); err != nil {
		storeError(w, err)
		return
	}
	s.audit(r.Context(), "user.delete", strconv.FormatInt(id, 10))
	w.WriteHeader(http.StatusNoContent)
}

// generateToken returns a new random access token with the "pamt_" prefix.
func generateToken() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "pamt_" + hex.EncodeToString(b), nil
}

// --- live sessions (listing + kill-switch) ---

// listSessions returns the live proxy/RDP sessions, or an empty list when no
// session registry is wired.
func (s *Server) listSessions(w http.ResponseWriter, r *http.Request) {
	if s.sessions == nil {
		writeJSON(w, http.StatusOK, []any{})
		return
	}
	writeJSON(w, http.StatusOK, s.sessions.List())
}

// killSession terminates a live session by id via the registry and audits it; an
// unknown session id is a 404.
func (s *Server) killSession(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if s.sessions == nil || !s.sessions.Kill(id) {
		writeError(w, http.StatusNotFound, "session not found")
		return
	}
	s.audit(r.Context(), "session.kill", "session:"+id)
	w.WriteHeader(http.StatusNoContent)
}

// --- audit ---

// listAudit returns recent audit events, capped by ?limit= (default 100).
func (s *Server) listAudit(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if q := r.URL.Query().Get("limit"); q != "" {
		if n, err := strconv.Atoi(q); err == nil {
			limit = n
		}
	}
	events, err := s.store.ListAudit(r.Context(), limit)
	if err != nil {
		storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, events)
}

// --- helpers ---

// writeJSON writes v as a JSON response body with the given status code.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeError writes a JSON {"error": msg} body with the given status code.
func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// readJSON decodes the request body (capped at 1 MiB) into v, writing a 400 and
// returning false on a decode failure.
func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return false
	}
	return true
}

// idParam parses the {id} path value as a positive int64, writing a 422 and
// returning false when it is missing or invalid.
func idParam(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id < 1 {
		writeError(w, http.StatusUnprocessableEntity, "invalid id")
		return 0, false
	}
	return id, true
}

// storeError maps a store error to an HTTP response: ErrNotFound to 404,
// ErrConflict to 409, and anything else to 500 (logged).
func storeError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "not found")
	case errors.Is(err, store.ErrConflict):
		writeError(w, http.StatusConflict, "already exists")
	default:
		slog.Error("store error", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
	}
}
