package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/morandeirachema/pamv1/internal/store"
	"github.com/morandeirachema/pamv1/internal/winrm"
)

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
	zsp := in.SecretType == "ssh_ca"
	switch {
	case in.Username == "":
		writeError(w, http.StatusUnprocessableEntity, "username is required")
		return
	case !validSecret[in.SecretType]:
		writeError(w, http.StatusUnprocessableEntity, `secret_type must be "password", "ssh_key" or "ssh_ca"`)
		return
	case !zsp && in.Secret == "":
		writeError(w, http.StatusUnprocessableEntity, "secret is required")
		return
	case zsp && in.Secret != "":
		writeError(w, http.StatusUnprocessableEntity, "an ssh_ca (zero standing privilege) credential must not carry a secret")
		return
	}
	target, err := s.store.GetTarget(r.Context(), in.TargetID)
	if err != nil {
		storeError(w, err)
		return
	}
	// A Zero Standing Privilege credential is served by minting a certificate over
	// SSH — it only makes sense on an ssh target.
	if zsp && target.Protocol != "ssh" {
		writeError(w, http.StatusUnprocessableEntity, "ssh_ca credentials are only valid on ssh targets")
		return
	}
	// Insert first so the row has an ID, then bind the ciphertext to (target,
	// credential) via the AAD and store it. Roll the row back if either fails.
	c := store.Credential{TargetID: target.ID, Username: in.Username, SecretType: in.SecretType}
	if err := s.store.CreateCredential(r.Context(), &c); err != nil {
		storeError(w, err)
		return
	}
	// Zero Standing Privilege credentials store no secret (SecretEnc stays empty):
	// there is nothing to vault — the proxy mints a short-lived certificate JIT.
	if !zsp {
		// Roll the half-built row back on a cancel-detached context, so a client
		// disconnect between the insert and the ciphertext write cannot orphan a
		// permanent empty-SecretEnc credential (which would be undecryptable).
		rollback := func() { _ = s.store.DeleteCredential(context.WithoutCancel(r.Context()), c.ID) }
		enc, err := s.vault.Encrypt(r.Context(), in.Secret, store.CredentialAAD(c.TargetID, c.ID))
		if err != nil {
			rollback()
			writeError(w, http.StatusInternalServerError, "encryption failed")
			return
		}
		if err := s.store.UpdateCredentialSecretEnc(r.Context(), c.ID, enc); err != nil {
			rollback()
			storeError(w, err)
			return
		}
		c.SecretEnc = enc
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
	if s.rt().revealDisabled && !principalFrom(r.Context()).BreakGlass {
		s.audit(r.Context(), "credential.reveal_denied", "reason:reveal-disabled-by-policy")
		writeError(w, http.StatusForbidden, "credential reveal is disabled by policy; connect through the proxy")
		return
	}
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	c, target, ok := s.loadCredentialTarget(w, r, id)
	if !ok {
		return
	}
	// Reveal is a credential-access path: it obeys the same per-target grants and
	// four-eyes approval gate as connecting, so a reveal_secret holder can't read
	// a credential for a target it wasn't granted or bypass an approval window.
	if !s.gateCredentialAccess(w, r, target, "credential.reveal") {
		return
	}
	// A Zero Standing Privilege credential stores no secret — there is nothing to
	// reveal. Refuse cleanly rather than trying to decrypt an empty SecretEnc
	// (which would 500 and log a misleading credential.decrypt_failed).
	if c.SecretType == "ssh_ca" {
		writeError(w, http.StatusUnprocessableEntity, "this credential has no stored secret (zero standing privilege); connect through the proxy")
		return
	}
	secret, err := s.vault.Decrypt(r.Context(), c.SecretEnc, store.CredentialAAD(c.TargetID, c.ID))
	if err != nil {
		s.audit(r.Context(), "credential.decrypt_failed", fmt.Sprintf("credential:%d target:%d op:reveal", c.ID, c.TargetID))
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
	if !s.protocolAllowed("winrm") {
		writeError(w, http.StatusForbidden, "winrm is not allowed by policy")
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

	res, err := s.execWinRM(r.Context(), target, &cred, in.Command, actorFrom(r.Context()))
	if errors.Is(err, errDecryptFailed) {
		writeError(w, http.StatusInternalServerError, "decryption failed")
		return
	}
	if err != nil {
		writeError(w, http.StatusBadGateway, "winrm execution failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"target":    target.Name,
		"exit_code": res.ExitCode,
		"stdout":    res.Stdout,
		"stderr":    res.Stderr,
	})
}

// errDecryptFailed marks a just-in-time vault decrypt failure, so callers can map
// it to an internal-error status distinct from a target execution failure.
var errDecryptFailed = errors.New("decryption failed")

// execWinRM injects target's vaulted credential just-in-time, runs command over
// WinRM, records the transcript, and audits the run — returning only the result.
// The plaintext secret never leaves this function. Shared by the REST handler and
// the agent-broker winrm_exec tool.
func (s *Server) execWinRM(ctx context.Context, target *store.Target, cred *store.Credential, command, actor string) (winrm.Result, error) {
	secret, err := s.vault.Decrypt(ctx, cred.SecretEnc, store.CredentialAAD(target.ID, cred.ID))
	if err != nil {
		s.audit(ctx, "credential.decrypt_failed", fmt.Sprintf("credential:%d target:%s op:winrm", cred.ID, target.Name))
		return winrm.Result{}, errDecryptFailed
	}
	res, err := s.winrm.Run(ctx, target.Host, target.Port, cred.Username, secret, command)
	if err != nil {
		s.log.Error("winrm run failed", "target", target.Name, "err", err)
		s.audit(ctx, "winrm.error", fmt.Sprintf("target:%s cred_user:%s error:%v", target.Name, cred.Username, err))
		return winrm.Result{}, err
	}
	file, sum := s.recordWinRM(target, cred.Username, actor, command, res)
	s.audit(ctx, "winrm.run",
		fmt.Sprintf("target:%s cred_user:%s exit:%d file:%s sha256:%s", target.Name, cred.Username, res.ExitCode, file, sum))
	return res, nil
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
