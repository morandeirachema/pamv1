package api

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/store"
)

var (
	validOS       = map[string]bool{"linux": true, "windows": true}
	validProtocol = map[string]bool{"ssh": true, "winrm": true, "rdp": true}
	validSecret   = map[string]bool{"password": true, "ssh_key": true}
)

// --- targets ---

type targetIn struct {
	Name     string `json:"name"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	OSType   string `json:"os_type"`
	Protocol string `json:"protocol"`
}

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
	t := store.Target{Name: in.Name, Host: in.Host, Port: in.Port, OSType: in.OSType, Protocol: in.Protocol}
	if err := s.store.CreateTarget(r.Context(), &t); err != nil {
		storeError(w, err)
		return
	}
	s.audit(r.Context(), "target.create", t.Name)
	writeJSON(w, http.StatusCreated, t)
}

func (s *Server) listTargets(w http.ResponseWriter, r *http.Request) {
	targets, err := s.store.ListTargets(r.Context())
	if err != nil {
		storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, targets)
}

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

// --- credentials ---

type credentialIn struct {
	TargetID   int64  `json:"target_id"`
	Username   string `json:"username"`
	Secret     string `json:"secret"`
	SecretType string `json:"secret_type"`
}

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

// --- login sessions (Active Directory / password identities) ---

// sessionTTL is how long a login session token is valid.
const sessionTTL = 12 * time.Hour

type loginIn struct {
	Username string `json:"username"`
	Password string `json:"password"`
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
	token, err := generateToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "token generation failed")
		return
	}
	sum := sha256.Sum256([]byte(token))
	sess := store.Session{
		Username:  principal.Name,
		Role:      string(principal.Role),
		TokenHash: hex.EncodeToString(sum[:]),
		ExpiresAt: time.Now().Add(sessionTTL).UTC(),
	}
	if err := s.store.CreateSession(r.Context(), &sess); err != nil {
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

// logout revokes the caller's own session token.
func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	sum := sha256.Sum256([]byte(r.Header.Get("X-API-Key")))
	// Best-effort: only session tokens exist in the table; other identities
	// (bootstrap/token) simply have nothing to delete.
	_ = s.store.DeleteSession(r.Context(), hex.EncodeToString(sum[:]))
	s.audit(r.Context(), "logout", actorFrom(r.Context()))
	w.WriteHeader(http.StatusNoContent)
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
	sum := sha256.Sum256([]byte(token))
	u := store.User{Username: in.Username, Role: string(role), TokenHash: hex.EncodeToString(sum[:])}
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

func (s *Server) listUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.store.ListUsers(r.Context())
	if err != nil {
		storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, users)
}

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

func generateToken() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "pamt_" + hex.EncodeToString(b), nil
}

// --- audit ---

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

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return false
	}
	return true
}

func idParam(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id < 1 {
		writeError(w, http.StatusUnprocessableEntity, "invalid id")
		return 0, false
	}
	return id, true
}

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
