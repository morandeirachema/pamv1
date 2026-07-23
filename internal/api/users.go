package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"

	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/store"
)

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
	// The role is a built-in role or an existing custom profile (Phase 12).
	grantCaps, err := s.capsForGrant(r.Context(), in.Role)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, `role must be a built-in role (admin|user|auditor|approver) or an existing profile`)
		return
	}
	// You cannot mint a user more capable than yourself (privilege-escalation
	// guard for delegated user-admins). The bootstrap/break-glass admin holds
	// every capability and so is unconstrained.
	if !principalFrom(r.Context()).Covers(grantCaps) {
		writeError(w, http.StatusForbidden, "cannot assign a role or profile with capabilities you do not hold")
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
	u := store.User{Username: in.Username, Role: in.Role, TokenHash: hashHex(token)}
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

// listLoginSessions returns all active password/SSO login sessions (never their
// token hashes), so an admin can see who is logged in and revoke them. This is
// distinct from GET /api/sessions, which lists live proxied target sessions.
func (s *Server) listLoginSessions(w http.ResponseWriter, r *http.Request) {
	sessions, err := s.store.ListSessions(r.Context())
	if err != nil {
		storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, sessions)
}

// revokeLoginSessions force-invalidates every active login session for a username
// — the admin control missing for directory (AD/SSO) logins, which create session
// rows rather than user rows and so survive a directory disable until they expire.
func (s *Server) revokeLoginSessions(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Username string `json:"username"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	if in.Username == "" {
		writeError(w, http.StatusUnprocessableEntity, "username is required")
		return
	}
	n, err := s.store.DeleteSessionsByUsername(r.Context(), in.Username)
	if err != nil {
		storeError(w, err)
		return
	}
	// Revoking a login cuts the user off entirely — also terminate any in-flight
	// proxied target sessions they hold, not just their login tokens.
	killed := s.killUserSessions(r.Context(), in.Username, "login-revoked")
	s.audit(r.Context(), "session.revoked", fmt.Sprintf("user:%s sessions:%d killed:%d", in.Username, n, killed))
	writeJSON(w, http.StatusOK, map[string]any{"username": in.Username, "revoked": n, "killed": killed})
}

// killUserSessions terminates every live proxied session an actor holds (via the
// shared session registry) and audits it. Returns how many were killed; a no-op
// when no registry is wired. Note: the registry is per-replica, so in an HA
// deployment this cuts sessions on this replica only.
func (s *Server) killUserSessions(ctx context.Context, username, reason string) int {
	if s.sessions == nil {
		return 0
	}
	killed := s.sessions.KillByActor(username)
	if killed > 0 {
		s.audit(ctx, "session.killed", fmt.Sprintf("user:%s count:%d reason:%s", username, killed, reason))
	}
	return killed
}

// capsForGrant resolves a built-in role name or an existing custom profile name
// to the capability set it would confer on a user, or an error if the name is
// neither. Used to bound what a caller may grant.
func (s *Server) capsForGrant(ctx context.Context, name string) (auth.CapSet, error) {
	if role, err := auth.ParseRole(name); err == nil {
		return role.CapabilitySet(), nil
	}
	prof, err := s.store.GetProfile(ctx, name)
	if err != nil {
		return nil, err
	}
	return auth.ParseCapabilities(prof.Capabilities)
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
