package api

import (
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
