package api

import (
	"context"
	"fmt"
	"net/http"
)

// identityResult is one user's directory reconciliation outcome.
type identityResult struct {
	Username string `json:"username"`
	Status   string `json:"status"` // active | disabled | not_in_directory | error
	Revoked  bool   `json:"revoked,omitempty"`
}

// reconcileIdentities checks every local pamv1 user against the directory and
// **revokes (deletes) users the directory reports as disabled** — leaving absent
// (local-only) accounts in place but surfacing them as not_in_directory. With
// ?dry_run=true it reports what it would do without changing anything. Requires a
// configured directory (PAM_LDAP_URL) and CapManageUsers.
func (s *Server) reconcileIdentities(w http.ResponseWriter, r *http.Request) {
	if s.rt().directory == nil {
		writeError(w, http.StatusServiceUnavailable, "identity reconciliation requires a directory (set PAM_LDAP_URL)")
		return
	}
	dryRun := r.URL.Query().Get("dry_run") == "true"
	users, err := s.store.ListUsers(r.Context())
	if err != nil {
		storeError(w, err)
		return
	}

	results := make([]identityResult, 0, len(users))
	var revoked int
	for _, u := range users {
		exists, enabled, derr := s.rt().directory.UserStatus(r.Context(), u.Username)
		switch {
		case derr != nil:
			// Never revoke on uncertainty (a transient directory error).
			results = append(results, identityResult{Username: u.Username, Status: "error"})
		case !exists:
			results = append(results, identityResult{Username: u.Username, Status: "not_in_directory"})
		case enabled:
			results = append(results, identityResult{Username: u.Username, Status: "active"})
		default: // exists but disabled → revoke
			res := identityResult{Username: u.Username, Status: "disabled"}
			revoked++
			if !dryRun {
				if err := s.store.DeleteUser(r.Context(), u.ID); err == nil {
					res.Revoked = true
					s.audit(r.Context(), "user.revoked", "user:"+u.Username+" reason:directory-disabled")
				}
			}
			results = append(results, res)
		}
	}
	// Directory (AD/SSO) logins create login-session rows, not user rows, so the
	// loop above never revokes them — a disabled directory user would otherwise
	// keep a valid session until it expires. Walk the active login sessions, and
	// for each distinct subject the directory reports disabled/absent, revoke it.
	sessRevoked, sessChecked := s.reconcileSessions(r.Context(), dryRun)

	s.audit(r.Context(), "identity.reconcile", fmt.Sprintf("checked:%d disabled:%d sessions_checked:%d sessions_revoked:%d dry_run:%t", len(users), revoked, sessChecked, sessRevoked, dryRun))
	writeJSON(w, http.StatusOK, map[string]any{
		"checked": len(users), "disabled": revoked, "dry_run": dryRun, "results": results,
		"sessions_checked": sessChecked, "sessions_revoked": sessRevoked,
	})
}

// reconcileSessions revokes active login sessions whose subject the directory
// reports disabled or absent, so a centrally-deprovisioned directory user loses
// their pamv1 session promptly instead of at TTL expiry. Returns (revoked,
// distinctSubjectsChecked). Never revokes on a transient directory error.
func (s *Server) reconcileSessions(ctx context.Context, dryRun bool) (revoked, checked int) {
	sessions, err := s.store.ListSessions(ctx)
	if err != nil {
		return 0, 0
	}
	seen := make(map[string]bool)
	for _, sess := range sessions {
		if seen[sess.Username] {
			continue
		}
		seen[sess.Username] = true
		checked++
		exists, enabled, derr := s.rt().directory.UserStatus(ctx, sess.Username)
		if derr != nil || (exists && enabled) {
			continue // uncertain or still-valid: never revoke
		}
		if dryRun {
			revoked++
			continue
		}
		if n, err := s.store.DeleteSessionsByUsername(ctx, sess.Username); err == nil && n > 0 {
			revoked += n
			s.audit(ctx, "session.revoked", "user:"+sess.Username+" reason:directory-disabled")
		}
	}
	return revoked, checked
}
