package api

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"sync"
	"time"

	"github.com/morandeirachema/pamv1/internal/alert"
	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/shamir"
)

const unsealTTL = 10 * time.Minute

// unsealState collects break-glass shares until the quorum is met. It is reset
// on success, on a bad combination, or when the collection goes stale.
type unsealState struct {
	mu      sync.Mutex
	shares  [][]byte
	expires time.Time
}

// newUnsealState returns an empty break-glass share collector.
func newUnsealState() *unsealState { return &unsealState{} }

// add records a distinct share and returns the current collected set (a copy),
// resetting first if the collection has expired.
func (u *unsealState) add(share []byte, now time.Time) [][]byte {
	u.mu.Lock()
	defer u.mu.Unlock()
	if now.After(u.expires) {
		u.shares = nil
	}
	for _, s := range u.shares {
		if bytes.Equal(s, share) {
			return copyShares(u.shares) // already submitted
		}
	}
	u.shares = append(u.shares, append([]byte{}, share...))
	u.expires = now.Add(unsealTTL)
	return copyShares(u.shares)
}

// reset discards any collected shares.
func (u *unsealState) reset() {
	u.mu.Lock()
	u.shares = nil
	u.mu.Unlock()
}

// copyShares returns a new slice header over the same share byte slices.
func copyShares(s [][]byte) [][]byte {
	out := make([][]byte, len(s))
	copy(out, s)
	return out
}

type unsealIn struct {
	Share string `json:"share"`
}

// breakGlassUnseal collects M-of-N Shamir shares of the break-glass key; once
// enough are submitted it reconstructs the key, verifies it against the
// configured hash, and issues a short-lived break-glass session. Public (it is
// itself an emergency authentication path) but rate-limited and loudly alerted.
func (s *Server) breakGlassUnseal(w http.ResponseWriter, r *http.Request) {
	if len(s.breakGlassHash) == 0 || s.bgThreshold < 2 {
		writeError(w, http.StatusNotFound, "break-glass quorum is not configured")
		return
	}
	var in unsealIn
	if !readJSON(w, r, &in) {
		return
	}
	share, err := hex.DecodeString(in.Share)
	if err != nil || len(share) < 2 {
		writeError(w, http.StatusUnprocessableEntity, "share must be hex")
		return
	}

	collected := s.unseal.add(share, time.Now())
	if len(collected) < s.bgThreshold {
		writeJSON(w, http.StatusOK, map[string]any{
			"collected": len(collected), "needed": s.bgThreshold,
		})
		return
	}

	key, err := shamir.Combine(collected)
	if err == nil {
		sum := sha256.Sum256(key)
		if subtle.ConstantTimeCompare(sum[:], s.breakGlassHash) == 1 {
			s.unseal.reset()
			principal := &auth.Principal{Name: "break-glass", Role: auth.RoleAdmin, BreakGlass: true}
			token, sess, ierr := s.issueSessionTTL(r.Context(), principal, auth.SessionScopeBreakGlass, s.bgTTL)
			if ierr != nil {
				storeError(w, ierr)
				return
			}
			s.log.Warn("BREAK-GLASS quorum unsealed", "remote", r.RemoteAddr, "expires", sess.ExpiresAt)
			setActor(r.Context(), "break-glass")
			s.audit(withPrincipal(r.Context(), principal), "breakglass.unseal", "quorum met; session issued")
			s.alerter.Notify(r.Context(), alert.Event{
				Type: "breakglass.unseal", Actor: "break-glass",
				Detail: "quorum met; session issued", Remote: r.RemoteAddr, Time: time.Now(),
			})
			writeJSON(w, http.StatusCreated, map[string]any{
				"token": token, "role": "admin", "expires_at": sess.ExpiresAt,
			})
			return
		}
	}
	// Wrong / insufficient shares combined — make the operators start over.
	s.unseal.reset()
	s.log.Warn("break-glass unseal failed", "remote", r.RemoteAddr)
	writeError(w, http.StatusUnauthorized, "shares did not reconstruct the key; start over")
}
