package api

import (
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/oidc"
)

const oidcStateTTL = 10 * time.Minute

// pendingAuth holds the PKCE verifier and nonce for an in-flight OIDC login,
// keyed by the opaque state parameter.
type pendingAuth struct {
	verifier string
	nonce    string
	expires  time.Time
}

// oidcPending is an in-memory store of in-flight OIDC logins. It is per-process;
// a multi-replica deployment needs shared storage (roadmap).
type oidcPending struct {
	mu sync.Mutex
	m  map[string]pendingAuth
}

func newOIDCPending() *oidcPending { return &oidcPending{m: make(map[string]pendingAuth)} }

func (p *oidcPending) put(state string, a pendingAuth) {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	for k, v := range p.m { // opportunistic expiry sweep
		if now.After(v.expires) {
			delete(p.m, k)
		}
	}
	p.m[state] = a
}

func (p *oidcPending) take(state string) (pendingAuth, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	a, ok := p.m[state]
	if ok {
		delete(p.m, state)
	}
	if !ok || time.Now().After(a.expires) {
		return pendingAuth{}, false
	}
	return a, true
}

// oidcStart begins the Authorization Code + PKCE flow and redirects to the IdP.
func (s *Server) oidcStart(w http.ResponseWriter, r *http.Request) {
	if s.oidc == nil {
		writeError(w, http.StatusNotFound, "OIDC login is not configured")
		return
	}
	state, err1 := oidc.RandomString()
	nonce, err2 := oidc.RandomString()
	verifier, challenge, err3 := oidc.GeneratePKCE()
	if err1 != nil || err2 != nil || err3 != nil {
		writeError(w, http.StatusInternalServerError, "oidc init failed")
		return
	}
	s.oidcPending.put(state, pendingAuth{verifier: verifier, nonce: nonce, expires: time.Now().Add(oidcStateTTL)})
	http.Redirect(w, r, s.oidc.AuthCodeURL(state, nonce, challenge), http.StatusFound)
}

// oidcCallback completes the flow: validate the code+state, exchange for a
// signature-verified ID token, map the role and issue a session, then redirect
// back to the portal with the token in the URL fragment.
func (s *Server) oidcCallback(w http.ResponseWriter, r *http.Request) {
	if s.oidc == nil {
		writeError(w, http.StatusNotFound, "OIDC login is not configured")
		return
	}
	q := r.URL.Query()
	if e := q.Get("error"); e != "" {
		s.redirectPortal(w, r, "pam_error="+url.QueryEscape(e))
		return
	}
	code, state := q.Get("code"), q.Get("state")
	pending, ok := s.oidcPending.take(state)
	if code == "" || !ok {
		s.log.Warn("oidc callback: invalid state", "remote", r.RemoteAddr)
		s.redirectPortal(w, r, "pam_error=invalid_state")
		return
	}
	claims, err := s.oidc.Exchange(r.Context(), code, pending.verifier, pending.nonce)
	if err != nil {
		s.log.Warn("oidc exchange failed", "err", err, "remote", r.RemoteAddr)
		s.redirectPortal(w, r, "pam_error=login_failed")
		return
	}
	role, ok := auth.HighestRole(append(append([]string{}, claims.Roles...), claims.Groups...), s.oidcRoleMap)
	if !ok {
		s.log.Warn("oidc login: no mapped role", "user", claims.PreferredUsername)
		s.redirectPortal(w, r, "pam_error=no_role")
		return
	}
	name := claims.PreferredUsername
	if name == "" {
		name = claims.Subject
	}
	principal := &auth.Principal{Name: name, Role: role}
	token, _, err := s.issueSession(r.Context(), principal, "")
	if err != nil {
		s.redirectPortal(w, r, "pam_error=session_failed")
		return
	}
	setActor(r.Context(), principal.Name)
	s.audit(withPrincipal(r.Context(), principal), "login", "user:"+principal.Name+" via:oidc role:"+string(role))
	s.redirectPortal(w, r, "pam_token="+url.QueryEscape(token))
}

func (s *Server) redirectPortal(w http.ResponseWriter, r *http.Request, fragment string) {
	http.Redirect(w, r, s.portalURL+"#"+fragment, http.StatusFound)
}
