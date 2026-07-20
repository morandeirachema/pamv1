package api

import (
	"crypto/subtle"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/oidc"
)

// requestIsHTTPS reports whether the browser reached the edge over TLS, honoring
// a TLS-terminating proxy's X-Forwarded-Proto so the login-CSRF state cookie
// still gets the Secure attribute in the common reverse-proxy deployment. Only
// used to set Secure (over-setting merely drops the cookie on plain HTTP), never
// to make a trust decision, so a spoofed header cannot weaken anything.
func requestIsHTTPS(r *http.Request) bool {
	return r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

// oidcStateTTL bounds an in-flight OIDC login. The PKCE verifier + nonce are
// persisted in the store (keyed by the opaque state) so the callback can land on
// any replica (HA).
const oidcStateTTL = 10 * time.Minute

// oidcStateCookie binds an in-flight login to the browser that started it: the
// callback's state must match this cookie, so an attacker cannot complete their
// own flow in a victim's browser (login CSRF / session fixation).
const oidcStateCookie = "pam_oidc_state"

// oidcStart begins the Authorization Code + PKCE flow and redirects to the IdP.
func (s *Server) oidcStart(w http.ResponseWriter, r *http.Request) {
	oidcp := s.rt().oidc // snapshot once (a concurrent hot-swap could null it)
	if oidcp == nil {
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
	if err := s.store.PutOIDCState(r.Context(), state, verifier, nonce, time.Now().Add(oidcStateTTL)); err != nil {
		writeError(w, http.StatusInternalServerError, "oidc init failed")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: oidcStateCookie, Value: state, Path: "/api/auth/oidc/",
		MaxAge: int(oidcStateTTL.Seconds()), HttpOnly: true,
		Secure: requestIsHTTPS(r), SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, oidcp.AuthCodeURL(state, nonce, challenge), http.StatusFound)
}

// oidcCallback completes the flow: validate the code+state, exchange for a
// signature-verified ID token, map the role and issue a session, then redirect
// back to the portal with the token in the URL fragment.
func (s *Server) oidcCallback(w http.ResponseWriter, r *http.Request) {
	rt := s.rt() // snapshot once (a concurrent hot-swap could null oidc)
	if rt.oidc == nil {
		writeError(w, http.StatusNotFound, "OIDC login is not configured")
		return
	}
	q := r.URL.Query()
	if e := q.Get("error"); e != "" {
		s.redirectPortal(w, r, "pam_error="+url.QueryEscape(e))
		return
	}
	code, state := q.Get("code"), q.Get("state")
	// Bind to the initiating browser: the state cookie set at /start must match
	// the state the IdP echoed back. Checked before consuming the single-use
	// server state so a foreign request can't burn a legitimate one.
	sc, cerr := r.Cookie(oidcStateCookie)
	http.SetCookie(w, &http.Cookie{Name: oidcStateCookie, Value: "", Path: "/api/auth/oidc/", MaxAge: -1, HttpOnly: true, Secure: requestIsHTTPS(r), SameSite: http.SameSiteLaxMode})
	if state == "" || cerr != nil || subtle.ConstantTimeCompare([]byte(sc.Value), []byte(state)) != 1 {
		s.log.Warn("oidc callback: state cookie mismatch", "remote", r.RemoteAddr)
		s.redirectPortal(w, r, "pam_error=invalid_state")
		return
	}
	verifier, nonce, ok, err := s.store.TakeOIDCState(r.Context(), state, time.Now())
	if err != nil {
		s.log.Error("oidc state lookup failed", "err", err)
		s.redirectPortal(w, r, "pam_error=login_failed")
		return
	}
	if code == "" || !ok {
		s.log.Warn("oidc callback: invalid state", "remote", r.RemoteAddr)
		s.redirectPortal(w, r, "pam_error=invalid_state")
		return
	}
	claims, err := rt.oidc.Exchange(r.Context(), code, verifier, nonce)
	if err != nil {
		s.log.Warn("oidc exchange failed", "err", err, "remote", r.RemoteAddr)
		s.redirectPortal(w, r, "pam_error=login_failed")
		return
	}
	role, ok := auth.HighestRole(append(append([]string{}, claims.Roles...), claims.Groups...), rt.oidcRoleMap)
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

// redirectPortal 302-redirects to the portal URL with the given URL fragment,
// which carries either a session token or an error code.
func (s *Server) redirectPortal(w http.ResponseWriter, r *http.Request, fragment string) {
	http.Redirect(w, r, s.portalURL+"#"+fragment, http.StatusFound)
}
