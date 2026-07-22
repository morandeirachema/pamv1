package api

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/morandeirachema/pamv1/internal/store"
)

// appHandler is a handler that runs after appAuth has resolved the application.
type appHandler func(w http.ResponseWriter, r *http.Request, app *store.AppKey)

// appAuth authenticates an application bearer key (Phase 24) and invokes next
// with the resolved application, or returns 401. Only the SHA-256 hash of the
// token is stored, so the lookup is over the hash; a disabled app is treated as
// not found (fail-closed).
func (s *Server) appAuth(next appHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok := bearerToken(r)
		if tok == "" {
			writeError(w, http.StatusUnauthorized, "missing application credential")
			return
		}
		app, err := s.store.GetAppKeyByTokenHash(r.Context(), hashHex(tok))
		if err != nil {
			writeError(w, http.StatusUnauthorized, "invalid application credential")
			return
		}
		setActor(r.Context(), "app:"+app.Name)
		next(w, r, app)
	}
}

// fetchAppSecret returns the secret of the credential named by the {id} path
// value to an authenticated application, but only if the application has an
// explicit grant for it (default-deny). The secret is decrypted just-in-time and
// the retrieval is audited (never the secret itself). This is the deliberate,
// opt-in Conjur-style secret-delivery path for non-agent applications.
func (s *Server) fetchAppSecret(w http.ResponseWriter, r *http.Request, app *store.AppKey) {
	// Honor the global reveal-disabled kill switch: when an operator has turned off
	// plaintext secret delivery, the application-secrets path is disabled too (it
	// is a secret-delivery path like reveal/checkout/broker-reveal).
	if s.rt().revealDisabled {
		s.auditAs(r.Context(), "app:"+app.Name, "app.secret_denied", "reason:reveal-disabled-by-policy")
		writeError(w, http.StatusForbidden, "secret delivery is disabled by policy")
		return
	}
	credID, ok := idParam(w, r)
	if !ok {
		return
	}
	allowed, err := s.store.AppMayAccessCredential(r.Context(), app.ID, credID)
	if err != nil {
		storeError(w, err)
		return
	}
	if !allowed {
		s.auditAs(r.Context(), "app:"+app.Name, "app.secret_denied", fmt.Sprintf("credential:%d reason:not-granted", credID))
		writeError(w, http.StatusForbidden, "this application is not granted access to that credential")
		return
	}
	cred, err := s.store.GetCredential(r.Context(), credID)
	if err != nil {
		storeError(w, err)
		return
	}
	// A Zero Standing Privilege credential has no stored secret to deliver.
	if cred.SecretType == "ssh_ca" {
		writeError(w, http.StatusUnprocessableEntity, "this credential has no stored secret (zero standing privilege)")
		return
	}
	target, err := s.store.GetTarget(r.Context(), cred.TargetID)
	if err != nil {
		storeError(w, err)
		return
	}
	secret, err := s.vault.Decrypt(r.Context(), cred.SecretEnc, store.CredentialAAD(cred.TargetID, cred.ID))
	if err != nil {
		s.auditAs(r.Context(), "app:"+app.Name, "credential.decrypt_failed", fmt.Sprintf("credential:%d target:%s op:app-secret", cred.ID, target.Name))
		writeError(w, http.StatusInternalServerError, "decryption failed")
		return
	}
	// Fail closed: the retrieval must be durably audited before the secret leaves.
	if !s.mustAuditAs(w, r.Context(), "app:"+app.Name, "app.secret_retrieved",
		fmt.Sprintf("credential:%d target:%s user:%s", cred.ID, target.Name, cred.Username)) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"credential_id": cred.ID,
		"target":        target.Name,
		"username":      cred.Username,
		"secret_type":   cred.SecretType,
		"secret":        secret,
	})
}

type appKeyIn struct {
	Name  string `json:"name"`
	Owner string `json:"owner"`
}

// createAppKey mints a new application identity for an admin; the token is shown
// once and only its SHA-256 hash is stored.
func (s *Server) createAppKey(w http.ResponseWriter, r *http.Request) {
	var in appKeyIn
	if !readJSON(w, r, &in) {
		return
	}
	if in.Name == "" {
		writeError(w, http.StatusUnprocessableEntity, "name is required")
		return
	}
	token, err := generateToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "token generation failed")
		return
	}
	k := store.AppKey{Name: in.Name, Owner: in.Owner, TokenHash: hashHex(token)}
	if err := s.store.CreateAppKey(r.Context(), &k); err != nil {
		storeError(w, err)
		return
	}
	s.audit(r.Context(), "app.create", fmt.Sprintf("%s owner:%s", k.Name, k.Owner))
	writeJSON(w, http.StatusCreated, map[string]any{
		"id": k.ID, "name": k.Name, "owner": k.Owner, "token": token,
		"note": "Give this token to the application; only its hash is stored. Prefer HTTPS.",
	})
}

// listAppKeys returns the registered application identities (never a token hash).
func (s *Server) listAppKeys(w http.ResponseWriter, r *http.Request) {
	keys, err := s.store.ListAppKeys(r.Context())
	if err != nil {
		storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, keys)
}

// deleteAppKey revokes an application so its bearer token stops resolving (its
// secret grants cascade away).
func (s *Server) deleteAppKey(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	if err := s.store.DeleteAppKey(r.Context(), id); err != nil {
		storeError(w, err)
		return
	}
	s.audit(r.Context(), "app.revoke", fmt.Sprintf("app:%d", id))
	w.WriteHeader(http.StatusNoContent)
}

type appGrantIn struct {
	CredentialID int64 `json:"credential_id"`
}

// grantAppSecret authorizes an application to retrieve one credential's secret.
// It needs CapRevealSecret — granting an app a secret is delegating reveal
// access, so only a principal who could reveal the secret itself may hand it out.
func (s *Server) grantAppSecret(w http.ResponseWriter, r *http.Request) {
	appID, ok := idParam(w, r)
	if !ok {
		return
	}
	var in appGrantIn
	if !readJSON(w, r, &in) {
		return
	}
	if in.CredentialID <= 0 {
		writeError(w, http.StatusUnprocessableEntity, "credential_id is required")
		return
	}
	g := store.AppSecretGrant{AppID: appID, CredentialID: in.CredentialID}
	if err := s.store.GrantAppSecret(r.Context(), &g); err != nil {
		storeError(w, err)
		return
	}
	s.audit(r.Context(), "app.grant", fmt.Sprintf("app:%d credential:%d", appID, in.CredentialID))
	writeJSON(w, http.StatusCreated, g)
}

// listAppSecretGrants returns the credentials an application may retrieve.
func (s *Server) listAppSecretGrants(w http.ResponseWriter, r *http.Request) {
	appID, ok := idParam(w, r)
	if !ok {
		return
	}
	grants, err := s.store.ListAppSecretGrants(r.Context(), appID)
	if err != nil {
		storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, grants)
}

// deleteAppSecretGrant revokes one of an application's secret grants. The route
// is scoped to the app, so a grant belonging to a different app is not removed.
func (s *Server) deleteAppSecretGrant(w http.ResponseWriter, r *http.Request) {
	appID, ok := idParam(w, r)
	if !ok {
		return
	}
	gid, err := strconv.ParseInt(r.PathValue("gid"), 10, 64)
	if err != nil || gid < 1 {
		writeError(w, http.StatusUnprocessableEntity, "invalid grant id")
		return
	}
	grants, err := s.store.ListAppSecretGrants(r.Context(), appID)
	if err != nil {
		storeError(w, err)
		return
	}
	found := false
	for _, g := range grants {
		if g.ID == gid {
			found = true
			break
		}
	}
	if !found {
		writeError(w, http.StatusNotFound, "grant not found for this application")
		return
	}
	if err := s.store.DeleteAppSecretGrant(r.Context(), gid); err != nil {
		storeError(w, err)
		return
	}
	s.audit(r.Context(), "app.grant_revoked", fmt.Sprintf("app:%d grant:%d", appID, gid))
	w.WriteHeader(http.StatusNoContent)
}
