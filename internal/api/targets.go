package api

import (
	"context"
	"fmt"
	"net/http"
	"strconv"

	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/store"
)

var (
	validOS       = map[string]bool{"linux": true, "windows": true}
	validProtocol = map[string]bool{"ssh": true, "winrm": true, "rdp": true, "postgres": true}
	// "ssh_ca" is a Zero Standing Privilege credential (Phase 22): it stores no
	// secret — the proxy mints a short-lived certificate just-in-time instead.
	validSecret = map[string]bool{"password": true, "ssh_key": true, "ssh_ca": true}
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
		writeError(w, http.StatusUnprocessableEntity, `protocol must be "ssh", "winrm", "rdp" or "postgres"`)
		return
	case !s.protocolAllowed(in.Protocol):
		writeError(w, http.StatusUnprocessableEntity, "protocol "+in.Protocol+" is not allowed by policy")
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
		if _, err := auth.ParseGrantRole(in.Subject); err != nil {
			writeError(w, http.StatusUnprocessableEntity, `subject must be a valid role (admin|user|auditor|approver|agent)`)
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
	tid, ok := idParam(w, r)
	if !ok {
		return
	}
	gid, err := strconv.ParseInt(r.PathValue("gid"), 10, 64)
	if err != nil || gid < 1 {
		writeError(w, http.StatusUnprocessableEntity, "invalid grant id")
		return
	}
	// The route is scoped to a target — only delete the grant if it belongs to
	// that target, so DELETE /targets/1/grants/5 cannot remove target 2's grant.
	grants, err := s.store.ListTargetGrants(r.Context(), tid)
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
		writeError(w, http.StatusNotFound, "grant not found for this target")
		return
	}
	if err := s.store.DeleteTargetGrant(r.Context(), gid); err != nil {
		storeError(w, err)
		return
	}
	s.audit(r.Context(), "grant.delete", fmt.Sprintf("target:%d grant:%d", tid, gid))
	w.WriteHeader(http.StatusNoContent)
}

// authorizedForTarget reports whether the caller may connect to a target under
// its access grants.
func (s *Server) authorizedForTarget(ctx context.Context, targetID int64) (bool, error) {
	grants, err := s.store.EffectiveTargetGrants(ctx, targetID)
	if err != nil {
		return false, err
	}
	return auth.CanConnectTarget(principalFrom(ctx), grants), nil
}

// gateCredentialAccess enforces the per-target grant and four-eyes approval gates
// that guard EVERY credential-access path — the SSH/WinRM/RDP connect paths and,
// equally, reveal and checkout. It writes a 403 and returns false when the caller
// may not reach the target. action names the audited denial (e.g. "credential.reveal").
func (s *Server) gateCredentialAccess(w http.ResponseWriter, r *http.Request, target *store.Target, action string) bool {
	if ok, err := s.authorizedForTarget(r.Context(), target.ID); err != nil {
		storeError(w, err)
		return false
	} else if !ok {
		s.audit(r.Context(), action+"_denied", "target:"+target.Name+" reason:target-policy")
		writeError(w, http.StatusForbidden, "not authorized for this target")
		return false
	}
	if ok, err := s.enforceApproval(r.Context(), target); err != nil {
		storeError(w, err)
		return false
	} else if !ok {
		s.audit(r.Context(), "access.denied", "target:"+target.Name+" reason:approval-required")
		writeError(w, http.StatusForbidden, "access requires an approved access request")
		return false
	}
	return true
}

// --- credentials ---
