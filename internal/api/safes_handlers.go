package api

import (
	"context"
	"fmt"
	"net/http"
	"strconv"

	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/store"
)

// --- safes (Phase 17): named containers that group targets and delegate who may
// access them. A safe member may connect to every target in the safe (an
// authorization path alongside per-target grants); a can_manage member is a
// delegated safe administrator. ---

type safeIn struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// createSafe creates a safe (CapManageTargets) and audits it.
func (s *Server) createSafe(w http.ResponseWriter, r *http.Request) {
	var in safeIn
	if !readJSON(w, r, &in) {
		return
	}
	if in.Name == "" {
		writeError(w, http.StatusUnprocessableEntity, "name is required")
		return
	}
	sf := store.Safe{Name: in.Name, Description: in.Description}
	if err := s.store.CreateSafe(r.Context(), &sf); err != nil {
		storeError(w, err)
		return
	}
	s.audit(r.Context(), "safe.create", "safe:"+in.Name)
	writeJSON(w, http.StatusCreated, sf)
}

// listSafes returns all safes (CapReadInventory).
func (s *Server) listSafes(w http.ResponseWriter, r *http.Request) {
	safes, err := s.store.ListSafes(r.Context())
	if err != nil {
		storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, safes)
}

// deleteSafe removes a safe (CapManageTargets); its members cascade and its
// targets are unassigned.
func (s *Server) deleteSafe(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	if err := s.store.DeleteSafe(r.Context(), id); err != nil {
		storeError(w, err)
		return
	}
	s.audit(r.Context(), "safe.delete", fmt.Sprintf("safe:%d", id))
	w.WriteHeader(http.StatusNoContent)
}

type safeMemberIn struct {
	SubjectType string `json:"subject_type"`
	Subject     string `json:"subject"`
	CanManage   bool   `json:"can_manage"`
}

// addSafeMember adds a member to a safe. The route is open to inventory readers
// so a delegated can_manage member (not only a global target manager) can grant
// access to their own safe; canManageSafe enforces the finer check.
func (s *Server) addSafeMember(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	if !s.canManageSafe(r.Context(), id) {
		writeError(w, http.StatusForbidden, "not authorized to manage this safe")
		return
	}
	var in safeMemberIn
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
	m := store.SafeMember{SafeID: id, SubjectType: in.SubjectType, Subject: in.Subject, CanManage: in.CanManage}
	if err := s.store.AddSafeMember(r.Context(), &m); err != nil {
		storeError(w, err)
		return
	}
	s.audit(r.Context(), "safe.member.add", fmt.Sprintf("safe:%d %s:%s manage:%t", id, in.SubjectType, in.Subject, in.CanManage))
	writeJSON(w, http.StatusCreated, m)
}

// listSafeMembers returns a safe's members (CapReadInventory).
func (s *Server) listSafeMembers(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	members, err := s.store.ListSafeMembers(r.Context(), id)
	if err != nil {
		storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, members)
}

// deleteSafeMember removes a member from a safe (target manager or a can_manage
// member of that safe).
func (s *Server) deleteSafeMember(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	if !s.canManageSafe(r.Context(), id) {
		writeError(w, http.StatusForbidden, "not authorized to manage this safe")
		return
	}
	mid, err := strconv.ParseInt(r.PathValue("mid"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid member id")
		return
	}
	if err := s.store.DeleteSafeMember(r.Context(), mid); err != nil {
		storeError(w, err)
		return
	}
	s.audit(r.Context(), "safe.member.remove", fmt.Sprintf("safe:%d member:%d", id, mid))
	w.WriteHeader(http.StatusNoContent)
}

// canManageSafe reports whether the caller may manage a safe's membership: a
// global target manager (CapManageTargets) or a can_manage member of that safe.
func (s *Server) canManageSafe(ctx context.Context, safeID int64) bool {
	p := principalFrom(ctx)
	if p.Can(auth.CapManageTargets) {
		return true
	}
	members, err := s.store.ListSafeMembers(ctx, safeID)
	if err != nil {
		return false
	}
	for _, m := range members {
		if m.CanManage && auth.SubjectMatches(p, m.SubjectType, m.Subject) {
			return true
		}
	}
	return false
}

type targetSafeIn struct {
	SafeID *int64 `json:"safe_id"`
}

// setTargetSafe places a target in a safe (or clears it when safe_id is null);
// CapManageTargets. Putting a target in a safe restricts it to the safe's
// members (plus any direct target grants).
func (s *Server) setTargetSafe(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	var in targetSafeIn
	if !readJSON(w, r, &in) {
		return
	}
	if err := s.store.AssignTargetSafe(r.Context(), id, in.SafeID); err != nil {
		storeError(w, err)
		return
	}
	detail := fmt.Sprintf("target:%d safe:none", id)
	if in.SafeID != nil {
		detail = fmt.Sprintf("target:%d safe:%d", id, *in.SafeID)
	}
	s.audit(r.Context(), "target.safe_set", detail)
	w.WriteHeader(http.StatusNoContent)
}
