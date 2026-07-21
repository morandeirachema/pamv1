package api

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/morandeirachema/pamv1/internal/alert"
	"github.com/morandeirachema/pamv1/internal/store"
)

// --- access-request approval workflow (4-eyes) ---

type accessRequestIn struct {
	TargetID int64  `json:"target_id"`
	Reason   string `json:"reason"`
	Ticket   string `json:"ticket"`
}

// createAccessRequest files a request to connect to a target. The requester is
// the caller; approval must come from a different principal (see approve/deny).
func (s *Server) createAccessRequest(w http.ResponseWriter, r *http.Request) {
	var in accessRequestIn
	if !readJSON(w, r, &in) {
		return
	}
	if _, err := s.store.GetTarget(r.Context(), in.TargetID); err != nil {
		storeError(w, err)
		return
	}
	// ITSM / ticketing gate (Phase 20): require and/or validate a change ticket
	// before the request is created; the ticket is recorded in the audit trail.
	if s.requireTicket && in.Ticket == "" {
		writeError(w, http.StatusUnprocessableEntity, "a change/incident ticket is required for access requests")
		return
	}
	if in.Ticket != "" && s.ticketValidator.Enabled() {
		if err := s.ticketValidator.Validate(r.Context(), in.Ticket); err != nil {
			s.audit(r.Context(), "access.ticket_rejected", fmt.Sprintf("target:%d ticket:%q reason:%v", in.TargetID, in.Ticket, err))
			writeError(w, http.StatusUnprocessableEntity, "ticket rejected: "+err.Error())
			return
		}
	}
	ar := store.AccessRequest{
		Requester: actorFrom(r.Context()),
		TargetID:  in.TargetID,
		Reason:    in.Reason,
		Status:    "pending",
		ExpiresAt: time.Now().Add(s.rt().approvalWindow).UTC(),
		Ticket:    in.Ticket,
	}
	if err := s.store.CreateAccessRequest(r.Context(), &ar); err != nil {
		storeError(w, err)
		return
	}
	s.audit(r.Context(), "access.request", fmt.Sprintf("request:%d target:%d reason:%q ticket:%q", ar.ID, ar.TargetID, ar.Reason, ar.Ticket))
	writeJSON(w, http.StatusCreated, ar)
}

// listAccessRequests lists requests, optionally filtered by ?status=.
func (s *Server) listAccessRequests(w http.ResponseWriter, r *http.Request) {
	status := r.URL.Query().Get("status")
	switch status {
	case "", "pending", "approved", "denied":
	default:
		writeError(w, http.StatusUnprocessableEntity, "status must be pending, approved or denied")
		return
	}
	reqs, err := s.store.ListAccessRequests(r.Context(), status)
	if err != nil {
		storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, reqs)
}

// approveAccessRequest approves the access request named in the {id} path value.
func (s *Server) approveAccessRequest(w http.ResponseWriter, r *http.Request) {
	s.decideAccessRequest(w, r, "approved")
}

// denyAccessRequest denies the access request named in the {id} path value.
func (s *Server) denyAccessRequest(w http.ResponseWriter, r *http.Request) {
	s.decideAccessRequest(w, r, "denied")
}

// decideAccessRequest records an approver's decision, enforcing the 4-eyes rule
// (the approver must differ from the requester) and that only pending requests
// can be decided.
func (s *Server) decideAccessRequest(w http.ResponseWriter, r *http.Request, decision string) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	ar, err := s.store.GetAccessRequest(r.Context(), id)
	if err != nil {
		storeError(w, err)
		return
	}
	approver := actorFrom(r.Context())
	if ar.Requester == approver {
		s.audit(r.Context(), "access.decision_denied", fmt.Sprintf("request:%d reason:self-approval", ar.ID))
		writeError(w, http.StatusForbidden, "four-eyes: you cannot decide your own access request")
		return
	}
	if ar.Status != "pending" {
		writeError(w, http.StatusConflict, "request already "+ar.Status)
		return
	}
	if err := s.store.DecideAccessRequest(r.Context(), ar.ID, decision, approver, time.Now()); err != nil {
		storeError(w, err)
		return
	}
	action := "access.approve"
	if decision == "denied" {
		action = "access.deny"
	}
	s.audit(r.Context(), action, fmt.Sprintf("request:%d requester:%s target:%d", ar.ID, ar.Requester, ar.TargetID))
	s.alerter.Notify(r.Context(), alert.Event{
		Type: action, Actor: approver,
		Detail: fmt.Sprintf("request:%d requester:%s target:%d", ar.ID, ar.Requester, ar.TargetID),
		Remote: r.RemoteAddr, Time: time.Now(),
	})
	ar.Status = decision
	ar.Approver = approver
	writeJSON(w, http.StatusOK, ar)
}

// --- enforcement ---

// requireApprovalFor reports whether connecting to target needs an approved
// access request (per-target flag or the global OT policy).
func (s *Server) requireApprovalFor(t *store.Target) bool {
	return s.rt().approvalRequired || t.RequireApproval
}

// enforceApproval reports whether the caller may connect to target under the
// approval policy. Break-glass bypasses (emergency access is already loud).
func (s *Server) enforceApproval(ctx context.Context, t *store.Target) (bool, error) {
	if !s.requireApprovalFor(t) {
		return true, nil
	}
	if principalFrom(ctx).BreakGlass {
		return true, nil
	}
	return s.store.HasActiveApproval(ctx, actorFrom(ctx), t.ID, time.Now())
}
