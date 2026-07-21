package api

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/morandeirachema/pamv1/internal/alert"
	"github.com/morandeirachema/pamv1/internal/store"
)

// --- access-request approval workflow (4-eyes) ---

type accessRequestIn struct {
	TargetID int64  `json:"target_id"`
	Reason   string `json:"reason"`
	Ticket   string `json:"ticket"`
	// Phase 21: multi-tier chains + scheduled windows. Approvals asks for more
	// than the configured minimum distinct approvers; NotBefore/NotAfter schedule
	// a maintenance window (the approval is only active between them).
	Approvals int        `json:"approvals,omitempty"`
	NotBefore *time.Time `json:"not_before,omitempty"`
	NotAfter  *time.Time `json:"not_after,omitempty"`
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
	// Mandatory reason code (Phase 21), when configured.
	if s.requireReason && in.Reason == "" {
		writeError(w, http.StatusUnprocessableEntity, "a reason is required for access requests")
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
	// Multi-tier chains + scheduled window (Phase 21). RequiredApprovals is the
	// larger of the request's ask and the configured default (at least 1). The
	// window defaults to now → now+approvalWindow; a scheduled request supplies
	// not_before / not_after.
	required := s.approvalsRequired
	if in.Approvals > required {
		required = in.Approvals
	}
	if required < 1 {
		required = 1
	}
	expires := time.Now().Add(s.rt().approvalWindow).UTC()
	if in.NotAfter != nil {
		expires = in.NotAfter.UTC()
	}
	ar := store.AccessRequest{
		Requester:         actorFrom(r.Context()),
		TargetID:          in.TargetID,
		Reason:            in.Reason,
		Status:            "pending",
		ExpiresAt:         expires,
		Ticket:            in.Ticket,
		RequiredApprovals: required,
		NotBefore:         in.NotBefore,
	}
	if err := s.store.CreateAccessRequest(r.Context(), &ar); err != nil {
		storeError(w, err)
		return
	}
	s.audit(r.Context(), "access.request", fmt.Sprintf("request:%d target:%d reason:%q ticket:%q approvals_required:%d", ar.ID, ar.TargetID, ar.Reason, ar.Ticket, ar.RequiredApprovals))
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

	// A single deny is final.
	if decision == "denied" {
		if err := s.store.DecideAccessRequest(r.Context(), ar.ID, "denied", approver, time.Now()); err != nil {
			storeError(w, err)
			return
		}
		s.notifyDecision(r, "access.deny", approver, ar)
		ar.Status = "denied"
		ar.Approver = approver
		writeJSON(w, http.StatusOK, ar)
		return
	}

	// Approve: accumulate DISTINCT approvers (Phase 21 multi-tier chains). The
	// request is granted only once RequiredApprovals of them have approved.
	approvers := splitApprovers(ar.ApprovedBy)
	for _, a := range approvers {
		if strings.EqualFold(a, approver) {
			writeError(w, http.StatusConflict, "you have already approved this request")
			return
		}
	}
	approvers = append(approvers, approver)
	required := ar.RequiredApprovals
	if required < 1 {
		required = 1
	}
	joined := strings.Join(approvers, ",")
	if len(approvers) >= required {
		now := time.Now()
		if err := s.store.SetApprovalState(r.Context(), ar.ID, joined, "approved", approver, &now); err != nil {
			storeError(w, err)
			return
		}
		s.audit(r.Context(), "access.approve", fmt.Sprintf("request:%d requester:%s target:%d approvers:%d/%d", ar.ID, ar.Requester, ar.TargetID, len(approvers), required))
		s.notifyDecision(r, "access.approve", approver, ar)
		ar.Status = "approved"
		ar.Approver = approver
	} else {
		if err := s.store.SetApprovalState(r.Context(), ar.ID, joined, "pending", "", nil); err != nil {
			storeError(w, err)
			return
		}
		s.audit(r.Context(), "access.approve_partial", fmt.Sprintf("request:%d target:%d approver:%s approvals:%d/%d", ar.ID, ar.TargetID, approver, len(approvers), required))
	}
	ar.ApprovedBy = joined
	writeJSON(w, http.StatusOK, ar)
}

// splitApprovers parses a comma-joined approver set into a trimmed, non-empty
// slice.
func splitApprovers(s string) []string {
	var out []string
	for _, a := range strings.Split(s, ",") {
		if a = strings.TrimSpace(a); a != "" {
			out = append(out, a)
		}
	}
	return out
}

// notifyDecision audits nothing (the caller audits) but fires the real-time
// alert for a final approve/deny decision.
func (s *Server) notifyDecision(r *http.Request, action, approver string, ar *store.AccessRequest) {
	if action == "access.deny" {
		s.audit(r.Context(), "access.deny", fmt.Sprintf("request:%d requester:%s target:%d", ar.ID, ar.Requester, ar.TargetID))
	}
	s.alerter.Notify(r.Context(), alert.Event{
		Type: action, Actor: approver,
		Detail: fmt.Sprintf("request:%d requester:%s target:%d", ar.ID, ar.Requester, ar.TargetID),
		Remote: r.RemoteAddr, Time: time.Now(),
	})
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
