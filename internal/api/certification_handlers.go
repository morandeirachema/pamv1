package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/morandeirachema/pamv1/internal/store"
)

// --- access certification / attestation campaigns (Phase 19): a point-in-time
// review of who has access to what. A campaign snapshots the current access
// grants (target grants + safe members); a reviewer certifies or revokes each,
// and a "revoke" actually removes the underlying grant. ---

type campaignIn struct {
	Name  string     `json:"name"`
	DueAt *time.Time `json:"due_at,omitempty"`
}

// createCampaign snapshots the current access grants into a new campaign
// (CapManageUsers) and audits it.
func (s *Server) createCampaign(w http.ResponseWriter, r *http.Request) {
	var in campaignIn
	if !readJSON(w, r, &in) {
		return
	}
	if in.Name == "" {
		writeError(w, http.StatusUnprocessableEntity, "name is required")
		return
	}
	ctx := r.Context()
	c := store.Campaign{Name: in.Name, CreatedBy: actorFrom(ctx), DueAt: in.DueAt, Status: "open"}
	if err := s.store.CreateCampaign(ctx, &c); err != nil {
		storeError(w, err)
		return
	}
	items, err := s.snapshotAccess(ctx, c.ID)
	if err != nil {
		storeError(w, err)
		return
	}
	s.audit(ctx, "certification.campaign_created", fmt.Sprintf("campaign:%d name:%q items:%d", c.ID, c.Name, items))
	writeJSON(w, http.StatusCreated, map[string]any{"campaign": c, "items": items})
}

// snapshotAccess records the current target grants and safe members as items of
// campaign cid, returning how many were captured.
func (s *Server) snapshotAccess(ctx context.Context, cid int64) (int, error) {
	n := 0
	targets, err := s.store.ListTargets(ctx)
	if err != nil {
		return 0, err
	}
	for _, t := range targets {
		grants, err := s.store.ListTargetGrants(ctx, t.ID)
		if err != nil {
			return 0, err
		}
		for _, g := range grants {
			if err := s.store.AddCampaignItem(ctx, &store.CampaignItem{
				CampaignID: cid, Kind: "target_grant", RefID: g.ID,
				SubjectType: g.SubjectType, Subject: g.Subject,
				Detail: fmt.Sprintf("grant on target %q", t.Name),
			}); err != nil {
				return 0, err
			}
			n++
		}
	}
	safes, err := s.store.ListSafes(ctx)
	if err != nil {
		return 0, err
	}
	for _, sf := range safes {
		members, err := s.store.ListSafeMembers(ctx, sf.ID)
		if err != nil {
			return 0, err
		}
		for _, mem := range members {
			if err := s.store.AddCampaignItem(ctx, &store.CampaignItem{
				CampaignID: cid, Kind: "safe_member", RefID: mem.ID,
				SubjectType: mem.SubjectType, Subject: mem.Subject,
				Detail: fmt.Sprintf("member of safe %q", sf.Name),
			}); err != nil {
				return 0, err
			}
			n++
		}
	}
	return n, nil
}

// listCampaigns returns all campaigns (CapReadAudit).
func (s *Server) listCampaigns(w http.ResponseWriter, r *http.Request) {
	cs, err := s.store.ListCampaigns(r.Context())
	if err != nil {
		storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, cs)
}

// getCampaign returns a campaign with its items (CapReadAudit).
func (s *Server) getCampaign(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	c, err := s.store.GetCampaign(r.Context(), id)
	if err != nil {
		storeError(w, err)
		return
	}
	items, err := s.store.ListCampaignItems(r.Context(), id)
	if err != nil {
		storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"campaign": c, "items": items})
}

type certDecisionIn struct {
	Decision string `json:"decision"` // certify | revoke
}

// decideCampaignItem records a certify/revoke decision (CapManageUsers). A
// "revoke" deletes the underlying access grant/member.
func (s *Server) decideCampaignItem(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	iid, err := strconv.ParseInt(r.PathValue("iid"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid item id")
		return
	}
	var in certDecisionIn
	if !readJSON(w, r, &in) {
		return
	}
	if in.Decision != "certify" && in.Decision != "revoke" {
		writeError(w, http.StatusUnprocessableEntity, `decision must be "certify" or "revoke"`)
		return
	}
	ctx := r.Context()
	c, err := s.store.GetCampaign(ctx, id)
	if err != nil {
		storeError(w, err)
		return
	}
	if c.Status != "open" {
		writeError(w, http.StatusConflict, "campaign is closed")
		return
	}
	item, err := s.store.GetCampaignItem(ctx, iid)
	if err != nil {
		storeError(w, err)
		return
	}
	if item.CampaignID != id {
		writeError(w, http.StatusNotFound, "item not in this campaign")
		return
	}

	if in.Decision == "revoke" {
		if err := s.revokeAccess(ctx, item); err != nil {
			storeError(w, err)
			return
		}
		if err := s.store.DecideCampaignItem(ctx, iid, "revoked", actorFrom(ctx), time.Now()); err != nil {
			storeError(w, err)
			return
		}
		s.audit(ctx, "certification.item_revoked", fmt.Sprintf("campaign:%d item:%d %s:%s %s", id, iid, item.SubjectType, item.Subject, item.Detail))
	} else {
		if err := s.store.DecideCampaignItem(ctx, iid, "certified", actorFrom(ctx), time.Now()); err != nil {
			storeError(w, err)
			return
		}
		s.audit(ctx, "certification.item_certified", fmt.Sprintf("campaign:%d item:%d %s:%s %s", id, iid, item.SubjectType, item.Subject, item.Detail))
	}
	w.WriteHeader(http.StatusNoContent)
}

// revokeAccess deletes the underlying grant an item points at. A grant already
// gone (e.g. deleted since the snapshot) is not an error — the goal state is
// "no access", which already holds.
func (s *Server) revokeAccess(ctx context.Context, item *store.CampaignItem) error {
	var err error
	switch item.Kind {
	case "target_grant":
		err = s.store.DeleteTargetGrant(ctx, item.RefID)
	case "safe_member":
		err = s.store.DeleteSafeMember(ctx, item.RefID)
	default:
		return fmt.Errorf("unknown campaign item kind %q", item.Kind)
	}
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	return err
}

// closeCampaign marks a campaign closed (CapManageUsers).
func (s *Server) closeCampaign(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	if err := s.store.CloseCampaign(r.Context(), id, time.Now()); err != nil {
		storeError(w, err)
		return
	}
	s.audit(r.Context(), "certification.campaign_closed", fmt.Sprintf("campaign:%d", id))
	w.WriteHeader(http.StatusNoContent)
}
