package api

import (
	"fmt"
	"net/http"

	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/store"
)

type profileIn struct {
	Name         string   `json:"name"`
	Capabilities []string `json:"capabilities"`
}

// createProfile defines a custom permission profile — a named capability set
// assignable to users as an alternative to the four built-in roles.
func (s *Server) createProfile(w http.ResponseWriter, r *http.Request) {
	var in profileIn
	if !readJSON(w, r, &in) {
		return
	}
	if in.Name == "" {
		writeError(w, http.StatusUnprocessableEntity, "name is required")
		return
	}
	// A profile name must not shadow a built-in role or the agent role.
	if _, err := auth.ParseGrantRole(in.Name); err == nil {
		writeError(w, http.StatusUnprocessableEntity, "name collides with a built-in role")
		return
	}
	if _, err := auth.ParseCapabilities(in.Capabilities); err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	p := store.Profile{Name: in.Name, Capabilities: in.Capabilities}
	if err := s.store.CreateProfile(r.Context(), &p); err != nil {
		storeError(w, err)
		return
	}
	s.audit(r.Context(), "profile.create", fmt.Sprintf("%s caps:%d", p.Name, len(p.Capabilities)))
	writeJSON(w, http.StatusCreated, p)
}

// listProfiles returns all custom profiles.
func (s *Server) listProfiles(w http.ResponseWriter, r *http.Request) {
	profiles, err := s.store.ListProfiles(r.Context())
	if err != nil {
		storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, profiles)
}

// deleteProfile removes a custom profile by ID.
func (s *Server) deleteProfile(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	if err := s.store.DeleteProfile(r.Context(), id); err != nil {
		storeError(w, err)
		return
	}
	s.audit(r.Context(), "profile.delete", fmt.Sprintf("profile:%d", id))
	w.WriteHeader(http.StatusNoContent)
}
