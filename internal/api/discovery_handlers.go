package api

import (
	"fmt"
	"net/http"

	"github.com/morandeirachema/pamv1/internal/discovery"
	"github.com/morandeirachema/pamv1/internal/store"
)

type discoveryIn struct {
	Hosts  []string `json:"hosts"`
	Ports  []int    `json:"ports"`
	Create bool     `json:"create"` // auto-create targets for new candidates
}

// discoveryScan probes the given hosts for reachable management ports (SSH,
// WinRM, RDP) and returns candidates. With create=true it onboards new ones as
// targets (skipping hosts already inventoried for that protocol). It only checks
// reachability — no credentials are used.
func (s *Server) discoveryScan(w http.ResponseWriter, r *http.Request) {
	var in discoveryIn
	if !readJSON(w, r, &in) {
		return
	}
	if len(in.Hosts) == 0 {
		writeError(w, http.StatusUnprocessableEntity, "hosts is required")
		return
	}
	if len(in.Hosts) > 1024 {
		writeError(w, http.StatusUnprocessableEntity, "too many hosts (max 1024)")
		return
	}
	candidates := discovery.Scanner{Dial: s.discoveryDial}.Scan(r.Context(), in.Hosts, in.Ports)
	s.audit(r.Context(), "discovery.scan", fmt.Sprintf("hosts:%d candidates:%d create:%t", len(in.Hosts), len(candidates), in.Create))

	created := []store.Target{}
	if in.Create {
		existing, err := s.store.ListTargets(r.Context())
		if err != nil {
			storeError(w, err)
			return
		}
		have := map[string]bool{}
		for _, t := range existing {
			have[t.Host+"/"+t.Protocol] = true
		}
		for _, c := range candidates {
			if have[c.Host+"/"+c.Protocol] {
				continue
			}
			t := store.Target{
				Name: fmt.Sprintf("%s-%s", c.Host, c.Protocol),
				Host: c.Host, Port: c.Port, OSType: c.OSType, Protocol: c.Protocol,
			}
			if err := s.store.CreateTarget(r.Context(), &t); err != nil {
				// A racing/duplicate name is non-fatal; skip it.
				continue
			}
			have[c.Host+"/"+c.Protocol] = true
			created = append(created, t)
			s.audit(r.Context(), "target.create", t.Name+" via:discovery")
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"candidates": candidates,
		"created":    created,
	})
}
