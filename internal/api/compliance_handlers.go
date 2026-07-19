package api

import (
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/morandeirachema/pamv1/internal/store"
)

// exportAudit produces a tamper-evident audit slice for NIS2 incident reporting
// (Art. 23 early-warning / notification duties). Query params:
//
//	since, until  RFC3339 timestamps (bounds; defaults: beginning .. now)
//	actor, action optional substring/exact filters to scope an incident
//	format        json (default) | csv
//
// The response carries a SHA-256 over the canonical event list (JSON body field
// "sha256" and the X-PAM-Export-SHA256 header) so a regulator can verify the
// export was not altered after generation. The export itself is audited.
func (s *Server) exportAudit(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	since, err := parseTimeParam(q.Get("since"))
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "since must be RFC3339")
		return
	}
	until, err := parseTimeParam(q.Get("until"))
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "until must be RFC3339")
		return
	}
	events, err := s.store.ExportAudit(r.Context(), since, until)
	if err != nil {
		storeError(w, err)
		return
	}
	events = filterAudit(events, q.Get("actor"), q.Get("action"))

	// Canonical digest over the filtered events (tamper evidence).
	canonical, _ := json.Marshal(events)
	sum := sha256.Sum256(canonical)
	digest := hex.EncodeToString(sum[:])

	s.audit(r.Context(), "audit.export",
		fmt.Sprintf("events:%d since:%s until:%s sha256:%s", len(events), q.Get("since"), q.Get("until"), digest))
	w.Header().Set("X-PAM-Export-SHA256", digest)

	if q.Get("format") == "csv" {
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", "attachment; filename=pamv1-audit-export.csv")
		cw := csv.NewWriter(w)
		_ = cw.Write([]string{"id", "ts", "actor", "action", "detail"})
		for _, e := range events {
			_ = cw.Write([]string{
				strconv.FormatInt(e.ID, 10), e.TS.UTC().Format(time.RFC3339Nano),
				csvSafe(e.Actor), csvSafe(e.Action), csvSafe(e.Detail),
			})
		}
		cw.Flush()
		return
	}

	w.Header().Set("Content-Disposition", "attachment; filename=pamv1-audit-export.json")
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at": time.Now().UTC(),
		"count":        len(events),
		"sha256":       digest,
		"events":       events,
	})
}

// csvSafe defuses spreadsheet formula injection: a cell that a spreadsheet would
// evaluate (leading =, +, -, @, tab or CR) is prefixed with a single quote, so a
// target name or reason in this compliance export can't run as a formula.
func csvSafe(s string) string {
	if s == "" {
		return s
	}
	switch s[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + s
	}
	return s
}

// parseTimeParam parses an RFC3339 timestamp, treating the empty string as the
// zero time (an open bound).
func parseTimeParam(v string) (time.Time, error) {
	if v == "" {
		return time.Time{}, nil
	}
	return time.Parse(time.RFC3339, v)
}

// filterAudit narrows events by exact action and case-insensitive actor
// substring; empty filters pass everything through.
func filterAudit(events []store.AuditEvent, actor, action string) []store.AuditEvent {
	if actor == "" && action == "" {
		return events
	}
	actorLC := strings.ToLower(actor)
	out := make([]store.AuditEvent, 0, len(events))
	for _, e := range events {
		if action != "" && e.Action != action {
			continue
		}
		if actor != "" && !strings.Contains(strings.ToLower(e.Actor), actorLC) {
			continue
		}
		out = append(out, e)
	}
	return out
}
