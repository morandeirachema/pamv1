package api

import (
	"bytes"
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
// The X-PAM-Export-SHA256 header is a SHA-256 over the exact delivered bytes (the
// JSON or CSV artifact), so a regulator can `sha256sum` the file and match the
// header. The export — its scope and digest — is itself audited.
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

	// Build the exact artifact bytes for the requested format, then hash THOSE — so
	// `sha256sum <downloaded file>` matches the X-PAM-Export-SHA256 header for both
	// json and csv (previously the digest was always over the JSON, so it never
	// matched a delivered CSV). The sha256 moves to the header only (embedding it in
	// the JSON body would make the body un-hashable against itself).
	var body []byte
	contentType, filename := "application/json", "pamv1-audit-export.json"
	if q.Get("format") == "csv" {
		var buf bytes.Buffer
		cw := csv.NewWriter(&buf)
		_ = cw.Write([]string{"id", "ts", "actor", "action", "detail"})
		for _, e := range events {
			_ = cw.Write([]string{
				strconv.FormatInt(e.ID, 10), e.TS.UTC().Format(time.RFC3339Nano),
				csvSafe(e.Actor), csvSafe(e.Action), csvSafe(e.Detail),
			})
		}
		cw.Flush()
		body = buf.Bytes()
		contentType, filename = "text/csv", "pamv1-audit-export.csv"
	} else {
		// No wall-clock field in the hashed body: it must stay deterministic over a
		// fixed window so a regulator re-running the export gets the same digest (the
		// export time is captured in the audit.export event instead).
		body, _ = json.MarshalIndent(map[string]any{
			"count":  len(events),
			"events": events,
		}, "", "  ")
	}
	sum := sha256.Sum256(body)
	digest := hex.EncodeToString(sum[:])

	// Record the FULL query (filter included) with the digest, so the export is
	// attributable to a known scope and the digest can be tied to what it covers.
	s.audit(r.Context(), "audit.export", fmt.Sprintf(
		"events:%d format:%s since:%s until:%s actor:%q action:%q sha256:%s",
		len(events), contentType, q.Get("since"), q.Get("until"), q.Get("actor"), q.Get("action"), digest))

	w.Header().Set("X-PAM-Export-SHA256", digest)
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", "attachment; filename="+filename)
	_, _ = w.Write(body)
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
