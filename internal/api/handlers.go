package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/morandeirachema/pamv1/internal/auditchain"
	"github.com/morandeirachema/pamv1/internal/store"
)

func (s *Server) listSessions(w http.ResponseWriter, r *http.Request) {
	if s.sessions == nil {
		writeJSON(w, http.StatusOK, []any{})
		return
	}
	writeJSON(w, http.StatusOK, s.sessions.List())
}

// streamSession streams a live session's output to a supervisor as Server-Sent
// Events (Phase 16 live monitoring). Each output frame is one `data:` event; the
// stream ends when the client disconnects or the session ends. Requires
// CapReadAudit and audits the start of monitoring.
func (s *Server) streamSession(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if s.live == nil {
		writeError(w, http.StatusNotFound, "live monitoring is not enabled")
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}
	frames, cancel := s.live.Subscribe(id)
	defer cancel()

	s.audit(r.Context(), "session.monitor", "session:"+id)
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no") // disable proxy buffering
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	for {
		select {
		case <-r.Context().Done():
			return
		case b := <-frames:
			// SSE frames are newline-delimited; encode as one data: field per
			// output chunk (any embedded newlines are re-prefixed by the client).
			if _, err := fmt.Fprintf(w, "data: %s\n\n", sseEscape(b)); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

// sseEscape renders an output frame safe for a single SSE data: line by
// replacing raw newlines (which would otherwise split the event) with a literal
// marker; the terminal content is otherwise passed through.
func sseEscape(b []byte) string {
	return strings.ReplaceAll(string(b), "\n", "\\n")
}

// killSession terminates a live session by id via the registry and audits it; an
// unknown session id is a 404.
func (s *Server) killSession(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if s.sessions == nil || !s.sessions.Kill(id) {
		writeError(w, http.StatusNotFound, "session not found")
		return
	}
	s.audit(r.Context(), "session.kill", "session:"+id)
	w.WriteHeader(http.StatusNoContent)
}

// --- audit ---

// listAudit returns recent audit events, capped by ?limit= (default 100).
func (s *Server) listAudit(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if q := r.URL.Query().Get("limit"); q != "" {
		if n, err := strconv.Atoi(q); err == nil {
			limit = n
		}
	}
	// Clamp here so the response size is bounded and identical on both stores
	// (memstore would otherwise return everything for limit<=0).
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	events, err := s.store.ListAudit(r.Context(), limit)
	if err != nil {
		storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, events)
}

// verifyAudit recomputes the tamper-evident chain over the primary audit trail
// and reports whether it is intact. It returns 501 when chaining is not enabled
// (no PAM_AUDIT_HMAC_KEY). A broken chain reports ok=false with the offending id.
func (s *Server) verifyAudit(w http.ResponseWriter, r *http.Request) {
	ok, brokeAtID, err := s.store.VerifyAuditChain(r.Context())
	if err != nil {
		writeError(w, http.StatusNotImplemented, "audit chain is not enabled (set PAM_AUDIT_HMAC_KEY)")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": ok, "broke_at_id": brokeAtID})
}

// auditHead returns an ed25519-signed checkpoint of the primary audit chain's
// current head. An auditor stores it out-of-band and later detects TAIL
// TRUNCATION (which the HMAC chain alone cannot catch) by re-verifying the signed
// (last_id, head) against the published public key. Returns 501 when checkpoint
// signing is not configured (no PAM_AUDIT_SIGN_SEED).
func (s *Server) auditHead(w http.ResponseWriter, r *http.Request) {
	if s.auditSignKey == nil {
		writeError(w, http.StatusNotImplemented, "audit checkpoints are not enabled (set PAM_AUDIT_HMAC_KEY and PAM_AUDIT_SIGN_SEED)")
		return
	}
	head, err := s.store.GetAuditHead(r.Context())
	if err != nil {
		storeError(w, err)
		return
	}
	var lastID int64
	var h []byte
	if head != nil {
		lastID, h = head.ID, head.HMAC
	}
	writeJSON(w, http.StatusOK, auditchain.SignCheckpoint(s.auditSignKey, lastID, h, time.Now()))
}

// --- helpers ---

// writeJSON writes v as a JSON response body with the given status code.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeError writes a JSON {"error": msg} body with the given status code.
func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// readJSON decodes the request body (capped at 1 MiB) into v, writing a 400 and
// returning false on a decode failure.
func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return false
	}
	return true
}

// idParam parses the {id} path value as a positive int64, writing a 422 and
// returning false when it is missing or invalid.
func idParam(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id < 1 {
		writeError(w, http.StatusUnprocessableEntity, "invalid id")
		return 0, false
	}
	return id, true
}

// storeError maps a store error to an HTTP response: ErrNotFound to 404,
// ErrConflict to 409, and anything else to 500 (logged).
func storeError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "not found")
	case errors.Is(err, store.ErrConflict):
		writeError(w, http.StatusConflict, "already exists")
	default:
		slog.Error("store error", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
	}
}
