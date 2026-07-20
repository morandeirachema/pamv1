package api

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/morandeirachema/pamv1/internal/agentid"
	"github.com/morandeirachema/pamv1/internal/broker"
	"github.com/morandeirachema/pamv1/internal/store"
)

// maxToolCallBytes bounds a tool-call request body.
const maxToolCallBytes = 64 << 10

// agentHandler is an HTTP handler that has already resolved the agent identity.
type agentHandler func(w http.ResponseWriter, r *http.Request, id *agentid.Identity)

// agentAuth authenticates an agent bearer credential (static key or, later, an
// SVID) and invokes next with the verified identity, or returns 401.
func (s *Server) agentAuth(next agentHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := s.agentVerifier.Verify(r.Context(), bearerToken(r))
		if err != nil {
			writeError(w, http.StatusUnauthorized, "invalid or missing agent credential")
			return
		}
		// Put the agent principal in the request context so reused helpers (e.g.
		// execWinRM's s.audit) attribute the sensitive action to the agent, not the
		// "unknown" fallback, and the access log records the agent.
		r = r.WithContext(withPrincipal(r.Context(), id.Principal()))
		setActor(r.Context(), id.AgentName)
		next(w, r, id)
	}
}

// bearerToken extracts a Bearer token from the Authorization header.
func bearerToken(r *http.Request) string {
	const p = "Bearer "
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, p) {
		return strings.TrimSpace(h[len(p):])
	}
	return ""
}

type toolCallIn struct {
	SessionID string         `json:"session_id"`
	Tool      string         `json:"tool"`
	Args      map[string]any `json:"args"`
}

// processToolCall runs an agent tool call through the broker's policy loop. It
// always returns HTTP 200: the decision is in the body's status field (per the
// broker contract, transport failures are the only non-200 responses).
func (s *Server) processToolCall(w http.ResponseWriter, r *http.Request, id *agentid.Identity) {
	r.Body = http.MaxBytesReader(w, r.Body, maxToolCallBytes)
	var in toolCallIn
	if !readJSON(w, r, &in) {
		return
	}
	if in.Tool == "" {
		writeError(w, http.StatusUnprocessableEntity, "tool is required")
		return
	}
	out := s.broker.ProcessCall(r.Context(), id, broker.Call{SessionID: in.SessionID, Tool: in.Tool, Args: in.Args})
	// Surface broker activity in the unified audit trail too; the hash chain
	// remains the authoritative, verifiable record.
	s.auditAs(r.Context(), id.AgentName, "broker.tool_call",
		fmt.Sprintf("tool:%s status:%s call:%s", in.Tool, out.Status, out.CallID))
	writeJSON(w, http.StatusOK, out)
}

// getToolCall returns the latest known outcome for a call id.
func (s *Server) getToolCall(w http.ResponseWriter, r *http.Request, _ *agentid.Identity) {
	out, ok := s.broker.Lookup(r.PathValue("id"))
	if !ok {
		writeError(w, http.StatusNotFound, "unknown call id")
		return
	}
	writeJSON(w, http.StatusOK, out)
}

type agentKeyIn struct {
	Name  string `json:"name"`
	Owner string `json:"owner"`
}

// createAgentKey mints a new agent identity key for an admin; the token is shown
// once and only its SHA-256 hash is stored.
func (s *Server) createAgentKey(w http.ResponseWriter, r *http.Request) {
	var in agentKeyIn
	if !readJSON(w, r, &in) {
		return
	}
	if in.Name == "" {
		writeError(w, http.StatusUnprocessableEntity, "name is required")
		return
	}
	token, err := generateToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "token generation failed")
		return
	}
	k := store.AgentKey{Name: in.Name, Owner: in.Owner, TokenHash: hashHex(token)}
	if err := s.store.CreateAgentKey(r.Context(), &k); err != nil {
		storeError(w, err)
		return
	}
	s.audit(r.Context(), "agent.create", fmt.Sprintf("%s owner:%s", k.Name, k.Owner))
	writeJSON(w, http.StatusCreated, map[string]any{
		"id": k.ID, "name": k.Name, "owner": k.Owner, "token": token,
		"note": "Give this token to the agent; only its hash is stored.",
	})
}

// listAgentKeys returns the registered agent identities (never their token hash).
func (s *Server) listAgentKeys(w http.ResponseWriter, r *http.Request) {
	keys, err := s.store.ListAgentKeys(r.Context())
	if err != nil {
		storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, keys)
}

// deleteAgentKey revokes an agent identity so its bearer token stops resolving.
func (s *Server) deleteAgentKey(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	if err := s.store.DeleteAgentKey(r.Context(), id); err != nil {
		storeError(w, err)
		return
	}
	s.audit(r.Context(), "agent.revoke", fmt.Sprintf("agent:%d", id))
	w.WriteHeader(http.StatusNoContent)
}

// listBrokerAudit returns recent broker audit events (oldest-first, chain order).
func (s *Server) listBrokerAudit(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if q := r.URL.Query().Get("limit"); q != "" {
		if n, err := strconv.Atoi(q); err == nil {
			limit = n
		}
	}
	events, err := s.store.ListBrokerAudit(r.Context(), limit)
	if err != nil {
		storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, events)
}

// verifyBrokerAudit walks the broker audit chain and reports whether it is intact.
func (s *Server) verifyBrokerAudit(w http.ResponseWriter, r *http.Request) {
	ok, brokeAt, err := s.auditChain.Verify(r.Context())
	if err != nil {
		storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": ok, "broke_at_id": brokeAt})
}

// brokerAuditHead returns a signed checkpoint anchoring the chain, for offline
// truncation detection.
func (s *Server) brokerAuditHead(w http.ResponseWriter, r *http.Request) {
	cp, err := s.auditChain.Head(r.Context(), time.Now())
	if err != nil {
		storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, cp)
}
