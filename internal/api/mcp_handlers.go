package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/morandeirachema/pamv1/internal/agentid"
	"github.com/morandeirachema/pamv1/internal/broker"
	"github.com/morandeirachema/pamv1/internal/mcp"
)

// serveMCP handles POST /mcp: a JSON-RPC 2.0 endpoint exposing the broker's tools
// to MCP clients. Auth is the same agentAuth as REST, and tools/call routes
// through the same broker.ProcessCall, so policy and audit are identical across
// the two transports.
func (s *Server) serveMCP(w http.ResponseWriter, r *http.Request, id *agentid.Identity) {
	r.Body = http.MaxBytesReader(w, r.Body, maxToolCallBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "request body too large or unreadable")
		return
	}
	resp, ok := s.mcpDispatcher(id).Handle(r.Context(), body)
	if !ok {
		w.WriteHeader(http.StatusNoContent) // JSON-RPC notification: no response body
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// mcpDispatcher builds the JSON-RPC method table bound to the authenticated agent.
func (s *Server) mcpDispatcher(id *agentid.Identity) mcp.Dispatcher {
	return mcp.Dispatcher{
		"initialize": func(context.Context, json.RawMessage) (any, *mcp.Error) {
			return map[string]any{
				"protocolVersion": mcp.Version,
				"capabilities":    map[string]any{"tools": map[string]any{}},
				"serverInfo":      map[string]any{"name": "pamv1-broker", "version": "13"},
			}, nil
		},
		"ping": func(context.Context, json.RawMessage) (any, *mcp.Error) {
			return map[string]any{}, nil
		},
		"tools/list": func(context.Context, json.RawMessage) (any, *mcp.Error) {
			tools := s.broker.Tools()
			out := make([]map[string]any, 0, len(tools))
			for _, t := range tools {
				out = append(out, map[string]any{
					"name":        t.Name(),
					"description": t.Description(),
					"inputSchema": jsonSchema(t.InputSchema()),
				})
			}
			return map[string]any{"tools": out}, nil
		},
		"tools/call": func(ctx context.Context, params json.RawMessage) (any, *mcp.Error) {
			var p struct {
				Name      string         `json:"name"`
				Arguments map[string]any `json:"arguments"`
			}
			if err := json.Unmarshal(params, &p); err != nil || p.Name == "" {
				return nil, mcp.Errorf(mcp.CodeInvalidParams, "tools/call requires a name")
			}
			out := s.broker.ProcessCall(ctx, id, broker.Call{Tool: p.Name, Args: p.Arguments})
			s.auditAs(ctx, id.AgentName, "broker.tool_call", fmt.Sprintf("tool:%s status:%s call:%s via:mcp", p.Name, out.Status, out.CallID))
			return toolResult(out), nil
		},
		"broker/resume": func(ctx context.Context, params json.RawMessage) (any, *mcp.Error) {
			var p struct {
				Token string `json:"token"`
			}
			if err := json.Unmarshal(params, &p); err != nil || p.Token == "" {
				return nil, mcp.Errorf(mcp.CodeInvalidParams, "broker/resume requires a token")
			}
			out, ok := s.broker.Resume(ctx, p.Token)
			if !ok {
				return nil, mcp.Errorf(mcp.CodeInvalidParams, "invalid, expired, or already-used resume token")
			}
			s.auditAs(ctx, id.AgentName, "broker.tool_call.resumed", fmt.Sprintf("call:%s status:%s via:mcp", out.CallID, out.Status))
			return toolResult(out), nil
		},
	}
}

// jsonSchema converts a tool's field->type map into a minimal JSON Schema object
// for MCP tools/list.
func jsonSchema(fields map[string]string) map[string]any {
	props := map[string]any{}
	for name, typ := range fields {
		jt := "string"
		switch typ {
		case "int":
			jt = "integer"
		case "bool":
			jt = "boolean"
		}
		props[name] = map[string]any{"type": jt}
	}
	return map[string]any{"type": "object", "properties": props}
}

// toolResult renders a broker outcome as an MCP tools/call result: the outcome as
// a JSON text block plus structured content, flagged isError only on a failure.
func toolResult(out broker.Outcome) map[string]any {
	raw, _ := json.Marshal(out)
	return map[string]any{
		"content":           []map[string]any{{"type": "text", "text": string(raw)}},
		"structuredContent": out,
		"isError":           out.Status == broker.StatusFailed,
	}
}
