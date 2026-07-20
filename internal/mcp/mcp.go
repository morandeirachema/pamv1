// Package mcp is a minimal, hand-rolled JSON-RPC 2.0 core for pamv1's Model
// Context Protocol endpoint. It handles framing and method dispatch only — the
// actual methods (initialize, tools/list, tools/call, ping, broker/resume) are
// supplied by the api layer and share the broker's one policy loop, so an MCP
// tool call is authorized and audited exactly like a REST call. stdlib only.
package mcp

import (
	"context"
	"encoding/json"
)

// Version is the MCP protocol version this server implements.
const Version = "2024-11-05"

// Request is a JSON-RPC 2.0 request. A request with no id is a notification and
// gets no response.
type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// Response is a JSON-RPC 2.0 response.
type Response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *Error          `json:"error,omitempty"`
}

// Error is a JSON-RPC 2.0 error object.
type Error struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

// Error implements error so a Method can return it directly.
func (e *Error) Error() string { return e.Message }

// Standard JSON-RPC 2.0 error codes.
const (
	CodeParse          = -32700
	CodeInvalidRequest = -32600
	CodeMethodNotFound = -32601
	CodeInvalidParams  = -32602
	CodeInternal       = -32603
)

// Errorf builds an *Error with a code and message.
func Errorf(code int, message string) *Error { return &Error{Code: code, Message: message} }

// Method handles one JSON-RPC method: given the raw params, it returns a result
// or a JSON-RPC error.
type Method func(ctx context.Context, params json.RawMessage) (any, *Error)

// Dispatcher routes JSON-RPC method names to handlers.
type Dispatcher map[string]Method

// isNotification reports whether the request is a notification (absent or null
// id), which per JSON-RPC 2.0 must not be answered.
func isNotification(id json.RawMessage) bool {
	return len(id) == 0 || string(id) == "null"
}

// Handle parses a single JSON-RPC request and dispatches it. It returns the
// response to send and whether there is one (notifications produce ok=false, so
// the caller can reply 204/empty). JSON-RPC-level problems (bad JSON, unknown
// method) become error responses, never transport errors.
func (d Dispatcher) Handle(ctx context.Context, body []byte) (Response, bool) {
	var req Request
	if err := json.Unmarshal(body, &req); err != nil {
		return errorResponse(nil, Errorf(CodeParse, "parse error")), true
	}
	if req.JSONRPC != "2.0" || req.Method == "" {
		if isNotification(req.ID) {
			return Response{}, false
		}
		return errorResponse(req.ID, Errorf(CodeInvalidRequest, "invalid request")), true
	}
	method, ok := d[req.Method]
	if !ok {
		if isNotification(req.ID) {
			return Response{}, false // unknown notification: ignore
		}
		return errorResponse(req.ID, Errorf(CodeMethodNotFound, "method not found: "+req.Method)), true
	}
	result, rpcErr := method(ctx, req.Params)
	if isNotification(req.ID) {
		return Response{}, false // notifications get no response even on error
	}
	if rpcErr != nil {
		return errorResponse(req.ID, rpcErr), true
	}
	return Response{JSONRPC: "2.0", ID: req.ID, Result: result}, true
}

// errorResponse builds a JSON-RPC error response with the given id (null when nil).
func errorResponse(id json.RawMessage, e *Error) Response {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	return Response{JSONRPC: "2.0", ID: id, Error: e}
}
