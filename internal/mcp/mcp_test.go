package mcp_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/morandeirachema/pamv1/internal/mcp"
)

// TestDispatcherHandle covers the JSON-RPC 2.0 framing: success, method errors,
// unknown methods, parse errors, and that notifications get no response.
func TestDispatcherHandle(t *testing.T) {
	d := mcp.Dispatcher{
		"echo": func(_ context.Context, params json.RawMessage) (any, *mcp.Error) {
			return map[string]any{"params": string(params)}, nil
		},
		"boom": func(context.Context, json.RawMessage) (any, *mcp.Error) {
			return nil, mcp.Errorf(mcp.CodeInternal, "boom")
		},
	}
	ctx := context.Background()

	// Success: id echoed, no error.
	resp, ok := d.Handle(ctx, []byte(`{"jsonrpc":"2.0","id":1,"method":"echo","params":{"x":1}}`))
	if !ok || resp.Error != nil || string(resp.ID) != "1" {
		t.Fatalf("echo: ok=%v resp=%+v", ok, resp)
	}

	// A method-level error becomes a JSON-RPC error response (still ok=true).
	resp, ok = d.Handle(ctx, []byte(`{"jsonrpc":"2.0","id":2,"method":"boom"}`))
	if !ok || resp.Error == nil || resp.Error.Code != mcp.CodeInternal {
		t.Fatalf("boom: %+v", resp)
	}

	// Unknown method → -32601.
	resp, _ = d.Handle(ctx, []byte(`{"jsonrpc":"2.0","id":3,"method":"nope"}`))
	if resp.Error == nil || resp.Error.Code != mcp.CodeMethodNotFound {
		t.Fatalf("unknown method: %+v", resp)
	}

	// Bad JSON → parse error.
	resp, _ = d.Handle(ctx, []byte(`{bad`))
	if resp.Error == nil || resp.Error.Code != mcp.CodeParse {
		t.Fatalf("parse: %+v", resp)
	}

	// Wrong jsonrpc version → invalid request.
	resp, _ = d.Handle(ctx, []byte(`{"jsonrpc":"1.0","id":4,"method":"echo"}`))
	if resp.Error == nil || resp.Error.Code != mcp.CodeInvalidRequest {
		t.Fatalf("bad version: %+v", resp)
	}

	// A notification (no id) produces no response.
	if _, ok := d.Handle(ctx, []byte(`{"jsonrpc":"2.0","method":"echo"}`)); ok {
		t.Fatal("notification should produce no response")
	}
	// An unknown notification is also silently ignored.
	if _, ok := d.Handle(ctx, []byte(`{"jsonrpc":"2.0","method":"nope"}`)); ok {
		t.Fatal("unknown notification should produce no response")
	}
}
