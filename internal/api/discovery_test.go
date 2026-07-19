package api_test

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"testing"

	"github.com/morandeirachema/pamv1/internal/api"
)

func TestDiscoveryScanAndCreate(t *testing.T) {
	// A real listener answers only for port 22; the injected dialer redirects
	// probes of 127.0.0.1:22 to it, so the scan finds one SSH candidate.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			c.Close()
		}
	}()

	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		_, port, _ := net.SplitHostPort(addr)
		if port == "22" {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", ln.Addr().String())
		}
		return nil, &net.OpError{Op: "dial", Err: net.UnknownNetworkError("closed")}
	}
	srv, _ := newTestServerOpts(t, nil, api.Options{DiscoveryDial: dial})

	body := map[string]any{"hosts": []string{"10.0.0.5"}, "ports": []int{22, 3389}, "create": true}
	status, data := do(t, srv, http.MethodPost, "/api/discovery/scan", testAPIKey, body)
	if status != http.StatusOK {
		t.Fatalf("scan: %d %s", status, data)
	}
	var out struct {
		Candidates []map[string]any `json:"candidates"`
		Created    []map[string]any `json:"created"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Candidates) != 1 || out.Candidates[0]["protocol"] != "ssh" {
		t.Fatalf("expected one ssh candidate, got %s", data)
	}
	if len(out.Created) != 1 || out.Created[0]["protocol"] != "ssh" {
		t.Fatalf("expected one created target, got %s", data)
	}

	// The target is now in the inventory; a second scan creates nothing new.
	_, data = do(t, srv, http.MethodPost, "/api/discovery/scan", testAPIKey, body)
	json.Unmarshal(data, &out)
	if len(out.Created) != 0 {
		t.Fatalf("second scan should not re-create: %s", data)
	}
}

func TestDiscoveryScanRequiresHosts(t *testing.T) {
	srv := newTestServer(t)
	if status, _ := do(t, srv, http.MethodPost, "/api/discovery/scan", testAPIKey, map[string]any{"hosts": []string{}}); status != http.StatusUnprocessableEntity {
		t.Fatalf("empty hosts: want 422, got %d", status)
	}
}

func TestDiscoveryScanNeedsManageTargets(t *testing.T) {
	srv := newTestServer(t)
	tok := seedUser(t, srv, "alice", "auditor") // no CapManageTargets
	if status, _ := do(t, srv, http.MethodPost, "/api/discovery/scan", tok, map[string]any{"hosts": []string{"h"}}); status != http.StatusForbidden {
		t.Fatalf("auditor scan: want 403, got %d", status)
	}
}
