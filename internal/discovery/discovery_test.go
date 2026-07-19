package discovery

import (
	"context"
	"net"
	"testing"
	"time"
)

// TestScanFindsOpenPort verifies a reachable port is returned and classified by
// protocol and OS type.
func TestScanFindsOpenPort(t *testing.T) {
	// A real listener on an ephemeral port; we tell the scanner to probe it as
	// if it were SSH (port 22) via an injected dialer that rewrites the address.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	sc := Scanner{
		Timeout: 500 * time.Millisecond,
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// Redirect the well-known port to our listener; drop everything else.
			_, port, _ := net.SplitHostPort(addr)
			if port == "22" {
				var d net.Dialer
				return d.DialContext(ctx, "tcp", ln.Addr().String())
			}
			return nil, &net.OpError{Op: "dial", Err: net.UnknownNetworkError("closed")}
		},
	}
	got := sc.Scan(context.Background(), []string{"10.0.0.5"}, []int{22, 3389})
	if len(got) != 1 {
		t.Fatalf("expected 1 candidate, got %d: %+v", len(got), got)
	}
	if got[0].Protocol != "ssh" || got[0].OSType != "linux" || got[0].Port != 22 {
		t.Fatalf("misclassified candidate: %+v", got[0])
	}
}

// TestScanSkipsUnknownPortsAndClosed verifies unknown ports and failed dials
// yield no candidates.
func TestScanSkipsUnknownPortsAndClosed(t *testing.T) {
	sc := Scanner{
		Timeout: 200 * time.Millisecond,
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return nil, &net.OpError{Op: "dial", Err: net.UnknownNetworkError("closed")}
		},
	}
	// 9999 is unknown (skipped); 22 is known but the dial fails (closed).
	if got := sc.Scan(context.Background(), []string{"h"}, []int{9999, 22}); len(got) != 0 {
		t.Fatalf("expected no candidates, got %+v", got)
	}
}

// TestDefaultPorts checks the default port set is non-empty.
func TestDefaultPorts(t *testing.T) {
	if len(DefaultPorts()) == 0 {
		t.Fatal("DefaultPorts must not be empty")
	}
}
