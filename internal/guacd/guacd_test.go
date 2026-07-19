package guacd

import (
	"bufio"
	"context"
	"net"
	"testing"
	"time"
)

// TestInstructionEncode checks the wire encoding and that element lengths count
// Unicode code points, not bytes.
func TestInstructionEncode(t *testing.T) {
	got := Instruction{Opcode: "select", Args: []string{"rdp"}}.Encode()
	if got != "6.select,3.rdp;" {
		t.Fatalf("encode = %q", got)
	}
	// Unicode length is counted in code points, not bytes.
	if g := (Instruction{Opcode: "x", Args: []string{"café"}}).Encode(); g != "1.x,4.café;" {
		t.Fatalf("unicode encode = %q", g)
	}
}

// mockGuacd plays the server side of the handshake and reports the connect args.
func mockGuacd(t *testing.T, argNames []string, connectCh chan<- []string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		r := bufio.NewReader(conn)
		// Expect select.
		if inst, err := readInstruction(r); err != nil || inst.Opcode != "select" {
			return
		}
		// Send args (first element a version token, like guacd ≥1.3).
		conn.Write([]byte(Instruction{Opcode: "args", Args: append([]string{"VERSION_1_5_0"}, argNames...)}.Encode()))
		// Read until connect, capturing its args.
		for {
			inst, err := readInstruction(r)
			if err != nil {
				return
			}
			if inst.Opcode == "connect" {
				connectCh <- inst.Args
				conn.Write([]byte(Instruction{Opcode: "ready", Args: []string{"$conn-123"}}.Encode()))
				return
			}
		}
	}()
	return ln.Addr().String()
}

// TestConnectInjectsCredentials checks connect values are supplied in the order
// guacd advertised its args, with the credential injected.
func TestConnectInjectsCredentials(t *testing.T) {
	connectCh := make(chan []string, 1)
	addr := mockGuacd(t, []string{"hostname", "port", "username", "password", "domain"}, connectCh)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := Connect(ctx, addr, Params{
		Protocol: "rdp", Hostname: "10.0.0.9", Port: "3389",
		Username: "Administrator", Password: "Rdp-S3cret!", Domain: "CONTOSO",
	})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer c.Close()
	if c.ID != "$conn-123" {
		t.Fatalf("connection id = %q", c.ID)
	}

	got := <-connectCh
	// Order matches the args guacd advertised: version, hostname, port, user, pass, domain.
	want := []string{"VERSION_1_5_0", "10.0.0.9", "3389", "Administrator", "Rdp-S3cret!", "CONTOSO"}
	if len(got) != len(want) {
		t.Fatalf("connect args = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("connect arg %d = %q, want %q", i, got[i], want[i])
		}
	}
}

// TestConnectRecordingParams checks the recording args, including a derived
// create-recording-path=true, are populated.
func TestConnectRecordingParams(t *testing.T) {
	connectCh := make(chan []string, 1)
	addr := mockGuacd(t, []string{"recording-path", "recording-name", "create-recording-path"}, connectCh)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := Connect(ctx, addr, Params{
		Protocol: "rdp", RecordingPath: "/recordings", RecordingName: "sess-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	got := <-connectCh
	// version, recording-path, recording-name, create-recording-path
	if got[1] != "/recordings" || got[2] != "sess-1" || got[3] != "true" {
		t.Fatalf("recording params not injected: %v", got)
	}
}

// TestConnectUnknownArgsAreEmpty checks Extra fills matching args while unknown
// args are sent as empty values.
func TestConnectUnknownArgsAreEmpty(t *testing.T) {
	connectCh := make(chan []string, 1)
	addr := mockGuacd(t, []string{"hostname", "security", "ignore-cert"}, connectCh)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := Connect(ctx, addr, Params{
		Protocol: "rdp", Hostname: "h", Extra: map[string]string{"security": "nla"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	got := <-connectCh
	// version, hostname=h, security=nla (from Extra), ignore-cert="" (unknown)
	if got[1] != "h" || got[2] != "nla" || got[3] != "" {
		t.Fatalf("unexpected connect args: %v", got)
	}
}
