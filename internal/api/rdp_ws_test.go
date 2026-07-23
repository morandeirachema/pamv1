package api_test

import (
	"bufio"
	"context"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/morandeirachema/pamv1/internal/api"
	"github.com/morandeirachema/pamv1/internal/guacd"
)

// fakeInst is a minimal decoded Guacamole instruction for the test's fake guacd.
type fakeInst struct {
	op   string
	args []string
}

// readFakeInst parses one Guacamole instruction (LENGTH.VALUE elements, ',' between,
// ';' terminator). It counts bytes rather than runes, which is exact for the ASCII
// the test exchanges.
func readFakeInst(r *bufio.Reader) (fakeInst, error) {
	var elems []string
	for {
		lenStr, err := r.ReadString('.')
		if err != nil {
			return fakeInst{}, err
		}
		n, err := strconv.Atoi(strings.TrimRight(lenStr, "."))
		if err != nil {
			return fakeInst{}, err
		}
		val := make([]byte, n)
		if _, err := io.ReadFull(r, val); err != nil {
			return fakeInst{}, err
		}
		elems = append(elems, string(val))
		sep, err := r.ReadByte()
		if err != nil {
			return fakeInst{}, err
		}
		if sep == ';' {
			break
		}
	}
	return fakeInst{op: elems[0], args: elems[1:]}, nil
}

// fakeGuacd plays the guacd server side: it completes the handshake, reports the
// connect args (so the test can assert the credential was injected), pushes one
// post-ready render instruction (to prove guacd→browser piping), and reports the
// first browser instruction it receives (to prove browser→guacd piping).
func fakeGuacd(t *testing.T, connectCh chan<- []string, inputCh chan<- string) string {
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
		if _, err := readFakeInst(r); err != nil { // select
			return
		}
		conn.Write([]byte(guacd.Instruction{Opcode: "args", Args: []string{"VERSION_1_5_0", "hostname", "port", "username", "password"}}.Encode()))
		for {
			inst, err := readFakeInst(r)
			if err != nil {
				return
			}
			if inst.op == "connect" {
				connectCh <- inst.args
				break
			}
		}
		conn.Write([]byte(guacd.Instruction{Opcode: "ready", Args: []string{"$test-conn"}}.Encode()))
		conn.Write([]byte(guacd.Instruction{Opcode: "sync", Args: []string{"0"}}.Encode())) // post-ready render stream
		// A single instruction far larger than the old 8 KB copy buffer — a stand-in
		// for a real screen paint. The bridge must deliver it as ONE WebSocket message;
		// the old raw-chunk copy split it and broke the browser tunnel.
		conn.Write([]byte(guacd.Instruction{Opcode: "blob", Args: []string{"0", strings.Repeat("A", bigBlobLen)}}.Encode()))
		if inst, err := readFakeInst(r); err == nil {
			inputCh <- inst.op
		}
		io.Copy(io.Discard, r) // keep the session open until the browser closes it
	}()
	return ln.Addr().String()
}

// bigBlobLen is the payload size of the fake guacd's large post-ready instruction,
// chosen well above the 8192-byte read chunking that used to split instructions.
const bigBlobLen = 20000

// TestRDPTunnelEndToEnd drives the whole browser-facing path against a fake guacd:
// it mints a short-lived token, opens the WebSocket, and proves (1) the tunnel
// prelude the JS client needs is emitted first, (2) the vaulted secret is injected
// into guacd's handshake (never sent by the browser), and (3) both piping
// directions work.
func TestRDPTunnelEndToEnd(t *testing.T) {
	connectCh := make(chan []string, 1)
	inputCh := make(chan string, 1)
	guacdAddr := fakeGuacd(t, connectCh, inputCh)

	srv, _ := newTestServerOpts(t, nil, api.Options{GuacdAddr: guacdAddr})

	// Seed an RDP target and its credential with a known secret.
	_, data := do(t, srv, "POST", "/api/targets", testAPIKey, map[string]any{
		"name": "win-rdp", "host": "10.0.0.9", "port": 3389, "os_type": "windows", "protocol": "rdp",
	})
	id := int64(jsonMap(t, data)["id"].(float64))
	const secret = "Rdp-S3cret!"
	do(t, srv, "POST", "/api/credentials", testAPIKey, map[string]any{
		"target_id": id, "username": "Administrator", "secret": secret,
	})

	// Mint the short-lived WS token instead of putting the API key in the URL.
	status, data := do(t, srv, "POST", "/api/rdp-token", testAPIKey, nil)
	if status != 200 {
		t.Fatalf("rdp-token status %d: %s", status, data)
	}
	tok, _ := jsonMap(t, data)["token"].(string)
	if tok == "" {
		t.Fatalf("no rdp token returned: %s", data)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/api/targets/" + itoa(id) + "/rdp?token=" + tok + "&width=800&height=600"
	c, _, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{Subprotocols: []string{"guacamole"}})
	if err != nil {
		t.Fatalf("ws dial: %v", err)
	}
	defer c.Close(websocket.StatusNormalClosure, "")

	readFrame := func() string {
		_, b, err := c.Read(ctx)
		if err != nil {
			t.Fatalf("ws read: %v", err)
		}
		return string(b)
	}

	// (1) The prelude: an internal tunnel-UUID instruction, then the re-emitted ready.
	if first := readFrame(); !strings.HasPrefix(first, "0.,") {
		t.Fatalf("first frame = %q, want an internal tunnel-UUID instruction (0.,…)", first)
	}
	if second := readFrame(); !strings.HasPrefix(second, "5.ready,") || !strings.Contains(second, "$test-conn") {
		t.Fatalf("second frame = %q, want ready with the guacd connection id", second)
	}
	// (3a) guacd→browser: the post-ready render instruction is piped through.
	if third := readFrame(); !strings.Contains(third, "sync") {
		t.Fatalf("third frame = %q, want the piped guacd render stream (sync)", third)
	}
	// (3a') Instruction framing: a >8 KB instruction must arrive as ONE whole
	// WebSocket message (the vendored client rejects a message ending mid-instruction).
	wantBlob := guacd.Instruction{Opcode: "blob", Args: []string{"0", strings.Repeat("A", bigBlobLen)}}.Encode()
	if fourth := readFrame(); fourth != wantBlob {
		if len(fourth) < len(wantBlob) {
			t.Fatalf("large instruction split across WebSocket messages: got a %d-byte frame, want the whole %d-byte instruction", len(fourth), len(wantBlob))
		}
		t.Fatalf("fourth frame did not match the large instruction (len got=%d want=%d)", len(fourth), len(wantBlob))
	}

	// (2) JIT injection: the vaulted secret reached guacd, positioned as the password.
	select {
	case args := <-connectCh:
		// args order mirrors the advertised args: VERSION, hostname, port, username, password.
		if len(args) != 5 || args[3] != "Administrator" || args[4] != secret {
			t.Fatalf("connect args = %v, want the injected credential at [3],[4]", args)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("guacd never received the connect (credential injection failed)")
	}

	// (3b) browser→guacd: an instruction sent by the client reaches guacd.
	if err := c.Write(ctx, websocket.MessageText, []byte(guacd.Instruction{Opcode: "key", Args: []string{"65", "1"}}.Encode())); err != nil {
		t.Fatalf("ws write: %v", err)
	}
	select {
	case op := <-inputCh:
		if op != "key" {
			t.Fatalf("guacd received %q, want the browser's key instruction", op)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("guacd never received the browser instruction (browser→guacd piping failed)")
	}
}

// TestRDPTokenRequiresConnect verifies the short-lived-token endpoint enforces
// CapConnect and is gated on guacd being configured.
func TestRDPTokenRequiresConnect(t *testing.T) {
	// Without guacd configured, the endpoint is 404 even for an admin.
	noGuacd := newTestServer(t)
	if status, _ := do(t, noGuacd, "POST", "/api/rdp-token", testAPIKey, nil); status != 404 {
		t.Fatalf("rdp-token without guacd should be 404, got %d", status)
	}

	srv, _ := newTestServerOpts(t, nil, api.Options{GuacdAddr: "127.0.0.1:4822"})
	auditorTok := seedUser(t, srv, "theo", "auditor") // no CapConnect
	if status, _ := do(t, srv, "POST", "/api/rdp-token", auditorTok, nil); status != 403 {
		t.Fatalf("auditor minting an RDP token should be 403, got %d", status)
	}
	if status, data := do(t, srv, "POST", "/api/rdp-token", testAPIKey, nil); status != 200 {
		t.Fatalf("admin minting an RDP token should be 200, got %d: %s", status, data)
	}
}

// TestRDPTokenIsTunnelScoped proves a minted RDP token — which travels in the WS
// URL and can leak via logs — is usable only at the tunnel: the API middleware
// refuses it, so it cannot read inventory, act, or re-mint itself.
func TestRDPTokenIsTunnelScoped(t *testing.T) {
	srv, _ := newTestServerOpts(t, nil, api.Options{GuacdAddr: "127.0.0.1:4822"})
	_, data := do(t, srv, "POST", "/api/rdp-token", testAPIKey, nil)
	tok, _ := jsonMap(t, data)["token"].(string)
	if tok == "" {
		t.Fatalf("no rdp token: %s", data)
	}
	// The token is refused on a normal authz endpoint (would be 200 for the admin key)...
	if status, _ := do(t, srv, "GET", "/api/targets", tok, nil); status != 403 {
		t.Fatalf("RDP token on GET /api/targets should be 403 (tunnel-only), got %d", status)
	}
	// ...on an `authenticated` endpoint...
	if status, _ := do(t, srv, "GET", "/api/me", tok, nil); status != 403 {
		t.Fatalf("RDP token on GET /api/me should be 403 (tunnel-only), got %d", status)
	}
	// ...and it cannot re-mint a fresh token to escape the TTL.
	if status, _ := do(t, srv, "POST", "/api/rdp-token", tok, nil); status != 403 {
		t.Fatalf("RDP token re-minting should be 403 (tunnel-only), got %d", status)
	}
}
