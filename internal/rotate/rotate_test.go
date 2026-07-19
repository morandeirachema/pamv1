package rotate

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/morandeirachema/pamv1/internal/store"
	"github.com/morandeirachema/pamv1/internal/winrm"
	"golang.org/x/crypto/ssh"
)

// TestGeneratePassword checks generated passwords are unique across many draws,
// correctly sized, category-complete and free of shell-unsafe characters.
func TestGeneratePassword(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		pw, err := GeneratePassword(24)
		if err != nil {
			t.Fatal(err)
		}
		if len(pw) != 24 {
			t.Fatalf("len = %d, want 24", len(pw))
		}
		if seen[pw] {
			t.Fatalf("duplicate password generated: %q", pw)
		}
		seen[pw] = true
		if !strings.ContainsAny(pw, lowers) || !strings.ContainsAny(pw, uppers) ||
			!strings.ContainsAny(pw, digits) || !strings.ContainsAny(pw, symbols) {
			t.Fatalf("password %q missing a required category", pw)
		}
		// Must be shell-safe: no spaces, quotes or newlines that could break a
		// `net user` command line or stdin payload.
		if strings.ContainsAny(pw, " \t\n\r\"'`\\") {
			t.Fatalf("password %q contains an unsafe character", pw)
		}
	}
}

// TestGeneratePasswordMinLength checks a requested length below 12 is clamped up.
func TestGeneratePasswordMinLength(t *testing.T) {
	pw, err := GeneratePassword(4)
	if err != nil {
		t.Fatal(err)
	}
	if len(pw) < 12 {
		t.Fatalf("short length was not clamped up: %d", len(pw))
	}
}

// --- SSH connector against an in-process SSH server ---

// TestSSHConnectorVerifyAndRotate exercises Verify (valid and wrong secret) and
// Rotate against an in-process SSH server, asserting the exact chpasswd stdin.
func TestSSHConnectorVerifyAndRotate(t *testing.T) {
	const user, oldPass = "svc-pam", "old-Secret.1"
	srv := startSSHServer(t, user, oldPass)

	target := store.Target{Host: srv.host, Port: srv.port, Protocol: "ssh"}
	conn := SSHConnector{}

	// Verify: the current secret authenticates.
	if err := conn.Verify(context.Background(), target, user, oldPass); err != nil {
		t.Fatalf("verify with valid secret: %v", err)
	}
	// Verify: a wrong secret is reported as drift.
	if err := conn.Verify(context.Background(), target, user, "wrong"); err == nil {
		t.Fatal("verify with wrong secret should fail")
	}

	// Rotate: run chpasswd with a new password; assert the server received the
	// exact "user:newpass" payload on stdin.
	newPass, err := GeneratePassword(20)
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.Rotate(context.Background(), target, user, oldPass, newPass); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	got := srv.lastStdin()
	if want := user + ":" + newPass + "\n"; got != want {
		t.Fatalf("chpasswd stdin = %q, want %q", got, want)
	}
}

// TestSSHConnectorRejectsUnsafeUsername checks Rotate refuses a username
// containing ':' (or newlines) that could corrupt the chpasswd payload.
// TestSSHConnectorRotateKey proves ssh_key rotation: authenticate with the old
// key, install the freshly generated public key, and confirm exactly that key is
// written to authorized_keys.
func TestSSHConnectorRotateKey(t *testing.T) {
	oldPriv, err := GenerateSSHKey()
	if err != nil {
		t.Fatal(err)
	}
	oldSigner, err := ssh.ParsePrivateKey([]byte(oldPriv))
	if err != nil {
		t.Fatal(err)
	}
	srv := startSSHServerPubkey(t, "svc-pam", oldSigner.PublicKey())
	target := store.Target{Host: srv.host, Port: srv.port, Protocol: "ssh"}

	newPriv, err := GenerateSSHKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := (SSHConnector{}).RotateKey(context.Background(), target, "svc-pam", oldPriv, newPriv); err != nil {
		t.Fatalf("RotateKey: %v", err)
	}
	newSigner, err := ssh.ParsePrivateKey([]byte(newPriv))
	if err != nil {
		t.Fatal(err)
	}
	want := string(ssh.MarshalAuthorizedKey(newSigner.PublicKey()))
	if got := srv.lastStdin(); got != want {
		t.Fatalf("installed authorized_keys = %q, want %q", got, want)
	}
}

// TestSSHConnectorVerifySSHKey proves Verify authenticates an ssh_key credential
// with public-key auth (not by presenting the PEM as a password), so key
// credentials reconcile as in-sync instead of reporting false drift.
func TestSSHConnectorVerifySSHKey(t *testing.T) {
	priv, err := GenerateSSHKey()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.ParsePrivateKey([]byte(priv))
	if err != nil {
		t.Fatal(err)
	}
	srv := startSSHServerPubkey(t, "svc-pam", signer.PublicKey())
	target := store.Target{Host: srv.host, Port: srv.port, Protocol: "ssh"}
	if err := (SSHConnector{}).Verify(context.Background(), target, "svc-pam", priv); err != nil {
		t.Fatalf("Verify with ssh_key credential: %v", err)
	}
}

func TestSSHConnectorRejectsUnsafeUsername(t *testing.T) {
	conn := SSHConnector{}
	err := conn.Rotate(context.Background(), store.Target{Host: "127.0.0.1", Port: 1}, "bad:user", "old", "new")
	if err == nil || !strings.Contains(err.Error(), "unsafe username") {
		t.Fatalf("expected unsafe-username error, got %v", err)
	}
}

// --- WinRM connector via a fake runner ---

type fakeRunner struct {
	lastCmd  string
	lastUser string
	lastPass string
	exit     int
	err      error
}

// Run records the command and credentials it was called with, then returns the
// configured exit code or error.
func (f *fakeRunner) Run(_ context.Context, _ string, _ int, user, pass, cmd string) (winrm.Result, error) {
	f.lastCmd, f.lastUser, f.lastPass = cmd, user, pass
	if f.err != nil {
		return winrm.Result{}, f.err
	}
	return winrm.Result{ExitCode: f.exit}, nil
}

// TestWinRMConnectorRotate checks Rotate issues the expected `net user` command
// and authenticates with the old secret.
func TestWinRMConnectorRotate(t *testing.T) {
	fr := &fakeRunner{}
	conn := WinRMConnector{Runner: fr}
	target := store.Target{Host: "win01", Port: 5986, Protocol: "winrm"}
	if err := conn.Rotate(context.Background(), target, "Administrator", "old", "N3w-Pass_1"); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if fr.lastCmd != "net user Administrator N3w-Pass_1 /y" {
		t.Fatalf("command = %q (missing /y auto-confirm?)", fr.lastCmd)
	}
	if fr.lastPass != "old" {
		t.Fatalf("authenticated with %q, want old secret", fr.lastPass)
	}
}

// TestWinRMConnectorVerify checks a zero exit passes and a non-zero exit is
// reported as drift.
func TestWinRMConnectorVerify(t *testing.T) {
	conn := WinRMConnector{Runner: &fakeRunner{exit: 0}}
	if err := conn.Verify(context.Background(), store.Target{Protocol: "winrm"}, "u", "s"); err != nil {
		t.Fatalf("verify exit 0: %v", err)
	}
	conn = WinRMConnector{Runner: &fakeRunner{exit: 5}}
	if err := conn.Verify(context.Background(), store.Target{Protocol: "winrm"}, "u", "s"); err == nil {
		t.Fatal("verify with non-zero exit should fail")
	}
}

// --- in-process SSH test server ---

type sshServer struct {
	host string
	port int
	mu   sync.Mutex
	last string
}

// lastStdin returns the stdin the server last captured from an exec channel.
func (s *sshServer) lastStdin() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.last
}

// startSSHServer starts an in-process SSH server that accepts only
// (wantUser, wantPass) and records exec stdin for later inspection.
// startSSHServerCfg listens on an ephemeral port and serves connections with cfg.
func startSSHServerCfg(t *testing.T, cfg *ssh.ServerConfig) *sshServer {
	t.Helper()
	srv := &sshServer{}
	cfg.AddHostKey(mustSigner(t))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go srv.serve(conn, cfg)
		}
	}()
	h, p, _ := net.SplitHostPort(ln.Addr().String())
	srv.host = h
	srv.port, _ = strconv.Atoi(p)
	return srv
}

// startSSHServer starts a mock upstream accepting one password credential.
func startSSHServer(t *testing.T, wantUser, wantPass string) *sshServer {
	t.Helper()
	return startSSHServerCfg(t, &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if c.User() == wantUser && string(pass) == wantPass {
				return &ssh.Permissions{}, nil
			}
			return nil, io.EOF
		},
	})
}

// startSSHServerPubkey starts a mock upstream accepting one public key.
func startSSHServerPubkey(t *testing.T, wantUser string, wantKey ssh.PublicKey) *sshServer {
	t.Helper()
	return startSSHServerCfg(t, &ssh.ServerConfig{
		PublicKeyCallback: func(c ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if c.User() == wantUser && bytes.Equal(key.Marshal(), wantKey.Marshal()) {
				return &ssh.Permissions{}, nil
			}
			return nil, io.EOF
		},
	})
}

// serve handles one connection, capturing the stdin of exec requests and
// replying with exit-status 0.
func (s *sshServer) serve(conn net.Conn, cfg *ssh.ServerConfig) {
	sconn, chans, reqs, err := ssh.NewServerConn(conn, cfg)
	if err != nil {
		return
	}
	defer sconn.Close()
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		if nc.ChannelType() != "session" {
			nc.Reject(ssh.UnknownChannelType, "")
			continue
		}
		ch, chReqs, err := nc.Accept()
		if err != nil {
			continue
		}
		go func() {
			for req := range chReqs {
				switch req.Type {
				case "exec":
					if req.WantReply {
						req.Reply(true, nil)
					}
					data, _ := io.ReadAll(ch)
					s.mu.Lock()
					s.last = string(data)
					s.mu.Unlock()
					ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Code uint32 }{0}))
					ch.Close()
				default:
					if req.WantReply {
						req.Reply(true, nil)
					}
				}
			}
		}()
	}
}

// mustSigner returns a fresh ed25519 SSH signer or fails the test.
func mustSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}
