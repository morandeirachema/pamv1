package proxy_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/proxy"
	"github.com/morandeirachema/pamv1/internal/store"
	"github.com/morandeirachema/pamv1/internal/store/memstore"
)

// TestCredentialDecryptedOnlyAfterAuthz proves the JIT secret is decrypted only
// after every authorization gate passes: a session denied by policy must not
// materialize plaintext. The credential is deliberately undecryptable, so any
// decryption attempt is observable as a failure in the audit trail.
func TestCredentialDecryptedOnlyAfterAuthz(t *testing.T) {
	ctx := context.Background()
	st := memstore.New()
	v := mustVault(t)
	target := &store.Target{Name: "web-01", Host: "127.0.0.1", Port: 65000, OSType: "linux", Protocol: "ssh"}
	if err := st.CreateTarget(ctx, target); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateCredential(ctx, &store.Credential{
		TargetID: target.ID, Username: upstreamUser, SecretType: "password",
		SecretEnc: "v1:not-a-real-token",
	}); err != nil {
		t.Fatal(err)
	}

	resolver, err := auth.NewResolver(st, proxyAPIKey, "")
	if err != nil {
		t.Fatal(err)
	}
	// The protocol allowlist forbids ssh, so the connect is denied by the protocol
	// gate — which runs before decryption.
	px, err := proxy.New(st, v, resolver, proxy.Config{
		HostKey:          mustSigner(t),
		RecordingDir:     t.TempDir(),
		AllowedProtocols: []string{"winrm"},
	})
	if err != nil {
		t.Fatal(err)
	}
	addr := serveProxy(t, px)

	client, err := dialProxy(t, addr, "web-01", proxyAPIKey)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	if sess, e := client.NewSession(); e == nil {
		sess.Close()
		t.Fatal("session opened for a policy-forbidden protocol")
	}
	client.Close()

	events, err := st.ListAudit(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	var gateDenied, decryptAttempted bool
	for _, e := range events {
		if strings.Contains(e.Detail, "protocol-not-allowed") {
			gateDenied = true
		}
		if e.Action == "credential.decrypt_failed" || strings.Contains(e.Detail, "decryption failed") {
			decryptAttempted = true
		}
	}
	if !gateDenied {
		t.Error("expected the protocol gate to deny the session")
	}
	if decryptAttempted {
		t.Error("credential was decrypted for a policy-denied session — decryption must run only after authz")
	}
}

// startStderrUpstream is an in-process SSH target that, on exec/shell, writes a
// marker to the channel's STDERR (not stdout) and exits 0. It accepts only
// (wantUser, wantPass).
func startStderrUpstream(t *testing.T, wantUser, wantPass, stderrMark string) (host string, port int) {
	t.Helper()
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if c.User() == wantUser && string(pass) == wantPass {
				return &ssh.Permissions{}, nil
			}
			return nil, fmt.Errorf("upstream: auth denied")
		},
	}
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
			go func() {
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
							case "exec", "shell":
								if req.WantReply {
									req.Reply(true, nil)
								}
								io.WriteString(ch.Stderr(), stderrMark)
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
			}()
		}
	}()
	h, p, _ := net.SplitHostPort(ln.Addr().String())
	pn, _ := strconv.Atoi(p)
	return h, pn
}

// readCast returns the contents of the first .cast file found under dir, polling
// briefly because the recording is flushed when the session tears down.
func readCast(t *testing.T, dir string) string {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		entries, _ := os.ReadDir(dir)
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".cast") {
				b, err := os.ReadFile(filepath.Join(dir, e.Name()))
				if err == nil && len(b) > 0 {
					return string(b)
				}
			}
		}
		if time.Now().After(deadline) {
			return ""
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestStderrIsRecorded proves the target's stderr is captured in the asciicast
// recording (and thus its audited hash), not only stdout.
func TestStderrIsRecorded(t *testing.T) {
	const mark = "STDERR-SENTINEL-42"
	host, port := startStderrUpstream(t, upstreamUser, upstreamSecret, mark)
	st := memstore.New()
	v := mustVault(t)
	seedTarget(t, st, v, host, port)
	recDir := t.TempDir()
	addr := startProxy(t, st, v, recDir)

	client, err := dialProxy(t, addr, "web-01", proxyAPIKey)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	sess, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	_, _ = sess.Output("run") // upstream writes only to stderr
	sess.Close()
	client.Close()

	if cast := readCast(t, recDir); !strings.Contains(cast, mark) {
		t.Errorf("stderr marker %q not found in recording; stderr is not being recorded", mark)
	}
}

// TestRecordingFailureIsAudited proves that when a session cannot be recorded
// (unwritable recording dir) the downgrade is audited rather than silent, and by
// default the session still proceeds.
func TestRecordingFailureIsAudited(t *testing.T) {
	host, port := startUpstream(t, upstreamUser, upstreamSecret, targetOutput)
	st := memstore.New()
	v := mustVault(t)
	seedTarget(t, st, v, host, port)
	// A recording dir that cannot be created: it sits under a regular file.
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	badDir := filepath.Join(blocker, "recordings")
	addr := startProxy(t, st, v, badDir)

	client, err := dialProxy(t, addr, "web-01", proxyAPIKey)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	sess, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	out, _ := sess.Output("run")
	sess.Close()
	client.Close()

	if string(out) != targetOutput {
		t.Errorf("session should still run unrecorded by default, got %q", out)
	}
	if !auditHas(t, st, "session.record_failed") {
		t.Error("recording failure was not audited")
	}
}

// TestRequireRecordingRefusesWhenRecordingFails proves the fail-closed option:
// with RequireRecording set, an unrecordable session is refused.
func TestRequireRecordingRefusesWhenRecordingFails(t *testing.T) {
	host, port := startUpstream(t, upstreamUser, upstreamSecret, targetOutput)
	st := memstore.New()
	v := mustVault(t)
	seedTarget(t, st, v, host, port)
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	resolver, err := auth.NewResolver(st, proxyAPIKey, "")
	if err != nil {
		t.Fatal(err)
	}
	px, err := proxy.New(st, v, resolver, proxy.Config{
		HostKey:          mustSigner(t),
		RecordingDir:     filepath.Join(blocker, "recordings"),
		RequireRecording: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	addr := serveProxy(t, px)

	client, err := dialProxy(t, addr, "web-01", proxyAPIKey)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	sess, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	out, _ := sess.Output("run")
	sess.Close()
	client.Close()

	if string(out) != "" {
		t.Errorf("session should be refused when recording is required but failed, got %q", out)
	}
	if !auditHas(t, st, "session.record_failed") {
		t.Error("recording failure was not audited")
	}
}

// auditHas reports whether the store holds an audit event with the given action.
func auditHas(t *testing.T, st store.Store, action string) bool {
	t.Helper()
	events, err := st.ListAudit(context.Background(), 200)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range events {
		if e.Action == action {
			return true
		}
	}
	return false
}

// flakyListener returns a configurable number of temporary Accept errors before
// delegating to the real listener, modelling transient fd exhaustion.
type flakyListener struct {
	net.Listener
	remainingTempErrs int
}

func (l *flakyListener) Accept() (net.Conn, error) {
	if l.remainingTempErrs > 0 {
		l.remainingTempErrs--
		return nil, flakyTempErr{}
	}
	return l.Listener.Accept()
}

type flakyTempErr struct{}

func (flakyTempErr) Error() string   { return "temporary accept failure" }
func (flakyTempErr) Timeout() bool   { return false }
func (flakyTempErr) Temporary() bool { return true }

// TestServeRetriesTemporaryAcceptErrors proves Serve backs off and keeps serving
// on a transient Accept error instead of tearing the listener down.
func TestServeRetriesTemporaryAcceptErrors(t *testing.T) {
	host, port := startUpstream(t, upstreamUser, upstreamSecret, targetOutput)
	st := memstore.New()
	v := mustVault(t)
	seedTarget(t, st, v, host, port)
	resolver, err := auth.NewResolver(st, proxyAPIKey, "")
	if err != nil {
		t.Fatal(err)
	}
	px, err := proxy.New(st, v, resolver, proxy.Config{
		HostKey:      mustSigner(t),
		RecordingDir: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	fl := &flakyListener{Listener: base, remainingTempErrs: 3}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- px.Serve(ctx, fl) }()

	client, err := dialProxy(t, base.Addr().String(), "web-01", proxyAPIKey)
	if err != nil {
		cancel()
		t.Fatalf("proxy should survive transient accept errors: %v", err)
	}
	sess, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	out, _ := sess.Output("run")
	if string(out) != targetOutput {
		t.Errorf("output = %q, want %q", out, targetOutput)
	}
	sess.Close()
	client.Close()

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Serve returned %v, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return after cancel")
	}
}
