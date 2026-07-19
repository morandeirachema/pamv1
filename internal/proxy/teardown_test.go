package proxy_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/proxy"
	"github.com/morandeirachema/pamv1/internal/store/memstore"
)

// startDelayedUpstream is like startUpstream but produces its output only AFTER a
// delay, and returns a caller-chosen exit status. The delay guarantees the
// client's stdin half-close (CHANNEL_EOF) reaches the proxy before any output is
// produced — the exact ordering that previously caused the proxy to tear the
// upstream channel down mid-command. It still accepts ONLY (wantUser, wantPass),
// so a passing test also proves the credential was injected from the vault.
func startDelayedUpstream(t *testing.T, wantUser, wantPass string, delay time.Duration, output string, exitCode uint32) (host string, port int) {
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
			go serveDelayedUpstream(conn, cfg, delay, output, exitCode)
		}
	}()

	h, p, _ := net.SplitHostPort(ln.Addr().String())
	pn, _ := strconv.Atoi(p)
	return h, pn
}

// serveDelayedUpstream answers one exec/shell request by sleeping, then writing
// the output and exit-status. It deliberately keeps reading (and discarding) the
// channel after a stdin EOF rather than exiting on it, modelling a real command
// like `sleep 1; echo done` that outlives its stdin.
func serveDelayedUpstream(conn net.Conn, cfg *ssh.ServerConfig, delay time.Duration, output string, exitCode uint32) {
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
			go io.Copy(io.Discard, ch) // absorb (and ignore) any forwarded stdin/EOF
			for req := range chReqs {
				switch req.Type {
				case "exec", "shell":
					if req.WantReply {
						req.Reply(true, nil)
					}
					time.Sleep(delay) // output is produced only after the client's EOF
					io.WriteString(ch, output)
					ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Code uint32 }{exitCode}))
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

// TestExecWithClosedStdinNotTruncated is the regression guard for the half-close
// bug: a batch command whose stdin EOFs immediately (nil Stdin, `ssh -n`, piped
// input) must still receive its full output and real exit-status through the
// proxy. Before the fix the proxy sent CHANNEL_CLOSE upstream on the stdin EOF,
// so the client got empty output and *ssh.ExitMissingError.
func TestExecWithClosedStdinNotTruncated(t *testing.T) {
	const want = "delayed-output-line\n"
	host, port := startDelayedUpstream(t, upstreamUser, upstreamSecret, 150*time.Millisecond, want, 3)
	st := memstore.New()
	v := mustVault(t)
	seedTarget(t, st, v, host, port)
	addr := startProxy(t, st, v, t.TempDir())

	client, err := dialProxy(t, addr, "web-01", proxyAPIKey)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()

	// nil Stdin makes x/crypto send CHANNEL_EOF right after the exec request —
	// the exact half-close that previously truncated the session.
	out, err := sess.Output("run")

	var ee *ssh.ExitError
	if !errors.As(err, &ee) {
		t.Fatalf("expected *ssh.ExitError (exit-status delivered), got %T: %v (output %q)", err, err, out)
	}
	if ee.ExitStatus() != 3 {
		t.Errorf("exit status = %d, want 3", ee.ExitStatus())
	}
	if string(out) != want {
		t.Errorf("output = %q, want %q (upstream torn down before it produced output?)", out, want)
	}
}

// TestObserverStreamsOutputWithClosedStdin guards the observer variant of the
// same bug: a read-only (+observe) session whose stdin EOFs immediately (the
// natural `ssh -n` watch invocation) must still stream the target's output
// rather than self-destruct the instant its stdin closes.
func TestObserverStreamsOutputWithClosedStdin(t *testing.T) {
	const want = "streamed-to-observer\n"
	host, port := startDelayedUpstream(t, upstreamUser, upstreamSecret, 100*time.Millisecond, want, 0)
	st := memstore.New()
	v := mustVault(t)
	seedTarget(t, st, v, host, port)
	addr := startProxy(t, st, v, t.TempDir())

	client, err := dialProxy(t, addr, "web-01+observe", proxyAPIKey)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()

	stdout, err := sess.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	// Observers can't exec (it's refused); a shell with nil Stdin sends an
	// immediate CHANNEL_EOF, which must not tear the watched session down.
	if err := sess.Shell(); err != nil {
		t.Fatalf("shell: %v", err)
	}

	got := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(stdout)
		got <- string(b)
	}()
	select {
	case s := <-got:
		if !strings.Contains(s, strings.TrimSpace(want)) {
			t.Errorf("observer output = %q, want it to contain %q", s, strings.TrimSpace(want))
		}
	case <-time.After(3 * time.Second):
		t.Fatal("observer received no output within 3s (session torn down on stdin EOF?)")
	}
}

// startIdleUpstream accepts sessions but never produces output or closes them —
// it models a target holding an interactive shell open and idle.
func startIdleUpstream(t *testing.T, wantUser, wantPass string) (host string, port int) {
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
					go io.Copy(io.Discard, ch)
					go func() {
						for req := range chReqs {
							if req.WantReply {
								req.Reply(true, nil) // accept shell/pty, produce nothing
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

// TestServeShutdownBoundedWithLiveSession proves the shutdown drain is bounded:
// with a live, idle session open, cancelling the context must make Serve return
// promptly (it force-closes active connections) rather than blocking until the
// operator voluntarily disconnects.
func TestServeShutdownBoundedWithLiveSession(t *testing.T) {
	host, port := startIdleUpstream(t, upstreamUser, upstreamSecret)
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
		DialTimeout:  5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- px.Serve(ctx, ln) }()

	client, err := dialProxy(t, ln.Addr().String(), "web-01", proxyAPIKey)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer client.Close()
	sess, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	if err := sess.Shell(); err != nil {
		t.Fatalf("shell: %v", err)
	}

	// A live, idle session is open. Cancelling must drain promptly, not hang.
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Serve returned %v, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return within 5s of ctx cancel — shutdown drain is not bounded")
	}
}
