// Package proxy is the pamv1 SSH session gateway. Operators connect to it
// instead of to targets directly; the proxy authenticates them, pulls the
// right credential from the vault and injects it just-in-time (JIT) into the
// upstream SSH connection — the operator never sees the secret. Every session
// is recorded and audited.
//
// Login convention (Phase 2, before the AD connector):
//
//	ssh -p 2222 <target-name>@pam-host                 # first credential of the target
//	ssh -p 2222 <cred-user>@<target-name>@pam-host     # a specific credential
//
// The SSH password presented to the proxy is the PAM API key; AD-backed user
// auth replaces this in Phase 3.
package proxy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/logging"
	"github.com/morandeirachema/pamv1/internal/session"
	"github.com/morandeirachema/pamv1/internal/store"
	"github.com/morandeirachema/pamv1/internal/vault"
	"github.com/morandeirachema/pamv1/internal/winrm"
)

type Config struct {
	Addr         string     // listen address, e.g. ":2222"
	HostKey      ssh.Signer // proxy SSH host key
	RecordingDir string     // where session recordings are written
	DialTimeout  time.Duration
	Sessions     *session.Registry // live-session registry (optional)
	// RequireApproval gates every session behind an approved access request
	// (global OT policy); per-target Target.RequireApproval also applies.
	RequireApproval bool
	// UpstreamHostKey verifies the target's SSH host key (e.g. a known_hosts
	// callback). nil trusts any upstream key — insecure, and logged loudly.
	UpstreamHostKey ssh.HostKeyCallback
	// OnSessionEnd, if set, is called with the credential ID when a proxied
	// session ends — used to force credential rotation after use. It runs in a
	// goroutine and must not block.
	OnSessionEnd func(credentialID int64)
	// AllowedProtocols, when non-empty, restricts which target protocols the proxy
	// will broker (the proxy only handles "ssh"; this lets an OT policy forbid it).
	AllowedProtocols []string
	// WinRMRunner, if set, lets the proxy broker an interactive command loop to
	// WinRM (Windows) targets; nil disables WinRM through the proxy.
	WinRMRunner winrm.Runner
	// Jump, if set, reaches SSH targets through an SSH bastion (for legacy
	// equipment only accessible via a jump host).
	Jump *JumpConfig
	// RequireRecording refuses a session when its recording cannot be created,
	// rather than proceeding unrecorded (fail-closed session auditing).
	RequireRecording bool
}

// JumpConfig configures reaching SSH targets through an SSH bastion.
type JumpConfig struct {
	Addr    string              // bastion host:port
	User    string              // bastion login
	KeyPEM  string              // bastion private key (OpenSSH PEM)
	HostKey ssh.HostKeyCallback // verifies the bastion's host key (nil = trust-any)
}

type Proxy struct {
	store        store.Store
	vault        *vault.Vault
	resolver     *auth.Resolver
	log          *slog.Logger
	sshCfg       *ssh.ServerConfig
	hostKey      ssh.Signer
	recordingDir string
	dialTimeout  time.Duration
	sessions     *session.Registry
	requireApprv bool
	upstreamHKCB ssh.HostKeyCallback
	onSessionEnd func(credentialID int64)
	allowedProto map[string]bool
	winrm        winrm.Runner
	upstreamDial func(addr string) (net.Conn, error)
	chain        *recordChain
	requireRec   bool

	bg sync.WaitGroup // background tasks (post-session rotation) to drain on shutdown

	mu      sync.Mutex
	ln      net.Listener
	conns   map[net.Conn]struct{} // accepted client connections, for shutdown force-close
	closing bool                  // set once shutdown has begun force-closing connections
}

// New constructs a Proxy from the store, vault, auth resolver and cfg. It
// requires a HostKey and resolver, defaults RecordingDir and DialTimeout when
// unset, and warns loudly (falling back to InsecureIgnoreHostKey) when no
// upstream host-key callback is supplied.
func New(st store.Store, v *vault.Vault, resolver *auth.Resolver, cfg Config) (*Proxy, error) {
	if cfg.HostKey == nil {
		return nil, errors.New("proxy: HostKey is required")
	}
	if resolver == nil {
		return nil, errors.New("proxy: resolver is required")
	}
	if cfg.RecordingDir == "" {
		cfg.RecordingDir = "recordings"
	}
	if cfg.DialTimeout == 0 {
		cfg.DialTimeout = 10 * time.Second
	}
	p := &Proxy{
		store:        st,
		vault:        v,
		resolver:     resolver,
		log:          logging.Component("proxy"),
		hostKey:      cfg.HostKey,
		recordingDir: cfg.RecordingDir,
		dialTimeout:  cfg.DialTimeout,
		sessions:     cfg.Sessions,
		requireApprv: cfg.RequireApproval,
		upstreamHKCB: cfg.UpstreamHostKey,
		onSessionEnd: cfg.OnSessionEnd,
		allowedProto: protocolSet(cfg.AllowedProtocols),
		winrm:        cfg.WinRMRunner,
		chain:        newRecordChain(cfg.RecordingDir),
		requireRec:   cfg.RequireRecording,
		conns:        make(map[net.Conn]struct{}),
	}
	if p.upstreamHKCB == nil {
		p.log.Warn("upstream SSH host keys are NOT verified (set PAM_SSH_KNOWN_HOSTS to pin them)")
		p.upstreamHKCB = ssh.InsecureIgnoreHostKey()
	}
	if cfg.Jump != nil {
		dial, err := jumpDial(*cfg.Jump, cfg.DialTimeout)
		if err != nil {
			return nil, fmt.Errorf("proxy: jump host: %w", err)
		}
		p.upstreamDial = dial
		p.log.Info("SSH targets routed through a jump host", "jump", cfg.Jump.Addr)
	}
	p.sshCfg = &ssh.ServerConfig{PasswordCallback: p.authenticate}
	p.sshCfg.AddHostKey(cfg.HostKey)
	return p, nil
}

// authenticate resolves the SSH password (a PAM key or per-user token) into a
// Principal and stashes it with the requested target/credential in the
// connection permissions; the role check and target resolution happen after
// the handshake.
func (p *Proxy) authenticate(c ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
	principal, err := p.resolver.Resolve(context.Background(), string(password))
	if err != nil {
		p.log.Warn("authentication failed", "login", c.User(), "remote", c.RemoteAddr().String())
		return nil, fmt.Errorf("pamv1: authentication failed")
	}
	// A "+observe" suffix requests a read-only (view-only) session: the operator
	// sees output but their keystrokes and exec requests are dropped.
	login := c.User()
	observe := false
	if rest, ok := strings.CutSuffix(login, "+observe"); ok {
		observe, login = true, rest
	}
	credUser, targetName := splitLogin(login)
	ext := map[string]string{
		"login":     c.User(),
		"principal": principal.Name,
		"role":      string(principal.Role),
		"target":    targetName,
		"cred_user": credUser,
	}
	if observe {
		ext["observe"] = "true"
	}
	if principal.EnrollOnly {
		ext["enroll_only"] = "true"
	}
	if principal.BreakGlass {
		ext["break_glass"] = "true"
	}
	return &ssh.Permissions{Extensions: ext}, nil
}

// splitLogin parses "creduser@target" (rightmost @ separates the target) or
// bare "target". Target names never contain '@'.
func splitLogin(login string) (credUser, target string) {
	if i := strings.LastIndex(login, "@"); i >= 0 {
		return login[:i], login[i+1:]
	}
	return "", login
}

// ListenAndServe binds Config.Addr and serves until ctx is cancelled.
func (p *Proxy) ListenAndServe(ctx context.Context, addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return p.Serve(ctx, ln)
}

// Serve accepts connections on ln until ctx is cancelled. On cancellation it
// closes the listener and force-closes every active client connection, then
// waits for the in-flight handlers to return — so the drain is bounded (it does
// not wait for operators to voluntarily disconnect) and no handler goroutine
// outlives Serve. A fatal Accept error (not caused by cancellation) is returned
// promptly without waiting on active handlers. Exposed separately so tests can
// supply a 127.0.0.1:0 listener and read the address back.
func (p *Proxy) Serve(ctx context.Context, ln net.Listener) error {
	p.mu.Lock()
	p.ln = ln
	p.closing = false // reset in case this Proxy is served again
	p.mu.Unlock()

	go func() {
		<-ctx.Done()
		ln.Close()
		p.closeActiveConns() // unblock in-flight handlers so the drain is bounded
	}()

	p.log.Info("ssh proxy listening",
		"addr", ln.Addr().String(),
		"hostkey_fp", ssh.FingerprintSHA256(p.hostKey.PublicKey()))
	var wg sync.WaitGroup
	var tempDelay time.Duration
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				wg.Wait() // graceful shutdown: active conns already force-closed
				p.bg.Wait()
				return nil
			}
			// Retry a transient accept error (e.g. fd exhaustion, EMFILE) with
			// capped exponential backoff instead of tearing the listener down —
			// the same policy net/http's Server uses.
			if ne, ok := err.(net.Error); ok && ne.Temporary() { //nolint:staticcheck // Temporary() is the only portable transient-accept signal
				if tempDelay == 0 {
					tempDelay = 5 * time.Millisecond
				} else {
					tempDelay *= 2
				}
				if tempDelay > time.Second {
					tempDelay = time.Second
				}
				p.log.Warn("ssh proxy accept error; retrying", "err", err, "retry_in", tempDelay)
				select {
				case <-time.After(tempDelay):
				case <-ctx.Done():
					wg.Wait()
					p.bg.Wait()
					return nil
				}
				continue
			}
			return err // fatal listener error: report it without blocking on sessions
		}
		tempDelay = 0
		p.trackConn(conn)
		wg.Add(1)
		go func(c net.Conn) {
			defer wg.Done()
			defer p.untrackConn(c)
			p.handleConn(ctx, c)
		}(conn)
	}
}

// trackConn records an accepted client connection so shutdown can force-close it.
func (p *Proxy) trackConn(c net.Conn) {
	p.mu.Lock()
	if p.closing {
		// Shutdown already force-closed the tracked set; close this straggler too
		// so it cannot slip past the drain and block Serve's wg.Wait.
		p.mu.Unlock()
		c.Close()
		return
	}
	p.conns[c] = struct{}{}
	p.mu.Unlock()
}

// untrackConn drops a client connection once its handler has returned.
func (p *Proxy) untrackConn(c net.Conn) {
	p.mu.Lock()
	delete(p.conns, c)
	p.mu.Unlock()
}

// fireSessionEnd runs the post-session credential-rotation callback (if any) as
// a tracked background task, so a graceful shutdown drains in-flight rotations
// instead of killing the process mid-rotation (which could leave a target's
// password changed but the vault stale). It must not block the caller.
func (p *Proxy) fireSessionEnd(credID int64) {
	if p.onSessionEnd == nil {
		return
	}
	p.bg.Add(1)
	go func() {
		defer p.bg.Done()
		p.onSessionEnd(credID)
	}()
}

// closeActiveConns force-closes every tracked client connection. Closing the
// client transport tears down its SSH mux, which ends the handler's channel loop
// and unblocks the session copies — bounding Serve's shutdown drain.
func (p *Proxy) closeActiveConns() {
	p.mu.Lock()
	p.closing = true // any connection tracked after this point closes itself
	conns := make([]net.Conn, 0, len(p.conns))
	for c := range p.conns {
		conns = append(conns, c)
	}
	p.mu.Unlock()
	for _, c := range conns {
		c.Close()
	}
}

// Addr returns the bound address (useful once Serve is running).
func (p *Proxy) Addr() net.Addr {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.ln.Addr()
}

// handleConn completes the SSH handshake and runs every authorization gate in
// order (enrollment, role CapConnect, target/credential resolution, per-target
// grants and the approval gate) before dialing the upstream with the
// JIT-decrypted secret and proxying its session channels. Each denial and the
// session lifecycle are audited.
func (p *Proxy) handleConn(ctx context.Context, nConn net.Conn) {
	sconn, chans, reqs, err := ssh.NewServerConn(nConn, p.sshCfg)
	if err != nil {
		return // handshake/auth failure; nothing authenticated to audit
	}
	defer sconn.Close()
	go ssh.DiscardRequests(reqs)

	ext := sconn.Permissions.Extensions
	actor := ext["principal"]
	login := ext["login"]
	role := auth.Role(ext["role"])
	remote := sconn.RemoteAddr().String()
	p.log.Info("connection authenticated", "actor", actor, "role", string(role),
		"login", login, "remote", remote)

	// An enrollment-only session (MFA setup pending) may not open sessions.
	if ext["enroll_only"] == "true" {
		p.log.Warn("session denied: mfa enrollment incomplete", "actor", actor, "remote", remote)
		p.audit(ctx, actor, "session.denied", "login:"+login+" reason:mfa-enrollment-incomplete")
		rejectAll(chans, ssh.Prohibited, "pamv1: complete MFA enrollment first")
		return
	}

	// auditor (and any role without CapConnect) may authenticate but not open
	// sessions through the proxy.
	if !role.Can(auth.CapConnect) {
		p.log.Warn("session denied by role", "actor", actor, "role", string(role), "remote", remote)
		p.audit(ctx, actor, "session.denied",
			fmt.Sprintf("login:%s role:%s reason:role may not connect", login, role))
		rejectAll(chans, ssh.Prohibited, "pamv1: your role may not open sessions")
		return
	}

	target, cred, err := p.resolveTarget(ctx, ext["target"], ext["cred_user"])
	if err != nil {
		p.log.Warn("session denied", "actor", actor, "login", login, "reason", err.Error(), "remote", remote)
		p.audit(ctx, actor, "session.denied", fmt.Sprintf("login:%s reason:%v", login, err))
		rejectAll(chans, ssh.Prohibited, "pamv1: "+err.Error())
		return
	}

	// Protocol allowlist (OT policy): refuse forbidden protocols.
	if p.allowedProto != nil && !p.allowedProto[target.Protocol] {
		p.log.Warn("session denied: protocol not allowed", "actor", actor, "target", target.Name, "protocol", target.Protocol)
		p.audit(ctx, actor, "access.denied", "target:"+target.Name+" reason:protocol-not-allowed")
		rejectAll(chans, ssh.Prohibited, "pamv1: this protocol is not allowed by policy")
		return
	}

	// Per-target authorization: honor the target's access grants.
	grants, err := p.store.ListTargetGrants(ctx, target.ID)
	if err != nil {
		p.log.Error("target grants lookup failed", "target", target.Name, "err", err)
		rejectAll(chans, ssh.Prohibited, "pamv1: authorization check failed")
		return
	}
	if !auth.CanConnectTarget(&auth.Principal{Name: actor, Role: role}, grants) {
		p.log.Warn("session denied: target policy", "actor", actor, "target", target.Name, "remote", remote)
		p.audit(ctx, actor, "session.denied", "target:"+target.Name+" reason:target-policy")
		rejectAll(chans, ssh.Prohibited, "pamv1: not authorized for this target")
		return
	}

	// Approval gate (4-eyes / OT maintenance window). Break-glass bypasses.
	if (p.requireApprv || target.RequireApproval) && ext["break_glass"] != "true" {
		approved, aerr := p.store.HasActiveApproval(ctx, actor, target.ID, time.Now())
		if aerr != nil {
			p.log.Error("approval check failed", "target", target.Name, "err", aerr)
			rejectAll(chans, ssh.Prohibited, "pamv1: approval check failed")
			return
		}
		if !approved {
			p.log.Warn("session denied: approval required", "actor", actor, "target", target.Name, "remote", remote)
			p.audit(ctx, actor, "access.denied", "target:"+target.Name+" reason:approval-required")
			rejectAll(chans, ssh.Prohibited, "pamv1: connection requires an approved access request")
			return
		}
	}

	// Refuse protocols this gateway cannot broker (ssh always; winrm only with a
	// runner configured) before decrypting, so plaintext never materializes for a
	// session that is about to be denied. serveWinRM re-checks defensively.
	if target.Protocol != "ssh" && !(target.Protocol == "winrm" && p.winrm != nil) {
		p.log.Warn("session denied: protocol not proxyable", "actor", actor, "target", target.Name, "protocol", target.Protocol)
		p.audit(ctx, actor, "session.denied", "target:"+target.Name+" reason:protocol-not-proxyable")
		rejectAll(chans, ssh.Prohibited, "pamv1: this target's protocol is not available through the proxy")
		return
	}

	// Every authorization gate has passed — decrypt the secret just-in-time.
	// Plaintext exists only from here on, never for a session that was denied.
	secret, err := p.decryptSecret(ctx, target, cred)
	if err != nil {
		p.log.Error("credential decryption failed", "actor", actor, "target", target.Name, "err", err)
		p.audit(ctx, actor, "credential.decrypt_failed",
			fmt.Sprintf("target:%s cred_user:%s op:connect", target.Name, cred.Username))
		rejectAll(chans, ssh.ConnectionFailed, "pamv1: credential unavailable")
		return
	}

	observeMode := ext["observe"] == "true"

	// Non-SSH targets are brokered differently: WinRM targets get an interactive
	// command loop (if a runner is configured); anything else is refused.
	if target.Protocol != "ssh" {
		p.serveWinRM(ctx, sconn, chans, target, cred, secret, actor, remote, observeMode)
		return
	}

	upstream, err := p.dialUpstream(target, cred, secret)
	if err != nil {
		p.log.Error("upstream connection failed", "actor", actor, "target", target.Name,
			"host", fmt.Sprintf("%s:%d", target.Host, target.Port), "err", err)
		p.audit(ctx, actor, "session.error",
			fmt.Sprintf("target:%s host:%s:%d error:%v", target.Name, target.Host, target.Port, err))
		rejectAll(chans, ssh.ConnectionFailed, "pamv1: upstream connection failed")
		return
	}
	defer upstream.Close()

	observe := ext["observe"] == "true"
	mode := "interactive"
	if observe {
		mode = "observer"
	}
	p.log.Info("session started", "actor", actor, "target", target.Name,
		"host", fmt.Sprintf("%s:%d", target.Host, target.Port), "cred_user", cred.Username, "mode", mode)
	p.audit(ctx, actor, "session.start",
		fmt.Sprintf("target:%s host:%s:%d cred_user:%s mode:%s", target.Name, target.Host, target.Port, cred.Username, mode))
	if p.sessions != nil {
		sid := p.sessions.Register(session.Info{
			Actor: actor, Target: target.Name, Protocol: "ssh", Remote: remote, Started: time.Now(),
		}, func() { sconn.Close() })
		defer p.sessions.Remove(sid)
	}
	defer func() {
		p.log.Info("session ended", "actor", actor, "target", target.Name)
		p.auditClosing(ctx, actor, "session.end", "target:"+target.Name)
		// Force post-session credential rotation, if configured, so a secret
		// used in one session cannot be reused in the next.
		p.fireSessionEnd(cred.ID)
	}()

	var wg sync.WaitGroup
	for nc := range chans {
		if nc.ChannelType() != "session" {
			nc.Reject(ssh.UnknownChannelType, "pamv1: only session channels are proxied")
			continue
		}
		wg.Add(1)
		go func(nc ssh.NewChannel) {
			defer wg.Done()
			p.handleSession(ctx, nc, upstream, target, cred, actor, observe)
		}(nc)
	}
	// The chans range ends when the client connection closes — the true
	// "client is gone" signal. Close the upstream now (before waiting) so any
	// session still blocked copying idle or wedged upstream output unblocks;
	// otherwise the deferred upstream.Close() below would sit behind this Wait.
	upstream.Close()
	wg.Wait()
}

// resolveTarget looks up the target and the credential to inject WITHOUT
// decrypting the secret, so every authorization gate can run before any
// plaintext exists. The just-in-time decryption is a separate step
// (decryptSecret) taken only once the session is authorized.
func (p *Proxy) resolveTarget(ctx context.Context, targetName, credUser string) (*store.Target, *store.Credential, error) {
	if targetName == "" {
		return nil, nil, errors.New("no target specified")
	}
	targets, err := p.store.ListTargets(ctx)
	if err != nil {
		return nil, nil, errors.New("target lookup failed")
	}
	var target *store.Target
	for i := range targets {
		if targets[i].Name == targetName {
			target = &targets[i]
			break
		}
	}
	if target == nil {
		return nil, nil, fmt.Errorf("unknown target %q", targetName)
	}
	creds, err := p.store.ListCredentials(ctx, target.ID)
	if err != nil {
		return nil, nil, errors.New("credential lookup failed")
	}
	var cred *store.Credential
	for i := range creds {
		if credUser == "" || creds[i].Username == credUser {
			cred = &creds[i]
			break
		}
	}
	if cred == nil {
		return nil, nil, fmt.Errorf("no matching credential for target %q", targetName)
	}
	return target, cred, nil
}

// decryptSecret performs the just-in-time decryption of a credential's secret.
// It must be called only after every authorization gate has passed — plaintext
// must never be materialized for a session that will be denied.
func (p *Proxy) decryptSecret(ctx context.Context, target *store.Target, cred *store.Credential) (string, error) {
	secret, err := p.vault.Decrypt(ctx, cred.SecretEnc, store.CredentialAAD(target.ID, cred.ID))
	if err != nil {
		return "", errors.New("credential decryption failed")
	}
	return secret, nil
}

// dialUpstream opens an SSH client to the target, authenticating with the
// decrypted secret as either a parsed private key (SecretType "ssh_key") or a
// password. The upstream host key is checked via the configured callback.
func (p *Proxy) dialUpstream(target *store.Target, cred *store.Credential, secret string) (*ssh.Client, error) {
	var auth ssh.AuthMethod
	switch cred.SecretType {
	case "ssh_key":
		signer, err := ssh.ParsePrivateKey([]byte(secret))
		if err != nil {
			return nil, fmt.Errorf("parse ssh key: %w", err)
		}
		auth = ssh.PublicKeys(signer)
	default:
		auth = ssh.Password(secret)
	}
	cfg := &ssh.ClientConfig{
		User:            cred.Username,
		Auth:            []ssh.AuthMethod{auth},
		HostKeyCallback: p.upstreamHKCB,
		Timeout:         p.dialTimeout,
	}
	addr := fmt.Sprintf("%s:%d", target.Host, target.Port)
	// Route the raw TCP connection through the jump-host dialer when configured
	// (targets reachable only via a bastion); otherwise dial directly.
	if p.upstreamDial == nil {
		return ssh.Dial("tcp", addr, cfg)
	}
	conn, err := p.upstreamDial(addr)
	if err != nil {
		return nil, err
	}
	c, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return ssh.NewClient(c, chans, reqs), nil
}

// jumpDial builds an upstream dialer that reaches the target through an SSH
// bastion: it opens a fresh bastion connection (public-key auth) per target dial
// and tunnels a direct-tcpip channel to the target. Closing the returned conn
// also closes the bastion connection.
func jumpDial(jc JumpConfig, timeout time.Duration) (func(addr string) (net.Conn, error), error) {
	if jc.Addr == "" || jc.User == "" || jc.KeyPEM == "" {
		return nil, errors.New("jump host requires an address, user and key")
	}
	signer, err := ssh.ParsePrivateKey([]byte(jc.KeyPEM))
	if err != nil {
		return nil, fmt.Errorf("parse jump key: %w", err)
	}
	hostCB := jc.HostKey
	if hostCB == nil {
		hostCB = ssh.InsecureIgnoreHostKey()
	}
	return func(addr string) (net.Conn, error) {
		bastion, err := ssh.Dial("tcp", jc.Addr, &ssh.ClientConfig{
			User:            jc.User,
			Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
			HostKeyCallback: hostCB,
			Timeout:         timeout,
		})
		if err != nil {
			return nil, fmt.Errorf("jump host dial: %w", err)
		}
		conn, err := bastion.Dial("tcp", addr)
		if err != nil {
			bastion.Close()
			return nil, fmt.Errorf("jump to target: %w", err)
		}
		return &jumpConn{Conn: conn, bastion: bastion}, nil
	}, nil
}

// jumpConn wraps a tunneled connection so closing it also closes the bastion.
type jumpConn struct {
	net.Conn
	bastion *ssh.Client
}

// Close closes the tunneled connection and the underlying bastion connection.
func (j *jumpConn) Close() error {
	err := j.Conn.Close()
	j.bastion.Close()
	return err
}

// handleSession bridges one client session channel to a freshly opened upstream
// channel, forwarding channel requests and stdin/stdout/stderr both directions
// and tee'ing the target's output into an asciicast recording. On close the
// recording's SHA-256 and its position in the tamper-evident chain are audited.
func (p *Proxy) handleSession(ctx context.Context, nc ssh.NewChannel, upstream *ssh.Client, target *store.Target, cred *store.Credential, actor string, observe bool) {
	clientChan, clientReqs, err := nc.Accept()
	if err != nil {
		return
	}
	defer clientChan.Close()

	upChan, upReqs, err := upstream.OpenChannel("session", nil)
	if err != nil {
		fmt.Fprintln(clientChan.Stderr(), "pamv1: could not open upstream session")
		return
	}
	defer upChan.Close()

	now := time.Now()
	title := fmt.Sprintf("%d_%s_%s", now.UnixNano(), target.Name, actor)
	rec, err := newRecording(p.recordingDir, title, now)
	if err != nil {
		p.log.Error("recording setup failed", "actor", actor, "target", target.Name, "err", err)
		p.audit(ctx, actor, "session.record_failed",
			fmt.Sprintf("target:%s cred_user:%s error:%v", target.Name, cred.Username, err))
		if p.requireRec {
			fmt.Fprintln(clientChan.Stderr(), "pamv1: session recording is unavailable; session refused")
			return
		}
	}

	// Forward channel requests both directions (pty-req, shell, exec,
	// window-change from the client; exit-status from upstream). In observer mode
	// the client→upstream pump refuses exec/subsystem, and operator keystrokes are
	// dropped — the session is view-only.
	// The client→upstream request pump is joined so its in-flight reply (notably
	// the exec/shell reply the client's Session.Start blocks on) is guaranteed to
	// reach clientChan before the deferred clientChan.Close() below tears it down.
	clientReqDone := make(chan struct{}) // stops the pump between requests
	var clientReqPump sync.WaitGroup
	clientReqPump.Add(1)
	go func() {
		defer clientReqPump.Done()
		if observe {
			pumpRequestsObserver(clientReqs, upChan, clientReqDone)
		} else {
			pumpRequests(clientReqs, upChan, clientReqDone)
		}
	}()
	var upReqDone sync.WaitGroup
	upReqDone.Add(1)
	go func() {
		defer upReqDone.Done()
		pumpRequests(upReqs, clientChan, nil) // exits when the upstream channel closes
	}()

	// Target stderr -> operator, also tee'd into the recording so the audited
	// hash covers stderr, not just stdout (Recording.Write is concurrency-safe).
	// The copy is joined before rec.Close() below: stdout hitting EOF (which ends
	// io.Copy(out, upChan)) does not mean stderr has drained, and a late write
	// into an already-closed Recording would vanish from the audited hash. The
	// upstream channel closing EOFs Stderr() too, so this never outlives stdout.
	var errOut io.Writer = clientChan.Stderr()
	if rec != nil {
		errOut = io.MultiWriter(clientChan.Stderr(), rec)
	}
	var errCopyDone sync.WaitGroup
	errCopyDone.Add(1)
	go func() {
		defer errCopyDone.Done()
		io.Copy(errOut, upChan.Stderr())
	}()
	if observe {
		// Read-only: drop operator keystrokes; never touch the upstream channel.
		go io.Copy(io.Discard, clientChan)
	} else {
		go func() {
			io.Copy(upChan, clientChan) // operator keystrokes -> target
			// Propagate a client stdin half-close (CHANNEL_EOF) upstream, but keep
			// the channel open so the command's remaining output and exit-status
			// still flow back. Full upstream teardown happens in handleConn when the
			// client connection actually closes.
			upChan.CloseWrite()
		}()
	}

	// Target output -> operator, tee'd into the recording.
	var out io.Writer = clientChan
	if rec != nil {
		out = io.MultiWriter(clientChan, rec)
	}
	io.Copy(out, upChan)
	upReqDone.Wait() // make sure exit-status reached the client

	// Upstream is done and exit-status is delivered; stop the client-request pump
	// and wait for it to park, so any reply it is mid-way through delivering
	// flushes to clientChan before the deferred clientChan.Close() runs.
	close(clientReqDone)
	clientReqPump.Wait()

	// Flush upstream stderr into the recording before hashing and closing it, so
	// the audited sha256 covers every stderr byte the session produced.
	errCopyDone.Wait()

	if rec != nil {
		path, sum, n := rec.Close()
		chain := p.chain.append(sum)
		p.auditClosing(ctx, actor, "session.record",
			fmt.Sprintf("target:%s cred_user:%s file:%s bytes:%d sha256:%s chain:%s",
				target.Name, cred.Username, path, n, sum, chain))
	}
}

// serveWinRM brokers an interactive command loop to a WinRM (Windows) target.
// The connection has already passed every gate (role, grants, approval, protocol
// allowlist). Each operator line is run as a separate WinRM command — this is a
// command loop, not a stateful PowerShell (working directory / variables do not
// persist across lines). Refuses cleanly when no WinRM runner is configured.
func (p *Proxy) serveWinRM(ctx context.Context, sconn *ssh.ServerConn, chans <-chan ssh.NewChannel, target *store.Target, cred *store.Credential, secret, actor, remote string, observe bool) {
	if target.Protocol != "winrm" || p.winrm == nil {
		p.log.Warn("session denied: protocol not proxyable", "actor", actor, "target", target.Name, "protocol", target.Protocol)
		p.audit(ctx, actor, "session.denied", "target:"+target.Name+" reason:protocol-not-proxyable")
		rejectAll(chans, ssh.Prohibited, "pamv1: this target's protocol is not available through the proxy")
		return
	}
	mode := "interactive"
	if observe {
		mode = "observer"
	}
	p.log.Info("winrm session started", "actor", actor, "target", target.Name, "mode", mode)
	p.audit(ctx, actor, "session.start",
		fmt.Sprintf("target:%s host:%s:%d cred_user:%s protocol:winrm mode:%s", target.Name, target.Host, target.Port, cred.Username, mode))
	if p.sessions != nil {
		sid := p.sessions.Register(session.Info{
			Actor: actor, Target: target.Name, Protocol: "winrm", Remote: remote, Started: time.Now(),
		}, func() { sconn.Close() })
		defer p.sessions.Remove(sid)
	}
	defer func() {
		p.log.Info("winrm session ended", "actor", actor, "target", target.Name)
		p.auditClosing(ctx, actor, "session.end", "target:"+target.Name+" protocol:winrm")
		p.fireSessionEnd(cred.ID)
	}()

	for nc := range chans {
		if nc.ChannelType() != "session" {
			nc.Reject(ssh.UnknownChannelType, "pamv1: only session channels are proxied")
			continue
		}
		p.handleWinRMSession(ctx, nc, target, cred, secret, actor, observe)
	}
}

// handleWinRMSession answers channel requests for one WinRM session channel: it
// runs a "shell" as an interactive command loop and an "exec" as a single
// command, tee'ing output into an asciicast recording.
func (p *Proxy) handleWinRMSession(ctx context.Context, nc ssh.NewChannel, target *store.Target, cred *store.Credential, secret, actor string, observe bool) {
	ch, reqs, err := nc.Accept()
	if err != nil {
		return
	}
	defer ch.Close()

	now := time.Now()
	rec, err := newRecording(p.recordingDir, fmt.Sprintf("%d_%s_%s", now.UnixNano(), target.Name, actor), now)
	if err != nil {
		p.log.Error("recording setup failed", "actor", actor, "target", target.Name, "err", err)
		p.audit(ctx, actor, "session.record_failed",
			fmt.Sprintf("target:%s cred_user:%s protocol:winrm error:%v", target.Name, cred.Username, err))
		if p.requireRec {
			fmt.Fprintln(ch, "pamv1: session recording is unavailable; session refused")
			return
		}
	}
	defer func() {
		if rec != nil {
			path, sum, n := rec.Close()
			chain := p.chain.append(sum)
			p.auditClosing(ctx, actor, "session.record",
				fmt.Sprintf("target:%s cred_user:%s file:%s bytes:%d sha256:%s chain:%s", target.Name, cred.Username, path, n, sum, chain))
		}
	}()

	for req := range reqs {
		switch req.Type {
		case "pty-req", "env", "window-change":
			if req.WantReply {
				req.Reply(true, nil)
			}
		case "shell":
			if req.WantReply {
				req.Reply(true, nil)
			}
			p.winrmShellLoop(ctx, ch, target, cred, secret, actor, observe, rec)
			ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Code uint32 }{0}))
			return
		case "exec":
			if req.WantReply {
				req.Reply(true, nil)
			}
			var m struct{ Command string }
			_ = ssh.Unmarshal(req.Payload, &m)
			code := p.winrmRun(ctx, ch, target, cred, secret, actor, observe, rec, m.Command)
			ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Code uint32 }{uint32(code)}))
			return
		default:
			if req.WantReply {
				req.Reply(false, nil)
			}
		}
	}
}

// winrmShellLoop reads operator lines and runs each as a WinRM command, printing
// a prompt and streaming output. "exit"/"quit"/"logout" or EOF ends the session.
func (p *Proxy) winrmShellLoop(ctx context.Context, ch ssh.Channel, target *store.Target, cred *store.Credential, secret, actor string, observe bool, rec io.Writer) {
	out := recWriter(ch, rec)
	fmt.Fprintf(out, "pamv1 WinRM shell for %s (each line is a separate command; type 'exit' to quit)\r\n", target.Name)
	prompt := "pamv1 " + target.Name + "> "
	scanner := bufio.NewScanner(ch)
	scanner.Buffer(make([]byte, 0, 4096), 1<<20)
	for {
		fmt.Fprint(out, prompt)
		if !scanner.Scan() {
			return
		}
		line := strings.TrimRight(scanner.Text(), "\r\n")
		fmt.Fprint(out, "\r\n") // echo the newline for the recording
		switch strings.TrimSpace(line) {
		case "":
			continue
		case "exit", "quit", "logout":
			return
		}
		p.winrmRun(ctx, ch, target, cred, secret, actor, observe, rec, line)
	}
}

// winrmRun executes one WinRM command, streams its output (tee'd to rec) and
// audits it, returning the remote exit code. In observer mode it refuses to run.
func (p *Proxy) winrmRun(ctx context.Context, ch ssh.Channel, target *store.Target, cred *store.Credential, secret, actor string, observe bool, rec io.Writer, command string) int {
	out := recWriter(ch, rec)
	if observe {
		fmt.Fprint(out, "pamv1: read-only session, command ignored\r\n")
		p.audit(ctx, actor, "access.denied", "target:"+target.Name+" reason:observer-winrm")
		return 1
	}
	res, err := p.winrm.Run(ctx, target.Host, target.Port, cred.Username, secret, command)
	if err != nil {
		fmt.Fprintf(out, "pamv1: winrm error: %v\r\n", err)
		p.audit(ctx, actor, "winrm.error", fmt.Sprintf("target:%s via:proxy error:%v", target.Name, err))
		return 1
	}
	if res.Stdout != "" {
		io.WriteString(out, crlf(res.Stdout))
	}
	if res.Stderr != "" {
		io.WriteString(out, crlf(res.Stderr))
	}
	p.audit(ctx, actor, "winrm.run", fmt.Sprintf("target:%s cred_user:%s via:proxy exit:%d", target.Name, cred.Username, res.ExitCode))
	return res.ExitCode
}

// recWriter returns a writer that sends to the client channel and, when set, tees
// into the recording.
func recWriter(ch ssh.Channel, rec io.Writer) io.Writer {
	if rec == nil {
		return ch
	}
	return io.MultiWriter(ch, rec)
}

// crlf normalizes bare LF line endings to CRLF for terminal display.
func crlf(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "\r\n", "\n"), "\n", "\r\n")
}

// pumpRequests forwards SSH channel requests from in to dst, relaying replies,
// until in closes or done fires. Closing done stops the pump only between
// requests — a request already dequeued is forwarded and its reply delivered
// before the pump returns, so a caller can join it to guarantee an in-flight
// reply (e.g. the exec/shell reply) reaches its channel before that channel is
// torn down. A nil done means "run until in closes".
func pumpRequests(in <-chan *ssh.Request, dst ssh.Channel, done <-chan struct{}) {
	for {
		select {
		case req, ok := <-in:
			if !ok {
				return
			}
			okr, err := dst.SendRequest(req.Type, req.WantReply, req.Payload)
			if req.WantReply {
				req.Reply(okr && err == nil, nil)
			}
		case <-done:
			return
		}
	}
}

// pumpRequestsObserver forwards channel requests like pumpRequests but refuses
// anything that would run a command (exec, subsystem), so a read-only session
// cannot execute — the operator may open a shell/pty and watch, nothing more.
func pumpRequestsObserver(in <-chan *ssh.Request, dst ssh.Channel, done <-chan struct{}) {
	for {
		select {
		case req, ok := <-in:
			if !ok {
				return
			}
			if req.Type == "exec" || req.Type == "subsystem" {
				if req.WantReply {
					req.Reply(false, nil)
				}
				continue
			}
			okr, err := dst.SendRequest(req.Type, req.WantReply, req.Payload)
			if req.WantReply {
				req.Reply(okr && err == nil, nil)
			}
		case <-done:
			return
		}
	}
}

// rejectAll rejects every pending channel with reason and msg, used to refuse a
// connection after authentication once a policy gate fails.
// protocolSet turns a protocol list into a lookup set; an empty list returns nil
// (meaning "allow all protocols").
func protocolSet(ps []string) map[string]bool {
	if len(ps) == 0 {
		return nil
	}
	m := make(map[string]bool, len(ps))
	for _, p := range ps {
		if p = strings.TrimSpace(p); p != "" {
			m[p] = true
		}
	}
	return m
}

// rejectAll rejects every channel the client opens with reason and msg, used to
// refuse a connection after authentication once a policy gate fails.
func rejectAll(chans <-chan ssh.NewChannel, reason ssh.RejectionReason, msg string) {
	for nc := range chans {
		nc.Reject(reason, msg)
	}
}

// audit appends an audit event, defaulting an empty actor to "proxy" and logging
// (rather than returning) any append failure.
func (p *Proxy) audit(ctx context.Context, actor, action, detail string) {
	if actor == "" {
		actor = "proxy"
	}
	e := store.AuditEvent{Actor: actor, Action: action, Detail: detail}
	if err := p.store.AppendAudit(ctx, &e); err != nil {
		p.log.Error("audit append failed", "action", action, "err", err)
	}
}

// auditClosing writes a session-teardown audit event that must survive graceful
// shutdown. It detaches from ctx so a shutdown-cancelled context does not drop
// the event, and bounds the write so a hung store cannot stall the drain.
func (p *Proxy) auditClosing(ctx context.Context, actor, action, detail string) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	p.audit(ctx, actor, action, detail)
}
