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
	chain        *recordChain

	mu sync.Mutex
	ln net.Listener
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
		chain:        newRecordChain(cfg.RecordingDir),
	}
	if p.upstreamHKCB == nil {
		p.log.Warn("upstream SSH host keys are NOT verified (set PAM_SSH_KNOWN_HOSTS to pin them)")
		p.upstreamHKCB = ssh.InsecureIgnoreHostKey()
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

// Serve accepts connections on ln until ctx is cancelled. Exposed separately
// so tests can supply a 127.0.0.1:0 listener and read back the address.
func (p *Proxy) Serve(ctx context.Context, ln net.Listener) error {
	p.mu.Lock()
	p.ln = ln
	p.mu.Unlock()

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	p.log.Info("ssh proxy listening",
		"addr", ln.Addr().String(),
		"hostkey_fp", ssh.FingerprintSHA256(p.hostKey.PublicKey()))
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go p.handleConn(ctx, conn)
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

	target, cred, secret, err := p.resolve(ctx, ext["target"], ext["cred_user"])
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
		p.audit(ctx, actor, "session.end", "target:"+target.Name)
		// Force post-session credential rotation, if configured, so a secret
		// used in one session cannot be reused in the next.
		if p.onSessionEnd != nil {
			go p.onSessionEnd(cred.ID)
		}
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
	wg.Wait()
}

// resolve looks up the target and credential and decrypts the secret — this
// decryption is the "just-in-time" moment: plaintext exists only for the
// lifetime of the upstream dial, never in the DB response or on the client.
func (p *Proxy) resolve(ctx context.Context, targetName, credUser string) (*store.Target, *store.Credential, string, error) {
	if targetName == "" {
		return nil, nil, "", errors.New("no target specified")
	}
	targets, err := p.store.ListTargets(ctx)
	if err != nil {
		return nil, nil, "", errors.New("target lookup failed")
	}
	var target *store.Target
	for i := range targets {
		if targets[i].Name == targetName {
			target = &targets[i]
			break
		}
	}
	if target == nil {
		return nil, nil, "", fmt.Errorf("unknown target %q", targetName)
	}
	if target.Protocol != "ssh" {
		return nil, nil, "", fmt.Errorf("target %q protocol %q not supported by the ssh proxy", targetName, target.Protocol)
	}
	creds, err := p.store.ListCredentials(ctx, target.ID)
	if err != nil {
		return nil, nil, "", errors.New("credential lookup failed")
	}
	var cred *store.Credential
	for i := range creds {
		if credUser == "" || creds[i].Username == credUser {
			cred = &creds[i]
			break
		}
	}
	if cred == nil {
		return nil, nil, "", fmt.Errorf("no matching credential for target %q", targetName)
	}
	secret, err := p.vault.Decrypt(ctx, cred.SecretEnc, store.CredentialAAD(target.ID))
	if err != nil {
		return nil, nil, "", errors.New("credential decryption failed")
	}
	return target, cred, secret, nil
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
	return ssh.Dial("tcp", fmt.Sprintf("%s:%d", target.Host, target.Port), cfg)
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
		p.log.Error("recording setup failed", "err", err)
	}

	// Forward channel requests both directions (pty-req, shell, exec,
	// window-change from the client; exit-status from upstream). In observer mode
	// the client→upstream pump refuses exec/subsystem, and operator keystrokes are
	// dropped — the session is view-only.
	if observe {
		go pumpRequestsObserver(clientReqs, upChan)
	} else {
		go pumpRequests(clientReqs, upChan)
	}
	var upReqDone sync.WaitGroup
	upReqDone.Add(1)
	go func() {
		defer upReqDone.Done()
		pumpRequests(upReqs, clientChan)
	}()

	go io.Copy(clientChan.Stderr(), upChan.Stderr())
	if observe {
		go io.Copy(io.Discard, clientChan) // drop operator keystrokes
	} else {
		go func() {
			io.Copy(upChan, clientChan) // operator keystrokes -> target
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

	if rec != nil {
		path, sum, n := rec.Close()
		chain := p.chain.append(sum)
		p.audit(ctx, actor, "session.record",
			fmt.Sprintf("target:%s cred_user:%s file:%s bytes:%d sha256:%s chain:%s",
				target.Name, cred.Username, path, n, sum, chain))
	}
}

// pumpRequests forwards SSH channel requests from in to dst, relaying replies.
func pumpRequests(in <-chan *ssh.Request, dst ssh.Channel) {
	for req := range in {
		ok, err := dst.SendRequest(req.Type, req.WantReply, req.Payload)
		if req.WantReply {
			req.Reply(ok && err == nil, nil)
		}
	}
}

// pumpRequestsObserver forwards channel requests like pumpRequests but refuses
// anything that would run a command (exec, subsystem), so a read-only session
// cannot execute — the operator may open a shell/pty and watch, nothing more.
func pumpRequestsObserver(in <-chan *ssh.Request, dst ssh.Channel) {
	for req := range in {
		if req.Type == "exec" || req.Type == "subsystem" {
			if req.WantReply {
				req.Reply(false, nil)
			}
			continue
		}
		ok, err := dst.SendRequest(req.Type, req.WantReply, req.Payload)
		if req.WantReply {
			req.Reply(ok && err == nil, nil)
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
