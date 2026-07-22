package proxy

// dbproxy.go extends the session-broker chokepoint to databases. It speaks the
// PostgreSQL frontend/backend wire protocol: an operator points psql (or any
// libpq client) at the proxy with user "<dbcred>@<target>" and their PAM key as
// the password; the proxy authenticates them, runs every authorization gate the
// SSH proxy runs, decrypts the target's DB credential just-in-time, dials the
// real PostgreSQL injecting that secret, and brokers the wire protocol —
// auditing each SQL statement and recording the session. The operator never
// sees the database credential (same invariant as the SSH/WinRM paths).

import (
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
	"golang.org/x/crypto/pbkdf2"

	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/logging"
	"github.com/morandeirachema/pamv1/internal/session"
	"github.com/morandeirachema/pamv1/internal/store"
	"github.com/morandeirachema/pamv1/internal/vault"
)

// DBConfig configures the PostgreSQL session proxy.
type DBConfig struct {
	Addr             string            // listen address, e.g. ":5433"; "off" disables it
	RecordingDir     string            // where session recordings are written
	Sessions         *session.Registry // live-session registry (optional)
	RequireApproval  bool              // global 4-eyes/OT gate (per-target also applies)
	AllowedProtocols []string          // protocol allowlist (must include "postgres")
	RequireRecording bool              // refuse a session that cannot be recorded
	DialTimeout      time.Duration
	// ClientTLS, when set, offers TLS on the operator-facing leg (responds 'S' to
	// an SSLRequest). When nil the proxy responds 'N' and the operator's PAM key
	// travels in cleartext — logged loudly at startup, terminate TLS at the ingress.
	ClientTLS *tls.Config
	// OnSessionEnd forces post-session credential rotation, like the SSH proxy.
	OnSessionEnd func(credentialID int64)
	// CommandGuard blocks SQL statements matching its deny patterns (Phase 16).
	CommandGuard *CommandGuard
	// Live receives each recorded statement keyed by session id, so a supervisor
	// can watch the session live (Phase 16).
	Live *session.Hub
	// AuthRatePerMin throttles operator authentication attempts per source IP per
	// minute, limiting online guessing of the PAM key (0 disables).
	AuthRatePerMin int
	// UpstreamTLS, when non-nil, VERIFIES the upstream PostgreSQL server's TLS
	// certificate on the target leg (RootCAs / ServerName). nil keeps the legacy
	// trust-any-with-warning behavior for the upstream connection.
	UpstreamTLS *tls.Config
}

// DBProxy brokers PostgreSQL sessions with just-in-time credential injection.
type DBProxy struct {
	store        store.Store
	vault        *vault.Vault
	resolver     *auth.Resolver
	log          *slog.Logger
	recordingDir string
	sessions     *session.Registry
	requireApprv bool
	allowedProto map[string]bool
	requireRec   bool
	dialTimeout  time.Duration
	clientTLS    *tls.Config
	onSessionEnd func(int64)
	guard        *CommandGuard
	live         *session.Hub
	chain        *recordChain
	authLimiter  *authRateLimiter
	upstreamTLS  *tls.Config

	bg sync.WaitGroup // background tasks (post-session rotation) drained on shutdown

	mu      sync.Mutex
	conns   map[net.Conn]struct{}
	closing bool
}

// NewDB constructs a DBProxy from the store, vault, auth resolver and cfg. It
// requires a resolver, defaults RecordingDir and DialTimeout, and warns loudly
// when the operator-facing leg is unencrypted (no ClientTLS).
func NewDB(st store.Store, v *vault.Vault, resolver *auth.Resolver, cfg DBConfig) (*DBProxy, error) {
	if resolver == nil {
		return nil, errors.New("dbproxy: resolver is required")
	}
	if cfg.RecordingDir == "" {
		cfg.RecordingDir = "recordings"
	}
	if cfg.DialTimeout == 0 {
		cfg.DialTimeout = 10 * time.Second
	}
	d := &DBProxy{
		store:        st,
		vault:        v,
		resolver:     resolver,
		log:          logging.Component("dbproxy"),
		recordingDir: cfg.RecordingDir,
		sessions:     cfg.Sessions,
		requireApprv: cfg.RequireApproval,
		allowedProto: protocolSet(cfg.AllowedProtocols),
		requireRec:   cfg.RequireRecording,
		dialTimeout:  cfg.DialTimeout,
		clientTLS:    cfg.ClientTLS,
		onSessionEnd: cfg.OnSessionEnd,
		guard:        cfg.CommandGuard,
		live:         cfg.Live,
		chain:        newRecordChain(cfg.RecordingDir),
		authLimiter:  newAuthRateLimiter(cfg.AuthRatePerMin),
		upstreamTLS:  cfg.UpstreamTLS,
		conns:        make(map[net.Conn]struct{}),
	}
	if d.clientTLS == nil {
		d.log.Warn("database proxy operator leg is NOT encrypted (set PAM_TLS_CERT/KEY or terminate TLS at the ingress)")
	}
	if d.upstreamTLS == nil {
		d.log.Warn("upstream PostgreSQL TLS is NOT verified (set PAM_DB_UPSTREAM_CA or PAM_DB_UPSTREAM_TLS_VERIFY to pin it)")
	}
	return d, nil
}

// ListenAndServe binds addr and serves until ctx is cancelled.
func (d *DBProxy) ListenAndServe(ctx context.Context, addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return d.Serve(ctx, ln)
}

// Serve accepts connections until ctx is cancelled, then closes the listener and
// force-closes active connections so the drain is bounded. Modeled on
// Proxy.Serve (the SSH proxy), including the transient-accept backoff.
func (d *DBProxy) Serve(ctx context.Context, ln net.Listener) error {
	d.mu.Lock()
	d.closing = false
	d.mu.Unlock()

	go func() {
		<-ctx.Done()
		ln.Close()
		d.closeActiveConns()
	}()

	d.log.Info("database proxy listening", "addr", ln.Addr().String(), "protocol", "postgres")
	var wg sync.WaitGroup
	var tempDelay time.Duration
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				wg.Wait()
				d.bg.Wait()
				return nil
			}
			if ne, ok := err.(net.Error); ok && ne.Temporary() { //nolint:staticcheck // Temporary() is the only portable transient-accept signal
				if tempDelay == 0 {
					tempDelay = 5 * time.Millisecond
				} else {
					tempDelay *= 2
				}
				if tempDelay > time.Second {
					tempDelay = time.Second
				}
				d.log.Warn("db proxy accept error; retrying", "err", err, "retry_in", tempDelay)
				select {
				case <-time.After(tempDelay):
				case <-ctx.Done():
					wg.Wait()
					d.bg.Wait()
					return nil
				}
				continue
			}
			return err
		}
		tempDelay = 0
		d.trackConn(conn)
		wg.Add(1)
		go func(c net.Conn) {
			defer wg.Done()
			defer d.untrackConn(c)
			defer recoverPanicLog(d.log, "db-connection")
			d.handleConn(ctx, c)
		}(conn)
	}
}

// trackConn records an accepted connection so shutdown can force-close it.
func (d *DBProxy) trackConn(c net.Conn) {
	d.mu.Lock()
	if d.closing {
		d.mu.Unlock()
		c.Close()
		return
	}
	d.conns[c] = struct{}{}
	d.mu.Unlock()
}

// untrackConn drops a connection once its handler returns.
func (d *DBProxy) untrackConn(c net.Conn) {
	d.mu.Lock()
	delete(d.conns, c)
	d.mu.Unlock()
}

// closeActiveConns force-closes every tracked connection to bound the drain.
func (d *DBProxy) closeActiveConns() {
	d.mu.Lock()
	d.closing = true
	conns := make([]net.Conn, 0, len(d.conns))
	for c := range d.conns {
		conns = append(conns, c)
	}
	d.mu.Unlock()
	for _, c := range conns {
		c.Close()
	}
}

// fireSessionEnd runs the post-session rotation callback as a tracked background
// task (drained on shutdown), mirroring the SSH proxy.
func (d *DBProxy) fireSessionEnd(credID int64) {
	if d.onSessionEnd == nil {
		return
	}
	d.bg.Add(1)
	go func() {
		defer d.bg.Done()
		d.onSessionEnd(credID)
	}()
}

// audit appends an audit event, defaulting an empty actor to "dbproxy".
func (d *DBProxy) audit(ctx context.Context, actor, action, detail string) {
	if actor == "" {
		actor = "dbproxy"
	}
	appendAudit(ctx, d.store, d.log, actor, action, detail)
}

// auditClosing writes a teardown audit event that must survive graceful shutdown
// (detached from a cancelled ctx, bounded so a hung store cannot stall the drain).
func (d *DBProxy) auditClosing(ctx context.Context, actor, action, detail string) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	d.audit(ctx, actor, action, detail)
}

// handleConn brokers one PostgreSQL connection end to end: startup + SSL
// negotiation, operator authentication, the authorization gates, JIT credential
// injection into the upstream, and the audited/recorded message relay.
func (d *DBProxy) handleConn(ctx context.Context, nConn net.Conn) {
	defer recoverPanicLog(d.log, "db-session")
	remote := nConn.RemoteAddr().String()
	conn := nConn
	defer func() { conn.Close() }()

	// --- Startup / SSL negotiation ---
	backend := pgproto3.NewBackend(conn, conn)
	var startup *pgproto3.StartupMessage
	for startup == nil {
		msg, err := backend.ReceiveStartupMessage()
		if err != nil {
			return
		}
		switch msg.(type) {
		case *pgproto3.SSLRequest:
			if d.clientTLS != nil {
				if _, err := conn.Write([]byte{'S'}); err != nil {
					return
				}
				tconn := tls.Server(conn, d.clientTLS)
				if err := tconn.HandshakeContext(ctx); err != nil {
					return
				}
				conn = tconn
				backend = pgproto3.NewBackend(conn, conn) // re-frame over TLS
			} else if _, err := conn.Write([]byte{'N'}); err != nil {
				return
			}
		case *pgproto3.GSSEncRequest:
			if _, err := conn.Write([]byte{'N'}); err != nil {
				return
			}
		case *pgproto3.StartupMessage:
			startup = msg.(*pgproto3.StartupMessage)
		default:
			return
		}
	}

	login := startup.Parameters["user"]
	database := startup.Parameters["database"]
	if database == "" {
		database = login // libpq defaults dbname to the user
	}

	// --- Authenticate the operator: cleartext password = their PAM key ---
	backend.Send(&pgproto3.AuthenticationCleartextPassword{})
	if err := backend.Flush(); err != nil {
		return
	}
	if err := backend.SetAuthType(pgproto3.AuthTypeCleartextPassword); err != nil {
		return
	}
	pmsg, err := backend.Receive()
	if err != nil {
		return
	}
	pw, ok := pmsg.(*pgproto3.PasswordMessage)
	if !ok {
		d.fail(backend, "28000", "pamv1: password expected")
		return
	}
	// Throttle online guessing of the PAM key before any resolve work.
	if !d.authLimiter.allow(remoteHost(nConn.RemoteAddr())) {
		d.log.Warn("db authentication rate limited", "login", login, "remote", remote)
		d.audit(ctx, login, "proxy.auth_rate_limited", "proto:postgres remote:"+remote)
		d.fail(backend, "28P01", "pamv1: too many attempts; try again shortly")
		return
	}
	principal, err := d.resolver.Resolve(ctx, pw.Password)
	if err != nil {
		d.log.Warn("db authentication failed", "login", login, "remote", remote)
		d.audit(ctx, login, "proxy.auth_failed", "proto:postgres remote:"+remote)
		d.fail(backend, "28P01", "pamv1: authentication failed")
		return
	}
	actor := principal.Name

	// --- Authorization gates (mirror the SSH proxy; decrypt only after all pass) ---
	// An enrollment-only session (MFA setup pending under PAM_MFA_REQUIRED) may not
	// open sessions — mirror the SSH proxy and the HTTP authz middleware, so the
	// mandatory-MFA policy is not bypassable via the database proxy.
	if principal.EnrollOnly {
		d.audit(ctx, actor, "db.session.denied", "login:"+login+" reason:mfa-enrollment-incomplete")
		d.deny(ctx, backend, actor, login, "complete MFA enrollment first")
		return
	}
	if !principal.Can(auth.CapConnect) {
		d.deny(ctx, backend, actor, login, "your role may not open sessions")
		return
	}
	credUser, targetName := splitLogin(login)
	target, cred, err := lookupTargetCred(ctx, d.store, targetName, credUser)
	if err != nil {
		d.deny(ctx, backend, actor, login, err.Error())
		return
	}
	if target.Protocol != "postgres" {
		d.deny(ctx, backend, actor, login, "target is not a postgres target")
		return
	}
	if d.allowedProto != nil && !d.allowedProto[target.Protocol] {
		d.deny(ctx, backend, actor, login, "protocol not allowed by policy")
		return
	}
	grants, err := d.store.EffectiveTargetGrants(ctx, target.ID)
	if err != nil {
		d.log.Error("target grants lookup failed", "target", target.Name, "err", err)
		d.fail(backend, "58000", "pamv1: authorization check failed")
		return
	}
	if !auth.CanConnectTarget(principal, grants, target.SafeID != nil) {
		d.deny(ctx, backend, actor, login, "not authorized for this target")
		return
	}
	if (d.requireApprv || target.RequireApproval) && !principal.BreakGlass {
		approved, aerr := d.store.HasActiveApproval(ctx, actor, target.ID, time.Now())
		if aerr != nil {
			d.log.Error("approval check failed", "target", target.Name, "err", aerr)
			d.fail(backend, "58000", "pamv1: approval check failed")
			return
		}
		if !approved {
			d.audit(ctx, actor, "access.denied", "target:"+target.Name+" reason:approval-required")
			d.fail(backend, "28000", "pamv1: connection requires an approved access request")
			return
		}
	}

	// Fail closed: durably audit the session before any secret is decrypted or
	// injected upstream. If the audit store is unavailable we refuse the session
	// rather than open an unaudited privileged connection.
	if err := appendAuditErr(ctx, d.store, d.log, actor, "db.session.start", fmt.Sprintf("target:%s db:%s cred_user:%s", target.Name, database, cred.Username)); err != nil {
		d.fail(backend, "58000", "pamv1: audit log unavailable; session refused")
		return
	}

	// Every gate passed — decrypt just-in-time. Plaintext exists only from here.
	secret, err := jitDecrypt(ctx, d.vault, target, cred)
	if err != nil {
		d.log.Error("credential decryption failed", "actor", actor, "target", target.Name, "err", err)
		d.audit(ctx, actor, "credential.decrypt_failed", "target:"+target.Name+" cred_user:"+cred.Username+" op:connect")
		d.fail(backend, "58000", "pamv1: credential unavailable")
		return
	}

	up, err := d.dialUpstream(ctx, target, cred.Username, secret, database)
	if err != nil {
		d.log.Error("upstream database connection failed", "actor", actor, "target", target.Name, "err", err)
		d.audit(ctx, actor, "db.session.error", fmt.Sprintf("target:%s db:%s error:%v", target.Name, database, err))
		d.fail(backend, "08006", "pamv1: upstream connection failed")
		return
	}
	defer up.conn.Close()

	// Tell the operator's client authentication succeeded; the upstream's
	// ParameterStatus/BackendKeyData/ReadyForQuery flow through the relay.
	backend.Send(&pgproto3.AuthenticationOk{})
	if err := backend.Flush(); err != nil {
		return
	}

	d.log.Info("db session started", "actor", actor, "target", target.Name, "db", database, "cred_user", cred.Username, "remote", remote)

	var rec *Recording
	if r, rerr := newRecording(d.recordingDir, "pgsql-"+actor+"-"+target.Name+"-"+time.Now().UTC().Format("20060102-150405"), time.Now()); rerr == nil {
		rec = r
	} else {
		d.audit(ctx, actor, "session.record_failed", "proto:postgres target:"+target.Name+" err:"+rerr.Error())
		if d.requireRec {
			d.fail(backend, "58000", "pamv1: session recording unavailable")
			return
		}
	}

	var sid string
	if d.sessions != nil {
		sid = d.sessions.Register(session.Info{
			Actor: actor, Target: target.Name, Protocol: "postgres", Remote: remote, Started: time.Now(),
		}, func() { conn.Close(); up.conn.Close() })
		defer d.sessions.Remove(sid)
	}
	defer func() {
		if rec != nil {
			path, sum, n := rec.Close()
			chainHash := d.chain.append(sum)
			d.auditClosing(ctx, actor, "session.record",
				fmt.Sprintf("proto:postgres target:%s file:%s sha256:%s bytes:%d chain:%s", target.Name, filepath.Base(path), sum, n, chainHash))
		}
		d.log.Info("db session ended", "actor", actor, "target", target.Name)
		d.auditClosing(ctx, actor, "db.session.end", "target:"+target.Name)
		d.fireSessionEnd(cred.ID)
	}()

	d.relay(ctx, backend, up.fe, conn, up.conn, actor, target, rec, sid)
}

// upstreamPG is an authenticated connection to the real PostgreSQL server.
type upstreamPG struct {
	conn net.Conn
	fe   *pgproto3.Frontend
}

// dialUpstream connects to the target PostgreSQL, negotiates optional TLS, sends
// the startup message for credUser/database and completes authentication with
// the vaulted secret (cleartext, MD5 or SCRAM-SHA-256).
func (d *DBProxy) dialUpstream(ctx context.Context, target *store.Target, user, secret, database string) (*upstreamPG, error) {
	addr := net.JoinHostPort(target.Host, strconv.Itoa(target.Port))
	dialer := net.Dialer{Timeout: d.dialTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	tconn, err := d.maybeUpstreamTLS(conn, target.Host)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("upstream tls: %w", err)
	}
	conn = tconn
	fe := pgproto3.NewFrontend(conn, conn)
	fe.Send(&pgproto3.StartupMessage{
		ProtocolVersion: pgproto3.ProtocolVersionNumber,
		Parameters:      map[string]string{"user": user, "database": database},
	})
	if err := fe.Flush(); err != nil {
		conn.Close()
		return nil, err
	}
	if err := pgAuthUpstream(fe, user, secret); err != nil {
		conn.Close()
		return nil, err
	}
	return &upstreamPG{conn: conn, fe: fe}, nil
}

// relay brokers messages both ways until either side closes. Client→upstream
// Query/Parse statements are audited and recorded; everything else passes
// through so result sets, prepared statements and COPY still work.
func (d *DBProxy) relay(ctx context.Context, backend *pgproto3.Backend, fe *pgproto3.Frontend, clientConn, upConn net.Conn, actor string, target *store.Target, rec *Recording, sid string) {
	var once sync.Once
	stop := func() { clientConn.Close(); upConn.Close() }
	// The client-facing backend is written by BOTH directions — the upstream→
	// client relay and a policy refusal on the client→upstream side — so every
	// write goes through this mutex; pgproto3.Backend is not concurrency-safe.
	var bmu sync.Mutex
	sendClient := func(msgs ...pgproto3.BackendMessage) error {
		bmu.Lock()
		defer bmu.Unlock()
		for _, m := range msgs {
			backend.Send(m)
		}
		return backend.Flush()
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { // client → upstream
		defer wg.Done()
		defer once.Do(stop)
		defer recoverPanicLog(d.log, "db-c2u")
		for {
			msg, err := backend.Receive()
			if err != nil {
				return
			}
			switch m := msg.(type) {
			case *pgproto3.Query:
				if d.blockedStatement(ctx, sendClient, actor, target, m.String, false) {
					continue // refused by policy; session stays usable
				}
				d.recordQuery(ctx, rec, actor, target, m.String, sid)
			case *pgproto3.Parse:
				if d.blockedStatement(ctx, sendClient, actor, target, m.Query, true) {
					return // fail-closed: end the extended-protocol session
				}
				d.recordQuery(ctx, rec, actor, target, m.Query, sid)
			case *pgproto3.FunctionCall:
				// The deprecated fast-path call carries no SQL text, so it can't be
				// command-filtered — but audit it so it can't silently evade the
				// per-statement trail the Query/Parse paths provide.
				d.recordQuery(ctx, rec, actor, target, fmt.Sprintf("[fastpath function_call oid=%d]", m.Function), sid)
			case *pgproto3.Terminate:
				fe.Send(msg)
				_ = fe.Flush()
				return
			}
			fe.Send(msg)
			if err := fe.Flush(); err != nil {
				return
			}
		}
	}()
	go func() { // upstream → client
		defer wg.Done()
		defer once.Do(stop)
		defer recoverPanicLog(d.log, "db-u2c")
		for {
			msg, err := fe.Receive()
			if err != nil {
				return
			}
			if err := sendClient(msg); err != nil {
				return
			}
		}
	}()
	wg.Wait()
}

// recordQuery audits and records a single SQL statement, and publishes it to the
// live hub so a supervisor can watch the session.
func (d *DBProxy) recordQuery(ctx context.Context, rec *Recording, actor string, target *store.Target, sql, sid string) {
	trimmed := strings.TrimSpace(sql)
	if trimmed == "" {
		return
	}
	d.audit(ctx, actor, "db.query", "target:"+target.Name+" sql:"+auditCmd(trimmed))
	line := []byte("psql> " + trimmed + "\r\n")
	if rec != nil {
		_, _ = rec.Write(line)
	}
	d.live.Publish(sid, line)
}

// blockedStatement reports whether sql is blocked by command control. When it is,
// it audits command.blocked and sends the client an error: a graceful
// ErrorResponse+ReadyForQuery for a simple query (extended=false, session stays
// usable) or a FATAL error for an extended-protocol Parse (the caller ends it).
func (d *DBProxy) blockedStatement(ctx context.Context, sendClient func(...pgproto3.BackendMessage) error, actor string, target *store.Target, sql string, extended bool) bool {
	pat, blocked := d.guard.Blocked(sql)
	if !blocked {
		return false
	}
	d.audit(ctx, actor, "command.blocked", fmt.Sprintf("target:%s via:postgres pattern:%s sql:%s", target.Name, pat, auditCmd(sql)))
	sev := "ERROR"
	if extended {
		sev = "FATAL"
	}
	errResp := &pgproto3.ErrorResponse{Severity: sev, Code: "42501", Message: "pamv1: command blocked by policy"}
	if extended {
		_ = sendClient(errResp)
	} else {
		// A simple query: report the error and a fresh ReadyForQuery so the
		// session stays usable after the refusal.
		_ = sendClient(errResp, &pgproto3.ReadyForQuery{TxStatus: 'I'})
	}
	return true
}

// fail sends a FATAL ErrorResponse to the operator's client.
func (d *DBProxy) fail(backend *pgproto3.Backend, code, msg string) {
	backend.Send(&pgproto3.ErrorResponse{Severity: "FATAL", Code: code, Message: msg})
	_ = backend.Flush()
}

// deny audits a refused session and reports it to the client.
func (d *DBProxy) deny(ctx context.Context, backend *pgproto3.Backend, actor, login, reason string) {
	d.log.Warn("db session denied", "actor", actor, "login", login, "reason", reason)
	d.audit(ctx, actor, "db.session.denied", "login:"+login+" reason:"+reason)
	d.fail(backend, "28000", "pamv1: "+reason)
}

// maybeUpstreamTLS offers SSL to the upstream PostgreSQL. If the server accepts
// ('S') the connection is wrapped in TLS; if it declines ('N') the plaintext
// connection continues.
//
// When an upstream TLS config is set (PAM_DB_UPSTREAM_CA / PAM_DB_UPSTREAM_TLS_VERIFY)
// the server certificate is VERIFIED (fail-closed) so the JIT-injected DB
// credential cannot be harvested by a MITM impersonating the target. When it is
// unset the connection falls back to the legacy trust-any-with-warning posture
// (a warning is logged at startup), mirroring the SSH proxy's unpinned host-key
// behavior — but a verified config removes that gap entirely for the DB leg.
func (d *DBProxy) maybeUpstreamTLS(conn net.Conn, host string) (net.Conn, error) {
	// SSLRequest: int32 length 8, int32 request code 80877103.
	if _, err := conn.Write([]byte{0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f}); err != nil {
		return nil, err
	}
	resp := make([]byte, 1)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return nil, err
	}
	if resp[0] != 'S' {
		// Upstream declined TLS. If verification was demanded, refuse rather than
		// silently sending the vaulted credential over a plaintext link.
		if d.upstreamTLS != nil {
			return nil, errors.New("upstream declined TLS but PAM_DB_UPSTREAM verification is required")
		}
		return conn, nil
	}
	var cfg *tls.Config
	if d.upstreamTLS != nil {
		cfg = d.upstreamTLS.Clone()
		if cfg.ServerName == "" {
			cfg.ServerName = host
		}
	} else {
		cfg = &tls.Config{ServerName: host, InsecureSkipVerify: true} //nolint:gosec // legacy trust-any; set PAM_DB_UPSTREAM_CA to verify
	}
	tconn := tls.Client(conn, cfg)
	if err := tconn.Handshake(); err != nil {
		return nil, err
	}
	return tconn, nil
}

// pgAuthUpstream completes the frontend side of PostgreSQL authentication with
// the vaulted secret, supporting trust, cleartext, MD5 and SCRAM-SHA-256.
func pgAuthUpstream(fe *pgproto3.Frontend, user, password string) error {
	for {
		msg, err := fe.Receive()
		if err != nil {
			return err
		}
		switch m := msg.(type) {
		case *pgproto3.AuthenticationOk:
			return nil
		case *pgproto3.AuthenticationCleartextPassword:
			fe.Send(&pgproto3.PasswordMessage{Password: password})
			if err := fe.Flush(); err != nil {
				return err
			}
		case *pgproto3.AuthenticationMD5Password:
			fe.Send(&pgproto3.PasswordMessage{Password: md5Password(user, password, m.Salt)})
			if err := fe.Flush(); err != nil {
				return err
			}
		case *pgproto3.AuthenticationSASL:
			if err := scramAuth(fe, password, m.AuthMechanisms); err != nil {
				return err
			}
		case *pgproto3.ErrorResponse:
			return fmt.Errorf("upstream rejected authentication: %s", m.Message)
		default:
			// NoticeResponse / ParameterStatus before auth completes: ignore.
		}
	}
}

// md5Password builds the "md5"-prefixed hash libpq sends for MD5 authentication:
// md5( md5(password+user) + salt ).
func md5Password(user, password string, salt [4]byte) string {
	inner := md5.Sum([]byte(password + user)) //nolint:gosec // protocol-mandated by PostgreSQL MD5 auth
	outer := md5.Sum(append([]byte(hex.EncodeToString(inner[:])), salt[:]...))
	return "md5" + hex.EncodeToString(outer[:])
}

// scramAuth performs the client side of SCRAM-SHA-256 (RFC 5802) against the
// upstream, proving knowledge of the vaulted password without sending it.
func scramAuth(fe *pgproto3.Frontend, password string, mechanisms []string) error {
	supported := false
	for _, m := range mechanisms {
		if m == "SCRAM-SHA-256" {
			supported = true
		}
	}
	if !supported {
		return fmt.Errorf("no supported SASL mechanism offered: %v", mechanisms)
	}
	raw := make([]byte, 18)
	if _, err := rand.Read(raw); err != nil {
		return err
	}
	clientNonce := base64.StdEncoding.EncodeToString(raw)
	clientFirstBare := "n=,r=" + clientNonce
	fe.Send(&pgproto3.SASLInitialResponse{AuthMechanism: "SCRAM-SHA-256", Data: []byte("n,," + clientFirstBare)})
	if err := fe.Flush(); err != nil {
		return err
	}

	msg, err := fe.Receive()
	if err != nil {
		return err
	}
	cont, ok := msg.(*pgproto3.AuthenticationSASLContinue)
	if !ok {
		return fmt.Errorf("expected SASLContinue, got %T", msg)
	}
	serverFirst := string(cont.Data)
	attrs := parseSCRAM(serverFirst)
	serverNonce := attrs["r"]
	if !strings.HasPrefix(serverNonce, clientNonce) {
		return errors.New("scram: server nonce does not extend client nonce")
	}
	salt, err := base64.StdEncoding.DecodeString(attrs["s"])
	if err != nil {
		return fmt.Errorf("scram salt: %w", err)
	}
	iters, err := strconv.Atoi(attrs["i"])
	if err != nil {
		return fmt.Errorf("scram iterations: %w", err)
	}

	saltedPassword := pbkdf2.Key([]byte(password), salt, iters, sha256.Size, sha256.New)
	clientKey := hmacSHA256(saltedPassword, []byte("Client Key"))
	storedKey := sha256.Sum256(clientKey)
	clientFinalBare := "c=biws,r=" + serverNonce
	authMessage := clientFirstBare + "," + serverFirst + "," + clientFinalBare
	clientSig := hmacSHA256(storedKey[:], []byte(authMessage))
	proof := make([]byte, len(clientKey))
	for i := range clientKey {
		proof[i] = clientKey[i] ^ clientSig[i]
	}
	fe.Send(&pgproto3.SASLResponse{Data: []byte(clientFinalBare + ",p=" + base64.StdEncoding.EncodeToString(proof))})
	if err := fe.Flush(); err != nil {
		return err
	}

	msg, err = fe.Receive()
	if err != nil {
		return err
	}
	if e, isErr := msg.(*pgproto3.ErrorResponse); isErr {
		return fmt.Errorf("scram rejected: %s", e.Message)
	}
	final, ok := msg.(*pgproto3.AuthenticationSASLFinal)
	if !ok {
		return fmt.Errorf("expected SASLFinal, got %T", msg)
	}
	// Verify the server signature (SCRAM mutual authentication): recompute the
	// expected ServerSignature and constant-time compare it with the server's
	// v=… value. Skipping this — as the proxy previously did — forfeits mutual auth
	// and lets a MITM/impostor upstream complete the handshake without proving it
	// knows the password.
	serverKey := hmacSHA256(saltedPassword, []byte("Server Key"))
	expectedSig := hmacSHA256(serverKey, []byte(authMessage))
	gotSig, err := base64.StdEncoding.DecodeString(parseSCRAM(string(final.Data))["v"])
	if err != nil {
		return fmt.Errorf("scram server signature: %w", err)
	}
	if !hmac.Equal(gotSig, expectedSig) {
		return errors.New("scram: server signature mismatch (possible MITM upstream)")
	}
	return nil // AuthenticationOk follows and is consumed by the caller's loop
}

// parseSCRAM parses a SCRAM "k=v,k=v,..." message into a map.
func parseSCRAM(s string) map[string]string {
	out := make(map[string]string)
	for _, part := range strings.Split(s, ",") {
		if k, v, ok := strings.Cut(part, "="); ok {
			out[k] = v
		}
	}
	return out
}

// hmacSHA256 returns HMAC-SHA-256(key, msg).
func hmacSHA256(key, msg []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(msg)
	return h.Sum(nil)
}

// --- shared with the SSH proxy (proxy.go) ---

// lookupTargetCred resolves a target by name and a matching credential (by
// username, or the first credential when credUser is empty) WITHOUT decrypting
// the secret, so every authorization gate can run before any plaintext exists.
func lookupTargetCred(ctx context.Context, st store.Store, targetName, credUser string) (*store.Target, *store.Credential, error) {
	if targetName == "" {
		return nil, nil, errors.New("no target specified")
	}
	targets, err := st.ListTargets(ctx)
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
	creds, err := st.ListCredentials(ctx, target.ID)
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

// jitDecrypt performs the just-in-time decryption of a credential's secret. It
// must be called only after every authorization gate has passed.
func jitDecrypt(ctx context.Context, v *vault.Vault, target *store.Target, cred *store.Credential) (string, error) {
	secret, err := v.Decrypt(ctx, cred.SecretEnc, store.CredentialAAD(target.ID, cred.ID))
	if err != nil {
		return "", errors.New("credential decryption failed")
	}
	return secret, nil
}

// appendAudit writes an audit event, logging (not failing) on a store error.
func appendAudit(ctx context.Context, st store.Store, log *slog.Logger, actor, action, detail string) {
	_ = appendAuditErr(ctx, st, log, actor, action, detail)
}

// appendAuditErr is appendAudit that returns the store error, so a session that
// must be audited before a secret is injected upstream can fail closed on it.
func appendAuditErr(ctx context.Context, st store.Store, log *slog.Logger, actor, action, detail string) error {
	e := store.AuditEvent{Actor: actor, Action: action, Detail: detail}
	err := st.AppendAudit(ctx, &e)
	if err != nil {
		log.Error("audit append failed", "action", action, "err", err)
	}
	return err
}

// recoverPanicLog logs and swallows a panic in a per-connection or per-session
// goroutine so one malformed session cannot crash the whole proxy.
func recoverPanicLog(log *slog.Logger, where string) {
	if r := recover(); r != nil {
		log.Error("proxy: recovered from panic", "where", where, "panic", r, "stack", string(debug.Stack()))
	}
}
