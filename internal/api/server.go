// Package api exposes the PAM REST API and the embedded portal.
package api

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/morandeirachema/pamv1/internal/agentid"
	"github.com/morandeirachema/pamv1/internal/alert"
	"github.com/morandeirachema/pamv1/internal/auditchain"
	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/broker"
	"github.com/morandeirachema/pamv1/internal/logging"
	"github.com/morandeirachema/pamv1/internal/metrics"
	"github.com/morandeirachema/pamv1/internal/oidc"
	"github.com/morandeirachema/pamv1/internal/policy"
	"github.com/morandeirachema/pamv1/internal/rotate"
	"github.com/morandeirachema/pamv1/internal/session"
	"github.com/morandeirachema/pamv1/internal/store"
	"github.com/morandeirachema/pamv1/internal/vault"
	"github.com/morandeirachema/pamv1/internal/web"
	"github.com/morandeirachema/pamv1/internal/winrm"
	"golang.org/x/crypto/ssh"
)

type ctxKey int

const (
	principalKey ctxKey = iota
	reqInfoKey
)

// withPrincipal returns a copy of ctx carrying the authenticated Principal.
func withPrincipal(ctx context.Context, p *auth.Principal) context.Context {
	return context.WithValue(ctx, principalKey, p)
}

// principalFrom returns the Principal stored in ctx, or a fallback "unknown"
// principal when none is present.
func principalFrom(ctx context.Context) *auth.Principal {
	if p, ok := ctx.Value(principalKey).(*auth.Principal); ok {
		return p
	}
	return &auth.Principal{Name: "unknown"}
}

// actorFrom returns the name of the Principal in ctx, used for audit attribution.
func actorFrom(ctx context.Context) string {
	return principalFrom(ctx).Name
}

// reqInfo is a per-request holder the access-log middleware places in the
// context and the authz middleware fills with the resolved actor.
type reqInfo struct{ actor string }

// setActor records the resolved actor on the per-request reqInfo (if present),
// so the access-log middleware can log who made the request.
func setActor(ctx context.Context, actor string) {
	if ri, ok := ctx.Value(reqInfoKey).(*reqInfo); ok {
		ri.actor = actor
	}
}

// Options tunes server policy.
type Options struct {
	// MFARequired makes password login require a confirmed second factor: users
	// without one get an enrollment-only session until they set up MFA.
	MFARequired bool
	// WinRM runs commands on Windows targets; defaults to a real HTTPS client.
	WinRM winrm.Runner
	// RecordingDir is where session/command transcripts are written.
	RecordingDir string
	// OIDC (optional) enables the browser Authorization Code login flow.
	OIDC *oidc.Provider
	// OIDCRoleMap maps OIDC app-role/group claims to roles.
	OIDCRoleMap map[string]auth.Role
	// PortalURL is where the OIDC callback redirects (default "/").
	PortalURL string
	// GuacdAddr enables RDP brokering via an Apache Guacamole guacd daemon
	// (e.g. "127.0.0.1:4822"); empty disables RDP.
	GuacdAddr string
	// GuacdRecordingPath, if set, makes guacd record RDP sessions server-side
	// (a path on the guacd host).
	GuacdRecordingPath string
	// GuacdRDPSecurity sets the RDP security mode ("nla"/"tls"/"rdp"/…); empty
	// negotiates. GuacdIgnoreCert disables RDP server-cert verification (dev only).
	GuacdRDPSecurity string
	GuacdIgnoreCert  bool
	// AuthRatePerMin limits authentication attempts per client IP per minute
	// (0 disables rate limiting).
	AuthRatePerMin int
	// RevealDisabled makes credential reveal break-glass-only (proxy is the norm).
	RevealDisabled bool
	// Sessions is the live-session registry (shared with the proxy).
	Sessions *session.Registry
	// BreakGlassHashHex is the hex SHA-256 of the emergency key (for quorum unseal).
	BreakGlassHashHex string
	// BreakGlassThreshold (M) enables M-of-N quorum unseal when >= 2.
	BreakGlassThreshold int
	// BreakGlassTTL is the lifetime of an unsealed break-glass session.
	BreakGlassTTL time.Duration
	// Alerter delivers real-time break-glass alerts (defaults to no-op).
	Alerter alert.Notifier
	// Rotators changes a credential's secret on the target, keyed by target
	// protocol ("ssh", "winrm"). Defaults are built from the SSH/WinRM connectors.
	Rotators map[string]rotate.Rotator
	// Verifiers checks a vaulted secret still authenticates, keyed by protocol.
	// Defaults are built from the SSH/WinRM connectors.
	Verifiers map[string]rotate.Verifier
	// RequireApproval, when true, gates every target's connect paths behind an
	// approved access request (global OT maintenance-window / 4-eyes policy).
	// Individual targets can also opt in via Target.RequireApproval.
	RequireApproval bool
	// ApprovalWindow is how long an approved access request stays valid
	// (default 60m).
	ApprovalWindow time.Duration
	// CheckoutTTL is the lifetime of a credential checkout lease (default 30m).
	CheckoutTTL time.Duration
	// AirGap disables all outbound network calls (alert webhooks) for isolated
	// OT/air-gapped deployments.
	AirGap bool
	// DiscoveryDial overrides the TCP dialer used by the discovery scanner
	// (tests inject a dialer; nil uses the default net.Dialer).
	DiscoveryDial func(ctx context.Context, network, addr string) (net.Conn, error)
	// SSHHostKeyCallback pins the host key for the default SSH rotation/reconcile
	// connector (nil trusts any upstream key). Ignored if Rotators/Verifiers are
	// supplied explicitly.
	SSHHostKeyCallback ssh.HostKeyCallback
	// AllowedProtocols, when non-empty, restricts which target protocols may be
	// created and connected to (e.g. {"ssh","winrm"}); empty allows all.
	AllowedProtocols []string
	// Directory (optional) backs identity reconciliation: pamv1 revokes access for
	// users the directory reports as disabled. nil disables the reconcile endpoint.
	Directory auth.DirectorySource
	// BrokerPolicy (optional) enables the AI-agent access broker (Phase 13). When
	// non-nil the broker routes are served; BrokerAuditKey (32 bytes) and
	// BrokerAuditSignKey are then required for the tamper-evident audit chain.
	BrokerPolicy       *policy.Engine
	BrokerAuditKey     []byte
	BrokerAuditSignKey ed25519.PrivateKey
}

type Server struct {
	store              store.Store
	vault              *vault.Vault
	resolver           *auth.Resolver
	authn              auth.Authenticator // password login (e.g. AD); nil if not configured
	winrm              winrm.Runner
	mfaRequired        bool
	recordingDir       string
	oidc               *oidc.Provider
	oidcRoleMap        map[string]auth.Role
	portalURL          string
	guacdAddr          string
	guacdRecordingPath string
	guacdRDPSecurity   string
	guacdIgnoreCert    bool
	authLimiter        *rateLimiter
	revealDisabled     bool
	sessions           *session.Registry
	breakGlassHash     []byte
	bgThreshold        int
	bgTTL              time.Duration
	unseal             *unsealState
	alerter            alert.Notifier
	rotators           map[string]rotate.Rotator
	verifiers          map[string]rotate.Verifier
	approvalRequired   bool
	approvalWindow     time.Duration
	checkoutTTL        time.Duration
	airGap             bool
	discoveryDial      func(ctx context.Context, network, addr string) (net.Conn, error)
	allowedProtocols   map[string]bool
	directory          auth.DirectorySource
	metrics            *metrics.Metrics
	log                *slog.Logger
	mux                *http.ServeMux
	handler            http.Handler
	// AI-agent access broker (Phase 13); nil unless a policy file is configured.
	broker        *broker.Broker
	agentVerifier agentid.Verifier
	auditChain    *auditchain.Chain
}

// New builds the HTTP handler. The resolver authenticates the X-API-Key header
// into a Principal (bootstrap admin key, break-glass key, per-user token, or a
// login session). authn (optional) backs POST /api/login with a password
// identity source such as Active Directory; pass nil to disable password login.
func New(st store.Store, v *vault.Vault, resolver *auth.Resolver, authn auth.Authenticator, opts Options) (*Server, error) {
	if resolver == nil {
		return nil, errors.New("api: resolver is required")
	}
	runner := opts.WinRM
	if runner == nil {
		runner = winrm.Client{HTTPS: true}
	}
	portalURL := opts.PortalURL
	if portalURL == "" {
		portalURL = "/"
	}
	var bgHash []byte
	if opts.BreakGlassHashHex != "" {
		if b, derr := hex.DecodeString(opts.BreakGlassHashHex); derr == nil {
			bgHash = b
		}
	}
	bgTTL := opts.BreakGlassTTL
	if bgTTL <= 0 {
		bgTTL = 15 * time.Minute
	}
	alerter := opts.Alerter
	if alerter == nil || opts.AirGap {
		// Air-gapped deployments must make no outbound calls; drop the webhook.
		alerter = alert.Noop{}
	}
	approvalWindow := opts.ApprovalWindow
	if approvalWindow <= 0 {
		approvalWindow = 60 * time.Minute
	}
	checkoutTTL := opts.CheckoutTTL
	if checkoutTTL <= 0 {
		checkoutTTL = 30 * time.Minute
	}
	sshConn := rotate.SSHConnector{HostKeyCallback: opts.SSHHostKeyCallback}
	rotators := opts.Rotators
	if rotators == nil {
		rotators = map[string]rotate.Rotator{
			"ssh":   sshConn,
			"winrm": rotate.WinRMConnector{Runner: runner},
		}
	}
	verifiers := opts.Verifiers
	if verifiers == nil {
		verifiers = map[string]rotate.Verifier{
			"ssh":   sshConn,
			"winrm": rotate.WinRMConnector{Runner: runner},
		}
	}
	s := &Server{
		store:              st,
		vault:              v,
		resolver:           resolver,
		authn:              authn,
		winrm:              runner,
		mfaRequired:        opts.MFARequired,
		recordingDir:       opts.RecordingDir,
		oidc:               opts.OIDC,
		oidcRoleMap:        opts.OIDCRoleMap,
		portalURL:          portalURL,
		guacdAddr:          opts.GuacdAddr,
		guacdRecordingPath: opts.GuacdRecordingPath,
		guacdRDPSecurity:   opts.GuacdRDPSecurity,
		guacdIgnoreCert:    opts.GuacdIgnoreCert,
		authLimiter:        newRateLimiter(opts.AuthRatePerMin),
		revealDisabled:     opts.RevealDisabled,
		sessions:           opts.Sessions,
		breakGlassHash:     bgHash,
		bgThreshold:        opts.BreakGlassThreshold,
		bgTTL:              bgTTL,
		unseal:             newUnsealState(),
		alerter:            alerter,
		rotators:           rotators,
		verifiers:          verifiers,
		approvalRequired:   opts.RequireApproval,
		approvalWindow:     approvalWindow,
		checkoutTTL:        checkoutTTL,
		airGap:             opts.AirGap,
		discoveryDial:      opts.DiscoveryDial,
		allowedProtocols:   protocolSet(opts.AllowedProtocols),
		directory:          opts.Directory,
		metrics:            metrics.New(),
		log:                logging.Component("api"),
		mux:                http.NewServeMux(),
	}
	if s.sessions != nil {
		s.metrics.SetActiveSessionsSource(func() int { return len(s.sessions.List()) })
	}
	if err := s.setupBroker(opts); err != nil {
		return nil, err
	}
	s.routes()
	s.handler = s.withAccessLog(s.withSecurityHeaders(s.mux))
	return s, nil
}

// ServeHTTP dispatches the request through the server's middleware chain and router.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.handler.ServeHTTP(w, r)
}

// statusWriter captures the response status and byte count for the access log.
type statusWriter struct {
	http.ResponseWriter
	status int
	bytes  int
}

// WriteHeader records the status code before writing it to the underlying writer.
func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

// Write proxies to the underlying writer, defaulting the status to 200 (as
// net/http does on an implicit write) and accumulating the byte count.
func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytes += n
	return n, err
}

// withAccessLog logs one line per HTTP request (method, path, status, bytes,
// duration, actor, remote). Health probes are skipped to avoid noise.
func (s *Server) withAccessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip health/readiness/metrics probes: they are high-frequency and would
		// drown the access log and inflate the request counter (self-counting).
		switch r.URL.Path {
		case "/healthz", "/readyz", "/metrics":
			next.ServeHTTP(w, r)
			return
		}
		start := time.Now()
		ri := &reqInfo{}
		ctx := context.WithValue(r.Context(), reqInfoKey, ri)
		sw := &statusWriter{ResponseWriter: w}
		next.ServeHTTP(sw, r.WithContext(ctx))
		if sw.status == 0 {
			sw.status = http.StatusOK
		}
		s.metrics.HTTPRequest(sw.status)
		s.log.Info("http request",
			"method", r.Method, "path", r.URL.Path, "status", sw.status,
			"bytes", sw.bytes, "dur_ms", time.Since(start).Milliseconds(),
			"actor", ri.actor, "remote", r.RemoteAddr)
	})
}

// routes registers every HTTP route on the server's mux.
func (s *Server) routes() {
	s.mux.HandleFunc("GET /healthz", s.health)         // liveness
	s.mux.HandleFunc("GET /readyz", s.readyz)          // readiness (store reachable)
	s.mux.HandleFunc("GET /metrics", s.metricsHandler) // Prometheus exposition
	s.mux.HandleFunc("GET /{$}", web.Index)

	// Authentication endpoints are rate-limited per client IP.
	s.mux.Handle("POST /api/login", s.rateLimit(http.HandlerFunc(s.login))) // public: this IS authentication
	s.mux.Handle("POST /api/logout", s.authenticated(s.logout))
	s.mux.Handle("GET /api/auth/oidc/start", s.rateLimit(http.HandlerFunc(s.oidcStart)))
	s.mux.Handle("GET /api/auth/oidc/callback", s.rateLimit(http.HandlerFunc(s.oidcCallback)))
	s.mux.Handle("POST /api/breakglass/unseal", s.rateLimit(http.HandlerFunc(s.breakGlassUnseal)))

	// Identity of the caller (drives the portal's role-aware menu).
	s.mux.Handle("GET /api/me", s.authenticated(s.me))

	// Self-service MFA (any authenticated identity manages its own second factor).
	s.mux.Handle("GET /api/mfa", s.authenticated(s.mfaStatus))
	s.mux.Handle("POST /api/mfa/enroll", s.authenticated(s.mfaEnroll))
	s.mux.Handle("POST /api/mfa/verify", s.rateLimit(s.authenticated(s.mfaVerify)))
	s.mux.Handle("POST /api/mfa/recovery-codes", s.authenticated(s.mfaRecoveryCodes))
	s.mux.Handle("DELETE /api/mfa", s.authenticated(s.mfaDisable))

	s.mux.Handle("POST /api/targets", s.authz(auth.CapManageTargets, s.createTarget))
	s.mux.Handle("GET /api/targets", s.authz(auth.CapReadInventory, s.listTargets))
	s.mux.Handle("GET /api/targets/{id}", s.authz(auth.CapReadInventory, s.getTarget))
	s.mux.Handle("DELETE /api/targets/{id}", s.authz(auth.CapManageTargets, s.deleteTarget))

	s.mux.Handle("POST /api/targets/{id}/grants", s.authz(auth.CapManageTargets, s.createTargetGrant))
	s.mux.Handle("GET /api/targets/{id}/grants", s.authz(auth.CapManageTargets, s.listTargetGrants))
	s.mux.Handle("DELETE /api/targets/{id}/grants/{gid}", s.authz(auth.CapManageTargets, s.deleteTargetGrant))

	s.mux.Handle("POST /api/targets/{id}/winrm", s.authz(auth.CapConnect, s.runWinRM))
	s.mux.HandleFunc("GET /api/targets/{id}/rdp", s.rdpTunnel) // WebSocket; auths via query token

	s.mux.Handle("POST /api/credentials", s.authz(auth.CapManageCredentials, s.createCredential))
	s.mux.Handle("GET /api/credentials", s.authz(auth.CapReadInventory, s.listCredentials))
	s.mux.Handle("POST /api/credentials/{id}/reveal", s.authz(auth.CapRevealSecret, s.revealCredential))
	s.mux.Handle("POST /api/credentials/{id}/rotate", s.authz(auth.CapManageCredentials, s.rotateCredentialHandler))
	s.mux.Handle("POST /api/credentials/{id}/reconcile", s.authz(auth.CapManageCredentials, s.reconcileCredentialHandler))
	s.mux.Handle("GET /api/reconcile", s.authz(auth.CapManageCredentials, s.reconcileAllHandler))
	s.mux.Handle("POST /api/credentials/{id}/checkout", s.authz(auth.CapRevealSecret, s.checkoutCredential))
	s.mux.Handle("POST /api/credentials/{id}/checkin", s.authz(auth.CapRevealSecret, s.checkinCredential))
	s.mux.Handle("GET /api/checkouts", s.authz(auth.CapReadAudit, s.listCheckouts))
	s.mux.Handle("POST /api/discovery/scan", s.authz(auth.CapManageTargets, s.discoveryScan))
	s.mux.Handle("DELETE /api/credentials/{id}", s.authz(auth.CapManageCredentials, s.deleteCredential))

	// Access-request approval workflow (4-eyes). A connect-capable user files a
	// request; an approver (a *different* principal) approves or denies it.
	s.mux.Handle("POST /api/access-requests", s.authz(auth.CapConnect, s.createAccessRequest))
	s.mux.Handle("GET /api/access-requests", s.authz(auth.CapApprove, s.listAccessRequests))
	s.mux.Handle("POST /api/access-requests/{id}/approve", s.authz(auth.CapApprove, s.approveAccessRequest))
	s.mux.Handle("POST /api/access-requests/{id}/deny", s.authz(auth.CapApprove, s.denyAccessRequest))

	s.mux.Handle("GET /api/audit", s.authz(auth.CapReadAudit, s.listAudit))
	s.mux.Handle("GET /api/audit/export", s.authz(auth.CapReadAudit, s.exportAudit))

	s.mux.Handle("GET /api/sessions", s.authz(auth.CapReadAudit, s.listSessions))
	s.mux.Handle("DELETE /api/sessions/{id}", s.authz(auth.CapManageTargets, s.killSession))

	s.mux.Handle("POST /api/users", s.authz(auth.CapManageUsers, s.createUser))
	s.mux.Handle("GET /api/users", s.authz(auth.CapManageUsers, s.listUsers))
	s.mux.Handle("DELETE /api/users/{id}", s.authz(auth.CapManageUsers, s.deleteUser))
	s.mux.Handle("POST /api/identity/reconcile", s.authz(auth.CapManageUsers, s.reconcileIdentities))

	// AI-agent access broker (Phase 13), served only when a policy is configured.
	// Agent-facing routes authenticate an agent bearer key/SVID; operator-facing
	// routes reuse the human RBAC capabilities.
	if s.broker != nil {
		s.mux.HandleFunc("POST /v1/tool-calls", s.agentAuth(s.processToolCall))
		s.mux.HandleFunc("GET /v1/tool-calls/{id}", s.agentAuth(s.getToolCall))
		s.mux.Handle("POST /v1/agents", s.authz(auth.CapManageUsers, s.createAgentKey))
		s.mux.Handle("GET /v1/audit", s.authz(auth.CapReadAudit, s.listBrokerAudit))
		s.mux.Handle("GET /v1/audit/verify", s.authz(auth.CapReadAudit, s.verifyBrokerAudit))
		s.mux.Handle("GET /v1/audit/head", s.authz(auth.CapReadAudit, s.brokerAuditHead))
	}
}

// authz resolves the caller into a Principal and enforces that its role holds
// the required capability. Break-glass use is deliberately loud: every request
// made with the emergency key appends a "breakglass.access" audit event and
// logs a warning.
func (s *Server) authz(cap auth.Capability, next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, err := s.resolver.Resolve(r.Context(), r.Header.Get("X-API-Key"))
		if err != nil {
			s.log.Warn("authentication failed", "path", r.URL.Path, "remote", r.RemoteAddr)
			writeError(w, http.StatusUnauthorized, "invalid or missing API key")
			return
		}
		setActor(r.Context(), p.Name)
		ctx := withPrincipal(r.Context(), p)
		if p.BreakGlass {
			s.metrics.BreakGlass()
			s.log.Warn("BREAK-GLASS access", "method", r.Method, "path", r.URL.Path, "remote", r.RemoteAddr)
			s.audit(ctx, "breakglass.access", r.Method+" "+r.URL.Path)
			s.alerter.Notify(ctx, alert.Event{
				Type: "breakglass.access", Actor: p.Name,
				Detail: r.Method + " " + r.URL.Path, Remote: r.RemoteAddr, Time: time.Now(),
			})
		}
		if p.EnrollOnly {
			s.audit(ctx, "authz.denied", r.Method+" "+r.URL.Path+" reason:mfa-enrollment-incomplete")
			writeError(w, http.StatusForbidden, "complete MFA enrollment to continue")
			return
		}
		if !p.Role.Can(cap) {
			s.log.Warn("authorization denied", "actor", p.Name, "role", string(p.Role),
				"method", r.Method, "path", r.URL.Path)
			s.audit(ctx, "authz.denied", r.Method+" "+r.URL.Path+" role:"+string(p.Role))
			writeError(w, http.StatusForbidden, "your role does not permit this action")
			return
		}
		next(w, r.WithContext(ctx))
	})
}

// authenticated resolves the caller into a Principal without a capability
// check (used by endpoints any signed-in identity may call, e.g. logout).
func (s *Server) authenticated(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, err := s.resolver.Resolve(r.Context(), r.Header.Get("X-API-Key"))
		if err != nil {
			writeError(w, http.StatusUnauthorized, "invalid or missing API key")
			return
		}
		setActor(r.Context(), p.Name)
		next(w, r.WithContext(withPrincipal(r.Context(), p)))
	})
}

// audit appends an audit event attributed to the actor in ctx, bumps the audit
// (and, for rotations, rotation) metrics, and logs it. A store failure is logged
// but not returned to the caller.
func (s *Server) audit(ctx context.Context, action, detail string) {
	s.auditAs(ctx, actorFrom(ctx), action, detail)
}

// auditAs appends an audit event with an explicit actor, for events where the
// actor is not the authenticated principal in ctx — notably failed logins, whose
// actor is the attempted (unauthenticated) username.
func (s *Server) auditAs(ctx context.Context, actor, action, detail string) {
	e := store.AuditEvent{Actor: actor, Action: action, Detail: detail}
	if err := s.store.AppendAudit(ctx, &e); err != nil {
		s.log.Error("audit append failed", "action", action, "err", err)
	}
	s.metrics.Audit()
	if action == "credential.rotate" {
		s.metrics.Rotation()
	}
	s.log.Info("audit", "actor", actor, "action", action, "detail", detail)
}

// health is the liveness probe: it always reports ok while the process serves.
func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// protocolSet turns a protocol list into a lookup set; an empty list returns nil,
// meaning "allow all protocols".
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

// protocolAllowed reports whether a target using proto may be created or
// connected to under the configured allowlist (nil allowlist = all allowed).
func (s *Server) protocolAllowed(proto string) bool {
	return s.allowedProtocols == nil || s.allowedProtocols[proto]
}

// readyz reports readiness: the server is up AND its store backend is reachable.
// Kubernetes should gate traffic on this, and liveness on /healthz.
func (s *Server) readyz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.store.Ping(ctx); err != nil {
		s.log.Warn("readiness check failed", "err", err)
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "not ready", "reason": "store unreachable"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

// metricsHandler serves the Prometheus exposition. It is intentionally
// unauthenticated (like /healthz) and exposes only low-sensitivity counts;
// restrict it at the network/ingress layer.
func (s *Server) metricsHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	s.metrics.WritePrometheus(w)
}
