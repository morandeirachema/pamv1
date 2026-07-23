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
	"sync"
	"sync/atomic"
	"time"

	"github.com/morandeirachema/pamv1/internal/agentid"
	"github.com/morandeirachema/pamv1/internal/alert"
	"github.com/morandeirachema/pamv1/internal/analytics"
	"github.com/morandeirachema/pamv1/internal/auditchain"
	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/broker"
	"github.com/morandeirachema/pamv1/internal/logging"
	"github.com/morandeirachema/pamv1/internal/metrics"
	"github.com/morandeirachema/pamv1/internal/oidc"
	"github.com/morandeirachema/pamv1/internal/policy"
	"github.com/morandeirachema/pamv1/internal/ratelimit"
	"github.com/morandeirachema/pamv1/internal/rotate"
	"github.com/morandeirachema/pamv1/internal/session"
	"github.com/morandeirachema/pamv1/internal/sshca"
	"github.com/morandeirachema/pamv1/internal/store"
	"github.com/morandeirachema/pamv1/internal/ticket"
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
	// TrustedProxyHops is how many trusted reverse-proxy hops sit in front of the
	// server; it selects the real client IP from X-Forwarded-For for rate limiting
	// (0 = use RemoteAddr directly).
	TrustedProxyHops int
	// RevealDisabled makes credential reveal break-glass-only (proxy is the norm).
	RevealDisabled bool
	// Sessions is the live-session registry (shared with the proxy).
	Sessions *session.Registry
	// Live is the live-session output hub (shared with the proxy) that backs the
	// GET /api/sessions/{id}/stream monitoring endpoint (Phase 16).
	Live *session.Hub
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
	// TicketValidator validates an ITSM change/incident ticket on access
	// requests (Phase 20); nil disables validation. RequireTicket makes a ticket
	// mandatory on every access request.
	TicketValidator *ticket.Validator
	RequireTicket   bool
	// ApprovalsRequired is the default number of distinct approvers an access
	// request needs (Phase 21 multi-tier chains; default 1). RequireReason
	// rejects an access request that carries no reason.
	ApprovalsRequired int
	RequireReason     bool
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
	// Reconfigure (optional) rebuilds the hot-swappable RuntimeConfig from the
	// current stored configuration (Phase 12). When set, PUT/DELETE /api/config
	// take effect without a restart; nil keeps the startup snapshot (changes
	// apply on the next restart).
	Reconfigure func(context.Context) (*RuntimeConfig, error)
	// BrokerPolicy (optional) enables the AI-agent access broker (Phase 13). When
	// non-nil the broker routes are served; BrokerAuditKey (32 bytes) and
	// BrokerAuditSignKey are then required for the tamper-evident audit chain.
	BrokerPolicy       *policy.Engine
	BrokerAuditKey     []byte
	BrokerAuditSignKey ed25519.PrivateKey
	// BrokerTokenTTL is how long a single-use approval resume token stays valid
	// (default 15m). BrokerMaxArgBytes caps a tool call's serialized arguments (0
	// = uncapped). BrokerRatePerMin rate-limits tool calls per agent (0 = off).
	BrokerTokenTTL    time.Duration
	BrokerMaxArgBytes int
	BrokerRatePerMin  int
	// BrokerSVIDVerifier (optional) accepts SPIFFE JWT-SVIDs in addition to static
	// agent keys (Phase 13d); nil = static keys only.
	BrokerSVIDVerifier agentid.Verifier
	// CA (optional) is the Zero Standing Privilege SSH certificate authority
	// (Phase 22). When set, GET /api/ca/ssh publishes its public key so operators
	// can install it in a target's TrustedUserCAKeys; nil disables ZSP.
	CA *sshca.CertAuthority
	// Analytics (optional) enables privileged threat analytics (Phase 23): the
	// GET /api/analytics/risk endpoint and, when AnalyticsInterval > 0, a
	// background risk-scoring worker. nil disables both. AnalyticsWindow is how
	// far back each pass scores (default 60m); AnalyticsAutoKill terminates a
	// critical-risk actor's live sessions.
	Analytics         *analytics.Engine
	AnalyticsWindow   time.Duration
	AnalyticsAutoKill bool
	// AppSecretsEnabled turns on the application-secrets API (Phase 24): the app
	// identity + secret-grant admin routes and the /v1/app-secrets fetch path.
	AppSecretsEnabled bool
}

type Server struct {
	store              store.Store
	vault              *vault.Vault
	resolver           *auth.Resolver
	winrm              winrm.Runner
	recordingDir       string
	portalURL          string
	guacdAddr          string
	guacdRecordingPath string
	guacdRDPSecurity   string
	guacdIgnoreCert    bool
	authLimiter        *ratelimit.Limiter
	trustedProxyHops   int
	sessions           *session.Registry
	live               *session.Hub
	breakGlassHash     []byte
	bgThreshold        int
	bgTTL              time.Duration
	unseal             *unsealState
	alerter            alert.Notifier
	ticketValidator    *ticket.Validator
	requireTicket      bool
	approvalsRequired  int
	requireReason      bool
	rotators           map[string]rotate.Rotator
	verifiers          map[string]rotate.Verifier
	sshConnector       rotate.SSHConnector // one-shot SSH exec for the broker's ssh_exec tool
	airGap             bool
	discoveryDial      func(ctx context.Context, network, addr string) (net.Conn, error)
	sshCA              *sshca.CertAuthority
	analytics          *analytics.Engine
	analyticsWindow    time.Duration
	analyticsCooldown  time.Duration
	analyticsAutoKill  bool
	analyticsMu        sync.Mutex
	analyticsAlerted   map[string]analyticsAlert // actor → last alert (score + time)
	appSecretsEnabled  bool
	metrics            *metrics.Metrics
	log                *slog.Logger
	mux                *http.ServeMux
	handler            http.Handler
	// rtc is the atomically-swappable snapshot of runtime-overridable settings
	// (identity backends + operational policy). PUT /api/config rebuilds it via
	// reconfigure without a restart (Phase 12). Read it through s.rt().
	rtc atomic.Pointer[runtimeConf]
	// reconfigure rebuilds the runtime snapshot from current stored config; nil
	// disables hot-swap (changes then apply on the next restart).
	reconfigure func(context.Context) (*RuntimeConfig, error)
	// AI-agent access broker (Phase 13); nil unless a policy file is configured.
	broker        *broker.Broker
	agentVerifier agentid.Verifier
	auditChain    *auditchain.Chain
	brokerLimiter *ratelimit.Limiter // per-agent tool-call rate limit (Phase 13)
}

// RuntimeConfig is the set of settings PUT /api/config can change without a
// server restart (Phase 12 hot-swap): the identity backends and operational
// policy. main builds it from the base env config plus stored overrides and
// hands the server a Reconfigure closure that reproduces it after each change.
// Transport/bootstrap settings (listeners, TLS, DB URL, KEK) are not here —
// they stay environment-only and require a restart.
type RuntimeConfig struct {
	Authn            auth.Authenticator
	Directory        auth.DirectorySource
	OIDC             *oidc.Provider
	OIDCRoleMap      map[string]auth.Role
	MFARequired      bool
	RevealDisabled   bool
	ApprovalRequired bool
	ApprovalWindow   time.Duration
	CheckoutTTL      time.Duration
	AllowedProtocols []string
}

// runtimeConf is the server's immutable in-memory copy of a RuntimeConfig,
// stored behind s.rtc (atomic.Pointer) so in-flight requests read a consistent
// snapshot while a swap is in progress.
type runtimeConf struct {
	authn            auth.Authenticator
	directory        auth.DirectorySource
	oidc             *oidc.Provider
	oidcRoleMap      map[string]auth.Role
	mfaRequired      bool
	revealDisabled   bool
	approvalRequired bool
	approvalWindow   time.Duration
	checkoutTTL      time.Duration
	allowedProtocols map[string]bool
}

// snapshot converts an externally-built RuntimeConfig into the internal
// immutable form, defaulting the approval window and checkout TTL exactly as New
// does so a hot swap never installs a zero duration.
func snapshot(rc RuntimeConfig) *runtimeConf {
	if rc.ApprovalWindow <= 0 {
		rc.ApprovalWindow = 60 * time.Minute
	}
	if rc.CheckoutTTL <= 0 {
		rc.CheckoutTTL = 30 * time.Minute
	}
	return &runtimeConf{
		authn:            rc.Authn,
		directory:        rc.Directory,
		oidc:             rc.OIDC,
		oidcRoleMap:      rc.OIDCRoleMap,
		mfaRequired:      rc.MFARequired,
		revealDisabled:   rc.RevealDisabled,
		approvalRequired: rc.ApprovalRequired,
		approvalWindow:   rc.ApprovalWindow,
		checkoutTTL:      rc.CheckoutTTL,
		allowedProtocols: protocolSet(rc.AllowedProtocols),
	}
}

// rt returns the current runtime configuration snapshot. Never nil after New.
func (s *Server) rt() *runtimeConf { return s.rtc.Load() }

// applyReconfigure rebuilds the runtime snapshot from the current stored config
// and installs it atomically, so identity backends and policy take effect
// without a restart. A nil reconfigure (e.g. in tests) leaves the running
// snapshot in place and the change applies on the next restart.
func (s *Server) applyReconfigure(ctx context.Context) error {
	if s.reconfigure == nil {
		return nil
	}
	rc, err := s.reconfigure(ctx)
	if err != nil {
		return err
	}
	s.rtc.Store(snapshot(*rc))
	return nil
}

// hotSwap reports whether runtime configuration changes take effect immediately
// (a reconfigure closure is wired) rather than on the next restart.
func (s *Server) hotSwap() bool { return s.reconfigure != nil }

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
		winrm:              runner,
		ticketValidator:    opts.TicketValidator,
		requireTicket:      opts.RequireTicket,
		approvalsRequired:  opts.ApprovalsRequired,
		requireReason:      opts.RequireReason,
		recordingDir:       opts.RecordingDir,
		portalURL:          portalURL,
		guacdAddr:          opts.GuacdAddr,
		guacdRecordingPath: opts.GuacdRecordingPath,
		guacdRDPSecurity:   opts.GuacdRDPSecurity,
		guacdIgnoreCert:    opts.GuacdIgnoreCert,
		authLimiter:        ratelimit.New(opts.AuthRatePerMin),
		trustedProxyHops:   opts.TrustedProxyHops,
		sessions:           opts.Sessions,
		live:               opts.Live,
		breakGlassHash:     bgHash,
		bgThreshold:        opts.BreakGlassThreshold,
		bgTTL:              bgTTL,
		unseal:             newUnsealState(),
		alerter:            alerter,
		rotators:           rotators,
		verifiers:          verifiers,
		sshConnector:       sshConn,
		airGap:             opts.AirGap,
		discoveryDial:      opts.DiscoveryDial,
		reconfigure:        opts.Reconfigure,
		sshCA:              opts.CA,
		analytics:          opts.Analytics,
		analyticsWindow:    opts.AnalyticsWindow,
		analyticsAutoKill:  opts.AnalyticsAutoKill,
		analyticsAlerted:   make(map[string]analyticsAlert),
		appSecretsEnabled:  opts.AppSecretsEnabled,
		metrics:            metrics.New(),
		log:                logging.Component("api"),
		mux:                http.NewServeMux(),
	}
	// The initial runtime snapshot comes from opts (built by main from the base
	// env config + stored overrides); PUT /api/config later swaps it via
	// applyReconfigure.
	s.rtc.Store(snapshot(RuntimeConfig{
		Authn:            authn,
		Directory:        opts.Directory,
		OIDC:             opts.OIDC,
		OIDCRoleMap:      opts.OIDCRoleMap,
		MFARequired:      opts.MFARequired,
		RevealDisabled:   opts.RevealDisabled,
		ApprovalRequired: opts.RequireApproval,
		ApprovalWindow:   opts.ApprovalWindow,
		CheckoutTTL:      opts.CheckoutTTL,
		AllowedProtocols: opts.AllowedProtocols,
	}))
	if s.analyticsWindow <= 0 {
		s.analyticsWindow = time.Hour
	}
	// A flagged actor is re-alerted (and, if critical, re-killed) once per cooldown
	// so a sustained or recurring incident isn't suppressed forever; the cooldown
	// tracks the scoring window.
	s.analyticsCooldown = s.analyticsWindow
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

// Flush forwards to the underlying writer so streaming handlers (the live
// session SSE endpoint) can push frames — the embedded http.ResponseWriter
// interface does not promote Flush on its own.
func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		if w.status == 0 {
			w.status = http.StatusOK
		}
		f.Flush()
	}
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
	s.mux.Handle("PUT /api/targets/{id}/safe", s.authz(auth.CapManageTargets, s.setTargetSafe))

	// Safes (Phase 17): named containers grouping targets with delegated members.
	// Membership management is open to inventory readers so a delegated can_manage
	// member can grant access to their own safe (canManageSafe enforces it).
	s.mux.Handle("POST /api/safes", s.authz(auth.CapManageTargets, s.createSafe))
	s.mux.Handle("GET /api/safes", s.authz(auth.CapReadInventory, s.listSafes))
	s.mux.Handle("DELETE /api/safes/{id}", s.authz(auth.CapManageTargets, s.deleteSafe))
	s.mux.Handle("GET /api/safes/{id}/members", s.authz(auth.CapReadInventory, s.listSafeMembers))
	s.mux.Handle("POST /api/safes/{id}/members", s.authz(auth.CapReadInventory, s.addSafeMember))
	s.mux.Handle("DELETE /api/safes/{id}/members/{mid}", s.authz(auth.CapReadInventory, s.deleteSafeMember))

	s.mux.Handle("POST /api/targets/{id}/winrm", s.authz(auth.CapConnect, s.runWinRM))
	s.mux.HandleFunc("GET /api/targets/{id}/rdp", s.rdpTunnel) // WebSocket; auths via query token

	// Zero Standing Privilege (Phase 22): publish the SSH CA public key so an
	// operator can install it in a target's TrustedUserCAKeys. 404 when ZSP is off.
	s.mux.Handle("GET /api/ca/ssh", s.authz(auth.CapReadInventory, s.sshCAPublicKey))

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

	// Dependent accounts (Phase 17): a credential's consumers, updated over WinRM
	// on rotation so it does not break production.
	s.mux.Handle("POST /api/credentials/{id}/dependencies", s.authz(auth.CapManageCredentials, s.createDependency))
	s.mux.Handle("GET /api/credentials/{id}/dependencies", s.authz(auth.CapReadInventory, s.listDependencies))
	s.mux.Handle("DELETE /api/credentials/{id}/dependencies/{did}", s.authz(auth.CapManageCredentials, s.deleteDependency))

	// Access-request approval workflow (4-eyes). A connect-capable user files a
	// request; an approver (a *different* principal) approves or denies it.
	s.mux.Handle("POST /api/access-requests", s.authz(auth.CapConnect, s.createAccessRequest))
	s.mux.Handle("GET /api/access-requests", s.authz(auth.CapApprove, s.listAccessRequests))
	s.mux.Handle("POST /api/access-requests/{id}/approve", s.authz(auth.CapApprove, s.approveAccessRequest))
	s.mux.Handle("POST /api/access-requests/{id}/deny", s.authz(auth.CapApprove, s.denyAccessRequest))

	s.mux.Handle("GET /api/audit", s.authz(auth.CapReadAudit, s.listAudit))
	s.mux.Handle("GET /api/audit/export", s.authz(auth.CapReadAudit, s.exportAudit))
	s.mux.Handle("GET /api/audit/verify", s.authz(auth.CapReadAudit, s.verifyAudit))

	s.mux.Handle("GET /api/sessions", s.authz(auth.CapReadAudit, s.listSessions))
	s.mux.Handle("GET /api/sessions/{id}/stream", s.authz(auth.CapReadAudit, s.streamSession))
	s.mux.Handle("DELETE /api/sessions/{id}", s.authz(auth.CapManageTargets, s.killSession))

	// Privileged threat analytics (Phase 23): behavioral risk scores over the
	// audit trail. Read-only, so an auditor may review risk without changing state.
	if s.analytics != nil {
		s.mux.Handle("GET /api/analytics/risk", s.authz(auth.CapReadAudit, s.analyticsRisk))
	}

	// Application-secrets API (Phase 24, Tier-4): Conjur-style secret delivery for
	// non-agent applications, opt-in via PAM_APP_SECRETS_ENABLED. The fetch path
	// authenticates an application bearer key; the admin routes reuse human RBAC —
	// app identity CRUD needs CapManageUsers, and delegating a secret to an app
	// needs CapRevealSecret (you can only hand out a secret you could reveal).
	if s.appSecretsEnabled {
		s.mux.HandleFunc("GET /v1/app-secrets/{id}", s.appAuth(s.fetchAppSecret))
		s.mux.Handle("POST /v1/apps", s.authz(auth.CapManageUsers, s.createAppKey))
		s.mux.Handle("GET /v1/apps", s.authz(auth.CapManageUsers, s.listAppKeys))
		s.mux.Handle("DELETE /v1/apps/{id}", s.authz(auth.CapManageUsers, s.deleteAppKey))
		s.mux.Handle("GET /v1/apps/{id}/grants", s.authz(auth.CapManageUsers, s.listAppSecretGrants))
		s.mux.Handle("POST /v1/apps/{id}/grants", s.authz(auth.CapRevealSecret, s.grantAppSecret))
		s.mux.Handle("DELETE /v1/apps/{id}/grants/{gid}", s.authz(auth.CapRevealSecret, s.deleteAppSecretGrant))
	}

	s.mux.Handle("POST /api/users", s.authz(auth.CapManageUsers, s.createUser))
	s.mux.Handle("GET /api/users", s.authz(auth.CapManageUsers, s.listUsers))
	s.mux.Handle("DELETE /api/users/{id}", s.authz(auth.CapManageUsers, s.deleteUser))
	s.mux.Handle("GET /api/login-sessions", s.authz(auth.CapManageUsers, s.listLoginSessions))
	s.mux.Handle("POST /api/login-sessions/revoke", s.authz(auth.CapManageUsers, s.revokeLoginSessions))
	s.mux.Handle("POST /api/identity/reconcile", s.authz(auth.CapManageUsers, s.reconcileIdentities))

	// Access certification / attestation campaigns (Phase 19): a periodic review
	// of who has access to what; a revoke decision removes the underlying grant.
	s.mux.Handle("POST /api/campaigns", s.authz(auth.CapManageUsers, s.createCampaign))
	s.mux.Handle("GET /api/campaigns", s.authz(auth.CapReadAudit, s.listCampaigns))
	s.mux.Handle("GET /api/campaigns/{id}", s.authz(auth.CapReadAudit, s.getCampaign))
	s.mux.Handle("POST /api/campaigns/{id}/items/{iid}/decision", s.authz(auth.CapManageUsers, s.decideCampaignItem))
	s.mux.Handle("POST /api/campaigns/{id}/close", s.authz(auth.CapManageUsers, s.closeCampaign))

	// Custom permission profiles (Phase 12): named capability sets for users.
	s.mux.Handle("POST /api/profiles", s.authz(auth.CapManageUsers, s.createProfile))
	s.mux.Handle("GET /api/profiles", s.authz(auth.CapManageUsers, s.listProfiles))
	s.mux.Handle("DELETE /api/profiles/{id}", s.authz(auth.CapManageUsers, s.deleteProfile))

	// System configuration overrides (Phase 12): DB-persisted PAM_* settings.
	s.mux.Handle("GET /api/config", s.authz(auth.CapManageUsers, s.listConfig))
	s.mux.Handle("GET /api/config/effective", s.authz(auth.CapManageUsers, s.effectiveConfig))
	s.mux.Handle("GET /api/config/iac", s.authz(auth.CapManageUsers, s.iacConfig))
	s.mux.Handle("PUT /api/config", s.authz(auth.CapManageUsers, s.putConfig))
	s.mux.Handle("DELETE /api/config/{key}", s.authz(auth.CapManageUsers, s.deleteConfig))

	// AI-agent access broker (Phase 13), served only when a policy is configured.
	// Agent-facing routes authenticate an agent bearer key/SVID; operator-facing
	// routes reuse the human RBAC capabilities.
	if s.broker != nil {
		s.mux.HandleFunc("POST /v1/tool-calls", s.agentAuth(s.processToolCall))
		s.mux.HandleFunc("GET /v1/tool-calls/{id}", s.agentAuth(s.getToolCall))
		s.mux.HandleFunc("POST /v1/tool-calls/{id}/resume", s.agentAuth(s.resumeToolCall))
		s.mux.HandleFunc("POST /mcp", s.agentAuth(s.serveMCP))
		s.mux.Handle("GET /v1/approvals", s.authz(auth.CapApprove, s.listBrokerApprovals))
		s.mux.Handle("POST /v1/approvals/{id}/decision", s.authz(auth.CapApprove, s.decideBrokerApproval))
		s.mux.Handle("POST /v1/agents", s.authz(auth.CapManageUsers, s.createAgentKey))
		s.mux.Handle("GET /v1/agents", s.authz(auth.CapManageUsers, s.listAgentKeys))
		s.mux.Handle("DELETE /v1/agents/{id}", s.authz(auth.CapManageUsers, s.deleteAgentKey))
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
		s.noteBreakGlass(ctx, p, r)
		if p.EnrollOnly {
			s.audit(ctx, "authz.denied", r.Method+" "+r.URL.Path+" reason:mfa-enrollment-incomplete")
			writeError(w, http.StatusForbidden, "complete MFA enrollment to continue")
			return
		}
		if !p.Can(cap) {
			s.log.Warn("authorization denied", "actor", p.Name, "role", string(p.Role),
				"method", r.Method, "path", r.URL.Path)
			s.audit(ctx, "authz.denied", r.Method+" "+r.URL.Path+" role:"+string(p.Role))
			writeError(w, http.StatusForbidden, "your role does not permit this action")
			return
		}
		next(w, r.WithContext(ctx))
	})
}

// noteBreakGlass loudly records and alerts a break-glass access (the security
// invariant: break-glass use is always audited + alerted). Every entry point that
// resolves its own principal outside the authz middleware — e.g. the RDP tunnel —
// must call this, or an emergency-key privileged action would go unnoticed.
func (s *Server) noteBreakGlass(ctx context.Context, p *auth.Principal, r *http.Request) {
	if !p.BreakGlass {
		return
	}
	s.metrics.BreakGlass()
	s.log.Warn("BREAK-GLASS access", "method", r.Method, "path", r.URL.Path, "remote", r.RemoteAddr)
	s.audit(ctx, "breakglass.access", r.Method+" "+r.URL.Path)
	s.alerter.Notify(ctx, alert.Event{
		Type: "breakglass.access", Actor: p.Name,
		Detail: r.Method + " " + r.URL.Path, Remote: r.RemoteAddr, Time: time.Now(),
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
		ctx := withPrincipal(r.Context(), p)
		// Break-glass use is always loudly audited + alerted — including on the
		// low-sensitivity endpoints any signed-in identity may call (/me, /logout,
		// /mfa/*), so an emergency-key holder never acts entirely unrecorded.
		s.noteBreakGlass(ctx, p, r)
		next(w, r.WithContext(ctx))
	})
}

// audit appends an audit event attributed to the actor in ctx, bumps the audit
// (and, for rotations, rotation) metrics, and logs it. A store failure is logged
// but not returned to the caller (best-effort; use mustAudit for secret paths).
func (s *Server) audit(ctx context.Context, action, detail string) {
	_ = s.auditAs(ctx, actorFrom(ctx), action, detail)
}

// auditAs appends an audit event with an explicit actor, for events where the
// actor is not the authenticated principal in ctx — notably failed logins, whose
// actor is the attempted (unauthenticated) username. It returns the store error
// so secret-use paths can fail closed (see mustAudit); non-secret callers ignore
// it and remain best-effort.
func (s *Server) auditAs(ctx context.Context, actor, action, detail string) error {
	e := store.AuditEvent{Actor: actor, Action: action, Detail: detail}
	err := s.store.AppendAudit(ctx, &e)
	if err != nil {
		s.log.Error("audit append failed", "action", action, "err", err)
	}
	s.metrics.Audit()
	if action == "credential.rotate" {
		s.metrics.Rotation()
	}
	s.log.Info("audit", "actor", actor, "action", action, "detail", detail)
	return err
}

// mustAudit records a secret-use audit event FAIL-CLOSED: the durable audit must
// persist before the secret is delivered. If the append fails it writes a 503 and
// returns false, so the caller aborts without handing out an unaudited secret —
// upholding the invariant that every secret use appends an audit event. This is
// the audit analogue of PAM_REQUIRE_RECORDING for the proxy.
func (s *Server) mustAudit(w http.ResponseWriter, ctx context.Context, action, detail string) bool {
	return s.mustAuditAs(w, ctx, actorFrom(ctx), action, detail)
}

// mustAuditAs is mustAudit with an explicit actor (e.g. an application identity).
func (s *Server) mustAuditAs(w http.ResponseWriter, ctx context.Context, actor, action, detail string) bool {
	if err := s.auditAs(ctx, actor, action, detail); err != nil {
		writeError(w, http.StatusServiceUnavailable, "audit log unavailable; secret access denied")
		return false
	}
	return true
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
	allowed := s.rt().allowedProtocols
	return allowed == nil || allowed[proto]
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
