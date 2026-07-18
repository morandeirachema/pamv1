// Package api exposes the PAM REST API and the embedded portal.
package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/logging"
	"github.com/morandeirachema/pamv1/internal/oidc"
	"github.com/morandeirachema/pamv1/internal/store"
	"github.com/morandeirachema/pamv1/internal/vault"
	"github.com/morandeirachema/pamv1/internal/web"
	"github.com/morandeirachema/pamv1/internal/winrm"
)

type ctxKey int

const (
	principalKey ctxKey = iota
	reqInfoKey
)

func withPrincipal(ctx context.Context, p *auth.Principal) context.Context {
	return context.WithValue(ctx, principalKey, p)
}

func principalFrom(ctx context.Context) *auth.Principal {
	if p, ok := ctx.Value(principalKey).(*auth.Principal); ok {
		return p
	}
	return &auth.Principal{Name: "unknown"}
}

func actorFrom(ctx context.Context) string {
	return principalFrom(ctx).Name
}

// reqInfo is a per-request holder the access-log middleware places in the
// context and the authz middleware fills with the resolved actor.
type reqInfo struct{ actor string }

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
	// AuthRatePerMin limits authentication attempts per client IP per minute
	// (0 disables rate limiting).
	AuthRatePerMin int
	// RevealDisabled makes credential reveal break-glass-only (proxy is the norm).
	RevealDisabled bool
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
	oidcPending        *oidcPending
	portalURL          string
	guacdAddr          string
	guacdRecordingPath string
	authLimiter        *rateLimiter
	revealDisabled     bool
	log                *slog.Logger
	mux                *http.ServeMux
	handler            http.Handler
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
		oidcPending:        newOIDCPending(),
		portalURL:          portalURL,
		guacdAddr:          opts.GuacdAddr,
		guacdRecordingPath: opts.GuacdRecordingPath,
		authLimiter:        newRateLimiter(opts.AuthRatePerMin),
		revealDisabled:     opts.RevealDisabled,
		log:                logging.Component("api"),
		mux:                http.NewServeMux(),
	}
	s.routes()
	s.handler = s.withAccessLog(s.withSecurityHeaders(s.mux))
	return s, nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.handler.ServeHTTP(w, r)
}

// statusWriter captures the response status and byte count for the access log.
type statusWriter struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

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
		if r.URL.Path == "/healthz" {
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
		s.log.Info("http request",
			"method", r.Method, "path", r.URL.Path, "status", sw.status,
			"bytes", sw.bytes, "dur_ms", time.Since(start).Milliseconds(),
			"actor", ri.actor, "remote", r.RemoteAddr)
	})
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /healthz", s.health)
	s.mux.HandleFunc("GET /{$}", web.Index)

	// Authentication endpoints are rate-limited per client IP.
	s.mux.Handle("POST /api/login", s.rateLimit(http.HandlerFunc(s.login))) // public: this IS authentication
	s.mux.Handle("POST /api/logout", s.authenticated(s.logout))
	s.mux.HandleFunc("GET /api/auth/oidc/start", s.oidcStart)
	s.mux.Handle("GET /api/auth/oidc/callback", s.rateLimit(http.HandlerFunc(s.oidcCallback)))

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
	s.mux.Handle("DELETE /api/credentials/{id}", s.authz(auth.CapManageCredentials, s.deleteCredential))

	s.mux.Handle("GET /api/audit", s.authz(auth.CapReadAudit, s.listAudit))

	s.mux.Handle("POST /api/users", s.authz(auth.CapManageUsers, s.createUser))
	s.mux.Handle("GET /api/users", s.authz(auth.CapManageUsers, s.listUsers))
	s.mux.Handle("DELETE /api/users/{id}", s.authz(auth.CapManageUsers, s.deleteUser))
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
			s.log.Warn("BREAK-GLASS access", "method", r.Method, "path", r.URL.Path, "remote", r.RemoteAddr)
			s.audit(ctx, "breakglass.access", r.Method+" "+r.URL.Path)
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

func (s *Server) audit(ctx context.Context, action, detail string) {
	e := store.AuditEvent{Actor: actorFrom(ctx), Action: action, Detail: detail}
	if err := s.store.AppendAudit(ctx, &e); err != nil {
		s.log.Error("audit append failed", "action", action, "err", err)
	}
	s.log.Info("audit", "actor", e.Actor, "action", action, "detail", detail)
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
