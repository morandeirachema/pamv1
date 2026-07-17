// Package api exposes the PAM REST API and the embedded portal.
package api

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"

	"github.com/morandeirachema/pamv1/internal/store"
	"github.com/morandeirachema/pamv1/internal/vault"
	"github.com/morandeirachema/pamv1/internal/web"
)

type ctxKey int

const actorKey ctxKey = iota

func withActor(ctx context.Context, actor string) context.Context {
	return context.WithValue(ctx, actorKey, actor)
}

func actorFrom(ctx context.Context) string {
	if a, ok := ctx.Value(actorKey).(string); ok {
		return a
	}
	return "unknown"
}

type Server struct {
	store          store.Store
	vault          *vault.Vault
	apiKey         []byte
	breakGlassHash []byte
	mux            *http.ServeMux
}

// New builds the HTTP handler. breakGlassHashHex is the hex SHA-256 of the
// sealed emergency key; pass "" to disable the break-glass path.
func New(st store.Store, v *vault.Vault, apiKey, breakGlassHashHex string) (*Server, error) {
	var bgHash []byte
	if breakGlassHashHex != "" {
		b, err := hex.DecodeString(breakGlassHashHex)
		if err != nil || len(b) != sha256.Size {
			return nil, errors.New("PAM_BREAK_GLASS_KEY_HASH must be a hex-encoded SHA-256")
		}
		bgHash = b
	}
	s := &Server{store: st, vault: v, apiKey: []byte(apiKey), breakGlassHash: bgHash, mux: http.NewServeMux()}
	s.routes()
	return s, nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /healthz", s.health)
	s.mux.HandleFunc("GET /{$}", web.Index)

	s.mux.Handle("POST /api/targets", s.auth(s.createTarget))
	s.mux.Handle("GET /api/targets", s.auth(s.listTargets))
	s.mux.Handle("GET /api/targets/{id}", s.auth(s.getTarget))
	s.mux.Handle("DELETE /api/targets/{id}", s.auth(s.deleteTarget))

	s.mux.Handle("POST /api/credentials", s.auth(s.createCredential))
	s.mux.Handle("GET /api/credentials", s.auth(s.listCredentials))
	s.mux.Handle("POST /api/credentials/{id}/reveal", s.auth(s.revealCredential))
	s.mux.Handle("DELETE /api/credentials/{id}", s.auth(s.deleteCredential))

	s.mux.Handle("GET /api/audit", s.auth(s.listAudit))
}

// auth accepts the admin API key or, as an emergency path, the sealed
// break-glass key. Break-glass use is deliberately loud: every request made
// with it appends a "breakglass.access" audit event and logs a warning.
func (s *Server) auth(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := []byte(r.Header.Get("X-API-Key"))
		if subtle.ConstantTimeCompare(key, s.apiKey) == 1 {
			next(w, r.WithContext(withActor(r.Context(), "api-key")))
			return
		}
		if len(s.breakGlassHash) != 0 && len(key) != 0 {
			sum := sha256.Sum256(key)
			if subtle.ConstantTimeCompare(sum[:], s.breakGlassHash) == 1 {
				ctx := withActor(r.Context(), "break-glass")
				slog.Warn("BREAK-GLASS access", "method", r.Method, "path", r.URL.Path, "remote", r.RemoteAddr)
				s.audit(ctx, "breakglass.access", r.Method+" "+r.URL.Path)
				next(w, r.WithContext(ctx))
				return
			}
		}
		writeError(w, http.StatusUnauthorized, "invalid or missing API key")
	})
}

func (s *Server) audit(ctx context.Context, action, detail string) {
	e := store.AuditEvent{Actor: actorFrom(ctx), Action: action, Detail: detail}
	if err := s.store.AppendAudit(ctx, &e); err != nil {
		slog.Error("audit append failed", "action", action, "err", err)
	}
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
