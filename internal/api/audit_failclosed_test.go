package api_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/morandeirachema/pamv1/internal/api"
	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/store"
	"github.com/morandeirachema/pamv1/internal/store/memstore"
	"github.com/morandeirachema/pamv1/internal/vault"
)

// failAuditStore wraps a Store and makes AppendAudit fail on demand, to prove the
// secret-delivery paths fail CLOSED when the audit log is unavailable.
type failAuditStore struct {
	store.Store
	fail bool
}

func (f *failAuditStore) AppendAudit(ctx context.Context, e *store.AuditEvent) error {
	if f.fail {
		return errors.New("audit store unavailable")
	}
	return f.Store.AppendAudit(ctx, e)
}

// TestRevealFailsClosedWithoutAudit proves a credential reveal is refused (503)
// rather than returning the secret when the durable audit write fails — upholding
// the invariant that every secret use appends an audit event.
func TestRevealFailsClosedWithoutAudit(t *testing.T) {
	fs := &failAuditStore{Store: memstore.New()}
	masterKey, err := vault.GenerateMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	v, err := vault.New(masterKey)
	if err != nil {
		t.Fatal(err)
	}
	bgHash := sha256.Sum256([]byte(breakGlassKey))
	resolver, err := auth.NewResolver(fs, testAPIKey, hex.EncodeToString(bgHash[:]))
	if err != nil {
		t.Fatal(err)
	}
	resolver.WithProfiles(fs)
	handler, err := api.New(fs, v, resolver, nil, api.Options{})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	// Seed with a working audit store (creation audits are best-effort anyway).
	_, data := do(t, srv, http.MethodPost, "/api/targets", testAPIKey, map[string]any{
		"name": "web-01", "host": "10.0.0.5", "port": 22, "os_type": "linux", "protocol": "ssh",
	})
	targetID := int64(jsonMap(t, data)["id"].(float64))
	_, data = do(t, srv, http.MethodPost, "/api/credentials", testAPIKey, map[string]any{
		"target_id": targetID, "username": "root", "secret": secretPassword,
	})
	credID := int64(jsonMap(t, data)["id"].(float64))

	// Now break the audit store and attempt a reveal.
	fs.fail = true
	status, body := do(t, srv, http.MethodPost, "/api/credentials/"+itoa(credID)+"/reveal", testAPIKey, nil)
	if status != http.StatusServiceUnavailable {
		t.Fatalf("reveal with a failing audit store: want 503, got %d (%s)", status, body)
	}
	if strings.Contains(string(body), secretPassword) {
		t.Fatalf("reveal leaked the secret despite a failed audit: %s", body)
	}
}
