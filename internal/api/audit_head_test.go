package api_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"net/http"
	"testing"

	"github.com/morandeirachema/pamv1/internal/api"
)

// TestAuditHeadEndpoint covers GET /api/audit/head: 501 when checkpoint signing
// is off, and a valid ed25519-signed checkpoint (over last_id||head) when on.
func TestAuditHeadEndpoint(t *testing.T) {
	// Not enabled → 501.
	srv, _ := newTestServerStore(t)
	if status, _ := do(t, srv, http.MethodGet, "/api/audit/head", testAPIKey, nil); status != http.StatusNotImplemented {
		t.Fatalf("head (signing off): want 501, got %d", status)
	}

	// Enabled: server holds the sign key, store has the HMAC chain on.
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 7)
	}
	signKey := ed25519.NewKeyFromSeed(seed)
	srv2, st := newTestServerOpts(t, nil, api.Options{AuditSignKey: signKey})
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	st.EnableAuditChain(key)

	// Perform an audited action so the chain has a head.
	if s, _ := do(t, srv2, http.MethodPost, "/api/targets", testAPIKey, map[string]any{
		"name": "web-01", "host": "10.0.0.5", "port": 22, "os_type": "linux", "protocol": "ssh",
	}); s != http.StatusCreated {
		t.Fatalf("create target: %d", s)
	}

	status, data := do(t, srv2, http.MethodGet, "/api/audit/head", testAPIKey, nil)
	if status != http.StatusOK {
		t.Fatalf("head (signing on): want 200, got %d (%s)", status, data)
	}
	m := jsonMap(t, data)
	lastID := int64(m["last_id"].(float64))
	if lastID == 0 {
		t.Fatal("checkpoint last_id should be > 0 after an audited action")
	}
	head := b64(t, m["head"])
	sig := b64(t, m["signature"])
	pub := b64(t, m["public_key"])

	// The published public key must match the server's signing key.
	if !ed25519.PublicKey(pub).Equal(signKey.Public()) {
		t.Fatal("checkpoint public_key does not match the signing key")
	}
	// The signature must verify over the canonical message: BE(last_id) || head.
	msg := make([]byte, 8, 8+len(head))
	binary.BigEndian.PutUint64(msg, uint64(lastID))
	msg = append(msg, head...)
	if !ed25519.Verify(pub, msg, sig) {
		t.Fatal("checkpoint signature does not verify (truncation detection would be forgeable)")
	}
}

// b64 decodes a base64 JSON string field into bytes.
func b64(t *testing.T, v any) []byte {
	t.Helper()
	s, ok := v.(string)
	if !ok {
		t.Fatalf("expected a base64 string, got %T", v)
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}
	return b
}
