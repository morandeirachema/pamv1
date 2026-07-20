package api_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/morandeirachema/pamv1/internal/agentid"
	"github.com/morandeirachema/pamv1/internal/winrm"
)

// TestBrokerSVIDAuth proves the agent transport accepts a SPIFFE JWT-SVID
// alongside static keys: an SVID-bearing agent runs an allowed tool call.
func TestBrokerSVIDAuth(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	b64 := func(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
	jwks, _ := json.Marshal(map[string]any{"keys": []map[string]any{{"kty": "OKP", "crv": "Ed25519", "kid": "k1", "x": b64(pub)}}})
	path := filepath.Join(t.TempDir(), "jwks.json")
	if err := os.WriteFile(path, jwks, 0o600); err != nil {
		t.Fatal(err)
	}
	verifier, err := agentid.NewSVIDVerifier(path, "example.org", "pam-broker", 1)
	if err != nil {
		t.Fatal(err)
	}

	fake := &fakeWinRM{result: winrm.Result{Stdout: "ok"}}
	opts := brokerOpts(t, fake, toolsetRules) // allows list_targets (no grant needed)
	opts.BrokerSVIDVerifier = verifier
	srv, _ := newTestServerOpts(t, nil, opts)
	seedWinRMTarget(t, srv, "win-svid", "pw")

	// Mint an SVID for the agent.
	hdr := b64([]byte(`{"alg":"EdDSA","kid":"k1","typ":"JWT"}`))
	claims, _ := json.Marshal(map[string]any{"sub": "spiffe://example.org/ns/prod/sa/bot", "aud": "pam-broker", "exp": 4102444800})
	signing := hdr + "." + b64(claims)
	svid := signing + "." + b64(ed25519.Sign(priv, []byte(signing)))

	// The SVID authenticates and the allowed tool runs.
	st, data := doBearer(t, srv, http.MethodPost, "/v1/tool-calls", svid, map[string]any{"tool": "list_targets"})
	if st != http.StatusOK || jsonMap(t, data)["status"] != "executed" {
		t.Fatalf("svid tool call: %d %s", st, data)
	}

	// A bogus bearer is still rejected (401).
	if st, _ := doBearer(t, srv, http.MethodPost, "/v1/tool-calls", "not-a-token", map[string]any{"tool": "list_targets"}); st != http.StatusUnauthorized {
		t.Fatalf("bogus bearer: want 401, got %d", st)
	}
}
