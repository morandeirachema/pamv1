package agentid_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/morandeirachema/pamv1/internal/agentid"
)

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// makeEdDSA builds an Ed25519-signed JWT from the given claims.
func makeEdDSA(t *testing.T, priv ed25519.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	hdr := b64url([]byte(`{"alg":"EdDSA","kid":"` + kid + `","typ":"JWT"}`))
	cb, _ := json.Marshal(claims)
	signing := hdr + "." + b64url(cb)
	return signing + "." + b64url(ed25519.Sign(priv, []byte(signing)))
}

// edJWKS writes a one-key Ed25519 JWKS to a temp file and returns its path.
func edJWKS(t *testing.T, pub ed25519.PublicKey, kid string) string {
	t.Helper()
	jwks := map[string]any{"keys": []map[string]any{{"kty": "OKP", "crv": "Ed25519", "kid": kid, "x": b64url(pub)}}}
	b, _ := json.Marshal(jwks)
	path := filepath.Join(t.TempDir(), "jwks.json")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestSVIDVerify covers a valid SVID, audience/expiry/trust-domain enforcement,
// a forged signature, and RFC 8693 delegation-depth capping.
func TestSVIDVerify(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	path := edJWKS(t, pub, "k1")
	const td, aud = "example.org", "pam-broker"
	v, err := agentid.NewSVIDVerifier(path, td, aud, 2)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	sub := "spiffe://example.org/ns/prod/sa/bot"

	// A valid SVID resolves to an identity carrying the SPIFFE ID.
	good := makeEdDSA(t, priv, "k1", map[string]any{"sub": sub, "aud": aud, "exp": time.Now().Add(time.Hour).Unix()})
	id, err := v.Verify(ctx, good)
	if err != nil || id.SPIFFEID != sub || id.AgentName != sub {
		t.Fatalf("valid svid: id=%+v err=%v", id, err)
	}

	// Wrong audience is rejected.
	badAud := makeEdDSA(t, priv, "k1", map[string]any{"sub": sub, "aud": "someone-else", "exp": time.Now().Add(time.Hour).Unix()})
	if _, err := v.Verify(ctx, badAud); err == nil {
		t.Fatal("wrong audience should be rejected")
	}

	// Expired is rejected (fail closed).
	expired := makeEdDSA(t, priv, "k1", map[string]any{"sub": sub, "aud": aud, "exp": time.Now().Add(-time.Hour).Unix()})
	if _, err := v.Verify(ctx, expired); err == nil {
		t.Fatal("expired svid should be rejected")
	}

	// A subject outside the trust domain is rejected.
	foreign := makeEdDSA(t, priv, "k1", map[string]any{"sub": "spiffe://evil.example/ns/x", "aud": aud, "exp": time.Now().Add(time.Hour).Unix()})
	if _, err := v.Verify(ctx, foreign); err == nil {
		t.Fatal("foreign trust domain should be rejected")
	}

	// A forged signature (flip the last byte) is rejected.
	forged := good[:len(good)-2] + string([]byte{good[len(good)-2] ^ 0x01}) + good[len(good)-1:]
	if _, err := v.Verify(ctx, forged); err == nil {
		t.Fatal("forged signature should be rejected")
	}

	// Delegation within the depth cap populates the actor chain.
	deleg := makeEdDSA(t, priv, "k1", map[string]any{
		"sub": sub, "aud": aud, "exp": time.Now().Add(time.Hour).Unix(),
		"act": map[string]any{"sub": "spiffe://example.org/user/alice"},
	})
	id, err = v.Verify(ctx, deleg)
	if err != nil || len(id.ActorChain) != 2 || id.OnBehalfOf != "spiffe://example.org/user/alice" {
		t.Fatalf("delegation: id=%+v err=%v", id, err)
	}

	// A chain deeper than maxDepth (2) is fail-closed.
	tooDeep := makeEdDSA(t, priv, "k1", map[string]any{
		"sub": sub, "aud": aud, "exp": time.Now().Add(time.Hour).Unix(),
		"act": map[string]any{"sub": "spiffe://example.org/svc/a", "act": map[string]any{"sub": "spiffe://example.org/user/bob"}},
	})
	if _, err := v.Verify(ctx, tooDeep); err == nil {
		t.Fatal("delegation past the depth cap should be rejected")
	}
}

// TestSVIDVerifyES256 covers the ECDSA P-256 verification branch.
func TestSVIDVerifyES256(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jwks := map[string]any{"keys": []map[string]any{{
		"kty": "EC", "crv": "P-256", "kid": "e1",
		"x": b64url(key.X.Bytes()), "y": b64url(key.Y.Bytes()),
	}}}
	b, _ := json.Marshal(jwks)
	path := filepath.Join(t.TempDir(), "ec.json")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	v, err := agentid.NewSVIDVerifier(path, "example.org", "pam-broker", 1)
	if err != nil {
		t.Fatal(err)
	}

	sub := "spiffe://example.org/ns/prod/sa/ec-bot"
	hdr := b64url([]byte(`{"alg":"ES256","kid":"e1","typ":"JWT"}`))
	cb, _ := json.Marshal(map[string]any{"sub": sub, "aud": "pam-broker", "exp": time.Now().Add(time.Hour).Unix()})
	signing := hdr + "." + b64url(cb)
	digest := sha256.Sum256([]byte(signing))
	r, s, _ := ecdsa.Sign(rand.Reader, key, digest[:])
	// JWT ES256 signature is fixed-width r||s (32 bytes each).
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	token := signing + "." + b64url(sig)

	id, err := v.Verify(context.Background(), token)
	if err != nil || id.SPIFFEID != sub {
		t.Fatalf("ES256 svid: id=%+v err=%v", id, err)
	}
}
