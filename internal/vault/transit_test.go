package vault

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// mockTransit stands in for HashiCorp Vault's Transit engine with a reversible
// (non-cryptographic) transform: ciphertext = "vault:v1:" + <plaintext b64>.
func mockTransit(t *testing.T, wantToken string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/transit/encrypt/", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != wantToken {
			http.Error(w, "permission denied", http.StatusForbidden)
			return
		}
		var in struct {
			Plaintext string `json:"plaintext"`
		}
		json.NewDecoder(r.Body).Decode(&in)
		writeData(w, "ciphertext", "vault:v1:"+in.Plaintext)
	})
	mux.HandleFunc("/v1/transit/decrypt/", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != wantToken {
			http.Error(w, "permission denied", http.StatusForbidden)
			return
		}
		var in struct {
			Ciphertext string `json:"ciphertext"`
		}
		json.NewDecoder(r.Body).Decode(&in)
		writeData(w, "plaintext", strings.TrimPrefix(in.Ciphertext, "vault:v1:"))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// writeData writes a Vault-style {"data": {field: value}} JSON response.
func writeData(w http.ResponseWriter, field, value string) {
	json.NewEncoder(w).Encode(map[string]any{"data": map[string]string{field: value}})
}

// TestTransitKEKRoundtrip proves wrap→unwrap round-trips the data key through
// the mock Transit engine and produces a transit-style ciphertext.
func TestTransitKEKRoundtrip(t *testing.T) {
	ctx := context.Background()
	srv := mockTransit(t, "s.token")
	kek, err := NewTransitKEK(srv.URL, "s.token", "pam")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(kek.ID(), "vault-transit:") {
		t.Fatalf("unexpected ID %q", kek.ID())
	}
	dek := []byte("0123456789abcdef0123456789abcdef")
	wrapped, err := kek.Wrap(ctx, dek)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	if !strings.HasPrefix(string(wrapped), "vault:v1:") {
		t.Fatalf("wrapped key is not a transit ciphertext: %q", wrapped)
	}
	got, err := kek.Unwrap(ctx, wrapped)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	if string(got) != string(dek) {
		t.Fatalf("roundtrip mismatch: %q", got)
	}
}

// TestVaultOverTransit proves the whole envelope path works with a KMS-style
// KEK: the secret is sealed under a data key that is wrapped by the (mock)
// Transit engine, and decrypts back correctly.
func TestVaultOverTransit(t *testing.T) {
	ctx := context.Background()
	srv := mockTransit(t, "s.token")
	kek, err := NewTransitKEK(srv.URL, "s.token", "pam")
	if err != nil {
		t.Fatal(err)
	}
	v := NewWithKEK(kek)
	token, err := v.Encrypt(ctx, "kms-sealed-secret", "target:7")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	got, err := v.Decrypt(ctx, token, "target:7")
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if got != "kms-sealed-secret" {
		t.Fatalf("roundtrip mismatch: %q", got)
	}
	if _, err := v.Decrypt(ctx, token, "target:8"); err == nil {
		t.Fatal("wrong AAD should fail even with a KMS KEK")
	}
}

// TestTransitKEKAuthError proves a wrong Vault token surfaces as a Wrap error.
func TestTransitKEKAuthError(t *testing.T) {
	ctx := context.Background()
	srv := mockTransit(t, "s.token")
	kek, _ := NewTransitKEK(srv.URL, "wrong-token", "pam")
	if _, err := kek.Wrap(ctx, make([]byte, 32)); err == nil {
		t.Fatal("wrong vault token should produce an error")
	}
}
