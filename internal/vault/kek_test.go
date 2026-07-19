package vault

import (
	"bytes"
	"context"
	"testing"
)

// TestLocalKEKRoundtrip proves wrap→unwrap restores the data key and the
// wrapped blob does not expose the plaintext key.
func TestLocalKEKRoundtrip(t *testing.T) {
	ctx := context.Background()
	key, _ := GenerateMasterKey()
	kek, err := NewLocalKEK(key)
	if err != nil {
		t.Fatal(err)
	}
	dek := bytes.Repeat([]byte{0xAB}, 32)
	wrapped, err := kek.Wrap(ctx, dek)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	if bytes.Contains(wrapped, dek) {
		t.Fatal("wrapped data key exposes the plaintext key")
	}
	got, err := kek.Unwrap(ctx, wrapped)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	if !bytes.Equal(got, dek) {
		t.Fatal("unwrap mismatch")
	}
}

// TestLocalKEKTamper proves a corrupted wrapped key fails to unwrap.
func TestLocalKEKTamper(t *testing.T) {
	ctx := context.Background()
	key, _ := GenerateMasterKey()
	kek, _ := NewLocalKEK(key)
	wrapped, _ := kek.Wrap(ctx, bytes.Repeat([]byte{1}, 32))
	wrapped[len(wrapped)-1] ^= 0xFF
	if _, err := kek.Unwrap(ctx, wrapped); err == nil {
		t.Fatal("tampered wrapped key should fail to unwrap")
	}
}

// TestNewKEK checks provider selection: local (explicit and default), unknown
// provider errors, and vault-transit without config errors.
func TestNewKEK(t *testing.T) {
	key, _ := GenerateMasterKey()

	if kek, err := NewKEK(KEKOptions{Provider: "local", MasterKey: key}); err != nil || kek.ID() != "local" {
		t.Fatalf("local provider: kek=%v err=%v", kek, err)
	}
	if _, err := NewKEK(KEKOptions{Provider: "", MasterKey: key}); err != nil {
		t.Fatalf("empty provider should default to local: %v", err)
	}
	if _, err := NewKEK(KEKOptions{Provider: "kubernetes"}); err == nil {
		t.Fatal("unknown provider should error")
	}
	if _, err := NewKEK(KEKOptions{Provider: "vault-transit"}); err == nil {
		t.Fatal("vault-transit without config should error")
	}
}
