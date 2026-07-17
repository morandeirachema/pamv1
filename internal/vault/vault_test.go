package vault

import (
	"strings"
	"testing"
)

func newVault(t *testing.T) *Vault {
	t.Helper()
	key, err := GenerateMasterKey()
	if err != nil {
		t.Fatalf("GenerateMasterKey: %v", err)
	}
	v, err := New(key)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return v
}

func TestRoundtrip(t *testing.T) {
	v := newVault(t)
	token, err := v.Encrypt("s3cret-p@ss", "target:1")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if !strings.HasPrefix(token, "v1:") {
		t.Fatalf("token missing version prefix: %q", token)
	}
	if strings.Contains(token, "s3cret") {
		t.Fatal("plaintext leaked into token")
	}
	got, err := v.Decrypt(token, "target:1")
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if got != "s3cret-p@ss" {
		t.Fatalf("roundtrip mismatch: %q", got)
	}
}

func TestAADBinding(t *testing.T) {
	v := newVault(t)
	token, _ := v.Encrypt("s3cret", "target:1")
	if _, err := v.Decrypt(token, "target:2"); err == nil {
		t.Fatal("decrypt with wrong AAD should fail")
	}
}

func TestTamperDetection(t *testing.T) {
	v := newVault(t)
	token, _ := v.Encrypt("s3cret", "target:1")
	last := token[len(token)-1]
	flip := byte('A')
	if last == 'A' {
		flip = 'B'
	}
	tampered := token[:len(token)-1] + string(flip)
	if _, err := v.Decrypt(tampered, "target:1"); err == nil {
		t.Fatal("tampered token should fail to decrypt")
	}
}

func TestUnknownVersion(t *testing.T) {
	v := newVault(t)
	if _, err := v.Decrypt("v9:AAAA", "x"); err == nil {
		t.Fatal("unknown token version should fail")
	}
}

func TestBadKey(t *testing.T) {
	if _, err := New("too-short"); err == nil {
		t.Fatal("short master key should be rejected")
	}
}

func TestDistinctNonces(t *testing.T) {
	v := newVault(t)
	a, _ := v.Encrypt("same", "aad")
	b, _ := v.Encrypt("same", "aad")
	if a == b {
		t.Fatal("two encryptions of the same plaintext must differ (random nonce)")
	}
}
