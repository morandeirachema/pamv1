package mfa

import (
	"strings"
	"testing"
	"time"
)

// TestRFC6238Vector checks the code against the RFC 6238 Appendix B SHA-1
// vector: seed "12345678901234567890", T=59s → 8-digit 94287082, so the
// 6-digit truncation is 287082.
func TestRFC6238Vector(t *testing.T) {
	secret := b32.EncodeToString([]byte("12345678901234567890"))
	got, err := Code(secret, time.Unix(59, 0))
	if err != nil {
		t.Fatal(err)
	}
	if got != "287082" {
		t.Fatalf("RFC 6238 vector: got %s, want 287082", got)
	}
}

func TestValidateRoundtrip(t *testing.T) {
	secret, err := GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0)
	code, _ := Code(secret, now)
	if !Validate(secret, code, now) {
		t.Fatal("fresh code should validate")
	}
	// Within skew (previous step).
	if !Validate(secret, code, now.Add(30*time.Second)) {
		t.Fatal("code should validate one step later (skew)")
	}
	// Outside skew.
	if Validate(secret, code, now.Add(5*time.Minute)) {
		t.Fatal("stale code should not validate")
	}
	if Validate(secret, "000000", now) && code != "000000" {
		t.Fatal("wrong code should not validate")
	}
	if Validate(secret, "12345", now) {
		t.Fatal("wrong-length code should not validate")
	}
}

func TestProvisioningURI(t *testing.T) {
	uri := ProvisioningURI("ABC234", "alice", "pamv1")
	for _, want := range []string{"otpauth://totp/", "secret=ABC234", "issuer=pamv1", "digits=6", "period=30"} {
		if !strings.Contains(uri, want) {
			t.Fatalf("URI %q missing %q", uri, want)
		}
	}
}

func TestGenerateSecretDistinct(t *testing.T) {
	a, _ := GenerateSecret()
	b, _ := GenerateSecret()
	if a == b || a == "" {
		t.Fatal("secrets must be random and non-empty")
	}
}

func TestGenerateRecoveryCodes(t *testing.T) {
	codes, err := GenerateRecoveryCodes(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(codes) != 10 {
		t.Fatalf("got %d codes, want 10", len(codes))
	}
	seen := map[string]bool{}
	for _, c := range codes {
		if len(c) != 11 || c[5] != '-' {
			t.Fatalf("unexpected code format: %q", c)
		}
		if seen[c] {
			t.Fatalf("duplicate recovery code: %q", c)
		}
		seen[c] = true
	}
}
