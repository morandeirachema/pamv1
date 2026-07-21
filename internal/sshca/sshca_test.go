package sshca

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// testCA builds a CertAuthority backed by a fresh ed25519 key.
func testCA(t *testing.T) *CertAuthority {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return New(signer)
}

// TestIssueUserSignsValidCert proves a minted certificate is a user cert, signed
// by the CA, scoped to the requested principal, unexpired, and accepted by an
// ssh.CertChecker that trusts the CA — the exact check a ZSP-configured sshd runs.
func TestIssueUserSignsValidCert(t *testing.T) {
	ca := testCA(t)
	signer, cert, err := ca.IssueUser("root", 2*time.Minute, "pamv1:alice@web-01")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if cert.CertType != ssh.UserCert {
		t.Fatalf("cert type = %d, want UserCert", cert.CertType)
	}
	if len(cert.ValidPrincipals) != 1 || cert.ValidPrincipals[0] != "root" {
		t.Fatalf("principals = %v, want [root]", cert.ValidPrincipals)
	}
	if cert.KeyId != "pamv1:alice@web-01" {
		t.Fatalf("key id = %q", cert.KeyId)
	}
	// The presented signer must carry the certificate (so the upstream sees a cert).
	if _, ok := signer.PublicKey().(*ssh.Certificate); !ok {
		t.Fatal("signer public key is not a certificate")
	}

	checker := &ssh.CertChecker{
		IsUserAuthority: func(auth ssh.PublicKey) bool {
			return keysEqual(auth, ca.PublicKey())
		},
	}
	if err := checker.CheckCert("root", cert); err != nil {
		t.Fatalf("valid cert rejected by checker: %v", err)
	}
	// A different principal must be refused.
	if err := checker.CheckCert("admin", cert); err == nil {
		t.Fatal("cert accepted for a principal it was not issued for")
	}
}

// TestIssueUserSerialsAreUnique confirms successive certificates get distinct,
// increasing serials (audit correlation).
func TestIssueUserSerialsAreUnique(t *testing.T) {
	ca := testCA(t)
	_, c1, err := ca.IssueUser("root", time.Minute, "id1")
	if err != nil {
		t.Fatal(err)
	}
	_, c2, err := ca.IssueUser("root", time.Minute, "id2")
	if err != nil {
		t.Fatal(err)
	}
	if c2.Serial <= c1.Serial {
		t.Fatalf("serials not increasing: %d then %d", c1.Serial, c2.Serial)
	}
}

// TestIssueUserExpires proves a short-TTL certificate is rejected once its
// validity window has passed — the property that makes access non-standing. A
// certificate valid for one minute is checked against a clock an hour ahead.
func TestIssueUserExpires(t *testing.T) {
	ca := testCA(t)
	_, cert, err := ca.IssueUser("root", time.Minute, "id")
	if err != nil {
		t.Fatal(err)
	}
	future := &ssh.CertChecker{
		Clock:           func() time.Time { return time.Now().Add(time.Hour) },
		IsUserAuthority: func(auth ssh.PublicKey) bool { return keysEqual(auth, ca.PublicKey()) },
	}
	if err := future.CheckCert("root", cert); err == nil {
		t.Fatal("an expired certificate must be rejected")
	}
	// The same cert is accepted at the present time (sanity: it is only expiry).
	now := &ssh.CertChecker{
		IsUserAuthority: func(auth ssh.PublicKey) bool { return keysEqual(auth, ca.PublicKey()) },
	}
	if err := now.CheckCert("root", cert); err != nil {
		t.Fatalf("cert should be valid now: %v", err)
	}
}

// keysEqual compares two SSH public keys by their wire encoding.
func keysEqual(a, b ssh.PublicKey) bool {
	am, bm := a.Marshal(), b.Marshal()
	if len(am) != len(bm) {
		return false
	}
	for i := range am {
		if am[i] != bm[i] {
			return false
		}
	}
	return true
}
