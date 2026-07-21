package api_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"strings"
	"testing"

	"github.com/morandeirachema/pamv1/internal/api"
	"github.com/morandeirachema/pamv1/internal/sshca"
	"golang.org/x/crypto/ssh"
)

// mustTestSigner returns a fresh ed25519 SSH signer for the ZSP tests.
func mustTestSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// TestZSPCredentialValidation covers the Zero Standing Privilege credential rules
// on POST /api/credentials: an ssh_ca credential carries no secret, must be on an
// ssh target, and is stored with an empty SecretEnc (nothing to leak).
func TestZSPCredentialValidation(t *testing.T) {
	srv, _ := newTestServerStore(t)

	// An ssh target to attach the ZSP credential to.
	status, data := do(t, srv, http.MethodPost, "/api/targets", testAPIKey, map[string]any{
		"name": "web-zsp", "host": "10.0.0.9", "port": 22, "os_type": "linux", "protocol": "ssh",
	})
	if status != http.StatusCreated {
		t.Fatalf("create target: %d %s", status, data)
	}
	sshID := int64(jsonMap(t, data)["id"].(float64))

	// A winrm target: ssh_ca must be refused there.
	status, data = do(t, srv, http.MethodPost, "/api/targets", testAPIKey, map[string]any{
		"name": "win-zsp", "host": "10.0.0.10", "port": 5985, "os_type": "windows", "protocol": "winrm",
	})
	if status != http.StatusCreated {
		t.Fatalf("create winrm target: %d %s", status, data)
	}
	winID := int64(jsonMap(t, data)["id"].(float64))

	// Valid ZSP credential: no secret, on an ssh target.
	status, data = do(t, srv, http.MethodPost, "/api/credentials", testAPIKey, map[string]any{
		"target_id": sshID, "username": "root", "secret_type": "ssh_ca",
	})
	if status != http.StatusCreated {
		t.Fatalf("create ssh_ca credential: %d %s", status, data)
	}

	// A ZSP credential must NOT carry a secret.
	status, _ = do(t, srv, http.MethodPost, "/api/credentials", testAPIKey, map[string]any{
		"target_id": sshID, "username": "svc", "secret_type": "ssh_ca", "secret": "oops",
	})
	if status != http.StatusUnprocessableEntity {
		t.Fatalf("ssh_ca with a secret should be 422, got %d", status)
	}

	// A ZSP credential is only valid on an ssh target.
	status, _ = do(t, srv, http.MethodPost, "/api/credentials", testAPIKey, map[string]any{
		"target_id": winID, "username": "admin", "secret_type": "ssh_ca",
	})
	if status != http.StatusUnprocessableEntity {
		t.Fatalf("ssh_ca on a winrm target should be 422, got %d", status)
	}

	// The credential list must never leak SecretEnc (it is empty anyway).
	status, data = do(t, srv, http.MethodGet, "/api/credentials?target_id="+itoa(sshID), testAPIKey, nil)
	if status != http.StatusOK {
		t.Fatalf("list credentials: %d %s", status, data)
	}
	if strings.Contains(string(data), `"secret"`) || strings.Contains(string(data), `"secret_enc"`) {
		t.Fatalf("credential listing leaked a secret field: %s", data)
	}
}

// TestSSHCAEndpoint proves GET /api/ca/ssh returns the CA public key when ZSP is
// enabled and 404 when it is not.
func TestSSHCAEndpoint(t *testing.T) {
	// Disabled: no CA configured.
	srv, _ := newTestServerStore(t)
	if status, _ := do(t, srv, http.MethodGet, "/api/ca/ssh", testAPIKey, nil); status != http.StatusNotFound {
		t.Fatalf("ca endpoint without a CA should be 404, got %d", status)
	}

	// Enabled: a CA is wired via Options.
	ca := sshca.New(mustTestSigner(t))
	srv2, _ := newTestServerOpts(t, nil, api.Options{CA: ca})
	status, data := do(t, srv2, http.MethodGet, "/api/ca/ssh", testAPIKey, nil)
	if status != http.StatusOK {
		t.Fatalf("ca endpoint should be 200, got %d %s", status, data)
	}
	m := jsonMap(t, data)
	if got := m["public_key"].(string); got != ca.AuthorizedKey() {
		t.Fatalf("public_key = %q, want %q", got, ca.AuthorizedKey())
	}
	if m["type"] != "ssh_ca" {
		t.Fatalf("type = %v, want ssh_ca", m["type"])
	}
}
