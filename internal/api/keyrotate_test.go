package api_test

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/morandeirachema/pamv1/internal/api"
	"github.com/morandeirachema/pamv1/internal/rotate"
	"github.com/morandeirachema/pamv1/internal/store"
)

// fakeKeyConnector implements Rotator + Verifier + KeyRotator, recording the new
// private key it was asked to install.
type fakeKeyConnector struct{ lastNewKey string }

func (f *fakeKeyConnector) Rotate(context.Context, store.Target, string, string, string) error {
	return nil
}

func (f *fakeKeyConnector) Verify(context.Context, store.Target, string, string) error { return nil }

func (f *fakeKeyConnector) RotateKey(_ context.Context, _ store.Target, _, _, newPrivPEM string) error {
	f.lastNewKey = newPrivPEM
	return nil
}

func TestSSHKeyRotation(t *testing.T) {
	fc := &fakeKeyConnector{}
	srv, _ := newTestServerOpts(t, nil, api.Options{
		Rotators: map[string]rotate.Rotator{"ssh": fc},
	})
	credID := seedTargetCred(t, srv, "ssh", "ssh_key", "OLD-PRIVATE-KEY")

	status, data := do(t, srv, http.MethodPost, fmt.Sprintf("/api/credentials/%d/rotate", credID), testAPIKey, nil)
	if status != http.StatusOK || jsonMap(t, data)["rotated"] != true {
		t.Fatalf("rotate ssh_key: %d %s", status, data)
	}
	if fc.lastNewKey == "" {
		t.Fatal("connector was not asked to install a new key")
	}

	// The vault now holds the freshly generated private key (a real OpenSSH PEM),
	// not the old placeholder.
	status, data = do(t, srv, http.MethodPost, fmt.Sprintf("/api/credentials/%d/reveal", credID), testAPIKey, nil)
	if status != http.StatusOK {
		t.Fatalf("reveal: %d %s", status, data)
	}
	revealed := jsonMap(t, data)["secret"].(string)
	if revealed != fc.lastNewKey {
		t.Fatal("vault does not hold the newly installed private key")
	}
	if !strings.Contains(revealed, "OPENSSH PRIVATE KEY") || revealed == "OLD-PRIVATE-KEY" {
		t.Fatalf("expected a freshly generated OpenSSH key, got %q", revealed)
	}
}
