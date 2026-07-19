package api_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/morandeirachema/pamv1/internal/api"
	"github.com/morandeirachema/pamv1/internal/rotate"
	"github.com/morandeirachema/pamv1/internal/store"
)

// TestCredentialCheckoutLifecycle covers exclusive checkout, conflict on a double
// checkout, active listing, rotation-on-check-in, and re-checkout returning the
// new secret.
func TestCredentialCheckoutLifecycle(t *testing.T) {
	fc := &fakeConnector{}
	srv, _ := newTestServerOpts(t, nil, api.Options{
		Rotators:  map[string]rotate.Rotator{"ssh": fc},
		Verifiers: map[string]rotate.Verifier{"ssh": fc},
	})
	credID := seedTargetCred(t, srv, "ssh", "", "original-secret")

	// Checkout returns the secret and opens an exclusive lease.
	status, data := do(t, srv, http.MethodPost, fmt.Sprintf("/api/credentials/%d/checkout", credID), testAPIKey, map[string]any{"reason": "debug prod"})
	if status != http.StatusCreated {
		t.Fatalf("checkout: %d %s", status, data)
	}
	if jsonMap(t, data)["secret"].(string) != "original-secret" {
		t.Fatalf("checkout did not return the secret: %s", data)
	}

	// A second checkout is refused while one is active.
	if status, _ := do(t, srv, http.MethodPost, fmt.Sprintf("/api/credentials/%d/checkout", credID), testAPIKey, nil); status != http.StatusConflict {
		t.Fatalf("double checkout: want 409, got %d", status)
	}

	// It shows up in the active list.
	_, data = do(t, srv, http.MethodGet, "/api/checkouts?active=true", testAPIKey, nil)
	var active []map[string]any
	if err := json.Unmarshal(data, &active); err != nil {
		t.Fatal(err)
	}
	if len(active) != 1 {
		t.Fatalf("expected 1 active checkout, got %s", data)
	}

	// Check-in rotates the credential (the seen secret is invalidated).
	status, data = do(t, srv, http.MethodPost, fmt.Sprintf("/api/credentials/%d/checkin", credID), testAPIKey, nil)
	if status != http.StatusOK {
		t.Fatalf("checkin: %d %s", status, data)
	}
	if jsonMap(t, data)["rotated"] != true {
		t.Fatalf("checkin did not rotate: %s", data)
	}
	if fc.newSecret() == "" || fc.newSecret() == "original-secret" {
		t.Fatalf("secret was not rotated on check-in: %q", fc.newSecret())
	}

	// After check-in a fresh checkout is possible again, and returns the NEW secret.
	status, data = do(t, srv, http.MethodPost, fmt.Sprintf("/api/credentials/%d/checkout", credID), testAPIKey, nil)
	if status != http.StatusCreated {
		t.Fatalf("re-checkout: %d %s", status, data)
	}
	if jsonMap(t, data)["secret"].(string) != fc.newSecret() {
		t.Fatalf("re-checkout returned a stale secret")
	}
}

// TestCheckoutInvalidatesExpiredLease proves that when a prior lease expired
// without a check-in, a new checkout rotates the credential before issuing the
// new lease — so the expired holder's secret stops working and the new holder is
// handed the fresh one, closing the window where a re-checkout that races ahead
// of the periodic sweep would otherwise reuse the expired holder's secret.
func TestCheckoutInvalidatesExpiredLease(t *testing.T) {
	fc := &fakeConnector{}
	srv, st := newTestServerOpts(t, nil, api.Options{
		Rotators:  map[string]rotate.Rotator{"ssh": fc},
		Verifiers: map[string]rotate.Verifier{"ssh": fc},
	})
	credID := seedTargetCred(t, srv, "ssh", "", "original-secret")

	cred, err := st.GetCredential(context.Background(), credID)
	if err != nil {
		t.Fatal(err)
	}
	// A lease held by someone else that expired an hour ago and was never returned.
	past := time.Now().Add(-time.Hour)
	if err := st.CreateCheckout(context.Background(), &store.Checkout{
		CredentialID: credID, TargetID: cred.TargetID, Holder: "ghost", ExpiresAt: past,
	}, past); err != nil {
		t.Fatal(err)
	}

	// The new checkout must rotate away the ghost's secret before issuing a lease.
	status, data := do(t, srv, http.MethodPost, fmt.Sprintf("/api/credentials/%d/checkout", credID), testAPIKey, nil)
	if status != http.StatusCreated {
		t.Fatalf("checkout over an expired lease: %d %s", status, data)
	}
	if fc.newSecret() == "" || fc.newSecret() == "original-secret" {
		t.Fatalf("expired lease was not rotated before re-checkout: %q", fc.newSecret())
	}
	if jsonMap(t, data)["secret"].(string) != fc.newSecret() {
		t.Fatalf("re-checkout returned the expired holder's stale secret")
	}
}

// TestCheckinWithoutCheckout verifies checking in a credential that is not checked
// out returns 409.
func TestCheckinWithoutCheckout(t *testing.T) {
	fc := &fakeConnector{}
	srv, _ := newTestServerOpts(t, nil, api.Options{Rotators: map[string]rotate.Rotator{"ssh": fc}})
	credID := seedTargetCred(t, srv, "ssh", "", "s")
	if status, _ := do(t, srv, http.MethodPost, fmt.Sprintf("/api/credentials/%d/checkin", credID), testAPIKey, nil); status != http.StatusConflict {
		t.Fatalf("checkin without checkout: want 409, got %d", status)
	}
}

// TestCheckoutRespectsRevealDisabled verifies checkout is refused under the
// reveal-disabled policy except for break-glass.
func TestCheckoutRespectsRevealDisabled(t *testing.T) {
	fc := &fakeConnector{}
	srv, _ := newTestServerOpts(t, nil, api.Options{
		RevealDisabled: true,
		Rotators:       map[string]rotate.Rotator{"ssh": fc},
	})
	credID := seedTargetCred(t, srv, "ssh", "", "s")
	// A normal admin cannot check out when reveal is disabled by policy.
	if status, _ := do(t, srv, http.MethodPost, fmt.Sprintf("/api/credentials/%d/checkout", credID), testAPIKey, nil); status != http.StatusForbidden {
		t.Fatalf("checkout under reveal-disabled: want 403, got %d", status)
	}
	// Break-glass may still check out.
	if status, _ := do(t, srv, http.MethodPost, fmt.Sprintf("/api/credentials/%d/checkout", credID), breakGlassKey, nil); status != http.StatusCreated {
		t.Fatalf("break-glass checkout: want 201, got %d", status)
	}
}
