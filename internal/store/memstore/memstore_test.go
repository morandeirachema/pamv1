package memstore

import (
	"context"
	"testing"
	"time"
)

// TestOIDCStateSharedAcrossInstances proves the HA property: an OIDC login
// begun against one server (which writes the PKCE state to the shared store) can
// be completed by another server reading the same store.
func TestOIDCStateSharedAcrossInstances(t *testing.T) {
	st := New() // one store, stands in for a shared database
	ctx := context.Background()
	now := time.Now()

	if err := st.PutOIDCState(ctx, "state-abc", "verifier-xyz", "nonce-123", now.Add(10*time.Minute)); err != nil {
		t.Fatal(err)
	}

	// A "different replica" reading the same store gets the state back once.
	v, n, ok, err := st.TakeOIDCState(ctx, "state-abc", now)
	if err != nil || !ok {
		t.Fatalf("take: ok=%v err=%v", ok, err)
	}
	if v != "verifier-xyz" || n != "nonce-123" {
		t.Fatalf("wrong values: %q %q", v, n)
	}

	// It is single-use: a replay finds nothing.
	if _, _, ok, _ := st.TakeOIDCState(ctx, "state-abc", now); ok {
		t.Fatal("state must be consumed on first take")
	}
}

// TestOIDCStateExpiry checks an expired OIDC state is not returned by TakeOIDCState.
func TestOIDCStateExpiry(t *testing.T) {
	st := New()
	ctx := context.Background()
	now := time.Now()
	if err := st.PutOIDCState(ctx, "s", "v", "n", now.Add(-1*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, _, ok, _ := st.TakeOIDCState(ctx, "s", now); ok {
		t.Fatal("expired state must not be returned")
	}
}

// TestOIDCStateMissing checks TakeOIDCState reports not-found for an unknown state.
func TestOIDCStateMissing(t *testing.T) {
	st := New()
	if _, _, ok, err := st.TakeOIDCState(context.Background(), "nope", time.Now()); ok || err != nil {
		t.Fatalf("missing state: ok=%v err=%v", ok, err)
	}
}
