package api

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/rotate"
	"github.com/morandeirachema/pamv1/internal/store"
	"github.com/morandeirachema/pamv1/internal/store/memstore"
	"github.com/morandeirachema/pamv1/internal/vault"
)

type schedFake struct {
	mu     sync.Mutex
	actual string
}

// Rotate records newSecret as the on-target password.
func (f *schedFake) Rotate(_ context.Context, _ store.Target, _, _, newSecret string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.actual = newSecret
	return nil
}

// Verify returns a non-nil error (drift) when secret does not match the
// on-target password.
func (f *schedFake) Verify(_ context.Context, _ store.Target, _, secret string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.actual != "" && secret != f.actual {
		return context.DeadlineExceeded // any non-nil error = drift
	}
	return nil
}

// newSchedTestServer builds a server with one seeded target and password
// credential wired to the given fake connector, returning the server and credential.
func newSchedTestServer(t *testing.T, fc *schedFake) (*Server, *store.Credential) {
	t.Helper()
	ctx := context.Background()
	masterKey, err := vault.GenerateMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	v, err := vault.New(masterKey)
	if err != nil {
		t.Fatal(err)
	}
	st := memstore.New()
	target := &store.Target{Name: "t", Host: "h", Port: 22, OSType: "linux", Protocol: "ssh"}
	if err := st.CreateTarget(ctx, target); err != nil {
		t.Fatal(err)
	}
	cred := &store.Credential{TargetID: target.ID, Username: "root", SecretType: "password"}
	if err := st.CreateCredential(ctx, cred); err != nil {
		t.Fatal(err)
	}
	enc, err := v.Encrypt(ctx, "orig", store.CredentialAAD(target.ID, cred.ID))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpdateCredentialSecretEnc(ctx, cred.ID, enc); err != nil {
		t.Fatal(err)
	}
	cred.SecretEnc = enc
	resolver, err := auth.NewResolver(st, "testkey", "")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(st, v, resolver, nil, Options{
		Rotators:  map[string]rotate.Rotator{"ssh": fc},
		Verifiers: map[string]rotate.Verifier{"ssh": fc},
	})
	if err != nil {
		t.Fatal(err)
	}
	return srv, cred
}

// TestLifecycleWorkerReconcileOnly verifies a report-only pass (maxAge 0) rotates
// nothing and reports no drift.
func TestLifecycleWorkerReconcileOnly(t *testing.T) {
	fc := &schedFake{}
	srv, _ := newSchedTestServer(t, fc)
	// maxAge 0 = report only, credential young: nothing rotated, nothing drifted.
	rep := srv.runLifecycleOnce(systemContext(context.Background()), 0, time.Now())
	if rep.Checked != 1 || rep.OutOfSync != 0 || rep.Rotated != 0 {
		t.Fatalf("reconcile-only pass = %+v", rep)
	}
}

// TestLifecycleWorkerDetectsDrift verifies the pass flags an out-of-band password
// change as out_of_sync.
func TestLifecycleWorkerDetectsDrift(t *testing.T) {
	fc := &schedFake{}
	srv, _ := newSchedTestServer(t, fc)
	fc.mu.Lock()
	fc.actual = "changed-out-of-band"
	fc.mu.Unlock()
	rep := srv.runLifecycleOnce(systemContext(context.Background()), 0, time.Now())
	if rep.OutOfSync != 1 {
		t.Fatalf("expected 1 out_of_sync, got %+v", rep)
	}
}

// TestLifecycleWorkerRotatesByMaxAge verifies a credential older than maxAge is
// rotated and re-vaulted, stamping rotated_at.
func TestLifecycleWorkerRotatesByMaxAge(t *testing.T) {
	fc := &schedFake{}
	srv, cred := newSchedTestServer(t, fc)
	// Pretend two hours have passed with a one-hour max age: the credential is
	// stale and must be rotated.
	future := time.Now().Add(2 * time.Hour)
	rep := srv.runLifecycleOnce(systemContext(context.Background()), time.Hour, future)
	if rep.Rotated != 1 {
		t.Fatalf("expected 1 rotation, got %+v", rep)
	}
	// The store now holds a rotated_at and a new secret.
	got, err := srv.store.GetCredential(context.Background(), cred.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.RotatedAt == nil {
		t.Fatal("rotated_at not stamped by the worker")
	}
	secret, err := srv.vault.Decrypt(context.Background(), got.SecretEnc, store.CredentialAAD(got.TargetID, got.ID))
	if err != nil {
		t.Fatal(err)
	}
	if secret == "orig" {
		t.Fatal("secret was not rotated by the worker")
	}
}

// TestRotateCredentialByID proves the proxy's post-session hook rotates the
// credential and stamps rotated_at.
func TestRotateCredentialByID(t *testing.T) {
	fc := &schedFake{}
	srv, cred := newSchedTestServer(t, fc)
	srv.RotateCredentialByID(context.Background(), cred.ID)
	got, err := srv.store.GetCredential(context.Background(), cred.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.RotatedAt == nil {
		t.Fatal("RotateCredentialByID did not rotate the credential")
	}
	// A missing credential is a safe no-op (no panic).
	srv.RotateCredentialByID(context.Background(), 999999)
}

// TestRotateCredentialByIDAuditsStart proves the post-session rotation records
// an attempt (credential.rotate_started) before the external password change, so
// a crash mid-rotation leaves a detectable trail, plus credential.rotate on
// success.
func TestRotateCredentialByIDAuditsStart(t *testing.T) {
	fc := &schedFake{}
	srv, cred := newSchedTestServer(t, fc)
	srv.RotateCredentialByID(context.Background(), cred.ID)
	events, err := srv.store.ListAudit(context.Background(), 100)
	if err != nil {
		t.Fatal(err)
	}
	var started, done bool
	for _, e := range events {
		switch e.Action {
		case "credential.rotate_started":
			started = true
		case "credential.rotate":
			done = true
		}
	}
	if !started {
		t.Error("expected credential.rotate_started before the rotation")
	}
	if !done {
		t.Error("expected credential.rotate on success")
	}
}

// TestSweepExpiredCheckoutRotates proves the worker invalidates the secret of an
// expired checkout that was never checked back in.
func TestSweepExpiredCheckoutRotates(t *testing.T) {
	fc := &schedFake{}
	srv, cred := newSchedTestServer(t, fc)
	ctx := context.Background()

	// An expired, unreturned checkout (created in the past so it isn't auto-closed).
	co := &store.Checkout{CredentialID: cred.ID, TargetID: cred.TargetID, Holder: "alice", ExpiresAt: time.Now().Add(-time.Hour)}
	if err := srv.store.CreateCheckout(ctx, co, time.Now().Add(-2*time.Hour)); err != nil {
		t.Fatalf("CreateCheckout: %v", err)
	}

	if n := srv.sweepExpiredCheckouts(ctx, time.Now()); n != 1 {
		t.Fatalf("swept %d, want 1", n)
	}
	got, err := srv.store.GetCredential(ctx, cred.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.RotatedAt == nil {
		t.Fatal("expired checkout should have triggered a rotation")
	}
	if _, err := srv.store.GetActiveCheckout(ctx, cred.ID, time.Now()); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("swept checkout should be returned, got %v", err)
	}
}
