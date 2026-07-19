package api

import (
	"context"
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

func (f *schedFake) Rotate(_ context.Context, _ store.Target, _, _, newSecret string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.actual = newSecret
	return nil
}

func (f *schedFake) Verify(_ context.Context, _ store.Target, _, secret string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.actual != "" && secret != f.actual {
		return context.DeadlineExceeded // any non-nil error = drift
	}
	return nil
}

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
	enc, err := v.Encrypt(ctx, "orig", store.CredentialAAD(target.ID))
	if err != nil {
		t.Fatal(err)
	}
	cred := &store.Credential{TargetID: target.ID, Username: "root", SecretType: "password", SecretEnc: enc}
	if err := st.CreateCredential(ctx, cred); err != nil {
		t.Fatal(err)
	}
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

func TestLifecycleWorkerReconcileOnly(t *testing.T) {
	fc := &schedFake{}
	srv, _ := newSchedTestServer(t, fc)
	// maxAge 0 = report only, credential young: nothing rotated, nothing drifted.
	rep := srv.runLifecycleOnce(systemContext(context.Background()), 0, time.Now())
	if rep.Checked != 1 || rep.OutOfSync != 0 || rep.Rotated != 0 {
		t.Fatalf("reconcile-only pass = %+v", rep)
	}
}

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
	secret, err := srv.vault.Decrypt(context.Background(), got.SecretEnc, store.CredentialAAD(got.TargetID))
	if err != nil {
		t.Fatal(err)
	}
	if secret == "orig" {
		t.Fatal("secret was not rotated by the worker")
	}
}
