// Package storetest provides a reusable conformance suite for the store.Store
// contract. Both memstore and pgstore run RunStoreContract against a fresh,
// empty store so the two implementations are held to identical behavior — and so
// the PostgreSQL SQL (which memstore's map-based tests can't exercise) is
// actually verified against a live database in CI.
package storetest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/morandeirachema/pamv1/internal/store"
)

// RunStoreContract exercises the full Store interface against an empty st,
// asserting the shared semantics (IDs populated, sentinel errors, expiry,
// exclusivity, single-use consumption).
func RunStoreContract(t *testing.T, st store.Store) {
	t.Helper()
	ctx := context.Background()
	now := time.Now()
	future := now.Add(time.Hour)

	if err := st.Ping(ctx); err != nil {
		t.Fatalf("Ping: %v", err)
	}

	// --- targets ---
	tgt := &store.Target{Name: "web-01", Host: "10.0.0.5", Port: 22, OSType: "linux", Protocol: "ssh", RequireApproval: true}
	if err := st.CreateTarget(ctx, tgt); err != nil {
		t.Fatalf("CreateTarget: %v", err)
	}
	if tgt.ID == 0 || tgt.CreatedAt.IsZero() {
		t.Fatal("CreateTarget did not populate ID/CreatedAt")
	}
	if got, err := st.GetTarget(ctx, tgt.ID); err != nil || !got.RequireApproval {
		t.Fatalf("GetTarget require_approval: %+v err %v", got, err)
	}
	if err := st.CreateTarget(ctx, &store.Target{Name: "web-01", Host: "x", Port: 22, OSType: "linux", Protocol: "ssh"}); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("duplicate target name: want ErrConflict, got %v", err)
	}
	if ts, err := st.ListTargets(ctx); err != nil || len(ts) != 1 {
		t.Fatalf("ListTargets: %d err %v", len(ts), err)
	}
	if _, err := st.GetTarget(ctx, 99999); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("GetTarget missing: want ErrNotFound, got %v", err)
	}

	// --- credentials ---
	cred := &store.Credential{TargetID: tgt.ID, Username: "root", SecretType: "password", SecretEnc: "v2:one"}
	if err := st.CreateCredential(ctx, cred); err != nil {
		t.Fatalf("CreateCredential: %v", err)
	}
	if err := st.CreateCredential(ctx, &store.Credential{TargetID: 99999, Username: "x", SecretType: "password", SecretEnc: "v2:z"}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("credential for missing target: want ErrNotFound, got %v", err)
	}
	if cs, err := st.ListCredentials(ctx, tgt.ID); err != nil || len(cs) != 1 {
		t.Fatalf("ListCredentials: %d err %v", len(cs), err)
	}
	if err := st.RotateCredentialSecret(ctx, cred.ID, "v2:two", now); err != nil {
		t.Fatalf("RotateCredentialSecret: %v", err)
	}
	got, _ := st.GetCredential(ctx, cred.ID)
	if got.SecretEnc != "v2:two" || got.RotatedAt == nil {
		t.Fatalf("after rotate: secret=%q rotated_at=%v", got.SecretEnc, got.RotatedAt)
	}
	if err := st.UpdateCredentialSecretEnc(ctx, cred.ID, "v2:three"); err != nil {
		t.Fatalf("UpdateCredentialSecretEnc: %v", err)
	}
	got, _ = st.GetCredential(ctx, cred.ID)
	if got.SecretEnc != "v2:three" || got.RotatedAt == nil {
		t.Fatal("UpdateCredentialSecretEnc must not clear rotated_at")
	}

	// --- grants ---
	g := &store.TargetGrant{TargetID: tgt.ID, SubjectType: "user", Subject: "alice"}
	if err := st.CreateTargetGrant(ctx, g); err != nil {
		t.Fatalf("CreateTargetGrant: %v", err)
	}
	if err := st.CreateTargetGrant(ctx, &store.TargetGrant{TargetID: tgt.ID, SubjectType: "user", Subject: "alice"}); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("duplicate grant: want ErrConflict, got %v", err)
	}
	if gs, err := st.ListTargetGrants(ctx, tgt.ID); err != nil || len(gs) != 1 {
		t.Fatalf("ListTargetGrants: %d err %v", len(gs), err)
	}
	if err := st.DeleteTargetGrant(ctx, g.ID); err != nil {
		t.Fatalf("DeleteTargetGrant: %v", err)
	}

	// --- access requests (4-eyes) ---
	ar := &store.AccessRequest{Requester: "alice", TargetID: tgt.ID, Reason: "patch", Status: "pending", ExpiresAt: future}
	if err := st.CreateAccessRequest(ctx, ar); err != nil {
		t.Fatalf("CreateAccessRequest: %v", err)
	}
	if ok, _ := st.HasActiveApproval(ctx, "alice", tgt.ID, now); ok {
		t.Fatal("pending request must not count as an active approval")
	}
	if err := st.DecideAccessRequest(ctx, ar.ID, "approved", "bob", now); err != nil {
		t.Fatalf("DecideAccessRequest: %v", err)
	}
	if a, _ := st.GetAccessRequest(ctx, ar.ID); a.Status != "approved" || a.Approver != "bob" || a.DecidedAt == nil {
		t.Fatalf("decided request: %+v", a)
	}
	if ok, _ := st.HasActiveApproval(ctx, "alice", tgt.ID, now); !ok {
		t.Fatal("approved unexpired request must be active")
	}
	if ok, _ := st.HasActiveApproval(ctx, "alice", tgt.ID, future.Add(time.Minute)); ok {
		t.Fatal("expired approval must not be active")
	}
	if reqs, err := st.ListAccessRequests(ctx, "approved"); err != nil || len(reqs) != 1 {
		t.Fatalf("ListAccessRequests(approved): %d err %v", len(reqs), err)
	}

	// --- checkouts (exclusive lease) ---
	co := &store.Checkout{CredentialID: cred.ID, TargetID: tgt.ID, Holder: "alice", ExpiresAt: future}
	if err := st.CreateCheckout(ctx, co, now); err != nil {
		t.Fatalf("CreateCheckout: %v", err)
	}
	if err := st.CreateCheckout(ctx, &store.Checkout{CredentialID: cred.ID, TargetID: tgt.ID, Holder: "eve", ExpiresAt: future}, now); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("double checkout: want ErrConflict, got %v", err)
	}
	if active, err := st.GetActiveCheckout(ctx, cred.ID, now); err != nil || active.Holder != "alice" {
		t.Fatalf("GetActiveCheckout: %+v err %v", active, err)
	}
	if err := st.CheckinCheckout(ctx, co.ID, now); err != nil {
		t.Fatalf("CheckinCheckout: %v", err)
	}
	if _, err := st.GetActiveCheckout(ctx, cred.ID, now); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("after checkin: want ErrNotFound, got %v", err)
	}
	if err := st.CreateCheckout(ctx, &store.Checkout{CredentialID: cred.ID, TargetID: tgt.ID, Holder: "carol", ExpiresAt: future}, now); err != nil {
		t.Fatalf("re-checkout after checkin: %v", err)
	}
	if all, err := st.ListCheckouts(ctx, false, now); err != nil || len(all) != 2 {
		t.Fatalf("ListCheckouts(all): %d err %v", len(all), err)
	}
	if act, err := st.ListCheckouts(ctx, true, now); err != nil || len(act) != 1 {
		t.Fatalf("ListCheckouts(active): %d err %v", len(act), err)
	}
	// An expired-but-unreturned lease must not block a new checkout, and it is no
	// longer the active one.
	carol, err := st.GetActiveCheckout(ctx, cred.ID, now)
	if err != nil {
		t.Fatalf("GetActiveCheckout(carol): %v", err)
	}
	if err := st.CheckinCheckout(ctx, carol.ID, now); err != nil {
		t.Fatalf("checkin carol: %v", err)
	}
	if err := st.CreateCheckout(ctx, &store.Checkout{CredentialID: cred.ID, TargetID: tgt.ID, Holder: "stale", ExpiresAt: now.Add(-time.Hour)}, now); err != nil {
		t.Fatalf("create expired lease: %v", err)
	}
	if err := st.CreateCheckout(ctx, &store.Checkout{CredentialID: cred.ID, TargetID: tgt.ID, Holder: "fresh", ExpiresAt: future}, now); err != nil {
		t.Fatalf("checkout over an expired lease should succeed, got %v", err)
	}
	if active, err := st.GetActiveCheckout(ctx, cred.ID, now); err != nil || active.Holder != "fresh" {
		t.Fatalf("active checkout after expiry = %+v err %v, want holder fresh", active, err)
	}

	// --- audit + export ---
	if err := st.AppendAudit(ctx, &store.AuditEvent{Actor: "tester", Action: "unit.test", Detail: "hello"}); err != nil {
		t.Fatalf("AppendAudit: %v", err)
	}
	if evs, err := st.ListAudit(ctx, 10); err != nil || len(evs) == 0 {
		t.Fatalf("ListAudit: %d err %v", len(evs), err)
	}
	if evs, err := st.ExportAudit(ctx, time.Time{}, future); err != nil || len(evs) == 0 {
		t.Fatalf("ExportAudit: %d err %v", len(evs), err)
	}

	// --- users ---
	u := &store.User{Username: "u1", Role: "admin", TokenHash: "tokhash1"}
	if err := st.CreateUser(ctx, u); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := st.CreateUser(ctx, &store.User{Username: "u1", Role: "user", TokenHash: "x"}); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("duplicate username: want ErrConflict, got %v", err)
	}
	if err := st.CreateUser(ctx, &store.User{Username: "u2", Role: "user", TokenHash: "tokhash1"}); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("duplicate token hash: want ErrConflict, got %v", err)
	}
	if by, err := st.GetUserByTokenHash(ctx, "tokhash1"); err != nil || by.Username != "u1" {
		t.Fatalf("GetUserByTokenHash: %+v err %v", by, err)
	}
	if _, err := st.GetUserByTokenHash(ctx, "nope"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("GetUserByTokenHash missing: want ErrNotFound, got %v", err)
	}
	if err := st.DeleteUser(ctx, u.ID); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}

	// --- sessions (with expiry) ---
	sess := &store.Session{Username: "u1", Role: "admin", TokenHash: "sesshash", ExpiresAt: future}
	if err := st.CreateSession(ctx, sess); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if s, err := st.GetSessionByTokenHash(ctx, "sesshash"); err != nil || s.Username != "u1" {
		t.Fatalf("GetSessionByTokenHash: %+v err %v", s, err)
	}
	if err := st.CreateSession(ctx, &store.Session{Username: "u1", Role: "admin", TokenHash: "expired", ExpiresAt: now.Add(-time.Hour)}); err != nil {
		t.Fatalf("CreateSession(expired): %v", err)
	}
	if _, err := st.GetSessionByTokenHash(ctx, "expired"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expired session: want ErrNotFound, got %v", err)
	}
	if err := st.DeleteSession(ctx, "sesshash"); err != nil {
		t.Fatalf("DeleteSession: %v", err)
	}

	// --- MFA enrollment + recovery codes ---
	if err := st.UpsertMFAEnrollment(ctx, &store.MFAEnrollment{Username: "u1", SecretEnc: "v2:totp", Confirmed: false}); err != nil {
		t.Fatalf("UpsertMFAEnrollment: %v", err)
	}
	if err := st.UpsertMFAEnrollment(ctx, &store.MFAEnrollment{Username: "u1", SecretEnc: "v2:totp", Confirmed: true}); err != nil {
		t.Fatalf("UpsertMFAEnrollment(confirm): %v", err)
	}
	if e, err := st.GetMFAEnrollment(ctx, "u1"); err != nil || !e.Confirmed {
		t.Fatalf("GetMFAEnrollment: %+v err %v", e, err)
	}
	if es, err := st.ListMFAEnrollments(ctx); err != nil || len(es) != 1 {
		t.Fatalf("ListMFAEnrollments: %d err %v", len(es), err)
	}
	// TOTP anti-replay: a step is accepted once, then rejected; a newer step wins.
	if ok, err := st.ConsumeTOTPStep(ctx, "u1", 100); err != nil || !ok {
		t.Fatalf("ConsumeTOTPStep(100) = %v, %v; want true", ok, err)
	}
	if ok, err := st.ConsumeTOTPStep(ctx, "u1", 100); err != nil || ok {
		t.Fatalf("ConsumeTOTPStep(100) replay = %v, %v; want false", ok, err)
	}
	if ok, err := st.ConsumeTOTPStep(ctx, "u1", 101); err != nil || !ok {
		t.Fatalf("ConsumeTOTPStep(101) = %v, %v; want true", ok, err)
	}
	if e, err := st.GetMFAEnrollment(ctx, "u1"); err != nil || e.LastTOTPStep != 101 {
		t.Fatalf("GetMFAEnrollment last step = %d err %v; want 101", e.LastTOTPStep, err)
	}
	if err := st.ReplaceMFARecoveryCodes(ctx, "u1", []string{"h1", "h2"}); err != nil {
		t.Fatalf("ReplaceMFARecoveryCodes: %v", err)
	}
	if n, _ := st.CountMFARecoveryCodes(ctx, "u1"); n != 2 {
		t.Fatalf("CountMFARecoveryCodes: got %d, want 2", n)
	}
	if ok, err := st.ConsumeMFARecoveryCode(ctx, "u1", "h1"); err != nil || !ok {
		t.Fatalf("ConsumeMFARecoveryCode: ok=%v err=%v", ok, err)
	}
	if ok, _ := st.ConsumeMFARecoveryCode(ctx, "u1", "h1"); ok {
		t.Fatal("recovery code must be single-use")
	}
	if n, _ := st.CountMFARecoveryCodes(ctx, "u1"); n != 1 {
		t.Fatalf("after consume: got %d, want 1", n)
	}
	if err := st.DeleteMFAEnrollment(ctx, "u1"); err != nil {
		t.Fatalf("DeleteMFAEnrollment: %v", err)
	}

	// --- OIDC login state (single-use, expiry) ---
	if err := st.PutOIDCState(ctx, "state1", "verifier1", "nonce1", future); err != nil {
		t.Fatalf("PutOIDCState: %v", err)
	}
	v, n, ok, err := st.TakeOIDCState(ctx, "state1", now)
	if err != nil || !ok || v != "verifier1" || n != "nonce1" {
		t.Fatalf("TakeOIDCState: v=%q n=%q ok=%v err=%v", v, n, ok, err)
	}
	if _, _, ok, _ := st.TakeOIDCState(ctx, "state1", now); ok {
		t.Fatal("OIDC state must be single-use")
	}
	if err := st.PutOIDCState(ctx, "state2", "v", "n", now.Add(-time.Minute)); err != nil {
		t.Fatalf("PutOIDCState(expired): %v", err)
	}
	if _, _, ok, _ := st.TakeOIDCState(ctx, "state2", now); ok {
		t.Fatal("expired OIDC state must not be returned")
	}
}
