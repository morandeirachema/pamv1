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
	// ListMFAEnrollments must preserve last_totp_step too (a KEK-rotation re-Upsert
	// of a listed enrollment would otherwise reset the anti-replay counter to 0).
	if es, err := st.ListMFAEnrollments(ctx); err != nil || len(es) != 1 || es[0].LastTOTPStep != 101 {
		t.Fatalf("ListMFAEnrollments last step = %v err %v; want [101]", es, err)
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

	// --- ListUsers ---
	if err := st.CreateUser(ctx, &store.User{Username: "list-check", Role: "auditor", TokenHash: "listuserhash"}); err != nil {
		t.Fatalf("CreateUser(list): %v", err)
	}
	if users, err := st.ListUsers(ctx); err != nil || len(users) == 0 {
		t.Fatalf("ListUsers: %d users, err %v", len(users), err)
	}

	// --- delete cascades (memstore hand-codes what pgstore FK ON DELETE CASCADE does; assert parity) ---
	checkoutGone := func(credID int64) bool {
		cos, _ := st.ListCheckouts(ctx, false, now)
		for _, c := range cos {
			if c.CredentialID == credID {
				return false
			}
		}
		return true
	}
	casc := &store.Target{Name: "cascade-tgt", Host: "h", OSType: "linux", Protocol: "ssh"}
	if err := st.CreateTarget(ctx, casc); err != nil {
		t.Fatalf("CreateTarget(cascade): %v", err)
	}
	cc := &store.Credential{TargetID: casc.ID, Username: "root", SecretType: "password", SecretEnc: "v2:x"}
	if err := st.CreateCredential(ctx, cc); err != nil {
		t.Fatalf("CreateCredential(cascade): %v", err)
	}
	if err := st.CreateTargetGrant(ctx, &store.TargetGrant{TargetID: casc.ID, SubjectType: "role", Subject: "user"}); err != nil {
		t.Fatalf("CreateTargetGrant(cascade): %v", err)
	}
	if err := st.CreateCheckout(ctx, &store.Checkout{CredentialID: cc.ID, TargetID: casc.ID, Holder: "h", ExpiresAt: future}, now); err != nil {
		t.Fatalf("CreateCheckout(cascade): %v", err)
	}
	// Deleting the target cascades to its credentials, grants and checkouts.
	if err := st.DeleteTarget(ctx, casc.ID); err != nil {
		t.Fatalf("DeleteTarget: %v", err)
	}
	if _, err := st.GetCredential(ctx, cc.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("credential was not cascaded on target delete")
	}
	if g, _ := st.ListTargetGrants(ctx, casc.ID); len(g) != 0 {
		t.Fatalf("grants not cascaded on target delete: %d", len(g))
	}
	if !checkoutGone(cc.ID) {
		t.Fatal("checkout not cascaded on target delete")
	}

	// Deleting a credential cascades its checkouts.
	casc2 := &store.Target{Name: "cascade-tgt2", Host: "h", OSType: "linux", Protocol: "ssh"}
	if err := st.CreateTarget(ctx, casc2); err != nil {
		t.Fatal(err)
	}
	cc2 := &store.Credential{TargetID: casc2.ID, Username: "root", SecretType: "password", SecretEnc: "v2:x"}
	if err := st.CreateCredential(ctx, cc2); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateCheckout(ctx, &store.Checkout{CredentialID: cc2.ID, TargetID: casc2.ID, Holder: "h", ExpiresAt: future}, now); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteCredential(ctx, cc2.ID); err != nil {
		t.Fatalf("DeleteCredential: %v", err)
	}
	if !checkoutGone(cc2.ID) {
		t.Fatal("checkout not cascaded on credential delete")
	}

	// --- settings (config overrides, Phase 12) ---
	if _, err := st.GetSetting(ctx, "PAM_MFA_REQUIRED"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("GetSetting(missing): want ErrNotFound, got %v", err)
	}
	if err := st.PutSetting(ctx, &store.Setting{Key: "PAM_MFA_REQUIRED", Value: "true"}); err != nil {
		t.Fatalf("PutSetting: %v", err)
	}
	if err := st.PutSetting(ctx, &store.Setting{Key: "PAM_MFA_REQUIRED", Value: "false"}); err != nil { // upsert
		t.Fatalf("PutSetting(upsert): %v", err)
	}
	if got, err := st.GetSetting(ctx, "PAM_MFA_REQUIRED"); err != nil || got.Value != "false" {
		t.Fatalf("GetSetting: %+v err %v", got, err)
	}
	if err := st.PutSetting(ctx, &store.Setting{Key: "PAM_LDAP_BIND_PASSWORD", Value: "v2:enc", Secret: true}); err != nil {
		t.Fatalf("PutSetting(secret): %v", err)
	}
	if ss, err := st.ListSettings(ctx); err != nil || len(ss) != 2 {
		t.Fatalf("ListSettings: %d err %v", len(ss), err)
	}
	if err := st.DeleteSetting(ctx, "PAM_MFA_REQUIRED"); err != nil {
		t.Fatalf("DeleteSetting: %v", err)
	}
	if _, err := st.GetSetting(ctx, "PAM_MFA_REQUIRED"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("deleted setting must be gone")
	}

	// --- profiles (custom RBAC, Phase 12) ---
	if _, err := st.GetProfile(ctx, "nope"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("GetProfile(missing): want ErrNotFound, got %v", err)
	}
	prof := &store.Profile{Name: "readonly", Capabilities: []string{"read_inventory", "read_audit"}}
	if err := st.CreateProfile(ctx, prof); err != nil {
		t.Fatalf("CreateProfile: %v", err)
	}
	if err := st.CreateProfile(ctx, &store.Profile{Name: "readonly"}); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("duplicate profile: want ErrConflict, got %v", err)
	}
	if got, err := st.GetProfile(ctx, "readonly"); err != nil || len(got.Capabilities) != 2 || got.Capabilities[0] != "read_inventory" {
		t.Fatalf("GetProfile: %+v err %v", got, err)
	}
	if ps, err := st.ListProfiles(ctx); err != nil || len(ps) != 1 {
		t.Fatalf("ListProfiles: %d err %v", len(ps), err)
	}
	if err := st.DeleteProfile(ctx, prof.ID); err != nil {
		t.Fatalf("DeleteProfile: %v", err)
	}
	if _, err := st.GetProfile(ctx, "readonly"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("deleted profile must be gone")
	}

	// --- agent keys + broker audit chain (Phase 13) ---
	if head, err := st.GetBrokerAuditHead(ctx); err != nil || head != nil {
		t.Fatalf("GetBrokerAuditHead(empty): head=%v err=%v", head, err)
	}
	ak := &store.AgentKey{Name: "bot", Owner: "alice", TokenHash: "agenthash1"}
	if err := st.CreateAgentKey(ctx, ak); err != nil {
		t.Fatalf("CreateAgentKey: %v", err)
	}
	if got, err := st.GetAgentKeyByTokenHash(ctx, "agenthash1"); err != nil || got.Name != "bot" || got.Owner != "alice" {
		t.Fatalf("GetAgentKeyByTokenHash: %+v err %v", got, err)
	}
	if _, err := st.GetAgentKeyByTokenHash(ctx, "nope"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("GetAgentKeyByTokenHash(missing): want ErrNotFound, got %v", err)
	}
	if err := st.CreateAgentKey(ctx, &store.AgentKey{Name: "off", TokenHash: "agenthash2", Disabled: true}); err != nil {
		t.Fatalf("CreateAgentKey(disabled): %v", err)
	}
	if _, err := st.GetAgentKeyByTokenHash(ctx, "agenthash2"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("a disabled agent key must not resolve")
	}
	if keys, err := st.ListAgentKeys(ctx); err != nil || len(keys) != 2 {
		t.Fatalf("ListAgentKeys: %d err %v", len(keys), err)
	}
	if err := st.DeleteAgentKey(ctx, ak.ID); err != nil {
		t.Fatalf("DeleteAgentKey: %v", err)
	}
	if _, err := st.GetAgentKeyByTokenHash(ctx, "agenthash1"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("a deleted agent key must not resolve")
	}

	// Broker audit is append-only; head follows the latest, list is chain order.
	e1 := &store.BrokerAuditEvent{Actor: "bot", Action: "broker.tool_call.executed", Detail: "one", PrevHash: []byte{}, HMAC: []byte{0x01}}
	if err := st.AppendBrokerAudit(ctx, e1); err != nil {
		t.Fatalf("AppendBrokerAudit: %v", err)
	}
	e2 := &store.BrokerAuditEvent{Actor: "bot", Action: "broker.tool_call.denied", Detail: "two", PrevHash: []byte{0x01}, HMAC: []byte{0x02}}
	if err := st.AppendBrokerAudit(ctx, e2); err != nil {
		t.Fatalf("AppendBrokerAudit: %v", err)
	}
	if head, err := st.GetBrokerAuditHead(ctx); err != nil || head == nil || head.Detail != "two" {
		t.Fatalf("GetBrokerAuditHead: %+v err %v", head, err)
	}
	all, err := st.ListBrokerAudit(ctx, 0)
	if err != nil || len(all) != 2 || all[0].Detail != "one" || all[1].Detail != "two" {
		t.Fatalf("ListBrokerAudit: %+v err %v", all, err)
	}
	if len(all[0].HMAC) != 1 || all[0].HMAC[0] != 0x01 {
		t.Fatalf("broker audit HMAC not round-tripped: %v", all[0].HMAC)
	}

	// --- broker single-use resume tokens (Phase 13) ---
	if err := st.CreateBrokerToken(ctx, &store.BrokerToken{JTI: "jti-1", CallID: "call_abc", ExpiresAt: time.Now().Add(time.Hour).UTC()}); err != nil {
		t.Fatalf("CreateBrokerToken: %v", err)
	}
	// A duplicate JTI is a conflict in both stores (not a silent overwrite).
	if err := st.CreateBrokerToken(ctx, &store.BrokerToken{JTI: "jti-1", CallID: "call_other", ExpiresAt: time.Now().Add(time.Hour).UTC()}); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("CreateBrokerToken(dup): want ErrConflict, got %v", err)
	}
	// First consume wins and returns the bound call id.
	if cid, err := st.ConsumeBrokerToken(ctx, "jti-1"); err != nil || cid != "call_abc" {
		t.Fatalf("ConsumeBrokerToken: cid=%q err=%v", cid, err)
	}
	// A second consume of the same token fails — single-use.
	if _, err := st.ConsumeBrokerToken(ctx, "jti-1"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("ConsumeBrokerToken(reuse): want ErrNotFound, got %v", err)
	}
	// An unknown token fails.
	if _, err := st.ConsumeBrokerToken(ctx, "jti-nope"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("ConsumeBrokerToken(unknown): want ErrNotFound, got %v", err)
	}
	// An expired token cannot be consumed.
	if err := st.CreateBrokerToken(ctx, &store.BrokerToken{JTI: "jti-exp", CallID: "call_x", ExpiresAt: time.Now().Add(-time.Minute).UTC()}); err != nil {
		t.Fatalf("CreateBrokerToken(expired): %v", err)
	}
	if _, err := st.ConsumeBrokerToken(ctx, "jti-exp"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("ConsumeBrokerToken(expired): want ErrNotFound, got %v", err)
	}

	// Peek returns the bound call id WITHOUT spending the token (repeatable), then
	// Consume spends it and Peek reports it gone.
	if err := st.CreateBrokerToken(ctx, &store.BrokerToken{JTI: "jti-peek", CallID: "call_peek", ExpiresAt: time.Now().Add(time.Hour).UTC()}); err != nil {
		t.Fatalf("CreateBrokerToken(peek): %v", err)
	}
	for i := 0; i < 2; i++ {
		if cid, err := st.PeekBrokerToken(ctx, "jti-peek"); err != nil || cid != "call_peek" {
			t.Fatalf("PeekBrokerToken (unspent): cid=%q err=%v", cid, err)
		}
	}
	if _, err := st.ConsumeBrokerToken(ctx, "jti-peek"); err != nil {
		t.Fatalf("ConsumeBrokerToken(peek): %v", err)
	}
	if _, err := st.PeekBrokerToken(ctx, "jti-peek"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("PeekBrokerToken(spent): want ErrNotFound, got %v", err)
	}

	// GC removes spent + expired tokens; an unexpired unused one survives.
	if err := st.CreateBrokerToken(ctx, &store.BrokerToken{JTI: "jti-live", CallID: "call_live", ExpiresAt: time.Now().Add(time.Hour).UTC()}); err != nil {
		t.Fatalf("CreateBrokerToken(live): %v", err)
	}
	if n, err := st.DeleteExpiredBrokerTokens(ctx); err != nil || n < 1 {
		t.Fatalf("DeleteExpiredBrokerTokens: n=%d err=%v", n, err)
	}
	if cid, err := st.PeekBrokerToken(ctx, "jti-live"); err != nil || cid != "call_live" {
		t.Fatalf("GC removed a live token: cid=%q err=%v", cid, err)
	}
}
