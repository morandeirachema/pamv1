package pgstore_test

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/morandeirachema/pamv1/internal/store"
	"github.com/morandeirachema/pamv1/internal/store/pgstore"
	"github.com/morandeirachema/pamv1/internal/store/storetest"
)

// TestPGStoreContract runs the shared store conformance suite against a live
// PostgreSQL, verifying the SQL/migrations that memstore's map-based tests can't
// reach. It skips unless PAM_TEST_DATABASE_URL points at a database (CI provides
// a postgres service; the database is truncated first for repeatability).
func TestPGStoreContract(t *testing.T) {
	url := os.Getenv("PAM_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("PAM_TEST_DATABASE_URL not set; skipping live Postgres contract test")
	}
	ctx := context.Background()

	// Open runs the embedded migrations, creating every table.
	st, err := pgstore.Open(ctx, url)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	// Start from an empty dataset so the suite's fixed names don't collide.
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if _, err := pool.Exec(ctx,
		`TRUNCATE targets, credentials, target_grants, access_requests, checkouts,
		 audit_events, users, sessions, mfa_enrollments, mfa_recovery_codes, oidc_states,
		 settings, profiles, agent_keys, broker_audit_events, broker_tokens, safes, safe_members,
		 credential_dependencies, campaigns, campaign_items, app_keys, app_secret_grants
		 RESTART IDENTITY CASCADE`); err != nil {
		t.Fatalf("truncate: %v", err)
	}

	storetest.RunStoreContract(t, st)
	storetest.RunAuditChainContract(t, st)
}

// TestPGStoreAuditChainTamperDetection proves the primary-audit chain catches a
// database-level edit against a live PostgreSQL: it appends chained events, edits
// one row's detail directly, and confirms VerifyAuditChain flags it.
func TestPGStoreAuditChainTamperDetection(t *testing.T) {
	url := os.Getenv("PAM_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("PAM_TEST_DATABASE_URL not set; skipping live Postgres audit-chain test")
	}
	ctx := context.Background()
	st, err := pgstore.Open(ctx, url)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if _, err := pool.Exec(ctx, `TRUNCATE audit_events RESTART IDENTITY`); err != nil {
		t.Fatalf("truncate: %v", err)
	}

	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	st.EnableAuditChain(key)
	for i := 0; i < 4; i++ {
		if err := st.AppendAudit(ctx, &store.AuditEvent{Actor: "a", Action: "credential.reveal", Detail: "x"}); err != nil {
			t.Fatal(err)
		}
	}
	if ok, _, err := st.VerifyAuditChain(ctx); err != nil || !ok {
		t.Fatalf("fresh chain: ok=%v err=%v", ok, err)
	}

	// Edit a row in the middle of the chain, as an attacker with DB write access would.
	if _, err := pool.Exec(ctx,
		`UPDATE audit_events SET detail = 'TAMPERED'
		 WHERE id = (SELECT id FROM audit_events WHERE hmac IS NOT NULL ORDER BY id ASC OFFSET 1 LIMIT 1)`); err != nil {
		t.Fatalf("tamper update: %v", err)
	}
	ok, brokeAt, err := st.VerifyAuditChain(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if ok || brokeAt == 0 {
		t.Fatalf("tampering not detected: ok=%v brokeAt=%d", ok, brokeAt)
	}
}

// TestPGStoreLeaderLockMutualExclusion proves the advisory-lock leader election
// is real against a live database: while one holder runs under the lock, a
// concurrent acquisition of the SAME key is refused (ran=false), and a DIFFERENT
// key is granted. Memstore can't exercise this (it always runs fn), so it lives
// in the live-Postgres suite.
func TestPGStoreLeaderLockMutualExclusion(t *testing.T) {
	url := os.Getenv("PAM_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("PAM_TEST_DATABASE_URL not set; skipping live Postgres leader-lock test")
	}
	ctx := context.Background()
	st, err := pgstore.Open(ctx, url)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	const key = int64(0x70616d5f6c6f636b) // "pam_lock"
	holding := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)

	// Holder acquires the lock and keeps it until we signal release.
	go func() {
		_, err := st.WithLeaderLock(ctx, key, func(context.Context) error {
			close(holding)
			<-release
			return nil
		})
		done <- err
	}()

	<-holding // the holder now owns the lock
	// A concurrent attempt on the same key must be refused without running fn.
	ran, err := st.WithLeaderLock(ctx, key, func(context.Context) error {
		t.Error("fn ran while another holder owned the lock")
		return nil
	})
	if err != nil {
		t.Fatalf("contended WithLeaderLock: unexpected err %v", err)
	}
	if ran {
		t.Fatal("contended WithLeaderLock: want ran=false (lock held), got true")
	}
	// A different key is independent and is granted.
	if ran, err := st.WithLeaderLock(ctx, key+1, func(context.Context) error { return nil }); err != nil || !ran {
		t.Fatalf("different-key WithLeaderLock: ran=%v err=%v", ran, err)
	}

	close(release) // let the holder finish and drop the lock
	if err := <-done; err != nil {
		t.Fatalf("holder WithLeaderLock: %v", err)
	}
	// Once released, the key is acquirable again.
	if ran, err := st.WithLeaderLock(ctx, key, func(context.Context) error { return nil }); err != nil || !ran {
		t.Fatalf("post-release WithLeaderLock: ran=%v err=%v", ran, err)
	}
}
