package pgstore_test

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
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
}
