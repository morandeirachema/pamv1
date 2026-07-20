// Package pgstore implements store.Store on PostgreSQL via pgx. Embedded,
// versioned migrations (migrations/*.sql, tracked in schema_migrations) are
// applied in order on startup.
package pgstore

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/morandeirachema/pamv1/internal/logging"
	"github.com/morandeirachema/pamv1/internal/store"
)

const (
	pgUniqueViolation     = "23505"
	pgForeignKeyViolation = "23503"
)

type PGStore struct {
	pool *pgxpool.Pool
	log  *slog.Logger
}

// Open connects to the Postgres database at url, verifies connectivity, applies
// pending migrations, and returns a ready PGStore.
func Open(ctx context.Context, url string) (*PGStore, error) {
	log := logging.Component("store")
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, err
	}
	// Trace every query at debug level (SQL text + duration + rows, never
	// arguments — those could carry ciphertext or token hashes).
	cfg.ConnConfig.Tracer = queryTracer{log: log}

	// HA resilience: after a CloudNativePG (or managed-Postgres) failover the
	// read-write endpoint re-points to a new primary, so recycle connections and
	// health-check idle ones — otherwise the pool would keep handing out
	// connections stapled to the demoted/dead primary. Callers only override
	// these by putting pool_* params in the URL (ParseConfig already applied them).
	if cfg.MaxConnLifetime == 0 {
		cfg.MaxConnLifetime = 30 * time.Minute
	}
	if cfg.MaxConnIdleTime == 0 {
		cfg.MaxConnIdleTime = 5 * time.Minute
	}
	if cfg.HealthCheckPeriod == 0 {
		cfg.HealthCheckPeriod = time.Minute
	}

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	if err := migrate(ctx, pool); err != nil {
		pool.Close()
		return nil, err
	}
	log.Info("connected to postgres", "host", cfg.ConnConfig.Host, "db", cfg.ConnConfig.Database)
	return &PGStore{pool: pool, log: log}, nil
}

// queryTracer logs each SQL statement's outcome. It implements pgx.QueryTracer.
type queryTracer struct{ log *slog.Logger }

type qtCtxKey struct{}

type qtState struct {
	start time.Time
	sql   string
}

// TraceQueryStart stashes the query text and start time in the context for
// TraceQueryEnd to log.
func (t queryTracer) TraceQueryStart(ctx context.Context, _ *pgx.Conn, d pgx.TraceQueryStartData) context.Context {
	return context.WithValue(ctx, qtCtxKey{}, qtState{start: time.Now(), sql: d.SQL})
}

// TraceQueryEnd logs the completed query's collapsed SQL, rows affected, and
// duration (errors other than no-rows are logged at error level).
func (t queryTracer) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, d pgx.TraceQueryEndData) {
	st, _ := ctx.Value(qtCtxKey{}).(qtState)
	sql := strings.Join(strings.Fields(st.sql), " ") // collapse whitespace to one line
	if len(sql) > 120 {
		sql = sql[:120] + "…"
	}
	if d.Err != nil && !errors.Is(d.Err, pgx.ErrNoRows) {
		t.log.Error("query failed", "sql", sql, "err", d.Err)
		return
	}
	t.log.Debug("query", "sql", sql, "rows", d.CommandTag.RowsAffected(),
		"dur_ms", time.Since(st.start).Milliseconds())
}

// pgCode returns the PostgreSQL SQLSTATE code of err, or "" if err is not a pg error.
func pgCode(err error) string {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code
	}
	return ""
}

// getOne runs a single-row query, scanning with scan, and maps pgx.ErrNoRows to
// store.ErrNotFound — the shared shape of every Get* lookup.
func getOne[T any](ctx context.Context, pool *pgxpool.Pool, scan func(pgx.CollectableRow) (T, error), sql string, args ...any) (*T, error) {
	rows, err := pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	v, err := pgx.CollectExactlyOneRow(rows, scan)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &v, nil
}

// execExpectingRow runs an Exec that must affect a row, returning
// store.ErrNotFound when it affects none — the shared shape of Delete* and
// single-row Update* methods.
func execExpectingRow(ctx context.Context, pool *pgxpool.Pool, sql string, args ...any) error {
	tag, err := pool.Exec(ctx, sql, args...)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	return nil
}

// CreateTarget inserts a target, populating its ID and CreatedAt; ErrConflict if the name is taken.
func (s *PGStore) CreateTarget(ctx context.Context, t *store.Target) error {
	err := s.pool.QueryRow(ctx,
		`INSERT INTO targets (name, host, port, os_type, protocol, require_approval)
		 VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, created_at`,
		t.Name, t.Host, t.Port, t.OSType, t.Protocol, t.RequireApproval,
	).Scan(&t.ID, &t.CreatedAt)
	if pgCode(err) == pgUniqueViolation {
		return store.ErrConflict
	}
	return err
}

// ListTargets returns all targets ordered by ID.
func (s *PGStore) ListTargets(ctx context.Context) ([]store.Target, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, name, host, port, os_type, protocol, require_approval, created_at
		 FROM targets ORDER BY id`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, scanTarget)
}

// GetTarget returns the target with the given ID, or ErrNotFound.
func (s *PGStore) GetTarget(ctx context.Context, id int64) (*store.Target, error) {
	return getOne(ctx, s.pool, scanTarget,
		`SELECT id, name, host, port, os_type, protocol, require_approval, created_at
		 FROM targets WHERE id = $1`, id)
}

// DeleteTarget removes a target by ID (cascading via FK constraints); ErrNotFound if absent.
func (s *PGStore) DeleteTarget(ctx context.Context, id int64) error {
	return execExpectingRow(ctx, s.pool, `DELETE FROM targets WHERE id = $1`, id)
}

// CreateCredential inserts a credential, populating its ID and CreatedAt;
// ErrNotFound if the target does not exist.
func (s *PGStore) CreateCredential(ctx context.Context, c *store.Credential) error {
	err := s.pool.QueryRow(ctx,
		`INSERT INTO credentials (target_id, username, secret_type, secret_enc)
		 VALUES ($1, $2, $3, $4) RETURNING id, created_at`,
		c.TargetID, c.Username, c.SecretType, c.SecretEnc,
	).Scan(&c.ID, &c.CreatedAt)
	if pgCode(err) == pgForeignKeyViolation {
		return store.ErrNotFound
	}
	return err
}

// ListCredentials returns credentials for one target, or all when targetID is 0,
// ordered by ID.
func (s *PGStore) ListCredentials(ctx context.Context, targetID int64) ([]store.Credential, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, target_id, username, secret_type, secret_enc, created_at, rotated_at
		 FROM credentials WHERE ($1 = 0 OR target_id = $1) ORDER BY id`, targetID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, scanCredential)
}

// GetCredential returns the credential with the given ID, or ErrNotFound.
func (s *PGStore) GetCredential(ctx context.Context, id int64) (*store.Credential, error) {
	return getOne(ctx, s.pool, scanCredential,
		`SELECT id, target_id, username, secret_type, secret_enc, created_at, rotated_at
		 FROM credentials WHERE id = $1`, id)
}

// UpdateCredentialSecretEnc replaces a credential's encrypted secret without
// touching rotated_at; ErrNotFound if absent.
func (s *PGStore) UpdateCredentialSecretEnc(ctx context.Context, id int64, secretEnc string) error {
	return execExpectingRow(ctx, s.pool, `UPDATE credentials SET secret_enc = $1 WHERE id = $2`, secretEnc, id)
}

// RotateCredentialSecret replaces the encrypted secret and stamps rotated_at;
// ErrNotFound if absent.
func (s *PGStore) RotateCredentialSecret(ctx context.Context, id int64, secretEnc string, rotatedAt time.Time) error {
	return execExpectingRow(ctx, s.pool,
		`UPDATE credentials SET secret_enc = $1, rotated_at = $2 WHERE id = $3`, secretEnc, rotatedAt.UTC(), id)
}

// CreateTargetGrant adds a grant, populating its ID; ErrConflict if an identical
// grant exists, ErrNotFound if the target is missing.
func (s *PGStore) CreateTargetGrant(ctx context.Context, g *store.TargetGrant) error {
	err := s.pool.QueryRow(ctx,
		`INSERT INTO target_grants (target_id, subject_type, subject) VALUES ($1, $2, $3) RETURNING id`,
		g.TargetID, g.SubjectType, g.Subject,
	).Scan(&g.ID)
	switch pgCode(err) {
	case pgUniqueViolation:
		return store.ErrConflict
	case pgForeignKeyViolation:
		return store.ErrNotFound
	}
	return err
}

// ListTargetGrants returns the grants for a target, ordered by ID.
func (s *PGStore) ListTargetGrants(ctx context.Context, targetID int64) ([]store.TargetGrant, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, target_id, subject_type, subject FROM target_grants WHERE target_id = $1 ORDER BY id`, targetID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (store.TargetGrant, error) {
		var g store.TargetGrant
		err := row.Scan(&g.ID, &g.TargetID, &g.SubjectType, &g.Subject)
		return g, err
	})
}

// DeleteTargetGrant removes a grant by ID; ErrNotFound if absent.
func (s *PGStore) DeleteTargetGrant(ctx context.Context, id int64) error {
	return execExpectingRow(ctx, s.pool, `DELETE FROM target_grants WHERE id = $1`, id)
}

// DeleteCredential removes a credential by ID; ErrNotFound if absent.
func (s *PGStore) DeleteCredential(ctx context.Context, id int64) error {
	return execExpectingRow(ctx, s.pool, `DELETE FROM credentials WHERE id = $1`, id)
}

// CreateAccessRequest inserts a request (defaulting status to pending),
// populating its ID and CreatedAt; ErrNotFound if the target is missing.
func (s *PGStore) CreateAccessRequest(ctx context.Context, ar *store.AccessRequest) error {
	if ar.Status == "" {
		ar.Status = "pending"
	}
	err := s.pool.QueryRow(ctx,
		`INSERT INTO access_requests (requester, target_id, reason, status, expires_at)
		 VALUES ($1, $2, $3, $4, $5) RETURNING id, created_at`,
		ar.Requester, ar.TargetID, ar.Reason, ar.Status, ar.ExpiresAt,
	).Scan(&ar.ID, &ar.CreatedAt)
	if pgCode(err) == pgForeignKeyViolation {
		return store.ErrNotFound
	}
	return err
}

// GetAccessRequest returns the access request with the given ID, or ErrNotFound.
func (s *PGStore) GetAccessRequest(ctx context.Context, id int64) (*store.AccessRequest, error) {
	return getOne(ctx, s.pool, scanAccessRequest,
		`SELECT id, requester, target_id, reason, status, approver, created_at, decided_at, expires_at
		 FROM access_requests WHERE id = $1`, id)
}

// ListAccessRequests returns requests with the given status (all when status is
// ""), ordered by ID.
func (s *PGStore) ListAccessRequests(ctx context.Context, status string) ([]store.AccessRequest, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, requester, target_id, reason, status, approver, created_at, decided_at, expires_at
		 FROM access_requests WHERE ($1 = '' OR status = $1) ORDER BY id`, status)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, scanAccessRequest)
}

// DecideAccessRequest records an approve/deny decision, approver, and decision
// time; ErrNotFound if the request is missing.
func (s *PGStore) DecideAccessRequest(ctx context.Context, id int64, status, approver string, decidedAt time.Time) error {
	return execExpectingRow(ctx, s.pool,
		`UPDATE access_requests SET status = $1, approver = $2, decided_at = $3 WHERE id = $4`,
		status, approver, decidedAt.UTC(), id)
}

// HasActiveApproval reports whether requester has an approved, unexpired request
// for targetID as of now.
func (s *PGStore) HasActiveApproval(ctx context.Context, requester string, targetID int64, now time.Time) (bool, error) {
	var exists bool
	err := s.pool.QueryRow(ctx,
		`SELECT EXISTS(
			SELECT 1 FROM access_requests
			WHERE requester = $1 AND target_id = $2 AND status = 'approved' AND expires_at > $3)`,
		requester, targetID, now.UTC()).Scan(&exists)
	return exists, err
}

// AppendAudit inserts an audit event, populating its ID and TS.
func (s *PGStore) AppendAudit(ctx context.Context, e *store.AuditEvent) error {
	return s.pool.QueryRow(ctx,
		`INSERT INTO audit_events (actor, action, detail)
		 VALUES ($1, $2, $3) RETURNING id, ts`,
		e.Actor, e.Action, e.Detail,
	).Scan(&e.ID, &e.TS)
}

// ListAudit returns the most recent audit events, newest first; limit is clamped
// to [1,500] (defaulting to 100 when out of range).
func (s *PGStore) ListAudit(ctx context.Context, limit int) ([]store.AuditEvent, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx,
		`SELECT id, ts, actor, action, detail
		 FROM audit_events ORDER BY id DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (store.AuditEvent, error) {
		var e store.AuditEvent
		err := row.Scan(&e.ID, &e.TS, &e.Actor, &e.Action, &e.Detail)
		return e, err
	})
}

// CreateCheckout leases a credential within a transaction; ErrConflict if it
// already has an active checkout as of now, ErrNotFound if the credential is missing.
func (s *PGStore) CreateCheckout(ctx context.Context, co *store.Checkout, now time.Time) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	// Auto-close expired-but-unreturned leases so an expired lease does not block
	// a new checkout (and does not collide with the partial unique index below).
	if _, err := tx.Exec(ctx,
		`UPDATE checkouts SET returned_at = $2
		 WHERE credential_id = $1 AND returned_at IS NULL AND expires_at <= $2`,
		co.CredentialID, now.UTC()); err != nil {
		return err
	}
	// Exclusivity is enforced atomically by the checkouts_one_active_idx partial
	// unique index: a concurrent second insert fails with a unique violation
	// rather than both check-then-inserts racing to success.
	err = tx.QueryRow(ctx,
		`INSERT INTO checkouts (credential_id, target_id, holder, reason, expires_at)
		 VALUES ($1, $2, $3, $4, $5) RETURNING id, checked_out_at`,
		co.CredentialID, co.TargetID, co.Holder, co.Reason, co.ExpiresAt,
	).Scan(&co.ID, &co.CheckedOutAt)
	switch pgCode(err) {
	case pgUniqueViolation:
		return store.ErrConflict
	case pgForeignKeyViolation:
		return store.ErrNotFound
	}
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// GetActiveCheckout returns the credential's active (unreturned, unexpired)
// checkout as of now, or ErrNotFound.
func (s *PGStore) GetActiveCheckout(ctx context.Context, credentialID int64, now time.Time) (*store.Checkout, error) {
	return getOne(ctx, s.pool, scanCheckout,
		`SELECT id, credential_id, target_id, holder, reason, checked_out_at, expires_at, returned_at
		 FROM checkouts
		 WHERE credential_id = $1 AND returned_at IS NULL AND expires_at > $2
		 ORDER BY id DESC LIMIT 1`, credentialID, now.UTC())
}

// CheckinCheckout marks a checkout returned; ErrNotFound if missing or already returned.
func (s *PGStore) CheckinCheckout(ctx context.Context, id int64, at time.Time) error {
	return execExpectingRow(ctx, s.pool,
		`UPDATE checkouts SET returned_at = $1 WHERE id = $2 AND returned_at IS NULL`, at.UTC(), id)
}

// ListCheckouts returns checkouts ordered by ID; activeOnly limits to
// unreturned, unexpired ones as of now.
func (s *PGStore) ListCheckouts(ctx context.Context, activeOnly bool, now time.Time) ([]store.Checkout, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, credential_id, target_id, holder, reason, checked_out_at, expires_at, returned_at
		 FROM checkouts
		 WHERE (NOT $1) OR (returned_at IS NULL AND expires_at > $2)
		 ORDER BY id`, activeOnly, now.UTC())
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, scanCheckout)
}

// scanCheckout maps one result row into a store.Checkout.
func scanCheckout(row pgx.CollectableRow) (store.Checkout, error) {
	var co store.Checkout
	err := row.Scan(&co.ID, &co.CredentialID, &co.TargetID, &co.Holder, &co.Reason,
		&co.CheckedOutAt, &co.ExpiresAt, &co.ReturnedAt)
	return co, err
}

// ExportAudit returns audit events with since <= ts < until, oldest-first; a
// zero since means from the beginning and a zero until means up to now.
func (s *PGStore) ExportAudit(ctx context.Context, since, until time.Time) ([]store.AuditEvent, error) {
	if until.IsZero() {
		until = time.Now()
	}
	rows, err := s.pool.Query(ctx,
		`SELECT id, ts, actor, action, detail
		 FROM audit_events
		 WHERE ($1::timestamptz IS NULL OR ts >= $1) AND ts < $2
		 ORDER BY id ASC`, nullableTime(since), until.UTC())
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (store.AuditEvent, error) {
		var e store.AuditEvent
		err := row.Scan(&e.ID, &e.TS, &e.Actor, &e.Action, &e.Detail)
		return e, err
	})
}

// nullableTime maps the zero time to a SQL NULL (used as "no lower bound").
func nullableTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	u := t.UTC()
	return &u
}

// CreateUser inserts a user, populating its ID and CreatedAt; ErrConflict if the username is taken.
func (s *PGStore) CreateUser(ctx context.Context, u *store.User) error {
	err := s.pool.QueryRow(ctx,
		`INSERT INTO users (username, role, token_hash)
		 VALUES ($1, $2, $3) RETURNING id, created_at`,
		u.Username, u.Role, u.TokenHash,
	).Scan(&u.ID, &u.CreatedAt)
	if pgCode(err) == pgUniqueViolation {
		return store.ErrConflict
	}
	return err
}

// ListUsers returns all users ordered by ID.
func (s *PGStore) ListUsers(ctx context.Context) ([]store.User, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, username, role, token_hash, created_at FROM users ORDER BY id`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, scanUser)
}

// GetUserByTokenHash returns the user whose token hash matches, or ErrNotFound.
func (s *PGStore) GetUserByTokenHash(ctx context.Context, tokenHashHex string) (*store.User, error) {
	return getOne(ctx, s.pool, scanUser,
		`SELECT id, username, role, token_hash, created_at FROM users WHERE token_hash = $1`,
		tokenHashHex)
}

// DeleteUser removes a user by ID; ErrNotFound if absent.
func (s *PGStore) DeleteUser(ctx context.Context, id int64) error {
	return execExpectingRow(ctx, s.pool, `DELETE FROM users WHERE id = $1`, id)
}

// CreateAgentKey inserts an agent key, populating its ID and CreatedAt.
func (s *PGStore) CreateAgentKey(ctx context.Context, k *store.AgentKey) error {
	err := s.pool.QueryRow(ctx,
		`INSERT INTO agent_keys (name, owner, token_hash, disabled)
		 VALUES ($1, $2, $3, $4) RETURNING id, created_at`,
		k.Name, k.Owner, k.TokenHash, k.Disabled,
	).Scan(&k.ID, &k.CreatedAt)
	if pgCode(err) == pgUniqueViolation {
		return store.ErrConflict
	}
	return err
}

// GetAgentKeyByTokenHash returns the enabled agent key whose token hash matches,
// or ErrNotFound (a disabled key is treated as not found).
func (s *PGStore) GetAgentKeyByTokenHash(ctx context.Context, tokenHashHex string) (*store.AgentKey, error) {
	return getOne(ctx, s.pool, scanAgentKey,
		`SELECT id, name, owner, token_hash, disabled, created_at
		 FROM agent_keys WHERE token_hash = $1 AND disabled = FALSE`, tokenHashHex)
}

// ListAgentKeys returns all agent keys ordered by ID.
func (s *PGStore) ListAgentKeys(ctx context.Context) ([]store.AgentKey, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, name, owner, token_hash, disabled, created_at FROM agent_keys ORDER BY id`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, scanAgentKey)
}

// DeleteAgentKey removes an agent key by ID; ErrNotFound if absent.
func (s *PGStore) DeleteAgentKey(ctx context.Context, id int64) error {
	return execExpectingRow(ctx, s.pool, `DELETE FROM agent_keys WHERE id = $1`, id)
}

// CreateBrokerToken stores a single-use resume token for a parked tool call.
func (s *PGStore) CreateBrokerToken(ctx context.Context, t *store.BrokerToken) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO broker_tokens (jti, call_id, expires_at) VALUES ($1, $2, $3)`,
		t.JTI, t.CallID, t.ExpiresAt)
	if pgCode(err) == pgUniqueViolation {
		return store.ErrConflict // a duplicate jti maps to the sentinel, like sibling Create*
	}
	return err
}

// ConsumeBrokerToken atomically spends a token, returning its bound call id. The
// UPDATE ... WHERE used_at IS NULL AND expires_at > now() RETURNING makes the
// spend a single winner; a used, expired, or unknown jti returns ErrNotFound.
func (s *PGStore) ConsumeBrokerToken(ctx context.Context, jti string) (string, error) {
	var callID string
	err := s.pool.QueryRow(ctx,
		`UPDATE broker_tokens SET used_at = now()
		 WHERE jti = $1 AND used_at IS NULL AND expires_at > now()
		 RETURNING call_id`, jti).Scan(&callID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", store.ErrNotFound
	}
	return callID, err
}

// PeekBrokerToken returns a token's bound call id without spending it.
func (s *PGStore) PeekBrokerToken(ctx context.Context, jti string) (string, error) {
	var callID string
	err := s.pool.QueryRow(ctx,
		`SELECT call_id FROM broker_tokens WHERE jti = $1 AND used_at IS NULL AND expires_at > now()`,
		jti).Scan(&callID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", store.ErrNotFound
	}
	return callID, err
}

// DeleteExpiredBrokerTokens removes spent or expired tokens (periodic GC).
func (s *PGStore) DeleteExpiredBrokerTokens(ctx context.Context) (int64, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM broker_tokens WHERE used_at IS NOT NULL OR expires_at <= now()`)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// PutSetting upserts a configuration override, stamping UpdatedAt.
func (s *PGStore) PutSetting(ctx context.Context, st *store.Setting) error {
	return s.pool.QueryRow(ctx,
		`INSERT INTO settings (key, value, secret) VALUES ($1, $2, $3)
		 ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, secret = EXCLUDED.secret, updated_at = now()
		 RETURNING updated_at`, st.Key, st.Value, st.Secret).Scan(&st.UpdatedAt)
}

// GetSetting returns the override for key, or ErrNotFound.
func (s *PGStore) GetSetting(ctx context.Context, key string) (*store.Setting, error) {
	return getOne(ctx, s.pool, scanSetting,
		`SELECT key, value, secret, updated_at FROM settings WHERE key = $1`, key)
}

// ListSettings returns all configuration overrides ordered by key.
func (s *PGStore) ListSettings(ctx context.Context) ([]store.Setting, error) {
	rows, err := s.pool.Query(ctx, `SELECT key, value, secret, updated_at FROM settings ORDER BY key`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, scanSetting)
}

// DeleteSetting removes the override for key; ErrNotFound if absent.
func (s *PGStore) DeleteSetting(ctx context.Context, key string) error {
	return execExpectingRow(ctx, s.pool, `DELETE FROM settings WHERE key = $1`, key)
}

// CreateProfile inserts a custom permission profile; ErrConflict on a duplicate name.
func (s *PGStore) CreateProfile(ctx context.Context, p *store.Profile) error {
	err := s.pool.QueryRow(ctx,
		`INSERT INTO profiles (name, capabilities) VALUES ($1, $2) RETURNING id, created_at`,
		p.Name, strings.Join(p.Capabilities, ",")).Scan(&p.ID, &p.CreatedAt)
	if pgCode(err) == pgUniqueViolation {
		return store.ErrConflict
	}
	return err
}

// GetProfile returns the profile with the given name, or ErrNotFound.
func (s *PGStore) GetProfile(ctx context.Context, name string) (*store.Profile, error) {
	return getOne(ctx, s.pool, scanProfile,
		`SELECT id, name, capabilities, created_at FROM profiles WHERE name = $1`, name)
}

// ListProfiles returns all custom profiles ordered by name.
func (s *PGStore) ListProfiles(ctx context.Context) ([]store.Profile, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, name, capabilities, created_at FROM profiles ORDER BY name`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, scanProfile)
}

// DeleteProfile removes a profile by ID; ErrNotFound if absent.
func (s *PGStore) DeleteProfile(ctx context.Context, id int64) error {
	return execExpectingRow(ctx, s.pool, `DELETE FROM profiles WHERE id = $1`, id)
}

// scanProfile maps one result row into a store.Profile, splitting the
// comma-separated capabilities column.
func scanProfile(row pgx.CollectableRow) (store.Profile, error) {
	var p store.Profile
	var caps string
	if err := row.Scan(&p.ID, &p.Name, &caps, &p.CreatedAt); err != nil {
		return p, err
	}
	if caps != "" {
		p.Capabilities = strings.Split(caps, ",")
	}
	return p, nil
}

const brokerAuditCols = `id, ts, actor, on_behalf_of, actor_chain, action, detail, scope, prev_hash, hmac`

// AppendBrokerAudit inserts a pre-chained broker audit event, populating ID and TS.
func (s *PGStore) AppendBrokerAudit(ctx context.Context, e *store.BrokerAuditEvent) error {
	return s.pool.QueryRow(ctx,
		`INSERT INTO broker_audit_events (actor, on_behalf_of, actor_chain, action, detail, scope, prev_hash, hmac)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id, ts`,
		e.Actor, e.OnBehalfOf, e.ActorChain, e.Action, e.Detail, e.Scope, e.PrevHash, e.HMAC,
	).Scan(&e.ID, &e.TS)
}

// ListBrokerAudit returns broker audit events oldest-first (id ASC). limit <= 0
// returns the whole chain (for verification); limit > 0 returns the most recent
// limit events, still in chain order.
func (s *PGStore) ListBrokerAudit(ctx context.Context, limit int) ([]store.BrokerAuditEvent, error) {
	var rows pgx.Rows
	var err error
	if limit > 0 {
		rows, err = s.pool.Query(ctx,
			`SELECT `+brokerAuditCols+` FROM (SELECT `+brokerAuditCols+
				` FROM broker_audit_events ORDER BY id DESC LIMIT $1) t ORDER BY id ASC`, limit)
	} else {
		rows, err = s.pool.Query(ctx, `SELECT `+brokerAuditCols+` FROM broker_audit_events ORDER BY id ASC`)
	}
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, scanBrokerAudit)
}

// GetBrokerAuditHead returns the most recent broker audit event, or (nil, nil)
// when the log is empty.
func (s *PGStore) GetBrokerAuditHead(ctx context.Context) (*store.BrokerAuditEvent, error) {
	e, err := getOne(ctx, s.pool, scanBrokerAudit,
		`SELECT `+brokerAuditCols+` FROM broker_audit_events ORDER BY id DESC LIMIT 1`)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	return e, err
}

// CreateSession inserts a session, populating its ID and CreatedAt.
func (s *PGStore) CreateSession(ctx context.Context, sess *store.Session) error {
	err := s.pool.QueryRow(ctx,
		`INSERT INTO sessions (username, role, roles, scope, token_hash, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, created_at`,
		sess.Username, sess.Role, sess.Roles, sess.Scope, sess.TokenHash, sess.ExpiresAt,
	).Scan(&sess.ID, &sess.CreatedAt)
	if pgCode(err) == pgUniqueViolation {
		return store.ErrConflict
	}
	return err
}

// GetSessionByTokenHash returns a non-expired session matching the token hash,
// or ErrNotFound.
func (s *PGStore) GetSessionByTokenHash(ctx context.Context, tokenHashHex string) (*store.Session, error) {
	return getOne(ctx, s.pool, scanSession,
		`SELECT id, username, role, roles, scope, token_hash, created_at, expires_at
		 FROM sessions WHERE token_hash = $1 AND expires_at > now()`, tokenHashHex)
}

// DeleteSession removes the session with the given token hash; ErrNotFound if absent.
func (s *PGStore) DeleteSession(ctx context.Context, tokenHashHex string) error {
	return execExpectingRow(ctx, s.pool, `DELETE FROM sessions WHERE token_hash = $1`, tokenHashHex)
}

// UpsertMFAEnrollment creates or replaces a user's TOTP enrollment, populating CreatedAt.
func (s *PGStore) UpsertMFAEnrollment(ctx context.Context, e *store.MFAEnrollment) error {
	return s.pool.QueryRow(ctx,
		`INSERT INTO mfa_enrollments (username, secret_enc, confirmed, last_totp_step)
		 VALUES ($1, $2, $3, $4)
		 ON CONFLICT (username) DO UPDATE SET secret_enc = EXCLUDED.secret_enc, confirmed = EXCLUDED.confirmed, last_totp_step = EXCLUDED.last_totp_step
		 RETURNING created_at`,
		e.Username, e.SecretEnc, e.Confirmed, e.LastTOTPStep,
	).Scan(&e.CreatedAt)
}

// GetMFAEnrollment returns a user's TOTP enrollment, or ErrNotFound.
func (s *PGStore) GetMFAEnrollment(ctx context.Context, username string) (*store.MFAEnrollment, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT username, secret_enc, confirmed, created_at, last_totp_step FROM mfa_enrollments WHERE username = $1`, username)
	if err != nil {
		return nil, err
	}
	e, err := pgx.CollectExactlyOneRow(rows, func(row pgx.CollectableRow) (store.MFAEnrollment, error) {
		var m store.MFAEnrollment
		err := row.Scan(&m.Username, &m.SecretEnc, &m.Confirmed, &m.CreatedAt, &m.LastTOTPStep)
		return m, err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &e, nil
}

// ConsumeTOTPStep atomically advances the user's last-used TOTP step: the UPDATE
// affects a row only when step is newer than the stored one, so a replayed code
// (step <= stored) is rejected without a read-modify-write race.
func (s *PGStore) ConsumeTOTPStep(ctx context.Context, username string, step int64) (bool, error) {
	tag, err := s.pool.Exec(ctx,
		`UPDATE mfa_enrollments SET last_totp_step = $2 WHERE username = $1 AND $2 > last_totp_step`,
		username, step)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

// ListMFAEnrollments returns all enrollments ordered by username.
func (s *PGStore) ListMFAEnrollments(ctx context.Context) ([]store.MFAEnrollment, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT username, secret_enc, confirmed, created_at, last_totp_step FROM mfa_enrollments ORDER BY username`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (store.MFAEnrollment, error) {
		var m store.MFAEnrollment
		// last_totp_step must be selected/scanned: a caller that re-Upserts a listed
		// enrollment (KEK rotation) would otherwise reset the TOTP anti-replay
		// high-water mark to 0 and reopen replay.
		err := row.Scan(&m.Username, &m.SecretEnc, &m.Confirmed, &m.CreatedAt, &m.LastTOTPStep)
		return m, err
	})
}

// DeleteMFAEnrollment removes a user's enrollment and their recovery codes;
// ErrNotFound if the enrollment is absent.
func (s *PGStore) DeleteMFAEnrollment(ctx context.Context, username string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	// Delete recovery codes and the enrollment atomically, so a failure between
	// them can't leave orphaned recovery-code hashes for a user with no enrollment.
	if _, err := tx.Exec(ctx, `DELETE FROM mfa_recovery_codes WHERE username = $1`, username); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `DELETE FROM mfa_enrollments WHERE username = $1`, username)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	return tx.Commit(ctx)
}

// ReplaceMFARecoveryCodes stores a fresh set of recovery-code hashes for a user
// within a transaction, discarding any previous set.
func (s *PGStore) ReplaceMFARecoveryCodes(ctx context.Context, username string, codeHashes []string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `DELETE FROM mfa_recovery_codes WHERE username = $1`, username); err != nil {
		return err
	}
	for _, h := range codeHashes {
		if _, err := tx.Exec(ctx,
			`INSERT INTO mfa_recovery_codes (username, code_hash) VALUES ($1, $2)
			 ON CONFLICT DO NOTHING`, username, h); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// ConsumeMFARecoveryCode removes a matching unused recovery code and reports
// whether one was consumed.
func (s *PGStore) ConsumeMFARecoveryCode(ctx context.Context, username, codeHash string) (bool, error) {
	tag, err := s.pool.Exec(ctx,
		`DELETE FROM mfa_recovery_codes WHERE username = $1 AND code_hash = $2`, username, codeHash)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

// CountMFARecoveryCodes returns how many recovery codes remain for a user.
func (s *PGStore) CountMFARecoveryCodes(ctx context.Context, username string) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx,
		`SELECT count(*) FROM mfa_recovery_codes WHERE username = $1`, username).Scan(&n)
	return n, err
}

// PutOIDCState stores (or replaces) PKCE verifier/nonce state for an OIDC login,
// best-effort GCing expired rows first.
func (s *PGStore) PutOIDCState(ctx context.Context, state, verifier, nonce string, expiresAt time.Time) error {
	// Best-effort GC of expired rows, then upsert.
	_, _ = s.pool.Exec(ctx, `DELETE FROM oidc_states WHERE expires_at <= now()`)
	_, err := s.pool.Exec(ctx,
		`INSERT INTO oidc_states (state, verifier, nonce, expires_at) VALUES ($1, $2, $3, $4)
		 ON CONFLICT (state) DO UPDATE SET verifier = EXCLUDED.verifier, nonce = EXCLUDED.nonce, expires_at = EXCLUDED.expires_at`,
		state, verifier, nonce, expiresAt.UTC())
	return err
}

// TakeOIDCState atomically deletes and returns an unexpired state; ok is false
// if it is missing or expired.
func (s *PGStore) TakeOIDCState(ctx context.Context, state string, now time.Time) (string, string, bool, error) {
	var verifier, nonce string
	err := s.pool.QueryRow(ctx,
		`DELETE FROM oidc_states WHERE state = $1 AND expires_at > $2 RETURNING verifier, nonce`,
		state, now.UTC()).Scan(&verifier, &nonce)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", false, nil
	}
	if err != nil {
		return "", "", false, err
	}
	return verifier, nonce, true, nil
}

// Ping reports whether the database is reachable (readiness probe).
func (s *PGStore) Ping(ctx context.Context) error {
	return s.pool.Ping(ctx)
}

// Close releases the underlying connection pool.
func (s *PGStore) Close() {
	s.pool.Close()
}

// scanTarget maps one result row into a store.Target.
func scanTarget(row pgx.CollectableRow) (store.Target, error) {
	var t store.Target
	err := row.Scan(&t.ID, &t.Name, &t.Host, &t.Port, &t.OSType, &t.Protocol, &t.RequireApproval, &t.CreatedAt)
	return t, err
}

// scanAccessRequest maps one result row into a store.AccessRequest.
func scanAccessRequest(row pgx.CollectableRow) (store.AccessRequest, error) {
	var ar store.AccessRequest
	err := row.Scan(&ar.ID, &ar.Requester, &ar.TargetID, &ar.Reason, &ar.Status,
		&ar.Approver, &ar.CreatedAt, &ar.DecidedAt, &ar.ExpiresAt)
	return ar, err
}

// scanCredential maps one result row into a store.Credential.
func scanCredential(row pgx.CollectableRow) (store.Credential, error) {
	var c store.Credential
	err := row.Scan(&c.ID, &c.TargetID, &c.Username, &c.SecretType, &c.SecretEnc, &c.CreatedAt, &c.RotatedAt)
	return c, err
}

// scanUser maps one result row into a store.User.
func scanUser(row pgx.CollectableRow) (store.User, error) {
	var u store.User
	err := row.Scan(&u.ID, &u.Username, &u.Role, &u.TokenHash, &u.CreatedAt)
	return u, err
}

// scanSession maps one result row into a store.Session.
func scanSession(row pgx.CollectableRow) (store.Session, error) {
	var s store.Session
	err := row.Scan(&s.ID, &s.Username, &s.Role, &s.Roles, &s.Scope, &s.TokenHash, &s.CreatedAt, &s.ExpiresAt)
	return s, err
}

// scanAgentKey maps one result row into a store.AgentKey.
func scanAgentKey(row pgx.CollectableRow) (store.AgentKey, error) {
	var k store.AgentKey
	err := row.Scan(&k.ID, &k.Name, &k.Owner, &k.TokenHash, &k.Disabled, &k.CreatedAt)
	return k, err
}

// scanSetting maps one result row into a store.Setting.
func scanSetting(row pgx.CollectableRow) (store.Setting, error) {
	var s store.Setting
	err := row.Scan(&s.Key, &s.Value, &s.Secret, &s.UpdatedAt)
	return s, err
}

// scanBrokerAudit maps one result row into a store.BrokerAuditEvent.
func scanBrokerAudit(row pgx.CollectableRow) (store.BrokerAuditEvent, error) {
	var e store.BrokerAuditEvent
	err := row.Scan(&e.ID, &e.TS, &e.Actor, &e.OnBehalfOf, &e.ActorChain, &e.Action, &e.Detail, &e.Scope, &e.PrevHash, &e.HMAC)
	return e, err
}
