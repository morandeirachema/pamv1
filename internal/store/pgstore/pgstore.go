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
	rows, err := s.pool.Query(ctx,
		`SELECT id, name, host, port, os_type, protocol, require_approval, created_at
		 FROM targets WHERE id = $1`, id)
	if err != nil {
		return nil, err
	}
	t, err := pgx.CollectExactlyOneRow(rows, scanTarget)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// DeleteTarget removes a target by ID (cascading via FK constraints); ErrNotFound if absent.
func (s *PGStore) DeleteTarget(ctx context.Context, id int64) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM targets WHERE id = $1`, id)
	if err == nil && tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	return err
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
	rows, err := s.pool.Query(ctx,
		`SELECT id, target_id, username, secret_type, secret_enc, created_at, rotated_at
		 FROM credentials WHERE id = $1`, id)
	if err != nil {
		return nil, err
	}
	c, err := pgx.CollectExactlyOneRow(rows, scanCredential)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// UpdateCredentialSecretEnc replaces a credential's encrypted secret without
// touching rotated_at; ErrNotFound if absent.
func (s *PGStore) UpdateCredentialSecretEnc(ctx context.Context, id int64, secretEnc string) error {
	tag, err := s.pool.Exec(ctx, `UPDATE credentials SET secret_enc = $1 WHERE id = $2`, secretEnc, id)
	if err == nil && tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	return err
}

// RotateCredentialSecret replaces the encrypted secret and stamps rotated_at;
// ErrNotFound if absent.
func (s *PGStore) RotateCredentialSecret(ctx context.Context, id int64, secretEnc string, rotatedAt time.Time) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE credentials SET secret_enc = $1, rotated_at = $2 WHERE id = $3`, secretEnc, rotatedAt.UTC(), id)
	if err == nil && tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	return err
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
	tag, err := s.pool.Exec(ctx, `DELETE FROM target_grants WHERE id = $1`, id)
	if err == nil && tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	return err
}

// DeleteCredential removes a credential by ID; ErrNotFound if absent.
func (s *PGStore) DeleteCredential(ctx context.Context, id int64) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM credentials WHERE id = $1`, id)
	if err == nil && tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	return err
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
	rows, err := s.pool.Query(ctx,
		`SELECT id, requester, target_id, reason, status, approver, created_at, decided_at, expires_at
		 FROM access_requests WHERE id = $1`, id)
	if err != nil {
		return nil, err
	}
	ar, err := pgx.CollectExactlyOneRow(rows, scanAccessRequest)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &ar, nil
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
	tag, err := s.pool.Exec(ctx,
		`UPDATE access_requests SET status = $1, approver = $2, decided_at = $3 WHERE id = $4`,
		status, approver, decidedAt.UTC(), id)
	if err == nil && tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	return err
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

	var active bool
	if err := tx.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM checkouts
		 WHERE credential_id = $1 AND returned_at IS NULL AND expires_at > $2)`,
		co.CredentialID, now.UTC()).Scan(&active); err != nil {
		return err
	}
	if active {
		return store.ErrConflict
	}
	err = tx.QueryRow(ctx,
		`INSERT INTO checkouts (credential_id, target_id, holder, reason, expires_at)
		 VALUES ($1, $2, $3, $4, $5) RETURNING id, checked_out_at`,
		co.CredentialID, co.TargetID, co.Holder, co.Reason, co.ExpiresAt,
	).Scan(&co.ID, &co.CheckedOutAt)
	if pgCode(err) == pgForeignKeyViolation {
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
	rows, err := s.pool.Query(ctx,
		`SELECT id, credential_id, target_id, holder, reason, checked_out_at, expires_at, returned_at
		 FROM checkouts
		 WHERE credential_id = $1 AND returned_at IS NULL AND expires_at > $2
		 ORDER BY id DESC LIMIT 1`, credentialID, now.UTC())
	if err != nil {
		return nil, err
	}
	co, err := pgx.CollectExactlyOneRow(rows, scanCheckout)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &co, nil
}

// CheckinCheckout marks a checkout returned; ErrNotFound if missing or already returned.
func (s *PGStore) CheckinCheckout(ctx context.Context, id int64, at time.Time) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE checkouts SET returned_at = $1 WHERE id = $2 AND returned_at IS NULL`, at.UTC(), id)
	if err == nil && tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	return err
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
	rows, err := s.pool.Query(ctx,
		`SELECT id, username, role, token_hash, created_at FROM users WHERE token_hash = $1`,
		tokenHashHex)
	if err != nil {
		return nil, err
	}
	u, err := pgx.CollectExactlyOneRow(rows, scanUser)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &u, nil
}

// DeleteUser removes a user by ID; ErrNotFound if absent.
func (s *PGStore) DeleteUser(ctx context.Context, id int64) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, id)
	if err == nil && tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	return err
}

// CreateSession inserts a session, populating its ID and CreatedAt.
func (s *PGStore) CreateSession(ctx context.Context, sess *store.Session) error {
	return s.pool.QueryRow(ctx,
		`INSERT INTO sessions (username, role, scope, token_hash, expires_at)
		 VALUES ($1, $2, $3, $4, $5) RETURNING id, created_at`,
		sess.Username, sess.Role, sess.Scope, sess.TokenHash, sess.ExpiresAt,
	).Scan(&sess.ID, &sess.CreatedAt)
}

// GetSessionByTokenHash returns a non-expired session matching the token hash,
// or ErrNotFound.
func (s *PGStore) GetSessionByTokenHash(ctx context.Context, tokenHashHex string) (*store.Session, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, username, role, scope, token_hash, created_at, expires_at
		 FROM sessions WHERE token_hash = $1 AND expires_at > now()`, tokenHashHex)
	if err != nil {
		return nil, err
	}
	sess, err := pgx.CollectExactlyOneRow(rows, scanSession)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &sess, nil
}

// DeleteSession removes the session with the given token hash; ErrNotFound if absent.
func (s *PGStore) DeleteSession(ctx context.Context, tokenHashHex string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM sessions WHERE token_hash = $1`, tokenHashHex)
	if err == nil && tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	return err
}

// UpsertMFAEnrollment creates or replaces a user's TOTP enrollment, populating CreatedAt.
func (s *PGStore) UpsertMFAEnrollment(ctx context.Context, e *store.MFAEnrollment) error {
	return s.pool.QueryRow(ctx,
		`INSERT INTO mfa_enrollments (username, secret_enc, confirmed)
		 VALUES ($1, $2, $3)
		 ON CONFLICT (username) DO UPDATE SET secret_enc = EXCLUDED.secret_enc, confirmed = EXCLUDED.confirmed
		 RETURNING created_at`,
		e.Username, e.SecretEnc, e.Confirmed,
	).Scan(&e.CreatedAt)
}

// GetMFAEnrollment returns a user's TOTP enrollment, or ErrNotFound.
func (s *PGStore) GetMFAEnrollment(ctx context.Context, username string) (*store.MFAEnrollment, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT username, secret_enc, confirmed, created_at FROM mfa_enrollments WHERE username = $1`, username)
	if err != nil {
		return nil, err
	}
	e, err := pgx.CollectExactlyOneRow(rows, func(row pgx.CollectableRow) (store.MFAEnrollment, error) {
		var m store.MFAEnrollment
		err := row.Scan(&m.Username, &m.SecretEnc, &m.Confirmed, &m.CreatedAt)
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

// ListMFAEnrollments returns all enrollments ordered by username.
func (s *PGStore) ListMFAEnrollments(ctx context.Context) ([]store.MFAEnrollment, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT username, secret_enc, confirmed, created_at FROM mfa_enrollments ORDER BY username`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (store.MFAEnrollment, error) {
		var m store.MFAEnrollment
		err := row.Scan(&m.Username, &m.SecretEnc, &m.Confirmed, &m.CreatedAt)
		return m, err
	})
}

// DeleteMFAEnrollment removes a user's enrollment and their recovery codes;
// ErrNotFound if the enrollment is absent.
func (s *PGStore) DeleteMFAEnrollment(ctx context.Context, username string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM mfa_enrollments WHERE username = $1`, username)
	if err == nil && tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	if err == nil {
		_, err = s.pool.Exec(ctx, `DELETE FROM mfa_recovery_codes WHERE username = $1`, username)
	}
	return err
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
	err := row.Scan(&s.ID, &s.Username, &s.Role, &s.Scope, &s.TokenHash, &s.CreatedAt, &s.ExpiresAt)
	return s, err
}
