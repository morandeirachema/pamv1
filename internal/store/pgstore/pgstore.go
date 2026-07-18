// Package pgstore implements store.Store on PostgreSQL via pgx. The schema
// is embedded and applied idempotently on startup (a dedicated migration
// tool arrives with the hardening phase).
package pgstore

import (
	"context"
	_ "embed"
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

//go:embed schema.sql
var schema string

const (
	pgUniqueViolation     = "23505"
	pgForeignKeyViolation = "23503"
)

type PGStore struct {
	pool *pgxpool.Pool
	log  *slog.Logger
}

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
	if _, err := pool.Exec(ctx, schema); err != nil {
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

func (t queryTracer) TraceQueryStart(ctx context.Context, _ *pgx.Conn, d pgx.TraceQueryStartData) context.Context {
	return context.WithValue(ctx, qtCtxKey{}, qtState{start: time.Now(), sql: d.SQL})
}

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

func pgCode(err error) string {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code
	}
	return ""
}

func (s *PGStore) CreateTarget(ctx context.Context, t *store.Target) error {
	err := s.pool.QueryRow(ctx,
		`INSERT INTO targets (name, host, port, os_type, protocol)
		 VALUES ($1, $2, $3, $4, $5) RETURNING id, created_at`,
		t.Name, t.Host, t.Port, t.OSType, t.Protocol,
	).Scan(&t.ID, &t.CreatedAt)
	if pgCode(err) == pgUniqueViolation {
		return store.ErrConflict
	}
	return err
}

func (s *PGStore) ListTargets(ctx context.Context) ([]store.Target, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, name, host, port, os_type, protocol, created_at
		 FROM targets ORDER BY id`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, scanTarget)
}

func (s *PGStore) GetTarget(ctx context.Context, id int64) (*store.Target, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, name, host, port, os_type, protocol, created_at
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

func (s *PGStore) DeleteTarget(ctx context.Context, id int64) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM targets WHERE id = $1`, id)
	if err == nil && tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	return err
}

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

func (s *PGStore) ListCredentials(ctx context.Context, targetID int64) ([]store.Credential, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, target_id, username, secret_type, secret_enc, created_at, rotated_at
		 FROM credentials WHERE ($1 = 0 OR target_id = $1) ORDER BY id`, targetID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, scanCredential)
}

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

func (s *PGStore) UpdateCredentialSecretEnc(ctx context.Context, id int64, secretEnc string) error {
	tag, err := s.pool.Exec(ctx, `UPDATE credentials SET secret_enc = $1 WHERE id = $2`, secretEnc, id)
	if err == nil && tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	return err
}

func (s *PGStore) DeleteCredential(ctx context.Context, id int64) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM credentials WHERE id = $1`, id)
	if err == nil && tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	return err
}

func (s *PGStore) AppendAudit(ctx context.Context, e *store.AuditEvent) error {
	return s.pool.QueryRow(ctx,
		`INSERT INTO audit_events (actor, action, detail)
		 VALUES ($1, $2, $3) RETURNING id, ts`,
		e.Actor, e.Action, e.Detail,
	).Scan(&e.ID, &e.TS)
}

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

func (s *PGStore) ListUsers(ctx context.Context) ([]store.User, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, username, role, token_hash, created_at FROM users ORDER BY id`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, scanUser)
}

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

func (s *PGStore) DeleteUser(ctx context.Context, id int64) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, id)
	if err == nil && tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	return err
}

func (s *PGStore) CreateSession(ctx context.Context, sess *store.Session) error {
	return s.pool.QueryRow(ctx,
		`INSERT INTO sessions (username, role, scope, token_hash, expires_at)
		 VALUES ($1, $2, $3, $4, $5) RETURNING id, created_at`,
		sess.Username, sess.Role, sess.Scope, sess.TokenHash, sess.ExpiresAt,
	).Scan(&sess.ID, &sess.CreatedAt)
}

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

func (s *PGStore) DeleteSession(ctx context.Context, tokenHashHex string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM sessions WHERE token_hash = $1`, tokenHashHex)
	if err == nil && tag.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	return err
}

func (s *PGStore) UpsertMFAEnrollment(ctx context.Context, e *store.MFAEnrollment) error {
	return s.pool.QueryRow(ctx,
		`INSERT INTO mfa_enrollments (username, secret_enc, confirmed)
		 VALUES ($1, $2, $3)
		 ON CONFLICT (username) DO UPDATE SET secret_enc = EXCLUDED.secret_enc, confirmed = EXCLUDED.confirmed
		 RETURNING created_at`,
		e.Username, e.SecretEnc, e.Confirmed,
	).Scan(&e.CreatedAt)
}

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

func (s *PGStore) ConsumeMFARecoveryCode(ctx context.Context, username, codeHash string) (bool, error) {
	tag, err := s.pool.Exec(ctx,
		`DELETE FROM mfa_recovery_codes WHERE username = $1 AND code_hash = $2`, username, codeHash)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

func (s *PGStore) CountMFARecoveryCodes(ctx context.Context, username string) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx,
		`SELECT count(*) FROM mfa_recovery_codes WHERE username = $1`, username).Scan(&n)
	return n, err
}

func (s *PGStore) Close() {
	s.pool.Close()
}

func scanTarget(row pgx.CollectableRow) (store.Target, error) {
	var t store.Target
	err := row.Scan(&t.ID, &t.Name, &t.Host, &t.Port, &t.OSType, &t.Protocol, &t.CreatedAt)
	return t, err
}

func scanCredential(row pgx.CollectableRow) (store.Credential, error) {
	var c store.Credential
	err := row.Scan(&c.ID, &c.TargetID, &c.Username, &c.SecretType, &c.SecretEnc, &c.CreatedAt, &c.RotatedAt)
	return c, err
}

func scanUser(row pgx.CollectableRow) (store.User, error) {
	var u store.User
	err := row.Scan(&u.ID, &u.Username, &u.Role, &u.TokenHash, &u.CreatedAt)
	return u, err
}

func scanSession(row pgx.CollectableRow) (store.Session, error) {
	var s store.Session
	err := row.Scan(&s.ID, &s.Username, &s.Role, &s.Scope, &s.TokenHash, &s.CreatedAt, &s.ExpiresAt)
	return s, err
}
