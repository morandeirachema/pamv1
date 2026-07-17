// Package pgstore implements store.Store on PostgreSQL via pgx. The schema
// is embedded and applied idempotently on startup (a dedicated migration
// tool arrives with the hardening phase).
package pgstore

import (
	"context"
	_ "embed"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

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
}

func Open(ctx context.Context, url string) (*PGStore, error) {
	pool, err := pgxpool.New(ctx, url)
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
	return &PGStore{pool: pool}, nil
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
