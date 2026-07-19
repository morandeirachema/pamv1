package pgstore

import (
	"context"
	"embed"
	"fmt"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

type migration struct {
	version string // e.g. "0001"
	name    string // file name, used for ordering
	sql     string
}

// loadMigrations reads and orders the embedded migration files. Names are
// expected to be "<version>_<description>.sql" (e.g. 0001_init.sql).
func loadMigrations() ([]migration, error) {
	entries, err := migrationsFS.ReadDir("migrations")
	if err != nil {
		return nil, err
	}
	var out []migration
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		b, err := migrationsFS.ReadFile("migrations/" + e.Name())
		if err != nil {
			return nil, err
		}
		out = append(out, migration{
			version: strings.SplitN(e.Name(), "_", 2)[0],
			name:    e.Name(),
			sql:     string(b),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out, nil
}

// migrate applies any not-yet-applied migrations in order, each in its own
// transaction, and records them in schema_migrations. Safe to run on every
// startup and on a database created by the pre-migrations idempotent schema
// (0001 uses IF NOT EXISTS).
func migrate(ctx context.Context, pool *pgxpool.Pool) error {
	if _, err := pool.Exec(ctx,
		`CREATE TABLE IF NOT EXISTS schema_migrations (
			version    TEXT PRIMARY KEY,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)`); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}
	migrations, err := loadMigrations()
	if err != nil {
		return err
	}
	for _, m := range migrations {
		var applied bool
		if err := pool.QueryRow(ctx,
			`SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version = $1)`, m.version).Scan(&applied); err != nil {
			return err
		}
		if applied {
			continue
		}
		tx, err := pool.Begin(ctx)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, m.sql); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("migration %s: %w", m.name, err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations (version) VALUES ($1)`, m.version); err != nil {
			_ = tx.Rollback(ctx)
			return err
		}
		if err := tx.Commit(ctx); err != nil {
			return err
		}
	}
	return nil
}
