package store

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestMigrationRetryDoesNotHideOtherUniquenessOrSQLFailures(t *testing.T) {
	if !concurrentRoleCreation(fmt.Errorf("atomic migration: %w", &pgconn.PgError{Code: "23505", ConstraintName: "pg_authid_rolname_index"})) {
		t.Fatal("wrapped global role-name conflict was not classified")
	}
	for _, failure := range []error{nil, context.Canceled, &pgconn.PgError{Code: "23505", ConstraintName: "savings_ledger_pkey"}, &pgconn.PgError{Code: "42601", ConstraintName: "pg_authid_rolname_index"}, &pgconn.PgError{Code: "42710", Routine: "CreateSchema"}} {
		if concurrentRoleCreation(failure) {
			t.Fatal("a non-role migration error could be retried")
		}
	}
}

func TestConcurrentMigrationsAcrossDatabasesKeepGlobalRoleCreationAtomic(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("disposable PostgreSQL administrator required")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal("cannot configure disposable administrator")
	}
	t.Cleanup(admin.Close)
	id := strings.ReplaceAll(uuid.NewString(), "-", "")
	role := "migration_race_role_" + id
	marker := "finops-migration-race:" + id
	var exists bool
	if err = admin.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=$1)", role).Scan(&exists); err != nil || exists {
		t.Fatal("test role name is not available")
	}
	t.Cleanup(func() {
		var comment string
		if err := admin.QueryRow(ctx, "SELECT coalesce(shobj_description(oid,'pg_authid'),'') FROM pg_roles WHERE rolname=$1", role).Scan(&comment); err == pgx.ErrNoRows {
			return
		} else if err != nil || comment != marker {
			t.Error("refusing cleanup without the exact test-owned role marker")
			return
		}
		if _, err := admin.Exec(ctx, "DROP ROLE "+pgx.Identifier{role}.Sanitize()); err != nil {
			t.Error("cannot remove test-owned migration role")
		}
	})
	dir := t.TempDir()
	body := fmt.Sprintf("DO $$ BEGIN IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='%s') THEN PERFORM pg_sleep(1); CREATE ROLE %s NOLOGIN; COMMENT ON ROLE %s IS '%s'; END IF; END $$; CREATE TABLE role_race_marker(id integer PRIMARY KEY); INSERT INTO role_race_marker VALUES(1);", role, pgx.Identifier{role}.Sanitize(), pgx.Identifier{role}.Sanitize(), marker)
	if err = os.WriteFile(filepath.Join(dir, "001_role_race.sql"), []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	stores := make([]*Store, 0, 2)
	for _, suffix := range []string{"a", "b"} {
		database := "migration_race_" + id + "_" + suffix
		if _, err = admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{database}.Sanitize()); err != nil {
			t.Fatal("cannot create test-owned database")
		}
		configuration, err := pgxpool.ParseConfig(dsn)
		if err != nil {
			t.Fatal("invalid disposable connection")
		}
		configuration.ConnConfig.Database = database
		pool, err := pgxpool.NewWithConfig(ctx, configuration)
		if err != nil {
			t.Fatal("cannot open test-owned database")
		}
		t.Cleanup(func() {
			pool.Close()
			if _, err := admin.Exec(ctx, "DROP DATABASE "+pgx.Identifier{database}.Sanitize()); err != nil {
				t.Error("cannot remove test-owned migration database")
			}
		})
		stores = append(stores, &Store{Pool: pool})
	}
	start, finished := make(chan struct{}), make(chan error, len(stores))
	for _, database := range stores {
		go func() { <-start; finished <- database.Migrate(ctx, dir) }()
	}
	close(start)
	var migrationError error
	for range stores {
		if err := <-finished; err != nil {
			migrationError = err
		}
	}
	if migrationError != nil {
		t.Fatal("concurrent migration failed", migrationError)
	}
	for _, database := range stores {
		var migrations, rows int
		if err = database.Pool.QueryRow(ctx, "SELECT (SELECT count(*) FROM schema_migrations),(SELECT count(*) FROM role_race_marker)").Scan(&migrations, &rows); err != nil || migrations != 1 || rows != 1 {
			t.Fatal("the complete migration was not committed exactly once")
		}
		if err = database.Migrate(ctx, dir); err != nil {
			t.Fatal("checksum-protected migration replay failed")
		}
	}
	// If a competing transaction commits between the existence check and the
	// command, PostgreSQL reports its explicit CreateRole duplicate instead.
	// Confirm that precise native diagnostic without changing the existing role.
	if _, duplicate := admin.Exec(ctx, "CREATE ROLE "+pgx.Identifier{role}.Sanitize()); !concurrentRoleCreation(duplicate) {
		t.Fatal("native duplicate-role diagnostic was not recognized")
	}
}
