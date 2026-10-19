package store

import (
	"context"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func TestRuntimeIdentityRejectsUnknownProcessBeforeConnecting(t *testing.T) {
	for _, process := range []string{"", "migrate", "hardware-reader", "api; SET ROLE finops_executor"} {
		if db, err := OpenRuntime(context.Background(), "postgres://unreachable.invalid/test", process); err == nil {
			db.Pool.Close()
			t.Fatal("an unrecognized runtime process selected a database group")
		}
	}
}

func TestRuntimeIngestionRequiresLockTransactionAndHealthConnections(t *testing.T) {
	for _, process := range []string{"ingester", "fleet-history-reader"} {
		for _, count := range []string{"1", "2"} {
			db, err := OpenRuntime(context.Background(), "postgres://unreachable.invalid/test?pool_max_conns="+count, process)
			if err == nil {
				db.Pool.Close()
				t.Fatal("undersized ingestion pool accepted")
			}
			if err.Error() != "RUNTIME_INGESTION_POOL_MINIMUM_THREE_REQUIRED" {
				t.Fatal("unsafe pool was not rejected before network access")
			}
		}
	}
}

func TestRuntimeDatabaseIdentityIsDedicatedAcrossAllProcesses(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("disposable PostgreSQL administrator required")
	}
	ctx := context.Background()
	root, err := Open(ctx, dsn)
	if err != nil {
		t.Fatal("disposable administrator unavailable")
	}
	t.Cleanup(root.Pool.Close)
	id := strings.ReplaceAll(uuid.NewString(), "-", "")
	login, database := "runtime_login_"+id, "runtime_identity_"+id
	password := strings.ReplaceAll(uuid.NewString(), "-", "")
	identifier := pgx.Identifier{login}.Sanitize()
	if _, err = root.Pool.Exec(ctx, "CREATE ROLE "+identifier+" LOGIN PASSWORD '"+password+"'"); err != nil {
		t.Fatal("cannot create test-owned login")
	}
	t.Cleanup(func() {
		if _, err := root.Pool.Exec(context.Background(), "DROP ROLE "+identifier); err != nil {
			t.Error("cannot remove test-owned login", err)
		}
	})
	if _, err = root.Pool.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{database}.Sanitize()); err != nil {
		t.Fatal("cannot create test-owned database")
	}
	t.Cleanup(func() {
		if _, err := root.Pool.Exec(context.Background(), "DROP DATABASE "+pgx.Identifier{database}.Sanitize()); err != nil {
			t.Error("cannot remove test-owned database", err)
		}
	})
	parsed, err := url.Parse(dsn)
	if err != nil {
		t.Fatal("invalid disposable connection")
	}
	parsed.Path = "/" + database
	admin, err := Open(ctx, parsed.String())
	if err != nil {
		t.Fatal("test-owned database unavailable")
	}
	t.Cleanup(admin.Pool.Close)
	dir := t.TempDir()
	files, err := filepath.Glob("../../migrations/*.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		if filepath.Base(file) > "017_native_hardware.sql" {
			continue
		}
		body, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(dir, filepath.Base(file)), body, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err = admin.Migrate(ctx, dir); err != nil {
		t.Fatal(err)
	}
	connection := *parsed
	connection.User = url.UserPassword(login, password)
	command := func(t *testing.T, sql string) {
		t.Helper()
		if _, err := admin.Pool.Exec(ctx, sql); err != nil {
			t.Fatal("test identity setup failed", err)
		}
	}
	reject := func(t *testing.T, raw, process string) {
		t.Helper()
		if db, err := OpenRuntime(ctx, raw, process); err == nil {
			db.Pool.Close()
			t.Fatal("a privileged, wrong or mixed identity was accepted", process)
		}
	}
	processes := []struct{ process, group string }{
		{"api", "finops_api"}, {"worker", "finops_worker"}, {"signer", "finops_signer"},
		{"executor", "finops_executor"}, {"ingester", "finops_ingester"}, {"activity-ingress", "finops_activity"},
		{"fleet-history-reader", "finops_ingester"},
		{"telemetry-reader", "finops_telemetry_reader"}, {"telemetry-ingress", "finops_telemetry_ingress"},
		{"deployment-observer", "finops_deployment_observer"},
	}
	for _, entry := range processes {
		t.Run(entry.process, func(t *testing.T) {
			reject(t, parsed.String(), entry.process)
			reject(t, connection.String(), entry.process)
			command(t, "GRANT "+pgx.Identifier{entry.group}.Sanitize()+" TO "+identifier)
			defer command(t, "REVOKE "+pgx.Identifier{entry.group}.Sanitize()+" FROM "+identifier)
			db, err := OpenRuntime(ctx, connection.String(), entry.process)
			if err != nil {
				t.Fatal(err)
			}
			var current, session, searchPath string
			err = db.Pool.QueryRow(ctx, "SELECT current_user,session_user,current_setting('search_path')").Scan(&current, &session, &searchPath)
			db.Pool.Close()
			if err != nil || current != entry.group || session != login || searchPath != "public,pg_temp" {
				t.Fatal("commissioned login/group identity was not preserved")
			}
			wrong := "api"
			if wrong == entry.process {
				wrong = "executor"
			}
			reject(t, connection.String(), wrong)
			for _, extra := range []string{"pg_write_all_data", "finops_deployment_observer", "finops_executor"} {
				if extra == entry.group {
					continue
				}
				command(t, "GRANT "+pgx.Identifier{extra}.Sanitize()+" TO "+identifier)
				reject(t, connection.String(), entry.process)
				command(t, "REVOKE "+pgx.Identifier{extra}.Sanitize()+" FROM "+identifier)
			}
		})
	}
	command(t, "GRANT finops_api TO "+identifier)
	defer command(t, "REVOKE finops_api FROM "+identifier)
	for _, flag := range []string{"SUPERUSER", "CREATEROLE", "CREATEDB", "BYPASSRLS", "REPLICATION"} {
		command(t, "ALTER ROLE "+identifier+" "+flag)
		reject(t, connection.String(), "api")
		command(t, "ALTER ROLE "+identifier+" NO"+flag)
	}
	for _, parameter := range []string{"role", "ROLE", "session_authorization"} {
		masked := *parsed
		query := masked.Query()
		query.Set(parameter, "finops_api")
		masked.RawQuery = query.Encode()
		reject(t, masked.String(), "api")
		// libpq options can also set startup GUCs. The authenticated username
		// comparison must catch session authorization hidden in this field.
		query.Del(parameter)
		query.Set("options", "-c "+parameter+"=finops_api")
		masked.RawQuery = query.Encode()
		reject(t, masked.String(), "api")
	}
	searchPathOverride := connection
	query := searchPathOverride.Query()
	query.Set("search_path", "pg_temp,public")
	searchPathOverride.RawQuery = query.Encode()
	db, err := OpenRuntime(ctx, searchPathOverride.String(), "api")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Pool.Close()
	var searchPath string
	if err = db.Pool.QueryRow(ctx, "SHOW search_path").Scan(&searchPath); err != nil || searchPath != "public,pg_temp" {
		t.Fatal("caller startup schema order replaced the commissioned search path")
	}
}
