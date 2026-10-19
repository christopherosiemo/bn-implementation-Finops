package store

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/jackc/pgx/v5"
)

// The new file-lab domains do not imply process isolation. This acceptance uses
// independently authenticated PostgreSQL logins and the same strict startup
// gate as other runtime services, without installing credentials in Compose.
func TestGroupRuntimeDatabaseIdentityIsDedicated(t *testing.T) {
	f := newFleetHistoryDBTest(t) // A marked, owned child database; never migrate the administrator database.
	if err := f.admin.Migrate(f.ctx, "../../migrations"); err != nil {
		t.Fatal(err)
	}
	for _, entry := range []struct{ process, group string }{
		{"group-fixture", "finops_group_fixture"},
		{"group-ledger", "finops_group_ledger"},
		{"group-pipeline", "finops_group_pipeline"},
	} {
		t.Run(entry.process, func(t *testing.T) {
			ctx := context.Background()
			login := "group_identity_" + strings.ReplaceAll(model.ID(), "-", "")
			owner := "owned-group-identity-" + model.ID()
			password := model.ID() + model.ID()
			quoted := pgx.Identifier{login}.Sanitize()
			if _, err := f.admin.Pool.Exec(ctx, "CREATE ROLE "+quoted+" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '"+password+"' IN ROLE "+pgx.Identifier{entry.group}.Sanitize()); err != nil {
				t.Fatal("cannot create isolated test identity", err)
			}
			if _, err := f.admin.Pool.Exec(ctx, "COMMENT ON ROLE "+quoted+" IS '"+owner+"'"); err != nil {
				t.Fatal("cannot mark isolated identity", err)
			}
			t.Cleanup(func() {
				var actual string
				if err := f.admin.Pool.QueryRow(ctx, "SELECT coalesce(shobj_description(oid,'pg_authid'),'') FROM pg_roles WHERE rolname=$1", login).Scan(&actual); err != nil || actual != owner {
					t.Error("test identity cleanup ownership mismatch")
					return
				}
				if _, err := f.admin.Pool.Exec(ctx, "DROP ROLE "+quoted); err != nil {
					t.Error("cannot remove owned test identity", err)
				}
			})
			connection, err := url.Parse(f.admin.Pool.Config().ConnString())
			if err != nil {
				t.Fatal("test database configuration unavailable")
			}
			connection.User = url.UserPassword(login, password)
			privateURL := connection.String()
			open := func() *Store {
				t.Helper()
				db, err := OpenRuntime(ctx, privateURL, entry.process)
				if err != nil {
					t.Fatal("dedicated identity rejected", err)
				}
				return db
			}
			db := open()
			var session, current string
			err = db.Pool.QueryRow(ctx, "SELECT session_user,current_user").Scan(&session, &current)
			db.Pool.Close()
			if err != nil || session != login || current != entry.group {
				t.Fatal("authenticated group identity not preserved", err)
			}
			for _, extra := range []string{"finops_api", "finops_signer", "finops_executor", "finops_group_fixture", "finops_group_ledger", "finops_group_pipeline", "pg_write_all_data"} {
				if extra == entry.group {
					continue
				}
				grant := pgx.Identifier{extra}.Sanitize()
				if _, err := f.admin.Pool.Exec(ctx, "GRANT "+grant+" TO "+quoted); err != nil {
					t.Fatal(err)
				}
				unsafe, err := OpenRuntime(ctx, privateURL, entry.process)
				if unsafe != nil {
					unsafe.Pool.Close()
				}
				if _, revokeErr := f.admin.Pool.Exec(ctx, "REVOKE "+grant+" FROM "+quoted); revokeErr != nil {
					t.Fatal(revokeErr)
				}
				if err == nil {
					t.Fatal("mixed signing/execution/ingestion identity accepted", extra)
				}
			}
			db = open()
			db.Pool.Close()
		})
	}
}
