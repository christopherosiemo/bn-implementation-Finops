package groupfixturecommission

import (
	"context"
	"encoding/json"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	g "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetgroup"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/source"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestCommissionConfigIsFixedFixtureOnly(t *testing.T) {
	base := Config{SchemaVersion: "1", Mode: "INSTALL_PROFILE", Fixture: true, TenantID: "tenant-demo", DatabaseFile: "/secrets/database", ImageSHA256: strings.Repeat("a", 64), SourceSHA256: strings.Repeat("b", 64), ReceiptID: "inspected-native-toolchain"}
	if base.Validate() != nil {
		t.Fatal("explicit private installation rejected")
	}
	for _, change := range []func(*Config){func(c *Config) { c.Fixture = false }, func(c *Config) { c.TenantID = "tenant-other" }, func(c *Config) { c.Mode = "CUSTOMER_NATIVE" }, func(c *Config) { c.DatabaseFile = "/host/.pgpass" }, func(c *Config) { c.ImageSHA256 = "tag:latest" }, func(c *Config) { c.SourceID = "supplied-source" }} {
		bad := base
		change(&bad)
		if bad.Validate() == nil {
			t.Fatal("unapproved commissioning input accepted")
		}
	}
	raw, _ := json.Marshal(base)
	if _, err := Decode(raw); err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(append(raw, []byte(` {"fixture":true}`)...)); err == nil {
		t.Fatal("trailing object accepted")
	}
	if _, err := Decode([]byte(strings.TrimSuffix(string(raw), "}") + `,"trusted":true}`)); err == nil {
		t.Fatal("authority claim accepted")
	}
	for _, entry := range []string{"AWS_ACCESS_KEY_ID=unusable", "SIGNING_PRIVATE_KEY=unusable", "DOCKER_HOST=remote", "PGPASSWORD=unusable", "TF_VAR_input=unusable", "HTTPS_PROXY=http://proxy"} {
		if environment([]string{entry}) == nil {
			t.Fatal("ambient authority accepted")
		}
	}
}

func TestFixedRegistrationAndReaderDoNotBackfillNativeInstants(t *testing.T) {
	d := NewRegistration("tenant-demo", "test-source")
	if model.String(d, "read_role_binding_id") != ReadBinding || model.String(d, "prefix") != FixturePrefix {
		t.Fatal("fixture label missing")
	}
	request := RegistrationInput()
	for _, key := range []string{"id", "tenant_id", "version", "enabled", "trusted", "complete", "raw", "credentials"} {
		if _, ok := request[key]; ok {
			t.Fatal("public registration contains authority")
		}
	}
	r, err := source.ParseRegistration(d)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := source.NewFixtureReader(r, nil)
	if err != nil {
		t.Fatal(err)
	}
	before := g.Digest(reader.Execution)
	created, err := time.Parse(time.RFC3339, model.String(source.Object(reader.Execution["ExecutionStatus"]), "CreatedAt"))
	if err != nil || created.Year() != 2026 || created.Month() != time.September || created.Day() != 30 {
		t.Fatal("native September observation was replaced by current time")
	}
	other, err := source.NewFixtureReader(r, nil)
	if err != nil || g.Digest(other.Execution) != before {
		t.Fatal("unchanged native execution did not replay")
	}
	if len(reader.ManifestKeys) == 0 || len(reader.Objects) == 0 {
		t.Fatal("ordinary source reader lacks native manifest/object bytes")
	}
}

func TestPrivateInputAcceptsOnlyExactFixedFiles(t *testing.T) {
	c := Config{SchemaVersion: "1", Mode: "INSTALL_PROFILE", Fixture: true, TenantID: "tenant-demo", DatabaseFile: "/secrets/database", ImageSHA256: strings.Repeat("a", 64), SourceSHA256: strings.Repeat("b", 64), ReceiptID: "inspected-native-toolchain"}
	job, _ := json.Marshal(c)
	input := PrivateInput{Job: job, Files: map[string][]byte{"database": []byte("private-test-dsn")}}
	raw, _ := json.Marshal(input)
	if _, _, err := DecodePrivateInput(raw); err != nil {
		t.Fatal(err)
	}
	for _, files := range []map[string][]byte{
		{}, {"../database": []byte("no")}, {"database": {}},
		{"database": []byte(strings.Repeat("x", 8193))},
		{"database": []byte("private"), "signer.key": []byte("no")},
	} {
		bad, _ := json.Marshal(PrivateInput{Job: job, Files: files})
		if _, _, err := DecodePrivateInput(bad); err == nil {
			t.Fatal("unexpected private file accepted")
		}
	}
	for _, raw := range [][]byte{append(raw, []byte(` {}`)...), []byte(strings.Repeat(" ", 65537)), []byte(`{"job":{},"files":{},"trusted":true}`)} {
		if _, _, err := DecodePrivateInput(raw); err == nil {
			t.Fatal("unbounded or ambiguous private input accepted")
		}
	}
	c.Mode, c.SourceID, c.ImageSHA256, c.SourceSHA256, c.ReceiptID = "SYNC_SOURCE", "fixture-source", "", "", ""
	c.Storage = &Storage{"/secrets/object-access", "/secrets/object-secret", "/secrets/clickhouse-password", "/secrets/economics-token"}
	job, _ = json.Marshal(c)
	input = PrivateInput{Job: job, Files: map[string][]byte{"database": []byte("dsn"), "object-access": []byte("access"), "object-secret": []byte("secret"), "clickhouse-password": []byte("password"), "economics-token": []byte("token")}}
	raw, _ = json.Marshal(input)
	if _, _, err := DecodePrivateInput(raw); err != nil {
		t.Fatal(err)
	}
	delete(input.Files, "object-secret")
	raw, _ = json.Marshal(input)
	if _, _, err := DecodePrivateInput(raw); err == nil {
		t.Fatal("missing pinned private credential accepted")
	}
}

// Only a marked child database and a unique dedicated login are created in the
// explicitly supplied disposable cluster. No migration or main database write.
func TestCommissionActualPersistedFixtureBoundary(t *testing.T) {
	raw := os.Getenv("TEST_DATABASE_URL")
	if raw == "" {
		t.Skip("disposable PostgreSQL acceptance not configured")
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	admin, err := pgxpool.New(ctx, raw)
	if err != nil {
		t.Fatal("test administrator unavailable")
	}
	t.Cleanup(admin.Close)
	var exists bool
	if err = admin.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='finops_group_fixture')`).Scan(&exists); err != nil || !exists {
		t.Fatal("disposable029 private role required")
	}
	suffix := strings.ReplaceAll(model.ID(), "-", "")
	database, login, marker := "commission_"+suffix, "commission_login_"+suffix, "owned-commission-"+suffix
	qDatabase, qLogin := pgx.Identifier{database}.Sanitize(), pgx.Identifier{login}.Sanitize()
	if _, err = admin.Exec(ctx, "CREATE DATABASE "+qDatabase); err != nil {
		t.Fatal("cannot create isolated database")
	}
	if _, err = admin.Exec(ctx, "COMMENT ON DATABASE "+qDatabase+" IS '"+marker+"'"); err != nil {
		t.Fatal("cannot mark isolated database")
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		var actual string
		if e := admin.QueryRow(cleanup, `SELECT coalesce(shobj_description(oid,'pg_database'),'') FROM pg_database WHERE datname=$1`, database).Scan(&actual); e != nil || actual != marker {
			t.Error("database ownership mismatch")
			return
		}
		if _, e := admin.Exec(cleanup, "DROP DATABASE "+qDatabase+" WITH (FORCE)"); e != nil {
			t.Error("owned database cleanup failed")
		}
		if e := admin.QueryRow(cleanup, `SELECT coalesce(shobj_description(oid,'pg_authid'),'') FROM pg_roles WHERE rolname=$1`, login).Scan(&actual); e == nil && actual == marker {
			if _, e = admin.Exec(cleanup, "DROP ROLE "+qLogin); e != nil {
				t.Error("owned login cleanup failed")
			}
		} else if e == nil {
			t.Error("login ownership mismatch")
		}
	})
	password := model.ID() + model.ID()
	if _, err = admin.Exec(ctx, "BEGIN; CREATE ROLE "+qLogin+" LOGIN PASSWORD '"+password+"' IN ROLE finops_group_fixture; COMMENT ON ROLE "+qLogin+" IS '"+marker+"'; COMMIT"); err != nil {
		t.Fatal("private child login unavailable")
	}
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal("test URL invalid")
	}
	u.Path = "/" + database
	child, err := pgxpool.New(ctx, u.String())
	if err != nil {
		t.Fatal("child administrator unavailable")
	}
	defer child.Close()
	if _, err = child.Exec(ctx, `CREATE TABLE public.entities(tenant_id text,kind text,id text,version bigint NOT NULL DEFAULT 1,document jsonb,PRIMARY KEY(tenant_id,kind,id)); GRANT SELECT ON public.entities TO finops_group_fixture`); err != nil {
		t.Fatal("minimal fixture guard table unavailable")
	}
	u.User = url.UserPassword(login, password)
	db, err := store.OpenRuntime(ctx, u.String(), "group-fixture")
	if err != nil {
		t.Fatal("dedicated private identity refused")
	}
	defer db.Pool.Close()
	if fixtureOrganization(ctx, db) == nil {
		t.Fatal("missing organization accepted")
	}
	for _, document := range []string{`{"fixture":false}`, `{"fixture":"true"}`, `{"fixture":null}`, `{}`} {
		if _, err = child.Exec(ctx, `INSERT INTO public.entities(tenant_id,kind,id,document) VALUES('tenant-demo','org','tenant-demo',$1) ON CONFLICT(tenant_id,kind,id) DO UPDATE SET document=excluded.document`, document); err != nil {
			t.Fatal("cannot seed isolated organization")
		}
		if fixtureOrganization(ctx, db) == nil {
			t.Fatal("unproven persisted fixture flag accepted")
		}
	}
	if _, err = child.Exec(ctx, `UPDATE public.entities SET document='{"fixture":true}'`); err != nil {
		t.Fatal("cannot seed actual fixture flag")
	}
	if fixtureOrganization(ctx, db) != nil {
		t.Fatal("persisted explicit fixture organization refused")
	}
}
