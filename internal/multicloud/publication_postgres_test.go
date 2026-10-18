package multicloud

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type publicationPG struct {
	admin *pgxpool.Pool
	repo  *PostgresPublicationRepository
	dsn   string
}

func publicationPostgres(t *testing.T) publicationPG {
	t.Helper()
	adminURL := os.Getenv("TEST_MULTICLOUD_ADMIN_URL")
	if adminURL == "" {
		t.Skip("TEST_MULTICLOUD_ADMIN_URL enables a new disposable database; main schema is untouched")
	}
	ctx := context.Background()
	master, e := pgxpool.New(ctx, adminURL)
	if e != nil {
		t.Fatal("cannot open local test administration connection")
	}
	id := strings.ReplaceAll(uuid.NewString(), "-", "")
	database := "mc_publication_" + id
	login := "mc_pub_" + id
	password := uuid.NewString() + uuid.NewString()
	owner := "finops-local-publication:" + id
	t.Logf("Owned disposable database=%s login=%s ownership=%s", database, login, owner)
	if _, e = master.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{database}.Sanitize()); e != nil {
		master.Close()
		t.Fatal(e)
	}
	var admin *pgxpool.Pool
	var repo *PostgresPublicationRepository
	loginCreated := false
	t.Cleanup(func() {
		if repo != nil {
			repo.Pool.Close()
		}
		if admin != nil {
			admin.Close()
		}
		var databaseOwner string
		if e = master.QueryRow(ctx, "SELECT coalesce(shobj_description(oid,'pg_database'),'') FROM pg_database WHERE datname=$1", database).Scan(&databaseOwner); e != nil || databaseOwner != owner {
			t.Error("test database cleanup refused: exact ownership comment missing")
		} else if _, e = master.Exec(ctx, "DROP DATABASE "+pgx.Identifier{database}.Sanitize()+" WITH (FORCE)"); e != nil {
			t.Error("owned test database cleanup failed")
		}
		if loginCreated {
			var roleOwner string
			if e = master.QueryRow(ctx, "SELECT coalesce(shobj_description(oid,'pg_authid'),'') FROM pg_roles WHERE rolname=$1", login).Scan(&roleOwner); e != nil || roleOwner != owner {
				t.Error("test login cleanup refused: exact ownership comment missing")
			} else if _, e = master.Exec(ctx, "DROP ROLE "+pgx.Identifier{login}.Sanitize()); e != nil {
				t.Error("owned test login cleanup failed")
			}
		}
		master.Close()
	})
	if _, e = master.Exec(ctx, "COMMENT ON DATABASE "+pgx.Identifier{database}.Sanitize()+" IS '"+owner+"'"); e != nil {
		t.Fatal("owned test database tagging failed")
	}
	parsed, e := url.Parse(adminURL)
	if e != nil {
		t.Fatal("test administration URL invalid")
	}
	parsed.Path = "/" + database
	adminDSN := parsed.String()
	admin, e = pgxpool.New(ctx, adminDSN)
	if e != nil {
		t.Fatal("cannot open owned test database")
	}
	for _, migration := range []string{"001_control_plane.sql", "019_multicloud_observations.sql"} {
		raw, e := os.ReadFile(filepath.Join("..", "..", "migrations", migration))
		if e != nil {
			t.Fatal(e)
		}
		if _, e = admin.Exec(ctx, string(raw)); e != nil {
			t.Fatalf("isolated %s failed: %v", migration, e)
		}
	}
	// Login is local test-owned, neither migrator nor an inherited application role.
	if _, e = master.Exec(ctx, fmt.Sprintf("CREATE ROLE %s LOGIN PASSWORD '%s'", pgx.Identifier{login}.Sanitize(), password)); e != nil {
		t.Fatal(e)
	}
	loginCreated = true
	if _, e = master.Exec(ctx, "COMMENT ON ROLE "+pgx.Identifier{login}.Sanitize()+" IS '"+owner+"'"); e != nil {
		t.Fatal("owned test login tagging failed")
	}
	if _, e = master.Exec(ctx, "GRANT finops_multicloud_ingester TO "+pgx.Identifier{login}.Sanitize()); e != nil {
		t.Fatal(e)
	}
	parsed.User = url.UserPassword(login, password)
	dsn := parsed.String()
	repo, e = OpenPublicationRepository(ctx, dsn, PublicationDatabaseOptions{Fixture: true})
	if e != nil {
		t.Fatal("restricted publication database open failed:", e)
	}
	if broad, e := OpenPublicationRepository(ctx, adminDSN, PublicationDatabaseOptions{Fixture: true}); e == nil {
		broad.Pool.Close()
		t.Fatal("accepted superuser/migrator runtime identity")
	}
	return publicationPG{admin: admin, repo: repo, dsn: dsn}
}
func pgExpectDenied(t *testing.T, pool *pgxpool.Pool, role, tenant, sql string, args ...any) {
	t.Helper()
	ctx := context.Background()
	tx, e := pool.Begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback(ctx)
	if role != "" {
		if _, e = tx.Exec(ctx, "SET LOCAL ROLE "+pgx.Identifier{role}.Sanitize()); e != nil {
			t.Fatal(e)
		}
	}
	if _, e = tx.Exec(ctx, "SELECT set_config('app.tenant_id',$1,true)", tenant); e != nil {
		t.Fatal(e)
	}
	if _, e = tx.Exec(ctx, sql, args...); e == nil {
		t.Fatal("database accepted forbidden publication mutation")
	}
}

func TestPublicationPostgresIsolationRestartAndAuthorityBoundary(t *testing.T) {
	pg := publicationPostgres(t)
	ctx := context.Background()
	reg, s := publicationFixture(t, GCPDetailed)
	loginURL, parseError := url.Parse(pg.dsn)
	if parseError != nil {
		t.Fatal("private fixture DSN invalid")
	}
	login := loginURL.User.Username()
	for _, mixedRole := range []string{"finops_deployment_observer", "pg_write_all_data"} {
		if _, e := pg.admin.Exec(ctx, "GRANT "+pgx.Identifier{mixedRole}.Sanitize()+" TO "+pgx.Identifier{login}.Sanitize()); e != nil {
			t.Fatal("mixed role fixture requires the bootstrapped local stack", e)
		}
		for _, dsn := range []string{pg.dsn, pg.dsn + "&role=finops_multicloud_ingester"} {
			if broad, e := OpenPublicationRepository(ctx, dsn, PublicationDatabaseOptions{Fixture: true}); e == nil {
				broad.Pool.Close()
				t.Fatal("mixed process/predefined role identity accepted", mixedRole)
			}
		}
		if _, e := pg.admin.Exec(ctx, "REVOKE "+pgx.Identifier{mixedRole}.Sanitize()+" FROM "+pgx.Identifier{login}.Sanitize()); e != nil {
			t.Fatal(e)
		}
	}
	for _, base := range []string{pg.dsn, pg.admin.Config().ConnConfig.ConnString()} {
		for _, parameter := range []string{"role", "session_authorization", "options"} {
			parsed, err := url.Parse(base)
			if err != nil {
				t.Fatal("private fixture URL invalid")
			}
			query := parsed.Query()
			value := "finops_multicloud_ingester"
			if parameter == "options" {
				value = "-c session_authorization=finops_multicloud_ingester"
			}
			query.Set(parameter, value)
			parsed.RawQuery = query.Encode()
			if masked, err := OpenPublicationRepository(ctx, parsed.String(), PublicationDatabaseOptions{Fixture: true}); err == nil {
				masked.Pool.Close()
				t.Fatal("startup identity mask accepted", parameter)
			}
		}
	}
	if _, e := pg.admin.Exec(ctx, "ALTER ROLE "+pgx.Identifier{login}.Sanitize()+" REPLICATION"); e != nil {
		t.Fatal(e)
	}
	if broad, e := OpenPublicationRepository(ctx, pg.dsn, PublicationDatabaseOptions{Fixture: true}); e == nil {
		broad.Pool.Close()
		t.Fatal("replication-capable login accepted")
	}
	if _, e := pg.admin.Exec(ctx, "ALTER ROLE "+pgx.Identifier{login}.Sanitize()+" NOREPLICATION"); e != nil {
		t.Fatal(e)
	}
	if e := pg.repo.Register(ctx, reg); e != nil {
		t.Fatal(e)
	}
	if e := pg.repo.Register(ctx, reg); e != nil {
		t.Fatal("exact registration replay rejected", e)
	}
	changed := reg
	changed.BindingHash = strings.Repeat("a", 64)
	if e := pg.repo.Register(ctx, changed); e == nil {
		t.Fatal("accepted changed private binding")
	}
	if _, e := pg.repo.Current(ctx, "tenant-b", reg.Registration.ID); !errors.Is(e, ErrPublicationInactive) {
		t.Fatal("cross-tenant registration leaked", e)
	}
	manifest, _, _, e := PublicationContent(reg, s)
	if e != nil {
		t.Fatal(e)
	}
	job, _, e := pg.repo.Prepare(ctx, reg, "native-query-1", manifest)
	if e != nil {
		t.Fatal(e)
	}
	// No generic "persisted=true" or analytics-first declaration can publish.
	if _, _, e = pg.repo.Publish(ctx, reg.Registration.TenantID, job.ID); e == nil {
		t.Fatal("published without durable object/fact acknowledgements")
	}
	ack := FactAck{TenantID: manifest.TenantID, PopulationID: manifest.PopulationID, FactHash: manifest.FactHash, EconomicHash: manifest.EconomicHash, DistinctRows: manifest.DistinctRows, RecordCount: manifest.RecordCount, Database: "fixture", Table: "population"}
	if e = pg.repo.Checkpoint(ctx, reg.Registration.TenantID, job.ID, PublicationCheckpoint{Stage: "ANALYTICS_PERSISTED", Facts: &ack}); e == nil {
		t.Fatal("accepted analytics before raw/canonical")
	}
	archive := &publicationMemoryArchive{}
	facts := &publicationMemoryFacts{fail: true}
	p := PublicationPipeline{pg.repo, archive, facts}
	if _, _, e = p.Publish(ctx, reg, s, "native-query-1"); e == nil {
		t.Fatal("expected warehouse outage")
	}
	stages, e := pg.repo.Checkpoints(ctx, reg.Registration.TenantID, job.ID)
	if e != nil || len(stages) != 2 {
		t.Fatal("durable archive checkpoints lost", e)
	}
	puts := archive.puts
	// Simulate losing the process/connection pool after committing canonical stage.
	pg.repo.Pool.Close()
	reopened, e := OpenPublicationRepository(ctx, pg.dsn, PublicationDatabaseOptions{Fixture: true})
	if e != nil {
		t.Fatal(e)
	}
	defer reopened.Pool.Close()
	facts.fail = false
	p = PublicationPipeline{reopened, archive, facts}
	receipt, replay, e := p.Resume(ctx, reg.Registration.TenantID, job.ID)
	if e != nil {
		t.Fatal(e)
	}
	if !replay || !receipt.IsCurrent || !receipt.ActiveSource || receipt.Sequence != 1 || receipt.ExecutionAuthorized || receipt.VerifiedSaving != nil || archive.puts != puts {
		t.Fatal("restart authority/identity/checkpoint invalid")
	}
	// A repeat native poll has a distinct immutable observation, one economic
	// population and one current head. Historical observations are never summed.
	second, _, e := p.Publish(ctx, reg, s, "native-query-2")
	if e != nil {
		t.Fatal(e)
	}
	history, e := reopened.Receipts(ctx, reg.Registration.TenantID, reg.Registration.ID)
	if e != nil || len(history) != 2 || history[0].IsCurrent || !history[1].IsCurrent || second.Sequence != 2 || len(facts.populations) != 1 {
		t.Fatal("repeated polling duplicates current economic population", e)
	}
	ledgerDenied := []string{"INSERT INTO savings_ledger(tenant_id,id,execution_id,fingerprint,document) VALUES('tenant-a','x','x','x','{}')", "INSERT INTO signed_plans(tenant_id,plan_id,nonce,envelope) VALUES('tenant-a','x','x','{}')", "INSERT INTO provider_operations(tenant_id,execution_id,resource_id,stop_intent) VALUES('tenant-a','x','x',true)", "INSERT INTO entities(tenant_id,kind,id,document) VALUES('tenant-a','approvals','x','{}')"}
	for _, sql := range ledgerDenied {
		pgExpectDenied(t, reopened.Pool, "", "tenant-a", sql)
	}
	pgExpectDenied(t, pg.admin, "finops_api", "tenant-a", "INSERT INTO multicloud_jobs(tenant_id,id,registration_id,registration_version,idempotency_key,request_hash,manifest) SELECT tenant_id,'forged',registration_id,registration_version,'forged',request_hash,manifest FROM multicloud_jobs LIMIT 1")
	pgExpectDenied(t, reopened.Pool, "", "tenant-a", "UPDATE multicloud_receipts SET document=document||'{\"execution_authorized\":true}'::jsonb")
	pgExpectDenied(t, reopened.Pool, "", "tenant-a", "DELETE FROM multicloud_checkpoints")
	pgExpectDenied(t, reopened.Pool, "", "tenant-b", "INSERT INTO multicloud_revocations(tenant_id,registration_id,registration_version,reason_code) VALUES('tenant-a','gcp-source',1,'REVOKED')")
	// API may project its tenant metadata; same API role sees no other tenant.
	tx, e := pg.admin.Begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = tx.Exec(ctx, "SET LOCAL ROLE finops_api"); e != nil {
		t.Fatal(e)
	}
	if _, e = tx.Exec(ctx, "SELECT set_config('app.tenant_id','tenant-b',true)"); e != nil {
		t.Fatal(e)
	}
	var n int
	if e = tx.QueryRow(ctx, "SELECT count(*) FROM multicloud_receipts").Scan(&n); e != nil || n != 0 {
		t.Fatal("API cross-tenant receipt leak", e)
	}
	tx.Rollback(ctx)
	// Even a correctly scoped writer cannot change authority on direct insert.
	raw, _ := json.Marshal(manifest)
	pgExpectDenied(t, reopened.Pool, "", "tenant-a", `INSERT INTO multicloud_jobs(tenant_id,id,registration_id,registration_version,idempotency_key,request_hash,manifest) VALUES('tenant-a','authority-job','gcp-source',1,'authority',repeat('a',64),$1::jsonb||'{"status":"VERIFIED"}')`, raw)
	if e = reopened.Revoke(ctx, "tenant-a", "gcp-source", 1, "SOURCE_REVOKED"); e != nil {
		t.Fatal(e)
	}
	if _, _, e = p.Publish(ctx, reg, s, "native-query-3"); !errors.Is(e, ErrPublicationInactive) {
		t.Fatal("revoked source published", e)
	}
	history, e = reopened.Receipts(ctx, "tenant-a", "gcp-source")
	if e != nil || len(history) != 2 || history[0].ActiveSource || history[1].ActiveSource || !history[1].IsCurrent {
		t.Fatal("revocation erased history or retained authority", e)
	}
	// A new private configuration revision can resume observations; old receipt
	// validity never follows the mutable registration head.
	next := reg.Registration
	next.Version = 2
	b := reg.ReadBinding
	reg2, e := PrivateRegistration(next, ReadBinding{ID: b.ID, TenantID: b.TenantID, Provider: b.Provider, DirectoryTenantID: b.DirectoryTenantID, BillingAccountID: b.BillingAccountID, DatasetProjectID: b.DatasetProjectID, ScopeHash: b.ScopeHash})
	if e != nil {
		t.Fatal(e)
	}
	if e = reopened.Register(ctx, reg2); e != nil {
		t.Fatal(e)
	}
	if _, e = reopened.Current(ctx, "tenant-a", "gcp-source"); e != nil {
		t.Fatal("new private revision unavailable", e)
	}
}
