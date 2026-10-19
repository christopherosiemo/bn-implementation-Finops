package service

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/auth"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/fleetfixture"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/source"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/go-jose/go-jose/v4"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func fleetFixtureHTTPDatabase(t *testing.T) (*store.Store, map[string]*store.Store) {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("disposable PostgreSQL administrator required")
	}
	ctx := context.Background()
	master, e := pgx.Connect(ctx, dsn)
	if e != nil {
		t.Fatal("test administrator unavailable")
	}
	t.Cleanup(func() { _ = master.Close(context.Background()) })
	name := "fixture_http_" + strings.ReplaceAll(model.ID(), "-", "")
	marker := "owned-fixture-http-" + model.ID()
	if _, e = master.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); e != nil {
		t.Fatal(e)
	}
	if _, e = master.Exec(ctx, "COMMENT ON DATABASE "+pgx.Identifier{name}.Sanitize()+" IS '"+marker+"'"); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		var actual string
		if e := master.QueryRow(context.Background(), "SELECT shobj_description(oid,'pg_database') FROM pg_database WHERE datname=$1", name).Scan(&actual); e != nil || actual != marker || !strings.HasPrefix(name, "fixture_http_") {
			t.Error("test database ownership mismatch")
			return
		}
		if _, e := master.Exec(context.Background(), "DROP DATABASE "+pgx.Identifier{name}.Sanitize()); e != nil {
			t.Error(e)
		}
	})
	cfg, e := pgxpool.ParseConfig(dsn)
	if e != nil {
		t.Fatal("test database configuration invalid")
	}
	cfg.ConnConfig.Database = name
	pool, e := pgxpool.NewWithConfig(ctx, cfg)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(pool.Close)
	admin := &store.Store{Pool: pool}
	dir := t.TempDir()
	for _, name := range []string{"001_control_plane.sql", "002_ingestion_and_approval_boundary.sql", "005_trusted_sources.sql", "006_activity.sql", "025_fleet_history.sql", "027_fleet_configuration.sql", "029_fleet_fixture_proposals.sql"} {
		raw, e := os.ReadFile(filepath.Join("..", "..", "migrations", name))
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join(dir, name), raw, 0600); e != nil {
			t.Fatal(e)
		}
	}
	if e = admin.Migrate(ctx, dir); e != nil {
		t.Fatal(e)
	}
	roles := map[string]*store.Store{}
	for _, role := range []string{"api", "ingester"} {
		login := "fixture_api_" + strings.ReplaceAll(model.ID(), "-", "")
		password := model.ID()
		if _, e = master.Exec(ctx, "CREATE ROLE "+pgx.Identifier{login}.Sanitize()+" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '"+password+"' IN ROLE "+pgx.Identifier{"finops_" + role}.Sanitize()); e != nil {
			t.Fatal(e)
		}
		roleCfg := cfg.Copy()
		roleCfg.ConnConfig.User = login
		roleCfg.ConnConfig.Password = password
		roleCfg.ConnConfig.RuntimeParams = map[string]string{}
		roleCfg.AfterConnect = func(ctx context.Context, c *pgx.Conn) error {
			_, e := c.Exec(ctx, "SET ROLE "+pgx.Identifier{"finops_" + role}.Sanitize())
			return e
		}
		p, e := pgxpool.NewWithConfig(ctx, roleCfg)
		if e != nil {
			t.Fatal(e)
		}
		roles[role] = &store.Store{Pool: p}
		t.Cleanup(func() {
			p.Close()
			if _, e := master.Exec(context.Background(), "DROP ROLE "+pgx.Identifier{login}.Sanitize()); e != nil {
				t.Error(e)
			}
		})
	}
	return admin, roles
}

func newFleetFixtureHTTPTest(t *testing.T) (*mutationReplayFixture, *store.Store) {
	t.Helper()
	admin, roles := fleetFixtureHTTPDatabase(t)
	ctx := context.Background()
	key, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	signer, e := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithHeader("kid", "fleet-fixture"))
	if e != nil {
		t.Fatal(e)
	}
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "fleet-fixture", Algorithm: "RS256", Use: "sig"}}})
	}))
	t.Cleanup(jwks.Close)
	validator, e := auth.New(ctx, "https://mutation-issuer.invalid/realms/test", "finops", jwks.URL)
	if e != nil {
		t.Fatal(e)
	}
	f := &mutationReplayFixture{t: t, tenant: "fixture-http-" + model.ID(), roles: roles, sign: signer, api: &API{Store: roles["api"], Auth: validator, Config: Config{Fixture: true}}}
	login := "fixture_http_" + strings.ReplaceAll(model.ID(), "-", "")
	password := model.ID()
	if _, e = admin.Pool.Exec(ctx, "CREATE ROLE "+pgx.Identifier{login}.Sanitize()+" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '"+password+"' IN ROLE finops_group_fixture"); e != nil {
		t.Fatal(e)
	}
	cfg := admin.Pool.Config().Copy()
	cfg.ConnConfig.User = login
	cfg.ConnConfig.Password = password
	cfg.ConnConfig.RuntimeParams = map[string]string{}
	cfg.AfterConnect = func(ctx context.Context, c *pgx.Conn) error {
		_, e := c.Exec(ctx, "SET ROLE finops_group_fixture")
		return e
	}
	pool, e := pgxpool.NewWithConfig(ctx, cfg)
	if e != nil {
		t.Fatal(e)
	}
	producer := &store.Store{Pool: pool}
	t.Cleanup(func() {
		pool.Close()
		if _, e := admin.Pool.Exec(context.Background(), "DROP ROLE "+pgx.Identifier{login}.Sanitize()); e != nil {
			t.Error(e)
		}
	})
	if e = roles["api"].Do(ctx, f.tenant, func(tx *store.Tx) error {
		if e := tx.Seed(ctx, true); e != nil {
			return e
		}
		_, e := tx.Create(ctx, "workloads", model.Document{"id": "fixture-workload", "name": "Group fixture API", "owner": "assigned-owner", "environment": "NON_PRODUCTION"})
		return e
	}); e != nil {
		t.Fatal(e)
	}
	return f, producer
}

// Public ID-only selectors, real JWT/JWKS, independent restricted PG roles and
// issued025/027 rows. No historical receipt/backfill or real provider mutation.
func TestFleetFixtureAuthenticatedSelectionNeverApprovesUnknownProgram(t *testing.T) {
	f, producer := newFleetFixtureHTTPTest(t)
	ctx := context.Background()
	platform := f.token(f.tenant, "creator", "PLATFORM_ADMIN")
	approver := f.token(f.tenant, "independent", "APPROVER")
	viewer := f.token(f.tenant, "viewer", "VIEWER")
	foreign := f.token(f.tenant+"-foreign", "creator", "PLATFORM_ADMIN")
	get := func(path, token string) (int, model.Document) {
		t.Helper()
		r := httptest.NewRequest("GET", "/v1/"+path, nil)
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		f.api.ServeHTTP(w, r)
		var out model.Document
		if e := json.Unmarshal(w.Body.Bytes(), &out); e != nil {
			t.Fatal("non-JSON response", w.Code)
		}
		return w.Code, out
	}
	if code, page := get("fleet-fixture-profiles", platform); code != 200 || len(page["items"].([]any)) != 0 {
		t.Fatal("migration invented installed producer", code)
	}
	var profile fleetfixture.Profile
	if e := producer.Do(ctx, f.tenant, func(tx *store.Tx) error {
		var e error
		profile, e = tx.FleetFixtureProfileInstall(ctx, fleetfixture.Installation{TemplateID: "builtin-group-fixture-v1", ToolchainImageSHA256: strings.Repeat("a", 64), TerraformVersion: "1.16.0", ReceiptID: "explicit-http-installation-double", SourceSHA256: strings.Repeat("b", 64)})
		return e
	}); e != nil {
		t.Fatal(e)
	}
	activity := store.ActivitySource{ID: "fixture-completed", WorkloadID: "fixture-workload", ResourceID: "external-work", ProviderResourceID: "i-aaaaaaaaaaaaaaaaa", AccountID: "111122223333", Region: "eu-west-1", Issuer: "https://machine.example.invalid", Subject: "completed-work-collector", MetricDefinition: store.ActivityMetric{ID: "orders", Version: "1", Unit: "completed_orders"}, Enabled: true}
	src := source.FixtureRegistration(f.tenant, "fixture-native")
	if e := f.roles["api"].Do(ctx, f.tenant, func(tx *store.Tx) error {
		if _, e := tx.Create(ctx, "resources", model.Document{"id": activity.ResourceID, "workload_id": activity.WorkloadID, "provider": "AWS", "provider_resource_id": activity.ProviderResourceID, "account_id": activity.AccountID, "region": activity.Region}); e != nil {
			return e
		}
		if _, e := tx.SourceCreate(ctx, src); e != nil {
			return e
		}
		_, e := tx.ActivityRegister(ctx, activity)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	if e := f.roles["ingester"].Do(ctx, f.tenant, func(tx *store.Tx) error {
		return tx.SourceCheckpointSet(ctx, "fixture-native", "status", model.Document{"status": "HEALTHY", "config_hash": source.ConfigurationHash(src), "last_sync_at": time.Now().UTC().Format(time.RFC3339Nano)})
	}); e != nil {
		t.Fatal(e)
	}
	proposals := []string{}
	for index, name := range []string{"old", "candidate"} {
		code, r, _ := f.request("fleet-history-registrations", `"0"`, "fixture-register-"+name, platform, model.Document{"workload_id": activity.WorkloadID, "fleet_id": "fixture-" + name, "asg_arn": "arn:aws:autoscaling:eu-west-1:111122223333:autoScalingGroup:" + []string{"11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222"}[index] + ":autoScalingGroupName/fixture-" + name, "source_connection_id": "fixture-native", "cadence_seconds": 60, "max_gap_seconds": 120})
		if code != 201 {
			t.Fatal("registration", code, r)
		}
		code, d, _ := f.request("fleet-demand-definitions", `"0"`, "fixture-definition-"+name, platform, model.Document{"registration_id": r["id"], "activity_source_id": activity.ID, "business_operation": "declared completed orders", "semantic_contract_id": "orders-v1", "semantic_contract_hash": strings.Repeat("c", 64)})
		if code != 201 {
			t.Fatal("definition", code, d)
		}
		code, sc, _ := f.request("fleet-history-scopes", `"1"`, "fixture-scope-"+name, platform, model.Document{"registration_id": r["id"], "definition_id": d["id"], "definition_version": 1})
		if code != 201 {
			t.Fatal("scope", code, sc)
		}
		base := "fleet-history-registrations/" + model.String(r, "id")
		metadata := model.Document{"schema_version": "1", "authority": "TERRAFORM", "repository": model.Document{"url": "https://git.example.invalid/fixture.git", "ref": "refs/heads/declared", "directory": "infra"}, "pipeline": model.Document{"system": "GITHUB_ACTIONS", "identity": model.Document{"issuer": "https://token.actions.githubusercontent.com", "audience": "finops-deployment-observer", "subject": "repo:owner/fixture:ref:refs/heads/declared", "pipeline_id": "declared-customer-pipeline"}}, "terraform": model.Document{"workspace": "development", "state_lineage": "12345678-1234-1234-1234-123456789abc", "asg_address": "aws_autoscaling_group." + name, "launch_template_address": "aws_launch_template." + name, "traffic": model.Document{"listener_rule_address": "aws_lb_listener_rule.app", "target_group_addresses": []string{"aws_lb_target_group.old", "aws_lb_target_group.candidate"}}}}
		code, decl, _ := f.request(base+"/configuration-authorities", `"0"`, "fixture-declare-"+name, platform, metadata)
		if code != 201 {
			t.Fatal("declaration", code, decl)
		}
		code, p, _ := f.request(base+"/configuration-proposals", `"1"`, "fixture-configuration-"+name, platform, model.Document{"declaration_id": decl["id"], "scope_id": sc["id"]})
		if code != 201 {
			t.Fatal("configuration proposal", code, p)
		}
		proposals = append(proposals, model.String(p, "id"))
	}
	selection := model.Document{"old_configuration_proposal_id": proposals[0], "candidate_configuration_proposal_id": proposals[1], "fixture_profile_id": profile.ID}
	code, p, tag := f.request("fleet-fixture-proposals", `"0"`, "fixture-select-once", platform, selection)
	if code != 201 || tag != `"1"` || model.String(p, "status") != "WAITING_FOR_PROGRAM" {
		t.Fatal("fixture selection", code, p, tag)
	}
	id := model.String(p, "id")
	audit, events := f.counts()
	if code, again, _ := f.request("fleet-fixture-proposals", `"0"`, "fixture-select-once", platform, selection); code != 201 || again["id"] != id {
		t.Fatal("exact selection replay", code)
	}
	if a, b := f.counts(); a != audit || b != events {
		t.Fatal("replay repeated side effects")
	}
	if code, _, _ := f.request("fleet-fixture-proposals", `"0"`, "fixture-select-once", f.token(f.tenant, "creator", "VIEWER"), selection); code != 403 {
		t.Fatal("cached selection escaped current role", code)
	}
	for _, field := range []string{"binding", "program", "manifest", "amount", "approved", "history_complete", "execution_authorized", "artifact_refs"} {
		bad := model.Clone(selection)
		bad[field] = true
		if code, _, _ := f.request("fleet-fixture-proposals", `"0"`, "forged-fixture-"+field, platform, bad); code != 422 {
			t.Fatal("accepted client authority field", field, code)
		}
	}
	if code, p, _ := f.request("fleet-fixture-proposals/"+id+"/approvals", `"1"`, "fixture-approve-absent", approver, model.Document{}); code != 409 || model.String(p, "error") != "PROGRAM_NOT_PREPARED" {
		t.Fatal("unknown future program approved", code, p)
	}
	if code, _, _ := f.request("fleet-fixture-proposals/"+id+"/approvals", `"1"`, "fixture-self-approval", f.token(f.tenant, "creator", "ORGANISATION_OWNER"), model.Document{}); code != 403 {
		t.Fatal("organization owner bypassed independent actor", code)
	}
	if code, _, _ := f.request("fleet-fixture-proposals/"+id+"/approvals", `"1"`, "fixture-viewer-approval", viewer, model.Document{}); code != 403 {
		t.Fatal("viewer approval", code)
	}
	if code, p, _ := f.request("fleet-fixture-proposals/"+id+"/runs", `"1"`, "fixture-no-runtime", platform, model.Document{}); code != 503 || model.String(p, "error") != "FLEET_FIXTURE_RUNTIME_NOT_CONNECTED" {
		t.Fatal("fabricated queued/completed run", code, p)
	}
	if code, _ := get("fleet-fixture-proposals/"+id, foreign); code != 404 {
		t.Fatal("cross tenant detail", code)
	}
	if code, _ := get("fleet-fixture-proposals?workload_id="+activity.WorkloadID, viewer); code != 200 {
		t.Fatal("authorized observational read", code)
	}
	if code, _ := get("fleet-fixture-proposals?workload_id="+activity.WorkloadID, f.token(f.tenant, "unassigned", "APPLICATION_OWNER")); code != 403 {
		t.Fatal("unassigned owner read", code)
	}
	if code, _ := get("fleet-fixture-proposals?workload_id="+activity.WorkloadID+"&limit=1", platform); code != 200 {
		t.Fatal("scoped page", code)
	}
}
