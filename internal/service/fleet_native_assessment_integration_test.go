package service

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/fleetassessmentworker"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/fleetbilling"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/source"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/workload"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Every database is a newly marked child. JWTs are verified through real JWKS,
// and all domain rows are written by independently authenticated restricted
// roles. Fixture native transport must be identified separately by each test.
func newFleetNativeHTTPTest(t *testing.T) (*mutationReplayFixture, *store.Store, *store.Store, []string) {
	t.Helper()
	f, producer := newFleetFixtureHTTPTest(t)
	ctx := context.Background()
	cfg, e := pgxpool.ParseConfig(os.Getenv("TEST_DATABASE_URL"))
	if e != nil {
		t.Fatal("private test admin config invalid")
	}
	cfg.ConnConfig.Database = producer.Pool.Config().ConnConfig.Database
	if !strings.HasPrefix(cfg.ConnConfig.Database, "fixture_http_") {
		t.Fatal("test child database ownership differs")
	}
	pool, e := pgxpool.NewWithConfig(ctx, cfg)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(pool.Close)
	admin := &store.Store{Pool: pool}
	dir := t.TempDir()
	for _, name := range []string{"010_native_telemetry.sql", "011_workload_safety.sql", "017_native_hardware.sql", "035_group_native_assessments.sql"} {
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
	login := "assessment_http_" + strings.ReplaceAll(model.ID(), "-", "")
	password := model.ID()
	var assessor *store.Store
	if _, e = admin.Pool.Exec(ctx, "CREATE ROLE "+pgx.Identifier{login}.Sanitize()+" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '"+password+"' IN ROLE finops_group_assessor"); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if assessor != nil {
			assessor.Pool.Close()
		}
		if _, e := admin.Pool.Exec(context.Background(), "DROP ROLE "+pgx.Identifier{login}.Sanitize()); e != nil {
			t.Error(e)
		}
	})
	dsn := url.URL{Scheme: "postgres", Host: net.JoinHostPort(cfg.ConnConfig.Host, strconv.Itoa(int(cfg.ConnConfig.Port))), Path: "/" + cfg.ConnConfig.Database, User: url.UserPassword(login, password), RawQuery: "sslmode=disable"}
	assessor, e = store.OpenRuntime(ctx, dsn.String(), "group-assessment-reader")
	if e != nil {
		t.Fatal(e)
	}
	src := source.FixtureRegistration(f.tenant, "assessment-native")
	activity := store.ActivitySource{ID: "assessment-completed", WorkloadID: "fixture-workload", ResourceID: "assessment-external-work", ProviderResourceID: "i-aaaaaaaaaaaaaaaaa", AccountID: "111122223333", Region: "eu-west-1", Issuer: "https://machine.example.invalid", Subject: "independent-completed-collector", MetricDefinition: store.ActivityMetric{ID: "orders", Version: "1", Unit: "completed_orders"}, Enabled: true}
	if e = f.roles["api"].Do(ctx, f.tenant, func(tx *store.Tx) error {
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
	if e = f.roles["ingester"].Do(ctx, f.tenant, func(tx *store.Tx) error {
		return tx.SourceCheckpointSet(ctx, "assessment-native", "status", model.Document{"status": "HEALTHY", "config_hash": source.ConfigurationHash(src), "last_sync_at": time.Now().UTC().Format(time.RFC3339Nano)})
	}); e != nil {
		t.Fatal(e)
	}
	platform := f.token(f.tenant, "assessment-platform", "PLATFORM_ADMIN")
	proposals := []string{}
	for n, name := range []string{"original", "candidate"} {
		arn := "arn:aws:autoscaling:eu-west-1:111122223333:autoScalingGroup:00000000-0000-4000-8000-00000000000" + strconv.Itoa(n+1) + ":autoScalingGroupName/assessment-" + name
		code, reg, _ := f.request("fleet-history-registrations", `"0"`, "assessment-registration-"+name, platform, model.Document{"workload_id": "fixture-workload", "fleet_id": "assessment-" + name, "asg_arn": arn, "source_connection_id": "assessment-native", "cadence_seconds": 60, "max_gap_seconds": 120})
		if code != 201 {
			t.Fatal("real group registration", code, reg)
		}
		code, definition, _ := f.request("fleet-demand-definitions", `"0"`, "assessment-definition-"+name, platform, model.Document{"registration_id": reg["id"], "activity_source_id": activity.ID, "business_operation": "committed_order", "semantic_contract_id": "reviewed-independent-orders", "semantic_contract_hash": strings.Repeat("b", 64)})
		if code != 201 {
			t.Fatal("definition", code, definition)
		}
		code, scope, _ := f.request("fleet-history-scopes", `"1"`, "assessment-scope-"+name, platform, model.Document{"registration_id": reg["id"], "definition_id": definition["id"], "definition_version": 1})
		if code != 201 {
			t.Fatal("sealed scope", code, scope)
		}
		metadata := model.Document{"schema_version": "1", "authority": "TERRAFORM", "repository": model.Document{"url": "https://git.example.invalid/native-group.git", "ref": "refs/heads/declared", "directory": "infra"}, "pipeline": model.Document{"system": "GITHUB_ACTIONS", "identity": model.Document{"issuer": "https://token.actions.githubusercontent.com", "audience": "finops-deployment-observer", "subject": "repo:owner/group:ref:refs/heads/declared", "pipeline_id": "declared-native-group"}}, "terraform": model.Document{"workspace": "development", "state_lineage": "12345678-1234-1234-1234-123456789abc", "asg_address": "aws_autoscaling_group." + name, "launch_template_address": "aws_launch_template." + name, "traffic": model.Document{"listener_rule_address": "aws_lb_listener_rule.app", "target_group_addresses": []string{"aws_lb_target_group.original", "aws_lb_target_group.candidate"}}}}
		base := "fleet-history-registrations/" + model.String(reg, "id")
		code, decl, _ := f.request(base+"/configuration-authorities", `"0"`, "assessment-declare-"+name, platform, metadata)
		if code != 201 {
			t.Fatal("group declaration", code, decl)
		}
		code, proposal, _ := f.request(base+"/configuration-proposals", `"1"`, "assessment-propose-"+name, platform, model.Document{"declaration_id": decl["id"], "scope_id": scope["id"]})
		if code != 201 {
			t.Fatal("group proposal", code, proposal)
		}
		proposals = append(proposals, model.String(proposal, "id"))
	}
	profile := workload.Profile{SchemaVersion: "1", Criticality: "NON_PRODUCTION", Statefulness: "STATELESS", Timezone: "UTC", MinReplicas: 1, MinZones: 1, Headroom: workload.Headroom{CPUFreePPM: 300000, MemoryFreePPM: 300000}, Saturation: workload.Saturation{CPUP99PPM: 850000, MemoryP99PPM: 900000}, RTOSeconds: 900, MaxSimultaneousChangePPM: 100000}
	if e = f.roles["api"].Do(ctx, f.tenant, func(tx *store.Tx) error {
		_, e := tx.WorkloadSafetyAppend(ctx, "fixture-workload", 0, profile)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	return f, admin, assessor, proposals
}
func fleetNativeHTTPGet(t *testing.T, f *mutationReplayFixture, path, token string) (int, model.Document) {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/v1/"+path, nil)
	r.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	f.api.ServeHTTP(w, r)
	var d model.Document
	if e := json.Unmarshal(w.Body.Bytes(), &d); e != nil {
		t.Fatal("non JSON assessment response", w.Code)
	}
	return w.Code, d
}

type missingFleetNativeArchive struct{ calls int }

func (a *missingFleetNativeArchive) ReadPinned(context.Context, string, model.Document) (fleetbilling.PinnedObject, error) {
	a.calls++
	return fleetbilling.PinnedObject{}, errors.New("explicitly missing native archive")
}
func fleetNativeWorkerConfig(tenant string) fleetassessmentworker.Config {
	return fleetassessmentworker.Config{Enabled: true, TenantID: tenant, DatabaseFile: "/private/assessment/database", ArchiveMode: fleetassessmentworker.LocalArchive, ArchiveRegion: "eu-west-1", ArchiveEndpoint: "http://127.0.0.1:9000", ArchiveBucket: "native-assessment-test", ArchiveAccessKeyFile: "/private/assessment/access", ArchiveSecretKeyFile: "/private/assessment/secret"}
}

func TestFleetNativeAssessmentHTTPRolesReplayCursorAndWorker(t *testing.T) {
	f, _, assessor, proposals := newFleetNativeHTTPTest(t)
	finance := f.token(f.tenant, "finance", "FINANCE")
	auditor := f.token(f.tenant, "auditor", "AUDITOR")
	path := "workloads/fixture-workload/fleet-native-assessments"
	body := model.Document{"old_configuration_proposal_id": proposals[0], "candidate_configuration_proposal_id": proposals[1]}
	for _, role := range []string{"VIEWER", "APPLICATION_OWNER", "PLATFORM_ADMIN", "AUDITOR", "APPROVER"} {
		if code, _, _ := f.request(path, `"1"`, "denied-"+role, f.token(f.tenant, "current-user", role), body); code != 403 {
			t.Fatal("nonfinance request accepted", role, code)
		}
	}
	code, request, _ := f.request(path, `"1"`, "native-once", finance, body)
	if code != 202 || model.String(request, "status") != "QUEUED" || request["assessment"] != nil {
		t.Fatal("request did not queue immutable analytical work", code, request)
	}
	id := model.String(request, "id")
	if code, d, _ := f.request(path, `"0"`, "native-once", finance, body); code != 202 || d["id"] != id {
		t.Fatal("exact cached replay altered request", code)
	}
	if code, _, _ := f.request(path, `"1"`, "native-once", f.token(f.tenant, "finance", "VIEWER"), body); code != 403 {
		t.Fatal("cached request bypassed current role", code)
	}
	for _, field := range []string{"price", "binding", "source_id", "member_count", "approved", "execution_authorized"} {
		bad := model.Clone(body)
		bad[field] = true
		if code, _, _ := f.request(path, `"1"`, "native-forged-"+field, finance, bad); code != 422 {
			t.Fatal("public authority input accepted", field, code)
		}
	}
	if code, _, _ := f.request(path, `"2"`, "native-stale-profile", finance, body); code != 409 {
		t.Fatal("profileCAS not enforced", code)
	}
	if code, _, _ := f.request(path, `"1"`, "native-foreign", f.token(f.tenant+"-foreign", "finance", "FINANCE"), body); code != 404 {
		t.Fatal("foreign tenant selection accepted", code)
	}
	if code, _, _ := f.request(path, `"1"`, "native-second", finance, body); code != 202 {
		t.Fatal("second request", code)
	}
	code, page := fleetNativeHTTPGet(t, f, path+"?limit=1", auditor)
	if code != 200 || len(page["items"].([]any)) != 1 || page["next_cursor"] == nil {
		t.Fatal("bounded page missing", code, page)
	}
	cursor := url.QueryEscape(model.String(page, "next_cursor"))
	if code, p := fleetNativeHTTPGet(t, f, path+"?limit=1&cursor="+cursor, auditor); code != 200 || len(p["items"].([]any)) != 1 {
		t.Fatal("second page", code, p)
	}
	if code, _, _ := f.request("workloads/workload-dev/fleet-native-assessments", `"1"`, "native-wrong-workload", finance, body); code == 202 {
		t.Fatal("group request escaped selected workload")
	}
	if code, _ := fleetNativeHTTPGet(t, f, "workloads/workload-dev/fleet-native-assessments?cursor="+cursor, auditor); code != 422 {
		t.Fatal("cursor crossed workload", code)
	}
	archive := &missingFleetNativeArchive{}
	worker, e := fleetassessmentworker.New(context.Background(), fleetNativeWorkerConfig(f.tenant), assessor, archive)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = worker.Process(context.Background(), id); e != nil {
		t.Fatal("actual queue worker failed unavailable observation", e)
	}
	code, observed := fleetNativeHTTPGet(t, f, "fleet-native-assessments/"+id, auditor)
	if code != 200 || model.String(observed, "status") != "ASSESSED" {
		t.Fatal("worker result not public", code, observed)
	}
	assessment := sourceObject(observed["assessment"])
	scenario := sourceObject(assessment["scenario"])
	if model.String(assessment, "status") != "BLOCKED" || model.String(scenario, "status") != "UNAVAILABLE" || scenario["old_hourly_compute"] != nil || scenario["estimated_saving"] != nil || model.Bool(assessment, "execution_authorized") {
		t.Fatal("missing native inputs became money/authority")
	}
	if _, e = worker.Process(context.Background(), id); e != nil || archive.calls != 0 {
		t.Fatal("replay performed native I/O or failed", e, archive.calls)
	}
	if e = f.roles["api"].Do(context.Background(), f.tenant, func(tx *store.Tx) error {
		_, e := tx.Exec(context.Background(), `UPDATE public.source_registrations SET document=document||'{"enabled":false,"revoked":true}' WHERE tenant_id=$1 AND id='assessment-native'`, f.tenant)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	if code, _ := fleetNativeHTTPGet(t, f, "fleet-native-assessments/"+id, auditor); code != 200 {
		t.Fatal("historical read disappeared after revocation", code)
	}
	if code, _, _ := f.request(path, `"1"`, "native-after-revoke", finance, body); code != 409 {
		t.Fatal("new native selection survived revocation", code)
	}
	if code, _ := fleetNativeHTTPGet(t, f, "fleet-native-assessments/"+id, f.token(f.tenant+"-foreign", "finance", "FINANCE")); code != 404 {
		t.Fatal("foreign result visible", code)
	}
}
