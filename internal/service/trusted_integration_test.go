package service

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/evidence"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/provider"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/safety"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/source"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func trustedRoleStore(t *testing.T, dsn, role string) *store.Store {
	t.Helper()
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.AfterConnect = func(ctx context.Context, c *pgx.Conn) error {
		_, err := c.Exec(ctx, "SET ROLE "+pgx.Identifier{role}.Sanitize())
		return err
	}
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return &store.Store{Pool: pool}
}

// The default HTTP double tests API authority/orchestration only. Setting
// ECONOMICS_TEST_URL runs exactly the same full minute/native CUR inputs through
// the actual Python v3 evaluator instead of claiming a mock proves economics.
func trustedEconomics(t *testing.T) (string, string) {
	t.Helper()
	if endpoint := os.Getenv("ECONOMICS_TEST_URL"); endpoint != "" {
		return endpoint, os.Getenv("ECONOMICS_TEST_TOKEN")
	}
	t.Log("economics transport double: financial semantics require ECONOMICS_TEST_URL or independent Python v3 tests")
	worker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in model.Document
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			JSON(w, 422, model.Document{"error": "body"})
			return
		}
		if r.URL.Path == "/v3/normalize" {
			rows := []model.Document{}
			total := new(big.Rat)
			for _, raw := range evidence.Rows(in["records"]) {
				amount, _ := new(big.Rat).SetString(model.String(raw, "line_item_unblended_cost"))
				if amount == nil {
					JSON(w, 422, model.Document{"error": "cost"})
					return
				}
				total.Add(total, amount)
				rows = append(rows, model.Document{"ResourceId": raw["line_item_resource_id"], "SubAccountId": raw["line_item_usage_account_id"], "BillingAccountId": raw["bill_payer_account_id"], "InvoiceIssuerName": raw["bill_invoicing_entity"], "RegionId": raw["product_region_code"], "BillingCurrency": raw["line_item_currency_code"], "ChargePeriodStart": raw["line_item_usage_start_date"], "ChargePeriodEnd": raw["line_item_usage_end_date"], "ServiceName": "AmazonEC2", "BilledCost": amount.FloatString(12), "EffectiveCost": amount.FloatString(12), "ContractedCost": nil, "x_SourceId": in["source_id"], "x_SourceVersion": in["source_version"], "x_SourceRecordId": raw["identity_line_item_id"], "x_ProviderFields": raw, "x_NativeComputeCost": amount.FloatString(12), "x_PricingBasis": "UNBLENDED"})
			}
			JSON(w, 200, model.Document{"schema_version": "3", "records": rows, "totals": model.Document{"GBP": total.FloatString(12)}})
			return
		}
		baseline := evidence.Object(in["baseline"])
		if model.String(in, "schema_version") != "3" || len(evidence.Rows(baseline["workload_samples"])) != 14*24*60 || len(evidence.Rows(baseline["source_refs"])) != 1 || model.String(baseline, "source_receipt_id") == "" {
			JSON(w, 422, model.Document{"error": "server evidence not selected"})
			return
		}
		JSON(w, 200, model.Document{"schema_version": "3", "status": "MEASURING", "reason_code": "VERIFICATION_WINDOW_INCOMPLETE", "pre_execution_ready": true, "baseline_id": in["baseline_id"], "fingerprint": evidence.Hash(in), "verified_saving": nil, "pricing_basis": "UNBLENDED"})
	}))
	t.Cleanup(worker.Close)
	return worker.URL, ""
}

// Inserts one interval at a time through the real receipt trigger under the real
// activity role. Only the disposable database owner can install this private
// transaction clock; production's function is restored before committing rows.
func seedTrustedActivityHistory(t *testing.T, admin *store.Store, tenant string, sourceID string) {
	t.Helper()
	ctx := context.Background()
	tx, err := admin.Begin(ctx, tenant)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	_, err = tx.Exec(ctx, `CREATE TEMP TABLE activity_history_clock(instant timestamptz NOT NULL) ON COMMIT DROP; INSERT INTO activity_history_clock VALUES('2026-09-01T00:01:01Z'); GRANT SELECT,UPDATE ON activity_history_clock TO finops_activity; CREATE OR REPLACE FUNCTION activity_receive_time() RETURNS timestamptz LANGUAGE sql VOLATILE AS 'SELECT instant FROM pg_temp.activity_history_clock'; SET LOCAL ROLE finops_activity`)
	if err != nil {
		t.Fatal(err)
	}
	_, err = tx.Exec(ctx, `DO $$
DECLARE i bigint; left_at timestamptz; right_at timestamptz; received timestamptz; n bigint; source jsonb; raw jsonb; body bytea; digest text; doc jsonb; receipt_id text; binding jsonb; last_right timestamptz; last_idle boolean:=false; BEGIN
 SELECT document INTO STRICT source FROM activity_sources WHERE tenant_id=current_setting('app.tenant_id') AND resource_id='resource-dev-api';
 binding:=jsonb_build_object('tenant_id',current_setting('app.tenant_id'),'resource_id',source->>'resource_id','provider_resource_id',source->>'provider_resource_id','account_id',source->>'account_id','region',source->>'region');
 FOR i IN 1..40320 LOOP
  left_at:=CASE WHEN i<=20160 THEN '2026-09-01T00:00:00Z'::timestamptz+(i-1)*interval '1 minute' ELSE '2026-09-16T00:00:00Z'::timestamptz+(i-20161)*interval '1 minute' END;right_at:=left_at+interval '1 minute';received:=right_at+interval '1 second';
  UPDATE activity_history_clock SET instant=received;
  n:=CASE WHEN extract(hour FROM left_at AT TIME ZONE 'UTC')>=7 AND extract(hour FROM left_at AT TIME ZONE 'UTC')<20 THEN 1 ELSE 0 END;
  raw:=jsonb_build_object('schema_version','1','source_id',source->>'id','resource_id',source->>'resource_id','workload_id',source->>'workload_id','sequence',i,'interval_start',left_at,'interval_end',right_at,'metric_definition',source->'metric_definition','accepted',n,'completed',n,'rejected',0,'backlog',0,'inflight',0,'heartbeat',true,'incident','CLEAR','deployment','CLEAR','job','CLEAR');
  body:=convert_to(raw::text,'UTF8');digest:=encode(sha256(body),'hex');receipt_id:=md5(current_setting('app.tenant_id')||':minute:'||i::text);
  doc:=raw||jsonb_build_object('id',receipt_id,'tenant_id',current_setting('app.tenant_id'),'subject',source->>'subject','received_at',received,'body_sha256',digest,'idempotency_key','history-'||i::text,'previous_interval_end',last_right,'previous_sequence',i-1,'previous_idle',last_idle,'binding',binding);
  INSERT INTO activity_receipts(tenant_id,id,source_id,resource_id,sequence,interval_start,interval_end,received_at,body_sha256,idempotency_key,document,raw_body) VALUES(current_setting('app.tenant_id'),receipt_id,source->>'id',source->>'resource_id',i,left_at,right_at,received,digest,'history-'||i::text,doc,body);
  last_right:=right_at;last_idle:=n=0;
 END LOOP;
END $$; RESET ROLE; CREATE OR REPLACE FUNCTION activity_receive_time() RETURNS timestamptz LANGUAGE sql VOLATILE AS 'SELECT clock_timestamp()'`)
	if err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	// Two genuine current receive windows establish current safety without using
	// historical or caller-authored workload fields from the control API.
	end := time.Now().UTC().Truncate(time.Minute).Add(-time.Minute)
	for n := int64(0); n < 2; n++ {
		err = admin.Do(ctx, tenant, func(tx *store.Tx) error {
			if _, e := tx.Exec(ctx, "SET LOCAL ROLE finops_activity"); e != nil {
				return e
			}
			source, e := tx.ActivitySource(ctx, sourceID)
			if e != nil {
				return e
			}
			in := store.ActivityInterval{SchemaVersion: "1", SourceID: sourceID, ResourceID: source.ResourceID, WorkloadID: source.WorkloadID, Sequence: 40321 + n, IntervalStart: end.Add(time.Duration(n-1) * time.Minute), IntervalEnd: end.Add(time.Duration(n) * time.Minute), MetricDefinition: source.MetricDefinition, Heartbeat: true, Incident: "CLEAR", Deployment: "CLEAR", Job: "CLEAR"}
			body, _ := json.Marshal(in)
			_, _, e = tx.ActivityAppend(ctx, store.ActivitySubmission{Interval: in, RawBody: body, Issuer: source.Issuer, Subject: source.Subject, IdempotencyKey: "current-" + string(rune('a'+n))})
			return e
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestTrustedProviderReceiptsSelectBaselineBindPlanAndPreserveRecovery(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("disposable PostgreSQL required")
	}
	ctx := context.Background()
	admin, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Pool.Close()
	if err = admin.Migrate(ctx, "../../migrations"); err != nil {
		t.Fatal(err)
	}
	tenant := "trusted-api-" + model.ID()
	apiDB := trustedRoleStore(t, dsn, "finops_api")
	ingesterDB := trustedRoleStore(t, dsn, "finops_ingester")
	executorDB := trustedRoleStore(t, dsn, "finops_executor")
	endpoint, token := trustedEconomics(t)
	api := API{Store: apiDB, Config: Config{Fixture: false, EconomicsURL: endpoint, EconomicsToken: token, HealthAllowedHosts: "health.example.test"}, Client: &http.Client{Timeout: 60 * time.Second}}
	// An internal test clock places baseline activation immediately after its
	// complete billing days. It is not a runtime option or client-supplied clock.
	clock := time.Date(2026, 9, 15, 0, 0, 10, 0, time.UTC)
	api.Clock = func() time.Time { return clock }
	registration := source.FixtureRegistration(tenant, "trusted-cur2")
	parsed, err := source.ParseRegistration(registration)
	if err != nil {
		t.Fatal(err)
	}
	baseRows := []model.Document{}
	for _, row := range source.FixtureBillingRows(parsed, "i-0123456789abcdef0") {
		if model.String(row, "line_item_usage_start_date") < "2026-09-15T00:00:00Z" {
			row["bill_invoice_id"] = ""
			baseRows = append(baseRows, row)
		}
	}
	reader, err := source.NewFixtureReader(parsed, baseRows)
	if err != nil {
		t.Fatal(err)
	}
	reader.Invoices = []model.Document{}
	retimeTrustedDelivery(reader, "baseline-delivery", time.Date(2026, 9, 15, 0, 0, 5, 0, time.UTC))
	activitySource := store.ActivitySource{ID: "independent-gateway", ResourceID: "resource-dev-api", WorkloadID: "workload-dev", ProviderResourceID: "i-0123456789abcdef0", AccountID: "111122223333", Region: "eu-west-1", Issuer: "https://machine.example.test", Subject: "registered-gateway", MetricDefinition: store.ActivityMetric{ID: "accepted-orders", Version: "1", Unit: "order"}, Enabled: true}
	if err = apiDB.Do(ctx, tenant, func(tx *store.Tx) error {
		if e := tx.Seed(ctx, true); e != nil {
			return e
		}
		w, e := tx.Get(ctx, "workloads", "workload-dev")
		if e != nil {
			return e
		}
		w["health_url"] = "https://health.example.test/ready"
		if _, e = tx.Update(ctx, "workloads", "workload-dev", model.Number(w, "version"), w); e != nil {
			return e
		}
		if _, e = tx.SourceCreate(ctx, registration); e != nil {
			return e
		}
		_, e = tx.ActivityRegister(ctx, activitySource)
		return e
	}); err != nil {
		t.Fatal(err)
	}
	seedTrustedActivityHistory(t, admin, tenant, activitySource.ID)
	archives := map[string]string{}
	persisted := 0
	pipeline := source.Pipeline{Store: ingesterDB, Now: func() time.Time { return clock }, ProviderFactory: func(context.Context, source.Registration) (source.Reader, error) { return reader, nil }, Normalize: func(ctx context.Context, in model.Document) (model.Document, error) {
		return api.economics(ctx, "v3/normalize", in)
	}, Persist: func(_ context.Context, _ string, _ string, raw, canonical model.Document) error {
		if len(evidence.Rows(raw["records"])) != len(evidence.Rows(canonical["records"])) {
			return errors.New("persistence record mismatch")
		}
		persisted++
		return nil
	}, ArchiveObject: func(_ context.Context, gotTenant, id, key string, raw []byte) error {
		if gotTenant != tenant || id != parsed.ID {
			return errors.New("archive scope mismatch")
		}
		archives[key] = source.BytesHash(raw)
		return nil
	}}
	if err = pipeline.Sync(ctx, tenant, parsed.ID); err != nil {
		t.Fatal(err)
	}
	if persisted == 0 || len(archives) < 3 {
		t.Fatal("pipeline published authority without persistence/archive calls")
	}
	in := model.Document{"schema_version": "3", "resource_id": "resource-dev-api", "schedule_id": "schedule-dev", "source_connection_id": parsed.ID, "start": "2026-09-01T00:00:00Z", "end": "2026-09-15T00:00:00Z"}
	for _, field := range []string{"source_proof", "source_scope_records", "invoice_scope_records", "billing_records", "workload_samples", "commitment_scope", "invoice", "invoices"} {
		attempt := model.Clone(in)
		attempt[field] = model.Document{"trusted": true}
		err = apiDB.Do(ctx, tenant, func(tx *store.Tx) error { _, e := api.createTrustedBaseline(ctx, tx, attempt); return e })
		var problem *Problem
		if !errors.As(err, &problem) || problem.Code != "SERVER_SELECTED_EVIDENCE_REQUIRED" {
			t.Fatalf("caller evidence %s accepted:%v", field, err)
		}
	}
	var baseline, ready, plan model.Document
	if err = apiDB.Do(ctx, tenant, func(tx *store.Tx) error { var e error; baseline, e = api.createTrustedBaseline(ctx, tx, in); return e }); err != nil {
		t.Fatal(err)
	}
	if len(evidence.Rows(baseline["workload_samples"])) != 20160 || model.String(baseline, "source_receipt_id") == "" || model.String(baseline, "proof_set_id") == "" {
		t.Fatal("baseline did not bind server-selected independent receipts")
	}
	trustedRejectSnapshotTampering(t, ctx, apiDB, tenant, baseline)
	// Planning and executor safety use physical current time. A fresh provider
	// sync supplies current commitment and source-health receipts independently
	// of the immutable historical baseline's activation clock.
	clock = time.Now().UTC()
	api.Clock = nil // Present-time safety continues to advance during real evaluation.
	// Each provider refresh must also use its actual receive time. Keeping the
	// activation fixture clock fixed here makes a later genuine sync stale when
	// the full native/Python/correction journey lasts longer than five minutes.
	// Historical delivery/baseline timestamps remain frozen; safety does not.
	pipeline.Now = func() time.Time { return time.Now().UTC() }
	if err = pipeline.Sync(ctx, tenant, parsed.ID); err != nil {
		t.Fatal(err)
	}
	refreshTrustedActivity(t, apiDB, admin, tenant, activitySource.ID)
	stopActivityCollector := keepActivityTestCollectorRunning(t, tenant, activitySource.ID)
	defer stopActivityCollector()
	seedDependencyReview(t, ctx, &api, apiDB, tenant, "resource-dev-api")
	_, sliSource := seedSLOAuthority(t, ctx, &api, apiDB, tenant)
	stopCollector := keepSLOTestCollectorRunning(t, tenant, sliSource)
	defer stopCollector()
	if err = apiDB.Do(ctx, tenant, func(tx *store.Tx) error {
		var e error
		ready, e = api.readiness(ctx, tx, "resource-dev-api", true)
		if e != nil {
			return e
		}
		if !model.Bool(ready, "pre_execution_ready") || model.String(ready, "verification_status") != "MEASURING" {
			t.Fatalf("ready baseline must not need a verified future claim:%v", ready)
		}
		_, e = tx.Create(ctx, "recommendations", model.Document{"id": "trusted-recommendation", "resource_id": "resource-dev-api", "workload_id": "workload-dev", "status": "VALIDATED", "pre_execution_ready": true, "readiness_id": ready["id"]})
		if e != nil {
			return e
		}
		plan, e = BuildPlan(ctx, tx, "trusted-recommendation", "schedule-dev", true)
		return e
	}); err != nil {
		t.Fatalf("current plan gate: %#v", err)
	}
	p, err := decodePlan(plan)
	if err != nil {
		t.Fatal(err)
	}
	if p.SchemaVersion != "3" || p.ProofSetID == "" || p.DependencyReviewID == "" || p.DependencyGraphHash == "" || p.BaselineID != model.String(baseline, "id") {
		t.Fatalf("unbound v3 plan:%+v", p)
	}
	legacy := p
	legacy.SchemaVersion = "2"
	legacy.ProofSetID = ""
	if err = apiDB.Do(ctx, tenant, func(tx *store.Tx) error {
		res, e := tx.Get(ctx, "resources", "resource-dev-api")
		if e != nil {
			return e
		}
		return readinessPlanCheck(ctx, tx, legacy, res)
	}); err == nil {
		t.Fatal("legacy payload reused v3 execution authority before revocation")
	}
	if err = apiDB.Do(ctx, tenant+"-other", func(tx *store.Tx) error {
		_, e := tx.EvidenceGet(ctx, "baseline", p.BaselineID)
		if e != pgx.ErrNoRows {
			t.Fatalf("cross tenant baseline:%v", e)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	assertStaleDependencyServices := trustedDependencyServiceBoundaries(t, ctx, apiDB, executorDB, tenant, &api, p)
	if os.Getenv("ECONOMICS_TEST_URL") != "" {
		trustedNativeClaim(t, ctx, admin, apiDB, ingesterDB, executorDB, tenant, &api, &pipeline, reader, parsed, p)
	}
	// A graph revision cannot change an approved new stop, while its old signed
	// restoration below remains valid after graph/source revocation and expiry.
	if err = apiDB.Do(ctx, tenant, func(tx *store.Tx) error {
		g, e := tx.DependencyGraph(ctx)
		if e != nil {
			return e
		}
		_, e = tx.DependencyGraphAppend(ctx, model.Number(g, "version"), model.Document{"edges": []model.Document{}, "changed_by": "test-reviewer", "reason": "explicit re-review required"})
		return e
	}); err != nil {
		t.Fatal(err)
	}
	if err = apiDB.Do(ctx, tenant, func(tx *store.Tx) error {
		return DependencyPlanReady(ctx, tx, "resource-dev-api", p.DependencyReviewID, p.DependencyGraphHash, time.Now())
	}); err == nil {
		t.Fatal("graph revision retained old plan authority")
	}
	assertStaleDependencyServices()
	if err = apiDB.Do(ctx, tenant, func(tx *store.Tx) error {
		d, e := tx.SourceGet(ctx, parsed.ID)
		if e != nil {
			return e
		}
		d["enabled"] = false
		_, e = tx.SourceUpdate(ctx, parsed.ID, model.Number(d, "version"), d)
		return e
	}); err != nil {
		t.Fatal(err)
	}
	if err = apiDB.Do(ctx, tenant, func(tx *store.Tx) error { return precheck(ctx, tx, p, time.Now()) }); err == nil {
		t.Fatal("revoked source still authorized a new stop")
	}
	// Source revocation, expired stop authority and org pause cannot strand a stop
	// already owned by the actual restricted executor identity.
	pub, private, _ := ed25519.GenerateKey(rand.Reader)
	p.ID, p.Nonce = model.ID(), model.ID()
	p.ExpiresAt = time.Now().Add(-time.Hour)
	envelope, err := safety.Sign(p, private)
	if err != nil {
		t.Fatal(err)
	}
	executionID := model.ID()
	if err = apiDB.Do(ctx, tenant, func(tx *store.Tx) error {
		org, e := tx.Get(ctx, "org", tenant)
		if e != nil {
			return e
		}
		org["paused"] = true
		if _, e = tx.Update(ctx, "org", tenant, model.Number(org, "version"), org); e != nil {
			return e
		}
		_, e = tx.Create(ctx, "executions", model.Document{"id": executionID, "change_plan_id": p.ID, "status": "RESTORING", "restoration_owned": true})
		return e
	}); err != nil {
		t.Fatal(err)
	}
	if err = admin.Do(ctx, tenant, func(tx *store.Tx) error {
		if _, e := tx.Exec(ctx, "SET LOCAL ROLE finops_signer"); e != nil {
			return e
		}
		data, _ := json.Marshal(envelope)
		_, e := tx.Exec(ctx, "INSERT INTO signed_plans(tenant_id,plan_id,nonce,envelope) VALUES($1,$2,$3,$4)", tenant, p.ID, p.Nonce, data)
		return e
	}); err != nil {
		t.Fatal(err)
	}
	if err = executorDB.Do(ctx, tenant, func(tx *store.Tx) error {
		data, _ := json.Marshal(model.Document{"state": "stopped", "nonce": p.Nonce})
		_, e := tx.Exec(ctx, "INSERT INTO provider_operations(tenant_id,execution_id,resource_id,stop_intent,stop_owned,restored,document) VALUES($1,$2,$3,true,true,false,$4)", tenant, executionID, "111122223333:eu-west-1:i-0123456789abcdef0", data)
		return e
	}); err != nil {
		t.Fatal(err)
	}
	executor := SecureService{Store: executorDB, Config: Config{Fixture: true, Role: "executor"}, Public: pub}
	state, err := executor.dispatch(ctx, model.Dispatch{Envelope: envelope, ExecutionID: executionID, Operation: "START"})
	if err != nil || state.State != "running" {
		t.Fatalf("owned restoration stranded by source/expiry/pause:%+v,%v", state, err)
	}
}

func retimeTrustedDelivery(reader *source.FixtureReader, id string, created time.Time) {
	oldID := model.String(reader.Execution, "ExecutionId")
	rewrite := func(value string) string {
		return strings.ReplaceAll(strings.ReplaceAll(value, oldID, id), "20261001T000000Z", created.UTC().Format("20060102T150405Z"))
	}
	objects := map[string]provider.BillingObject{}
	for key, object := range reader.Objects {
		object.Key = rewrite(key)
		object.LastModified = created.Add(time.Second)
		if strings.HasSuffix(key, "Manifest.json") {
			object.Data = []byte(rewrite(string(object.Data)))
			object.LastModified = created.Add(2 * time.Second)
		}
		object.VersionID = "fixture-" + source.BytesHash(object.Data)
		object.ETag = source.BytesHash(object.Data)
		objects[object.Key] = object
	}
	reader.Objects = objects
	for n, key := range reader.ManifestKeys {
		reader.ManifestKeys[n] = rewrite(key)
	}
	reader.Execution["ExecutionId"] = id
	reader.Execution["ExecutionStatus"] = model.Document{"StatusCode": "DELIVERY_SUCCESS", "CreatedAt": created.UTC().Format(time.RFC3339Nano)}
}

func trustedNativeClaim(t *testing.T, ctx context.Context, admin, apiDB, ingesterDB, executorDB *store.Store, tenant string, api *API, pipeline *source.Pipeline, reader *source.FixtureReader, registration source.Registration, p model.Plan) {
	t.Helper()
	t.Log("native financial acceptance: dispatching signed schema-3 stop/start")
	refreshTrustedActivity(t, apiDB, admin, tenant, "independent-gateway")
	pub, private, _ := ed25519.GenerateKey(rand.Reader)
	envelope, err := safety.Sign(p, private)
	if err != nil {
		t.Fatal(err)
	}
	executionID := model.ID()
	if err = apiDB.Do(ctx, tenant, func(tx *store.Tx) error {
		_, e := tx.Create(ctx, "executions", model.Document{"id": executionID, "change_plan_id": p.ID, "resource_id": "resource-dev-api", "recommendation_id": "trusted-recommendation", "status": "RUNNING"})
		return e
	}); err != nil {
		t.Fatal(err)
	}
	if err = admin.Do(ctx, tenant, func(tx *store.Tx) error {
		if _, e := tx.Exec(ctx, "SET LOCAL ROLE finops_signer"); e != nil {
			return e
		}
		raw, _ := json.Marshal(envelope)
		_, e := tx.Exec(ctx, "INSERT INTO signed_plans(tenant_id,plan_id,nonce,envelope) VALUES($1,$2,$3,$4)", tenant, p.ID, p.Nonce, raw)
		return e
	}); err != nil {
		t.Fatal(err)
	}
	executor := SecureService{Store: executorDB, Config: Config{Fixture: true, Role: "executor"}, Public: pub}
	stopped, err := executor.dispatch(ctx, model.Dispatch{Envelope: envelope, ExecutionID: executionID, Operation: "STOP"})
	if err != nil || stopped.State != "stopped" {
		t.Fatalf("authorized native-proof fixture stop:%+v,%v", stopped, err)
	}
	started, err := executor.dispatch(ctx, model.Dispatch{Envelope: envelope, ExecutionID: executionID, Operation: "START"})
	if err != nil || started.State != "running" {
		t.Fatalf("fixture owned start:%+v,%v", started, err)
	}
	for n := 0; n < 3; n++ {
		if _, err = executor.dispatch(ctx, model.Dispatch{Envelope: envelope, ExecutionID: executionID, Operation: "HEALTH"}); err != nil {
			t.Fatal(err)
		}
		if n == 0 {
			time.Sleep(2100 * time.Millisecond)
		}
	}
	if err = apiDB.Do(ctx, tenant, func(tx *store.Tx) error {
		x, e := tx.Get(ctx, "executions", executionID)
		if e != nil {
			return e
		}
		x["status"] = "COMPLETED"
		_, e = tx.Update(ctx, "executions", executionID, model.Number(x, "version"), x)
		return e
	}); err != nil {
		t.Fatal(err)
	}
	var owned []model.Document
	if err = apiDB.Do(ctx, tenant, func(tx *store.Tx) error { var e error; owned, e = ownedIntervals(ctx, tx, p); return e }); err != nil {
		t.Fatal(err)
	}
	if len(owned) != 1 {
		t.Fatalf("actual stop/start/health did not establish one owned receipt:%v", owned)
	}
	final, err := source.NewFixtureReader(registration, nil)
	if err != nil {
		t.Fatal(err)
	}
	retimeTrustedDelivery(final, "final-delivery", time.Date(2026, 10, 1, 12, 0, 1, 0, time.UTC))
	// An authentic later delivery does not make the earlier execution or object
	// versions disappear. The ordinary pipeline revalidates retained deliveries.
	final.Executions = []model.Document{model.Clone(reader.Execution), model.Clone(final.Execution)}
	final.ManifestKeys = append(append([]string{}, reader.ManifestKeys...), final.ManifestKeys...)
	for key, object := range reader.Objects {
		final.Objects[key] = object
	}
	*reader = *final
	if err = pipeline.Sync(ctx, tenant, registration.ID); err != nil {
		t.Fatalf("final native delivery: %v", err)
	}
	t.Log("native financial acceptance: final delivery persisted; selecting post-period receipts")
	sealMeasurement := func() model.Document {
		t.Helper()
		var snapshot model.Document
		if err = apiDB.Do(ctx, tenant, func(tx *store.Tx) error {
			res, e := tx.Get(ctx, "resources", "resource-dev-api")
			if e != nil {
				return e
			}
			snapshot, e = api.trustedSnapshot(ctx, tx, model.Document{"resource_id": res["id"], "source_connection_id": registration.ID, "start": "2026-09-16T00:00:00Z", "end": "2026-09-30T00:00:00Z"}, res)
			return e
		}); err != nil {
			t.Fatalf("post-period server selection: %v", err)
		}
		_, clockFixture := evidence.FixtureMeasurement(evidence.Object(snapshot["binding"]), owned)
		// The issued native invoice is dated October 1 at noon. Observe it only
		// afterward; the fixture clock must not turn issuance into future evidence.
		financialClock := evidence.Object(clockFixture["financial_clock"])
		financialClock["as_of"] = "2026-10-02T00:00:00Z"
		snapshot["measurement_id"], snapshot["baseline_id"], snapshot["evidence_as_of"], snapshot["financial_clock"] = p.MeasurementID, p.BaselineID, time.Now().UTC().Format(time.RFC3339Nano), financialClock
		if len(evidence.Rows(snapshot["workload_samples"])) != 20160 {
			t.Fatal("post period did not resolve full independent minute history")
		}
		if err = ingesterDB.Do(ctx, tenant, func(tx *store.Tx) error { _, e := tx.EvidenceCreate(ctx, "measurement_snapshot", snapshot); return e }); err != nil {
			t.Fatalf("sealing post-period evidence: %v", err)
		}
		return snapshot
	}
	sealMeasurement()
	t.Log("native financial acceptance: evaluating sealed post-period evidence")
	fixtureAPI := *api
	fixtureAPI.Config.Fixture = true
	verify := func() model.Document {
		t.Helper()
		var result model.Document
		e := apiDB.Do(ctx, tenant, func(tx *store.Tx) error {
			var e error
			result, _, e = fixtureAPI.verifySavings(ctx, tx, nil, model.Document{"execution_id": executionID})
			return e
		})
		if e != nil {
			t.Fatalf("verification boundary: %v", e)
		}
		rows := evidence.Rows(result["savings"])
		if len(rows) != 1 {
			t.Fatalf("one execution claim expected:%v", result)
		}
		return rows[0]
	}
	verified := verify()
	if model.String(verified, "status") != "VERIFIED" || model.String(verified, "verified_saving") != "5.160000000000" {
		t.Fatalf("native final invoice/exact owned absence did not verify5.16:%v", verified)
	}
	t.Log("native financial acceptance: exact 5.160000000000 GBP claim verified")
	ledger := func() []model.Document {
		t.Helper()
		var rows []model.Document
		if e := apiDB.Do(ctx, tenant, func(tx *store.Tx) error { var e error; rows, e = tx.Evidence(ctx, "savings_ledger"); return e }); e != nil {
			t.Fatal(e)
		}
		return rows
	}
	before := ledger()
	if len(before) != 1 {
		t.Fatalf("unexpected initial ledger count:%d", len(before))
	}
	if err = pipeline.Sync(ctx, tenant, registration.ID); err != nil {
		t.Fatal(err)
	}
	if replay := verify(); model.String(replay, "id") != model.String(verified, "id") || len(ledger()) != 1 {
		t.Fatal("source replay added a second claim")
	}
	reader.Invoices[0]["TaxAuthorityStatus"] = "CANCELLED"
	if err = pipeline.Sync(ctx, tenant, registration.ID); err != nil {
		t.Fatal(err)
	}
	sealMeasurement()
	invalidated := verify()
	if invalidated["verified_saving"] != nil || model.String(invalidated, "reason_code") != "INVOICE_CANCELLED" {
		t.Fatalf("native invoice cancellation retained current claimed saving:%v", invalidated)
	}
	after := ledger()
	if len(after) != 2 {
		t.Fatalf("invoice cancellation must append exactly one correction:%d", len(after))
	}
	current := 0
	history := false
	for _, row := range after {
		if model.Bool(row, "is_current") {
			current++
			if row["verified_saving"] != nil {
				t.Fatal("cancelled current head still claims money")
			}
		}
		if model.String(row, "id") == model.String(verified, "id") {
			history = model.String(row, "verified_saving") == "5.160000000000" && !model.Bool(row, "is_current")
		}
	}
	if current != 1 || !history {
		t.Fatalf("append-only correction lost history/current identity:%v", after)
	}
	verify()
	if len(ledger()) != 2 {
		t.Fatal("replayed invalidation added redundant ledger history")
	}
	t.Log("native financial acceptance: replay deduplicated; cancellation appended one null current correction")
}

func trustedRejectSnapshotTampering(t *testing.T, ctx context.Context, db *store.Store, tenant string, snapshot model.Document) {
	t.Helper()
	for _, field := range []string{"billing_records", "source_scope_records", "invoice_scope_records", "invoices", "workload_samples"} {
		// Alter the embedded selection without changing its valid source receipt.
		// Even an intact identifier must not authorize replacement evidence.
		attempt := model.Document{}
		for key, value := range snapshot {
			attempt[key] = value
		}
		rows := append([]model.Document{}, evidence.Rows(snapshot[field])...)
		rows = append(rows, model.Document{"source_record_id": "caller-injected", "accepted": "999", "BilledCost": "0", "native": model.Document{"TaxAuthorityStatus": "ISSUED"}})
		attempt[field] = rows
		err := db.Do(ctx, tenant, func(tx *store.Tx) error {
			res, err := tx.Get(ctx, "resources", "resource-dev-api")
			if err != nil {
				return err
			}
			return validateSnapshotSources(ctx, tx, attempt, res)
		})
		want := "SNAPSHOT_SOURCE_RECORDS_CHANGED"
		if field == "workload_samples" {
			want = "SNAPSHOT_ACTIVITY_RECEIPTS_CHANGED"
		}
		if err == nil || err.Error() != want {
			t.Fatalf("altered %s retained receipt authority: %v", field, err)
		}
	}
}

func refreshTrustedActivity(t *testing.T, readDB, admin *store.Store, tenant, sourceID string) {
	t.Helper()
	ctx := context.Background()
	var latest store.ActivityReceipt
	if err := readDB.Do(ctx, tenant, func(tx *store.Tx) error {
		var e error
		latest, e = tx.ActivityLatest(ctx, "resource-dev-api")
		return e
	}); err != nil {
		t.Fatal(err)
	}
	current := time.Now().UTC().Truncate(time.Minute)
	for end := current.Add(-time.Minute); !end.After(current); end = end.Add(time.Minute) {
		if !end.After(latest.IntervalEnd) {
			continue
		}
		err := admin.Do(ctx, tenant, func(tx *store.Tx) error {
			if _, e := tx.Exec(ctx, "SET LOCAL ROLE finops_activity"); e != nil {
				return e
			}
			if _, e := tx.Exec(ctx,"SELECT pg_advisory_xact_lock(hashtextextended($1,0))",tenant+":activity:"+sourceID);e!=nil{return e}
			var e error
			latest,e=tx.ActivityLatest(ctx,"resource-dev-api")
			if e!=nil{return e}
			if !end.After(latest.IntervalEnd){return nil}
			source, e := tx.ActivitySource(ctx, sourceID)
			if e != nil {
				return e
			}
			in := store.ActivityInterval{SchemaVersion: "1", SourceID: sourceID, ResourceID: source.ResourceID, WorkloadID: source.WorkloadID, Sequence: latest.Sequence + 1, IntervalStart: end.Add(-time.Minute), IntervalEnd: end, MetricDefinition: source.MetricDefinition, Heartbeat: true, Incident: "CLEAR", Deployment: "CLEAR", Job: "CLEAR"}
			raw, _ := json.Marshal(in)
			latest, _, e = tx.ActivityAppend(ctx, store.ActivitySubmission{Interval: in, RawBody: raw, Issuer: source.Issuer, Subject: source.Subject, IdempotencyKey: "refresh-" + strconv.FormatInt(in.Sequence, 10)})
			return e
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

// Continue the explicitly synthetic live activity source while expensive
// financial checks run. Only newly completed current minutes pass normal
// admission; elapsed unobserved history is never manufactured.
func keepActivityTestCollectorRunning(t *testing.T, tenant, sourceID string) func() {
	t.Helper()
	db := trustedRoleStore(t, os.Getenv("TEST_DATABASE_URL"), "finops_activity")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				done <- nil
				return
			case <-ticker.C:
				err := db.Do(ctx, tenant, func(tx *store.Tx) error {
					if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", tenant+":activity:"+sourceID); err != nil {
						return err
					}
					latest, err := tx.ActivityLatest(ctx, "resource-dev-api")
					if err != nil {
						return err
					}
					end := time.Now().UTC().Truncate(time.Minute)
					if !end.After(latest.IntervalEnd) {
						return nil
					}
					source, err := tx.ActivitySource(ctx, sourceID)
					if err != nil {
						return err
					}
					in := store.ActivityInterval{SchemaVersion: "1", SourceID: sourceID, ResourceID: source.ResourceID, WorkloadID: source.WorkloadID, Sequence: latest.Sequence + 1, IntervalStart: end.Add(-time.Minute), IntervalEnd: end, MetricDefinition: source.MetricDefinition, Heartbeat: true, Incident: "CLEAR", Deployment: "CLEAR", Job: "CLEAR"}
					raw, _ := json.Marshal(in)
					_, _, err = tx.ActivityAppend(ctx, store.ActivitySubmission{Interval: in, RawBody: raw, Issuer: source.Issuer, Subject: source.Subject, IdempotencyKey: "live-" + strconv.FormatInt(in.Sequence, 10)})
					return err
				})
				if err != nil {
					if ctx.Err() != nil {
						done <- nil
					} else {
						done <- err
					}
					return
				}
			}
		}
	}()
	return func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("independent fixture activity collector: %v", err)
		}
	}
}
