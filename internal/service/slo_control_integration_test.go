package service

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/evidence"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/safety"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/slo"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"os"
	"testing"
	"time"
)

func TestSLOCurrentMinuteBreachLatchesAndPreservesOwnedRestoration(t *testing.T) {
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
	tenant := "slo-control-" + model.ID()
	apiDB := trustedRoleStore(t, dsn, "finops_api")
	workerDB := trustedRoleStore(t, dsn, "finops_worker")
	signerDB := trustedRoleStore(t, dsn, "finops_signer")
	executorDB := trustedRoleStore(t, dsn, "finops_executor")
	api := API{Store: apiDB, Config: Config{Fixture: true}}
	if err = apiDB.Do(ctx, tenant, func(tx *store.Tx) error { return tx.Seed(ctx, true) }); err != nil {
		t.Fatal(err)
	}
	obj, source := seedSLOAuthority(t, ctx, &api, apiDB, tenant)
	var snapshot model.Document
	if err = apiDB.Do(ctx, tenant, func(tx *store.Tx) error {
		res, e := tx.Get(ctx, "resources", "resource-dev-api")
		if e != nil {
			return e
		}
		state, e := currentSLO(ctx, tx, res, nil, true, time.Time{}, time.Time{})
		if e != nil {
			return e
		}
		if reasons := sloReasons(state); len(reasons) != 0 {
			t.Fatal("initialcurrentevidence notCLEAR", reasons)
		}
		snapshot, e = sealSLO(ctx, tx, state)
		return e
	}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	op := model.Operation{Type: "EC2_STOP", ResourceID: "resource-dev-api", ProviderResourceID: source.ProviderResourceID, AccountID: source.AccountID, Region: source.Region}
	restore := op
	restore.Type = "EC2_START"
	p := model.Plan{ID: model.ID(), TenantID: tenant, Nonce: model.ID(), SchemaVersion: "3", WorkloadID: "workload-dev", ScheduleID: "schedule-dev", Fixture: true, RiskClass: "R1", CreatedAt: now.Add(-time.Minute), StopAt: now.Add(-30 * time.Second), ExpiresAt: now.Add(-time.Second), RestoreAt: now.Add(10 * time.Second), MeasurementID: model.ID(), Operations: []model.Operation{op, restore}, SLOObjectiveID: model.String(obj, "id"), SLOObjectiveVersion: model.Number(obj, "version"), SLOObjectiveHash: model.String(obj, "hash"), SLOEvaluationID: model.String(snapshot, "id"), SLOEvaluationHash: model.String(snapshot, "hash")}
	execution := model.ID()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := safety.Sign(p, private)
	if err != nil {
		t.Fatal(err)
	}
	// This focused compensation test seeds an already-owned fixture occurrence
	// through the actual signer/executor database roles. It grants no new STOP;
	// the primary trusted integration proves real v3 planning and STOP separately.
	if err = apiDB.Do(ctx, tenant, func(tx *store.Tx) error {
		if _, e := tx.Create(ctx, "change_plans", model.Document{"id": p.ID, "payload": p, "status": "APPROVED", "stop_at": p.StopAt.Format(time.RFC3339Nano)}); e != nil {
			return e
		}
		_, e := tx.Create(ctx, "executions", model.Document{"id": execution, "change_plan_id": p.ID, "resource_id": op.ResourceID, "workload_id": p.WorkloadID, "schedule_id": p.ScheduleID, "status": "RESTORING", "restoration_owned": true})
		return e
	}); err != nil {
		t.Fatal(err)
	}
	if err = signerDB.Do(ctx, tenant, func(tx *store.Tx) error {
		b, _ := json.Marshal(envelope)
		_, e := tx.Exec(ctx, "INSERT INTO signed_plans(tenant_id,plan_id,nonce,envelope) VALUES($1,$2,$3,$4)", tenant, p.ID, p.Nonce, b)
		return e
	}); err != nil {
		t.Fatal(err)
	}
	if err = executorDB.Do(ctx, tenant, func(tx *store.Tx) error {
		b, _ := json.Marshal(model.Document{"state": "stopped", "nonce": p.Nonce, "stopped_at": p.StopAt.Format(time.RFC3339Nano)})
		_, e := tx.Exec(ctx, "INSERT INTO provider_operations(tenant_id,execution_id,resource_id,stop_intent,stop_owned,restored,document) VALUES($1,$2,$3,true,true,false,$4)", tenant, execution, op.AccountID+":"+op.Region+":"+op.ProviderResourceID, b)
		return e
	}); err != nil {
		t.Fatal(err)
	}
	observe := func() string {
		t.Helper()
		var reason string
		if err := workerDB.Do(ctx, tenant, func(tx *store.Tx) error { var e error; reason, e = ObserveSLO(ctx, tx, p, execution); return e }); err != nil {
			t.Fatal(err)
		}
		return reason
	}
	if reason := observe(); reason != "" {
		t.Fatal("initialgoodstate latched failure", reason)
	}
	counts := func() (int, int) {
		t.Helper()
		var violations, events int
		if err := apiDB.Do(ctx, tenant, func(tx *store.Tx) error {
			if e := tx.QueryRow(ctx, "SELECT count(*) FROM slo_violations WHERE tenant_id=$1 AND execution_id=$2", tenant, execution).Scan(&violations); e != nil {
				return e
			}
			return tx.QueryRow(ctx, "SELECT count(*) FROM outbox WHERE tenant_id=$1 AND event_type='execution.slo_violation' AND payload->>'execution_id'=$2", tenant, execution).Scan(&events)
		}); err != nil {
			t.Fatal(err)
		}
		return violations, events
	}
	if v, n := counts(); v != 0 || n != 0 {
		t.Fatal("initialgood observations emitted violation")
	}
	// Wait for a genuine new complete receive minute. Never replace old receipt
	// bodies, change database time, or manufacture a historical upload authority.
	delay := time.Until(time.Now().UTC().Truncate(time.Minute).Add(time.Minute).Add(150 * time.Millisecond))
	t.Logf("waiting %.1fs for next actual complete SLI minute", delay.Seconds())
	time.Sleep(delay)
	refreshSLOTestReceipts(t, ctx, tenant, source, true)
	if reason := observe(); reason != "SLO_ERROR_RATE_BREACH" {
		t.Fatalf("actual current100requests/10errors did not latch hardbreach:%s", reason)
	}
	if reason := observe(); reason != "SLO_ERROR_RATE_BREACH" {
		t.Fatal("observer retry forgot first failure", reason)
	}
	if v, n := counts(); v != 1 || n != 1 {
		t.Fatalf("expectedone immutable violation+event,got%d/%d", v, n)
	}
	var latched model.Document
	if err = apiDB.Do(ctx, tenant, func(tx *store.Tx) error {
		rows, e := tx.SLOViolations(ctx, p.MeasurementID)
		if e != nil {
			return e
		}
		latched = rows[0]
		latest, e := tx.SLOLatest(ctx, source.ResourceID, source.ObjectiveID)
		if e != nil {
			return e
		}
		ids := model.Strings(evidence.Object(evidence.Object(latched["state"])["evaluation"]), "receipt_ids")
		found := false
		for _, id := range ids {
			found = found || id == latest.ID
		}
		if !found {
			t.Fatal("latched evidence omitted actual current receipt", ids)
		}
		org, e := tx.Get(ctx, "org", tenant)
		if e != nil {
			return e
		}
		org["paused"] = true
		_, e = tx.Update(ctx, "org", tenant, model.Number(org, "version"), org)
		return e
	}); err != nil {
		t.Fatal(err)
	}
	executor := SecureService{Store: executorDB, Config: Config{Fixture: true, Role: "executor"}, Public: public}
	if state, e := executor.dispatch(ctx, model.Dispatch{Envelope: envelope, ExecutionID: execution, Operation: "START"}); e != nil || state.State != "running" {
		t.Fatalf("SLO/expiry/pause stranded existing restoration:%+v %v", state, e)
	}
	for n := 0; n < 3; n++ {
		if state, e := executor.dispatch(ctx, model.Dispatch{Envelope: envelope, ExecutionID: execution, Operation: "HEALTH"}); e != nil || !state.Healthy {
			t.Fatalf("restoration health failed:%+v %v", state, e)
		}
		if n == 0 {
			time.Sleep(2100 * time.Millisecond)
		}
	}
	// A later explicit policy can make the same collected current observations
	// CLEAR, while the old occurrence remains disqualified under its signed policy.
	relaxed := sloTestObjective()
	limits := evidence.Object(relaxed["limits"])
	limits["max_error_rate_ppm"], limits["max_p95_latency_ms"] = 200000, 120
	relaxed["limits"] = limits
	revised, e := dependencyRequest(t, ctx, &api, apiDB, tenant, "workloads/workload-dev/slo-objectives", 1, relaxed, false)
	if e != nil {
		t.Fatal(e)
	}
	local := api
	local.Config.Issuer = source.Issuer
	registered, e := dependencyRequest(t, ctx, &local, apiDB, tenant, "slo-sources", 0, model.Document{"objective_id": revised["id"], "resource_id": source.ResourceID, "subject": source.Subject}, false)
	if e != nil {
		t.Fatal(e)
	}
	var replacement slo.Source
	b, _ := json.Marshal(registered)
	_ = json.Unmarshal(b, &replacement)
	refreshSLOTestReceipts(t, ctx, tenant, replacement, true)
	if err = apiDB.Do(ctx, tenant, func(tx *store.Tx) error {
		res, e := tx.Get(ctx, "resources", op.ResourceID)
		if e != nil {
			return e
		}
		state, e := currentSLO(ctx, tx, res, nil, true, time.Time{}, time.Time{})
		if e == nil && len(sloReasons(state)) > 0 {
			t.Fatal("newexplicitpolicy current state notCLEAR", state)
		}
		return e
	}); err != nil {
		t.Fatal(err)
	}
	if reason := observe(); reason != "SLO_ERROR_RATE_BREACH" {
		t.Fatal("latergoodpolicy state erased first immutable failure", reason)
	}
	if v, n := counts(); v != 1 || n != 1 {
		t.Fatal("latergoodstate rewrote/duplicated latch or event", v, n)
	}
	if err = apiDB.Do(ctx, tenant, func(tx *store.Tx) error {
		rows, e := tx.SLOViolations(ctx, p.MeasurementID)
		if e == nil && rows[0]["id"] != latched["id"] {
			t.Fatal("first failure was replaced")
		}
		return e
	}); err != nil {
		t.Fatal(err)
	}
}
