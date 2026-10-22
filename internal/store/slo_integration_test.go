package store

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/slo"
	"github.com/jackc/pgx/v5"
	"os"
	"testing"
	"time"
)

func TestSLOEvidenceRoleBindingImmutabilityReplayAndLatch(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("disposable PostgreSQL required")
	}
	ctx := context.Background()
	db, e := Open(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Pool.Close()
	if e = db.Migrate(ctx, "../../migrations"); e != nil {
		t.Fatal(e)
	}
	tenant := "slo-" + model.ID()
	run := func(role string, fn func(*Tx) error) error {
		return db.Do(ctx, tenant, func(tx *Tx) error {
			if _, e := tx.Exec(ctx, "SET LOCAL ROLE "+pgx.Identifier{role}.Sanitize()); e != nil {
				return e
			}
			return fn(tx)
		})
	}
	objective := slo.Objective{SchemaVersion: "1", WorkloadID: "workload", Limits: slo.Limits{MaxErrorRatePPM: 10000, MinAvailabilityPPM: 999000, MaxP95LatencyMS: 180, MaxP99LatencyMS: 250, MinLatencySamples: 1}, EvaluationMinutes: 2, Availability: slo.Availability{Mode: "ALWAYS", Timezone: "UTC", Windows: []slo.Window{}}, Regression: slo.Regression{Enabled: false, MaxPercent: 15}}
	var obj model.Document
	if e = run("finops_api", func(tx *Tx) error {
		if _, e := tx.Create(ctx, "workloads", model.Document{"id": "workload", "owner": "owner", "environment": "NON_PRODUCTION"}); e != nil {
			return e
		}
		if _, e := tx.Create(ctx, "resources", model.Document{"id": "resource", "workload_id": "workload", "provider_resource_id": "i-slo", "account_id": "111122223333", "region": "eu-west-1"}); e != nil {
			return e
		}
		var e error
		obj, e = tx.SLOObjectiveAppend(ctx, "workload", 0, slo.Document(objective))
		return e
	}); e != nil {
		t.Fatal(e)
	}
	if e = run("finops_api", func(tx *Tx) error {
		_, e := tx.SLOObjectiveAppend(ctx, "workload", 0, slo.Document(objective))
		return e
	}); !errors.Is(e, ErrConflict) {
		t.Fatal("stale objective revision accepted", e)
	}
	source := slo.Source{SchemaVersion: "1", ID: "sli-gateway", ObjectiveID: model.String(obj, "id"), WorkloadID: "workload", ResourceID: "resource", ProviderResourceID: "i-slo", AccountID: "111122223333", Region: "eu-west-1", Issuer: "https://machine.invalid", Subject: "independent-collector", Enabled: true}
	if e = run("finops_api", func(tx *Tx) error { var e error; source, e = tx.SLORegister(ctx, source); return e }); e != nil {
		t.Fatal(e)
	}
	now := time.Now().UTC()
	end := now.Truncate(time.Minute).Add(-time.Minute)
	bound := int64(100)
	in := slo.Interval{SchemaVersion: "1", SourceID: source.ID, ObjectiveID: source.ObjectiveID, WorkloadID: source.WorkloadID, ResourceID: source.ResourceID, Sequence: 1, IntervalStart: end.Add(-time.Minute), IntervalEnd: end, RequestCount: 100, AvailabilityGoodSeconds: 60, AvailabilityTotalSeconds: 60, Latency: slo.Histogram{Unit: "milliseconds", SampleCount: 100, Buckets: []slo.Bucket{{UpperBoundMS: &bound, Count: 100}, {UpperBoundMS: nil, Count: 0}}}}
	submit := func(tx *Tx, i slo.Interval, subject, key string) (slo.Receipt, bool, error) {
		b, _ := json.Marshal(i)
		return tx.SLOAppend(ctx, SLOSubmission{Interval: i, RawBody: b, Issuer: source.Issuer, Subject: subject, IdempotencyKey: key})
	}
	var first slo.Receipt
	if e = run("finops_activity", func(tx *Tx) error { var e error; first, _, e = submit(tx, in, source.Subject, "one"); return e }); e != nil {
		t.Fatal(e)
	}
	if first.WriterRole != "finops_activity" || first.TenantID != tenant || first.BodySHA256 == "" || first.ReceivedAt.IsZero() {
		t.Fatal("receipt lost trusted provenance", first)
	}
	if e = run("finops_activity", func(tx *Tx) error {
		r, replay, e := submit(tx, in, source.Subject, "one")
		if e == nil && (!replay || r.ID != first.ID) {
			t.Fatal("exact replay inserted evidence")
		}
		return e
	}); e != nil {
		t.Fatal(e)
	}
	changed := in
	changed.ErrorCount = 1
	if e = run("finops_activity", func(tx *Tx) error { _, _, e := submit(tx, changed, source.Subject, "one"); return e }); !errors.Is(e, ErrSLOConflict) {
		t.Fatal("changed replay accepted", e)
	}
	next := in
	next.Sequence = 2
	next.IntervalStart = in.IntervalEnd
	next.IntervalEnd = in.IntervalEnd.Add(time.Minute)
	if e = run("finops_activity", func(tx *Tx) error { _, _, e := submit(tx, next, "unregistered-human", "two"); return e }); !errors.Is(e, ErrSLOSource) {
		t.Fatal("unregistered machine accepted", e)
	}
	if e = run("finops_api", func(tx *Tx) error { _, _, e := submit(tx, next, source.Subject, "two"); return e }); e == nil {
		t.Fatal("console/API forged SLI receipt")
	}
	if e = run("finops_activity", func(tx *Tx) error { _, _, e := submit(tx, next, source.Subject, "two"); return e }); e != nil {
		t.Fatal(e)
	}
	old := next
	old.Sequence = 3
	old.IntervalStart = old.IntervalStart.Add(-time.Hour)
	old.IntervalEnd = old.IntervalEnd.Add(-time.Hour)
	if e = run("finops_activity", func(tx *Tx) error { _, _, e := submit(tx, old, source.Subject, "old"); return e }); !errors.Is(e, ErrSLOOrder) {
		t.Fatal("historical backfill accepted", e)
	}
	for _, role := range []string{"finops_worker", "finops_signer", "finops_executor", "finops_ingester"} {
		if e = run(role, func(tx *Tx) error {
			_, e := tx.SLOObjectiveAppend(ctx, "workload", 1, slo.Document(objective))
			return e
		}); e == nil {
			t.Fatalf("%s forged objective", role)
		}
		if e = run(role, func(tx *Tx) error {
			rs, e := tx.SLOReceipts(ctx, "resource", source.ObjectiveID, in.IntervalStart, next.IntervalEnd)
			if e == nil && len(rs) != 2 {
				t.Fatal("reader lost receipts")
			}
			return e
		}); e != nil {
			t.Fatal(role, e)
		}
	}
	if e = run("finops_activity", func(tx *Tx) error {
		_, e := tx.Exec(ctx, "UPDATE slo_receipts SET document='{}' WHERE tenant_id=$1", tenant)
		return e
	}); e == nil {
		t.Fatal("immutable receipts changed")
	}
	var snapshot model.Document
	if e = run("finops_api", func(tx *Tx) error {
		rs, e := tx.SLOReceipts(ctx, "resource", source.ObjectiveID, in.IntervalStart, next.IntervalEnd)
		if e != nil {
			return e
		}
		o, e := slo.ParseObjective(obj)
		if e != nil {
			return e
		}
		eval := slo.Evaluate(slo.Input{Now: now, Objective: o, Source: source, Receipts: rs})
		snapshot, e = tx.SLOEvaluationCreate(ctx, slo.Document(eval))
		return e
	}); e != nil {
		t.Fatal(e)
	}
	if model.String(snapshot, "hash") == "" || model.String(snapshot, "writer_role") != "finops_api" {
		t.Fatal("evaluation lost identity", snapshot)
	}
	if e = db.Do(ctx, tenant+"-other", func(tx *Tx) error {
		_, e := tx.Exec(ctx, "SET LOCAL ROLE finops_api")
		if e != nil {
			return e
		}
		_, e = tx.SLOObjectiveGet(ctx, source.ObjectiveID)
		if !errors.Is(e, pgx.ErrNoRows) {
			t.Fatal("cross-tenant objective visible", e)
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	plan, execution, measurement := model.ID(), model.ID(), model.ID()
	if e = run("finops_api", func(tx *Tx) error {
		_, e := tx.Create(ctx, "executions", model.Document{"id": execution, "change_plan_id": plan})
		return e
	}); e != nil {
		t.Fatal(e)
	}
	if e = run("finops_signer", func(tx *Tx) error {
		b, _ := json.Marshal(model.Document{"plan": model.Document{"id": plan, "workload_id": "workload", "measurement_id": measurement, "slo_objective_id": source.ObjectiveID}})
		_, e := tx.Exec(ctx, "INSERT INTO signed_plans(tenant_id,plan_id,nonce,envelope) VALUES($1,$2,$3,$4)", tenant, plan, model.ID(), b)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	violation := model.Document{"objective_id": source.ObjectiveID, "workload_id": "workload", "reason_code": "SLO_P95_HARD_BREACH", "receipt_ids": []string{first.ID}}
	if e = run("finops_worker", func(tx *Tx) error {
		_, _, e := tx.SLOViolationAppend(ctx, execution, plan, measurement, violation)
		return e
	}); e == nil {
		t.Fatal("unowned occurrence latched violation")
	}
	if e = run("finops_executor", func(tx *Tx) error {
		_, e := tx.Exec(ctx, "INSERT INTO provider_operations(tenant_id,execution_id,resource_id,stop_intent,stop_owned,document) VALUES($1,$2,$3,true,true,'{}')", tenant, execution, "target")
		return e
	}); e != nil {
		t.Fatal(e)
	}
	for _, role := range []string{"finops_api", "finops_ingester", "finops_activity", "finops_executor"} {
		if e = run(role, func(tx *Tx) error {
			_, _, e := tx.SLOViolationAppend(ctx, execution, plan, measurement, violation)
			return e
		}); e == nil {
			t.Fatal("unauthorized violation writer", role)
		}
	}
	var latch model.Document
	if e = run("finops_worker", func(tx *Tx) error {
		var inserted bool
		var e error
		latch, inserted, e = tx.SLOViolationAppend(ctx, execution, plan, measurement, violation)
		if e == nil && !inserted {
			t.Fatal("first breach not latched")
		}
		return e
	}); e != nil {
		t.Fatal(e)
	}
	if e = run("finops_executor", func(tx *Tx) error {
		_, e := tx.Exec(ctx, "UPDATE provider_operations SET restored=true WHERE tenant_id=$1 AND execution_id=$2", tenant, execution)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	if e = run("finops_worker", func(tx *Tx) error {
		r, inserted, e := tx.SLOViolationAppend(ctx, execution, plan, measurement, violation)
		if e == nil && (inserted || r["id"] != latch["id"]) {
			t.Fatal("later healthy completion erased/replaced first breach")
		}
		return e
	}); e != nil {
		t.Fatal(e)
	}
	if e = run("finops_api", func(tx *Tx) error {
		rows, e := tx.SLOViolations(ctx, measurement)
		if e == nil && len(rows) != 1 {
			t.Fatal("measurement disqualification lost")
		}
		return e
	}); e != nil {
		t.Fatal(e)
	}
}
