package service

import (
	"context"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/evidence"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/jackc/pgx/v5"
)

// PrepareFixtureEvidence creates ordinary ingestion jobs. Persistence and source
// validation are identical to imported live sources; logical time is explicit.
func (a *API) PrepareFixtureEvidence(ctx context.Context, t *store.Tx) error {
	if !a.Config.Fixture {
		return nil
	}
	res, e := t.Get(ctx, "resources", "resource-dev-api")
	if e != nil {
		return e
	}
	org, e := t.Get(ctx, "org", t.Tenant)
	if e != nil {
		return e
	}
	generation := model.String(org, "fixture_generation")
	if generation == "" {
		generation = "initial"
	}
	baselineJobID := "fixture-baseline-v2-" + generation
	exists, e := t.IngestionJobExists(ctx, baselineJobID)
	if e != nil {
		return e
	}
	if !exists {
		raw, b, _ := evidence.Fixture(t.Tenant, res)
		canonical, e := a.economics(ctx, "normalize", raw)
		if e != nil {
			return e
		}
		metrics := []model.Document{}
		for _, sample := range evidence.Rows(b["workload_samples"]) {
			for _, name := range []string{"cpu_utilization", "network_in", "network_out"} {
				metrics = append(metrics, model.Document{"resource_id": res["provider_resource_id"], "metric_name": name, "source_time": sample["start"], "value": "0.000000000000", "fixture": true})
			}
		}
		raw["metric_records"], canonical["metric_facts"] = metrics, metrics
		_, e = t.Create(ctx, "ingestion_jobs", model.Document{"id": baselineJobID, "status": "PENDING", "source_provenance": "DETERMINISTIC_FIXTURE", "source_id": raw["source_id"], "raw": raw, "canonical": canonical, "fixture_baseline": b})
		if e != nil {
			return e
		}
	}
	executions, e := t.List(ctx, "executions")
	if e != nil {
		return e
	}
	for _, x := range executions {
		if model.String(x, "status") != "COMPLETED" {
			continue
		}
		pd, e := t.Get(ctx, "change_plans", model.String(x, "change_plan_id"))
		if e != nil {
			return e
		}
		p, e := decodePlan(pd)
		if e != nil {
			return e
		}
		if p.SchemaVersion != "2" {
			continue
		}
		id := "fixture-measurement-" + p.MeasurementID
		exists, e := t.IngestionJobExists(ctx, id)
		if e != nil {
			return e
		}
		if exists {
			continue
		}
		owned, e := ownedIntervals(ctx, t, p)
		if e != nil {
			return e
		}
		if len(owned) == 0 {
			continue
		}
		b, e := t.EvidenceGet(ctx, "baseline", p.BaselineID)
		if e != nil {
			return e
		}
		raw, snapshot := evidence.FixtureMeasurement(evidence.Object(b["binding"]), owned)
		canonical, e := a.economics(ctx, "normalize", raw)
		if e != nil {
			return e
		}
		snapshot["measurement_id"], snapshot["baseline_id"], snapshot["binding"], snapshot["resource_id"] = p.MeasurementID, p.BaselineID, b["binding"], x["resource_id"]
		if _, e = t.Create(ctx, "ingestion_jobs", model.Document{"id": id, "status": "PENDING", "source_provenance": "DETERMINISTIC_FIXTURE", "source_id": raw["source_id"], "raw": raw, "canonical": canonical, "fixture_measurement": snapshot}); e != nil {
			return e
		}
	}
	return nil
}

func (a *API) SealFixtureEvidence(ctx context.Context, t *store.Tx, job model.Document) error {
	if !a.Config.Fixture || model.String(job, "status") != "PERSISTED" {
		return nil
	}
	if value, ok := job["fixture_baseline"]; ok {
		id := model.String(job, "id")
		if _, e := t.EvidenceGet(ctx, "baseline", id); e == nil {
			return nil
		} else if e != pgx.ErrNoRows {
			return e
		}
		b := evidence.Object(value)
		res, e := t.Get(ctx, "resources", model.String(b, "resource_id"))
		if e != nil {
			return e
		}
		binding, records, e := evidence.Source(job, res, t.Tenant)
		if e != nil {
			return e
		}
		b["id"], b["binding"], b["billing_records"], b["ingestion_job_id"], b["source_hash"], b["canonical_hash"] = id, binding, records, job["id"], evidence.Hash(job["raw"]), evidence.Hash(job["canonical"])
		b["activation_at"] = evidence.Object(b["financial_clock"])["activation_at"]
		b["source_refs"] = []model.Document{evidence.SourceReference(job, binding)}
		schedule, e := t.Get(ctx, "schedules", "schedule-dev")
		if e != nil {
			return e
		}
		b["schedule"], b["schedule_id"] = schedule, schedule["id"]
		result, e := a.economics(ctx, "v2/evaluate", baselineInput(b))
		if e != nil {
			return e
		}
		b["evaluation"] = result
		_, e = t.EvidenceCreate(ctx, "baseline", b)
		return e
	}
	if value, ok := job["fixture_measurement"]; ok {
		snapshot := evidence.Object(value)
		id := "fixture-snapshot-" + model.String(snapshot, "measurement_id")
		if _, e := t.EvidenceGet(ctx, "measurement_snapshot", id); e == nil {
			return nil
		} else if e != pgx.ErrNoRows {
			return e
		}
		res, e := t.Get(ctx, "resources", model.String(snapshot, "resource_id"))
		if e != nil {
			return e
		}
		binding, records, e := evidence.Source(job, res, t.Tenant)
		if e != nil {
			return e
		}
		snapshot["id"], snapshot["binding"], snapshot["billing_records"], snapshot["ingestion_job_id"], snapshot["source_hash"], snapshot["canonical_hash"] = id, binding, records, job["id"], evidence.Hash(job["raw"]), evidence.Hash(job["canonical"])
		invoice := evidence.Object(snapshot["invoice"])
		invoice["reconciled_billed_total"] = evidence.Object(evidence.Object(job["canonical"])["totals"])[model.String(binding, "currency")]
		snapshot["invoice"] = invoice
		snapshot["source_refs"] = []model.Document{evidence.SourceReference(job, binding)}
		_, e = t.EvidenceCreate(ctx, "measurement_snapshot", snapshot)
		return e
	}
	return nil
}
