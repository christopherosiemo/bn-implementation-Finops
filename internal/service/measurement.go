package service

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/evidence"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"math/big"
	"time"
)

func (a *API) createMeasurement(ctx context.Context, t *store.Tx, in model.Document) (model.Document, error) {
	m, e := t.EvidenceGet(ctx, "measurement", model.String(in, "measurement_id"))
	if e != nil {
		return nil, e
	}
	b, e := t.EvidenceGet(ctx, "baseline", model.String(m, "baseline_id"))
	if e != nil {
		return nil, e
	}
	res, e := t.Get(ctx, "resources", model.String(m, "resource_id"))
	if e != nil {
		return nil, e
	}
	job, e := t.Get(ctx, "ingestion_jobs", model.String(in, "ingestion_job_id"))
	if e != nil {
		return nil, e
	}
	binding, records, e := evidence.Source(job, res, t.Tenant)
	if e != nil {
		return nil, evidenceProblem(e)
	}
	if e = trustedSource(job, a.Config.Fixture); e != nil {
		return nil, e
	}
	if !evidence.SameBinding(binding, evidence.Object(b["binding"])) {
		return nil, problem(422, "MEASUREMENT_BINDING_INVALID", "measurement source differs from baseline identity and currency")
	}
	start, e := inputTime(in, "start")
	if e != nil {
		return nil, e
	}
	end, e := inputTime(in, "end")
	if e != nil {
		return nil, e
	}
	activation, e := inputTime(m, "activation_at")
	if e != nil {
		return nil, e
	}
	if start.Before(activation) || !start.Before(end) || end.After(time.Now()) {
		return nil, problem(422, "MEASUREMENT_WINDOW_INVALID", "measurement must start at or after activation and end in the past")
	}
	records, e = evidence.PeriodRecords(records, start, end)
	if e != nil {
		return nil, evidenceProblem(e)
	}
	samples, e := evidence.Samples(binding, in["workload_samples"], start, end)
	if e != nil {
		return nil, evidenceProblem(e)
	}
	rawSource := evidence.Object(job["raw"])
	invoice := evidence.Object(rawSource["invoice"])
	if model.String(invoice, "invoice_id") == "" || model.String(invoice, "issued_at") == "" {
		return nil, problem(422, "INVOICE_SOURCE_REQUIRED", "measurement invoice metadata must be part of the immutable imported source")
	}
	if supplied := evidence.Object(in["invoice"]); len(supplied) > 0 && evidence.Hash(supplied) != evidence.Hash(invoice) {
		return nil, problem(422, "INVOICE_SOURCE_MISMATCH", "measurement invoice differs from the imported source")
	}
	total, ok := new(big.Rat).SetString(model.String(invoice, "total"))
	importTotal, okImport := new(big.Rat).SetString(model.String(evidence.Object(rawSource["invoice_totals"]), model.String(binding, "currency")))
	if !ok || !okImport || total.Cmp(importTotal) != 0 {
		return nil, problem(422, "INVOICE_SOURCE_MISMATCH", "native invoice total must equal the immutable source invoice total")
	}
	totals := evidence.Object(evidence.Object(job["canonical"])["totals"])
	invoice["reconciled_billed_total"] = totals[model.String(binding, "currency")]
	d := model.Document{"id": model.ID(), "resource_id": res["id"], "measurement_id": m["id"], "baseline_id": b["id"], "binding": binding, "ingestion_job_id": job["id"], "source_id": job["source_id"], "source_version": evidence.Object(job["raw"])["source_version"], "source_hash": evidence.Hash(job["raw"]), "canonical_hash": evidence.Hash(job["canonical"]), "start": start.Format(time.RFC3339Nano), "end": end.Format(time.RFC3339Nano), "billing_records": records, "workload_samples": samples, "invoice": invoice}
	d["source_refs"] = []model.Document{evidence.SourceReference(job, binding)}
	return t.EvidenceCreate(ctx, "measurement_snapshot", d)
}

func ownedIntervals(ctx context.Context, t *store.Tx, p model.Plan) ([]model.Document, error) {
	// Only executor-owned stop receipts are attribution authority. Caller supplied
	// intervals cannot establish ownership or manufacture stopped time.
	rows, e := t.Query(ctx, `SELECT x.id,o.document FROM provider_operations o JOIN entities x ON x.tenant_id=o.tenant_id AND x.kind='executions' AND x.id=o.execution_id JOIN entities p ON p.tenant_id=x.tenant_id AND p.kind='change_plans' AND p.id=x.document->>'change_plan_id' WHERE o.tenant_id=$1 AND o.stop_owned AND o.restored AND p.document->'payload'->>'measurement_id'=$2`, t.Tenant, p.MeasurementID)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []model.Document{}
	for rows.Next() {
		var id string
		var data []byte
		if e = rows.Scan(&id, &data); e != nil {
			return nil, e
		}
		d := model.Document{}
		if e = json.Unmarshal(data, &d); e != nil {
			return nil, e
		}
		stopped, running := model.String(d, "stopped_at"), model.String(d, "running_at")
		if stopped != "" && running != "" {
			out = append(out, model.Document{"execution_id": id, "stopped_at": stopped, "running_at": running})
		}
	}
	return out, rows.Err()
}

func (a *API) measurementInput(ctx context.Context, t *store.Tx, x model.Document) (model.Document, error) {
	plan, e := t.Get(ctx, "change_plans", model.String(x, "change_plan_id"))
	if e != nil {
		return nil, e
	}
	p, e := decodePlan(plan)
	if e != nil {
		return nil, e
	}
	if p.SchemaVersion != "2" {
		return nil, problem(422, "READINESS_V2_REQUIRED", "legacy execution lacks attributable measurement contract")
	}
	b, e := t.EvidenceGet(ctx, "baseline", p.BaselineID)
	if e != nil {
		return nil, e
	}
	res, e := t.Get(ctx, "resources", model.String(x, "resource_id"))
	if e != nil {
		return nil, e
	}
	if _, _, e = sourceForBaseline(ctx, t, b, res, a.Config.Fixture); e != nil {
		return nil, evidenceProblem(e)
	}
	m, e := t.EvidenceGet(ctx, "measurement", p.MeasurementID)
	if e != nil {
		return nil, e
	}
	owned, e := ownedIntervals(ctx, t, p)
	if e != nil {
		return nil, e
	}
	snapshots, e := t.EvidenceList(ctx, "measurement_snapshot", model.String(res, "id"))
	if e != nil {
		return nil, e
	}
	var snapshot model.Document
	for n := len(snapshots) - 1; n >= 0; n-- {
		if model.String(snapshots[n], "measurement_id") == p.MeasurementID {
			snapshot = snapshots[n]
			break
		}
	}
	input := baselineInput(b)
	input["phase"], input["measurement_id"], input["activation_at"] = "MEASUREMENT", p.MeasurementID, m["activation_at"]
	if snapshot == nil {
		input["phase"] = "BASELINE"
		return input, nil
	}
	job, e := t.Get(ctx, "ingestion_jobs", model.String(snapshot, "ingestion_job_id"))
	if e != nil {
		return nil, e
	}
	if e = trustedSource(job, a.Config.Fixture); e != nil {
		return nil, e
	}
	bind, _, e := evidence.Source(job, res, t.Tenant)
	if e != nil {
		return nil, evidenceProblem(e)
	}
	if !evidence.SameBinding(bind, evidence.Object(b["binding"])) || evidence.Hash(job["raw"]) != model.String(snapshot, "source_hash") || evidence.Hash(job["canonical"]) != model.String(snapshot, "canonical_hash") {
		return nil, problem(422, "MEASUREMENT_SOURCE_CHANGED", "measurement source differs from sealed evidence")
	}
	snapshot = model.Clone(snapshot)
	if !a.Config.Fixture && len(evidence.Object(snapshot["financial_clock"])) > 0 {
		return nil, problem(422, "LIVE_LOGICAL_CLOCK_FORBIDDEN", "logical financial clocks are permitted only for deterministic fixture evidence")
	}
	input["as_of"] = snapshot["created_at"]
	snapshot["owned_intervals"] = owned
	if clock := evidence.Object(snapshot["financial_clock"]); len(clock) > 0 {
		// Logical intervals require an executor receipt for every mapped occurrence.
		mappings := evidence.Rows(clock["owned_interval_mappings"])
		mapped := []model.Document{}
		for _, mapping := range mappings {
			found := false
			for _, o := range owned {
				if model.String(o, "execution_id") == model.String(mapping, "execution_id") && model.String(o, "stopped_at") == model.String(mapping, "actual_stopped_at") && model.String(o, "running_at") == model.String(mapping, "actual_running_at") {
					found = true
				}
			}
			if !found {
				return nil, errors.New("LOGICAL_CLOCK_OWNERSHIP_INVALID")
			}
			mapped = append(mapped, model.Document{"execution_id": mapping["execution_id"], "stopped_at": mapping["logical_stopped_at"], "running_at": mapping["logical_running_at"]})
		}
		snapshot["owned_intervals"] = mapped
		input["financial_clock"], input["as_of"] = clock, clock["as_of"]
	}
	input["measurement"], input["measurement_snapshot_id"] = snapshot, snapshot["id"]
	refs, err := evidence.IncrementalReferences(evidence.Rows(b["billing_records"]), evidence.Rows(snapshot["billing_records"]), evidence.Rows(snapshot["owned_intervals"]))
	if err != nil {
		return nil, evidenceProblem(err)
	}
	snapshot["incremental_billing_record_ids"] = refs
	return input, nil
}
