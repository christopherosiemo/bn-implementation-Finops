package service

import (
	"context"
	"encoding/json"
	"errors"
	"sort"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/evidence"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
)

const sloSavingsReason = "SLO_BREACH_DISQUALIFIED"

// reconcileSLOClaims runs under the API database identity before ordinary
// verification. A worker-owned violation is permanent measurement authority:
// neither a later healthy sample nor another completed occurrence can revive a
// saving for the same measurement. Existing financial history is never edited.
func reconcileSLOClaims(ctx context.Context, t *store.Tx) ([]model.Document, map[string]bool, error) {
	// The worker uses this same guard when recording a first violation. Holding
	// it for the verification transaction makes the initial latch scan stable.
	if _, err := t.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", t.Tenant+":dependency-graph"); err != nil {
		return nil, nil, err
	}
	violations, err := t.SLOViolations(ctx, "")
	if err != nil {
		return nil, nil, err
	}
	byMeasurement := map[string][]model.Document{}
	for _, violation := range violations {
		measurement := model.String(violation, "measurement_id")
		if measurement == "" || model.String(violation, "id") == "" || model.String(violation, "writer_role") != "finops_worker" {
			return nil, nil, errors.New("SLO_VIOLATION_BINDING_INVALID")
		}
		byMeasurement[measurement] = append(byMeasurement[measurement], violation)
	}
	measurements := make([]string, 0, len(byMeasurement))
	latched := make(map[string]bool, len(byMeasurement))
	for measurement := range byMeasurement {
		measurements = append(measurements, measurement)
		latched[measurement] = true
	}
	sort.Strings(measurements)
	results := []model.Document{}
	for _, measurement := range measurements {
		items := byMeasurement[measurement]
		ids := make([]string, 0, len(items))
		for _, item := range items {
			ids = append(ids, model.String(item, "id"))
		}
		sort.Strings(ids)
		// Use the same per-resource lock as ordinary financial verification and
		// re-read current heads after acquiring it. Do not use the dashboard's
		// bounded history projection to find claims requiring disqualification.
		rows, err := t.Query(ctx, "SELECT DISTINCT document->>'resource_id' FROM savings_ledger WHERE tenant_id=$1 AND document->>'measurement_id'=$2 ORDER BY 1", t.Tenant, measurement)
		if err != nil {
			return nil, nil, err
		}
		resources := []string{}
		for rows.Next() {
			var resource *string
			if err = rows.Scan(&resource); err != nil {
				rows.Close()
				return nil, nil, err
			}
			if resource == nil || *resource == "" {
				rows.Close()
				return nil, nil, errors.New("SLO_CLAIM_BINDING_INVALID")
			}
			resources = append(resources, *resource)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, nil, err
		}
		found := false
		for _, resource := range resources {
			if _, err = t.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", t.Tenant+":savings:"+resource); err != nil {
				return nil, nil, err
			}
			heads, err := sloCurrentClaims(ctx, t, measurement, resource)
			if err != nil {
				return nil, nil, err
			}
			for _, prior := range heads {
				found = true
				if model.Bool(prior, "slo_disqualified") && model.String(prior, "status") == "BLOCKED" && model.String(prior, "reason_code") == sloSavingsReason && prior["verified_saving"] == nil {
					prior["is_current"] = true
					results = append(results, prior)
					continue
				}
				d := model.Clone(prior)
				for _, field := range []string{"verified_saving", "actual_cost", "expected_baseline_cost", "incremental_cost", "observed_saving", "annualised_estimate"} {
					d[field] = nil
				}
				delete(d, "evidence_fingerprint")
				d["id"], d["created_at"], d["supersedes_id"] = model.ID(), model.Now(), prior["id"]
				d["schema_version"], d["status"], d["reason_code"], d["confidence"] = "3", "BLOCKED", sloSavingsReason, "LOW"
				d["slo_disqualified"], d["pre_execution_ready"], d["is_current"] = true, false, true
				d["slo_violation_ids"] = ids
				d["fingerprint"] = evidence.Hash(model.Document{"measurement_id": measurement, "supersedes_id": prior["id"], "slo_violation_ids": ids, "reason_code": sloSavingsReason})
				body, err := json.Marshal(d)
				if err != nil {
					return nil, nil, err
				}
				if _, err = t.Exec(ctx, "INSERT INTO savings_ledger(tenant_id,id,execution_id,fingerprint,document) VALUES($1,$2,$3,$4,$5)", t.Tenant, d["id"], d["execution_id"], d["fingerprint"], body); err != nil {
					return nil, nil, err
				}
				if err = t.Audit(ctx, "verification-engine", "savings.BLOCKED", model.String(d, "execution_id"), d); err != nil {
					return nil, nil, err
				}
				if err = t.Event(ctx, "savings.disqualified", d); err != nil {
					return nil, nil, err
				}
				results = append(results, d)
			}
		}
		if !found {
			// There is no economic claim to correct. Return a non-ledger status
			// without inventing currency, billing coverage or a claim amount.
			results = append(results, model.Document{"schema_version": "3", "measurement_id": measurement, "resource_id": items[0]["resource_id"], "execution_id": items[0]["execution_id"], "status": "BLOCKED", "reason_code": sloSavingsReason, "slo_disqualified": true, "pre_execution_ready": false, "verified_saving": nil, "slo_violation_ids": ids})
		}
	}
	return results, latched, nil
}

func sloCurrentClaims(ctx context.Context, t *store.Tx, measurement, resource string) ([]model.Document, error) {
	rows, err := t.Query(ctx, "SELECT l.document FROM savings_ledger l WHERE l.tenant_id=$1 AND l.document->>'measurement_id'=$2 AND l.document->>'resource_id'=$3 AND "+store.SavingsCurrentPredicate+" ORDER BY l.created_at,l.id", t.Tenant, measurement, resource)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	heads := []model.Document{}
	for rows.Next() {
		var raw []byte
		if err = rows.Scan(&raw); err != nil {
			return nil, err
		}
		d := model.Document{}
		if err = json.Unmarshal(raw, &d); err != nil {
			return nil, err
		}
		heads = append(heads, d)
	}
	return heads, rows.Err()
}
