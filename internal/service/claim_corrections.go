package service

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/evidence"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
)

// A newly revoked/superseded authority cannot leave an earlier verified amount
// as the current head merely because recalculation now fails closed.
func (a *API) invalidatedTrustedClaim(ctx context.Context, t *store.Tx, x model.Document, cause error) (model.Document, error) {
	plan, e := t.Get(ctx, "change_plans", model.String(x, "change_plan_id"))
	if e != nil {
		return nil, cause
	}
	p, e := decodePlan(plan)
	if e != nil || p.SchemaVersion != "3" {
		return nil, cause
	}
	var raw []byte
	e = t.QueryRow(ctx, "SELECT l.document FROM savings_ledger l WHERE l.tenant_id=$1 AND l.document->>'measurement_id'=$2 AND "+store.SavingsCurrentPredicate+" ORDER BY l.created_at DESC,l.id DESC LIMIT 1", t.Tenant, p.MeasurementID).Scan(&raw)
	if e != nil {
		return nil, cause
	}
	prior := model.Document{}
	if e = json.Unmarshal(raw, &prior); e != nil {
		return nil, e
	}
	reason := "SOURCE_AUTHORITY_INVALIDATED"
	var problem *Problem
	if errors.As(cause, &problem) {
		reason = problem.Code
	} else if code := cause.Error(); len(code) < 100 && safeReasonCode(code) {
		reason = code
	}
	baseline, e := t.EvidenceGet(ctx, "baseline", p.BaselineID)
	if e != nil {
		return nil, e
	}
	source, e := t.SourceGet(ctx, model.String(baseline, "source_connection_id"))
	if e != nil {
		return nil, e
	}
	d := model.Clone(prior)
	for _, field := range []string{"verified_saving", "actual_cost", "expected_baseline_cost", "incremental_cost", "observed_saving", "annualised_estimate"} {
		d[field] = nil
	}
	delete(d, "supersedes_id")
	d["schema_version"], d["status"], d["reason_code"], d["confidence"] = "3", "BLOCKED", reason, "LOW"
	d["pre_execution_ready"] = false
	d["fingerprint"] = evidence.Hash(model.Document{"measurement_id": p.MeasurementID, "reason_code": reason, "latest_receipt_id": source["latest_receipt_id"], "source_enabled": source["enabled"], "source_status": source["status"]})
	return d, nil
}
func safeReasonCode(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !(r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_') {
			return false
		}
	}
	return true
}
