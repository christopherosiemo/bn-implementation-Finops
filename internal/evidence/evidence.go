// Package evidence binds financial inputs to immutable provider source records.
package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"math/big"
	"time"
)

func Object(v any) model.Document {
	b, _ := json.Marshal(v)
	d := model.Document{}
	_ = json.Unmarshal(b, &d)
	return d
}
func Rows(v any) []model.Document {
	b, _ := json.Marshal(v)
	d := []model.Document{}
	_ = json.Unmarshal(b, &d)
	return d
}
func Hash(v any) string {
	b, _ := json.Marshal(v)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func Binding(tenant string, r model.Document, currency string) model.Document {
	return model.Document{"tenant_id": tenant, "resource_id": r["id"], "provider_resource_id": r["provider_resource_id"], "account_id": r["account_id"], "region": r["region"], "currency": currency}
}
func SameBinding(a, b model.Document) bool {
	for _, k := range []string{"tenant_id", "resource_id", "provider_resource_id", "account_id", "region", "currency"} {
		if model.String(a, k) == "" || model.String(a, k) != model.String(b, k) {
			return false
		}
	}
	return true
}

func SourceReference(job, binding model.Document) model.Document {
	return model.Document{"kind": "AWS_CUR2", "ingestion_job_id": job["id"], "source_id": job["source_id"], "source_version": Object(job["raw"])["source_version"], "source_hash": Hash(job["raw"]), "canonical_hash": Hash(job["canonical"]), "binding": binding}
}

// Source selects records from a persisted canonical snapshot. It never accepts
// caller supplied economic amounts, completeness flags, or a currency override.
func Source(job, res model.Document, tenant string) (model.Document, []model.Document, error) {
	if model.String(job, "status") != "PERSISTED" {
		return nil, nil, errors.New("BILLING_EVIDENCE_NOT_PERSISTED")
	}
	raw := Object(job["raw"])
	can := Object(job["canonical"])
	source := model.String(job, "source_id")
	version := model.String(raw, "source_version")
	if source == "" || version == "" || source != model.String(raw, "source_id") {
		return nil, nil, errors.New("SOURCE_BINDING_INVALID")
	}
	records := []model.Document{}
	currency := ""
	for _, r := range Rows(can["records"]) {
		if model.String(r, "ResourceId") != model.String(res, "provider_resource_id") {
			continue
		}
		if model.String(r, "SubAccountId") != model.String(res, "account_id") || model.String(r, "RegionId") != model.String(res, "region") || model.String(r, "x_SourceId") != source || model.String(r, "x_SourceVersion") != version {
			return nil, nil, errors.New("SOURCE_BINDING_INVALID")
		}
		c := model.String(r, "BillingCurrency")
		if c == "" || currency != "" && currency != c {
			return nil, nil, errors.New("CURRENCY_BINDING_INVALID")
		}
		currency = c
		records = append(records, r)
	}
	if len(records) == 0 {
		return nil, nil, errors.New("RESOURCE_SOURCE_RECORDS_REQUIRED")
	}
	if known := model.String(res, "currency"); known != "" && known != currency {
		return nil, nil, errors.New("CURRENCY_BINDING_INVALID")
	}
	return Binding(tenant, res, currency), records, nil
}

func Samples(binding model.Document, v any, start, end time.Time) ([]model.Document, error) {
	rows := Rows(v)
	if len(rows) == 0 {
		return nil, errors.New("WORKLOAD_EVIDENCE_REQUIRED")
	}
	for _, r := range rows {
		for _, k := range []string{"resource_id", "provider_resource_id", "account_id", "region"} {
			if model.String(r, k) != model.String(binding, k) {
				return nil, errors.New("WORKLOAD_BINDING_INVALID")
			}
		}
		if tenant := model.String(r, "tenant_id"); tenant != "" && tenant != model.String(binding, "tenant_id") {
			return nil, errors.New("WORKLOAD_BINDING_INVALID")
		}
		s, e1 := time.Parse(time.RFC3339Nano, model.String(r, "start"))
		e, e2 := time.Parse(time.RFC3339Nano, model.String(r, "end"))
		n, ok := new(big.Rat).SetString(model.String(r, "units"))
		if e1 != nil || e2 != nil || !s.Before(e) || s.Before(start) || e.After(end) || !ok || n.Sign() < 0 || model.String(r, "source_record_id") == "" {
			return nil, errors.New("WORKLOAD_EVIDENCE_INVALID")
		}
	}
	return rows, nil
}

func PeriodRecords(records []model.Document, start, end time.Time) ([]model.Document, error) {
	out := []model.Document{}
	for _, r := range records {
		s, e1 := time.Parse(time.RFC3339Nano, model.String(r, "ChargePeriodStart"))
		e, e2 := time.Parse(time.RFC3339Nano, model.String(r, "ChargePeriodEnd"))
		if e1 != nil || e2 != nil || !s.Before(e) {
			return nil, errors.New("SOURCE_PERIOD_INVALID")
		}
		if !s.Before(end) || !e.After(start) {
			continue
		}
		if s.Before(start) || e.After(end) {
			return nil, errors.New("SOURCE_PERIOD_BOUNDARY_SPLIT_REQUIRED")
		}
		out = append(out, r)
	}
	return out, nil
}

// Fixture is a normal source dataset with an explicit logical financial clock.
// No evaluator skips validation for fixture data.
func Fixture(tenant string, res model.Document) (model.Document, model.Document, model.Document) {
	activation := time.Date(2026, 9, 15, 20, 0, 0, 0, time.UTC)
	start := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	end := start.Add(14 * 24 * time.Hour)
	binding := Binding(tenant, res, "GBP")
	records := []model.Document{}
	samples := []model.Document{}
	for h := 0; h < 14*24; h++ {
		at := start.Add(time.Duration(h) * time.Hour)
		next := at.Add(time.Hour)
		id := fmt.Sprintf("fixture-baseline-%03d", h)
		records = append(records, model.Document{"identity_line_item_id": id, "line_item_line_item_type": "Usage", "line_item_unblended_cost": "0.480000000000", "ContractedCost": "0.480000000000", "line_item_currency_code": "GBP", "line_item_resource_id": binding["provider_resource_id"], "line_item_usage_account_id": binding["account_id"], "product_servicecode": "AmazonEC2", "product_region_code": binding["region"], "line_item_usage_start_date": at.Format(time.RFC3339), "line_item_usage_end_date": next.Format(time.RFC3339), "pricing_term": "OnDemand", "line_item_operation": "RunInstances"})
		units := "0"
		if at.Hour() >= 8 && at.Hour() < 18 {
			units = "10"
		}
		s := model.Clone(binding)
		delete(s, "currency")
		s["start"], s["end"], s["units"], s["source_record_id"] = at.Format(time.RFC3339), next.Format(time.RFC3339), units, id+"-work"
		samples = append(samples, s)
	}
	raw := model.Document{"source_id": "fixture-baseline-v2", "source_version": "fixture-baseline-v2.1", "records": records, "invoice_totals": model.Document{"GBP": "161.280000000000"}}
	baseline := model.Document{"resource_id": res["id"], "binding": binding, "start": start.Format(time.RFC3339), "end": end.Format(time.RFC3339), "source_id": raw["source_id"], "source_version": raw["source_version"], "workload_samples": samples, "schedule": model.Document{"timezone": "UTC", "stop_time": "20:00", "ready_time": "07:00", "days": []int{1, 2, 3, 4, 5, 6, 7}}, "financial_clock": model.Document{"mode": "DETERMINISTIC_LOGICAL", "activation_at": activation.Format(time.RFC3339), "as_of": activation.Format(time.RFC3339), "description": "Source timestamps use a recorded deterministic financial clock; provider stop/start receipts remain actual wall time."}}
	return raw, baseline, binding
}

func FixtureMeasurement(binding model.Document, owned []model.Document) (model.Document, model.Document) {
	start := time.Date(2026, 9, 16, 0, 0, 0, 0, time.UTC)
	end := start.Add(14 * 24 * time.Hour)
	stop := start.Add(20 * time.Hour)
	running := stop.Add(10*time.Hour + 45*time.Minute)
	records := []model.Document{}
	samples := []model.Document{}
	for q := 0; q < 14*24*4; q++ {
		at := start.Add(time.Duration(q) * 15 * time.Minute)
		next := at.Add(15 * time.Minute)
		cost := "0.120000000000"
		if !at.Before(stop) && at.Before(running) {
			cost = "0.000000000000"
		}
		id := fmt.Sprintf("fixture-measurement-%04d", q)
		records = append(records, model.Document{"identity_line_item_id": id, "line_item_line_item_type": "Usage", "line_item_unblended_cost": cost, "ContractedCost": cost, "line_item_currency_code": "GBP", "line_item_resource_id": binding["provider_resource_id"], "line_item_usage_account_id": binding["account_id"], "product_servicecode": "AmazonEC2", "product_region_code": binding["region"], "line_item_usage_start_date": at.Format(time.RFC3339), "line_item_usage_end_date": next.Format(time.RFC3339), "pricing_term": "OnDemand", "line_item_operation": "RunInstances"})
		units := "0"
		if at.Hour() >= 8 && at.Hour() < 18 {
			units = "2.5"
		}
		s := model.Clone(binding)
		delete(s, "currency")
		s["start"], s["end"], s["units"], s["source_record_id"] = at.Format(time.RFC3339), next.Format(time.RFC3339), units, id+"-work"
		samples = append(samples, s)
	}
	mappings := []model.Document{}
	if len(owned) > 0 {
		o := owned[0]
		mappings = append(mappings, model.Document{"execution_id": o["execution_id"], "actual_stopped_at": o["stopped_at"], "actual_running_at": o["running_at"], "logical_stopped_at": stop.Format(time.RFC3339), "logical_running_at": running.Format(time.RFC3339)})
	}
	clock := model.Document{"mode": "DETERMINISTIC_LOGICAL", "as_of": end.Add(24 * time.Hour).Format(time.RFC3339), "owned_interval_mappings": mappings, "description": "One actual fixture provider cycle mapped to one logical off window. All remaining post-activation time retains compute charges."}
	raw := model.Document{"source_id": "fixture-measurement-v2", "source_version": "fixture-measurement-v2.1", "records": records, "invoice_totals": model.Document{"GBP": "156.120000000000"}, "export_period": model.Document{"start": start.Format(time.RFC3339), "end": end.Format(time.RFC3339)}}
	snapshot := model.Document{"start": start.Format(time.RFC3339), "end": end.Format(time.RFC3339), "source_id": raw["source_id"], "source_version": raw["source_version"], "workload_samples": samples, "invoice": model.Document{"invoice_id": "fixture-logical-invoice-v2", "issued_at": end.Add(24 * time.Hour).Format(time.RFC3339), "final": true, "total": "156.120000000000"}, "financial_clock": clock}
	raw["invoice"] = snapshot["invoice"]
	return raw, snapshot
}
