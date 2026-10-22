package service

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
)

// billingFactRows preserves exact canonical costs, including correction/zero
// rows. It does not calculate an hourly price, avoidable cost or saving.
func billingFactRows(tenant, source string, canonical model.Document) ([]model.Document, error) {
	if !tenantKey.MatchString(tenant) || source == "" {
		return nil, errors.New("tenant and source identity required")
	}
	facts := []model.Document{}
	for _, r := range documentList(canonical["records"]) {
		timestamp := model.String(r, "ChargePeriodStart")
		if timestamp == "" {
			return nil, errors.New("billing source timestamp is missing")
		}
		if _, e := time.Parse(time.RFC3339, timestamp); e != nil {
			return nil, errors.New("billing source timestamp invalid")
		}
		record, version := model.String(r, "x_SourceRecordId"), model.String(r, "x_SourceVersion")
		if record == "" || version == "" {
			return nil, errors.New("billing source version identity is missing")
		}
		billed := model.String(r, "BilledCost")
		if billed == "" {
			return nil, errors.New("exact billing cost is missing")
		}
		payload, e := json.Marshal(r)
		if e != nil {
			return nil, e
		}
		facts = append(facts, model.Document{"tenant_id": tenant, "source_id": source, "source_version": version, "source_record_id": record, "resource_id": model.String(r, "ResourceId"), "currency": model.String(r, "BillingCurrency"), "billed_cost": billed, "effective_cost": r["EffectiveCost"], "source_time": timestamp, "payload": string(payload)})
	}
	return facts, nil
}

// The ordinary source publisher and connected native acceptance share this
// one projection and actual ClickHouse insertion path. Each caller separately
// authenticates/archives its raw source before invoking it.
func persistBillingFacts(ctx context.Context, tenant, source string, canonical model.Document) error {
	facts, e := billingFactRows(tenant, source, canonical)
	if e != nil {
		return e
	}
	return clickhouseRows(ctx, "billing_facts", facts)
}
