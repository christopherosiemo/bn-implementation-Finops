package service

import (
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"testing"
	"time"
)

func TestSparseBillingRequiresOwnedFinalAbsence(t *testing.T) {
	start := time.Date(2026, 9, 16, 20, 0, 0, 0, time.UTC)
	end := start.Add(4 * time.Hour)
	stamp := func(h int) string { return start.Add(time.Duration(h) * time.Hour).Format(time.RFC3339) }
	records := []model.Document{{"ServiceName": "AmazonEC2", "ChargePeriodStart": stamp(0), "ChargePeriodEnd": stamp(1), "x_SourceRecordId": "running", "x_ProviderFields": model.Document{"line_item_operation": "RunInstances"}}}
	proof := model.Document{"state": "FINAL", "period_start": stamp(0), "period_end": stamp(4), "receipt_id": "final"}
	owned := []model.Document{{"stopped_at": stamp(1), "running_at": stamp(3), "execution_id": "owned"}}
	result := billingObservations(records, []model.Document{proof}, owned, start, end)
	if len(result) != 3 || model.String(result[0], "state") != "OBSERVED" || model.String(result[1], "state") != "ABSENT_FINAL_EXPORT" || model.String(result[2], "state") != "UNKNOWN" {
		t.Fatalf("incorrect coverage:%v", result)
	}
	proof["state"] = "COMPLETE"
	for _, row := range billingObservations(records, []model.Document{proof}, owned, start, end) {
		if model.String(row, "state") == "ABSENT_FINAL_EXPORT" {
			t.Fatal("provisional export manufactured zero")
		}
	}
	proof["state"] = "FINAL"
	for _, row := range billingObservations(records, []model.Document{proof}, nil, start, end) {
		if model.String(row, "state") == "ABSENT_FINAL_EXPORT" {
			t.Fatal("manual stop claimed as owned")
		}
	}
	for _, row := range records {
		if _, ok := row["BilledCost"]; ok {
			t.Fatal("coverage mutated source record")
		}
	}
}

func TestV3RejectsSubmittedAuthority(t *testing.T) {
	for _, field := range []string{"workload_samples", "billing_records", "invoice", "source_proof", "commitment_scope", "billing_observations", "owned_intervals", "financial_clock", "proof_set_id", "ingestion_job_id"} {
		if rejectSubmittedAuthority(model.Document{field: nil}) == nil {
			t.Fatalf("submitted %s accepted", field)
		}
	}
	if e := rejectSubmittedAuthority(model.Document{"schema_version": "3", "resource_id": "r", "source_connection_id": "c", "start": "s", "end": "e"}); e != nil {
		t.Fatal(e)
	}
}

func TestBaselineEconomicCorrectionIncludesPayerScope(t *testing.T) {
	start := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	end := start.Add(14 * 24 * time.Hour)
	res := model.Document{"account_id": "111111111111", "region": "eu-west-1"}
	row := model.Document{"ResourceId": "i-test", "SubAccountId": res["account_id"], "RegionId": res["region"], "BillingCurrency": "GBP", "BillingAccountId": "222222222222", "InvoiceIssuerName": "AWS", "ServiceName": "AmazonEC2", "BilledCost": "1.00", "ChargePeriodStart": start.Format(time.RFC3339), "ChargePeriodEnd": start.Add(time.Hour).Format(time.RFC3339), "x_PricingBasis": "UNBLENDED", "x_NativeComputeCost": "1.00", "x_ProviderFields": model.Document{"line_item_line_item_type": "Usage"}}
	job := func(rows ...model.Document) model.Document {
		return model.Document{"canonical": model.Document{"records": rows}}
	}
	prior := baselineEconomicHash(job(row), res, start, end)
	metadata := model.Clone(row)
	metadata["InvoiceId"] = "issued-later"
	if baselineEconomicHash(job(metadata), res, start, end) != prior {
		t.Fatal("invoice-only metadata rewrote frozen baseline economics")
	}
	for _, kind := range []string{"RIFee", "Credit"} {
		global := model.Clone(row)
		global["ResourceId"], global["SubAccountId"], global["RegionId"] = "", "333333333333", ""
		global["x_ProviderFields"] = model.Document{"line_item_line_item_type": kind}
		if baselineEconomicHash(job(row, global), res, start, end) == prior {
			t.Fatalf("%s in another payer member did not invalidate baseline economics", kind)
		}
	}
}
