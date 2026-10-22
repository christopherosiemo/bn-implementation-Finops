package service

import (
	"math/big"
	"testing"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
)

func lambdaFinancialFixture() (model.Document, model.Document, model.Document, []model.Document, time.Time, time.Time) {
	start := time.Date(2026, 10, 6, 0, 0, 0, 0, time.UTC)
	end := start.Add(14 * 24 * time.Hour)
	base := "arn:aws:lambda:eu-west-1:111122223333:function:synthetic"
	r := model.Document{"id": "lambda-component", "provider": "AWS", "provider_resource_id": base, "account_id": "111122223333", "region": "eu-west-1", "resource_type": "LAMBDA_FUNCTION", "owner": "owner", "configuration_authority": "TERRAFORM"}
	config := model.Document{"base_function_arn": base, "qualified_arn": base + ":prod", "qualifier": "prod", "version": "42", "memory_size_mb": 2048, "architecture": "x86_64", "model": "EVENT_DEFAULT", "timeout_seconds": 30, "reserved_concurrency": 100, "provisioned_concurrency": []model.Document{}, "code_sha256": "native-package-digest"}
	r["lambda_configuration"] = config
	c := model.Document{"resource_id": r["id"], "account_id": r["account_id"], "region": r["region"], "config_hash": LambdaConfigurationHash(r), "configuration": config, "period": model.Document{"start": start.Format(time.RFC3339), "end": end.Format(time.RFC3339)}}
	reports := model.Document{"coverage": model.Document{"query_scope": "FUNCTION_ALL_VERSIONS", "status": "COMPLETE_OBSERVED", "start": start.Format(time.RFC3339), "end": end.Format(time.RFC3339)}, "rows": []model.Document{{"cohort_id": "exact-equivalent-native-reports", "count": "336", "first_event_time": start.Add(time.Minute).Format(time.RFC3339), "last_event_time": end.Add(-time.Minute).Format(time.RFC3339), "version": "42", "memory_size_mb": "2048", "max_memory_used_mb": "800", "duration_ms": "900", "billed_duration_ms": "1000"}}}
	c["reports"] = reports
	metrics := []model.Document{}
	for at := start; at.Before(end); at = at.Add(time.Hour) {
		metrics = append(metrics, model.Document{"metric": "Invocations", "statistic": "Sum", "qualified_arn": base, "version": "ALL", "source_time": at.Format(time.RFC3339), "period_seconds": 3600, "sample_count": "1", "value": "1", "unit": "Count"})
	}
	c["function_metrics"] = model.Document{"rows": metrics}
	dims := []model.Document{}
	records := []model.Document{}
	for _, v := range []struct{ kind, usage, unit, q, rate string }{{"request", "EUN1-Request", "Requests", "336", "0.0000002"}, {"compute", "EUN1-Lambda-GB-Second", "Lambda-GB-Second", "672", "0.00002"}} {
		q, _ := new(big.Rat).SetString(v.q)
		rate, _ := new(big.Rat).SetString(v.rate)
		cost := databaseInputMoney(new(big.Rat).Mul(q, rate))
		raw := model.Document{"product_servicecode": "AWSLambda", "product_region_code": "eu-west-1", "product_sku": "SKU_" + v.kind, "line_item_usage_type": v.usage, "line_item_operation": "AWSLambda", "pricing_unit": v.unit, "pricing_term": "OnDemand", "pricing_rate_code": "SKU_" + v.kind + ".native", "line_item_line_item_type": "Usage", "line_item_usage_amount": v.q, "line_item_net_unblended_rate": v.rate, "line_item_net_unblended_cost": cost, "line_item_resource_id": base, "line_item_usage_account_id": "111122223333", "bill_payer_account_id": "999900001111", "line_item_currency_code": "GBP"}
		records = append(records, model.Document{"ResourceId": base, "SubAccountId": "111122223333", "RegionId": "eu-west-1", "BillingAccountId": "999900001111", "BillingCurrency": "GBP", "ChargePeriodStart": start.Format(time.RFC3339), "ChargePeriodEnd": end.Format(time.RFC3339), "BilledCost": cost, "EffectiveCost": cost, "x_SourceRecordId": v.kind, "x_ProviderFields": raw})
		dims = append(dims, model.Document{"sku": "SKU_" + v.kind, "rate_code": "SKU_" + v.kind + ".native", "unit": v.unit, "service_code": "AWSLambda", "term_type": "OnDemand", "begin_range": "0", "end_range": "Inf", "applies_to": []string{}, "effective_date": "2026-01-01T00:00:00Z", "attributes": model.Document{"regionCode": "eu-west-1", "usagetype": v.usage, "operation": "AWSLambda"}, "public_price_reference": "99999"})
	}
	c["price_dimensions"] = dims
	ref := model.Document{"kind": "AWS_CUR2_CONNECTION", "source_version": "native-revision", "source_connection_id": "source-native", "source_receipt_id": "receipt-native", "payer_account_id": "999900001111"}
	return r, c, ref, records, start, end
}
func TestLambdaFinancialBaseARNRequiresIndependentCompleteReconciliation(t *testing.T) {
	r, c, ref, rows, start, end := lambdaFinancialFixture()
	if !lambdaBaseAllocationProof(r, c, rows, start, end) {
		t.Fatal("exact coherent reports/counts/nativeGBsec refused")
	}
	parts, reasons, free := lambdaFinancialRecords(r, c, ref, rows, start, end)
	if len(parts) != 2 || len(reasons) > 0 || !free {
		t.Fatal(parts, reasons, free)
	}
	for _, part := range parts {
		if part["allocation_basis"] != "MODELLED_SINGLE_VERSION_FUNCTION_ALLOCATION" || part["marginal_pricing_known"] != true || storageObject(part["rate_bracket"])["resolved"] != true {
			t.Fatal(part)
		}
	}
	for _, change := range []string{"missing-bin", "other-version", "wrong-count", "wrong-billed", "truncation", "query-scope", "wrong-window"} {
		t.Run(change, func(t *testing.T) {
			r, c, ref, rows, start, end := lambdaFinancialFixture()
			reports := storageObject(c["reports"])
			reportRows := storageRows(reports["rows"])
			coverage := storageObject(reports["coverage"])
			switch change {
			case "missing-bin":
				m := storageRows(storageObject(c["function_metrics"])["rows"])
				c["function_metrics"] = model.Document{"rows": m[1:]}
			case "other-version":
				reportRows[0]["version"] = "43"
			case "wrong-count":
				reportRows[0]["count"] = "335"
			case "wrong-billed":
				reportRows[0]["billed_duration_ms"] = "999"
			case "truncation":
				coverage["cohort_rows_truncated"] = true
			case "query-scope":
				coverage["query_scope"] = "VERSION_ONLY"
			case "wrong-window":
				coverage["end"] = end.Add(-time.Hour).Format(time.RFC3339)
			}
			reports["rows"], reports["coverage"] = reportRows, coverage
			c["reports"] = reports
			if lambdaBaseAllocationProof(r, c, rows, start, end) {
				t.Fatal("unproved population accepted")
			}
			_, reasons, _ := lambdaFinancialRecords(r, c, ref, rows, start, end)
			found := false
			for _, reason := range reasons {
				if reason == "LAMBDA_BILLING_SERVING_TARGET_UNRESOLVED" {
					found = true
				}
			}
			if !found {
				t.Fatal(reasons)
			}
		})
	}
}
func TestLambdaFinancialExactScopeNativeNetRatesAndTiers(t *testing.T) {
	for _, change := range []string{"cost", "rate", "currency", "raw-account", "raw-payer", "raw-resource", "missing-dimension", "crossed-tier", "free-tier", "commitment"} {
		t.Run(change, func(t *testing.T) {
			r, c, ref, rows, start, end := lambdaFinancialFixture()
			row := rows[1]
			raw := storageObject(row["x_ProviderFields"])
			switch change {
			case "cost":
				row["BilledCost"] = "9"
			case "rate":
				delete(raw, "line_item_net_unblended_rate")
			case "currency":
				raw["line_item_currency_code"] = "USD"
			case "raw-account":
				raw["line_item_usage_account_id"] = "222233334444"
			case "raw-payer":
				raw["bill_payer_account_id"] = "222233334444"
			case "raw-resource":
				raw["line_item_resource_id"] = "another"
			case "missing-dimension":
				c["price_dimensions"] = []model.Document{}
			case "crossed-tier":
				dims := storageRows(c["price_dimensions"])
				dims[1]["end_range"] = "600"
				c["price_dimensions"] = dims
			case "free-tier":
				raw["line_item_net_unblended_rate"] = "0"
			case "commitment":
				raw["line_item_line_item_type"] = "SavingsPlanCoveredUsage"
			}
			row["x_ProviderFields"] = raw
			rows[1] = row
			parts, reasons, free := lambdaFinancialRecords(r, c, ref, rows, start, end)
			if len(reasons) == 0 && free {
				t.Fatal("unproved economics accepted", parts)
			}
		})
	}
}
func TestLambdaChargeKindsDoNotConflateReservedConcurrencyOrModels(t *testing.T) {
	for usage, want := range map[string]string{"EUN1-Lambda-GB-Second": "ON_DEMAND_COMPUTE", "EUN1-Lambda-Provisioned-GB-Second": "PROVISIONED_COMPUTE", "EUN1-Lambda-Provisioned-Concurrency": "PROVISIONED_CAPACITY", "EUN1-Lambda-Storage-GB-Second": "EPHEMERAL_STORAGE", "EUN1-Request": "REQUEST", "EUN1-Event-Poller": "EVENT_POLLER", "EUN1-Lambda-Durable-GB-Second": "UNSUPPORTED", "ReservedConcurrency": "UNSUPPORTED"} {
		if got := lambdaChargeKind(model.Document{"product_servicecode": "AWSLambda", "line_item_usage_type": usage}); got != want {
			t.Fatal(usage, got, want)
		}
	}
}
