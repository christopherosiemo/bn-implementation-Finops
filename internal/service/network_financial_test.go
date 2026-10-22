package service

import (
	"math/big"
	"testing"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
)

func networkFinancialRateFixture() (model.Document, model.Document, model.Document, time.Time) {
	at := time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)
	r := model.Document{"id": "network-current", "provider_resource_id": "nat-current", "account_id": "111122223333", "region": "eu-west-1"}
	raw := model.Document{"product_sku": "SKU_NATIVE_ENDPOINT", "pricing_rate_code": "SKU_NATIVE_ENDPOINT.FLAT", "pricing_unit": "Hrs", "pricing_term": "OnDemand", "product_servicecode": "AmazonVPC", "product_region_code": "eu-west-1", "line_item_usage_type": "EUN1-VpcEndpoint-Hours", "line_item_operation": "VpcEndpoint", "line_item_resource_id": "vpce-native", "line_item_usage_account_id": "111122223333", "bill_payer_account_id": "999900001111", "line_item_currency_code": "GBP", "line_item_line_item_type": "Usage", "line_item_net_unblended_rate": "0.012", "line_item_usage_amount": "1.2", "line_item_net_unblended_cost": "0.0144"}
	dimension := model.Document{"sku": "SKU_NATIVE_ENDPOINT", "rate_code": "SKU_NATIVE_ENDPOINT.FLAT", "unit": "Hrs", "service_code": "AmazonVPC", "term_type": "OnDemand", "begin_range": "0", "end_range": "Inf", "applies_to": []string{}, "effective_date": "2026-01-01T00:00:00Z", "attributes": model.Document{"regionCode": "eu-west-1", "usagetype": "EUN1-VpcEndpoint-Hours", "operation": "VpcEndpoint"}, "public_price_reference": "9999.99"}
	endpoint := model.Document{"provider": "AWS", "provider_resource_id": "vpce-native", "resource_type": "VPC_ENDPOINT", "account_id": "111122223333", "region": "eu-west-1", "vpc_id": "vpc-native", "endpoint_type": "Interface", "service_name": "com.amazonaws.eu-west-1.s3"}
	canonical := model.Document{"price_dimensions": []model.Document{dimension}, "topology": model.Document{"resources": []model.Document{endpoint}}}
	row := model.Document{"ResourceId": "vpce-native", "SubAccountId": "111122223333", "RegionId": "eu-west-1", "BillingAccountId": "999900001111", "BillingCurrency": "GBP", "BilledCost": "0.0144", "x_SourceRecordId": "native-record-1", "x_ProviderFields": raw}
	ref := model.Document{"kind": "AWS_CUR2_CONNECTION", "source_version": "native-revision-1", "source_connection_id": "registered-cur", "source_receipt_id": "trusted-receipt-1", "payer_account_id": "999900001111"}
	return model.Document{"record": row, "reference": ref}, canonical, r, at
}

func TestNetworkFinancialFlatNativeDimensionsRejectMissingAndMismatchedFields(t *testing.T) {
	item, c, _, at := networkFinancialRateFixture()
	raw := storageObject(storageObject(item["record"])["x_ProviderFields"])
	dims := storageRows(c["price_dimensions"])
	if !networkFlatDimension(raw, dims, at) {
		t.Fatal("exact native flat dimension rejected")
	}
	for _, field := range []string{"product_sku", "pricing_rate_code", "pricing_unit", "product_servicecode", "product_region_code", "line_item_usage_type"} {
		t.Run("missing-"+field, func(t *testing.T) {
			changed := model.Clone(raw)
			delete(changed, field)
			if networkFlatDimension(changed, dims, at) {
				t.Fatal("missing native dimension became known", field)
			}
		})
	}
	cases := map[string]any{"sku": "different", "rate_code": "different", "unit": "GB", "service_code": "AmazonEC2", "term_type": "Reserved", "begin_range": "1", "end_range": "100", "applies_to": []string{"another-SKU"}, "effective_date": "2026-10-21T00:00:00Z"}
	for field, value := range cases {
		t.Run(field, func(t *testing.T) {
			d := model.Clone(dims[0])
			d[field] = value
			if networkFlatDimension(raw, []model.Document{d}, at) {
				t.Fatal("dimension mismatch admitted", field)
			}
		})
	}
	for _, field := range []string{"regionCode", "usagetype", "operation"} {
		d := model.Clone(dims[0])
		attrs := storageObject(d["attributes"])
		attrs[field] = "different"
		d["attributes"] = attrs
		if networkFlatDimension(raw, []model.Document{d}, at) {
			t.Fatal("native technical attribute mismatch", field)
		}
	}
	if networkFlatDimension(raw, append(dims, model.Clone(dims[0])), at) {
		t.Fatal("ambiguous native dimensions treated as one")
	}
}

func TestNetworkFinancialCandidateUsesExactNativeNetNotPublicPrice(t *testing.T) {
	item, c, r, at := networkFinancialRateFixture()
	rates := networkCandidateRates([]model.Document{item}, c, r, "GBP", at)
	if len(rates) != 1 {
		t.Fatal(rates)
	}
	rate := rates[0]
	if rate["rate"] != "0.012000000000" || rate["unit"] != "Hour" || rate["service"] != "s3" || rate["currency"] != "GBP" || rate["marginal_pricing_known"] != true {
		t.Fatal("public or guessed economics substituted", rate)
	}
	if model.String(storageObject(rate["source_ref"]), "version") != "native-revision-1" {
		t.Fatal("native source revision lost", rate)
	}
	for _, change := range []string{"net-missing", "cost-mismatch", "arithmetic-mismatch", "credit", "negative-quantity", "list-only"} {
		t.Run(change, func(t *testing.T) {
			changed := model.Clone(item)
			row := storageObject(changed["record"])
			raw := storageObject(row["x_ProviderFields"])
			switch change {
			case "net-missing":
				delete(raw, "line_item_net_unblended_rate")
			case "cost-mismatch":
				row["BilledCost"] = "0.014400000001"
			case "arithmetic-mismatch":
				raw["line_item_net_unblended_cost"], row["BilledCost"] = "0.0145", "0.0145"
			case "credit":
				raw["line_item_line_item_type"] = "Credit"
				raw["line_item_net_unblended_cost"], row["BilledCost"] = "-0.0144", "-0.0144"
			case "negative-quantity":
				raw["line_item_usage_amount"] = "-1.2"
			case "list-only":
				delete(raw, "line_item_net_unblended_cost")
				raw["line_item_unblended_cost"] = "0.0144"
			}
			row["x_ProviderFields"] = raw
			changed["record"] = row
			if len(networkCandidateRates([]model.Document{changed}, c, r, "GBP", at)) != 0 {
				t.Fatal("unproved native NET input became a rate", change)
			}
		})
	}
}

func TestNetworkFinancialCandidateScopeCannotBorrowAnotherAccountRegionOrPayer(t *testing.T) {
	for _, change := range []string{"canonical-account", "canonical-region", "raw-account", "raw-region", "canonical-payer", "raw-payer", "reference-payer", "endpoint-account", "endpoint-region", "service-region", "resource-binding", "currency", "missing-source-version", "missing-record-id", "wrong-reference-kind"} {
		t.Run(change, func(t *testing.T) {
			item, c, r, at := networkFinancialRateFixture()
			row := storageObject(item["record"])
			raw := storageObject(row["x_ProviderFields"])
			ref := storageObject(item["reference"])
			top := storageObject(c["topology"])
			endpoints := storageRows(top["resources"])
			switch change {
			case "canonical-account":
				row["SubAccountId"] = "222233334444"
			case "canonical-region":
				row["RegionId"] = "us-east-1"
			case "raw-account":
				raw["line_item_usage_account_id"] = "222233334444"
			case "raw-region":
				raw["product_region_code"] = "us-east-1"
			case "canonical-payer":
				row["BillingAccountId"] = "222233334444"
			case "raw-payer":
				raw["bill_payer_account_id"] = "222233334444"
			case "reference-payer":
				ref["payer_account_id"] = "222233334444"
			case "endpoint-account":
				endpoints[0]["account_id"] = "222233334444"
			case "endpoint-region":
				endpoints[0]["region"] = "us-east-1"
			case "service-region":
				endpoints[0]["service_name"] = "com.amazonaws.us-east-1.s3"
			case "resource-binding":
				raw["line_item_resource_id"] = "vpce-different"
			case "currency":
				row["BillingCurrency"] = "USD"
			case "missing-source-version":
				delete(ref, "source_version")
			case "missing-record-id":
				delete(row, "x_SourceRecordId")
			case "wrong-reference-kind":
				ref["kind"] = "CUSTOMER_IMPORT"
			}
			row["x_ProviderFields"] = raw
			item["record"], item["reference"] = row, ref
			top["resources"] = endpoints
			c["topology"] = top
			if len(networkCandidateRates([]model.Document{item}, c, r, "GBP", at)) != 0 {
				t.Fatal("scope confusion lent customer rate", change)
			}
		})
	}
}

func TestNetworkFinancialCorrectionsChangeIdentityAndConflictingRatesRemainUnknown(t *testing.T) {
	old, c, r, at := networkFinancialRateFixture()
	corrected := model.Clone(old)
	row := storageObject(corrected["record"])
	raw := storageObject(row["x_ProviderFields"])
	raw["line_item_net_unblended_rate"], raw["line_item_net_unblended_cost"] = "0.013", "0.0156"
	row["BilledCost"], row["x_SourceRecordId"] = "0.0156", "native-record-correction"
	row["x_ProviderFields"] = raw
	ref := storageObject(corrected["reference"])
	ref["source_version"], ref["source_receipt_id"] = "native-revision-2", "trusted-receipt-2"
	corrected["record"], corrected["reference"] = row, ref
	before, after := networkCandidateRates([]model.Document{old}, c, r, "GBP", at), networkCandidateRates([]model.Document{corrected}, c, r, "GBP", at)
	if len(before) != 1 || len(after) != 1 || before[0]["id"] == after[0]["id"] || after[0]["rate"] != "0.013000000000" {
		t.Fatal(before, after)
	}
	if len(networkCandidateRates([]model.Document{old, corrected}, c, r, "GBP", at)) != 0 {
		t.Fatal("conflicting native rates silently selected")
	}
}

func TestNetworkFinancialProcessingUnitsRequireCompleteIndependentCounters(t *testing.T) {
	_, c, _, _, _, _ := networkProjectionFixture()
	metrics := storageObject(c["metrics"])
	metrics["totals"] = model.Document{"BytesInFromSource": "1073741824", "BytesInFromDestination": "0"}
	c["metrics"] = metrics
	if got := networkProcessingUnitBytes(c, big.NewRat(1, 1)); got != "1073741824" {
		t.Fatal("independently resolved native unit unavailable", got)
	}
	coverage := storageRows(metrics["coverage"])
	coverage[0]["status"] = "GAPS"
	metrics["coverage"] = coverage
	c["metrics"] = metrics
	if got := networkProcessingUnitBytes(c, big.NewRat(1, 1)); got != "" {
		t.Fatal("partial metric equality became authoritative unit", got)
	}
}

func TestNetworkFinancialServerBlockersRemoveEveryCandidateClaim(t *testing.T) {
	result := networkBlocked(model.Document{"tenant_id": "tenant", "resource_id": "resource"}, nil)
	result["status"] = "RECOMMENDED"
	result["candidates"] = []model.Document{{"id": "candidate", "status": "RECOMMENDED", "decision": "GATEWAY_ENDPOINT_REVIEW", "economics": model.Document{"estimated_monthly_saving": "100"}, "confidence": model.Document{"status": "HIGH"}, "pre_execution_ready": false, "execution_authorized": false, "verified_saving": nil}}
	networkBlockForEvidence(result, []string{"NETWORK_BILLING_CORRECTED_OR_REVOKED"})
	candidates := storageRows(result["candidates"])
	if len(candidates) != 1 {
		t.Fatal(result)
	}
	c := candidates[0]
	if result["status"] != "BLOCKED" || c["status"] != "BLOCKED" || c["decision"] != "REVIEW_REQUIRED" || storageObject(c["economics"])["estimated_monthly_saving"] != nil || storageObject(c["confidence"])["status"] != "UNAVAILABLE" {
		t.Fatal("deep-copy edits did not revoke candidate claim", result)
	}
}

func TestNetworkFinancialWorkerRejectsNestedMutationAuthority(t *testing.T) {
	binding := model.Document{"tenant_id": "tenant", "resource_id": "resource"}
	input := model.Document{"binding": binding}
	result := networkBlocked(binding, nil)
	candidate := model.Document{"read_only": true, "pre_execution_ready": false, "execution_authorized": false, "verified_saving": nil}
	result["candidates"] = []model.Document{candidate}
	if e := validateNetworkResult(result, input); e != nil {
		t.Fatal(e)
	}
	for _, field := range []string{"read_only", "pre_execution_ready", "execution_authorized", "verified_saving"} {
		bad := model.Clone(result)
		rows := storageRows(bad["candidates"])
		rows[0][field] = true
		if field == "read_only" {
			rows[0][field] = false
		}
		bad["candidates"] = rows
		if validateNetworkResult(bad, input) == nil {
			t.Fatal("nested authority accepted", field)
		}
	}
}
