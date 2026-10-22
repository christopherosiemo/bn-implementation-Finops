package service

import (
	"context"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"strings"
	"testing"
	"time"
)

func commissioningCoverageTestGroup(currency string) model.Document {
	return model.Document{"currency": currency, "complete": true, "detected_spend": "100", "analysed_spend": "40", "observation_only_spend": "20", "blocked_spend": "30", "unsupported_spend": "10", "unallocated_spend": "25", "unowned_spend": "35", "credits": "-7.5", "net_spend": "92.5"}
}
func TestCommissioningCoverageUsesFourPartitionsAndOverlappingAllocationWithSeparateCreditsCurrencies(t *testing.T) {
	input := model.Document{"groups": []model.Document{commissioningCoverageTestGroup("GBP"), commissioningCoverageTestGroup("USD")}, "blockers": []string{}}
	result := commissioningCoverageProjection(input, "111122223333", "eu-west-1")
	if result["complete"] != true {
		t.Fatalf("trusted partitions rejected %#v", result)
	}
	rows := storageRows(result["currencies"])
	if len(rows) != 2 {
		t.Fatal("currencies combined")
	}
	for _, row := range rows {
		p := storageObject(row["percentages"])
		if row["detected_spend"] != "100" || row["credits"] != "-7.5" || row["unallocated_spend"] != "25" || p["analysed"] != "40" || p["unsupported"] != "10" || p["unallocated"] != "25" {
			t.Fatalf("coverage inflation %#v", row)
		}
	}
	if model.String(storageObject(result["scope"]), "financial_regions") != "ALL_REGIONS_INCLUDING_GLOBAL" {
		t.Fatal("scope narrowed to supported region")
	}
}
func TestCommissioningCoverageUnknownIncompleteZeroAndInvalidPartitionsHaveNoPercentages(t *testing.T) {
	for _, scenario := range []string{"incomplete", "unknown", "zero", "inflated", "currency", "allocation"} {
		t.Run(scenario, func(t *testing.T) {
			g := commissioningCoverageTestGroup("GBP")
			switch scenario {
			case "incomplete":
				g["complete"] = false
			case "unknown":
				g["detected_spend"] = nil
			case "zero":
				for _, key := range []string{"detected_spend", "analysed_spend", "observation_only_spend", "blocked_spend", "unsupported_spend", "unallocated_spend", "unowned_spend", "credits", "net_spend"} {
					g[key] = "0"
				}
			case "inflated":
				g["analysed_spend"] = "90"
			case "currency":
				g["currency"] = nil
			case "allocation":
				g["unallocated_spend"] = "101"
			}
			d := commissioningCoverageProjection(model.Document{"groups": []model.Document{g}}, "111122223333", "eu-west-1")
			for _, value := range storageObject(storageRows(d["currencies"])[0]["percentages"]) {
				if value != nil {
					t.Fatalf("%s unknown denominator became percentage %#v", scenario, d)
				}
			}
		})
	}
}
func TestCommissioningAccountCoverageDoesNotDropGlobalPayerChargesOrAcceptOtherMembers(t *testing.T) {
	account := "111122223333"
	rows := []model.Document{{"SubAccountId": account, "RegionId": "us-east-1", "ServiceName": "UnsupportedService"}, {"BillingAccountId": account, "SubAccountId": "", "ResourceId": "", "x_ProviderFields": model.Document{"line_item_usage_account_id": "", "line_item_resource_id": "", "line_item_line_item_type": "Credit", "bill_payer_account_id": account}}, {"SubAccountId": "999900001111", "BillingAccountId": account, "ResourceId": "i-other"}}
	if !commissioningAccountCharge(rows[0], account) || commissioningAccountCharge(rows[2], account) {
		t.Fatal("account scope or all-region denominator changed")
	}
	if !commissioningAccountCharge(rows[1], account) {
		t.Fatal("native payer credit disappeared")
	}
}
func TestCommissioningMetricReadinessRequiresIndependentMemoryAndCompletePairedSignals(t *testing.T) {
	metric := func(name string) model.Document {
		return model.Document{"metric": name, "status": "READY", "coverage_ppm": 1000000, "observed_samples": 24, "unknown_duration_ns": 0, "unit": "percent"}
	}
	cpu := metric("cpu_utilization")
	if !commissioningMetricReady([]model.Document{cpu}, "cpu") || commissioningMetricReady([]model.Document{cpu}, "memory") {
		t.Fatal("CPU inferred memory")
	}
	in := metric("network_receive")
	out := metric("network_transmit")
	if commissioningMetricReady([]model.Document{in}, "network") || !commissioningMetricReady([]model.Document{in, out}, "network") {
		t.Fatal("one direction established complete network evidence")
	}
	out["coverage_ppm"] = 999999
	if commissioningMetricReady([]model.Document{in, out}, "network") {
		t.Fatal("missing samples manufactured completeness")
	}
	if commissioningHistoryDays(model.Document{"environment": "NON_PRODUCTION"}, model.Document{"criticality": "NON_PRODUCTION"}, model.Document{"environment": "NON_PRODUCTION"}) != 14 || commissioningHistoryDays(model.Document{"environment": "PRODUCTION"}, nil) != 30 || commissioningHistoryDays(nil, model.Document{"high_seasonality": true}) != 90 {
		t.Fatal("history policy weakened")
	}
}
func TestAWSCommissioningEvidenceExactAccountScopeAndUnavailableBillingRemainExplicit(t *testing.T) {
	f := newMutationReplayFixture(t)
	ctx := context.Background()
	account := "444455556666"
	if e := f.roles["ingester"].Do(ctx, f.tenant, func(tx *store.Tx) error {
		for _, acct := range []string{account, "999900001111"} {
			_, e := tx.Create(ctx, "resources", model.Document{"provider": "AWS", "account_id": acct, "region": "eu-west-1", "resource_type": "EC2", "provider_resource_id": "i-readiness-" + acct, "environment": "NON_PRODUCTION", "owner": "UNKNOWN", "configuration_authority": "UNKNOWN", "workload_id": "not-a-persisted-workload"})
			if e != nil {
				return e
			}
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	var result model.Document
	if e := f.roles["ingester"].Do(ctx, f.tenant, func(tx *store.Tx) error {
		var e error
		result, e = (&API{}).CommissioningEvidence(ctx, tx, account, "eu-west-1", time.Now().UTC())
		return e
	}); e != nil {
		t.Fatal(e)
	}
	if model.Number(storageObject(result["ownership"]), "resource_count") != 1 || model.Number(storageObject(result["ownership"]), "unmapped_workload_count") != 1 {
		t.Fatalf("foreign account or nonexistent workload counted %#v", result["ownership"])
	}
	if result["execution_authorized"] != false || result["verified_saving"] != nil || storageObject(result["billing"])["status"] != "NOT_CONFIGURED" || storageObject(result["coverage"])["complete"] != false {
		t.Fatalf("missing evidence became authority %#v", result)
	}
	if len(storageRows(result["dimensions"])) != 8 {
		t.Fatal("scoreboard dimensions missing")
	}
	for _, row := range storageRows(storageObject(result["coverage"])["currencies"]) {
		if row["detected_spend"] != nil {
			t.Fatal("unknown spend became zero")
		}
		for _, percent := range storageObject(row["percentages"]) {
			if percent != nil {
				t.Fatal("unknown denominator became0 percent")
			}
		}
	}
}
func TestCommissioningHistoryCannotUseStaleResourceClassificationAfterWorkloadPromotion(t *testing.T) {
	r := model.Document{"environment": "NON_PRODUCTION"}
	p := model.Document{"criticality": "NON_PRODUCTION"}
	if commissioningHistoryDays(r, p, model.Document{"environment": "PRODUCTION"}) != 30 || commissioningHistoryDays(r, nil, model.Document{"environment": "NON_PRODUCTION"}) != 30 || commissioningHistoryDays(r, p) != 30 {
		t.Fatal("resource label or missing policy shortened production history")
	}
	p["high_seasonality"] = true
	if commissioningHistoryDays(r, p, model.Document{"environment": "PRODUCTION"}) != 90 {
		t.Fatal("seasonal production history shortened")
	}
}
func TestCommissioningNativeInvoiceIssuanceCancellationAndScopeStayDistinct(t *testing.T) {
	now := time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)
	native := model.Document{"InvoiceId": "native-invoice", "AccountId": "111122223333", "TaxAuthorityStatus": "ISSUED", "IssuedDate": now.Add(-time.Hour).Format(time.RFC3339), "Entity": model.Document{"InvoicingEntity": "AWS EMEA"}, "BaseCurrencyAmount": model.Document{"CurrencyCode": "GBP"}}
	receipt := func(n model.Document) model.Document {
		return model.Document{"id": "source-receipt", "invoices": []model.Document{{"receipt_id": "invoice-receipt", "native": n}}}
	}
	rows, status := commissioningInvoiceMetadata(receipt(native), "111122223333", now)
	if len(rows) != 1 || status != "NATIVE_ISSUED_EVIDENCE_NOT_BILLING_FINALITY" || rows[0]["post_issuance_corrections_possible"] != true {
		t.Fatal("issued invoice claimed final billing")
	}
	cancelled := model.Clone(native)
	cancelled["TaxAuthorityStatus"] = "CANCELLED"
	rows, status = commissioningInvoiceMetadata(receipt(cancelled), "111122223333", now)
	if status != "NON_FINAL_CANCELLED_OR_AMBIGUOUS" || rows[0]["native_status"] != "CANCELLED" {
		t.Fatal("cancellation hidden")
	}
	if _, status = commissioningInvoiceMetadata(receipt(native), "999900001111", now); status != "NON_FINAL_CANCELLED_OR_AMBIGUOUS" {
		t.Fatal("foreign payer invoice accepted")
	}
}
func TestCommissioningEBSPrivateAuthorityIsUnavailableOnlyForScopedReporting(t *testing.T) {
	record := model.Document{"status": "ASSESSED", "assessment": model.Document{"status": "RECOMMENDED", "source_refs": []model.Document{{"kind": "DECLARED_CONFIGURATION_AUTHORITY", "id": "restricted-authority", "sha256": "private-snapshot-hash"}}}}
	if !storageCommissioningAuthorityUnavailable(record, true) {
		t.Fatal("commissioning attempted private authority currentness")
	}
	if storageCommissioningAuthorityUnavailable(record, false) {
		t.Fatal("global API/analyst authority validation was bypassed")
	}
	if storageCommissioningAuthorityUnavailable(model.Document{"assessment": model.Document{"source_refs": []model.Document{{"kind": "REVIEWED_DEPENDENCY_GRAPH"}}}}, true) {
		t.Fatal("unaffected graph-only authority was classified as private")
	}
}
func TestCommissioningObjectStoragePrivateAuthorityKeepsGlobalCurrentnessUnchanged(t *testing.T) {
	record := model.Document{"assessment": model.Document{"configuration_authority_ref": model.Document{"kind": "DECLARED_S3_CONFIGURATION_AUTHORITY", "id": "private-declaration", "version": "1", "sha256": strings.Repeat("a", 64)}}}
	if !objectStorageCommissioningAuthorityUnavailable(record, true) {
		t.Fatal("commissioning attempted private object-storage authority currentness")
	}
	if objectStorageCommissioningAuthorityUnavailable(record, false) {
		t.Fatal("global API/analyst object-storage currentness was bypassed")
	}
	if objectStorageCommissioningAuthorityUnavailable(model.Document{"assessment": model.Document{}}, true) {
		t.Fatal("unaffected object-storage publication blocked")
	}
}
