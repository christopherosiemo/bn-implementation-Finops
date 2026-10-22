package service

import (
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"math/big"
	"strings"
	"testing"
)

func networkCoverageTestAssessment() model.Document {
	ref := model.Document{"kind": "AWS_CUR2_CONNECTION", "source_connection_id": "registered", "source_receipt_id": "receipt", "ingestion_job_id": "job", "canonical_hash": strings.Repeat("a", 64), "economic_record_ids": []string{"hourly-native", "processing-native"}}
	cohort := model.Document{"id": "cohort", "bytes": "1000", "traffic_complete": true, "attribution_complete": true}
	candidate := model.Document{"cohort_id": "cohort", "status": "RECOMMENDED", "economics": model.Document{"status": "MODELLED_NATIVE_CUSTOMER_ECONOMICS", "pricing_basis": "NATIVE_CUSTOMER_NET_ONLY", "currency": "GBP", "observed_allocated_cost": "100.000000000001"}}
	return model.Document{"model_kind": "NETWORK_ASSESSMENT_V1", "status": "RECOMMENDED", "read_only": true, "pre_execution_ready": false, "execution_authorized": false, "verified_saving": nil, "denominators": model.Document{"observation_complete": true, "flow_complete": true, "billing_complete": true, "billing_scope_complete": true, "observed_processed_bytes": "1000", "attributed_cohort_bytes": "1000", "unattributed_bytes": "0"}, "economics": model.Document{"currency": "GBP", "detected_native_cost": "100.000000000001"}, "cohorts": []model.Document{cohort}, "candidates": []model.Document{candidate}, "financial_references": []model.Document{ref}}
}
func TestNetworkCoverageRequiresFullNativePopulationAndCurrentEconomics(t *testing.T) {
	accepted := networkCoverageTestAssessment()
	lines := networkCoverageEconomicLines(accepted)
	if len(lines) != 2 {
		t.Fatalf("supported complete economics lost exact native lines: %v", lines)
	}
	for name, change := range map[string]func(model.Document){
		"partial flow":        func(d model.Document) { d["denominators"].(model.Document)["flow_complete"] = false },
		"missing traffic":     func(d model.Document) { d["denominators"].(model.Document)["observed_processed_bytes"] = nil },
		"partial attribution": func(d model.Document) { d["denominators"].(model.Document)["attributed_cohort_bytes"] = "500" },
		"unknown bytes":       func(d model.Document) { d["cohorts"].([]model.Document)[0]["bytes"] = nil },
		"partial allocation": func(d model.Document) {
			d["candidates"].([]model.Document)[0]["economics"].(model.Document)["observed_allocated_cost"] = "50"
		},
		"reference prices": func(d model.Document) {
			d["candidates"].([]model.Document)[0]["economics"].(model.Document)["pricing_basis"] = "PUBLIC_LIST"
		},
		"currency mismatch": func(d model.Document) {
			d["candidates"].([]model.Document)[0]["economics"].(model.Document)["currency"] = "USD"
		},
		"review only": func(d model.Document) { d["candidates"].([]model.Document)[0]["status"] = "OBSERVATION_ONLY" },
		"blocked":     func(d model.Document) { d["status"] = "BLOCKED" },
		"overlapping cohorts": func(d model.Document) {
			d["cohorts"] = append(storageRows(d["cohorts"]), storageRows(d["cohorts"])[0])
			d["candidates"] = append(storageRows(d["candidates"]), storageRows(d["candidates"])[0])
		},
		"missing source":     func(d model.Document) { delete(d["financial_references"].([]model.Document)[0], "canonical_hash") },
		"foreign provenance": func(d model.Document) { d["financial_references"].([]model.Document)[0]["kind"] = "CUSTOMER_IMPORT" },
	} {
		t.Run(name, func(t *testing.T) {
			d := networkCoverageTestAssessment()
			change(d)
			if len(networkCoverageEconomicLines(d)) != 0 {
				t.Fatal("partial/unsupported economics promoted native resource charges")
			}
		})
	}
	accepted["status"] = "NO_CHANGE"
	accepted["candidates"].([]model.Document)[0]["status"] = "NO_CHANGE"
	if len(networkCoverageEconomicLines(accepted)) != 2 {
		t.Fatal("supported uneconomic no-change must still count as analysed")
	}
}
func TestNetworkCoveragePreservesCreditsCurrencyAndUnknownDenominators(t *testing.T) {
	g := newDatabaseCoverageTotals()
	g.values["detected_spend"].SetInt64(100)
	g.values["analysed_spend"].SetInt64(25)
	g.values["credits"].SetInt64(-20)
	g.values["net_spend"].SetInt64(80)
	rows := networkCoverageRows(map[string]*databaseCoverageTotals{"GBP": g}, false)
	if rows[0]["analysed_percent"] != "25" || rows[0]["credits"] != "-20" || rows[0]["net_spend"] != "80" {
		t.Fatalf("credits altered positive denominator: %v", rows)
	}
	zero := newDatabaseCoverageTotals()
	zero.values["credits"].Set(big.NewRat(-1, 1))
	if networkCoverageRows(map[string]*databaseCoverageTotals{"USD": zero}, false)[0]["analysed_percent"] != nil {
		t.Fatal("zero positive denominator cannot claim percentage")
	}
	g.known = false
	unknown := networkCoverageRows(map[string]*databaseCoverageTotals{"GBP": g}, false)[0]
	if unknown["detected_spend"] != nil || unknown["analysed_percent"] != nil || unknown["complete"] != false {
		t.Fatal("unknown coverage was manufactured as zero")
	}
	if networkCoverageComponent(model.Document{"ServiceName": "AmazonVPC", "x_ProviderFields": model.Document{"product_servicecode": "AmazonVPC", "line_item_usage_type": "Unsupported-Network-Unit"}}) != "UNSUPPORTED_NETWORK_COMPONENT" {
		t.Fatal("unsupported network charge disappeared")
	}
	if networkCoverageComponent(model.Document{"ServiceName": "AmazonEC2", "x_ProviderFields": model.Document{"product_servicecode": "AmazonEC2", "line_item_usage_type": "BoxUsage:m6i.large"}}) != "" {
		t.Fatal("compute cost incorrectly classified as network")
	}
}
