package service

import (
	"github.com/christopherosiemo/bn-implementation-Finops/internal/evidence"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"strings"
	"testing"
	"time"
)

func storageFinancialTestRecord(id, kind, part, quantity, rate, amount string, start, end time.Time) model.Document {
	usage := map[string]string{"storage": "EBS:VolumeUsage.", "iops": "EBS:VolumeP-IOPS.", "throughput": "EBS:VolumeP-Throughput.", "snapshots": "EBS:SnapshotUsage", "fast_snapshot_restore": "EBS:FastSnapshotRestore", "archive": "EBS:SnapshotArchiveStorage"}[part]
	if part == "storage" || part == "iops" || part == "throughput" {
		usage += kind
	}
	unit := map[string]string{"storage": "GB-Mo", "iops": "IOPS-Mo", "throughput": "MiBps-Mo", "snapshots": "GB-Mo", "archive": "GB-Mo", "fast_snapshot_restore": "Hours"}[part]
	raw := model.Document{"product_servicecode": "AmazonEC2", "product_volume_api_name": kind, "line_item_usage_type": "EU-" + usage, "line_item_line_item_type": "Usage", "line_item_usage_account_id": "111122223333", "line_item_resource_id": id, "product_region_code": "eu-west-1", "pricing_term": "OnDemand", "pricing_unit": unit, "line_item_net_unblended_rate": rate, "line_item_usage_amount": quantity, "line_item_net_unblended_cost": amount, "line_item_currency_code": "USD", "pricing_rate_code": "component-" + kind + "-" + part, "line_item_operation": "CreateVolume-" + kind, "product_sku": "component-" + kind + "-" + part}
	return model.Document{"SubAccountId": "111122223333", "RegionId": "eu-west-1", "ResourceId": id, "ChargePeriodStart": start.Format(time.RFC3339), "ChargePeriodEnd": end.Format(time.RFC3339), "BilledCost": amount, "BillingCurrency": "USD", "x_SourceRecordId": id + ":" + part, "x_ProviderFields": raw}
}
func storageFinancialTestSetup() (model.Document, model.Document, model.Document, model.Document, time.Time, time.Time) {
	end := time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)
	start := end.Add(-24 * time.Hour)
	current := model.Document{"volume_id": "vol-0eb50000000000001", "volume_type": "gp2", "account_id": "111122223333", "region": "eu-west-1"}
	resource := model.Document{"provider_resource_id": current["volume_id"], "resource_type": "EBS_VOLUME", "account_id": current["account_id"], "region": current["region"], "storage_configuration": current}
	coverage := []model.Document{}
	for _, name := range []string{"snapshots", "fast_snapshot_restores", "snapshot_tiers"} {
		coverage = append(coverage, model.Document{"component": name, "status": "OBSERVED_COMPLETE_ACCOUNT_REGION_POINT_READ"})
	}
	inventory := model.Document{"volumes": []model.Document{current}, "snapshots": []model.Document{}, "coverage": coverage}
	canonical := model.Document{"inventory": inventory}
	caps := []model.Document{{"id": "gp2", "volume_type": "gp2", "baseline_iops": "3000", "baseline_throughput_mib_per_second": "250"}, {"id": "gp3", "volume_type": "gp3", "baseline_iops": "3000", "baseline_throughput_mib_per_second": "125"}}
	input := model.Document{"current_configuration": model.Document{"capability_id": "gp2", "volume_type": "gp2", "size_gib": "1000", "iops": "3000", "throughput_mib_per_second": "250"}, "capabilities": model.Document{"entries": caps}, "candidate_configurations": []model.Document{}, "snapshots": []model.Document{}}
	receipt := model.Document{"source_receipt_id": "component-receipt", "source_version": "1", "canonical_hash": strings.Repeat("a", 64), "source_proof": model.Document{"period_start": start.Format(time.RFC3339), "period_end": end.Format(time.RFC3339), "state": "COMPLETE"}}
	return resource, canonical, input, receipt, start, end
}

func TestStorageNativeThroughputRateNormalizesGiBpsMonth(t *testing.T) {
	_, _, _, receipt, start, end := storageFinancialTestSetup()
	id := "vol-0eb50000000000002"
	rows := []model.Document{storageFinancialTestRecord(id, "gp3", "storage", "1000", "0.08", "80", start, end), storageFinancialTestRecord(id, "gp3", "throughput", "1", "40.96", "40.96", start, end)}
	raw := evidence.Object(rows[1]["x_ProviderFields"])
	raw["pricing_unit"] = "GiBps-mo"
	rows[1]["x_ProviderFields"] = raw
	price, _, reasons := storageNativePrice(rows, "111122223333", "eu-west-1", id, "gp3", start, end, receipt, model.Document{"baseline_iops": "3000", "baseline_throughput_mib_per_second": "125"}, model.Document{"iops": "3000", "throughput_mib_per_second": "1149"})
	if len(reasons) > 0 {
		t.Fatal(reasons)
	}
	found := false
	for _, c := range evidence.Rows(price["components"]) {
		if c["component"] == "throughput" {
			found = true
			if c["unit"] != "MiBps-Mo" || c["rate"] != "0.040000000000" || c["quantity"] != "1024.000000000000" || c["amount"] != "40.960000000000" {
				t.Fatal("native amount/unit conversion changed", c)
			}
		}
	}
	if !found {
		t.Fatal("throughput component missing")
	}
}

func TestStorageCandidatePriceComparisonUsesOnlyBillableDimensions(t *testing.T) {
	for _, test := range []struct {
		name      string
		paid      bool
		change    string
		available bool
	}{{"unused-addons", false, "", true}, {"paid-rate-conflict", true, "rate", false}, {"storage-contract-conflict", false, "contract", false}} {
		t.Run(test.name, func(t *testing.T) {
			resource, canonical, input, receipt, start, end := storageFinancialTestSetup()
			a, b := "vol-0eb50000000000002", "vol-0eb50000000000003"
			inv := evidence.Object(canonical["inventory"])
			volumes := evidence.Rows(inv["volumes"])
			for _, id := range []string{a, b} {
				volumes = append(volumes, model.Document{"volume_id": id, "volume_type": "gp3", "account_id": "111122223333", "region": "eu-west-1"})
			}
			inv["volumes"] = volumes
			canonical["inventory"] = inv
			io := "3000"
			if test.paid {
				io = "6000"
			}
			candidate := model.Document{"id": "candidate", "capability_id": "gp3", "volume_type": "gp3", "size_gib": "1000", "iops": io, "throughput_mib_per_second": "125"}
			input["candidate_configurations"] = []model.Document{candidate}
			rows := []model.Document{storageFinancialTestRecord(model.String(resource, "provider_resource_id"), "gp2", "storage", "1000", "0.10", "100", start, end), storageFinancialTestRecord(a, "gp3", "storage", "1000", "0.08", "80", start, end), storageFinancialTestRecord(a, "gp3", "iops", "6000", "0.005", "30", start, end), storageFinancialTestRecord(a, "gp3", "throughput", "375", "0.04", "15", start, end), storageFinancialTestRecord(b, "gp3", "storage", "1000", "0.08", "80", start, end)}
			if test.change == "rate" {
				rows = append(rows, storageFinancialTestRecord(b, "gp3", "iops", "3000", "0.006", "18", start, end))
			}
			if test.change == "contract" {
				raw := evidence.Object(rows[4]["x_ProviderFields"])
				raw["product_sku"] = "different-native-contract"
				rows[4]["x_ProviderFields"] = raw
			}
			_, reasons := storageFinancialProjection(resource, canonical, input, receipt, rows, start, end)
			if len(reasons) > 0 {
				t.Fatal(reasons)
			}
			if (evidence.Object(evidence.Rows(input["candidate_configurations"])[0]["pricing"]) != nil) != test.available {
				t.Fatal("candidate billing-dimension ambiguity changed", candidate["pricing"])
			}
		})
	}
}

func TestStorageContinuingCostsRequireAttributableNativeIDs(t *testing.T) {
	for _, test := range []struct {
		name, id, part string
		known, related bool
	}{{"missing-snapshot-id", "", "snapshots", false, false}, {"unknown-fsr-id", "snap-0eb50000000000009", "fast_snapshot_restore", false, false}, {"unknown-archive-id", "snap-0eb50000000000009", "archive", false, false}, {"known-unrelated", "snap-0eb50000000000008", "snapshots", true, false}, {"associated-snapshot", "snap-0eb50000000000008", "snapshots", true, true}} {
		t.Run(test.name, func(t *testing.T) {
			resource, canonical, input, receipt, start, end := storageFinancialTestSetup()
			inv := evidence.Object(canonical["inventory"])
			if test.known {
				parent := "vol-0eb50000000000002"
				if test.related {
					parent = model.String(resource, "provider_resource_id")
				}
				inv["snapshots"] = []model.Document{{"snapshot_id": test.id, "volume_id": parent, "account_id": "111122223333", "region": "eu-west-1"}}
			}
			canonical["inventory"] = inv
			rows := []model.Document{storageFinancialTestRecord(model.String(resource, "provider_resource_id"), "gp2", "storage", "1000", "0.10", "100", start, end), storageFinancialTestRecord(test.id, "snapshot", test.part, "10", "0.05", "0.5", start, end)}
			ref, reasons := storageFinancialProjection(resource, canonical, input, receipt, rows, start, end)
			if !test.known {
				if input["continuing_costs"] != nil || len(reasons) == 0 || len(evidence.Rows(ref["absence_proofs"])) != 0 {
					t.Fatal("unknown native attribution became complete zero", input["continuing_costs"], reasons)
				}
				return
			}
			if len(reasons) > 0 || input["continuing_costs"] == nil {
				t.Fatal("known native attribution blocked", reasons)
			}
			for _, c := range evidence.Rows(evidence.Object(input["continuing_costs"])["components"]) {
				if c["component"] == "snapshots" {
					want := "0.000000000000"
					if test.related {
						want = "0.500000000000"
					}
					if c["amount"] != want {
						t.Fatal("snapshot attribution changed", c)
					}
				}
			}
		})
	}
	// Credits remain explicit continuing amounts; missing collection coverage
	// cannot become a proof that FSR/archive costs are absent.
	resource, canonical, input, receipt, start, end := storageFinancialTestSetup()
	id := model.String(resource, "provider_resource_id")
	credit := storageFinancialTestRecord(id, "gp2", "storage", "1", "2", "-2", start, end)
	creditRaw := evidence.Object(credit["x_ProviderFields"])
	creditRaw["line_item_line_item_type"] = "Credit"
	credit["x_ProviderFields"] = creditRaw
	rows := []model.Document{storageFinancialTestRecord(id, "gp2", "storage", "1000", "0.10", "100", start, end), credit}
	credit["x_SourceRecordId"] = "credit"
	_, reasons := storageFinancialProjection(resource, canonical, input, receipt, rows, start, end)
	if len(reasons) > 0 {
		t.Fatal(reasons)
	}
	found := false
	for _, c := range evidence.Rows(evidence.Object(input["continuing_costs"])["components"]) {
		if c["component"] == "continuing" && c["amount"] == "-2.000000000000" {
			found = true
		}
	}
	if !found {
		t.Fatal("native negative credit disappeared")
	}
	inv := evidence.Object(canonical["inventory"])
	inv["coverage"] = []model.Document{}
	canonical["inventory"] = inv
	ref, reasons := storageFinancialProjection(resource, canonical, input, receipt, rows, start, end)
	if input["continuing_costs"] != nil || len(reasons) == 0 || len(evidence.Rows(ref["absence_proofs"])) != 0 {
		t.Fatal("missing inventory became zero-cost closure")
	}
}
