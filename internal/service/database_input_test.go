package service

import (
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/provider"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/source"
)

func databaseInputTestArchive(name string) model.Document {
	return model.Document{"bucket": "native-evidence", "key": name, "version_id": "original-version", "body_sha256": strings.Repeat("a", 64)}
}

func TestDatabaseInputProvisionedStorageCannotProveClassIOCapacity(t *testing.T) {
	ref := databaseInputTestArchive("reviewed-io-baselines")
	ref["body_sha256"] = source.BytesHash(provider.RDSDocumentedIOBaselineAsset())
	catalog := model.Document{"ebs_baseline_asset_ref": ref}
	baseline, err := provider.RDSDocumentedIOBaseline("db.r6i.8xlarge")
	if err != nil || baseline == nil {
		t.Fatal("reviewed baseline unavailable", err)
	}
	native := model.Document{"ebs_baseline": baseline}
	iops, throughput := databaseClassIOCapacity("db.r6i.8xlarge", native, catalog, "60000", "2000000000")
	if iops != "40000.000000000000" || throughput != "1250000000.000000000000" {
		t.Fatal("provisioned setting exceeded fixed class baseline", iops, throughput)
	}
	iops, throughput = databaseClassIOCapacity("db.r6i.8xlarge", native, catalog, "3000", "131072000")
	if iops != "3000.000000000000" || throughput != "131072000.000000000000" {
		t.Fatal("class maximum replaced a smaller provisioned setting", iops, throughput)
	}
	for _, class := range []string{"db.r6i.large", "db.r6i.2xlarge", "db.t4g.large", "db.unknown.large"} {
		if a, b := databaseClassIOCapacity(class, native, catalog, "60000", "2000000000"); a != nil || b != nil {
			t.Fatal("unknown/burst class borrowed another class's IO", class)
		}
	}
	changed := databaseInputObject(native["ebs_baseline"])
	changed["iops"] = "999999"
	if a, b := databaseClassIOCapacity("db.r6i.8xlarge", model.Document{"ebs_baseline": changed}, catalog, "60000", "2000000000"); a != nil || b != nil {
		t.Fatal("altered capacity acquired documented authority")
	}
	ref["body_sha256"] = strings.Repeat("a", 64)
	if a, b := databaseClassIOCapacity("db.r6i.8xlarge", native, catalog, "60000", "2000000000"); a != nil || b != nil {
		t.Fatal("unarchived capacity source accepted")
	}
}

func TestDatabaseInputVersionedPhysicalCapacityRequiresArchiveAndNativeOrderability(t *testing.T) {
	asset := provider.RDSDocumentedPhysicalCapacityAssetV2()
	hash := source.BytesHash(asset)
	ref := databaseInputTestArchive("physical-capacity-v2")
	ref["body_sha256"] = hash
	legacy := databaseInputTestArchive("historical-v1")
	legacy["body_sha256"] = source.BytesHash(provider.RDSDocumentedIOBaselineAsset())
	native := databaseInputTestNative("db.m8g.16xlarge", "current-v2")
	catalog := model.Document{"raw_ref": databaseInputTestArchive("native-orderability"), "ebs_baseline_asset_ref": legacy, "ebs_baseline_asset_refs": model.Document{hash: ref}, "modification_constraints_status": "OBSERVED_NATIVE_CURRENT_INSTANCE_CONSTRAINTS", "modification_constraints": databaseInputTestModificationConstraints(native)}
	capacities, options := []model.Document{}, []model.Document{}
	for _, family := range []string{"m8g", "r8g", "m8i", "r8i", "m7i", "r7i"} {
		for _, size := range []string{"8xlarge", "12xlarge", "16xlarge"} {
			class := "db." + family + "." + size
			baseline, e := provider.RDSDocumentedCapacity(class, hash)
			if e != nil || baseline == nil {
				t.Fatal("reviewed literal class absent", class, e)
			}
			capacity := model.Document{"class": class, "status": "OBSERVED_CATALOG_CAPACITY", "ebs_baseline": baseline, "physical_capacity_asset_sha256": hash}
			for _, field := range []string{"vcpu", "memory_bytes", "network_bytes_per_second", "architecture", "cpu_model"} {
				capacity[field] = baseline[field]
			}
			capacities = append(capacities, capacity)
			options = append(options, model.Document{"class": class, "engine": "postgres", "engine_version": "16.4", "license_model": "postgresql-license", "storage_type": "gp3", "availability_zones": []string{"eu-west-1a"}, "multi_az_capable": true, "min_iops": 3000, "max_iops": 64000, "min_throughput_mibps": 125, "max_throughput_mibps": 1000, "min_storage_gib": 20, "max_storage_gib": 1000})
		}
	}
	catalog["capacities"], catalog["options"] = capacities, options
	parameters := model.Document{"raw_ref": databaseInputTestArchive("parameters"), "connection_capacity_status": "EXPLICIT_NATIVE_PARAMETER_LITERAL_ALL_GROUPS_IN_SYNC", "connection_capacity": 400}
	canonical := model.Document{"catalogs": model.Document{model.String(native, "arn"): catalog}, "parameters": model.Document{model.String(native, "arn"): parameters}}
	configuration := model.Document{"zones": []string{"eu-west-1a"}, "multi_az": false}
	entries, candidates, reasons := databaseCatalogInput(canonical, []model.Document{native}, configuration, "eu-west-1")
	if len(entries) != 18 || len(candidates) != 18 || len(reasons) > 0 {
		t.Fatal("native orderable V2 breadth refused", len(entries), len(candidates), reasons)
	}
	for _, entry := range entries {
		capacity := databaseInputObject(entry["capacity"])
		if capacity["vcpu"] == nil || capacity["memory_bytes"] == nil || capacity["network_bytes_per_second"] == nil || capacity["iops"] != "3000.000000000000" || capacity["throughput_bytes_per_second"] != "131072000.000000000000" {
			t.Fatal("native capacity or smaller provisioned cap lost", entry)
		}
		if !databaseSameStrings(model.Strings(entry, "zones"), []string{"eu-west-1a"}) {
			t.Fatal("zone orderability manufactured")
		}
	}
	// A documentation row alone does not make a class regionally orderable.
	catalog["options"] = options[1:]
	entries, _, _ = databaseCatalogInput(canonical, []model.Document{native}, configuration, "eu-west-1")
	if len(entries) != 17 {
		t.Fatal("unorderable documentation class became candidate")
	}
	catalog["options"] = options
	for _, change := range []string{"wrong-asset", "missing-archive", "altered-row", "native-memory", "native-cpu", "native-network", "native-architecture", "region"} {
		t.Run(change, func(t *testing.T) {
			copyCanonical := databaseInputObject(canonical)
			copyCatalog := databaseInputObject(databaseInputObject(copyCanonical["catalogs"])[model.String(native, "arn")])
			caps := databaseInputRows(copyCatalog["capacities"])
			region := "eu-west-1"
			switch change {
			case "wrong-asset":
				copyCatalog["ebs_baseline_asset_refs"] = model.Document{hash: legacy}
			case "missing-archive":
				delete(copyCatalog, "ebs_baseline_asset_refs")
			case "altered-row":
				row := databaseInputObject(caps[0]["ebs_baseline"])
				row["iops"] = "999999"
				caps[0]["ebs_baseline"] = row
			case "native-memory":
				caps[0]["memory_bytes"] = "1"
			case "native-cpu":
				caps[0]["vcpu"] = "1"
			case "native-network":
				caps[0]["network_bytes_per_second"] = "1"
			case "native-architecture":
				caps[0]["architecture"] = "x86_64"
			case "region":
				region = "eu-central-1"
			}
			copyCatalog["capacities"] = caps
			copyCanonical["catalogs"] = model.Document{model.String(native, "arn"): copyCatalog}
			entries, _, _ := databaseCatalogInput(copyCanonical, []model.Document{native}, configuration, region)
			for _, entry := range entries {
				if entry["class_id"] == "db.m8g.8xlarge" {
					for _, field := range []string{"vcpu", "memory_bytes", "network_bytes_per_second", "iops", "throughput_bytes_per_second"} {
						if databaseInputObject(entry["capacity"])[field] != nil {
							t.Fatal("unproved physical authority survived", change, field)
						}
					}
				}
			}
		})
	}
}
func databaseInputTestNative(class, id string) model.Document {
	return model.Document{"arn": "arn:aws:rds:eu-west-1:111122223333:db:" + id, "identifier": id, "resource_id": "db-" + id, "class": class, "engine": "postgres", "engine_version": "16.4", "license_model": "postgresql-license", "storage_type": "gp3", "availability_zone": "eu-west-1a", "multi_az": false, "status": "available", "account_id": "111122223333", "region": "eu-west-1", "allocated_storage_gib": 100, "iops": 3000, "storage_throughput_mibps": 125}
}
func databaseInputTestCUR(native model.Document, start time.Time, rate string) []model.Document {
	out := []model.Document{}
	r, _ := new(big.Rat).SetString(rate)
	for i := 0; i < 24; i++ {
		at := start.Add(time.Duration(i) * time.Hour)
		raw := model.Document{"product_servicecode": "AmazonRDS", "product_product_family": "Database Instance", "product_instance_type": native["class"], "product_region_code": native["region"], "product_database_engine": "PostgreSQL", "product_license_model": "No license required", "product_deployment_option": "Single-AZ", "line_item_operation": "CreateDBInstance:0014", "pricing_term": "OnDemand", "pricing_unit": "Hrs", "line_item_line_item_type": "Usage", "line_item_usage_account_id": native["account_id"], "line_item_resource_id": native["arn"], "line_item_currency_code": "USD", "line_item_net_unblended_rate": rate, "line_item_usage_amount": "1", "line_item_net_unblended_cost": databaseInputMoney(r)}
		out = append(out, model.Document{"ResourceId": native["arn"], "SubAccountId": native["account_id"], "RegionId": native["region"], "BillingCurrency": "USD", "BilledCost": databaseInputMoney(r), "ChargePeriodStart": at.Format(time.RFC3339), "ChargePeriodEnd": at.Add(time.Hour).Format(time.RFC3339), "x_SourceRecordId": model.String(native, "identifier") + at.Format(time.RFC3339), "x_ProviderFields": raw})
	}
	return out
}

func TestDatabaseInputNativeHourlyCoverageRetainsExtremaAndUnderlyingSamples(t *testing.T) {
	start := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	end := start.Add(24 * time.Hour)
	native := databaseInputTestNative("db.r6i.2xlarge", "current")
	rows := []model.Document{}
	for hour := 0; hour < 24; hour++ {
		for bin := 0; bin < 12; bin++ {
			for _, def := range databaseMetricDefs {
				if def.name == "replica_lag" {
					continue
				}
				value := "1"
				if def.name == "freeable_memory" {
					value = "20000000000"
				}
				if def.name == "used_storage" {
					value = "100000000000"
				}
				rows = append(rows, model.Document{"metric": def.native, "value": value, "unit": def.unit, "statistic": def.stat, "source_time": start.Add(time.Duration(hour)*time.Hour + time.Duration(bin)*5*time.Minute).Format(time.RFC3339), "period_seconds": 300, "sample_count": 5, "provider_resource_id": native["arn"], "account_id": native["account_id"], "region": native["region"]})
			}
		}
	}
	canonical := model.Document{"period": model.Document{"start": start.Format(time.RFC3339), "end": end.Format(time.RFC3339)}, "metrics": []model.Document{{"selection": model.Document{"resource_arn": native["arn"]}, "raw_ref": databaseInputTestArchive("metrics"), "metrics": rows}}}
	history, observations, reasons := databaseMetricsInput(canonical, []model.Document{native}, nil, end.Add(time.Hour))
	if len(reasons) != 0 || len(observations) != 24 {
		t.Fatalf("complete native coverage refused: %v", reasons)
	}
	point := databaseInputObject(databaseInputObject(observations[0]["metrics"])["cpu_utilization"])
	if model.Number(point, "sample_count") != 12 || point["native_sample_count"] != "60.000000000000" {
		t.Fatalf("native samples conflated with bins: %v", point)
	}
	for _, definition := range databaseInputRows(history["metrics"]) {
		if model.Number(definition, "expected_native_sample_count") != 60 {
			t.Fatal("native minute cadence absent")
		}
	}
	// One five-minute rollup with only one native minute is not full coverage.
	rows[0]["sample_count"] = 1
	_, _, reasons = databaseMetricsInput(canonical, []model.Document{native}, nil, end.Add(time.Hour))
	if !databaseInputHas(reasons, "DATABASE_NATIVE_SAMPLE_COVERAGE_INCOMPLETE") {
		t.Fatalf("sparse rollup admitted: %v", reasons)
	}
	rows[0]["sample_count"] = 5
	rows = append(rows, rows[0])
	databaseInputRowsValue := databaseInputRows(canonical["metrics"])
	databaseInputRowsValue[0]["metrics"] = rows
	canonical["metrics"] = databaseInputRowsValue
	_, _, reasons = databaseMetricsInput(canonical, []model.Document{native}, nil, end.Add(time.Hour))
	if !databaseInputHas(reasons, "DATABASE_METRIC_HOURLY_COVERAGE_INCOMPLETE") {
		t.Fatalf("duplicate bin admitted: %v", reasons)
	}
}

func TestDatabaseInputCURRequiresCompleteExactNativeNetRateAndPreservesNegativeCases(t *testing.T) {
	start := time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC)
	native := databaseInputTestNative("db.r6i.2xlarge", "current")
	rows := databaseInputTestCUR(native, start, "0.5")
	ref := databaseInputRef("AWS_CUR2_CONNECTION", "receipt", "revision", strings.Repeat("b", 64))
	price, reason := databaseCURPrice(rows, native, start, start.Add(24*time.Hour), ref)
	if reason != "" || price.wire["rate"] != "0.500000000000" || price.wire["quantity"] != "24.000000000000" || price.wire["amount"] != "12.000000000000" || len(price.ids) != 24 {
		t.Fatalf("native price mismatch: %s", reason)
	}
	_, reason = databaseCURPrice(rows[:23], native, start, start.Add(24*time.Hour), ref)
	if reason != "DATABASE_CUR_PRICE_COVERAGE_INCOMPLETE" {
		t.Fatalf("gap admitted: %s", reason)
	}
	_, reason = databaseCURPrice(append(rows, rows[0]), native, start, start.Add(24*time.Hour), ref)
	if reason != "DATABASE_CUR_PRICE_GAP_OR_MIXED_CONFIGURATION" {
		t.Fatalf("overlap admitted: %s", reason)
	}
	raw := databaseInputObject(rows[0]["x_ProviderFields"])
	raw["line_item_line_item_type"] = "DiscountedUsage"
	rows[0]["x_ProviderFields"] = raw
	_, reason = databaseCURPrice(rows, native, start, start.Add(24*time.Hour), ref)
	if reason != "DATABASE_CUR_PRICE_DIMENSIONS_UNSUPPORTED" {
		t.Fatalf("covered usage silently avoids commitments: %s", reason)
	}
	for _, tc := range []struct{ in, want string }{{"1.0000000000005", "1.000000000000"}, {"1.0000000000015", "1.000000000002"}, {"-1.0000000000015", "-1.000000000002"}} {
		r, _ := new(big.Rat).SetString(tc.in)
		if databaseInputMoney(r) != tc.want {
			t.Fatal("Decimal12 half-even changed")
		}
	}
}

func TestDatabaseInputCommitmentZeroRequiresSeparateNativeDatabasePlansAndCompletePayer(t *testing.T) {
	now := time.Date(2026, 10, 20, 1, 0, 0, 0, time.UTC)
	registration := model.Document{"id": "source", "version": 1, "payer_account_id": "111122223333", "usage_account_ids": []string{"111122223333"}, "commitment_receipt_id": "commitment"}
	canonical := model.Document{"resource": model.Document{"account_id": "111122223333"}, "commitments": model.Document{"scope_basis": "ACCOUNT_REGION_NATIVE_RDS_RESERVATION_INVENTORY", "reserved_instances": []model.Document{}}, "database_savings_plans": model.Document{"status": "OBSERVED_ACCOUNT_ONLY_NOT_COMPLETE_PAYER_PORTFOLIO", "plans": []model.Document{}, "raw_ref": databaseInputTestArchive("database-plans")}}
	receipt := model.Document{"id": "commitment", "kind": "AWS_COMMITMENT", "source_id": "source", "config_hash": source.ConfigurationHash(registration), "commitment_scope": model.Document{"observed_at": now.Format(time.RFC3339), "complete": true, "payer_account_id": "111122223333", "scope": "PAYER_ALL_LINKED_ACCOUNTS_ALL_REGIONS", "usage_account_ids": []string{"111122223333"}, "savings_plan_count": 0}}
	if reason := databaseCommitmentClosure(canonical, registration, receipt, now); reason != "" {
		t.Fatal(reason)
	}
	plans := databaseInputObject(canonical["database_savings_plans"])
	plans["plans"] = model.Document{}
	canonical["database_savings_plans"] = plans
	if databaseCommitmentClosure(canonical, registration, receipt, now) != "DATABASE_NATIVE_DATABASE_SAVINGS_PLAN_EXPOSURE_UNRESOLVED" {
		t.Fatal("malformed plan map became empty inventory")
	}
	plans["plans"] = []model.Document{}
	canonical["database_savings_plans"] = plans
	reservations := databaseInputObject(canonical["commitments"])
	reservations["reserved_instances"] = model.Document{}
	canonical["commitments"] = reservations
	if databaseCommitmentClosure(canonical, registration, receipt, now) != "DATABASE_RESERVED_INVENTORY_UNAVAILABLE" {
		t.Fatal("malformed reservation map became empty inventory")
	}
	reservations["reserved_instances"] = []model.Document{}
	canonical["commitments"] = reservations
	canonical["database_savings_plans"] = model.Document{"status": "UNKNOWN_NOT_COMMISSIONED"}
	if databaseCommitmentClosure(canonical, registration, receipt, now) != "DATABASE_NATIVE_DATABASE_SAVINGS_PLAN_EXPOSURE_UNRESOLVED" {
		t.Fatal("unknown DBSP treated as zero")
	}
	databaseInputObject(receipt["commitment_scope"])["usage_account_ids"] = []string{"111122223333", "999900001111"} // immutable copy below explicitly replaces the actual scope.
	scope := databaseInputObject(receipt["commitment_scope"])
	scope["usage_account_ids"] = []string{"111122223333", "999900001111"}
	receipt["commitment_scope"] = scope
	if databaseCommitmentClosure(canonical, registration, receipt, now) != "DATABASE_ORGANISATION_COMMITMENT_ALLOCATION_UNAVAILABLE" {
		t.Fatal("cross-account sharing treated as zero")
	}
}

func TestDatabaseInputClassOnlyContinuingCostsAndExactEconomicReferences(t *testing.T) {
	now := time.Date(2026, 10, 20, 1, 0, 0, 0, time.UTC)
	start := now.Add(-time.Hour).Add(-24 * time.Hour)
	end := start.Add(24 * time.Hour)
	current := databaseInputTestNative("db.r6i.2xlarge", "current")
	target := databaseInputTestNative("db.r6i.xlarge", "target")
	resource := model.Document{"resource_type": "RDS_INSTANCE", "account_id": current["account_id"], "region": current["region"], "provider_resource_id": current["arn"]}
	registration := model.Document{"id": "source", "version": 1, "payer_account_id": current["account_id"], "usage_account_ids": []string{model.String(current, "account_id")}, "commitment_receipt_id": "commitment"}
	commitment := model.Document{"id": "commitment", "kind": "AWS_COMMITMENT", "source_id": "source", "config_hash": source.ConfigurationHash(registration), "commitment_scope": model.Document{"observed_at": now.Format(time.RFC3339), "complete": true, "payer_account_id": current["account_id"], "scope": "PAYER_ALL_LINKED_ACCOUNTS_ALL_REGIONS", "usage_account_ids": []string{model.String(current, "account_id")}, "savings_plan_count": 0}}
	canonical := model.Document{"resource": resource, "discovery": model.Document{"instances": []model.Document{current, target}, "raw_ref": databaseInputTestArchive("discovery")}, "commitments": model.Document{"scope_basis": "ACCOUNT_REGION_NATIVE_RDS_RESERVATION_INVENTORY", "reserved_instances": []model.Document{}}, "database_savings_plans": model.Document{"status": "OBSERVED_ACCOUNT_ONLY_NOT_COMPLETE_PAYER_PORTFOLIO", "plans": []model.Document{}, "raw_ref": databaseInputTestArchive("plans")}}
	input := model.Document{"engine": "postgres", "engine_version": "16.4", "license_model": "postgresql-license", "storage_type": "gp3", "current_configuration": model.Document{"member_ids": []string{model.String(current, "arn")}, "multi_az": false}, "candidate_configurations": []model.Document{{"id": "class:db.r6i.xlarge", "catalog_id": "class:db.r6i.xlarge", "member_count": 1, "multi_az": false, "zones": []string{"eu-west-1a"}, "pricing": nil}}}
	ref := model.Document{"source_receipt_id": "receipt", "source_version": "revision", "canonical_hash": strings.Repeat("c", 64), "source_proof": model.Document{"period_start": time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC).Format(time.RFC3339), "period_end": end.Format(time.RFC3339), "state": "COMPLETE"}}
	rows := append(databaseInputTestCUR(current, start, "0.5"), databaseInputTestCUR(target, start, "0.25")...)
	full, reasons := databaseCURInput(resource, canonical, input, ref, registration, commitment, rows, now)
	if len(reasons) > 0 {
		t.Fatal(reasons)
	}
	if len(model.Strings(full, "economic_record_ids")) != 48 {
		t.Fatal("actual selected cost IDs absent")
	}
	if model.String(databaseInputObject(databaseInputObject(input["current_pricing"])["source_ref"]), "kind") != "AWS_CUR_NET_USAGE" {
		t.Fatal("compact CUR ref collides with server currentness ref")
	}
	continuing := databaseInputObject(input["continuing_costs"])
	if model.String(databaseInputObject(continuing["storage"]), "amount") != "0.000000000000" {
		t.Fatal("exhaustive zero changed")
	}
	// A fee without resource allocation makes the otherwise complete same-day
	// export insufficient. Credits are not used to fabricate avoided cost.
	fee := model.Document{"ResourceId": "", "SubAccountId": current["account_id"], "RegionId": current["region"], "ChargePeriodStart": start.Format(time.RFC3339), "ChargePeriodEnd": end.Format(time.RFC3339), "BillingCurrency": "USD", "BilledCost": "1", "x_SourceRecordId": "unallocated", "x_ProviderFields": model.Document{"product_servicecode": "AmazonRDS", "product_product_family": "Database Instance"}}
	_, reasons = databaseCURInput(resource, canonical, input, ref, registration, commitment, append(rows, fee), now)
	if !databaseInputHas(reasons, "DATABASE_UNALLOCATED_RDS_CHARGE_EXPOSURE") {
		t.Fatal("unallocated fees disappeared")
	}
	before, _ := json.Marshal(rows)
	databaseCURInput(resource, canonical, input, ref, registration, commitment, rows, now)
	after, _ := json.Marshal(rows)
	if string(before) != string(after) {
		t.Fatal("source records mutated")
	}
}
func databaseInputHas(rs []string, s string) bool {
	for _, r := range rs {
		if r == s {
			return true
		}
	}
	return false
}

func databaseInputTestModificationConstraints(native model.Document) model.Document {
	storage := model.Document{"storage_type": "gp3", "supports_storage_autoscaling": true, "storage_size": []model.Document{{"from": 20, "to": 1000, "step": 1}}, "provisioned_iops": []model.Document{{"from": 3000, "to": 64000, "step": 1}}, "provisioned_storage_throughput": []model.Document{{"from": 125, "to": 1000, "step": 1}}, "iops_to_storage_ratio": []model.Document{{"from": "0.5", "to": "500"}}, "storage_throughput_to_iops_ratio": []model.Document{{"from": "0.001", "to": "1"}}, "native_fields": model.Document{"name": "ValidStorageOptions", "value": "", "children": []model.Document{{"name": "StorageType", "value": "gp3", "children": []model.Document{}}}}}
	return model.Document{"resource_arn": native["arn"], "basis": "NATIVE_DESCRIBE_VALID_DB_INSTANCE_MODIFICATIONS_CURRENT_INSTANCE_ONLY", "raw_page_sha256": strings.Repeat("d", 64), "storage": []model.Document{storage}, "valid_processor_features": []model.Document{}, "supports_dedicated_log_volume": false, "additional_storage": nil, "native_message": model.Document{"name": "ValidDBInstanceModificationsMessage", "value": "", "children": []model.Document{databaseInputObject(storage["native_fields"])}}}
}

func TestDatabaseInputNativeModificationConstraintsDoNotInventStepOrCapacity(t *testing.T) {
	native := databaseInputTestNative("db.r6i.2xlarge", "current")
	catalog := model.Document{"modification_constraints_status": "OBSERVED_NATIVE_CURRENT_INSTANCE_CONSTRAINTS", "modification_constraints": databaseInputTestModificationConstraints(native)}
	if reason := databaseModificationReason(catalog, native); reason != "" {
		t.Fatal(reason)
	}
	constraint := databaseInputObject(catalog["modification_constraints"])
	storage := databaseInputRows(constraint["storage"])
	storage[0]["provisioned_iops"] = []model.Document{{"from": 3000, "to": 64000, "step": nil}}
	constraint["storage"] = storage
	catalog["modification_constraints"] = constraint
	if databaseModificationReason(catalog, native) != "DATABASE_NATIVE_STORAGE_MODIFICATION_BOUND_UNPROVEN" {
		t.Fatal("unknown native Step became one")
	}
	catalog["modification_constraints"] = databaseInputTestModificationConstraints(native)
	constraint = databaseInputObject(catalog["modification_constraints"])
	constraint["resource_arn"] = "foreign"
	catalog["modification_constraints"] = constraint
	if databaseModificationReason(catalog, native) != "DATABASE_NATIVE_MODIFICATION_CONSTRAINTS_BINDING_INVALID" {
		t.Fatal("foreign native modification constraint admitted")
	}
	catalog["modification_constraints_status"] = "UNSUPPORTED_NATIVE_MODIFICATION_CONSTRAINTS"
	if databaseModificationReason(catalog, native) != "DATABASE_NATIVE_MODIFICATION_CONSTRAINTS_UNAVAILABLE" {
		t.Fatal("unsupported native call became valid bounds")
	}
}

func TestDatabaseInputHourlyCURCapacityContinuityRejectsChangedSplitGapAndRecreatedInstances(t *testing.T) {
	start := time.Date(2026, 9, 28, 0, 0, 0, 0, time.UTC)
	end := start.Add(14 * 24 * time.Hour)
	native := databaseInputTestNative("db.r6i.2xlarge", "current")
	native["instance_create_time"] = start.Add(-24 * time.Hour).Format(time.RFC3339)
	rows := []model.Document{}
	for day := 0; day < 14; day++ {
		rows = append(rows, databaseInputTestCUR(native, start.Add(time.Duration(day)*24*time.Hour), "0.5")...)
	}
	ids, reason := databaseCURClassHistory(rows, []model.Document{native}, start, end)
	if reason != "" || len(ids) != 336 {
		t.Fatalf("complete actual billed hours refused: %s", reason)
	}
	copyRows := func() []model.Document { return databaseInputRows(rows) }
	for _, test := range []struct {
		name, want string
		mutate     func([]model.Document)
	}{
		{"class", "DATABASE_HISTORICAL_CLASS_CHANGED", func(r []model.Document) {
			raw := databaseInputObject(r[0]["x_ProviderFields"])
			raw["product_instance_type"] = "db.r6i.large"
			r[0]["x_ProviderFields"] = raw
		}},
		{"split", "DATABASE_HISTORICAL_WHOLE_HOURLY_USAGE_REQUIRED", func(r []model.Document) { r[0]["ChargePeriodEnd"] = start.Add(30 * time.Minute).Format(time.RFC3339) }},
		{"quantity", "DATABASE_HISTORICAL_WHOLE_HOURLY_USAGE_REQUIRED", func(r []model.Document) {
			raw := databaseInputObject(r[0]["x_ProviderFields"])
			raw["line_item_usage_amount"] = "0.5"
			r[0]["x_ProviderFields"] = raw
		}},
		{"dimensions", "DATABASE_HISTORICAL_DIMENSIONS_CHANGED", func(r []model.Document) {
			raw := databaseInputObject(r[0]["x_ProviderFields"])
			raw["product_deployment_option"] = "Multi-AZ"
			r[0]["x_ProviderFields"] = raw
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := copyRows()
			test.mutate(r)
			_, reason := databaseCURClassHistory(r, []model.Document{native}, start, end)
			if reason != test.want {
				t.Fatalf("got %s want %s", reason, test.want)
			}
		})
	}
	if _, reason = databaseCURClassHistory(rows[1:], []model.Document{native}, start, end); reason != "DATABASE_HISTORICAL_CONFIGURATION_REQUIRED" {
		t.Fatal("missing hour admitted", reason)
	}
	if _, reason = databaseCURClassHistory(append(copyRows(), rows[0]), []model.Document{native}, start, end); reason != "DATABASE_HISTORICAL_USAGE_AMBIGUOUS" {
		t.Fatal("duplicate whole hour admitted", reason)
	}
	newNative := databaseInputObject(native)
	newNative["instance_create_time"] = start.Add(time.Hour).Format(time.RFC3339)
	if _, reason = databaseCURClassHistory(rows, []model.Document{newNative}, start, end); reason != "DATABASE_HISTORICAL_INCARNATION_UNAVAILABLE" {
		t.Fatal("reused ARN established earlier incarnation", reason)
	}
	delete(newNative, "instance_create_time")
	if _, reason = databaseCURClassHistory(rows, []model.Document{newNative}, start, end); reason != "DATABASE_HISTORICAL_INCARNATION_UNAVAILABLE" {
		t.Fatal("unknown creation became old incarnation", reason)
	}
}

func TestDatabaseInputUnknownOwnershipAndClusterMemberCapacityRemainBlocked(t *testing.T) {
	now := time.Date(2026, 10, 20, 1, 0, 0, 0, time.UTC)
	native := databaseInputTestNative("db.r6i.2xlarge", "current")
	resource := model.Document{"id": "resource", "tenant_id": "tenant", "workload_id": "workload", "provider": "AWS", "provider_resource_id": native["arn"], "account_id": native["account_id"], "region": native["region"], "resource_type": "RDS_INSTANCE", "configuration_authority": "UNKNOWN", "database_configuration": native}
	snapshot := model.Document{"schema_version": "1", "resource_id": "resource", "config_hash": DatabaseConfigurationHash(resource)}
	canonical := model.Document{"schema_version": "1", "resource": resource, "discovery": model.Document{"scope": model.Document{"account_id": native["account_id"], "region": native["region"]}, "instances": []model.Document{native}, "clusters": []model.Document{}, "raw_ref": databaseInputTestArchive("discovery")}, "period": model.Document{"start": now.Add(-time.Hour).Add(-14 * 24 * time.Hour).Format(time.RFC3339), "end": now.Add(-time.Hour).Format(time.RFC3339)}}
	_, reasons := databaseNativeInput(resource, snapshot, canonical, nil, now)
	for _, reason := range []string{"DATABASE_OWNERSHIP_AND_CONFIGURATION_REQUIRED", "DATABASE_SAFETY_POLICY_REQUIRED"} {
		if !databaseInputHas(reasons, reason) {
			t.Fatalf("missing gate %s: %v", reason, reasons)
		}
	}
	native["pending_modified_values"] = model.Document{"DBInstanceClass": "db.r6i.large"}
	_, reasons = databaseNativeInput(resource, snapshot, canonical, nil, now)
	if !databaseInputHas(reasons, "DATABASE_PENDING_CONFIGURATION_CHANGE") {
		t.Fatal("pending native class change admitted")
	}
	delete(native, "pending_modified_values")
	native["cluster_identifier"] = "cluster"
	_, reasons = databaseNativeInput(resource, snapshot, canonical, nil, now)
	if !databaseInputHas(reasons, "DATABASE_CLUSTER_MEMBER_REQUIRES_WHOLE_CLUSTER_ASSESSMENT") {
		t.Fatal("Aurora member borrowed a whole-cluster zero")
	}
	native["class"] = "db.t4g.large"
	_, reasons = databaseNativeInput(resource, snapshot, canonical, nil, now)
	if !databaseInputHas(reasons, "DATABASE_BURST_CREDIT_BASELINE_AND_EXPOSURE_UNRESOLVED") {
		t.Fatal("unknown credit baseline admitted")
	}
}
