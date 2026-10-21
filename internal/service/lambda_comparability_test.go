package service

import (
	"github.com/christopherosiemo/bn-implementation-Finops/internal/evidence"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"testing"
	"time"
)

func TestLambdaBenchmarkNativeVersionEpochBindingAndAcquisitionMustMatch(t *testing.T) {
	now := time.Now().UTC()
	base := "arn:aws:lambda:eu-west-1:111122223333:function:processor"
	binding := model.Document{"tenant_id": "tenant", "provider": "AWS", "resource_id": "resource", "provider_resource_id": base, "account_id": "111122223333", "region": "eu-west-1", "workload_id": "workload"}
	config := model.Document{"base_function_arn": base, "version": "1", "memory_size_mb": 2048, "code_sha256": evidence.Hash("code"), "architecture": "x86_64", "configuration_epoch_hash": evidence.Hash("epoch"), "last_modified": now.Add(-24 * time.Hour).Format(time.RFC3339Nano)}
	point := model.Document{"binding": binding, "executed_version": "1", "executed_target_arn": base + ":1", "configuration_epoch_hash": config["configuration_epoch_hash"], "code_sha256": config["code_sha256"], "architecture": "x86_64", "memory_size_mb": "2048", "measurement_start": now.Add(-3 * time.Minute).Format(time.RFC3339Nano), "measurement_end": now.Add(-2 * time.Minute).Format(time.RFC3339Nano), "received_at": now.Add(-time.Minute).Format(time.RFC3339Nano)}
	snapshot := model.Document{"observed_at": now.Add(-4 * time.Minute).Format(time.RFC3339Nano)}
	if rs := lambdaPerformanceNativeConfigurationReasons(point, config, snapshot, binding, now); len(rs) > 0 {
		t.Fatal(rs)
	}
	for _, change := range []string{"version", "epoch", "memory", "code", "binding", "historical_backfill"} {
		d := model.Clone(point)
		switch change {
		case "version":
			d["executed_target_arn"] = base + ":2"
		case "epoch":
			d["configuration_epoch_hash"] = evidence.Hash("different")
		case "memory":
			d["memory_size_mb"] = "1536"
		case "code":
			d["code_sha256"] = evidence.Hash("other-package")
		case "binding":
			b := model.Clone(binding)
			b["tenant_id"] = "foreign"
			d["binding"] = b
		case "historical_backfill":
			d["measurement_start"] = now.Add(-5 * time.Minute).Format(time.RFC3339Nano)
		}
		if rs := lambdaPerformanceNativeConfigurationReasons(d, config, snapshot, binding, now); len(rs) == 0 {
			t.Fatal("mismatched native benchmark accepted", change)
		}
	}
}

func TestLambdaNativeV2CurveKeepsLegacyVisibleWithoutVeto(t *testing.T) {
	manifest := evidence.Hash("same-registered-dependency-manifest")
	current := model.Document{"version": "1", "memory_size_mb": 2048}
	first := model.Document{"id": "current-v2", "executed_version": "1", "memory_size_mb": "2048", "non_memory_compatibility": model.Document{"dependency_manifest_sha256": manifest}}
	second := model.Document{"id": "candidate-v2", "executed_version": "2", "memory_size_mb": "1536", "non_memory_compatibility": model.Document{"dependency_manifest_sha256": manifest}}
	points, refs, rs := lambdaSelectNativePerformance([]model.Document{first, second}, []model.Document{{"snapshot_id": "1"}, {"snapshot_id": "2"}}, current)
	if len(points) != 2 || len(refs) != 2 || len(rs) > 0 {
		t.Fatal("valid V2 curve filtered", rs)
	}
	result := model.Document{"status": "RECOMMENDED", "reason_codes": []string{}, "candidates": []model.Document{{"economics": model.Document{"estimated_window_saving": "1.00"}}}}
	lambdaApplyPerformanceAuthority(result, model.Document{"legacy_receipts": []model.Document{{"id": "legacy"}}}, model.Document{"receipts": points}, refs, []string{"LAMBDA_LEGACY_BENCHMARK_NOT_AUTHORITATIVE_FOR_NEW_CURVES"})
	if result["status"] != "RECOMMENDED" || len(model.Strings(result, "reason_codes")) != 0 || model.Number(storageObject(result["performance_authority"]), "legacy_receipt_count") != 1 {
		t.Fatal("legacy history vetoed valid V2 curve")
	}
	changed := model.Clone(second)
	changed["non_memory_compatibility"] = model.Document{"dependency_manifest_sha256": evidence.Hash("changed-dependencies")}
	selected, _, warnings := lambdaSelectNativePerformance([]model.Document{first, changed}, []model.Document{{}, {}}, current)
	if len(selected) != 1 || len(warnings) == 0 {
		t.Fatal("different dependencies entered same curve")
	}
}
