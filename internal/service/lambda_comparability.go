package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/evidence"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/lambdacost"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/jackc/pgx/v5"
)

var lambdaPublishedVersion = regexp.MustCompile(`^[1-9][0-9]{0,18}$`)
var lambdaNativeProofHash = regexp.MustCompile(`^[a-f0-9]{64}$`)

// A machine benchmark may select immutable evidence, but cannot certify native
// compatibility. Only this restricted analytical reader resolves the proof.
func (a *API) lambdaTrustedPerformance(ctx context.Context, t *store.Tx, r, canonical, performance model.Document, read databaseArchiveRead) (model.Document, []model.Document, []string, error) {
	current := storageObject(canonical["configuration"])
	fingerprint, currentReasons := lambdacost.NonMemoryFingerprint(current)
	accepted := []model.Document{}
	bindings := []model.Document{}
	reasons := []string{}
	if len(storageRows(performance["legacy_receipts"])) > 0 {
		reasons = append(reasons, "LAMBDA_LEGACY_BENCHMARK_NOT_AUTHORITATIVE_FOR_NEW_CURVES")
	}
	if len(currentReasons) > 0 {
		reasons = append(reasons, currentReasons...)
	}
	for _, point := range storageRows(performance["receipts"]) {
		if point["receipt_schema_version"] != "2" {
			reasons = append(reasons, "LAMBDA_NATIVE_BENCHMARK_V2_REQUIRED")
			continue
		}
		ref := storageObject(point["native_configuration_ref"])
		snapshot, e := t.LambdaEvidenceGet(ctx, model.String(ref, "snapshot_id"))
		if errors.Is(e, pgx.ErrNoRows) {
			reasons = append(reasons, "LAMBDA_BENCHMARK_NATIVE_REFERENCE_UNAVAILABLE")
			continue
		}
		if e != nil {
			return nil, nil, nil, e
		}
		if snapshot["resource_id"] != r["id"] || snapshot["account_id"] != r["account_id"] || snapshot["region"] != r["region"] || snapshot["content_hash"] != ref["content_hash"] || snapshot["config_hash"] != ref["config_hash"] {
			reasons = append(reasons, "LAMBDA_BENCHMARK_NATIVE_REFERENCE_BINDING_MISMATCH")
			continue
		}
		sourceID := model.String(snapshot, "source_id")
		if sourceID == "" {
			reasons = append(reasons, "LAMBDA_REGISTERED_NATIVE_CONFIGURATION_SOURCE_REQUIRED")
			continue
		}
		registration, e := t.SourceGet(ctx, sourceID)
		if errors.Is(e, pgx.ErrNoRows) {
			reasons = append(reasons, "LAMBDA_BENCHMARK_NATIVE_SOURCE_UNAVAILABLE")
			continue
		}
		if e != nil {
			return nil, nil, nil, e
		}
		if registration["kind"] != lambdacost.NativeKind || !model.Bool(registration, "enabled") || model.Bool(registration, "revoked") || model.Number(registration, "version") != model.Number(snapshot, "source_registration_version") || registration["account_id"] != r["account_id"] || registration["region"] != r["region"] || registration["function_arn"] != r["provider_resource_id"] {
			reasons = append(reasons, "LAMBDA_BENCHMARK_NATIVE_SOURCE_CHANGED_OR_REVOKED")
			continue
		}
		raw, e := read(ctx, t.Tenant, storageObject(snapshot["archive"]))
		if e != nil {
			if ctx.Err() != nil {
				return nil, nil, nil, ctx.Err()
			}
			reasons = append(reasons, "LAMBDA_BENCHMARK_NATIVE_ARCHIVE_UNAVAILABLE")
			continue
		}
		if lambdacost.BytesHash(raw) != model.String(snapshot, "content_hash") {
			reasons = append(reasons, "LAMBDA_BENCHMARK_NATIVE_ARCHIVE_HASH_MISMATCH")
			continue
		}
		native := storageObject(json.RawMessage(raw))
		cfg := storageObject(native["configuration"])
		if native["schema_version"] != "LAMBDA_NATIVE_V1" || native["resource_id"] != r["id"] || native["account_id"] != r["account_id"] || native["region"] != r["region"] || native["config_hash"] != snapshot["config_hash"] {
			reasons = append(reasons, "LAMBDA_BENCHMARK_NATIVE_CANONICAL_BINDING_MISMATCH")
			continue
		}
		pointReasons := lambdaPerformanceNativeConfigurationReasons(point, cfg, snapshot, storageBinding(t.Tenant, r), a.now())
		pointFingerprint, rs := lambdacost.NonMemoryFingerprint(cfg)
		pointReasons = append(pointReasons, rs...)
		compat := storageObject(point["non_memory_compatibility"])
		if compat["definition_version"] != lambdacost.NonMemoryConfigurationVersion || compat["sha256"] != pointFingerprint || pointFingerprint == "" || pointFingerprint != fingerprint || !lambdaNativeProofHash.MatchString(model.String(compat, "dependency_manifest_sha256")) {
			pointReasons = append(pointReasons, "LAMBDA_NON_MEMORY_CONFIGURATION_COMPARABILITY_UNPROVEN")
		}
		if len(pointReasons) > 0 {
			reasons = append(reasons, pointReasons...)
			continue
		}
		accepted = append(accepted, point)
		bindings = append(bindings, model.Document{"snapshot_id": snapshot["id"], "content_hash": snapshot["content_hash"], "config_hash": snapshot["config_hash"], "source_id": sourceID, "source_registration_version": snapshot["source_registration_version"], "configuration_epoch_hash": cfg["configuration_epoch_hash"], "native_non_memory_sha256": pointFingerprint})
	}
	accepted, bindings, selectionReasons := lambdaSelectNativePerformance(accepted, bindings, current)
	reasons = append(reasons, selectionReasons...)
	return model.Document{"receipts": accepted, "legacy_receipt_count": len(storageRows(performance["legacy_receipts"])), "authority_version": "2"}, bindings, databaseSortedReasons(reasons), nil
}

// The current measured point chooses the independently attested dependency
// manifest. Other manifests cannot share its numerical comparison curve.
func lambdaSelectNativePerformance(accepted, bindings []model.Document, current model.Document) ([]model.Document, []model.Document, []string) {
	reasons := []string{}
	manifest := ""
	currentCount := 0
	for _, point := range accepted {
		if fmt.Sprint(point["executed_version"]) == fmt.Sprint(current["version"]) && lambdaIntegerValue(point["memory_size_mb"]) == lambdaIntegerValue(current["memory_size_mb"]) {
			currentCount++
			manifest = model.String(storageObject(point["non_memory_compatibility"]), "dependency_manifest_sha256")
		}
	}
	if currentCount != 1 {
		accepted = []model.Document{}
		bindings = []model.Document{}
		reasons = append(reasons, "LAMBDA_EXACT_CURRENT_NATIVE_BENCHMARK_REQUIRED")
	} else {
		selected := []model.Document{}
		selectedBindings := []model.Document{}
		for n, point := range accepted {
			if model.String(storageObject(point["non_memory_compatibility"]), "dependency_manifest_sha256") != manifest {
				reasons = append(reasons, "LAMBDA_BENCHMARK_DEPENDENCY_MANIFEST_MISMATCH")
				continue
			}
			selected = append(selected, point)
			selectedBindings = append(selectedBindings, bindings[n])
		}
		accepted, bindings = selected, selectedBindings
	}
	return accepted, bindings, databaseSortedReasons(reasons)
}

// Rejected and legacy receipts stay explainable without making an unrelated
// immutable V1 receipt permanently veto an independently proved V2 curve.
func lambdaApplyPerformanceAuthority(result, raw, trusted model.Document, refs []model.Document, warnings []string) {
	result["performance_authority_version"] = "2"
	result["performance_native_references"] = refs
	result["performance_authority_warnings"] = databaseSortedReasons(warnings)
	result["performance_authority"] = model.Document{"version": "2", "accepted_receipt_count": len(storageRows(trusted["receipts"])), "legacy_receipt_count": len(storageRows(raw["legacy_receipts"])), "legacy_truncated": model.Bool(raw, "legacy_truncated"), "warning_codes": databaseSortedReasons(warnings)}
}

func lambdaPerformanceNativeConfigurationReasons(point, config, snapshot, binding model.Document, now time.Time) []string {
	reasons := []string{}
	version := model.String(point, "executed_version")
	expected := model.String(binding, "provider_resource_id") + ":" + version
	if !lambdaPublishedVersion.MatchString(version) || point["executed_target_arn"] != expected || config["version"] != version || config["base_function_arn"] != binding["provider_resource_id"] || evidence.Hash(point["binding"]) != evidence.Hash(binding) {
		reasons = append(reasons, "LAMBDA_BENCHMARK_EXECUTED_PUBLISHED_VERSION_MISMATCH")
	}
	if point["configuration_epoch_hash"] != config["configuration_epoch_hash"] || !lambdaNativeProofHash.MatchString(model.String(point, "configuration_epoch_hash")) || point["code_sha256"] != config["code_sha256"] || point["architecture"] != config["architecture"] || lambdaIntegerValue(point["memory_size_mb"]) != lambdaIntegerValue(config["memory_size_mb"]) {
		reasons = append(reasons, "LAMBDA_BENCHMARK_NATIVE_CONFIGURATION_EPOCH_MISMATCH")
	}
	start, e1 := time.Parse(time.RFC3339Nano, model.String(point, "measurement_start"))
	end, e2 := time.Parse(time.RFC3339Nano, model.String(point, "measurement_end"))
	observed, e3 := time.Parse(time.RFC3339Nano, model.String(snapshot, "observed_at"))
	received, e4 := time.Parse(time.RFC3339Nano, model.String(point, "received_at"))
	published, e5 := lambdaNativeModified(model.String(config, "last_modified"))
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || e5 != nil || !start.Before(end) || start.Before(observed) || published.After(start) || end.After(received) || received.After(now) || end.After(now) {
		reasons = append(reasons, "LAMBDA_NATIVE_CONFIGURATION_MUST_PRECEDE_BENCHMARK")
	}
	return databaseSortedReasons(reasons)
}
func lambdaNativeModified(value string) (time.Time, error) {
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05.000-0700", "2006-01-02T15:04:05-0700"} {
		if at, e := time.Parse(layout, value); e == nil {
			return at, nil
		}
	}
	return time.Time{}, errors.New("LAMBDA_NATIVE_MODIFIED_TIMESTAMP_INVALID")
}

func lambdaResultHasNumericalCurve(result model.Document) bool {
	for _, candidate := range storageRows(result["candidates"]) {
		economics := storageObject(candidate["economics"])
		if economics["estimated_window_saving"] != nil || economics["candidate_window_cost"] != nil {
			return true
		}
	}
	return false
}

func lambdaNativeComparabilityCurrent(ctx context.Context, t *store.Tx, result model.Document) ([]string, error) {
	reasons := []string{}
	if lambdaResultHasNumericalCurve(result) && result["performance_authority_version"] != "2" {
		reasons = append(reasons, "LAMBDA_NATIVE_BENCHMARK_V2_REQUIRED")
	}
	for _, ref := range storageRows(result["performance_native_references"]) {
		snapshot, e := t.LambdaEvidenceGet(ctx, model.String(ref, "snapshot_id"))
		if errors.Is(e, pgx.ErrNoRows) {
			reasons = append(reasons, "LAMBDA_BENCHMARK_NATIVE_REFERENCE_UNAVAILABLE")
			continue
		}
		if e != nil {
			return nil, e
		}
		if snapshot["content_hash"] != ref["content_hash"] || snapshot["config_hash"] != ref["config_hash"] || snapshot["source_id"] != ref["source_id"] {
			reasons = append(reasons, "LAMBDA_BENCHMARK_NATIVE_REFERENCE_CHANGED")
		}
		source, e := t.SourceGet(ctx, model.String(ref, "source_id"))
		if errors.Is(e, pgx.ErrNoRows) {
			reasons = append(reasons, "LAMBDA_BENCHMARK_NATIVE_SOURCE_CHANGED_OR_REVOKED")
			continue
		}
		if e != nil {
			return nil, e
		}
		if !model.Bool(source, "enabled") || model.Bool(source, "revoked") || model.Number(source, "version") != model.Number(ref, "source_registration_version") {
			reasons = append(reasons, "LAMBDA_BENCHMARK_NATIVE_SOURCE_CHANGED_OR_REVOKED")
		}
	}
	return databaseSortedReasons(reasons), nil
}
