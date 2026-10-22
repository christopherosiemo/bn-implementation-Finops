package service

import (
	"context"
	"errors"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/objectstorage"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/jackc/pgx/v5"
	"time"
)

func objectStorageModelRef(value any) model.Document {
	d := storageObject(value)
	if model.String(d, "kind") == "" || model.String(d, "id") == "" || model.String(d, "version") == "" || len(model.String(d, "sha256")) != 64 {
		return nil
	}
	return storageRef(model.String(d, "kind"), model.String(d, "id"), model.String(d, "version"), model.String(d, "sha256"))
}
func objectStorageModelRefs(value any) []model.Document {
	out := []model.Document{}
	for _, d := range storageRows(value) {
		if r := objectStorageModelRef(d); r != nil {
			out = append(out, r)
		}
	}
	return out
}
func objectStorageProjectCohorts(canonical, dataset, configuration model.Document) ([]model.Document, []string) {
	out := []model.Document{}
	reasons := []string{}
	did := model.String(dataset, "id")
	policy := storageObject(dataset["policy"])
	access := storageObject(canonical["access"])
	matchedDataset := dataset == nil
	for _, binding := range storageRows(canonical["dataset_bindings"]) {
		if model.String(binding, "id") == did && model.Number(binding, "dataset_version") == model.Number(dataset, "version") && model.String(binding, "dataset_hash") == objectStorageDatasetHash(dataset) {
			matchedDataset = true
		}
	}
	if !matchedDataset {
		reasons = append(reasons, "OBJECT_STORAGE_DATASET_EVIDENCE_REVISION_MISMATCH")
	}
	for _, raw := range storageRows(canonical["cohorts"]) {
		if did != "" && model.String(raw, "dataset_id") != did && model.String(raw, "id") != did {
			continue
		}
		c := model.Document{}
		for _, k := range []string{"id", "label", "source_class", "access_tier", "state", "object_count", "total_bytes", "size_bands", "age_days_min", "age_days_max", "minimum_duration_remaining_days", "inventory_complete", "population_hash", "source_ref", "access", "lifecycle", "retention"} {
			c[k] = raw[k]
		}
		c["source_ref"] = objectStorageModelRef(raw["source_ref"])
		nativeAccess := storageObject(raw["access"])
		for _, candidate := range append([]model.Document{access}, storageRows(access["datasets"])...) {
			if model.String(candidate, "source_type") == objectstorage.AppAccessReportType && candidate["requires_inventory_population_match"] == true && candidate["request_accounting_complete"] == true && candidate["complete"] == true && model.String(candidate, "dataset_id") == did && model.Number(candidate, "dataset_version") == model.Number(dataset, "version") && model.String(candidate, "population_sha256") == model.String(c, "population_hash") {
				nativeAccess = candidate
				break
			}
		}
		projectedAccess := model.Document{}
		for _, k := range []string{"state", "start", "end", "complete", "requests", "retrieved_bytes", "eligible_cold_bytes_fraction", "it_tier_fractions"} {
			projectedAccess[k] = nativeAccess[k]
		}
		projectedAccess["source_ref"] = objectStorageModelRef(nativeAccess["source_ref"])
		if projectedAccess["source_ref"] == nil && model.String(nativeAccess, "source_type") == objectstorage.AppAccessReportType {
			for _, ref := range objectStorageModelRefs(canonical["source_refs"]) {
				if model.String(ref, "kind") == "AWS_S3_APP_ACCESS" {
					projectedAccess["source_ref"] = ref
					break
				}
			}
		}
		c["access"] = projectedAccess
		retention := storageObject(c["retention"])
		if model.String(configuration, "object_lock_state") == "DISABLED" {
			retention["legal_hold"], retention["retained"] = false, false
		}
		if model.String(configuration, "replication_state") == "NONE" {
			retention["replication_pending"] = false
		}
		retention["dependencies_known"] = policy["dependencies_reviewed"] == true
		retention["known"] = policy["retention_known"] == true && retention["legal_hold"] != nil && retention["retained"] != nil && retention["replication_pending"] != nil
		c["retention"] = retention
		c["lifecycle"] = objectStorageLifecycle(canonical, dataset, c)
		if c["object_count"] == nil || c["total_bytes"] == nil || c["age_days_min"] == nil || c["age_days_max"] == nil || len(storageRows(c["size_bands"])) == 0 {
			reasons = append(reasons, "OBJECT_STORAGE_REQUIRED_POPULATION_FIELDS_UNKNOWN")
			continue
		}
		out = append(out, c)
	}
	return out, databaseSortedReasons(reasons)
}
func objectStorageBindingsCurrent(ctx context.Context, t *store.Tx, bindings []model.Document, now time.Time) ([]string, error) {
	reasons := []string{}
	if len(bindings) == 0 || len(bindings) > 512 {
		return []string{"OBJECT_STORAGE_SOURCE_BINDINGS_REQUIRED"}, nil
	}
	for _, binding := range bindings {
		source, e := t.SourceGet(ctx, model.String(binding, "source_id"))
		if errors.Is(e, pgx.ErrNoRows) {
			reasons = append(reasons, "OBJECT_STORAGE_SOURCE_CHANGED_OR_REVOKED")
			continue
		}
		if e != nil {
			return nil, e
		}
		parsed, e := objectstorage.ParseRegistration(source)
		if e != nil || !parsed.Enabled || model.String(source, "status") != "HEALTHY" || model.Number(source, "version") != model.Number(binding, "registration_version") || objectstorage.Hash(parsed) != model.String(binding, "config_hash") {
			reasons = append(reasons, "OBJECT_STORAGE_SOURCE_CHANGED_OR_REVOKED")
			continue
		}
		receipt, e := t.SourceReceiptGet(ctx, model.String(source, "latest_receipt_id"))
		if errors.Is(e, pgx.ErrNoRows) {
			reasons = append(reasons, "OBJECT_STORAGE_SOURCE_RECEIPT_NO_LONGER_CURRENT")
			continue
		}
		if e != nil {
			return nil, e
		}
		if model.String(receipt, "source_version") != model.String(binding, "source_version") || model.String(receipt, "writer_role") != "finops_ingester" || model.String(receipt, "config_hash") != objectstorage.Hash(parsed) || model.Number(receipt, "registration_version") != parsed.Version {
			reasons = append(reasons, "OBJECT_STORAGE_SOURCE_RECEIPT_NO_LONGER_CURRENT")
		}
		at, e := time.Parse(time.RFC3339Nano, model.String(source, "last_sync_at"))
		if e != nil || at.After(now.Add(time.Minute)) || now.Sub(at) > time.Hour {
			reasons = append(reasons, "OBJECT_STORAGE_SOURCE_INSPECTION_STALE")
		}
	}
	return databaseSortedReasons(reasons), nil
}
