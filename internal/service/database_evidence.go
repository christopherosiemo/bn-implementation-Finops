package service

import (
	"context"
	"encoding/json"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/evidence"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
)

func databaseObject(v any) model.Document { return evidence.Object(v) }
func decodeDatabaseDocument(raw []byte) (model.Document, error) {
	var out model.Document
	e := json.Unmarshal(raw, &out)
	return out, e
}

// Acquisitions do not change configuration identity. Ownership and declared
// authority do, and neither a newer heartbeat nor row version renews old advice.
func DatabaseConfigurationHash(resource model.Document) string {
	native := model.Clone(databaseObject(resource["database_configuration"]))
	for _, key := range []string{"last_seen_at", "collected_at", "status", "latest_restorable_time", "percent_progress", "raw_page_sha256", "raw_ref"} {
		delete(native, key)
	}
	return evidence.Hash(model.Document{"resource_id": resource["id"], "provider_resource_id": resource["provider_resource_id"], "account_id": resource["account_id"], "region": resource["region"], "resource_type": resource["resource_type"], "workload_id": resource["workload_id"], "environment": resource["environment"], "configuration_authority": resource["configuration_authority"], "native": native})
}

func databaseBillingReferencesCurrent(ctx context.Context, t *store.Tx, refs []model.Document) (bool, error) {
	found := false
	for _, ref := range refs {
		if model.String(ref, "kind") != "AWS_CUR2_CONNECTION" {
			continue
		}
		found = true
		if e := holdTrustedSourceSnapshot(ctx, t, model.String(ref, "source_connection_id")); e != nil {
			return false, e
		}
		registration, e := t.SourceGet(ctx, model.String(ref, "source_connection_id"))
		if e != nil {
			return false, e
		}
		if model.String(registration, "status") != "HEALTHY" {
			return false, nil
		}
		start, e := time.Parse(time.RFC3339Nano, model.String(ref, "billing_period_start"))
		if e != nil {
			return false, nil
		}
		heads, e := periodReceipts(ctx, t, model.String(registration, "id"), start, start.AddDate(0, 1, 0))
		if e != nil {
			return false, e
		}
		matched := false
		for _, head := range heads {
			if model.String(head, "id") == model.String(ref, "source_receipt_id") && model.String(head, "ingestion_job_id") == model.String(ref, "ingestion_job_id") {
				matched = true
			}
		}
		if !matched {
			return false, nil
		}
		job, e := t.Get(ctx, "ingestion_jobs", model.String(ref, "ingestion_job_id"))
		if e != nil {
			return false, e
		}
		if model.String(job, "status") != "PERSISTED" || evidence.Hash(job["canonical"]) != model.String(ref, "canonical_hash") {
			return false, nil
		}
		accounts := model.Strings(registration, "usage_account_ids")
		if len(accounts) == 0 {
			return false, nil
		}
		validated, validateErr := trustedJob(ctx, t, job, model.Document{"account_id": accounts[0], "region": registration["region"]})
		if validateErr != nil || model.String(validated, "id") != model.String(ref, "source_receipt_id") {
			return false, nil
		}
	}
	return found, nil
}
