package workflow

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/native"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/provider"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/service"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/telemetry"
	"github.com/jackc/pgx/v5"
	"sort"
	"strings"
	"time"
)

func blockStorageSnapshotDependencies(id string, inventory provider.EBSSnapshot) model.Document {
	selectRows := func(rows []model.Document, key string) any {
		if rows == nil {
			return nil
		}
		out := []model.Document{}
		for _, d := range rows {
			if model.String(d, key) == id {
				out = append(out, model.Clone(d))
			}
		}
		return out
	}
	var images any
	if inventory.OwnedImages != nil {
		rows := []model.Document{}
		for _, image := range inventory.OwnedImages {
			maps, _ := image["block_device_mappings"].([]model.Document)
			for _, m := range maps {
				if model.String(m, "snapshot_id") == id {
					rows = append(rows, model.Clone(image))
					break
				}
			}
		}
		images = rows
	}
	permissions := selectRows(inventory.SnapshotPermissions, "snapshot_id")
	for _, c := range inventory.Coverage {
		if model.String(c, "component") == "snapshot_permissions" && (model.String(c, "snapshot_id") == id || model.String(c, "snapshot_id") == "") && strings.HasPrefix(model.String(c, "status"), "UNAVAILABLE") {
			permissions = nil
		}
	}
	return model.Document{"basis": "NATIVE_ACCOUNT_REGION_POINT_READ_NOT_RETENTION_AUTHORITY", "owned_ami_references": images, "create_volume_permissions": permissions, "fast_snapshot_restores": selectRows(inventory.FastSnapshotRestores, "snapshot_id"), "tier_status": selectRows(inventory.SnapshotTierStatuses, "snapshot_id"), "locks": selectRows(inventory.LockedSnapshots, "snapshot_id"), "coverage": inventory.Coverage, "external_backup_retention_iac": "UNKNOWN_REQUIRES_INDEPENDENT_AUTHORITY", "delete_authorized": false}
}
func blockStorageAMIReferences(ctx context.Context, t *store.Tx, inventory provider.EBSSnapshot, account model.Document, resources map[string]model.Document) error {
	for _, image := range inventory.OwnedImages {
		relevant := false
		maps, _ := image["block_device_mappings"].([]model.Document)
		for _, m := range maps {
			if resources[model.String(m, "snapshot_id")] != nil {
				relevant = true
			}
		}
		if !relevant {
			continue
		}
		row := model.Clone(image)
		row["provider"] = "AWS"
		row["resource_type"] = "AMI_REFERENCE"
		row["provider_resource_id"] = image["image_id"]
		current, e := blockStorageUpsert(ctx, t, row, account)
		if e != nil {
			return e
		}
		resources[model.String(image, "image_id")] = current
	}
	return nil
}
func blockStorageConfigurationHistories(ctx context.Context, storage databaseArchive, tenant string, reader provider.EBSHistoryReader, scope provider.EBSScope, metrics provider.EBSMetricEvidence, start, end time.Time) ([]model.Document, []model.Document, error) {
	targets := []struct{ kind, id string }{{"AWS::EC2::Volume", metrics.Selection.VolumeID}}
	for _, instance := range metrics.Instances {
		targets = append(targets, struct{ kind, id string }{"AWS::EC2::Instance", model.String(instance, "instance_id")})
	}
	if len(targets) > 17 {
		return nil, nil, errors.New("EBS_HISTORY_ATTACHMENT_BOUND")
	}
	refs := []model.Document{}
	rows := []model.Document{}
	for _, target := range targets {
		history, e := reader.EBSConfigurationHistory(ctx, scope, target.kind, target.id, start, end)
		if e != nil {
			rows = append(rows, model.Document{"resource_type": target.kind, "resource_id": target.id, "status": "HISTORY_UNAVAILABLE", "reason_codes": []string{"NATIVE_CONFIG_READ_OR_SCOPE_UNAVAILABLE"}})
			continue
		}
		if history.Scope != scope || history.ResourceType != target.kind || history.ResourceID != target.id || !history.Start.Equal(start) || !history.End.Equal(end) {
			return nil, nil, errors.New("EBS_HISTORY_SCOPE_DIFFERS")
		}
		ref, e := blockStorageRaw(ctx, storage, tenant, history.EBSReadEvidence)
		if e != nil {
			return nil, nil, e
		}
		refs = append(refs, ref)
		row, e := databaseDocument(history)
		if e != nil {
			return nil, nil, e
		}
		row["raw_ref"] = ref
		rows = append(rows, row)
	}
	return refs, rows, nil
}

func blockStorageQuality(ctx context.Context, t *store.Tx, id, status, reason string) error {
	d, e := t.Get(ctx, "data_quality", id)
	if e == nil {
		d["status"] = status
		d["reason_codes"] = []string{reason}
		d["observed_at"] = model.Now()
		_, e = t.Update(ctx, "data_quality", id, model.Number(d, "version"), d)
		return e
	}
	if e != pgx.ErrNoRows {
		return e
	}
	_, e = t.Create(ctx, "data_quality", model.Document{"id": id, "name": "Native AWS EBS evidence", "status": status, "reason_codes": []string{reason}, "message": "Read-only EBS evidence; absent metrics, historical ownership, retention and backup dependencies remain unknown.", "observed_at": model.Now()})
	return e
}
func blockStorageRaw(ctx context.Context, storage databaseArchive, tenant string, evidence provider.EBSReadEvidence) (model.Document, error) {
	if evidence.Scope.TenantID != tenant || evidence.RawSHA256 != telemetry.BytesHash(evidence.Raw) {
		return nil, errors.New("EBS_RAW_SCOPE_OR_HASH_DIFFERS")
	}
	if _, e := provider.EBSCaptureFrames(evidence.Raw); e != nil {
		return nil, e
	}
	return databaseArchiveReadback(ctx, storage, tenant, "wire", "ebs-"+evidence.RawSHA256, evidence.Raw)
}
func blockStorageUpsert(ctx context.Context, t *store.Tx, row, account model.Document) (model.Document, error) {
	var id string
	e := t.QueryRow(ctx, "SELECT id FROM entities WHERE tenant_id=$1 AND kind='resources' AND document->>'provider'='AWS' AND document->>'account_id'=$2 AND document->>'region'=$3 AND document->>'provider_resource_id'=$4", t.Tenant, row["account_id"], row["region"], row["provider_resource_id"]).Scan(&id)
	out := model.Document{}
	version := int64(0)
	if e == nil {
		old, e := t.Get(ctx, "resources", id)
		if e != nil {
			return nil, e
		}
		out = model.Clone(old)
		version = model.Number(old, "version")
	} else if e == pgx.ErrNoRows {
		id = model.ID()
		out = model.Document{"id": id, "configuration_authority": "UNKNOWN", "eligibility": "OBSERVE_ONLY", "environment": "UNKNOWN"}
	} else {
		return nil, e
	}
	out["provider"] = "AWS"
	out["resource_type"] = row["resource_type"]
	out["provider_resource_id"] = row["provider_resource_id"]
	out["account_id"] = row["account_id"]
	out["region"] = row["region"]
	out["cloud_account_id"] = account["id"]
	out["storage_configuration"] = model.Clone(row)
	out["state"] = row["state"]
	out["last_seen_at"] = model.Now()
	if model.String(out, "name") == "" {
		out["name"] = row["provider_resource_id"]
	}
	if version == 0 {
		return t.Create(ctx, "resources", out)
	}
	return t.Update(ctx, "resources", id, version, out)
}
func blockStorageRelationships(ctx context.Context, t *store.Tx, resource model.Document, inventory provider.EBSSnapshot, resources map[string]model.Document) ([]model.Document, error) {
	out := []model.Document{}
	scope := inventory.Scope
	put := func(kind, id string) error {
		if id == "" {
			return nil
		}
		target := resources[id]
		if target == nil {
			var targetID string
			e := t.QueryRow(ctx, "SELECT id FROM entities WHERE tenant_id=$1 AND kind='resources' AND document->>'provider'='AWS' AND document->>'account_id'=$2 AND document->>'region'=$3 AND document->>'provider_resource_id'=$4", t.Tenant, scope.AccountID, scope.Region, id).Scan(&targetID)
			if e == pgx.ErrNoRows {
				return nil
			}
			if e != nil {
				return e
			}
			target = model.Document{"id": targetID}
		}
		out = append(out, model.Document{"type": kind, "target_resource_id": target["id"], "target_provider_resource_id": id, "basis": "NATIVE_EBS_POINT_RELATIONSHIP"})
		return nil
	}
	nativeRow, _ := databaseDocument(resource["storage_configuration"])
	if model.String(resource, "resource_type") == "EBS_VOLUME" {
		attachments, _ := nativeRow["attachments"].([]any)
		for _, a := range attachments {
			d, _ := databaseDocument(a)
			if e := put("ATTACHED_TO", model.String(d, "instance_id")); e != nil {
				return nil, e
			}
		}
	} else {
		if e := put("BACKED_BY", model.String(nativeRow, "volume_id")); e != nil {
			return nil, e
		}
		for _, image := range inventory.OwnedImages {
			maps, _ := image["block_device_mappings"].([]model.Document)
			for _, m := range maps {
				if model.String(m, "snapshot_id") == model.String(resource, "provider_resource_id") {
					if e := put("DEPENDS_ON", model.String(image, "image_id")); e != nil {
						return nil, e
					}
				}
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return model.String(out[i], "type")+model.String(out[i], "target_provider_resource_id") < model.String(out[j], "type")+model.String(out[j], "target_provider_resource_id")
	})
	return out, nil
}

// discoverBlockStorageAccount is called with the ordinary registered customer
// read role. Its savepoints cannot roll back EC2/RDS discovery on an EBS failure.
func discoverBlockStorageAccount(ctx context.Context, a *Activities, t *store.Tx, client provider.EBSReader, account model.Document) error {
	scope := provider.EBSScope{TenantID: t.Tenant, AccountID: model.String(account, "account_id"), Region: model.String(account, "region")}
	if service.ValidateAWSTenant(t.Tenant) != nil {
		return nil
	}
	quality := "quality-ebs-" + scope.AccountID + "-" + scope.Region
	inventory, e := client.EBSDiscover(ctx, scope)
	if e != nil {
		return blockStorageQuality(ctx, t, quality, "DEGRADED", "EBS_SCOPE_COLLECTION_UNAVAILABLE")
	}
	if inventory.Scope != scope {
		return blockStorageQuality(ctx, t, quality, "DEGRADED", "EBS_NATIVE_SCOPE_DIFFERS")
	}
	rows := append(append([]model.Document{}, inventory.Volumes...), inventory.Snapshots...)
	resources := map[string]model.Document{}
	for _, row := range rows {
		if model.String(row, "resource_type") == "EBS_SNAPSHOT" {
			row = model.Clone(row)
			row["snapshot_dependencies"] = blockStorageSnapshotDependencies(model.String(row, "snapshot_id"), inventory)
		}
		current, e := blockStorageUpsert(ctx, t, row, account)
		if e != nil {
			return e
		}
		resources[model.String(row, "provider_resource_id")] = current
	}
	if e = blockStorageAMIReferences(ctx, t, inventory, account, resources); e != nil {
		return e
	}
	for id, row := range resources {
		relations, e := blockStorageRelationships(ctx, t, row, inventory, resources)
		if e != nil {
			return e
		}
		row["provider_relationships"] = relations
		current, e := t.Update(ctx, "resources", model.String(row, "id"), model.Number(row, "version"), row)
		if e != nil {
			return e
		}
		resources[id] = current
	}
	if len(rows) == 0 {
		for _, c := range inventory.Coverage {
			if strings.HasPrefix(model.String(c, "status"), "UNAVAILABLE") {
				return blockStorageQuality(ctx, t, quality, "DEGRADED", "EBS_EMPTY_VOLUME_SCOPE_SNAPSHOT_DEPENDENCIES_UNAVAILABLE")
			}
		}
		return blockStorageQuality(ctx, t, quality, "HEALTHY", "EBS_EMPTY_NATIVE_VOLUME_SCOPE_OBSERVED_SNAPSHOT_COVERAGE_SEPARATE")
	}
	storage, e := native.StorageFromEnvironment(ctx, a.Config.Fixture)
	if e != nil {
		return blockStorageQuality(ctx, t, quality, "DEGRADED", "EBS_IMMUTABLE_STORAGE_UNAVAILABLE")
	}
	rawRef, e := blockStorageRaw(ctx, storage, t.Tenant, inventory.EBSReadEvidence)
	if e != nil {
		return blockStorageQuality(ctx, t, quality, "DEGRADED", "EBS_DISCOVERY_ARCHIVE_UNAVAILABLE")
	}
	asset := provider.EBSCapabilityAsset()
	assetRef, e := databaseArchiveReadback(ctx, storage, t.Tenant, "wire", "ebs-capabilities-"+telemetry.BytesHash(asset), asset)
	if e != nil {
		return blockStorageQuality(ctx, t, quality, "DEGRADED", "EBS_CAPABILITY_ARCHIVE_UNAVAILABLE")
	}
	ids := []string{}
	for id, row := range resources {
		if model.String(row, "resource_type") == "EBS_VOLUME" || model.String(row, "resource_type") == "EBS_SNAPSHOT" {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	failures := 0
	for _, id := range ids {
		resource := resources[id]
		latest, err := t.StorageEvidenceLatest(ctx, model.String(resource, "id"))
		if err != nil && err != pgx.ErrNoRows {
			return err
		}
		if latest != nil && model.String(latest, "config_hash") == service.StorageConfigurationHash(resource) {
			at, _ := time.Parse(time.RFC3339Nano, model.String(latest, "observed_at"))
			if at.After(time.Now().UTC().Add(-10 * time.Minute)) {
				continue
			}
		}
		if _, err = t.Exec(ctx, "SAVEPOINT ebs_resource_capture"); err != nil {
			return err
		}
		err = collectBlockStorageResource(ctx, t, client, storage, resource, inventory, rawRef, assetRef)
		if err != nil {
			failures++
			if _, err = t.Exec(ctx, "ROLLBACK TO SAVEPOINT ebs_resource_capture"); err != nil {
				return err
			}
		}
		if _, err = t.Exec(ctx, "RELEASE SAVEPOINT ebs_resource_capture"); err != nil {
			return err
		}
	}
	for _, c := range inventory.Coverage {
		if strings.HasPrefix(model.String(c, "status"), "UNAVAILABLE") {
			failures++
		}
	}
	if failures > 0 {
		return blockStorageQuality(ctx, t, quality, "DEGRADED", "EBS_RESOURCE_EVIDENCE_UNAVAILABLE")
	}
	return blockStorageQuality(ctx, t, quality, "HEALTHY", "NATIVE_EBS_CAPTURED_NO_EXECUTION_OR_DELETE_AUTHORITY")
}
func blockStorageMetricBatches(resource model.Document, metrics provider.EBSMetricEvidence) ([]telemetry.Batch, error) {
	if len(metrics.Metrics) > 250000 {
		return nil, errors.New("EBS_SAMPLE_BOUND")
	}
	binding := telemetry.Binding{TenantID: metrics.Scope.TenantID, ResourceID: model.String(resource, "id"), WorkloadID: model.String(resource, "workload_id"), Provider: "AWS", ProviderResourceID: metrics.Selection.VolumeID, AccountID: metrics.Scope.AccountID, Region: metrics.Scope.Region}
	if binding.ResourceID == "" || model.String(resource, "provider_resource_id") != binding.ProviderResourceID || model.String(resource, "account_id") != binding.AccountID || model.String(resource, "region") != binding.Region {
		return nil, errors.New("EBS_FACT_SCOPE_DIFFERS")
	}
	allowed := map[string]bool{binding.ProviderResourceID: true}
	for _, i := range metrics.Instances {
		allowed[model.String(i, "instance_id")] = true
	}
	samples := []telemetry.Sample{}
	for _, row := range metrics.Metrics {
		at, e := time.Parse(time.RFC3339Nano, model.String(row, "source_time"))
		nativeID := model.String(row, "provider_resource_id")
		if e != nil || at.Before(metrics.Selection.Start) || !at.Before(metrics.Selection.End) || !allowed[nativeID] || model.String(row, "account_id") != binding.AccountID || model.String(row, "region") != binding.Region || model.Number(row, "period_seconds") != int64(metrics.Selection.PeriodSeconds) {
			return nil, errors.New("EBS_FACT_NATIVE_BINDING_DIFFERS")
		}
		id := telemetry.Hash(model.Document{"native_id": nativeID, "metric": row["metric"], "time": row["source_time"], "statistic": row["statistic"], "raw_sha256": metrics.RawSHA256})
		samples = append(samples, telemetry.Sample{ID: id, DefinitionID: model.String(row, "namespace") + ":" + model.String(row, "metric"), StreamID: nativeID, Metric: model.String(row, "metric"), Type: "gauge", Unit: model.String(row, "unit"), Statistic: model.String(row, "statistic"), Temporality: "OBSERVED_PERIOD_STATISTIC", StartTime: at, Time: at, Attributes: map[string]string{}, ResourceAttributes: map[string]string{"provider_resource_id": nativeID, "selected_volume_id": binding.ProviderResourceID}, ScopeAttributes: map[string]string{"namespace": model.String(row, "namespace")}, OriginalAttributes: model.Clone(row), Value: model.String(row, "value"), RawSHA256: metrics.RawSHA256, SourceHashes: []string{model.String(row, "raw_page_sha256")}, ReasonCodes: []string{}})
	}
	batches := []telemetry.Batch{}
	for first := 0; first < len(samples); first += 5000 {
		batches = append(batches, telemetry.Batch{SchemaVersion: "1", ConnectionID: "ebs-cloudwatch-" + binding.ResourceID, ConfigHash: service.StorageConfigurationHash(resource), Binding: binding, SourceKind: "EBS_CLOUDWATCH", RawSHA256: metrics.RawSHA256, CollectedAt: metrics.CollectedAt, Start: metrics.Selection.Start, End: metrics.Selection.End, Samples: samples[first:min(first+5000, len(samples))], Rejections: []telemetry.Rejection{}, Warnings: []string{}})
	}
	return batches, nil
}
func collectBlockStorageResource(ctx context.Context, t *store.Tx, client provider.EBSReader, storage databaseArchive, resource model.Document, inventory provider.EBSSnapshot, inventoryRef, assetRef model.Document) error {
	profile := model.Document{}
	if workload := model.String(resource, "workload_id"); workload != "" {
		p, e := t.WorkloadSafetyLatest(ctx, workload)
		if e != nil && e != pgx.ErrNoRows {
			return e
		}
		if p != nil {
			profile = p
		}
	}
	start, end, reasons := databasePeriod(profile, time.Now().UTC())
	inventoryDoc, e := databaseDocument(inventory)
	if e != nil {
		return e
	}
	inventoryDoc["raw_ref"] = inventoryRef
	caps := provider.EBSCapabilities()
	caps["asset_ref"] = assetRef
	object := model.Document{"schema_version": "1", "resource": resource, "inventory": inventoryDoc, "metrics": []model.Document{}, "capabilities": caps, "period": model.Document{"start": start, "end": end}, "collection_reason_codes": reasons, "configuration_history": []model.Document{}}
	refs := []model.Document{inventoryRef, assetRef}
	observed := inventory.CollectedAt
	if model.String(resource, "resource_type") == "EBS_VOLUME" {
		period := 3600
		metrics, e := client.EBSMetrics(ctx, inventory.Scope, provider.EBSMetricSelection{VolumeID: model.String(resource, "provider_resource_id"), Start: start, End: end, PeriodSeconds: period})
		if e != nil {
			return e
		}
		if metrics.Scope != inventory.Scope || model.String(metrics.Volume, "volume_id") != model.String(resource, "provider_resource_id") {
			return errors.New("EBS_METRIC_SCOPE_DIFFERS")
		}
		before := model.Clone(metrics.Volume)
		delete(before, "raw_page_sha256")
		nativeRow, _ := databaseDocument(resource["storage_configuration"])
		delete(nativeRow, "raw_page_sha256")
		if telemetry.Hash(before) != telemetry.Hash(nativeRow) {
			return errors.New("EBS_NATIVE_CHANGED_DURING_COLLECTION")
		}
		ref, e := blockStorageRaw(ctx, storage, t.Tenant, metrics.EBSReadEvidence)
		if e != nil {
			return e
		}
		refs = append(refs, ref)
		d, e := databaseDocument(metrics)
		if e != nil {
			return e
		}
		d["raw_ref"] = ref
		object["metrics"] = []model.Document{d}
		if metrics.CollectedAt.After(observed) {
			observed = metrics.CollectedAt
		}
		if reader, ok := client.(provider.EBSHistoryReader); ok {
			historyRefs, historyRows, err := blockStorageConfigurationHistories(ctx, storage, t.Tenant, reader, inventory.Scope, metrics, start, end)
			if err != nil {
				return err
			}
			refs = append(refs, historyRefs...)
			object["configuration_history"] = historyRows
			for _, h := range historyRows {
				at, _ := time.Parse(time.RFC3339Nano, model.String(h, "collected_at"))
				if at.After(observed) {
					observed = at
				}
			}
		} else {
			object["configuration_history_status"] = "HISTORY_UNAVAILABLE_READER_NOT_COMMISSIONED"
		}
		batches, e := blockStorageMetricBatches(resource, metrics)
		if e != nil {
			return e
		}
		for i, batch := range batches {
			id := "ebs-" + telemetry.Hash(model.Document{"resource": resource["id"], "raw_sha256": metrics.RawSHA256, "chunk": i})
			ack, e := storage.WriteFacts(ctx, t.Tenant, id, batch)
			if e != nil {
				return e
			}
			if model.Number(ack, "sample_count") != int64(len(batch.Samples)) || model.String(ack, "canonical_hash") != telemetry.CanonicalHash(batch) {
				return errors.New("EBS_FACT_ACK_DIFFERS")
			}
		}
	}
	if observed.IsZero() || observed.After(time.Now().UTC()) {
		return errors.New("EBS_OBSERVED_AT_INVALID")
	}
	object["observed_at"] = observed
	raw, e := json.Marshal(object)
	if e != nil || len(raw) > 128<<20 {
		return errors.New("EBS_CANONICAL_BOUND")
	}
	ref, e := databaseArchiveReadback(ctx, storage, t.Tenant, "canonical", "ebs-"+telemetry.BytesHash(raw), raw)
	if e != nil {
		return e
	}
	_, e = t.StorageEvidenceAppend(ctx, model.Document{"id": model.ID(), "schema_version": "1", "resource_id": resource["id"], "account_id": inventory.Scope.AccountID, "region": inventory.Scope.Region, "config_hash": service.StorageConfigurationHash(resource), "content_hash": ref["body_sha256"], "archive": ref, "source_refs": refs, "observed_at": observed, "period": model.Document{"start": start, "end": end}})
	return e
}
