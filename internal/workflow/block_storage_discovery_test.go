package workflow

import (
	"context"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/provider"
	"testing"
	"time"
)

func TestBlockStorageFactsPreserveNativePeriodAndScope(t *testing.T) {
	at := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	scope := provider.EBSScope{TenantID: "tenant-ebs", AccountID: "111122223333", Region: "eu-west-1"}
	resource := model.Document{"id": "resource-ebs", "provider_resource_id": "vol-0123456789abcdef0", "account_id": scope.AccountID, "region": scope.Region, "resource_type": "EBS_VOLUME", "storage_configuration": model.Document{}}
	m := provider.EBSMetricEvidence{EBSReadEvidence: provider.EBSReadEvidence{Scope: scope, RawSHA256: "native-hash", CollectedAt: at.Add(time.Hour)}, Selection: provider.EBSMetricSelection{VolumeID: model.String(resource, "provider_resource_id"), Start: at, End: at.Add(time.Hour), PeriodSeconds: 300}, Metrics: []model.Document{{"metric": "VolumeReadOps", "value": "0", "namespace": "AWS/EBS", "unit": "Count", "statistic": "Sum", "source_time": at.Format(time.RFC3339Nano), "period_seconds": 300, "native_cadence_seconds": 60, "sample_count": nil, "provider_resource_id": resource["provider_resource_id"], "account_id": scope.AccountID, "region": scope.Region, "raw_page_sha256": "page-hash"}}}
	batches, e := blockStorageMetricBatches(resource, m)
	if e != nil || len(batches) != 1 {
		t.Fatal(e)
	}
	sample := batches[0].Samples[0]
	if sample.Value != "0" || sample.OriginalAttributes["sample_count"] != nil || model.Number(sample.OriginalAttributes, "native_cadence_seconds") != 60 || sample.Temporality != "OBSERVED_PERIOD_STATISTIC" {
		t.Fatal("native missing and observed zero conflated")
	}
	m.Metrics[0]["provider_resource_id"] = "vol-fffffffffffffffff"
	if _, e = blockStorageMetricBatches(resource, m); e == nil {
		t.Fatal("foreign sample accepted")
	}
}
func TestBlockStorageSnapshotDependenciesRemainUnknownWithoutReads(t *testing.T) {
	inventory := provider.EBSSnapshot{}
	d := blockStorageSnapshotDependencies("snap-0123456789abcdef0", inventory)
	if d["owned_ami_references"] != nil || d["create_volume_permissions"] != nil || d["delete_authorized"] != false {
		t.Fatal("missing dependencies promoted to empty or deletion")
	}
	inventory.OwnedImages = []model.Document{{"image_id": "ami-0123456789abcdef0", "block_device_mappings": []model.Document{{"snapshot_id": "snap-0123456789abcdef0"}}}}
	inventory.SnapshotPermissions = []model.Document{}
	d = blockStorageSnapshotDependencies("snap-0123456789abcdef0", inventory)
	if len(d["owned_ami_references"].([]model.Document)) != 1 || d["create_volume_permissions"] == nil || d["external_backup_retention_iac"] != "UNKNOWN_REQUIRES_INDEPENDENT_AUTHORITY" {
		t.Fatal("native dependency context lost")
	}
}
func TestBlockStorageRawScopeHashAndFramesRequired(t *testing.T) {
	e := provider.EBSReadEvidence{Scope: provider.EBSScope{TenantID: "foreign"}}
	if _, err := blockStorageRaw(context.Background(), nil, "tenant-ebs", e); err == nil {
		t.Fatal("foreign raw accepted")
	}
	e.Scope.TenantID = "tenant-ebs"
	if _, err := blockStorageRaw(context.Background(), nil, "tenant-ebs", e); err == nil {
		t.Fatal("unframed raw accepted")
	}
}
