package service

import (
	"encoding/json"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"net/http/httptest"
	"testing"
	"time"
)

func TestStorageNativeFractionalNumbersRemainDecimal(t *testing.T) {
	d := storageObject(model.Document{"clock": json.Number("1792450099.125"), "rows": []model.Document{{"value": json.Number("0.00125")}}})
	if v, ok := databaseDecimal(d["clock"]); !ok || v.FloatString(3) != "1792450099.125" {
		t.Fatal("native fractional recorder clock lost")
	}
	if v, ok := databaseDecimal(storageRows(d["rows"])[0]["value"]); !ok || v.FloatString(5) != "0.00125" {
		t.Fatal("native fractional metric lost")
	}
}

func TestStorageConfigurationSeparatesAcquisitionFromSnapshotDependencies(t *testing.T) {
	r := model.Document{"id": "snapshot", "storage_configuration": model.Document{"snapshot_dependencies": []model.Document{{"snapshot_id": "snap-one", "state": "enabled", "raw_page_sha256": "first-acquisition"}}}}
	before := StorageConfigurationHash(r)
	copy := storageObject(r)
	native := storageObject(copy["storage_configuration"])
	rows := storageRows(native["snapshot_dependencies"])
	rows[0]["raw_page_sha256"] = "new-acquisition"
	native["snapshot_dependencies"] = rows
	copy["storage_configuration"] = native
	if before != StorageConfigurationHash(copy) {
		t.Fatal("acquisition changed configuration authority")
	}
	rows[0]["state"] = "disabled"
	native["snapshot_dependencies"] = rows
	copy["storage_configuration"] = native
	if before == StorageConfigurationHash(copy) {
		t.Fatal("semantic dependency change kept old authority")
	}
}

func TestStoragePriorAttachmentsRemainRecordedScopedReviewFacts(t *testing.T) {
	now := time.Now().UTC()
	r := model.Document{"id": "volume", "tenant_id": "tenant", "account_id": "111122223333", "region": "eu-west-1", "provider_resource_id": "vol-0eb50000000000001"}
	c := storageInputTestCanonical(r, now.Add(-14*24*time.Hour).Truncate(24*time.Hour), now.Truncate(24*time.Hour))
	context, ref := storageRecordedPriorAttachments(c, r, now)
	if context == "" || model.String(ref, "kind") != "AWS_CONFIG_RECORDED_PRIOR_ATTACHMENTS" {
		t.Fatal("recorded prior attachment context missing")
	}
	r["tenant_id"] = "foreign"
	if context, ref = storageRecordedPriorAttachments(c, r, now); context != "" || ref != nil {
		t.Fatal("foreign prior context exposed")
	}
}

func TestStorageCursorCannotCrossTenantSubjectOrQuery(t *testing.T) {
	r := httptest.NewRequest("GET", "/v1/storage-assessments?resource_id=ebs-one&limit=1", nil)
	cursor := storageNextCursor(r, "tenant-a", "subject-a", "00000000-0000-4000-8000-000000000001").(string)
	for _, tc := range []struct {
		tenant, subject, path string
		valid                 bool
	}{{"tenant-a", "subject-a", "/v1/storage-assessments?resource_id=ebs-one&limit=10", true}, {"tenant-b", "subject-a", "/v1/storage-assessments?resource_id=ebs-one", false}, {"tenant-a", "subject-b", "/v1/storage-assessments?resource_id=ebs-one", false}, {"tenant-a", "subject-a", "/v1/storage-assessments?resource_id=ebs-two", false}} {
		q := httptest.NewRequest("GET", tc.path+"&cursor="+cursor, nil)
		_, _, e := storagePage(q, tc.tenant, tc.subject)
		if (e == nil) != tc.valid {
			t.Fatal("cursor isolation differs", tc, e)
		}
	}
}
func TestStorageDependencyAnalysisReviewExpiryAndBinding(t *testing.T) {
	now := time.Now().UTC()
	g := model.Document{"status": "DECLARED", "version": 2, "graph_hash": "graph", "inventory_hash": "inventory"}
	r := model.Document{"writer_role": "finops_api", "resource_id": "volume", "reviewed_by": "operator", "acknowledgement": "REVIEWED_DISCOVERED_AND_EXTERNAL_DEPENDENCIES", "reviewed_at": now.Add(-time.Hour).Format(time.RFC3339Nano), "expires_at": now.Add(time.Hour).Format(time.RFC3339Nano), "graph_version": 2, "graph_hash": "graph", "inventory_hash": "inventory", "status": "BLOCKED"}
	if !storageReviewCurrent(r, g, "volume", now) {
		t.Fatal("explicit current read-only review rejected")
	}
	if storageReviewCurrent(r, g, "other", now) || storageReviewCurrent(r, g, "volume", now.Add(2*time.Hour)) {
		t.Fatal("foreign or expired review accepted")
	}
	g["inventory_hash"] = "changed"
	if storageReviewCurrent(r, g, "volume", now) {
		t.Fatal("changed graph inventory accepted")
	}
}
