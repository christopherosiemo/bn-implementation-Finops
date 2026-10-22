package objectstorage

import (
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
)

// CanonicalSnapshot binds server-issued selectors, native populations and the
// bucket configuration independently from policy/pricing projections.
func CanonicalSnapshot(resourceID string, b Bucket, r Registration, g Generation, bucketSourceRef model.Document) model.Document {
	refs := append([]model.Document{}, g.SourceRefs...)
	cohorts := append([]model.Document{}, g.Cohorts...)
	if len(bucketSourceRef) > 0 {
		refs = append(refs, bucketSourceRef)
		multipart := MultipartCohorts(b, b.ObservedAt, bucketSourceRef)
		for _, d := range r.Datasets {
			if d.Kind == "BUCKET" && d.Prefix == "" && len(d.Tags) == 0 {
				for _, c := range multipart {
					c["dataset_id"] = d.ID
					c["dataset_version"] = d.DatasetVersion
					c["dataset_hash"] = d.DatasetHash
				}
				break
			}
		}
		cohorts = append(cohorts, multipart...)
	}
	bindings := []model.Document{}
	for _, d := range r.Datasets {
		bindings = append(bindings, model.Document{"id": d.ID, "dataset_id": d.ID, "dataset_version": d.DatasetVersion, "dataset_hash": d.DatasetHash, "kind": d.Kind, "prefix": d.Prefix, "tags": d.Tags, "storage_classes": d.StorageClasses, "workload_id": d.WorkloadID})
	}
	return model.Document{"schema_version": "1", "resource_id": resourceID, "account_id": r.AccountID, "region": r.Region, "config_hash": ConfigurationHash(b), "source_id": r.ID, "source_registration_version": r.Version, "source_version": g.SourceVersion, "observed_at": g.ObservedAt, "configuration": b, "inventory": g.Inventory, "cohorts": cohorts, "access": g.Access, "source_refs": refs, "dataset_bindings": bindings, "source_bindings": []model.Document{{"source_id": r.ID, "registration_version": r.Version, "config_hash": Hash(r), "source_version": g.SourceVersion}}}
}
