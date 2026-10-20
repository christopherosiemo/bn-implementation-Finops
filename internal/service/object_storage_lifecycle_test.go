package service

import (
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"testing"
)

func TestObjectStorageNativeLifecycleDoesNotInventAbsentOrFilterCoverage(t *testing.T) {
	dataset := model.Document{"selector": model.Document{"kind": "PREFIX", "prefix": "logs/"}}
	cohort := model.Document{"state": "CURRENT", "source_class": "STANDARD", "size_bands": []model.Document{{"min_bytes": "1048576", "max_bytes": "2097152", "count": "2", "total_bytes": "3145728"}}}
	configs := model.Document{"lifecycle": model.Document{"status": "ABSENT", "value": nil}, "intelligent_tiering": model.Document{"status": "OBSERVED", "value": model.Document{"Configurations": []model.Document{}, "complete": true}}}
	snapshot := model.Document{"configuration": model.Document{"configurations": configs}}
	got := objectStorageLifecycle(snapshot, dataset, cohort)
	if got["state"] != "NONE" || got["conflicts"] != false || len(model.Strings(got, "already_targets")) != 0 {
		t.Fatal("native absence lost", got)
	}
	for _, test := range []struct {
		name   string
		filter model.Document
		want   string
		target bool
	}{{"complete-prefix", model.Document{"Prefix": "logs/"}, "KNOWN", true}, {"disjoint-prefix", model.Document{"Prefix": "images/"}, "KNOWN", false}, {"partial-prefix", model.Document{"Prefix": "logs/nested/"}, "UNKNOWN", false}, {"object-tags-unknown", model.Document{"Tag": model.Document{"Key": "archive", "Value": "yes"}}, "UNKNOWN", false}, {"size-crosses-band", model.Document{"ObjectSizeGreaterThan": 1500000}, "UNKNOWN", false}, {"size-whole-cohort", model.Document{"ObjectSizeGreaterThan": 131072}, "KNOWN", true}} {
		t.Run(test.name, func(t *testing.T) {
			configs["lifecycle"] = model.Document{"status": "OBSERVED", "value": model.Document{"Rules": []model.Document{{"Status": "Enabled", "Filter": test.filter, "Transitions": []model.Document{{"Days": 30, "StorageClass": "STANDARD_IA"}}}}}}
			got := objectStorageLifecycle(snapshot, dataset, cohort)
			if got["state"] != test.want {
				t.Fatal("filter certainty", got)
			}
			has := len(model.Strings(got, "already_targets")) > 0
			if has != test.target {
				t.Fatal("invented/lost current policy", got)
			}
		})
	}
	configs["lifecycle"] = model.Document{"status": "DENIED"}
	if got := objectStorageLifecycle(snapshot, dataset, cohort); got["state"] != "UNKNOWN" || got["conflicts"] != nil {
		t.Fatal("denied became absent", got)
	}
}
