package lambdacost

import (
	"errors"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"regexp"
)

var ErrPerformanceV2 = errors.New("LAMBDA_PERFORMANCE_NATIVE_CONFIGURATION_REFERENCE_INVALID")
var performanceDigest = regexp.MustCompile(`^[a-f0-9]{64}$`)
var performancePublishedVersion = regexp.MustCompile(`^[1-9][0-9]{0,18}$`)
var performanceSnapshotID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)

// ValidatePerformanceV2Point checks a producer's claimed immutable native
// references. Only the restricted assessor can read the archived native
// configuration and establish actual epoch/non-memory comparability.
func ValidatePerformanceV2Point(point model.Document) error {
	binding := Document(point["binding"])
	for _, key := range []string{"tenant_id", "resource_id", "workload_id", "provider", "provider_resource_id", "account_id", "region"} {
		if model.String(binding, key) == "" {
			return ErrPerformanceV2
		}
	}
	if binding["provider"] != "AWS" {
		return ErrPerformanceV2
	}
	version := model.String(point, "executed_version")
	if !performancePublishedVersion.MatchString(version) {
		return ErrPerformanceV2
	}
	scope := Scope{TenantID: model.String(binding, "tenant_id"), AccountID: model.String(binding, "account_id"), Region: model.String(binding, "region")}
	base, qualifiedVersion, e := FunctionARN(scope, model.String(point, "executed_target_arn"))
	if e != nil || qualifiedVersion != version || base != model.String(binding, "provider_resource_id") {
		return ErrPerformanceV2
	}
	ref := Document(point["native_configuration_ref"])
	if len(ref) != 3 || !performanceSnapshotID.MatchString(model.String(ref, "snapshot_id")) || !performanceDigest.MatchString(model.String(ref, "content_hash")) || !performanceDigest.MatchString(model.String(ref, "config_hash")) {
		return ErrPerformanceV2
	}
	if !performanceDigest.MatchString(model.String(point, "configuration_epoch_hash")) {
		return ErrPerformanceV2
	}
	compatibility := Document(point["non_memory_compatibility"])
	if len(compatibility) != 3 || model.String(compatibility, "definition_version") != "LAMBDA_NON_MEMORY_CONFIG_V1" || !performanceDigest.MatchString(model.String(compatibility, "sha256")) || !performanceDigest.MatchString(model.String(compatibility, "dependency_manifest_sha256")) {
		return ErrPerformanceV2
	}
	return nil
}
