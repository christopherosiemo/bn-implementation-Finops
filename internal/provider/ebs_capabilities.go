package provider

import (
	"encoding/json"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
)

// This is a versioned selected-facts transcription of the linked AWS documents,
// not an AWS response, a full page capture, a price list, or customer authority.
// The collector archives these exact bytes alongside the native raw responses.
const ebsCapabilityAsset = `{
"schema_version":"1","basis":"AWS_DOCUMENTED_EBS_CAPABILITIES_V1","source_revision":"2026-10-20","scope":"COMMERCIAL_AWS_REGIONS_EXCLUDING_OUTPOSTS",
"source_urls":["https://docs.aws.amazon.com/ebs/latest/userguide/general-purpose.html","https://docs.aws.amazon.com/ebs/latest/userguide/provisioned-iops.html","https://docs.aws.amazon.com/ebs/latest/userguide/ebs-modify-volume.html","https://docs.aws.amazon.com/ebs/latest/userguide/modify-volume-requirements.html","https://docs.aws.amazon.com/ebs/latest/userguide/ebs-volumes-multi.html","https://docs.aws.amazon.com/ebs/latest/userguide/using_cloudwatch_ebs.html","https://docs.aws.amazon.com/ebs/latest/userguide/snapshot-archive.html"],
"volume_types":{
"gp3":{"min_size_gib":"1","max_size_gib":"65536","baseline_iops":"3000","max_iops":"80000","iops_per_gib":"500","baseline_throughput_mibps":"125","max_throughput_mibps":"2000","throughput_mibps_per_iops":"0.25","burst":false,"multi_attach":false},
"gp2":{"min_size_gib":"1","max_size_gib":"16384","min_baseline_iops":"100","max_iops":"16000","baseline_iops_per_gib":"3","burst_iops":"3000","burst_credit_capacity":"5400000","throughput_mibps_below_170_gib":"128","max_throughput_mibps":"250","sustained_250_mibps_min_size_gib":"334","burst":true,"multi_attach":false},
"io1":{"min_size_gib":"4","max_size_gib":"16384","min_iops":"100","max_iops_nitro":"64000","max_achievable_iops_non_nitro":"32000","iops_per_gib":"50","max_throughput_mibps":"1000","multi_attach":true,"latency_durability_equivalence_to_gp3":"NOT_ESTABLISHED"},
"io2":{"max_size_gib":"65536","max_iops_nitro":"256000","max_achievable_iops_non_nitro":"32000","iops_per_gib":"1000","max_throughput_mibps":"4000","throughput_mibps_per_iops":"0.256","multi_attach":true,"latency_durability_equivalence_to_gp3":"NOT_ESTABLISHED"}},
"modification":{"size_decrease_supported":false,"migration_to_smaller_volume_is_separate":true,"allowed_states":["available","in-use"],"prior_modification_required_state":"completed","max_modifications_per_rolling_24h":"4","latest_modification_does_not_prove_24h_count":true,"multi_attach_type_changes_only":["io1","io2"],"cancel_supported":false,"filesystem_and_partition_limits_require_independent_evidence":true,"all_current_generation_instances_support_elastic_volumes":true,"older_supported_families":["c1","c3","c4","g2","i2","m1","m3","m4","r3","r4"],"m3_feature_limitations_require_review":true},
"metrics":{"ebs_native_cadence_seconds":"60","attached_only":true,"native_sample_count_required":true,"missing_is_zero":false,"observed_period_rate_is_not_operation_p95":true,"instance_aggregate_limits_are_shared":true,"outposts_capabilities":"UNSUPPORTED_BY_THIS_ASSET"},
"snapshot":{"standard_storage":"INCREMENTAL_BLOCKS_NOT_VOLUME_SIZE","archive_storage":"FULL_WRITTEN_BLOCKS","retention_policy_and_external_backup_dependencies":"REQUIRES_INDEPENDENT_AUTHORITY","inventory_is_not_delete_authority":true},
"execution_allowed":false
}`

func EBSCapabilityAsset() []byte { return []byte(ebsCapabilityAsset) }
func EBSCapabilities() model.Document {
	var d model.Document
	_ = json.Unmarshal([]byte(ebsCapabilityAsset), &d)
	d["source_excerpt_sha256"] = rdsSHA([]byte(ebsCapabilityAsset))
	return d
}
