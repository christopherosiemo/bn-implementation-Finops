package service

import (
	"encoding/json"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/evidence"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/provider"
	"math/big"
	"strings"
	"testing"
	"time"
)

// Synthetic private transport-shaped input only. The native service test must
// replace every placeholder with a real versioned archive before publication.
func storageInputTestCanonical(resource model.Document, start, end time.Time) model.Document {
	ref := func(id, hash string) model.Document {
		if hash == "" {
			hash = strings.Repeat("a", 64)
		}
		return model.Document{"key": "tenant/component-wire/" + id, "version_id": "component-v1", "body_sha256": hash}
	}
	native := model.Clone(evidence.Object(resource["storage_configuration"]))
	if len(native) == 0 {
		native = model.Document{"volume_id": resource["provider_resource_id"], "provider_resource_id": resource["provider_resource_id"], "resource_type": "EBS_VOLUME", "provider": "AWS", "account_id": "111122223333", "region": "eu-west-1", "availability_zone": "eu-west-1a", "state": "in-use", "volume_type": "gp2", "size_gib": 1000, "iops": 3000, "throughput_mibps": nil, "encrypted": true, "kms_key_id": "arn:aws:kms:eu-west-1:111122223333:key/component", "multi_attach_enabled": false, "create_time": start.Add(-30 * 24 * time.Hour).Format(time.RFC3339), "attachments": []model.Document{{"volume_id": resource["provider_resource_id"], "instance_id": "i-0eb50000000000001", "device": "/dev/sdf", "state": "attached", "delete_on_termination": false}}, "tags": []any{}}
	}
	resource = model.Clone(resource)
	resource["storage_configuration"] = native
	instance := model.Document{"instance_id": "i-0eb50000000000001", "instance_type": "m6i.8xlarge", "root_device_name": "/dev/sda1", "root_device_type": "ebs", "ebs_optimized": true, "monitoring_state": "enabled", "block_device_mappings": []model.Document{{"volume_id": native["volume_id"], "device_name": "/dev/sdf", "delete_on_termination": false}}}
	catalog := model.Document{"instance_type": "m6i.8xlarge", "hypervisor": "nitro", "current_generation": true, "ebs": model.Document{"optimized_support": "default", "optimized_info": model.Document{"baseline_iops": "40000", "maximum_iops": "40000", "baseline_throughput_mb_per_second": "1250", "maximum_throughput_mb_per_second": "1250"}}}
	scope := model.Document{"tenant_id": resource["tenant_id"], "account_id": native["account_id"], "region": native["region"]}
	inventory := model.Document{"scope": scope, "volumes": []model.Document{native}, "snapshots": []model.Document{}, "owned_images": []model.Document{}, "fast_snapshot_restores": []model.Document{}, "snapshot_tier_statuses": []model.Document{}, "locked_snapshots": []model.Document{}, "volume_modifications": []model.Document{}, "volume_statuses": []model.Document{}, "snapshot_permissions": []model.Document{}, "instances": []model.Document{instance}, "instance_types": []model.Document{catalog}, "raw_ref": ref("inventory", "")}
	coverage := []model.Document{}
	for _, component := range []string{"snapshots", "owned_images", "fast_snapshot_restores", "snapshot_tiers", "snapshot_locks", "volume_modifications"} {
		coverage = append(coverage, model.Document{"component": component, "status": "OBSERVED_COMPLETE_ACCOUNT_REGION_POINT_READ"})
	}
	inventory["coverage"] = coverage
	caps := provider.EBSCapabilities()
	caps["asset_ref"] = ref("capabilities", model.String(caps, "source_excerpt_sha256"))
	metrics := []model.Document{}
	for at := start; at.Before(end); at = at.Add(time.Hour) {
		for _, spec := range []struct {
			name, unit, stat string
			sum, maximum     int64
		}{{"VolumeReadOps", "Count", "Sum", 360000, 6000}, {"VolumeWriteOps", "Count", "Sum", 180000, 3000}, {"VolumeReadBytes", "Bytes", "Sum", 5 * 1048576 * 3600, 5 * 1048576 * 60}, {"VolumeWriteBytes", "Bytes", "Sum", 2 * 1048576 * 3600, 2 * 1048576 * 60}, {"VolumeQueueLength", "Count", "Maximum", 0, 0}, {"VolumeAvgReadLatency", "Milliseconds", "Maximum", 1, 1}, {"VolumeAvgWriteLatency", "Milliseconds", "Maximum", 1, 1}, {"BurstBalance", "Percent", "Minimum", 100, 100}, {"VolumeIOPSExceededCheck", "None", "Maximum", 0, 0}, {"VolumeThroughputExceededCheck", "None", "Maximum", 0, 0}} {
			row := model.Document{"metric": spec.name, "namespace": "AWS/EBS", "provider_resource_id": native["volume_id"], "volume_id": native["volume_id"], "account_id": native["account_id"], "region": native["region"], "dimension_name": "VolumeId", "dimension_value": native["volume_id"], "unit": spec.unit, "statistic": spec.stat, "value": databaseInputMoney(big.NewRat(spec.sum, 1)), "source_time": at.Format(time.RFC3339), "period_seconds": 3600, "sample_count": 60, "native_cadence_seconds": 60, "raw_page_sha256": strings.Repeat("a", 64)}
			if spec.stat == "Sum" {
				row["native_maximum"] = databaseInputMoney(big.NewRat(spec.maximum, 1))
				row["native_maximum_period_seconds"] = 60
			}
			metrics = append(metrics, row)
		}
		for _, spec := range []struct {
			name, unit, stat string
			sum, maximum     int64
		}{{"EBSReadOps", "Count", "Sum", 720000, 12000}, {"EBSWriteOps", "Count", "Sum", 360000, 6000}, {"EBSReadBytes", "Bytes", "Sum", 10 * 1048576 * 3600, 10 * 1048576 * 60}, {"EBSWriteBytes", "Bytes", "Sum", 4 * 1048576 * 3600, 4 * 1048576 * 60}, {"InstanceEBSIOPSExceededCheck", "None", "Maximum", 0, 0}, {"InstanceEBSThroughputExceededCheck", "None", "Maximum", 0, 0}} {
			row := model.Document{"metric": spec.name, "namespace": "AWS/EC2", "provider_resource_id": instance["instance_id"], "account_id": native["account_id"], "region": native["region"], "dimension_name": "InstanceId", "dimension_value": instance["instance_id"], "unit": spec.unit, "statistic": spec.stat, "value": databaseInputMoney(big.NewRat(spec.sum, 1)), "source_time": at.Format(time.RFC3339), "period_seconds": 3600, "sample_count": 60, "native_cadence_seconds": 60}
			if spec.stat == "Sum" {
				row["native_maximum"] = databaseInputMoney(big.NewRat(spec.maximum, 1))
				row["native_maximum_period_seconds"] = 60
			}
			metrics = append(metrics, row)
		}
	}
	volumeConfig := model.Document{"volumeId": native["volume_id"], "volumeType": native["volume_type"], "size": native["size_gib"], "iops": native["iops"], "throughput": native["throughput_mibps"], "encrypted": native["encrypted"], "kmsKeyId": native["kms_key_id"], "multiAttachEnabled": native["multi_attach_enabled"]}
	oldAttachments := []model.Document{}
	for _, a := range evidence.Rows(native["attachments"]) {
		oldAttachments = append(oldAttachments, model.Document{"instanceId": a["instance_id"], "device": a["device"], "state": a["state"], "deleteOnTermination": a["delete_on_termination"]})
	}
	volumeConfig["attachments"] = oldAttachments
	histories := []model.Document{}
	for _, target := range []struct {
		kind, id string
		config   model.Document
	}{{"AWS::EC2::Volume", model.String(native, "volume_id"), volumeConfig}, {"AWS::EC2::Instance", model.String(instance, "instance_id"), model.Document{"instanceId": instance["instance_id"], "instanceType": instance["instance_type"], "rootDeviceName": instance["root_device_name"]}}} {
		histories = append(histories, model.Document{"scope": scope, "resource_type": target.kind, "resource_id": target.id, "start": start.Format(time.RFC3339), "end": end.Format(time.RFC3339), "collected_at": end.Add(time.Hour).Format(time.RFC3339), "status": "RECORDED_HISTORY_REQUIRES_RECORDER_AND_CONFIGURATION_VALIDATION", "raw_ref": ref("history-"+target.id, ""), "baseline": model.Document{"configurationItemStatus": "OK", "recordingFrequency": "CONTINUOUS", "capture_time": start.Add(-time.Hour).Format(time.RFC3339), "configuration_decoded": target.config}, "items": []model.Document{}, "recorders": []model.Document{{"name": "component", "recordingGroup": model.Document{"allSupported": true}, "recordingMode": model.Document{"recordingFrequency": "CONTINUOUS"}}}, "recorder_statuses": []model.Document{{"name": "component", "recording": true, "lastStatus": "Success", "lastStartTime": json.Number(strings.TrimSuffix(databaseInputMoney(big.NewRat(start.Add(-48*time.Hour).Unix(), 1)), ".000000000000"))}}})
	}
	for _, h := range histories {
		h["recorder_control_history"] = model.Document{"basis": "AWS_CLOUDTRAIL_CONFIG_RECORDER_MANAGEMENT_EVENTS", "status": "COMPLETE_ENUMERATION", "start": start.Add(-time.Hour).Format(time.RFC3339), "end": end.Add(time.Hour).Format(time.RFC3339), "event_source": "config.amazonaws.com", "account_id": scope["account_id"], "region": scope["region"], "events": []model.Document{}, "relevant_changes": []model.Document{}, "reason_codes": []string{}}
	}
	return model.Document{"schema_version": "1", "resource": resource, "inventory": inventory, "capabilities": caps, "period": model.Document{"start": start.Format(time.RFC3339), "end": end.Format(time.RFC3339)}, "metrics": []model.Document{{"scope": scope, "selection": model.Document{"volume_id": native["volume_id"], "period_seconds": 3600, "start": start.Format(time.RFC3339), "end": end.Format(time.RFC3339)}, "metrics": metrics, "raw_ref": ref("metrics", "")}}, "configuration_history": histories}
}

func TestStorageNativeMetricsPreserveMinutePeaksAndMissingUnknown(t *testing.T) {
	end := time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)
	start := end.Add(-14 * 24 * time.Hour)
	r := model.Document{"id": "storage-unit", "tenant_id": "tenant", "provider_resource_id": "vol-0eb50000000000001"}
	c := storageInputTestCanonical(r, start, end)
	native := evidence.Object(evidence.Object(c["resource"])["storage_configuration"])
	h, obs, maxima, rs := storageMetrics(c, native, end.Add(time.Hour))
	if len(rs) > 0 || len(obs) != 336 || model.String(h, "start") != start.Format(time.RFC3339) || maxima["read_iops"].Cmp(big.NewRat(100, 1)) != 0 || maxima["read_latency"].Cmp(big.NewRat(1, 1000)) != 0 {
		t.Fatal("native peaks/coverage changed", rs)
	}
	metric := evidence.Rows(c["metrics"])[0]
	rows := evidence.Rows(metric["metrics"])
	metric["metrics"] = rows[1:]
	c["metrics"] = []model.Document{metric}
	_, obs, _, rs = storageMetrics(c, native, end.Add(time.Hour))
	if len(rs) == 0 || evidence.Object(evidence.Object(obs[0]["metrics"])["read_iops"])["value"] != nil {
		t.Fatal("missing metric became zero")
	}
}
func TestStorageCandidatesNeverShrinkCapacityOrIncreaseGp3Performance(t *testing.T) {
	current := model.Document{"volume_type": "gp3", "size_gib": "1000", "iops": "9000", "throughput_mib_per_second": "500"}
	policy := model.Document{"reserve_above_demand_fraction": "0.1", "demand_growth_multiplier": "1", "iops_max_fraction": "0.8", "throughput_max_fraction": "0.8"}
	maxima := map[string]*big.Rat{"read_iops": big.NewRat(100, 1), "write_iops": big.NewRat(50, 1), "read_throughput": big.NewRat(5<<20, 1), "write_throughput": big.NewRat(2<<20, 1)}
	cs := storageCandidates(current, policy, maxima)
	if len(cs) != 3 {
		t.Fatal("independent candidate dimensions missing")
	}
	for _, c := range cs {
		size, _ := databaseDecimal(c["size_gib"])
		io, _ := databaseDecimal(c["iops"])
		tp, _ := databaseDecimal(c["throughput_mib_per_second"])
		if size.Cmp(big.NewRat(1000, 1)) != 0 || io.Cmp(big.NewRat(9000, 1)) > 0 || tp.Cmp(big.NewRat(500, 1)) > 0 {
			t.Fatal("unsafe candidate", c)
		}
	}
}
func TestStorageRecordedHistoryRejectsAbsentChangedDailyAndForeign(t *testing.T) {
	end := time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)
	start := end.Add(-14 * 24 * time.Hour)
	r := model.Document{"id": "storage-unit", "tenant_id": "tenant", "provider_resource_id": "vol-0eb50000000000001"}
	c := storageInputTestCanonical(r, start, end)
	native := evidence.Object(evidence.Object(c["resource"])["storage_configuration"])
	if rs := storageHistoryReasons(c, native, end.Add(2*time.Hour)); len(rs) != 0 {
		t.Fatal("actual recorded history blocked", rs)
	}
	for _, change := range []func(model.Document){func(d model.Document) { d["configuration_history"] = []model.Document{} }, func(d model.Document) {
		hs := storageRows(d["configuration_history"])
		h := hs[0]
		baseline := storageObject(h["baseline"])
		config := storageObject(baseline["configuration_decoded"])
		config["size"] = 500
		baseline["configuration_decoded"] = config
		h["baseline"] = baseline
		d["configuration_history"] = hs
	}, func(d model.Document) {
		hs := storageRows(d["configuration_history"])
		recorders := storageRows(hs[0]["recorders"])
		mode := storageObject(recorders[0]["recordingMode"])
		mode["recordingFrequency"] = "DAILY"
		recorders[0]["recordingMode"] = mode
		hs[0]["recorders"] = recorders
		d["configuration_history"] = hs
	}, func(d model.Document) {
		hs := storageRows(d["configuration_history"])
		scope := storageObject(hs[0]["scope"])
		scope["account_id"] = "999988887777"
		hs[0]["scope"] = scope
		d["configuration_history"] = hs
	}, func(d model.Document) {
		hs := storageRows(d["configuration_history"])
		delete(hs[0], "recorder_control_history")
		d["configuration_history"] = hs
	}, func(d model.Document) {
		hs := storageRows(d["configuration_history"])
		control := storageObject(hs[0]["recorder_control_history"])
		control["events"] = []model.Document{{"event_name": "PutConfigurationRecorder"}}
		hs[0]["recorder_control_history"] = control
		d["configuration_history"] = hs
	}} {
		copy := storageInputTestCanonical(r, start, end)
		change(copy)
		if len(storageHistoryReasons(copy, native, end.Add(2*time.Hour))) == 0 {
			t.Fatal("unproved history accepted")
		}
	}
}
