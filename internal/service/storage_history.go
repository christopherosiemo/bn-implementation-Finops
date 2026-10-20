package service

import (
	"encoding/json"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"math/big"
	"strings"
	"time"
)

// Recorded prior attachment facts support owner review only. They never
// establish a detachment time, ownership, disposal permission or current use.
func storageRecordedPriorAttachments(canonical, resource model.Document, now time.Time) (string, model.Document) {
	var latest time.Time
	var selected model.Document
	var attachments []model.Document
	for _, h := range storageRows(canonical["configuration_history"]) {
		scope := storageObject(h["scope"])
		if model.String(h, "resource_type") != "AWS::EC2::Volume" || h["resource_id"] != resource["provider_resource_id"] || scope["tenant_id"] != resource["tenant_id"] || scope["account_id"] != resource["account_id"] || scope["region"] != resource["region"] || storageArchiveRef("AWS_CONFIG_RECORDED_PRIOR_ATTACHMENTS", h["raw_ref"]) == nil {
			continue
		}
		items := append([]model.Document{storageObject(h["baseline"])}, storageRows(h["items"])...)
		for _, item := range items {
			at, e := time.Parse(time.RFC3339Nano, model.String(item, "capture_time"))
			config := storageObject(item["configuration_decoded"])
			prior := storageRows(config["attachments"])
			if e != nil || at.After(now) || !at.After(latest) || model.String(item, "configurationItemStatus") != "OK" || config["volumeId"] != resource["provider_resource_id"] || len(prior) == 0 {
				continue
			}
			valid := true
			for _, a := range prior {
				if model.String(a, "instanceId") == "" || model.String(a, "device") == "" {
					valid = false
				}
			}
			if valid {
				latest, selected, attachments = at, h, prior
			}
		}
	}
	if selected == nil {
		return "", nil
	}
	raw, _ := json.Marshal(attachments)
	return "AWS Config recorded attachment context at " + latest.Format(time.RFC3339) + " (recorded capture time, not an exact detach time): " + string(raw), storageArchiveRef("AWS_CONFIG_RECORDED_PRIOR_ATTACHMENTS", selected["raw_ref"])
}

// Native recorded CIs establish the analysis basis, not exact physical change
// timestamps. Daily/excluded/stopped recorders and absent baselines stay unknown.
func storageHistoryReasons(canonical, native model.Document, now time.Time) []string {
	period := storageObject(canonical["period"])
	start, se := time.Parse(time.RFC3339Nano, model.String(period, "start"))
	end, ee := time.Parse(time.RFC3339Nano, model.String(period, "end"))
	if se != nil || ee != nil {
		return []string{"STORAGE_CONFIGURATION_HISTORY_WINDOW_UNKNOWN"}
	}
	inv := storageObject(canonical["inventory"])
	expected := map[string]model.Document{"AWS::EC2::Volume\x00" + model.String(native, "volume_id"): native}
	for _, a := range storageRows(native["attachments"]) {
		for _, instance := range storageRows(inv["instances"]) {
			if instance["instance_id"] == a["instance_id"] {
				expected["AWS::EC2::Instance\x00"+model.String(instance, "instance_id")] = instance
			}
		}
	}
	seen := map[string]bool{}
	reasons := []string{}
	for _, h := range storageRows(canonical["configuration_history"]) {
		kind, id := model.String(h, "resource_type"), model.String(h, "resource_id")
		key := kind + "\x00" + id
		target := expected[key]
		if target == nil {
			reasons = append(reasons, "STORAGE_HISTORY_TARGET_MISMATCH")
			continue
		}
		if seen[key] {
			reasons = append(reasons, "STORAGE_HISTORY_TARGET_AMBIGUOUS")
		}
		seen[key] = true
		scope := storageObject(h["scope"])
		hs, hse := time.Parse(time.RFC3339Nano, model.String(h, "start"))
		he, hee := time.Parse(time.RFC3339Nano, model.String(h, "end"))
		collected, ce := time.Parse(time.RFC3339Nano, model.String(h, "collected_at"))
		if scope["account_id"] != native["account_id"] || scope["region"] != native["region"] || scope["tenant_id"] != storageObject(inv["scope"])["tenant_id"] || hse != nil || hee != nil || !hs.Equal(start) || !he.Equal(end) || ce != nil || collected.Before(end) || collected.After(now.Add(time.Minute)) || now.Sub(collected) > 24*time.Hour || model.String(h, "status") != "RECORDED_HISTORY_REQUIRES_RECORDER_AND_CONFIGURATION_VALIDATION" || storageArchiveRef("AWS_CONFIG_RECORDED_CONFIGURATION_HISTORY", h["raw_ref"]) == nil {
			reasons = append(reasons, "STORAGE_RECORDED_HISTORY_UNAVAILABLE")
			continue
		}
		if !storageContinuousRecorder(h, kind, start) {
			reasons = append(reasons, "STORAGE_CONTINUOUS_CONFIGURATION_RECORDING_UNPROVEN")
		}
		if !storageRecorderControlHistory(h, now) {
			reasons = append(reasons, "STORAGE_RECORDER_CONTROL_HISTORY_UNPROVEN")
		}
		baseline := storageObject(h["baseline"])
		at, ae := time.Parse(time.RFC3339Nano, model.String(baseline, "capture_time"))
		if ae != nil || at.After(start) || !storageRecordedConfiguration(baseline, target, kind) {
			reasons = append(reasons, "STORAGE_CONFIGURATION_BASELINE_UNPROVEN")
		}
		for _, item := range storageRows(h["items"]) {
			at, e := time.Parse(time.RFC3339Nano, model.String(item, "capture_time"))
			if e != nil || at.Before(start) || at.After(end) || !storageRecordedConfiguration(item, target, kind) {
				reasons = append(reasons, "STORAGE_RECORDED_CONFIGURATION_CHANGED")
			}
		}
	}
	for key := range expected {
		if !seen[key] {
			reasons = append(reasons, "STORAGE_NATIVE_CONFIGURATION_HISTORY_REQUIRED")
		}
	}
	for _, mod := range storageRows(inv["volume_modifications"]) {
		if mod["volume_id"] == native["volume_id"] {
			at, e := time.Parse(time.RFC3339Nano, model.String(mod, "end_time"))
			if e != nil || !at.Before(start) {
				reasons = append(reasons, "STORAGE_MODIFICATION_WITHIN_OBSERVATION_WINDOW")
			}
		}
	}
	return databaseSortedReasons(reasons)
}
func storageContinuousRecorder(h model.Document, kind string, start time.Time) bool {
	for _, rec := range storageRows(h["recorders"]) {
		group := storageObject(rec["recordingGroup"])
		included := model.Bool(group, "allSupported")
		for _, k := range model.Strings(group, "resourceTypes") {
			if k == kind {
				included = true
			}
		}
		for _, k := range model.Strings(storageObject(group["exclusionByResourceTypes"]), "resourceTypes") {
			if k == kind {
				included = false
			}
		}
		mode := storageObject(rec["recordingMode"])
		continuous := model.String(mode, "recordingFrequency") == "CONTINUOUS"
		for _, override := range storageRows(mode["recordingModeOverrides"]) {
			for _, k := range model.Strings(override, "resourceTypes") {
				if k == kind {
					continuous = model.String(override, "recordingFrequency") == "CONTINUOUS"
				}
			}
		}
		if !included || !continuous {
			continue
		}
		for _, status := range storageRows(h["recorder_statuses"]) {
			if status["name"] != rec["name"] || !model.Bool(status, "recording") || model.String(status, "lastStatus") != "Success" {
				continue
			}
			started, ok := databaseDecimal(status["lastStartTime"])
			if !ok || started.Cmp(big.NewRat(start.Unix(), 1)) > 0 {
				continue
			}
			if stopped, ok := databaseDecimal(status["lastStopTime"]); ok && stopped.Cmp(big.NewRat(start.Unix(), 1)) >= 0 {
				continue
			}
			return true
		}
	}
	return false
}

func storageRecorderControlHistory(h model.Document, now time.Time) bool {
	c := storageObject(h["recorder_control_history"])
	scope := storageObject(h["scope"])
	baseline, be := time.Parse(time.RFC3339Nano, model.String(storageObject(h["baseline"]), "capture_time"))
	start, se := time.Parse(time.RFC3339Nano, model.String(c, "start"))
	end, ee := time.Parse(time.RFC3339Nano, model.String(c, "end"))
	periodEnd, pe := time.Parse(time.RFC3339Nano, model.String(h, "end"))
	collected, ce := time.Parse(time.RFC3339Nano, model.String(h, "collected_at"))
	if model.String(c, "basis") != "AWS_CLOUDTRAIL_CONFIG_RECORDER_MANAGEMENT_EVENTS" || model.String(c, "status") != "COMPLETE_ENUMERATION" || model.String(c, "event_source") != "config.amazonaws.com" || c["account_id"] != scope["account_id"] || c["region"] != scope["region"] || be != nil || se != nil || ee != nil || pe != nil || ce != nil || start.After(baseline) || end.Before(periodEnd) || end.After(collected) || end.After(now.Add(time.Minute)) || start.Before(end.Add(-90*24*time.Hour)) || !databaseInputArrayKnown(c["events"]) || !databaseInputArrayKnown(c["relevant_changes"]) || len(storageRows(c["relevant_changes"])) != 0 {
		return false
	}
	for _, event := range storageRows(c["events"]) {
		if event["read_only"] != true {
			switch model.String(event, "event_name") {
			case "PutEvaluations", "PutExternalEvaluation", "StartConfigRulesEvaluation":
			default:
				return false
			}
		}
		switch model.String(event, "event_name") {
		case "PutConfigurationRecorder", "DeleteConfigurationRecorder", "StartConfigurationRecorder", "StopConfigurationRecorder", "PutServiceLinkedConfigurationRecorder", "DeleteServiceLinkedConfigurationRecorder":
			return false
		}
	}
	return true
}
func storageRecordedConfiguration(item, target model.Document, kind string) bool {
	if model.String(item, "configurationItemStatus") != "OK" || model.String(item, "recordingFrequency") != "CONTINUOUS" {
		return false
	}
	d := storageObject(item["configuration_decoded"])
	if kind == "AWS::EC2::Instance" {
		return d["instanceId"] == target["instance_id"] && d["instanceType"] == target["instance_type"] && d["rootDeviceName"] == target["root_device_name"]
	}
	if d["volumeId"] != target["volume_id"] || d["volumeType"] != target["volume_type"] || d["encrypted"] != target["encrypted"] || d["multiAttachEnabled"] != target["multi_attach_enabled"] || d["kmsKeyId"] != target["kms_key_id"] {
		return false
	}
	for _, pair := range [][2]string{{"size", "size_gib"}, {"iops", "iops"}, {"throughput", "throughput_mibps"}} {
		left, lok := databaseDecimal(d[pair[0]])
		right, rok := databaseDecimal(target[pair[1]])
		if lok != rok || lok && left.Cmp(right) != 0 {
			return false
		}
	}
	attachments := storageRows(d["attachments"])
	current := storageRows(target["attachments"])
	if len(attachments) != len(current) {
		return false
	}
	for _, a := range current {
		found := false
		for _, old := range attachments {
			if old["instanceId"] == a["instance_id"] && old["device"] == a["device"] && old["state"] == a["state"] && old["deleteOnTermination"] == a["delete_on_termination"] {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// Reserve the entire observed instance aggregate before evaluating the selected
// volume against the remaining sustained budget. This deliberately double
// reserves this volume's current activity instead of inventing per-device
// attribution from instance totals. The conservative basis is retained in refs.
func storageSharedInstanceReasons(canonical, native, policy, safety model.Document) []string {
	inv := storageObject(canonical["inventory"])
	period := storageObject(canonical["period"])
	start, se := time.Parse(time.RFC3339Nano, model.String(period, "start"))
	end, ee := time.Parse(time.RFC3339Nano, model.String(period, "end"))
	if se != nil || ee != nil {
		return []string{"STORAGE_INSTANCE_HISTORY_UNKNOWN"}
	}
	reasons := []string{}
	reserve, growth := storageNumber(policy, "reserve_above_demand_fraction"), storageNumber(policy, "demand_growth_multiplier")
	if reserve == nil || growth == nil {
		return []string{"STORAGE_INSTANCE_HEADROOM_POLICY_UNKNOWN"}
	}
	for _, attachment := range storageRows(native["attachments"]) {
		id := model.String(attachment, "instance_id")
		var instance, catalog model.Document
		for _, i := range storageRows(inv["instances"]) {
			if model.String(i, "instance_id") == id {
				instance = i
			}
		}
		for _, c := range storageRows(inv["instance_types"]) {
			if c["instance_type"] == instance["instance_type"] {
				catalog = c
			}
		}
		caps := storageObject(storageObject(catalog["ebs"])["optimized_info"])
		ioLimit, tpLimit := storageNumber(caps, "baseline_iops"), storageNumber(caps, "baseline_throughput_mb_per_second")
		if ioLimit == nil || tpLimit == nil {
			reasons = append(reasons, "STORAGE_INSTANCE_SUSTAINED_LIMIT_UNKNOWN")
			continue
		}
		tpLimit.Mul(tpLimit, big.NewRat(1000000, 1))
		bins := map[string]map[int64]model.Document{}
		p := 0
		for _, ev := range storageRows(canonical["metrics"]) {
			for _, row := range storageRows(ev["metrics"]) {
				if model.String(row, "namespace") != "AWS/EC2" || model.String(row, "provider_resource_id") != id {
					continue
				}
				name := model.String(row, "metric")
				if !strings.HasPrefix(name, "EBS") && !strings.HasPrefix(name, "InstanceEBS") {
					continue
				}
				if bins[name] == nil {
					bins[name] = map[int64]model.Document{}
				}
				at, e := time.Parse(time.RFC3339Nano, model.String(row, "source_time"))
				rp := int(model.Number(row, "period_seconds"))
				if e != nil || row["account_id"] != native["account_id"] || row["region"] != native["region"] || model.String(row, "dimension_name") != "InstanceId" || row["dimension_value"] != id || rp != 60 && rp != 300 && rp != 3600 || p != 0 && p != rp || at.Before(start) || !at.Before(end) || at.Unix()%int64(rp) != 0 {
					reasons = append(reasons, "STORAGE_INSTANCE_METRIC_BINDING_INVALID")
					continue
				}
				p = rp
				if bins[name][at.Unix()] != nil {
					reasons = append(reasons, "STORAGE_INSTANCE_METRIC_DUPLICATE")
				}
				bins[name][at.Unix()] = row
			}
		}
		if p == 0 {
			reasons = append(reasons, "STORAGE_INSTANCE_AGGREGATE_METRICS_REQUIRED")
			continue
		}
		peakIO, peakTP := new(big.Rat), new(big.Rat)
		for at := start; at.Before(end); at = at.Add(time.Duration(p) * time.Second) {
			values := map[string]*big.Rat{}
			for _, name := range []string{"EBSReadOps", "EBSWriteOps", "EBSReadBytes", "EBSWriteBytes"} {
				row := bins[name][at.Unix()]
				v, vok := databaseDecimal(row["native_maximum"])
				nativePeriod := model.Number(row, "native_maximum_period_seconds")
				if !vok && p == 60 {
					v, vok = databaseDecimal(row["value"])
					nativePeriod = 60
				}
				samples, sok := databaseDecimal(row["sample_count"])
				cadence := model.Number(row, "native_cadence_seconds")
				unit := "Count"
				if strings.HasSuffix(name, "Bytes") {
					unit = "Bytes"
				}
				if !vok || v.Sign() < 0 || !sok || cadence != 60 && cadence != 300 || samples.Cmp(big.NewRat(int64(p)/cadence, 1)) < 0 || nativePeriod != cadence || model.String(row, "unit") != unit || model.String(row, "statistic") != "Sum" {
					reasons = append(reasons, "STORAGE_INSTANCE_AGGREGATE_COVERAGE_INCOMPLETE")
					continue
				}
				values[name] = new(big.Rat).Quo(v, big.NewRat(nativePeriod, 1))
			}
			for _, pair := range []struct {
				read, write string
				limit, peak *big.Rat
			}{{"EBSReadOps", "EBSWriteOps", ioLimit, peakIO}, {"EBSReadBytes", "EBSWriteBytes", tpLimit, peakTP}} {
				if values[pair.read] == nil || values[pair.write] == nil {
					continue
				}
				v := new(big.Rat).Add(values[pair.read], values[pair.write])
				v.Mul(v, growth)
				v.Mul(v, new(big.Rat).Add(big.NewRat(1, 1), reserve))
				if v.Cmp(pair.peak) > 0 {
					pair.peak.Set(v)
				}
				if v.Cmp(pair.limit) > 0 {
					reasons = append(reasons, "STORAGE_INSTANCE_SHARED_SUSTAINED_HEADROOM_INSUFFICIENT")
				}
			}
			for _, name := range []string{"InstanceEBSIOPSExceededCheck", "InstanceEBSThroughputExceededCheck"} {
				row := bins[name][at.Unix()]
				v, ok := databaseDecimal(row["value"])
				samples, sok := databaseDecimal(row["sample_count"])
				cadence := model.Number(row, "native_cadence_seconds")
				if !ok || v.Sign() != 0 || model.String(row, "unit") != "None" || model.String(row, "statistic") != "Maximum" || !sok || cadence != 60 && cadence != 300 || samples.Cmp(big.NewRat(int64(p)/cadence, 1)) < 0 {
					reasons = append(reasons, "STORAGE_INSTANCE_EXCEEDED_SIGNAL_UNAVAILABLE_OR_ACTIVE")
				}
			}
		}
		remainingIO := new(big.Rat).Sub(ioLimit, peakIO)
		remainingTP := new(big.Rat).Quo(new(big.Rat).Sub(tpLimit, peakTP), big.NewRat(1<<20, 1))
		for key, value := range map[string]*big.Rat{"instance_iops_limit": remainingIO, "instance_throughput_mib_per_second_limit": remainingTP} {
			if value.Sign() < 0 {
				value.SetInt64(0)
			}
			old := storageNumber(safety, key)
			if old == nil || value.Cmp(old) < 0 {
				safety[key] = databaseInputMoney(value)
			}
		}
	}
	return databaseSortedReasons(reasons)
}
