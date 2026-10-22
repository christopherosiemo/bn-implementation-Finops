package provider

import (
	"context"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"math/big"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

type ebsMetricSpec struct {
	name, unit, statistic, namespace, id, dimension string
	cadence                                         int
}

func ebsNativeMaximumApplicable(s ebsMetricSpec, instances, types []model.Document) bool {
	if s.statistic != "Sum" || !(strings.HasSuffix(s.name, "Ops") || strings.HasSuffix(s.name, "Bytes")) || s.name == "VolumeConsumedReadWriteOps" {
		return false
	}
	if s.namespace == "AWS/EC2" {
		return true
	}
	if len(instances) == 0 {
		return false
	}
	for _, instance := range instances {
		found := false
		for _, kind := range types {
			if model.String(instance, "instance_type") == model.String(kind, "instance_type") {
				found = model.String(kind, "hypervisor") == "nitro"
			}
		}
		if !found {
			return false
		}
	}
	return true
}
func ebsVolumeSpecs(volume model.Document, instances, types []model.Document) ([]ebsMetricSpec, []model.Document) {
	id := model.String(volume, "volume_id")
	specs := []ebsMetricSpec{}
	coverage := []model.Document{}
	add := func(name, unit, stat string) {
		specs = append(specs, ebsMetricSpec{name, unit, stat, "AWS/EBS", id, "VolumeId", 60})
	}
	attached := ebsDocuments(volume["attachments"])
	if volume["attachments"] == nil {
		coverage = append(coverage, model.Document{"component": "volume_metrics", "status": "UNKNOWN_NATIVE_ATTACHMENT_POPULATION", "missing_is_zero": false})
		return specs, coverage
	}
	if len(attached) == 0 {
		coverage = append(coverage, model.Document{"component": "volume_metrics", "status": "NOT_PUBLISHED_WHILE_UNATTACHED", "missing_is_zero": false})
		return specs, coverage
	}
	nitro := len(instances) == len(attached)
	for _, i := range instances {
		found := false
		for _, t := range types {
			if model.String(i, "instance_type") == model.String(t, "instance_type") {
				found = model.String(t, "hypervisor") == "nitro"
			}
		}
		nitro = nitro && found
	}
	for _, s := range []ebsMetricSpec{{name: "VolumeReadOps", unit: "Count", statistic: "Sum"}, {name: "VolumeWriteOps", unit: "Count", statistic: "Sum"}, {name: "VolumeReadBytes", unit: "Bytes", statistic: "Sum"}, {name: "VolumeWriteBytes", unit: "Bytes", statistic: "Sum"}} {
		add(s.name, s.unit, s.statistic)
	}
	if nitro {
		add("VolumeQueueLength", "Count", "Maximum")
		add("VolumeAvgReadLatency", "Milliseconds", "Maximum")
		add("VolumeAvgWriteLatency", "Milliseconds", "Maximum")
	} else {
		add("VolumeQueueLength", "Count", "Average")
		coverage = append(coverage, model.Document{"metric": "VolumeQueueLength", "status": "NATIVE_XEN_MAXIMUM_UNSUPPORTED_AVERAGE_ONLY"})
	}
	multi, known := volume["multi_attach_enabled"].(bool)
	if known && !multi {
		add("VolumeTotalReadTime", "Seconds", "Sum")
		add("VolumeTotalWriteTime", "Seconds", "Sum")
		add("VolumeIdleTime", "Seconds", "Sum")
	} else {
		coverage = append(coverage, model.Document{"component": "total_latency_and_idle", "status": "UNAVAILABLE_MULTI_ATTACH_OR_UNKNOWN", "missing_is_zero": false})
	}
	switch model.String(volume, "volume_type") {
	case "gp2", "st1", "sc1":
		add("BurstBalance", "Percent", "Minimum")
	case "io1", "io2":
		if known && !multi {
			add("VolumeThroughputPercentage", "Percent", "Maximum")
		} else {
			coverage = append(coverage, model.Document{"metric": "VolumeThroughputPercentage", "status": "UNSUPPORTED_MULTI_ATTACH_OR_UNKNOWN", "missing_is_zero": false})
		}
		add("VolumeConsumedReadWriteOps", "Count", "Sum")
	}
	if nitro && known && !multi && model.String(volume, "volume_type") != "standard" {
		add("VolumeIOPSExceededCheck", "None", "Maximum")
		add("VolumeThroughputExceededCheck", "None", "Maximum")
		add("VolumeStalledIOCheck", "None", "Maximum")
	} else {
		coverage = append(coverage, model.Document{"component": "volume_exceeded_checks", "status": "UNSUPPORTED_OR_UNKNOWN_NATIVE_ATTACHMENT", "missing_is_zero": false})
	}
	for _, i := range instances {
		instanceID := model.String(i, "instance_id")
		cadence := 0
		switch model.String(i, "monitoring_state") {
		case "enabled":
			cadence = 60
		case "disabled":
			cadence = 300
		}
		if cadence == 0 {
			coverage = append(coverage, model.Document{"instance_id": instanceID, "component": "instance_aggregate_metrics", "status": "UNKNOWN_NATIVE_MONITORING_CADENCE"})
			continue
		}
		isNitro := false
		var caps model.Document
		for _, t := range types {
			if model.String(i, "instance_type") == model.String(t, "instance_type") {
				isNitro = model.String(t, "hypervisor") == "nitro"
				caps, _ = t["ebs"].(model.Document)
			}
		}
		if !isNitro {
			coverage = append(coverage, model.Document{"instance_id": instanceID, "component": "instance_aggregate_metrics", "status": "UNSUPPORTED_NON_NITRO_OR_UNKNOWN"})
			continue
		}
		for _, s := range []ebsMetricSpec{{name: "EBSReadOps", unit: "Count", statistic: "Sum"}, {name: "EBSWriteOps", unit: "Count", statistic: "Sum"}, {name: "EBSReadBytes", unit: "Bytes", statistic: "Sum"}, {name: "EBSWriteBytes", unit: "Bytes", statistic: "Sum"}, {name: "InstanceEBSIOPSExceededCheck", unit: "None", statistic: "Maximum"}, {name: "InstanceEBSThroughputExceededCheck", unit: "None", statistic: "Maximum"}} {
			s.namespace = "AWS/EC2"
			s.id = instanceID
			s.dimension = "InstanceId"
			s.cadence = cadence
			specs = append(specs, s)
		}
		if c, ok := caps["optimized_info"].(model.Document); ok && (model.String(c, "baseline_iops") != model.String(c, "maximum_iops") || model.String(c, "baseline_throughput_mb_per_second") != model.String(c, "maximum_throughput_mb_per_second")) {
			for _, name := range []string{"EBSIOBalance%", "EBSByteBalance%"} {
				specs = append(specs, ebsMetricSpec{name, "Percent", "Minimum", "AWS/EC2", instanceID, "InstanceId", cadence})
			}
		}
	}
	return specs, coverage
}

// EBSMetrics retains provider period statistics, actual SampleCount and missing
// bins. It does not relabel a period-average rate as per-operation p95.
func (a *AWS) EBSMetrics(ctx context.Context, s EBSScope, selection EBSMetricSelection) (EBSMetricEvidence, error) {
	out := EBSMetricEvidence{Selection: selection, Metrics: []model.Document{}, Coverage: []model.Document{}}
	r, e := newEBSRead(a, s)
	if e != nil {
		return out, e
	}
	now := time.Now().UTC()
	p := selection.PeriodSeconds
	if !ebsVolumeID.MatchString(selection.VolumeID) || p != 60 && p != 300 && p != 3600 || selection.Start.IsZero() || !selection.Start.Before(selection.End) || selection.End.After(now.Truncate(time.Minute)) || selection.End.Sub(selection.Start) > 90*24*time.Hour || selection.Start.Unix()%int64(p) != 0 || selection.End.Unix()%int64(p) != 0 || selection.Start.Nanosecond() != 0 || selection.End.Nanosecond() != 0 || p == 60 && selection.Start.Before(now.Add(-15*24*time.Hour)) || p == 300 && selection.Start.Before(now.Add(-63*24*time.Hour)) {
		return EBSMetricEvidence{}, ErrEBSRead
	}
	_, z := selection.Start.Zone()
	_, zz := selection.End.Zone()
	if z != 0 || zz != 0 {
		return EBSMetricEvidence{}, ErrEBSRead
	}
	volumes, e := r.pages(ctx, "DescribeVolumes", "volumeSet", url.Values{"VolumeId.1": {selection.VolumeID}, "IncludeManagedResources": {"true"}}, ebsVolume)
	if e != nil || len(volumes) != 1 || model.String(volumes[0], "volume_id") != selection.VolumeID {
		return EBSMetricEvidence{}, ErrEBSRead
	}
	out.Volume = volumes[0]
	out.Instances, out.InstanceTypes, e = r.attachments(ctx, volumes)
	if e != nil {
		out.Instances = nil
		out.InstanceTypes = nil
		out.Coverage = append(out.Coverage, model.Document{"component": "attachment_instance_capabilities", "status": "UNAVAILABLE"})
	}
	specs, coverage := ebsVolumeSpecs(out.Volume, out.Instances, out.InstanceTypes)
	out.Coverage = append(out.Coverage, coverage...)
	for _, spec := range specs {
		if p < spec.cadence {
			out.Coverage = append(out.Coverage, model.Document{"metric": spec.name, "provider_resource_id": spec.id, "status": "REQUEST_PERIOD_BELOW_NATIVE_CADENCE"})
			continue
		}
		points := map[int64]bool{}
		missingCounts := 0
		zeroCounts := 0
		missingMaximum := 0
		sampleSum := int64(0)
		for start := selection.Start; start.Before(selection.End); {
			end := start.Add(time.Duration(1440*p) * time.Second)
			if end.After(selection.End) {
				end = selection.End
			}
			v := url.Values{"Namespace": {spec.namespace}, "MetricName": {spec.name}, "Dimensions.member.1.Name": {spec.dimension}, "Dimensions.member.1.Value": {spec.id}, "StartTime": {start.Format(time.RFC3339)}, "EndTime": {end.Format(time.RFC3339)}, "Period": {strconv.Itoa(p)}, "Statistics.member.1": {spec.statistic}, "Statistics.member.2": {"SampleCount"}, "Unit": {spec.unit}}
			wantNativeMaximum := ebsNativeMaximumApplicable(spec, out.Instances, out.InstanceTypes)
			if wantNativeMaximum {
				v.Set("Statistics.member.3", "Maximum")
			}
			raw, e := r.query(ctx, "monitoring", "GetMetricStatistics", v)
			if e != nil {
				return EBSMetricEvidence{}, e
			}
			n, e := rdsTree(raw, "GetMetricStatistics", "Datapoints")
			if e != nil {
				return EBSMetricEvidence{}, ErrEBSRead
			}
			for _, point := range n.list("Datapoints") {
				at, e := time.Parse(time.RFC3339Nano, point.value("Timestamp"))
				value := point.value(spec.statistic)
				number, ok := new(big.Rat).SetString(value)
				if e != nil || at.Before(start) || !at.Before(end) || at.Unix()%int64(p) != 0 || at.Nanosecond() != 0 || points[at.Unix()] || !metricNumber.MatchString(value) || !ok || number.Sign() < 0 || point.value("Unit") != spec.unit {
					return EBSMetricEvidence{}, ErrEBSRead
				}
				if (spec.unit == "Percent" || spec.statistic == "Maximum" && spec.unit == "None") && number.Cmp(big.NewRat(100, 1)) > 0 {
					return EBSMetricEvidence{}, ErrEBSRead
				}
				if spec.unit == "None" && number.Cmp(big.NewRat(1, 1)) > 0 {
					return EBSMetricEvidence{}, ErrEBSRead
				}
				var sample any
				if point.get("SampleCount") != nil {
					count, ok := rdsMetricCount(point.value("SampleCount"))
					if !ok {
						return EBSMetricEvidence{}, ErrEBSRead
					}
					sample = count
					sampleSum += count
					if count == 0 {
						zeroCounts++
					}
				} else {
					missingCounts++
				}
				var maximum any
				if wantNativeMaximum && point.get("Maximum") != nil {
					value := point.value("Maximum")
					number, ok := new(big.Rat).SetString(value)
					if !metricNumber.MatchString(value) || !ok || number.Sign() < 0 {
						return EBSMetricEvidence{}, ErrEBSRead
					}
					sum, _ := new(big.Rat).SetString(point.value(spec.statistic))
					if sum == nil || number.Cmp(sum) > 0 {
						return EBSMetricEvidence{}, ErrEBSRead
					}
					maximum = value
				}
				if wantNativeMaximum && maximum == nil {
					missingMaximum++
				}
				points[at.Unix()] = true
				out.Metrics = append(out.Metrics, model.Document{"metric": spec.name, "value": value, "unit": spec.unit, "statistic": spec.statistic, "namespace": spec.namespace, "source_time": at.UTC().Format(time.RFC3339Nano), "period_seconds": p, "native_cadence_seconds": spec.cadence, "native_maximum": maximum, "native_maximum_expected": wantNativeMaximum, "native_maximum_period_seconds": spec.cadence, "sample_count": sample, "provider_resource_id": spec.id, "volume_id": selection.VolumeID, "account_id": s.AccountID, "region": s.Region, "dimension_name": spec.dimension, "dimension_value": spec.id, "raw_page_sha256": rdsSHA(raw)})
				if len(out.Metrics) > 250000 {
					return EBSMetricEvidence{}, ErrEBSRead
				}
			}
			start = end
		}
		expected := int(selection.End.Sub(selection.Start) / time.Duration(p) / time.Second)
		status := "OBSERVED_ALL_REQUESTED_PERIOD_BINS"
		if len(points) != expected || missingCounts > 0 || zeroCounts > 0 || missingMaximum > 0 {
			status = "INCOMPLETE_OR_UNKNOWN_SAMPLES"
		}
		out.Coverage = append(out.Coverage, model.Document{"metric": spec.name, "namespace": spec.namespace, "provider_resource_id": spec.id, "statistic": spec.statistic, "period_seconds": p, "native_cadence_seconds": spec.cadence, "expected_points": expected, "observed_points": len(points), "missing_points": expected - len(points), "sample_count_missing_points": missingCounts, "zero_sample_count_points": zeroCounts, "native_sample_count": sampleSum, "native_maximum_missing_points": missingMaximum, "status": status, "missing_is_zero": false})
	}
	sort.Slice(out.Metrics, func(i, j int) bool {
		a, b := out.Metrics[i], out.Metrics[j]
		ka := model.String(a, "provider_resource_id") + "/" + model.String(a, "metric") + "/" + model.String(a, "source_time")
		kb := model.String(b, "provider_resource_id") + "/" + model.String(b, "metric") + "/" + model.String(b, "source_time")
		return ka < kb
	})
	out.EBSReadEvidence = r.evidence()
	return out, nil
}
