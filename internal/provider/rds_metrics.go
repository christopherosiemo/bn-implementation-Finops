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

type rdsMetricSpec struct{ name, unit, statistic string }

var rdsInstanceMetrics = []rdsMetricSpec{
	{"CPUUtilization", "Percent", "Maximum"}, {"FreeableMemory", "Bytes", "Minimum"}, {"DatabaseConnections", "Count", "Maximum"},
	{"ReadIOPS", "Count/Second", "Maximum"}, {"WriteIOPS", "Count/Second", "Maximum"}, {"ReadThroughput", "Bytes/Second", "Maximum"}, {"WriteThroughput", "Bytes/Second", "Maximum"},
	{"NetworkReceiveThroughput", "Bytes/Second", "Maximum"}, {"NetworkTransmitThroughput", "Bytes/Second", "Maximum"},
	{"ReadLatency", "Seconds", "Maximum"}, {"WriteLatency", "Seconds", "Maximum"}, {"DiskQueueDepth", "Count", "Maximum"}, {"FreeStorageSpace", "Bytes", "Minimum"}, {"SwapUsage", "Bytes", "Maximum"},
}
var rdsClusterMetrics = []rdsMetricSpec{{"VolumeBytesUsed", "Bytes", "Maximum"}, {"VolumeReadIOPs", "Count", "Maximum"}, {"VolumeWriteIOPs", "Count", "Maximum"}}

func rdsMetricCount(raw string) (int64, bool) {
	n, ok := new(big.Rat).SetString(raw)
	if !ok || n.Sign() < 0 || !n.IsInt() || !n.Num().IsInt64() {
		return 0, false
	}
	return n.Num().Int64(), true
}

// RDSMetrics preserves actual provider statistics/sample counts. Minimum memory
// is freeable bytes, not inferred memory utilization; maximum IOPS/throughput
// is observed demand, not a hardware limit. No absent bin is assigned zero.
func (a *AWS) RDSMetrics(ctx context.Context, s RDSScope, selection RDSMetricSelection) (RDSMetricEvidence, error) {
	var out RDSMetricEvidence
	r, e := newRDSRead(a, s)
	if e != nil {
		return out, e
	}
	now := time.Now().UTC()
	period := selection.PeriodSeconds
	if period != 60 && period != 300 && period != 3600 || selection.Start.IsZero() || !selection.Start.Before(selection.End) || selection.End.After(now.Truncate(time.Minute)) || selection.End.Sub(selection.Start) > 90*24*time.Hour || selection.Start.Unix()%int64(period) != 0 || selection.End.Unix()%int64(period) != 0 || selection.Start.Nanosecond() != 0 || selection.End.Nanosecond() != 0 || period == 60 && selection.Start.Before(now.Add(-15*24*time.Hour)) || period == 300 && selection.Start.Before(now.Add(-63*24*time.Hour)) {
		return out, ErrRDSRead
	}
	_, offset := selection.Start.Zone()
	_, endOffset := selection.End.Zone()
	if offset != 0 || endOffset != 0 {
		return out, ErrRDSRead
	}
	kind, dimension, action, collection := "db", "DBInstanceIdentifier", "DescribeDBInstances", "DBInstances"
	parse := rdsInstance
	specs := rdsInstanceMetrics
	if _, e = rdsARN(s, selection.ResourceARN, "db"); e != nil {
		if _, e = rdsARN(s, selection.ResourceARN, "cluster"); e != nil {
			return out, e
		}
		kind, dimension, action, collection = "cluster", "DBClusterIdentifier", "DescribeDBClusters", "DBClusters"
		parse = rdsCluster
		specs = rdsClusterMetrics
	}
	id, _ := rdsARN(s, selection.ResourceARN, kind)
	resources, e := r.pages(ctx, action, collection, selection.ResourceARN, parse)
	if e != nil || len(resources) != 1 {
		return out, ErrRDSRead
	}
	out.Selection = selection
	out.Metrics = []model.Document{}
	out.Coverage = []model.Document{}
	if kind == "db" {
		native := resources[0]
		lagApplicable := false
		lag := rdsMetricSpec{"ReplicaLag", "Seconds", "Maximum"}
		if clusterID := model.String(native, "cluster_identifier"); clusterID != "" {
			clusterARN := "arn:aws:rds:" + s.Region + ":" + s.AccountID + ":cluster:" + clusterID
			clusters, e := r.pages(ctx, "DescribeDBClusters", "DBClusters", clusterARN, rdsCluster)
			if e != nil || len(clusters) != 1 {
				return RDSMetricEvidence{}, ErrRDSRead
			}
			found := false
			for _, member := range clusters[0]["members"].([]model.Document) {
				if model.String(member, "identifier") == id {
					writer, known := member["is_writer"].(bool)
					if !known {
						return RDSMetricEvidence{}, ErrRDSRead
					}
					found = true
					lagApplicable = !writer
				}
			}
			if !found {
				return RDSMetricEvidence{}, ErrRDSRead
			}
			if strings.HasPrefix(model.String(native, "engine"), "aurora") {
				lag = rdsMetricSpec{"AuroraReplicaLag", "Milliseconds", "Maximum"}
			}
		} else {
			lagApplicable = model.String(native, "read_replica_source_identifier") != ""
		}
		specs = append([]rdsMetricSpec{}, specs...)
		if lagApplicable {
			specs = append(specs, lag)
		} else {
			out.Coverage = append(out.Coverage, model.Document{"metric": lag.name, "status": "NOT_APPLICABLE_NATIVE_PRIMARY", "missing_is_zero": false})
		}
		if model.String(native, "class") == "db.serverless" {
			specs = append(specs, rdsMetricSpec{"ServerlessDatabaseCapacity", "", "Maximum"}, rdsMetricSpec{"ACUUtilization", "Percent", "Maximum"})
		}
	} else if strings.HasPrefix(model.String(resources[0], "engine"), "aurora") {
		specs = append(append([]rdsMetricSpec{}, specs...), rdsMetricSpec{"AuroraReplicaLagMaximum", "Milliseconds", "Maximum"})
		if model.String(resources[0], "engine_mode") == "serverless" || resources[0]["serverless_v2"] != nil {
			specs = append(specs, rdsMetricSpec{"ServerlessDatabaseCapacity", "", "Maximum"}, rdsMetricSpec{"ACUUtilization", "Percent", "Maximum"})
		}
	}
	expected := int(selection.End.Sub(selection.Start) / time.Duration(period) / time.Second)
	for _, spec := range specs {
		points := map[int64]bool{}
		withoutCount := 0
		zeroCount := 0
		unknownCount := 0
		// The native legacy operation has at most1440 points; bounded chunking retains
		// the original period/statistic rather than reducing source resolution.
		for start := selection.Start; start.Before(selection.End); {
			end := start.Add(time.Duration(1440*period) * time.Second)
			if end.After(selection.End) {
				end = selection.End
			}
			values := url.Values{"Namespace": {"AWS/RDS"}, "MetricName": {spec.name}, "Dimensions.member.1.Name": {dimension}, "Dimensions.member.1.Value": {id}, "StartTime": {start.Format(time.RFC3339)}, "EndTime": {end.Format(time.RFC3339)}, "Period": {strconv.Itoa(period)}, "Statistics.member.1": {spec.statistic}, "Statistics.member.2": {"SampleCount"}, "Unit": {spec.unit}}
			if spec.unit == "" {
				values.Del("Unit")
			}
			raw, e := r.query(ctx, "monitoring", "GetMetricStatistics", values)
			if e != nil {
				return RDSMetricEvidence{}, e
			}
			result, e := rdsTree(raw, "GetMetricStatistics", "Datapoints")
			if e != nil {
				return RDSMetricEvidence{}, e
			}
			for _, point := range result.list("Datapoints") {
				at, e := time.Parse(time.RFC3339Nano, point.value("Timestamp"))
				value := point.value(spec.statistic)
				if e != nil || at.Before(start) || !at.Before(end) || at.Unix()%int64(period) != 0 || at.Nanosecond() != 0 || points[at.Unix()] || !metricNumber.MatchString(value) || spec.unit != "" && point.value("Unit") != spec.unit {
					return RDSMetricEvidence{}, ErrRDSRead
				}
				number, ok := new(big.Rat).SetString(value)
				sentinel := ok && number.Sign() < 0 && (spec.name == "ReplicaLag" || spec.name == "AuroraReplicaLag" || spec.name == "AuroraReplicaLagMaximum")
				if !ok || number.Sign() < 0 && !sentinel || spec.name == "CPUUtilization" && number.Cmp(big.NewRat(100, 1)) > 0 {
					return RDSMetricEvidence{}, ErrRDSRead
				}
				var sample any
				if child := point.get("SampleCount"); child != nil {
					count, ok := rdsMetricCount(point.value("SampleCount"))
					if !ok {
						return RDSMetricEvidence{}, ErrRDSRead
					}
					sample = count
					if count == 0 {
						zeroCount++
					}
				} else {
					withoutCount++
				}
				points[at.Unix()] = true
				var projectedValue any = value
				var unknownReason any
				if sentinel {
					projectedValue = nil
					unknownReason = "NATIVE_REPLICA_LAG_UNAVAILABLE_SENTINEL"
					unknownCount++
				}
				unit := spec.unit
				if unit == "" {
					unit = point.value("Unit")
					if unit != "Count" && unit != "None" {
						return RDSMetricEvidence{}, ErrRDSRead
					}
				}
				out.Metrics = append(out.Metrics, model.Document{"metric": spec.name, "value": projectedValue, "native_value": value, "unknown_reason": unknownReason, "unit": unit, "statistic": spec.statistic, "source_time": at.UTC().Format(time.RFC3339Nano), "period_seconds": period, "sample_count": sample, "provider_resource_id": selection.ResourceARN, "account_id": s.AccountID, "region": s.Region, "dimension_name": dimension, "dimension_value": id, "raw_page_sha256": rdsSHA(raw)})
			}
			start = end
		}
		status := "COMPLETE_OBSERVED_BINS"
		if len(points) != expected || withoutCount > 0 || zeroCount > 0 || unknownCount > 0 {
			status = "INCOMPLETE_OR_UNKNOWN_SAMPLES"
		}
		out.Coverage = append(out.Coverage, model.Document{"metric": spec.name, "statistic": spec.statistic, "period_seconds": period, "expected_points": expected, "observed_points": len(points), "missing_points": expected - len(points), "sample_count_missing_points": withoutCount, "zero_sample_count_points": zeroCount, "unknown_native_value_points": unknownCount, "status": status, "missing_is_zero": false})
	}
	sort.Slice(out.Metrics, func(i, j int) bool {
		a, b := out.Metrics[i], out.Metrics[j]
		if model.String(a, "metric") != model.String(b, "metric") {
			return model.String(a, "metric") < model.String(b, "metric")
		}
		return model.String(a, "source_time") < model.String(b, "source_time")
	})
	out.RDSReadEvidence = r.evidence()
	return out, nil
}
