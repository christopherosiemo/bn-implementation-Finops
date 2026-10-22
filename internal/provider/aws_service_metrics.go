package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/awsservice"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
)

type serviceMetric struct {
	namespace, name, statistic, unit string
	dimensions                       map[string]string
}

func serviceMetricSpecs(resource model.Document) []serviceMetric {
	c := awsservice.Document(resource["aws_service_configuration"])
	out := []serviceMetric{}
	add := func(namespace, name, statistic, unit string, d map[string]string) {
		out = append(out, serviceMetric{namespace, name, statistic, unit, d})
	}
	switch model.String(resource, "resource_type") {
	case "ECS_SERVICE":
		cluster := model.String(c, "clusterArn")
		at := strings.LastIndex(cluster, "/")
		if at < 0 {
			return nil
		}
		d := map[string]string{"ClusterName": cluster[at+1:], "ServiceName": model.String(c, "serviceName")}
		for _, name := range []string{"CPUUtilization", "MemoryUtilization"} {
			add("AWS/ECS", name, "Maximum", "Percent", d)
		}
		for _, name := range []string{"RunningTaskCount", "DesiredTaskCount", "PendingTaskCount", "DeploymentCount"} {
			add("ECS/ContainerInsights", name, "Maximum", "Count", d)
		}
		add("ECS/ContainerInsights", "RunningTaskCount", "Minimum", "Count", d)
		add("ECS/ContainerInsights", "DesiredTaskCount", "Minimum", "Count", d)
		// Existing commissioned Container Insights is read only. These aggregate
		// service statistics are not relabelled exact individual task peaks.
		add("ECS/ContainerInsights", "TaskCpuUtilization", "Maximum", "Percent", d)
		add("ECS/ContainerInsights", "TaskMemoryUtilization", "Maximum", "Percent", d)
	case "DYNAMODB_TABLE", "DYNAMODB_GSI":
		d := map[string]string{}
		if model.String(resource, "resource_type") == "DYNAMODB_GSI" {
			arn := strings.Split(model.String(resource, "provider_resource_id"), ":table/")
			if len(arn) != 2 {
				return nil
			}
			bits := strings.Split(arn[1], "/index/")
			if len(bits) != 2 {
				return nil
			}
			d["TableName"], d["GlobalSecondaryIndexName"] = bits[0], bits[1]
		} else {
			d["TableName"] = model.String(c, "TableName")
		}
		for _, name := range []string{"ConsumedReadCapacityUnits", "ConsumedWriteCapacityUnits", "ReadThrottleEvents", "WriteThrottleEvents", "ThrottledRequests", "SuccessfulRequestLatency"} {
			stat, unit := "Sum", "Count"
			if name == "SuccessfulRequestLatency" {
				continue /* Requires Operation dimension; absence remains explicit below. */
			}
			add("AWS/DynamoDB", name, stat, unit, d)
		}
		for _, name := range []string{"ProvisionedReadCapacityUnits", "ProvisionedWriteCapacityUnits"} {
			add("AWS/DynamoDB", name, "Maximum", "Count", d)
			add("AWS/DynamoDB", name, "Minimum", "Count", d)
		}
	case "ELASTICACHE_CLUSTER", "ELASTICACHE_REPLICATION_GROUP":
		nodes := serviceList(c["CacheNodes"])
		if resource["resource_type"] == "ELASTICACHE_REPLICATION_GROUP" {
			nodes = []model.Document{}
			for _, group := range serviceList(c["NodeGroups"]) {
				nodes = append(nodes, serviceList(group["NodeGroupMembers"])...)
			}
		}
		for _, node := range nodes {
			cluster := model.String(c, "CacheClusterId")
			if node["CacheClusterId"] != nil {
				cluster = model.String(node, "CacheClusterId")
			}
			d := map[string]string{"CacheClusterId": cluster, "CacheNodeId": model.String(node, "CacheNodeId")}
			for _, name := range []string{"CPUUtilization", "EngineCPUUtilization", "DatabaseMemoryUsagePercentage", "FreeableMemory", "SwapUsage", "CurrConnections", "Evictions", "CacheHits", "CacheMisses", "NetworkBytesIn", "NetworkBytesOut", "ReplicationLag"} {
				if name == "ReplicationLag" && node["CurrentRole"] == "primary" {
					continue
				}
				unit, stat := "Count", "Maximum"
				switch name {
				case "CPUUtilization", "EngineCPUUtilization", "DatabaseMemoryUsagePercentage":
					unit = "Percent"
				case "FreeableMemory", "SwapUsage", "NetworkBytesIn", "NetworkBytesOut":
					unit = "Bytes"
				case "ReplicationLag":
					unit = "Seconds"
				}
				if awsservice.Contains([]string{"Evictions", "CacheHits", "CacheMisses", "NetworkBytesIn", "NetworkBytesOut"}, name) {
					stat = "Sum"
				}
				if name == "FreeableMemory" {
					stat = "Minimum"
				}
				add("AWS/ElastiCache", name, stat, unit, d)
			}
		}
	case "LOAD_BALANCER":
		subtype := model.String(c, "subtype")
		if subtype == "" {
			subtype = model.String(c, "Type")
		}
		arn := model.String(resource, "provider_resource_id")
		name := model.String(c, "LoadBalancerName")
		ns := "AWS/ApplicationELB"
		d := map[string]string{}
		if subtype == "CLASSIC" || subtype == "classic" {
			ns = "AWS/ELB"
			d["LoadBalancerName"] = name
		} else {
			at := strings.Index(arn, ":loadbalancer/")
			if at < 0 {
				return nil
			}
			d["LoadBalancer"] = arn[at+len(":loadbalancer/"):]
			if subtype == "NLB" || subtype == "network" {
				ns = "AWS/NetworkELB"
			}
		}
		specs := []serviceMetric{{ns, "ProcessedBytes", "Sum", "Bytes", d}, {ns, "HealthyHostCount", "Minimum", "Count", d}}
		if ns == "AWS/NetworkELB" {
			specs = append(specs, serviceMetric{ns, "NewFlowCount", "Sum", "Count", d}, serviceMetric{ns, "ActiveFlowCount", "Maximum", "Count", d}, serviceMetric{ns, "TCP_Target_Reset_Count", "Sum", "Count", d}, serviceMetric{ns, "SecurityGroupBlockedFlowCount_Inbound", "Sum", "Count", d}, serviceMetric{ns, "ConsumedLCUs", "Maximum", "Count", d})
		} else {
			specs = append(specs, serviceMetric{ns, "RequestCount", "Sum", "Count", d}, serviceMetric{ns, "HTTPCode_ELB_5XX_Count", "Sum", "Count", d}, serviceMetric{ns, "BackendConnectionErrors", "Sum", "Count", d})
			if ns == "AWS/ApplicationELB" {
				specs = append(specs, serviceMetric{ns, "NewConnectionCount", "Sum", "Count", d}, serviceMetric{ns, "ActiveConnectionCount", "Maximum", "Count", d}, serviceMetric{ns, "ConsumedLCUs", "Maximum", "Count", d})
			}
		}
		out = append(out, specs...)
	}
	return out
}

// ServiceMetrics reads retained hourly statistics without enabling paid
// telemetry. Maximums remain period maximums, never event percentiles. Missing
// series and engine-inapplicable dimensions remain visible in reason codes.
func (a *AWS) ServiceMetrics(ctx context.Context, reg awsservice.Registration, resource model.Document, start, end time.Time) (awsservice.Metrics, error) {
	out := awsservice.Metrics{Scope: awsservice.Scope{TenantID: reg.TenantID, AccountID: reg.AccountID, Region: reg.Region}, Family: model.String(resource, "service_family"), ProviderResourceID: model.String(resource, "provider_resource_id"), Start: start, End: end, PeriodSeconds: 3600, Rows: []model.Document{}, ReasonCodes: []string{}}
	if awsservice.ValidateRegistration(reg) != nil || !reg.Enabled || !awsservice.Contains(reg.ServiceFamilies, out.Family) || resource["account_id"] != reg.AccountID || resource["region"] != reg.Region || !awsservice.BoundARN(out.Scope, out.ProviderResourceID) || start.IsZero() || !start.Equal(start.UTC().Truncate(time.Hour)) || !end.Equal(end.UTC().Truncate(time.Hour)) || !start.Before(end) || end.Sub(start) > 90*24*time.Hour || end.After(time.Now().UTC().Add(time.Minute)) {
		return out, awsservice.ErrEvidence
	}
	r, e := newServiceRead(a, out.Scope)
	if e != nil {
		return out, e
	}
	specs := serviceMetricSpecs(resource)
	if len(specs) == 0 {
		out.ReasonCodes = append(out.ReasonCodes, "AWS_SERVICE_RESOURCE_METRICS_UNSUPPORTED")
	}
	for _, spec := range specs {
		out.ExpectedSeries = append(out.ExpectedSeries, model.Document{"metric": spec.name, "statistic": spec.statistic, "unit": spec.unit, "dimensions": spec.dimensions, "period_seconds": out.PeriodSeconds})
		if len(out.Rows) > 100000 {
			return out, awsservice.ErrEvidence
		}
		observed := 0
		bad := false
		for left := start; left.Before(end); {
			right := left.Add(60 * 24 * time.Hour)
			if right.After(end) {
				right = end
			}
			p := url.Values{"Namespace": {spec.namespace}, "MetricName": {spec.name}, "StartTime": {left.UTC().Format(time.RFC3339)}, "EndTime": {right.UTC().Format(time.RFC3339)}, "Period": {"3600"}, "Statistics.member.1": {spec.statistic}, "Statistics.member.2": {"SampleCount"}}
			keys := []string{}
			for key := range spec.dimensions {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			for n, key := range keys {
				p.Set(fmt.Sprintf("Dimensions.member.%d.Name", n+1), key)
				p.Set(fmt.Sprintf("Dimensions.member.%d.Value", n+1), spec.dimensions[key])
			}
			v, err := r.query(ctx, "monitoring", "GetMetricStatistics", "2010-08-01", p)
			if err != nil {
				out.ReasonCodes = append(out.ReasonCodes, "AWS_SERVICE_METRIC_"+strings.ToUpper(spec.name)+"_UNAVAILABLE")
				bad = true
				break
			}
			if model.String(v, "Label") != "" && model.String(v, "Label") != spec.name {
				return out, awsservice.ErrEvidence
			}
			points, ok := v["Datapoints"]
			if !ok {
				return out, awsservice.ErrEvidence
			}
			seen := map[string]bool{}
			for _, point := range serviceList(points) {
				stamp := model.String(point, "Timestamp")
				at, err := time.Parse(time.RFC3339Nano, stamp)
				value, count := model.String(point, spec.statistic), model.String(point, "SampleCount")
				val, vok := new(big.Rat).SetString(value)
				cnt, cok := new(big.Rat).SetString(count)
				if err != nil || at.Before(left) || !at.Before(right) || !at.Equal(at.UTC().Truncate(time.Hour)) || !vok || !cok || val.Sign() < 0 || cnt.Sign() <= 0 || model.String(point, "Unit") != spec.unit || seen[at.UTC().Format(time.RFC3339Nano)] {
					return out, awsservice.ErrEvidence
				}
				seen[at.UTC().Format(time.RFC3339Nano)] = true
				observed++
				out.Rows = append(out.Rows, model.Document{"metric": spec.name, "namespace": spec.namespace, "statistic": spec.statistic, "value": val.FloatString(12), "native_value": value, "unit": spec.unit, "period_seconds": 3600, "sample_count": cnt.FloatString(12), "native_sample_count": count, "source_time": at.UTC().Format(time.RFC3339Nano), "provider_resource_id": out.ProviderResourceID, "dimensions": spec.dimensions, "source_resolution": "RETAINED_HOURLY_PERIOD_STATISTIC", "raw_page_sha256": awsservice.Hash(v)})
			}
			left = right
		}
		if !bad && observed != int(end.Sub(start)/time.Hour) {
			out.ReasonCodes = append(out.ReasonCodes, "AWS_SERVICE_METRIC_"+strings.ToUpper(spec.name)+"_COVERAGE_GAPS")
		}
	}
	sort.Slice(out.Rows, func(a, b int) bool { return awsservice.Hash(out.Rows[a]) < awsservice.Hash(out.Rows[b]) })
	out.Raw, _ = json.Marshal(model.Document{"schema_version": "AWS_SERVICE_CLOUDWATCH_V1", "scope": out.Scope, "provider_resource_id": out.ProviderResourceID, "start": start, "end": end, "period_seconds": strconv.Itoa(out.PeriodSeconds), "frames": r.frames})
	if len(out.Raw) > awsservice.MaxCaptureBytes {
		return out, awsservice.ErrEvidence
	}
	out.RawSHA256 = awsservice.BytesHash(out.Raw)
	return out, nil
}
