package provider

import (
	"context"
	"math/big"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/network"
)

type networkMetricSpec struct{ name, unit, stat string }

var networkNATMetrics = []networkMetricSpec{
	{"BytesInFromSource", "Bytes", "Sum"}, {"BytesOutToDestination", "Bytes", "Sum"}, {"BytesInFromDestination", "Bytes", "Sum"}, {"BytesOutToSource", "Bytes", "Sum"},
	{"PacketsInFromSource", "Count", "Sum"}, {"PacketsOutToDestination", "Count", "Sum"}, {"PacketsInFromDestination", "Count", "Sum"}, {"PacketsOutToSource", "Count", "Sum"},
	{"ActiveConnectionCount", "Count", "Maximum"}, {"ConnectionAttemptCount", "Count", "Sum"}, {"ConnectionEstablishedCount", "Count", "Sum"}, {"ErrorPortAllocation", "Count", "Sum"}, {"PacketsDropCount", "Count", "Sum"}, {"IdleTimeoutCount", "Count", "Sum"},
	{"PeakBytesPerSecond", "Count", "Maximum"}, {"PeakPacketsPerSecond", "Count", "Maximum"},
}

// NetworkNATMetrics retains all four byte metrics independently. An economics
// consumer must choose one non-overlapping traffic pair (input source plus input
// destination), not sum the four views of the same packets.
func (a *AWS) NetworkNATMetrics(ctx context.Context, s network.Scope, sel network.MetricSelection) (network.MetricEvidence, error) {
	out := network.MetricEvidence{SchemaVersion: "NETWORK_NAT_METRICS_V1", Scope: s, Selection: sel, Metrics: []model.Document{}, Coverage: []model.Document{}}
	r, e := newNetworkRead(a, s)
	if e != nil {
		return out, e
	}
	now := time.Now().UTC()
	p := sel.PeriodSeconds
	if !strings.HasPrefix(sel.NATGatewayID, "nat-") || len(sel.NATGatewayID) > 64 || (p != 60 && p != 300 && p != 3600) || sel.Start.IsZero() || !sel.Start.Before(sel.End) || sel.End.After(now.Truncate(time.Minute)) || sel.End.Sub(sel.Start) > 90*24*time.Hour || sel.Start.Unix()%int64(p) != 0 || sel.End.Unix()%int64(p) != 0 || sel.Start.Nanosecond() != 0 || sel.End.Nanosecond() != 0 || p == 60 && sel.Start.Before(now.Add(-15*24*time.Hour)) || p == 300 && sel.Start.Before(now.Add(-63*24*time.Hour)) {
		return out, network.ErrEvidence
	}
	_, offset := sel.Start.Zone()
	_, endOffset := sel.End.Zone()
	if offset != 0 || endOffset != 0 {
		return out, network.ErrEvidence
	}
	raw, e := r.query(ctx, "DescribeNatGateways", url.Values{"NatGatewayId.1": {sel.NATGatewayID}})
	if e != nil {
		return out, e
	}
	n, e := ebsTree(raw, "DescribeNatGateways")
	if e != nil || len(n.list("natGatewaySet")) != 1 || n.list("natGatewaySet")[0].value("natGatewayId") != sel.NATGatewayID {
		return out, network.ErrEvidence
	}
	nat := n.list("natGatewaySet")[0]
	mode := nat.value("availabilityMode")
	if mode == "regional" {
		found := false
		for _, address := range nat.list("natGatewayAddressSet") {
			if address.value("availabilityZone") == sel.AvailabilityZone && sel.AvailabilityZone != "" {
				found = true
			}
		}
		if !found {
			return out, network.ErrEvidence
		}
	} else if mode != "zonal" || sel.AvailabilityZone != "" {
		return out, network.ErrEvidence
	}
	expected := int(sel.End.Sub(sel.Start) / time.Duration(p) / time.Second)
	for _, spec := range networkNATMetrics {
		points := map[int64]bool{}
		zero, withoutCount := 0, 0
		unavailable := false
		reason := ""
		for start := sel.Start; start.Before(sel.End); {
			end := start.Add(time.Duration(1440*p) * time.Second)
			if end.After(sel.End) {
				end = sel.End
			}
			v := url.Values{"Namespace": {"AWS/NATGateway"}, "MetricName": {spec.name}, "Dimensions.member.1.Name": {"NatGatewayId"}, "Dimensions.member.1.Value": {sel.NATGatewayID}, "StartTime": {start.Format(time.RFC3339)}, "EndTime": {end.Format(time.RFC3339)}, "Period": {strconv.Itoa(p)}, "Statistics.member.1": {spec.stat}, "Statistics.member.2": {"SampleCount"}, "Unit": {spec.unit}}
			if mode == "regional" {
				v.Set("Dimensions.member.2.Name", "AvailabilityZone")
				v.Set("Dimensions.member.2.Value", sel.AvailabilityZone)
			}
			raw, e := r.query(ctx, "GetMetricStatistics", v)
			if e != nil {
				unavailable = true
				reason = "NAT_METRIC_UNAVAILABLE"
				break
			}
			root, e := ebsTree(raw, "GetMetricStatistics")
			if e != nil {
				return out, network.ErrEvidence
			}
			result := root.get("GetMetricStatisticsResult")
			if result == nil || result.get("Datapoints") == nil {
				return out, network.ErrEvidence
			}
			for _, point := range result.list("Datapoints") {
				at, e := time.Parse(time.RFC3339Nano, point.value("Timestamp"))
				value := point.value(spec.stat)
				number, ok := new(big.Rat).SetString(value)
				if e != nil || at.Before(start) || !at.Before(end) || at.Nanosecond() != 0 || at.Unix()%int64(p) != 0 || points[at.Unix()] || !ok || number.Sign() < 0 || point.value("Unit") != spec.unit {
					return out, network.ErrEvidence
				}
				var count any
				observed := false
				if point.get("SampleCount") != nil {
					c, ok := rdsMetricCount(point.value("SampleCount"))
					if !ok {
						return out, network.ErrEvidence
					}
					count = c
					observed = c > 0
				}
				if !observed {
					withoutCount++
				} else if number.Sign() == 0 {
					zero++
				}
				points[at.Unix()] = true
				dimensions := model.Document{"NatGatewayId": sel.NATGatewayID}
				if mode == "regional" {
					dimensions["AvailabilityZone"] = sel.AvailabilityZone
				}
				out.Metrics = append(out.Metrics, model.Document{"metric": spec.name, "namespace": "AWS/NATGateway", "resource_id": sel.NATGatewayID, "dimensions": dimensions, "timestamp": at, "period_seconds": p, "statistic": spec.stat, "value": value, "unit": spec.unit, "sample_count": count, "observed": observed, "raw_page_sha256": network.BytesHash(raw), "byte_count_basis": "NATIVE_METRIC_INDEPENDENT_NOT_SUM_OF_FOUR_DIRECTIONS"})
			}
			start = end
		}
		status := "GAPS"
		if unavailable {
			status = "UNAVAILABLE"
		} else if len(points) == expected && withoutCount == 0 {
			status = "COMPLETE_OBSERVED"
			if zero == expected {
				status = "COMPLETE_ZERO_OBSERVED"
			}
		}
		out.Coverage = append(out.Coverage, model.Document{"metric": spec.name, "statistic": spec.stat, "period_seconds": p, "expected_periods": expected, "observed_periods": len(points), "missing_periods": expected - len(points), "periods_without_positive_sample_count": withoutCount, "status": status, "reason_code": reason, "missing_is_zero": false})
	}
	sort.Slice(out.Metrics, func(i, j int) bool {
		return model.String(out.Metrics[i], "metric")+out.Metrics[i]["timestamp"].(time.Time).Format(time.RFC3339) < model.String(out.Metrics[j], "metric")+out.Metrics[j]["timestamp"].(time.Time).Format(time.RFC3339)
	})
	out.Raw = r.raw()
	out.RawSHA256 = network.BytesHash(out.Raw)
	return out, nil
}
