package provider

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/awsservice"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
)

func TestAWSServiceMetricsNativePeriodsDimensionsAndMissingSignals(t *testing.T) {
	start := time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC)
	end := start.Add(time.Hour)
	arn := "arn:aws:dynamodb:eu-west-1:111122223333:table/actual"
	tr := &serviceTestTransport{}
	tr.handle = func(r *http.Request, _ model.Document, p url.Values) (string, int) {
		if r.URL.Host != "monitoring.eu-west-1.amazonaws.com" || p.Get("Action") != "GetMetricStatistics" || p.Get("Dimensions.member.1.Name") != "TableName" || p.Get("Dimensions.member.1.Value") != "actual" {
			t.Fatal("native metric scope changed")
		}
		if p.Get("MetricName") == "ThrottledRequests" {
			return serviceTestXML("GetMetricStatistics", "<Label>ThrottledRequests</Label><Datapoints/>")
		}
		stat := p.Get("Statistics.member.1")
		return serviceTestXML("GetMetricStatistics", fmt.Sprintf("<Label>%s</Label><Datapoints><member><Timestamp>%s</Timestamp><%s>0</%s><SampleCount>60</SampleCount><Unit>Count</Unit></member></Datapoints>", p.Get("MetricName"), start.Format(time.RFC3339), stat, stat))
	}
	resource := model.Document{"provider_resource_id": arn, "account_id": "111122223333", "region": "eu-west-1", "service_family": "DYNAMODB", "resource_type": "DYNAMODB_TABLE", "aws_service_configuration": model.Document{"TableName": "actual"}}
	got, err := serviceTestAWS(tr).ServiceMetrics(context.Background(), serviceTestRegistration(), resource, start, end)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Rows) != 8 || len(got.ExpectedSeries) != 9 || len(got.ReasonCodes) != 1 || !strings.Contains(got.ReasonCodes[0], "THROTTLEDREQUESTS_COVERAGE_GAPS") {
		t.Fatalf("missing is not a manufactured zero: rows=%d expected=%d reasons=%v", len(got.Rows), len(got.ExpectedSeries), got.ReasonCodes)
	}
	for _, row := range got.Rows {
		if row["value"] != "0.000000000000" || row["provider_resource_id"] != arn || row["period_seconds"] != 3600 || row["sample_count"] != "60.000000000000" {
			t.Fatal("native period, quantity or binding lost")
		}
	}
	if len(got.Raw) == 0 || got.RawSHA256 != awsservice.BytesHash(got.Raw) {
		t.Fatal("missing immutable metric provenance")
	}
}

func TestAWSServiceMetricsRejectDuplicateAndForeignPoints(t *testing.T) {
	start := time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC)
	resource := model.Document{"provider_resource_id": "arn:aws:dynamodb:eu-west-1:111122223333:table/actual", "account_id": "111122223333", "region": "eu-west-1", "service_family": "DYNAMODB", "resource_type": "DYNAMODB_TABLE", "aws_service_configuration": model.Document{"TableName": "actual"}}
	tr := &serviceTestTransport{handle: func(_ *http.Request, _ model.Document, p url.Values) (string, int) {
		stat := p.Get("Statistics.member.1")
		point := fmt.Sprintf("<member><Timestamp>%s</Timestamp><%s>0</%s><SampleCount>60</SampleCount><Unit>Count</Unit></member>", start.Format(time.RFC3339), stat, stat)
		return serviceTestXML("GetMetricStatistics", "<Datapoints>"+point+point+"</Datapoints>")
	}}
	if _, err := serviceTestAWS(tr).ServiceMetrics(context.Background(), serviceTestRegistration(), resource, start, start.Add(time.Hour)); err == nil {
		t.Fatal("duplicate native bins accepted")
	}
	resource["account_id"] = "999900001111"
	if _, err := serviceTestAWS(tr).ServiceMetrics(context.Background(), serviceTestRegistration(), resource, start, start.Add(time.Hour)); err == nil {
		t.Fatal("foreign account accepted")
	}
}

func TestAWSServiceCacheGroupMetricSelectorsPreserveReplicaTopology(t *testing.T) {
	resource := model.Document{"resource_type": "ELASTICACHE_REPLICATION_GROUP", "aws_service_configuration": model.Document{"NodeGroups": model.Document{"NodeGroup": []model.Document{{"NodeGroupMembers": model.Document{"NodeGroupMember": []model.Document{{"CacheClusterId": "primary", "CacheNodeId": "0001", "CurrentRole": "primary"}, {"CacheClusterId": "replica", "CacheNodeId": "0001", "CurrentRole": "replica"}}}}}}}}
	specs := serviceMetricSpecs(resource)
	counts := map[string]int{}
	for _, spec := range specs {
		counts[spec.name]++
		if spec.name == "ReplicationLag" && spec.dimensions["CacheClusterId"] != "replica" {
			t.Fatal("primary does not supply replica lag")
		}
	}
	if counts["CPUUtilization"] != 2 || counts["DatabaseMemoryUsagePercentage"] != 2 || counts["ReplicationLag"] != 1 {
		t.Fatalf("replication group was flattened: %v", counts)
	}
}
