package service

import (
	"testing"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
)

func TestFargateCURManagedIdentityDoesNotInventServiceBilling(t *testing.T) {
	arn := "arn:aws:ecs:eu-west-1:111122223333:task/orders/task-a"
	resource := model.Document{"account_id": "111122223333", "region": "eu-west-1", "provider_resource_id": "arn:aws:ecs:eu-west-1:111122223333:service/orders/web"}
	cfg := model.Document{"clusterArn": "arn:aws:ecs:eu-west-1:111122223333:cluster/orders", "serviceName": "web"}
	tasks := map[string]model.Document{arn: {}}
	row := model.Document{"ResourceId": arn, "x_ProviderFields": model.Document{"resource_tags": `{"aws:ecs:clusterName":"orders","aws:ecs:serviceName":"web"}`, "product_servicecode": "AmazonECS", "line_item_operation": "FargateTask"}}
	if matched, unknown := fargateCURMatches(resource, cfg, row, tasks); !matched || unknown {
		t.Fatal("native managed identity rejected")
	}
	for _, tags := range []string{`{}`, `{"aws:ecs:clusterName":"other","aws:ecs:serviceName":"web"}`, `{"aws:ecs:clusterName":"orders","aws:ecs:serviceName":"foreign"}`, `{"aws:ecs:clusterName":"orders","aws:ecs:clusterName":"orders","aws:ecs:serviceName":"web"}`} {
		bad := model.Clone(row)
		raw := storageObject(bad["x_ProviderFields"])
		raw["resource_tags"] = tags
		bad["x_ProviderFields"] = raw
		if matched, unknown := fargateCURMatches(resource, cfg, bad, tasks); matched || !unknown {
			t.Fatal("missing/conflicting historical tags accepted")
		}
	}
	bad := model.Clone(row)
	bad["ResourceId"] = resource["provider_resource_id"]
	if matched, unknown := fargateCURMatches(resource, cfg, bad, tasks); matched || !unknown {
		t.Fatal("invented service ARN accepted as native task billing")
	}
}

func TestFargateBillingRequiresExactContinuousQuantities(t *testing.T) {
	start := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	end := start.Add(2 * time.Hour)
	tasks := map[string]model.Document{"native-task": {}}
	cfg := model.Document{"task_definition": model.Document{"cpu": "1024", "memory": "2048"}}
	makeRow := func(component string, at time.Time) model.Document {
		quantity, usage := "1", "EU-Fargate-vCPU-Hours"
		if component == "memory" {
			quantity, usage = "2", "EU-Fargate-GB-Hours"
		}
		return model.Document{"ResourceId": "native-task", "ChargePeriodStart": at.Format(time.RFC3339), "ChargePeriodEnd": at.Add(time.Hour).Format(time.RFC3339), "x_ProviderFields": model.Document{"product_servicecode": "AmazonECS", "line_item_usage_type": usage, "line_item_usage_amount": quantity}}
	}
	coverage := fargateBillingCoverage{}
	for at := start; at.Before(end); at = at.Add(time.Hour) {
		for _, component := range []string{"cpu", "memory"} {
			if !coverage.observe(makeRow(component, at), cfg) {
				t.Fatal("exact quantity rejected")
			}
		}
	}
	if !coverage.complete(tasks, start, end) {
		t.Fatal("complete native billing rejected")
	}
	coverage.observe(makeRow("cpu", start), cfg)
	if coverage.complete(tasks, start, end) {
		t.Fatal("overlapping compute interval counted twice")
	}
	bad := makeRow("cpu", start)
	raw := storageObject(bad["x_ProviderFields"])
	raw["line_item_usage_amount"] = "0.5"
	bad["x_ProviderFields"] = raw
	if (fargateBillingCoverage{}).observe(bad, cfg) {
		t.Fatal("different historical configuration quantity accepted")
	}
}

func TestAWSServiceCoverageTaskChargeClaimsAreExactAndCurrencyBound(t *testing.T) {
	publications := map[string]lambdaCoveragePublication{"line:source-revision:cpu": {currency: "GBP", lines: map[string]bool{"source-revision:cpu": true}}}
	if category, ok := awsServiceCoverageLineCategory(publications, "source-revision:cpu", "GBP"); !ok || category != "analysed_spend" {
		t.Fatal("exact service→task claim lost")
	}
	if _, ok := awsServiceCoverageLineCategory(publications, "other-revision:cpu", "GBP"); ok {
		t.Fatal("unrelated revision promoted")
	}
	if category, ok := awsServiceCoverageLineCategory(publications, "source-revision:cpu", "USD"); !ok || category != "blocked_spend" {
		t.Fatal("currency confusion promoted")
	}
}
