package service

import (
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"testing"
)

func TestAWSServiceCoverageRequiresExactAnalysedFinancialClosure(t *testing.T) {
	ref := model.Document{"kind": "AWS_CUR2_CONNECTION", "source_connection_id": "source", "source_receipt_id": "receipt", "ingestion_job_id": "job", "canonical_hash": "hash", "economic_record_ids": []string{"compute", "storage"}}
	makeResult := func() model.Document {
		return model.Document{"model_kind": "AWS_SERVICE_ASSESSMENT_V1", "family": "ECS", "status": "RECOMMENDED", "read_only": true, "pre_execution_ready": false, "execution_authorized": false, "verified_saving": nil, "economics": model.Document{"status": "NATIVE_CUSTOMER_ECONOMICS"}, "financial_references": []model.Document{ref}, "economically_analysed_source_record_ids": []string{"compute", "unrelated"}}
	}
	result := makeResult()
	lines := awsServiceCoverageLines(result)
	if len(lines) != 1 || !lines[databaseCoverageLineKey(ref, "compute")] {
		t.Fatal("coverage promoted unanalysed storage or unrelated billing")
	}
	for _, scenario := range []string{"operational_lb", "unknown_economics", "blocked", "execution", "verified"} {
		t.Run(scenario, func(t *testing.T) {
			r := makeResult()
			switch scenario {
			case "operational_lb":
				r["family"] = "ELB"
			case "unknown_economics":
				r["economics"] = model.Document{"status": "ECONOMICS_UNAVAILABLE"}
			case "blocked":
				r["status"] = "BLOCKED"
			case "execution":
				r["execution_authorized"] = true
			case "verified":
				r["verified_saving"] = "1"
			}
			if len(awsServiceCoverageLines(r)) != 0 {
				t.Fatal("unsupported financial authority promoted coverage")
			}
		})
	}
}

func TestAWSServiceNativeChargeDimensionsDoNotEraseContinuingCosts(t *testing.T) {
	cases := []struct{ service, usage, typ, want string }{{"AmazonECS", "EU-Fargate-vCPU-Hours", "Usage", "FARGATE_CPU"}, {"AmazonECS", "EU-Fargate-EphemeralStorage-GB-Hours", "Usage", "FARGATE_EPHEMERAL"}, {"AmazonDynamoDB", "EU-ReplicatedWriteCapacityUnit-Hrs", "Usage", "CONTINUING"}, {"AmazonDynamoDB", "EU-ReadCapacityUnit-Hrs", "Usage", "READ_PROVISIONED"}, {"AmazonElastiCache", "EU-NodeUsage:cache.r7g.large", "Usage", "CACHE_NODE"}, {"AmazonElastiCache", "EU-ServerlessCache:Storage", "Usage", "CONTINUING"}, {"AmazonDynamoDB", "EU-ReadCapacityUnit-Hrs", "Credit", "CREDIT"}}
	for _, c := range cases {
		raw := model.Document{"product_servicecode": c.service, "line_item_usage_type": c.usage, "line_item_line_item_type": c.typ}
		if got := awsServiceChargeComponent(raw); got != c.want {
			t.Fatalf("%s %s: %s", c.service, c.usage, got)
		}
	}
	if awsServiceChargeUnit("FARGATE_CPU", "GB-Hours") || awsServiceChargeUnit("READ_PROVISIONED", "Requests") {
		t.Fatal("incompatible customer rate units accepted")
	}
}
