package workflow

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/provider"
)

func TestAWSAccountCommissioningReadinessDoesNotManufactureEvidence(t *testing.T) {
	request := model.Document{"id": "preflight-a", "cloud_account_id": "account-a", "cloud_account_version": 1, "account_id": "111122223333", "region": "eu-west-1", "read_role_binding_id": "fixture-aws-readonly"}
	probe, e := provider.FixtureAWSAccountReadPreflight(provider.AWSAccountProbeRequest{TenantID: "tenant-a", AccountID: "111122223333", Region: "eu-west-1", ExpectedRoleARN: "arn:aws:iam::111122223333:role/FixtureReadOnlyRole", ExternalIDConfigured: true})
	if e != nil {
		t.Fatal(e)
	}
	dimensions := []model.Document{}
	for _, key := range []string{"BILLING", "METRICS", "OWNERSHIP", "WORKLOAD_MAPPING", "CONFIGURATION_AUTHORITY", "COMMITMENT_EVIDENCE", "RECOMMENDATION_COVERAGE", "DATA_QUALITY"} {
		dimensions = append(dimensions, model.Document{"key": key, "status": "NOT_CONFIGURED", "reason_codes": []string{"MISSING_TRUSTED_EVIDENCE"}, "affected_spend": nil})
	}
	report := buildAWSCommissioningReport("tenant-a", request, probe, model.Document{"dimensions": dimensions, "coverage": model.Document{"complete": false, "currencies": []model.Document{}}}, model.Document{"version_id": "version-a"})
	if report["summary_state"] != "READ_ONLY_READY" || report["provider_mode"] != "DETERMINISTIC_FIXTURE" || report["execution_authorized"] != false || report["verified_saving"] != nil {
		t.Fatal("access probe promoted missing economic evidence")
	}
	if len(commissioningDimensions(report["dimensions"])) != 10 {
		t.Fatal("missing dimensions")
	}
	credentials := commissioningDocument(report["execution_credentials"])
	if credentials["status"] != "UNKNOWN" {
		t.Fatal("ingester guessed executor credential state")
	}
	hash := report["content_hash"]
	delete(report, "content_hash")
	raw, _ := json.Marshal(report)
	sum := sha256.Sum256(raw)
	if hash != hex.EncodeToString(sum[:]) {
		t.Fatal("report hash does not bind immutable content")
	}
	dimensions[7]["status"] = "PARTIAL"
	report = buildAWSCommissioningReport("tenant-a", request, probe, model.Document{"dimensions": dimensions}, nil)
	if report["summary_state"] != "READ_ONLY_READY" {
		t.Fatal("missing-data partial status invented recommendation authority")
	}
	dimensions[6]["status"] = "PARTIAL"
	report = buildAWSCommissioningReport("tenant-a", request, probe, model.Document{"dimensions": dimensions}, nil)
	if report["summary_state"] != "RECOMMENDATION_PARTIAL" {
		t.Fatal("persisted partial economic coverage hidden")
	}
	for i := range dimensions {
		dimensions[i]["status"] = "READY"
	}
	for i := range probe.Classes {
		probe.Classes[i].Status = "READY"
	}
	report = buildAWSCommissioningReport("tenant-a", request, probe, model.Document{"dimensions": dimensions}, nil)
	if report["summary_state"] != "RECOMMENDATION_READY" {
		t.Fatal("complete scoped readiness not represented")
	}
	probe.Identity.Status = "DENIED"
	report = buildAWSCommissioningReport("tenant-a", request, probe, model.Document{"dimensions": dimensions}, nil)
	if report["summary_state"] != "NOT_READY" {
		t.Fatal("identity failure allowed readiness")
	}
}
