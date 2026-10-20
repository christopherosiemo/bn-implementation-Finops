package service

import (
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"testing"
)

func TestDatabaseProviderComparisonNeverAdoptsProviderSavings(t *testing.T) {
	resource := model.Document{"provider_resource_id": "arn:rds", "account_id": "111122223333", "database_configuration": model.Document{"class": "large", "engine": "postgres", "engine_version": "16.4"}}
	provider := model.Document{"resourceArn": "arn:rds", "accountId": "111122223333", "currentDBInstanceClass": "large", "engine": "postgres", "engineVersion": "16.4", "instanceRecommendationOptions": []model.Document{{"rank": 1, "dbInstanceClass": "small", "savingsOpportunity": model.Document{"estimatedMonthlySavings": model.Document{"value": 999999}}}}}
	canonical := model.Document{"compute_optimizer": model.Document{"recommendations": []model.Document{provider}}}
	assessment := model.Document{"status": "RECOMMENDED", "candidate_configuration": model.Document{"class_id": "small"}, "economics": model.Document{"estimated_monthly_saving": "1.23"}}
	out := databaseProviderComparison(resource, canonical, assessment)
	if out["difference"] != "MATCH" || databaseObject(assessment["economics"])["estimated_monthly_saving"] != "1.23" {
		t.Fatal("supporting recommendation acquired financial authority", out)
	}
	assessment["status"] = "BLOCKED"
	if databaseProviderComparison(resource, canonical, assessment)["difference"] != "UNAVAILABLE" {
		t.Fatal("provider advice overrode our blocker")
	}
	provider["accountId"] = "999999999999"
	if databaseProviderComparison(resource, canonical, assessment)["difference"] != "UNAVAILABLE" {
		t.Fatal("foreign provider advice compared")
	}
}
