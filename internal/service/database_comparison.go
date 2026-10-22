package service

import (
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"math/big"
)

// This compares class choices only. Provider opportunity amounts, confidence
// and list prices never become the product's financial or safety evidence.
func databaseProviderComparison(resource, canonical, assessment model.Document) model.Document {
	provider := databaseObject(canonical["compute_optimizer"])
	ours := model.Document{"status": assessment["status"], "recommendation_kind": assessment["recommendation_kind"], "candidate_configuration": assessment["candidate_configuration"]}
	result := model.Document{"provider_recommendation": nil, "our_recommendation": ours, "difference": "UNAVAILABLE", "reason_for_difference": "Provider advice is unavailable or not directly comparable to this evidence-bound class assessment."}
	rows := documentList(provider["recommendations"])
	if len(rows) == 0 {
		return result
	}
	result["provider_recommendation"] = rows
	if len(rows) != 1 {
		return result
	}
	row := rows[0]
	native := databaseObject(resource["database_configuration"])
	if model.String(row, "accountId") != model.String(resource, "account_id") || model.String(row, "resourceArn") != model.String(resource, "provider_resource_id") || model.String(row, "engine") != model.String(native, "engine") || model.String(row, "engineVersion") != model.String(native, "engine_version") || model.String(row, "currentDBInstanceClass") != model.String(native, "class") {
		return result
	}
	top := ""
	for _, option := range documentList(row["instanceRecommendationOptions"]) {
		rank, ok := databaseDecimal(option["rank"])
		if !ok || rank.Cmp(big.NewRat(1, 1)) != 0 {
			continue
		}
		class := model.String(option, "dbInstanceClass")
		if class == "" || top != "" {
			return result
		}
		top = class
	}
	if top == "" {
		return result
	}
	chosen := model.String(databaseObject(assessment["candidate_configuration"]), "class_id")
	if model.String(assessment, "status") == "BLOCKED" || chosen == "" {
		return result
	}
	if model.String(assessment, "status") == "RECOMMENDED" && top == chosen {
		result["difference"] = "MATCH"
		result["reason_for_difference"] = "The proposed class matches. Our economics and evidence requirements are evaluated independently; provider savings estimates are retained as supporting data only."
	} else {
		result["difference"] = "DIFFERENT"
		result["reason_for_difference"] = "The provider class choice differs from our assessed outcome. Review our workload, capacity, topology, source coverage and customer-economics checks before considering a change."
	}
	return result
}
