package service

import (
	"slices"
	"testing"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/evidence"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
)

func TestRecommendationCurrentnessProjectionQualifiesImmutableHistory(t *testing.T) {
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	original := model.Document{"id": "historical-review", "status": "VALIDATED", "pre_execution_ready": true, "monthly_saving": "12.340000000001", "currency": "GBP", "expires_at": now.Add(time.Hour).Format(time.RFC3339Nano), "assessment": model.Document{"status": "RECOMMENDED", "economics": model.Document{"estimated_window_saving": "12.340000000001"}}}
	originalHash := evidence.Hash(original)
	for _, scenario := range []struct {
		name, reason, status string
		selected             model.Document
		git                  string
	}{
		{"unchanged", "", "CURRENT", model.Document{"baseline": model.Document{"financial_sources": "same-native-head"}, "current": model.Document{"financial_sources": "same-native-head"}}, ""},
		{"corrected_money", "BILLING_SOURCE_CHANGED_OR_REVOKED", "STALE", model.Document{"baseline": model.Document{"financial_sources": "original-native-head"}, "current": model.Document{"financial_sources": "corrected-native-head"}}, ""},
		{"telemetry_revoked", "TELEMETRY_REVISION_CHANGED_OR_REVOKED", "STALE", model.Document{"baseline": model.Document{"telemetry": "active"}, "current": model.Document{"telemetry": "revoked"}}, ""},
		{"git_changed", "IAC_REVISION_CHANGED", "STALE", model.Document{"baseline": model.Document{}, "current": model.Document{}}, "IAC_REVISION_CHANGED"},
		{"git_unavailable", "IAC_REVISION_UNAVAILABLE", "BLOCKED", model.Document{"baseline": model.Document{}, "current": model.Document{}}, "IAC_REVISION_UNAVAILABLE"},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			view := recommendationCurrentnessProjection(original, scenario.selected, nil, scenario.git, now)
			state := storageObject(view["currentness"])
			if state["status"] != scenario.status || state["checked_at"] != now.Format(time.RFC3339Nano) {
				t.Fatal("incorrect current evidence state", state)
			}
			if scenario.reason != "" && (!slices.Contains(model.Strings(state, "reason_codes"), scenario.reason) || view["pre_execution_ready"] != false || view["current"] != false || view["execution_authorized"] != false) {
				t.Fatal("unavailable assumptions retained action eligibility", state)
			}
			if scenario.status == "STALE" && !slices.Contains(model.Strings(state, "reason_codes"), "STALE_RECOMMENDATION") {
				t.Fatal("stale result lacks canonical explanation")
			}
			if scenario.name == "corrected_money" && state["economics_recompute"] != true {
				t.Fatal("billing correction did not require economic recomputation")
			}
			if scenario.name == "telemetry_revoked" && state["telemetry_recollect"] != true {
				t.Fatal("revoked telemetry did not require fresh evidence")
			}
			if scenario.git != "" && state["iac_changed"] != true {
				t.Fatal("IaC uncertainty or change hidden")
			}
			if view["monthly_saving"] != original["monthly_saving"] || evidence.Hash(view["assessment"]) != evidence.Hash(original["assessment"]) || evidence.Hash(original) != originalHash {
				t.Fatal("presentation currentness rewrote historical economics")
			}
		})
	}
	expired := model.Clone(original)
	expired["expires_at"] = now.Format(time.RFC3339Nano)
	if view := recommendationCurrentnessProjection(expired, nil, nil, "", now); storageObject(view["currentness"])["status"] != "EXPIRED" || view["pre_execution_ready"] != false {
		t.Fatal("expired recommendation remained current or actionable")
	}
}

func TestRecommendationCurrentnessCannotPromoteStaleExactBillingClaims(t *testing.T) {
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	publication := model.Document{"id": "service-assessment", "status": "ASSESSED", "pre_execution_ready": false, "execution_authorized": false, "verified_saving": nil}
	selected := model.Document{"baseline": model.Document{"financial_sources": "head-v1"}, "current": model.Document{"financial_sources": "head-v1"}}
	const line = "source-revision:exact-cpu-line"
	classify := func(projected model.Document) string {
		// The ordinary coverage reader sets blocked from its current family
		// projection before permitting any immutable exact-line attribution.
		p := lambdaCoveragePublication{blocked: projected["current"] != true, currency: "GBP", lines: map[string]bool{line: true}}
		category, found := awsServiceCoverageLineCategory(map[string]lambdaCoveragePublication{"line:" + line: p}, line, "GBP")
		if !found {
			t.Fatal("exact native charge disappeared from coverage")
		}
		return category
	}
	if category := classify(recommendationCurrentnessProjection(publication, selected, nil, "", now)); category != "analysed_spend" {
		t.Fatal("unchanged exact billing claim lost analysis classification", category)
	}
	selected["current"] = model.Document{"financial_sources": "head-v2-corrected"}
	if category := classify(recommendationCurrentnessProjection(publication, selected, nil, "", now)); category != "blocked_spend" {
		t.Fatal("stale economics inflated current analysed coverage", category)
	}
}

func TestFleetCurrentnessPresentationPreservesNonExecutableAnalysis(t *testing.T) {
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	for _, key := range []string{"assessment", "batch", "decision", "member"} {
		t.Run(key, func(t *testing.T) {
			d := model.Document{"id": "historical-fleet-read", "status": "ASSESSED", "execution_authorized": false, "verified_saving": nil, key: model.Document{"status": "BLOCKED", "scenario": model.Document{"hourly_compute_difference": "0.123456789012", "estimated_saving": nil}}}
			hash := evidence.Hash(d)
			unchanged := fleetAnalysisCurrentnessProjection(d, []string{"LEGACY_RECOMMENDATION_CONTEXT_UNAVAILABLE"}, now)
			if storageObject(unchanged["currentness"])["status"] != "BLOCKED" || unchanged["execution_authorized"] != false {
				t.Fatal("historical fleet analysis gained execution eligibility")
			}
			if !slices.Contains(model.Strings(storageObject(unchanged["currentness"]), "reason_codes"), "LEGACY_RECOMMENDATION_CONTEXT_UNAVAILABLE") {
				t.Fatal("missing historical owner, policy and SLO context hidden")
			}
			stale := fleetAnalysisCurrentnessProjection(d, []string{"LEGACY_RECOMMENDATION_CONTEXT_UNAVAILABLE", "FLEET_CONFIGURATION_OR_NATIVE_SOURCE_CHANGED"}, now)
			if storageObject(stale["currentness"])["status"] != "STALE" || stale["current"] != false || stale["execution_authorized"] != false || stale["verified_saving"] != nil {
				t.Fatal("changed fleet evidence remained current")
			}
			if evidence.Hash(stale[key]) != evidence.Hash(d[key]) || evidence.Hash(d) != hash {
				t.Fatal("fleet currentness rewrote immutable analysis or economics")
			}
		})
	}
}
