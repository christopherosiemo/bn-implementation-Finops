package commitmentportfolio

import (
	"testing"
	"time"
)

func sampleString(v string) *string { return &v }

// Typed model-contract fixture only. This does not issue native billing facts;
// the separate provider/Pipeline/PG fixture proves that connected boundary.
func modelContractFixture() (Input, Analysis) {
	now := time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC)
	left, right := now.AddDate(0, 0, -30), now.AddDate(0, 0, 1)
	yes := true
	in := Input{SchemaVersion: "1", RequestID: "request", TenantID: "tenant", PayerAccountID: "111122223333", UsageAccountIDs: []string{"111122223333"}, Selection: Selection{SourceID: "source", CommitmentReceiptID: "receipt", BillingReceiptIDs: []string{"bill"}, Period: Period{now.AddDate(0, 0, -1), now}}, InputRefs: []Ref{}, InventoryStatus: "COMPLETE_POINT_IN_TIME", BillingStatus: "COMPLETE_OBSERVED_WINDOW", ObservedAt: now, OptimizationOrder: []OptimizationStage{}, Billing: []BillingLine{}}
	p := Position{ID: "plan", AccountID: "111122223333", Class: "COMPUTE_SAVINGS_PLAN", State: "active", Currency: sampleString("USD"), Start: &left, End: &right, HourlyCommitment: sampleString("2"), ReasonCodes: []string{}}
	in.Positions = []Position{p}
	out := Analysis{SchemaVersion: "1", RequestID: in.RequestID, Selection: in.Selection, InputRefs: in.InputRefs, ObservedAt: now, InventoryStatus: in.InventoryStatus, BillingStatus: in.BillingStatus, UnmatchedBilling: []UnmatchedBilling{}, RecommendationStatus: "BLOCKED", ReasonCodes: []string{"NO_PURCHASE_OR_EXECUTION_AUTHORITY"}}
	out.Positions = []PositionAnalysis{{Position: p, Expiry: Expiry{Status: "ACTIVE", RemainingSeconds: sampleString("86400"), WithinDays: 30, ExpiresWithinWindow: &yes}, ObservedBilledCost: sampleString("48"), ObservedCommittedCost: sampleString("48"), ObservedUsedCommitment: sampleString("24"), ObservedUnusedCommitment: sampleString("24"), Utilization: sampleString("0.5"), DownsideIfZeroUsageObservedWindow: sampleString("48"), CommitmentCostBasis: "NATIVE_SP_HOURLY_TOTAL_AND_USED_COMMITMENT", Status: "OBSERVED_PARTIAL", ReasonCodes: []string{"FORECAST_CONFIDENCE_UNAVAILABLE"}}}
	out.Partitions = []Partition{{Class: p.Class, Currency: p.Currency, AccountID: p.AccountID, PositionIDs: []string{p.ID}, PositionCount: 1, ObservedBilledCost: sampleString("48"), ObservedCommittedCost: sampleString("48"), ObservedUsedCommitment: sampleString("24"), ObservedUnusedCommitment: sampleString("24"), Utilization: sampleString("0.5"), ExpiringPositionIDs: []string{p.ID}, HourlyCommitmentRate: sampleString("2"), HourlyCommitmentRateUnit: "currency/hour", PositionShares: []PositionShare{{PositionID: p.ID, Share: sampleString("1")}}, ConcentrationBasis: "NATIVE_HOURLY_COMMITMENT_RATE"}}
	for _, stage := range []string{"REMOVE_IDLE", "SCHEDULE", "RIGHTSIZE", "AUTOSCALE", "RECALCULATE_STABLE_DEMAND"} {
		out.OptimizationOrder = append(out.OptimizationOrder, OptimizationStage{Stage: stage, Status: "BLOCKED", ReasonCodes: []string{"ISSUED_OPTIMIZATION_OUTCOME_UNAVAILABLE"}})
	}
	out.ID = Hash(out)
	return in, out
}
func TestPortfolioResultRefusesResealedAuthorityMoneyAndPartitionChanges(t *testing.T) {
	in, out := modelContractFixture()
	if validateAnalysis(in, out) != nil {
		t.Fatal("valid typed model contract refused")
	}
	changes := []func(*Analysis){func(a *Analysis) { a.PurchaseAuthorized = true }, func(a *Analysis) { a.Positions[0].EffectiveDiscount = sampleString("0.5") }, func(a *Analysis) { a.Positions[0].Utilization = sampleString("-0.1") }, func(a *Analysis) { a.Positions[0].ObservedCommittedCost = sampleString("NaN") }, func(a *Analysis) { a.Partitions[0].Currency = sampleString("EUR") }, func(a *Analysis) { a.Partitions[0].PositionShares = nil }, func(a *Analysis) { a.Partitions[0].ObservedBilledCost = sampleString("49") }, func(a *Analysis) { a.OptimizationOrder[0].Stage = "PURCHASE" }, func(a *Analysis) { a.Positions[0].Position.AccountID = "999999999999" }, func(a *Analysis) { a.Positions[0].AllocatedCostBasis = sampleString("SYNTHETIC") }}
	for _, change := range changes {
		in, out := modelContractFixture()
		change(&out)
		out.ID = ""
		out.ID = Hash(out)
		if validateAnalysis(in, out) == nil {
			t.Fatal("resealed malformed model result accepted")
		}
	}
	out.ID = "not-a-sha"
	if validateAnalysis(in, out) == nil {
		t.Fatal("unbound model ID accepted")
	}
}
func TestReservedInstanceReferenceRequiresExactIssuedIdentity(t *testing.T) {
	position := Position{ID: "111122223333:ri:00000000-0000-4000-8000-000000000001", AccountID: "111122223333", Region: sampleString("eu-west-1"), ReservedInstanceTerms: &ReservedInstanceTerms{}}
	native := "arn:aws:ec2:eu-west-1:111122223333:reserved-instances/00000000-0000-4000-8000-000000000001"
	if selectedCommitmentIdentity(native, []Position{position}) != position.ID {
		t.Fatal("exact native RI ARN did not resolve")
	}
	for _, foreign := range []string{"arn:aws:ec2:eu-west-1:999999999999:reserved-instances/00000000-0000-4000-8000-000000000001", "arn:aws:ec2:us-east-1:111122223333:reserved-instances/00000000-0000-4000-8000-000000000001", native + "/other", native + "?suffix=true"} {
		if selectedCommitmentIdentity(foreign, []Position{position}) != foreign {
			t.Fatal("foreign ARN suffix acquired current native identity")
		}
	}
}
