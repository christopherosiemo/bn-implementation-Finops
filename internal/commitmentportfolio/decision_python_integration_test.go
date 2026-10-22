//go:build commitment_model_integration

package commitmentportfolio

// Actual typed Go -> private Python -> typed Go interoperability. Source,
// ownership and optimization inputs here are labelled synthetic unit doubles;
// successful arithmetic grants no native, Finance or product acceptance.
import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func TestCommitmentDecisionPythonTypedForecastAndAdvice(t *testing.T) {
	endpoint := os.Getenv("COMMITMENT_DECISION_MODEL_TEST_URL")
	if endpoint != "http://commitment-portfolio-model:8000" {
		t.Fatal("isolated model endpoint required")
	}
	token, err := os.ReadFile("/run/secrets/commitment-portfolio-model-token")
	if err != nil {
		t.Fatal("isolated model credential required")
	}
	calculator := HTTPCalculator{Endpoint: endpoint, Token: strings.TrimSpace(string(token)), Client: &http.Client{Timeout: 30 * time.Second}}
	str := func(v string) *string { return &v }
	ref := func(kind, id string) Ref { return Ref{Kind: kind, ID: "typed-unit-" + id, SHA256: Hash(id)} }
	now := time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC)
	history := Period{Start: now.Add(-24 * time.Hour), End: now}
	scope := DecisionScope{TenantID: "typed-unit-tenant", WorkloadID: "typed-unit-workload", PayerAccountID: "111122223333", UsageAccountIDs: []string{"111122223333"}, ResourceIDs: []string{"i-0123456789abcdef0"}, Class: "COMPUTE_SAVINGS_PLAN", Currency: "USD", ConfigurationSHA256: strings.Repeat("a", 64), OwnershipRef: ref("HISTORICAL_OWNERSHIP", "owner"), HistoryPeriod: history, ProjectionPeriod: Period{Start: now, End: now.Add(8760 * time.Hour)}}
	scope.SHA256 = Hash(scope)
	dims := Dimensions{AccountID: "111122223333", ServiceCode: "AmazonEC2", ProductType: "EC2", UsageType: "EU-BoxUsage:m6i.large", Operation: "RunInstances", Region: "eu-west-1", InstanceType: str("m6i.large"), InstanceFamily: str("m6i"), ProductDescription: str("Linux/UNIX"), Tenancy: str("Shared"), Unit: "Hrs", Currency: "USD"}
	cur, inventory := ref("AWS_CUR2", "billing"), ref("AWS_COMMITMENT", "inventory")
	portfolio := Analysis{SchemaVersion: "1", RequestID: "typed-unit-portfolio", Selection: Selection{SourceID: "typed-unit-source", CommitmentReceiptID: inventory.ID, BillingReceiptIDs: []string{cur.ID}, Period: history}, InputRefs: []Ref{cur, inventory}, ObservedAt: now, InventoryStatus: "COMPLETE_POINT_IN_TIME", BillingStatus: "COMPLETE_OBSERVED_WINDOW", Positions: []PositionAnalysis{}, Partitions: []Partition{}, UnmatchedBilling: []UnmatchedBilling{}, OptimizationOrder: []OptimizationStage{}, RecommendationStatus: "BLOCKED", ReasonCodes: []string{"NO_PURCHASE_OR_EXECUTION_AUTHORITY"}}
	portfolio.ID = Hash(portfolio)
	refs := []Ref{cur, inventory, scope.OwnershipRef, {Kind: "COMMITMENT_PORTFOLIO_ANALYSIS", ID: portfolio.RequestID, SHA256: Hash(portfolio)}}
	stages := []PostOptimizationStage{}
	for _, name := range decisionStages {
		d, o := ref("OPTIMIZATION_DECISION", name), ref("OPTIMIZATION_OUTCOME", name)
		refs = append(refs, d, o)
		stages = append(stages, PostOptimizationStage{Stage: name, Disposition: "EVIDENCED_NO_CHANGE", DecisionRef: d, OutcomeRef: o, ScopeSHA256: scope.SHA256, CompletedAt: now, ReasonCodes: []string{}})
	}
	nativeHistory := ref("AWS_CUR2", "historical")
	refs = append(refs, nativeHistory)
	request := DecisionForecastRequest{SchemaVersion: "2", RequestID: "typed-unit-forecast-production", Scope: scope, ObservedAt: now, OptimizationOrder: stages[:4], InputRefs: refs, History: []DecisionHistoryHour{}}
	const hours = 90*24 + 2*8760 + 168*22
	for i := 0; i < hours; i++ {
		start := now.Add(time.Duration(i-hours) * time.Hour)
		request.History = append(request.History, DecisionHistoryHour{Period: Period{Start: start, End: start.Add(time.Hour)}, Dimensions: dims, UsageAmount: "10", ConfigurationSHA256: scope.ConfigurationSHA256, NativeRef: nativeHistory})
	}
	produced, err := calculator.ProduceDecisionForecast(context.Background(), request)
	if err != nil {
		t.Fatalf("actual typed numerical producer refused: %v", err)
	}
	if produced.Status != "CALIBRATED" || produced.Calibration == nil || len(produced.Hours) != 8760 {
		t.Fatal("full term numerical calibration unavailable")
	}
	forecastRef := Ref{Kind: "POST_OPTIMIZATION_FORECAST", ID: produced.ID, SHA256: Hash(produced)}
	calibrationRef := Ref{Kind: "FORECAST_CALIBRATION", ID: Hash(produced.Calibration), SHA256: Hash(produced.Calibration)}
	forecast, err := assembleDecisionForecast(PersistedForecast{Production: produced, ForecastRef: forecastRef, CalibrationRef: &calibrationRef})
	if err != nil {
		t.Fatal("typed persisted forecast assembly refused")
	}
	offerRef, rateRef := ref("AWS_SAVINGS_PLAN_OFFER", "offer"), ref("AWS_SAVINGS_PLAN_OFFER_RATE", "offered-rate")
	refs = append(refs, forecastRef, calibrationRef, offerRef, rateRef)
	input := DecisionInput{SchemaVersion: "2", RequestID: "typed-unit-decision", Selection: DecisionSelection{PortfolioAnalysisRequestID: portfolio.RequestID, OfferReceiptID: offerRef.ID, PostOptimizationAssessmentID: "typed-unit-assessment", ForecastID: forecast.ID}, Scope: scope, Portfolio: portfolio, UsageStatus: "COMPLETE_OBSERVED_ELIGIBLE_WINDOW", Usage: []UsageHour{}, ContractRates: []ContractRate{}, ContractRateStatus: "COMPLETE_NATIVE_PLAN_RATE_SETS", ContractRatePlanIDs: []string{}, ContractRateRefs: []Ref{}, Offer: &Offer{ID: offerRef.ID, NativeOfferingID: "typed-unit-native-offering", Class: scope.Class, Currency: scope.Currency, PaymentOption: "No Upfront", DurationSeconds: "31536000", ValidityBasis: DecisionOfferValidityBasis, EffectivePeriod: Period{Start: now, End: now.Add(5 * time.Minute)}, Rates: []OfferRate{{Dimensions: dims, Rate: "0.12", NativeRef: rateRef}}, NativeRef: offerRef}, OptimizationOrder: stages, Forecast: &forecast, InputRefs: refs, ObservedAt: now, ReasonCodes: []string{}}
	for i := 0; i < 24; i++ {
		start := history.Start.Add(time.Duration(i) * time.Hour)
		input.Usage = append(input.Usage, UsageHour{ID: fmt.Sprintf("typed-unit-line-%d", i), Period: Period{Start: start, End: start.Add(time.Hour)}, Dimensions: dims, Kind: "Usage", UsageAmount: "10", BilledCost: "2", BilledCostBasis: "NATIVE_NET_UNBLENDED_COST", NetUsageCost: str("2"), OnDemandEquivalentCost: str("2.5"), OnDemandBasis: "NATIVE_UNBLENDED_ON_DEMAND_EQUIVALENT", NativeRef: cur})
	}
	last := input.Usage[len(input.Usage)-1]
	input.PAYGBasis = []PAYGBasis{{Dimensions: dims, ObservedPeriod: last.Period, Rate: "0.2", Basis: "CURRENT_NATIVE_NET_USAGE_COST_PER_UNIT", SourceLineIDs: []string{last.ID}, NativeRefs: []Ref{cur}}}
	result, err := calculator.EvaluateDecision(context.Background(), input)
	if err != nil {
		t.Fatalf("typed positive advice refused: %v", err)
	}
	if result.Status != "RECOMMEND_PURCHASE_PENDING_FINANCE" || result.ExpectedSavings.Value == nil || *result.ExpectedSavings.Value != "7008" || result.PurchaseAuthorized || result.ExecutionAuthorized || result.VerifiedSaving != nil {
		t.Fatal("positive advice or no-authority contract differs")
	}
	input.Offer.Rates[0].Rate = "0.3"
	result, err = calculator.EvaluateDecision(context.Background(), input)
	if err != nil || result.Status != "DO_NOT_PURCHASE" || result.ExpectedSavings.Value == nil || *result.ExpectedSavings.Value != "-8760" {
		t.Fatal("uneconomic typed advice must preserve negative result")
	}
	input.UsageStatus = "PARTIAL"
	result, err = calculator.EvaluateDecision(context.Background(), input)
	if err != nil || result.Status != "BLOCKED" || result.ExpectedSavings.Value != nil {
		t.Fatal("missing eligible coverage must remain blocked")
	}
}
