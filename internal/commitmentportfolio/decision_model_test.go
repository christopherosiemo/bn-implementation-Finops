package commitmentportfolio

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type decisionModelDoer func(*http.Request) (*http.Response, error)

func (d decisionModelDoer) Do(r *http.Request) (*http.Response, error) { return d(r) }
func decisionSeal(d Decision) Decision                                 { d.ID = ""; d.ID = Hash(d); return d }

// These are transport/consistency doubles, not issued origin or calibration.
func decisionTransportFixture() (DecisionInput, Decision) {
	now := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	usd := "USD"
	in := DecisionInput{SchemaVersion: "2", RequestID: "request", Scope: DecisionScope{Currency: usd, HistoryPeriod: Period{Start: now.Add(-24 * time.Hour), End: now}, ProjectionPeriod: Period{Start: now.Add(time.Hour), End: now.Add(8761 * time.Hour)}}, ObservedAt: now, InputRefs: []Ref{{Kind: "AWS_CUR2", ID: "cur", SHA256: strings.Repeat("a", 64)}}, OptimizationOrder: []PostOptimizationStage{}}
	end := now.Add(2 * 8760 * time.Hour)
	in.Portfolio.Positions = []PositionAnalysis{{Position: Position{Currency: &usd, End: &end}}}
	metric := func(unit string, span Period) DecisionMetric {
		var currency *string
		if unit != "fraction" {
			currency = &usd
		}
		return DecisionMetric{Status: "UNAVAILABLE", Unit: unit, Currency: currency, Basis: "UNAVAILABLE_NATIVE_PROOF", Period: span, ReasonCodes: []string{"SOURCE_UNAVAILABLE"}, InputRefs: in.InputRefs}
	}
	old, forward := in.Scope.HistoryPeriod, in.Scope.ProjectionPeriod
	cash := Period{Start: now, End: end}
	out := Decision{SchemaVersion: "2", RequestID: in.RequestID, Selection: in.Selection, Scope: in.Scope, InputRefs: in.InputRefs, Status: "BLOCKED", ObservedCoverage: metric("fraction", old), ObservedEffectiveDiscount: metric("fraction", old), ObservedUnusedExposure: metric("currency", old), ComputationPolicy: DecisionComputationPolicy, ProposedHourlyCommitment: metric("currency/hour", forward), ProposedTermObligation: metric("currency", forward), ExpectedUtilization: metric("fraction", forward), BreakEvenUtilization: metric("fraction", forward), ExpectedSavings: metric("currency", forward), DownsideExposure: metric("currency", forward), CashRequirement: metric("currency", forward), RemainingContractualObligation: metric("currency", cash), PaidUnamortizedValue: metric("currency", cash), ForwardPriceAssumption: DecisionPriceAssumption, Confidence: DecisionConfidence{Status: "UNAVAILABLE", ReasonCodes: []string{"CALIBRATION_UNAVAILABLE"}}, OptimizationOrder: in.OptimizationOrder, ReasonCodes: []string{"SOURCE_UNAVAILABLE"}, ObservedAt: now, FinanceApprovalRequired: true}
	out.PriceChangeStress = PriceChangeStress{Status: "UNAVAILABLE", Assumption: DecisionPriceAssumption, ZeroUsageLoss: out.DownsideExposure, ReasonCodes: []string{"SOURCE_UNAVAILABLE"}}
	return in, decisionSeal(out)
}

func TestDecisionNativeTransportKeepsCashHorizonAndNoAuthority(t *testing.T) {
	in, valid := decisionTransportFixture()
	cases := []struct {
		name   string
		change func(*Decision)
		okay   bool
	}{
		{"valid_blocked_retains_longer_native_cash", func(*Decision) {}, true},
		{"shortened_cash", func(d *Decision) { d.RemainingContractualObligation.Period = in.Scope.ProjectionPeriod }, false},
		{"negative_hourly_budget", func(d *Decision) {
			d.ProposedHourlyCommitment.Status = "AVAILABLE"
			d.ProposedHourlyCommitment.Value = decisionString("-1")
		}, false},
		{"purchase_flag", func(d *Decision) { d.PurchaseAuthorized = true }, false},
		{"wrong_ref", func(d *Decision) {
			d.InputRefs = []Ref{{Kind: "AWS_CUR2", ID: "other", SHA256: strings.Repeat("a", 64)}}
		}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := valid
			tc.change(&out)
			out = decisionSeal(out)
			calculator := HTTPCalculator{Endpoint: "http://fixed-private-model:8000", Token: "separate-private-test-token", Client: decisionModelDoer(func(request *http.Request) (*http.Response, error) {
				if request.Method != http.MethodPost || request.URL.String() != "http://fixed-private-model:8000/v6/commitment-decision" || request.Header.Get("Authorization") != "Bearer separate-private-test-token" {
					t.Fatal("private route/auth changed")
				}
				raw, _ := json.Marshal(out)
				return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(raw))}, nil
			})}
			_, err := calculator.EvaluateDecision(context.Background(), in)
			if (err == nil) != tc.okay {
				t.Fatalf("acceptance=%v error=%v", tc.okay, err)
			}
		})
	}
}

func TestDecisionForecastRejectsDifferentProducerDespiteResealedOutput(t *testing.T) {
	// Private transport double only. This checks release/model identity, not
	// statistical validity or native history issuance.
	now := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	dimension := Dimensions{AccountID: "123456789012", ServiceCode: "AmazonEC2", ProductType: "EC2", UsageType: "BoxUsage:m6i.large", Operation: "RunInstances", Region: "us-east-1", Unit: "Hrs", Currency: "USD"}
	in := DecisionForecastRequest{SchemaVersion: "2", RequestID: "forecast-request", Scope: DecisionScope{SHA256: strings.Repeat("a", 64), ProjectionPeriod: Period{Start: now.Add(time.Hour), End: now.Add(8761 * time.Hour)}}, ObservedAt: now, History: []DecisionHistoryHour{{Dimensions: dimension}}, InputRefs: []Ref{{Kind: "AWS_CUR2", ID: "history", SHA256: strings.Repeat("b", 64)}}}
	valid := DecisionForecastProduction{SchemaVersion: "2", RequestID: in.RequestID, ScopeSHA256: in.Scope.SHA256, RecalculatedAt: now, Status: "CALIBRATED", ReasonCodes: []string{}, InputRefs: in.InputRefs, Hours: []ForecastHour{}, Calibration: &ProducedCalibration{Target: "TERM_UTILIZATION_AND_NET_COST", HorizonHours: 8760, BacktestOriginCount: 12, SampleCount: 12, Method: "ROLLING_ORIGIN_TERM_BLOCK_V1", ModelVersion: "commitment-stable-floor-v1", ModelSHA256: decisionForecastModelSHA256, ScopeSHA256: in.Scope.SHA256}}
	for i := 0; i < 8760; i++ {
		start := in.Scope.ProjectionPeriod.Start.Add(time.Duration(i) * time.Hour)
		valid.Hours = append(valid.Hours, ForecastHour{Period: Period{Start: start, End: start.Add(time.Hour)}, Dimensions: dimension, LowerUsage: "1", ExpectedUsage: "1", UpperUsage: "1"})
	}
	for _, wrong := range []bool{false, true} {
		out := valid
		calibration := *valid.Calibration
		out.Calibration = &calibration
		if wrong {
			out.Calibration.ModelSHA256 = strings.Repeat("c", 64)
		}
		out.ID = ""
		out.ID = Hash(out)
		calculator := HTTPCalculator{Endpoint: "http://fixed-private-model:8000", Token: "separate-private-test-token", Client: decisionModelDoer(func(request *http.Request) (*http.Response, error) {
			if request.URL.Path != "/v6/commitment-forecast" || request.Header.Get("Authorization") != "Bearer separate-private-test-token" {
				t.Fatal("forecast private endpoint/auth changed")
			}
			raw, _ := json.Marshal(out)
			return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(raw))}, nil
		})}
		_, err := calculator.ProduceDecisionForecast(context.Background(), in)
		if (err != nil) != wrong {
			t.Fatalf("wrong_model=%v error=%v", wrong, err)
		}
	}
}

func TestDecisionNativeConfidenceUsesObservedHeldoutCoverage(t *testing.T) {
	in, out := decisionTransportFixture()
	calibrationRef := Ref{Kind: "FORECAST_CALIBRATION", ID: "calibration", SHA256: strings.Repeat("b", 64)}
	in.Forecast = &DecisionForecast{Calibration: &Calibration{Method: "ROLLING_ORIGIN_TERM_BLOCK_V1", ObservedCoverage: "0.75", NominalCoverage: "0.9", NativeRef: calibrationRef}}
	method := "ROLLING_ORIGIN_TERM_BLOCK_V1"
	out.Confidence = DecisionConfidence{Status: "AVAILABLE", LowerExpectedSavings: decisionString("-1"), UpperExpectedSavings: decisionString("3"), Coverage: decisionString("0.75"), Method: &method, CalibrationRef: &calibrationRef, ReasonCodes: []string{"DEPENDENT_EMPIRICAL_TERM_WINDOWS"}}
	if err := validateDecision(in, decisionSeal(out)); err != nil {
		t.Fatal(err)
	}
	out.Confidence.Coverage = decisionString("0.9")
	if validateDecision(in, decisionSeal(out)) == nil {
		t.Fatal("nominal hourly coverage replaced actual held-out term coverage")
	}
}

func TestDecisionNativeRefsAndSKUMapRefuseAmbiguity(t *testing.T) {
	first := Ref{Kind: "AWS_CUR2", ID: "a", SHA256: strings.Repeat("a", 64)}
	conflict := first
	conflict.SHA256 = strings.Repeat("b", 64)
	if _, err := decisionRefs([]Ref{first, conflict}); err == nil {
		t.Fatal("conflicting immutable revision accepted")
	}
	refs, err := decisionRefs([]Ref{first, first})
	if err != nil || len(refs) != 1 {
		t.Fatal("exact ref duplicate failed stable aggregation")
	}
	family := decisionInstanceFamily(decisionString("m6i.large"))
	if family == nil || *family != "m6i" || decisionInstanceFamily(decisionString("General purpose")) != nil {
		t.Fatal("marketing family promoted to native SKU family")
	}
}
