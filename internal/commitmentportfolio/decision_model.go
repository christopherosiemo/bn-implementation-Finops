package commitmentportfolio

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"
)

const DecisionComputationPolicy = "DECIMAL80_INTERMEDIATE_HALF_EVEN_12_FINAL"
const DecisionPriceAssumption = "HELD_CURRENT_NATIVE_NET_RATE"

// These methods extend the same private, endpoint-pinned calculator and bearer
// identity. They never accept a caller-selected model endpoint or token.
func (c HTTPCalculator) EvaluateDecision(ctx context.Context, in DecisionInput) (Decision, error) {
	var result Decision
	if err := c.decisionCall(ctx, "/v6/commitment-decision", in, &result, 2<<20); err != nil {
		return result, err
	}
	if err := validateDecision(in, result); err != nil {
		return Decision{}, err
	}
	return result, nil
}

// The same release must deliberately pin the exact private numerical producer.
// Existing published forecasts retain their original immutable model identity.
// SHA256_CLOSURE_V1 covers the sorted raw-source hashes of portfolio.py,
// portfolio_decision.py and portfolio_forecast.py, not just the entry module.
const decisionForecastModelSHA256 = "e69cc7d8e0a8a63cc05aeaad3a3c2dafeacfb31a2441d8355817782d37607c25"

func (c HTTPCalculator) ProduceDecisionForecast(ctx context.Context, in DecisionForecastRequest) (DecisionForecastProduction, error) {
	var out DecisionForecastProduction
	if len(in.History) > 100000 || in.History == nil {
		return out, ErrEvidence
	}
	if err := c.decisionCall(ctx, "/v6/commitment-forecast", in, &out, 8<<20); err != nil {
		return out, err
	}
	identity := out
	identity.ID = ""
	if out.SchemaVersion != "2" || out.RequestID != in.RequestID || out.ScopeSHA256 != in.Scope.SHA256 || !out.RecalculatedAt.Equal(in.ObservedAt) || Hash(out.InputRefs) != Hash(in.InputRefs) || !reasonList(out.ReasonCodes) || !shaPattern.MatchString(out.ID) || Hash(identity) != out.ID || out.Hours == nil || len(out.Hours) > 100000 {
		return DecisionForecastProduction{}, ErrEvidence
	}
	switch out.Status {
	case "UNAVAILABLE":
		if len(out.Hours) != 0 || out.Calibration != nil || len(out.ReasonCodes) == 0 {
			return DecisionForecastProduction{}, ErrEvidence
		}
	case "CALIBRATED":
		if out.Calibration == nil || len(out.Hours) == 0 || out.Calibration.Target != "TERM_UTILIZATION_AND_NET_COST" || out.Calibration.Method != "ROLLING_ORIGIN_TERM_BLOCK_V1" || out.Calibration.ModelVersion != "commitment-stable-floor-v1" || out.Calibration.ScopeSHA256 != in.Scope.SHA256 || out.Calibration.ModelSHA256 != decisionForecastModelSHA256 || out.Calibration.BacktestOriginCount < 12 || out.Calibration.SampleCount < out.Calibration.BacktestOriginCount || out.Calibration.HorizonHours != int(in.Scope.ProjectionPeriod.End.Sub(in.Scope.ProjectionPeriod.Start)/time.Hour) {
			return DecisionForecastProduction{}, ErrEvidence
		}
		dimensions := map[string]Dimensions{}
		for _, hour := range in.History {
			key := Hash(hour.Dimensions)
			dimensions[key] = hour.Dimensions
		}
		seen := map[string]bool{}
		counts := map[string]int{}
		for _, hour := range out.Hours {
			lower, e1 := numberValue(&hour.LowerUsage, false, false)
			expected, e2 := numberValue(&hour.ExpectedUsage, false, false)
			upper, e3 := numberValue(&hour.UpperUsage, false, false)
			key := Hash(hour.Dimensions)
			slot := key + ":" + hour.Period.Start.UTC().Format(time.RFC3339Nano)
			if e1 != nil || e2 != nil || e3 != nil || lower.Cmp(expected) > 0 || expected.Cmp(upper) > 0 || hour.Period.End.Sub(hour.Period.Start) != time.Hour || !hour.Period.Start.Equal(hour.Period.Start.Truncate(time.Hour)) || hour.Period.Start.Before(in.Scope.ProjectionPeriod.Start) || hour.Period.End.After(in.Scope.ProjectionPeriod.End) || dimensions[key].AccountID == "" || seen[slot] {
				return DecisionForecastProduction{}, ErrEvidence
			}
			seen[slot] = true
			counts[key]++
		}
		if len(counts) != len(dimensions) {
			return DecisionForecastProduction{}, ErrEvidence
		}
		for key := range dimensions {
			if counts[key] != out.Calibration.HorizonHours {
				return DecisionForecastProduction{}, ErrEvidence
			}
		}
	default:
		return DecisionForecastProduction{}, ErrEvidence
	}
	return out, nil
}

func (c HTTPCalculator) decisionCall(ctx context.Context, route string, in, out any, limit int64) error {
	if c.Client == nil || c.Endpoint == "" || c.Token == "" {
		return ErrJob
	}
	body, err := json.Marshal(in)
	if err != nil || len(body) > 32<<20 {
		return ErrEvidence
	}
	call, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(call, http.MethodPost, strings.TrimRight(c.Endpoint, "/")+route, bytes.NewReader(body))
	if err != nil {
		return ErrJob
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+c.Token)
	response, err := c.Client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode == 422 {
		return ErrEvidence
	}
	if response.StatusCode != 200 {
		return ErrJob
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil || int64(len(raw)) > limit {
		return ErrJob
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(out) != nil || decoder.Decode(new(any)) != io.EOF {
		return ErrJob
	}
	return nil
}

// Validation prevents a misrouted or malformed private model response from
// enlarging its scope. The model remains the numerical producer; hashes and
// shape checks do not authenticate source observations or recreate calibration.
func validateDecision(in DecisionInput, out Decision) error {
	identity := out
	identity.ID = ""
	if in.SchemaVersion != "2" || out.SchemaVersion != "2" || out.RequestID != in.RequestID || Hash(out.Selection) != Hash(in.Selection) || Hash(out.Scope) != Hash(in.Scope) || Hash(out.InputRefs) != Hash(in.InputRefs) || !out.ObservedAt.Equal(in.ObservedAt) || Hash(identity) != out.ID || !shaPattern.MatchString(out.ID) || out.ComputationPolicy != DecisionComputationPolicy || out.ForwardPriceAssumption != DecisionPriceAssumption || !out.FinanceApprovalRequired || out.PurchaseAuthorized || out.ExecutionAuthorized || out.VerifiedSaving != nil || !reasonList(out.ReasonCodes) || Hash(out.OptimizationOrder) != Hash(in.OptimizationOrder) {
		return ErrEvidence
	}
	if _, err := decisionRefs(in.InputRefs); err != nil {
		return err
	}
	if out.Status != "BLOCKED" && out.Status != "DO_NOT_PURCHASE" && out.Status != "RECOMMEND_PURCHASE_PENDING_FINANCE" {
		return ErrEvidence
	}
	metrics := []struct {
		value                     DecisionMetric
		unit                      string
		forward, signed, fraction bool
	}{
		{out.ObservedCoverage, "fraction", false, false, true},
		{out.ObservedEffectiveDiscount, "fraction", false, true, false},
		{out.ObservedUnusedExposure, "currency", false, false, false},
		{out.ProposedHourlyCommitment, "currency/hour", true, false, false},
		{out.ProposedTermObligation, "currency", true, false, false},
		{out.ExpectedUtilization, "fraction", true, false, true},
		{out.BreakEvenUtilization, "fraction", true, false, false},
		{out.ExpectedSavings, "currency", true, true, false},
		{out.DownsideExposure, "currency", true, false, false},
		{out.CashRequirement, "currency", true, false, false},
		{out.RemainingContractualObligation, "currency", true, false, false},
		{out.PaidUnamortizedValue, "currency", true, false, false},
	}
	cashSpan := Period{Start: in.ObservedAt, End: in.Scope.ProjectionPeriod.End}
	for _, position := range in.Portfolio.Positions {
		p := position.Position
		if p.Currency != nil && *p.Currency == in.Scope.Currency && p.End != nil && p.End.After(cashSpan.End) {
			cashSpan.End = *p.End
		}
	}
	for index, item := range metrics {
		m := item.value
		span := in.Scope.HistoryPeriod
		if item.forward {
			span = in.Scope.ProjectionPeriod
		}
		if index >= 10 {
			span = cashSpan
		}
		if m.Unit != item.unit || Hash(m.Period) != Hash(span) || Hash(m.InputRefs) != Hash(in.InputRefs) || !reasonList(m.ReasonCodes) || m.Basis == "" {
			return ErrEvidence
		}
		if item.unit == "fraction" {
			if m.Currency != nil {
				return ErrEvidence
			}
		} else if m.Currency == nil || *m.Currency != in.Scope.Currency {
			return ErrEvidence
		}
		if m.Value == nil {
			if m.Status != "UNAVAILABLE" || len(m.ReasonCodes) == 0 {
				return ErrEvidence
			}
		} else {
			if m.Status != "AVAILABLE" {
				return ErrEvidence
			}
			if _, err := numberValue(m.Value, item.signed, item.fraction); err != nil {
				return err
			}
		}
	}
	if value, err := numberValue(out.ObservedEffectiveDiscount.Value, true, false); err != nil || value != nil && value.Cmp(big.NewRat(1, 1)) > 0 {
		return ErrEvidence
	}
	confidence := out.Confidence
	if !reasonList(confidence.ReasonCodes) {
		return ErrEvidence
	}
	switch confidence.Status {
	case "UNAVAILABLE":
		if confidence.LowerExpectedSavings != nil || confidence.UpperExpectedSavings != nil || confidence.Coverage != nil || confidence.Method != nil || confidence.CalibrationRef != nil {
			return ErrEvidence
		}
	case "AVAILABLE":
		lower, e1 := numberValue(confidence.LowerExpectedSavings, true, false)
		upper, e2 := numberValue(confidence.UpperExpectedSavings, true, false)
		coverage, e3 := numberValue(confidence.Coverage, false, true)
		if e1 != nil || e2 != nil || e3 != nil || lower == nil || upper == nil || coverage == nil || lower.Cmp(upper) > 0 || in.Forecast == nil || in.Forecast.Calibration == nil || confidence.Method == nil || *confidence.Method != in.Forecast.Calibration.Method || confidence.CalibrationRef == nil || Hash(*confidence.CalibrationRef) != Hash(in.Forecast.Calibration.NativeRef) {
			return ErrEvidence
		}
		expectedCoverage, err := numberValue(&in.Forecast.Calibration.ObservedCoverage, false, true)
		if err != nil || expectedCoverage == nil || coverage.Cmp(expectedCoverage) != 0 {
			return ErrEvidence
		}
	default:
		return ErrEvidence
	}
	stress := out.PriceChangeStress
	if stress.Assumption != DecisionPriceAssumption || Hash(stress.ZeroUsageLoss) != Hash(out.DownsideExposure) || !reasonList(stress.ReasonCodes) {
		return ErrEvidence
	}
	drop, err := numberValue(stress.BreakEvenPAYGRateDropFraction, true, false)
	if err != nil || drop != nil && drop.Cmp(big.NewRat(1, 1)) > 0 {
		return ErrEvidence
	}
	if stress.Status != "AVAILABLE" && stress.Status != "UNAVAILABLE" || stress.Status == "UNAVAILABLE" && drop != nil {
		return ErrEvidence
	}
	if out.Status == "RECOMMEND_PURCHASE_PENDING_FINANCE" {
		budget, e1 := numberValue(out.ProposedHourlyCommitment.Value, false, false)
		saving, e2 := numberValue(out.ExpectedSavings.Value, true, false)
		lower, e3 := numberValue(confidence.LowerExpectedSavings, true, false)
		if e1 != nil || e2 != nil || e3 != nil || budget == nil || saving == nil || lower == nil || budget.Sign() <= 0 || saving.Sign() <= 0 || lower.Sign() <= 0 || confidence.Status != "AVAILABLE" || stress.Status != "AVAILABLE" || out.ProposedTermObligation.Value == nil || out.ExpectedUtilization.Value == nil || out.BreakEvenUtilization.Value == nil {
			return ErrEvidence
		}
	}
	return nil
}
