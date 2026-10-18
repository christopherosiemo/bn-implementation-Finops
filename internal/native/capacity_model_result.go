package native

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf16"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/telemetry"
)

type CapacityModelEconomics struct {
	Status          string             `json:"status"`
	ReasonCodes     []string           `json:"reason_codes"`
	Currency        *string            `json:"currency"`
	PeriodHours     *string            `json:"period_hours,omitempty"`
	CurrentCost     *string            `json:"current_cost"`
	CandidateCost   *string            `json:"candidate_cost"`
	EstimatedSaving *string            `json:"estimated_saving"`
	VerifiedSaving  *string            `json:"verified_saving,omitempty"`
	PriceSourceRefs []CapacityModelRef `json:"price_source_refs,omitempty"`
}
type CapacityModelRisk struct {
	Status              string `json:"status"`
	ProbabilityUpperPPM *int64 `json:"future_breach_probability_upper_ppm"`
	RequiredMaximumPPM  int64  `json:"required_maximum_ppm"`
	ReasonCode          string `json:"reason_code"`
}
type CapacityModelCandidate struct {
	ID               string                 `json:"id"`
	Count            int                    `json:"count"`
	CapacitySuitable bool                   `json:"capacity_suitable"`
	Status           string                 `json:"status"`
	ReasonCodes      []string               `json:"reason_codes"`
	Checks           []model.Document       `json:"checks"`
	Economics        CapacityModelEconomics `json:"economics"`
	FutureRisk       CapacityModelRisk      `json:"future_risk"`
	SourceRef        CapacityModelRef       `json:"source_ref"`
}
type CapacityModelResult struct {
	SchemaVersion    string                   `json:"schema_version"`
	ModelVersion     string                   `json:"model_version"`
	Binding          telemetry.Binding        `json:"binding"`
	Status           string                   `json:"status"`
	ReasonCodes      []string                 `json:"reason_codes"`
	History          model.Document           `json:"history"`
	Metrics          []model.Document         `json:"metrics"`
	Forecasts        []model.Document         `json:"forecasts"`
	Candidates       []CapacityModelCandidate `json:"candidates"`
	EvidenceRefs     []CapacityModelRef       `json:"evidence_refs"`
	ModelAssumptions []string                 `json:"model_assumptions"`
	AssessmentHash   string                   `json:"assessment_hash"`
}

// Python's canonical JSON uses sorted keys, no whitespace and ensure_ascii.
// Keep decimal/large integers as JSON numbers while verifying its body hash.
func CapacityModelBodyHash(raw []byte) (string, error) {
	var d map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if decoder.Decode(&d) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return "", errors.New("CAPACITY_MODEL_RESPONSE_INVALID")
	}
	delete(d, "assessment_hash")
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(d); err != nil {
		return "", err
	}
	var ascii strings.Builder
	for _, r := range strings.TrimSuffix(buf.String(), "\n") {
		if r >= 127 {
			if r <= 0xffff {
				fmt.Fprintf(&ascii, "\\u%04x", r)
			} else {
				hi, lo := utf16.EncodeRune(r)
				fmt.Fprintf(&ascii, "\\u%04x\\u%04x", hi, lo)
			}
		} else {
			ascii.WriteRune(r)
		}
	}
	sum := sha256.Sum256([]byte(ascii.String()))
	return hex.EncodeToString(sum[:]), nil
}

// DecodeCapacityModelResult accepts a calculation only for the exact selected
// inputs. Until native candidate contracted rates are implemented, every price
// and future-probability claim must remain unavailable, regardless of suitability.
func DecodeCapacityModelResult(raw []byte, input CapacityModelRequest) (CapacityModelResult, error) {
	var out CapacityModelResult
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if len(raw) > 1<<20 || decoder.Decode(&out) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return out, errors.New("CAPACITY_MODEL_RESPONSE_INVALID")
	}
	hash, err := CapacityModelBodyHash(raw)
	if err != nil || hash != out.AssessmentHash || out.SchemaVersion != "4" || out.ModelVersion != "capacity-weekday-block-v1" || out.Binding != input.Binding || out.Status != "BLOCKED" && out.Status != "INSUFFICIENT_OBSERVATION" || len(out.Candidates) != len(input.Candidates) || out.History == nil || out.Metrics == nil || out.Forecasts == nil || out.EvidenceRefs == nil {
		return out, errors.New("CAPACITY_MODEL_RESPONSE_BINDING_INVALID")
	}
	allowed := map[string]CapacityModelCatalog{}
	for _, candidate := range input.Candidates {
		allowed[candidate.ID] = candidate
	}
	seen := map[string]bool{}
	for _, candidate := range out.Candidates {
		expected, ok := allowed[candidate.ID]
		p := candidate.Economics
		if !ok || seen[candidate.ID] || candidate.Count != expected.Count || candidate.SourceRef != expected.SourceRef || candidate.Status != "BLOCKED" && candidate.Status != "INSUFFICIENT_OBSERVATION" || p.Status != "UNAVAILABLE" || p.Currency != nil || p.CurrentCost != nil || p.CandidateCost != nil || p.EstimatedSaving != nil || p.VerifiedSaving != nil || len(p.PriceSourceRefs) > 0 || !hasHardware(p.ReasonCodes, "NATIVE_AVOIDABLE_CONTRACTED_PRICE_REQUIRED") || candidate.FutureRisk.Status != "UNCALIBRATED" || candidate.FutureRisk.ProbabilityUpperPPM != nil {
			return out, errors.New("CAPACITY_MODEL_UNEVIDENCED_PRICE_OR_AUTHORITY")
		}
		seen[candidate.ID] = true
	}
	refs := map[CapacityModelRef]bool{}
	refs[input.Current.SourceRef] = true
	for _, c := range input.Candidates {
		refs[c.SourceRef] = true
	}
	for _, metric := range input.Metrics {
		for _, ref := range metric.SourceRefs {
			refs[ref] = true
		}
	}
	for _, event := range input.Events {
		refs[event.SourceRef] = true
	}
	if len(out.EvidenceRefs) != len(refs) {
		return out, errors.New("CAPACITY_MODEL_EVIDENCE_REFS_INVALID")
	}
	for _, ref := range out.EvidenceRefs {
		if !refs[ref] {
			return out, errors.New("CAPACITY_MODEL_EVIDENCE_REFS_INVALID")
		}
		delete(refs, ref)
	}
	if len(out.Metrics) != len(input.Metrics) {
		return out, errors.New("CAPACITY_MODEL_METRIC_BINDING_INVALID")
	}
	metrics := map[string]CapacityModelMetric{}
	for _, metric := range input.Metrics {
		metrics[metric.Name] = metric
	}
	for _, metric := range out.Metrics {
		expected, ok := metrics[model.String(metric, "name")]
		if !ok || model.String(metric, "unit") != expected.Unit || model.String(metric, "statistic") != expected.Statistic {
			return out, errors.New("CAPACITY_MODEL_METRIC_BINDING_INVALID")
		}
		delete(metrics, expected.Name)
	}
	if len(metrics) > 0 {
		return out, errors.New("CAPACITY_MODEL_METRIC_BINDING_INVALID")
	}
	return out, nil
}
