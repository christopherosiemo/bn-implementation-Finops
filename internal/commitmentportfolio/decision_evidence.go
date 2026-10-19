package commitmentportfolio

import (
	"encoding/json"
	"sort"
	"time"
)

// decisionRefs checks consistency only. The SQL resolver selects the rows and
// rechecks their issuer, tenant, workload, source and current configuration.
// An uploaded object with these checksums acquires no evidence authority.
func decisionRefs(values []Ref) ([]Ref, error) {
	if values == nil || len(values) > 2048 {
		return nil, ErrEvidence
	}
	byID := map[string]Ref{}
	for _, value := range values {
		if value.Kind == "" || !idPattern.MatchString(value.ID) || !shaPattern.MatchString(value.SHA256) {
			return nil, ErrEvidence
		}
		key := value.Kind + ":" + value.ID
		if previous, ok := byID[key]; ok && previous.SHA256 != value.SHA256 {
			return nil, ErrEvidence
		}
		byID[key] = value
	}
	keys := make([]string, 0, len(byID))
	for key := range byID {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]Ref, 0, len(keys))
	for _, key := range keys {
		out = append(out, byID[key])
	}
	return out, nil
}

type DecisionAssessment struct {
	SchemaVersion       string                  `json:"schema_version"`
	ID                  string                  `json:"id"`
	RequestID           string                  `json:"request_id"`
	Scope               DecisionScope           `json:"scope"`
	Status              string                  `json:"status"`
	OptimizationOrder   []PostOptimizationStage `json:"optimization_order"`
	InputRefs           []Ref                   `json:"input_refs"`
	ReasonCodes         []string                `json:"reason_codes"`
	ObservedAt          time.Time               `json:"observed_at"`
	ExecutionAuthorized bool                    `json:"execution_authorized"`
	VerifiedSaving      *string                 `json:"verified_saving"`
}

// PersistedForecast carries numerical output separately from its actual
// database references. This avoids hashing a reference into its own payload.
type PersistedForecast struct {
	Production     DecisionForecastProduction `json:"production"`
	ForecastRef    Ref                        `json:"forecast_ref"`
	CalibrationRef *Ref                       `json:"calibration_ref"`
}

func assembleDecisionForecast(value PersistedForecast) (DecisionForecast, error) {
	p := value.Production
	identity := p
	identity.ID = ""
	if Hash(identity) != p.ID || value.ForecastRef.Kind != "POST_OPTIMIZATION_FORECAST" || value.ForecastRef.ID != p.ID || value.ForecastRef.SHA256 != Hash(p) {
		return DecisionForecast{}, ErrEvidence
	}
	out := DecisionForecast{ID: p.ID, ScopeSHA256: p.ScopeSHA256, RecalculatedAt: p.RecalculatedAt, Hours: p.Hours, NativeRef: value.ForecastRef}
	if p.Status == "UNAVAILABLE" {
		if p.Calibration != nil || value.CalibrationRef != nil || len(p.Hours) != 0 {
			return out, ErrEvidence
		}
		return out, nil
	}
	if p.Status != "CALIBRATED" || p.Calibration == nil || value.CalibrationRef == nil || value.CalibrationRef.Kind != "FORECAST_CALIBRATION" || value.CalibrationRef.SHA256 != Hash(p.Calibration) || value.CalibrationRef.ID != Hash(p.Calibration) {
		return DecisionForecast{}, ErrEvidence
	}
	raw, err := json.Marshal(p.Calibration)
	if err != nil {
		return out, err
	}
	var calibration Calibration
	if json.Unmarshal(raw, &calibration) != nil {
		return out, ErrEvidence
	}
	calibration.NativeRef = *value.CalibrationRef
	out.Calibration = &calibration
	return out, nil
}

var decisionStages = []string{"REMOVE_IDLE", "SCHEDULE", "RIGHTSIZE", "AUTOSCALE", "RECALCULATE_STABLE_DEMAND"}

// Missing stage evidence stays missing. In particular an uneconomic candidate,
// absent recommendation or present-day membership is not a no-change proof.
func unavailableDecisionAssessment(requestID string, scope DecisionScope, refs []Ref, now time.Time) DecisionAssessment {
	result := DecisionAssessment{SchemaVersion: "2", RequestID: requestID, Scope: scope, Status: "BLOCKED", OptimizationOrder: []PostOptimizationStage{}, InputRefs: refs, ReasonCodes: []string{}, ObservedAt: now.UTC()}
	for _, stage := range decisionStages {
		reason := stage + "_ISSUED_OUTCOME_UNAVAILABLE"
		result.OptimizationOrder = append(result.OptimizationOrder, PostOptimizationStage{Stage: stage, Disposition: "UNAVAILABLE", ScopeSHA256: scope.SHA256, ReasonCodes: []string{reason}})
		result.ReasonCodes = append(result.ReasonCodes, reason)
	}
	result.ID = Hash(result)
	return result
}
