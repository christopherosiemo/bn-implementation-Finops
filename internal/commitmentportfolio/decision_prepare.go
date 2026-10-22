package commitmentportfolio

import (
	"encoding/json"
	"sort"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
)

type decisionEvidenceEnvelope struct {
	ID             string                       `json:"id"`
	Kind           string                       `json:"kind"`
	RequestID      string                       `json:"request_id"`
	WorkloadID     string                       `json:"workload_id"`
	Selection      DecisionPreparationSelection `json:"selection"`
	BaseSHA256     string                       `json:"base_sha256"`
	ScopeSHA256    string                       `json:"scope_sha256"`
	Payload        json.RawMessage              `json:"payload"`
	PayloadSHA256  string                       `json:"payload_sha256"`
	CalibrationRef *Ref                         `json:"calibration_ref"`
	WriterRole     string                       `json:"writer_role"`
}

type decisionBase struct {
	TenantID        string                    `json:"tenant_id"`
	WorkloadID      string                    `json:"workload_id"`
	Selection       json.RawMessage           `json:"selection"`
	Workload        model.Document            `json:"workload"`
	Resources       []model.Document          `json:"resources"`
	Portfolio       Analysis                  `json:"portfolio"`
	PortfolioInputs Resolved                  `json:"portfolio_inputs"`
	OfferReceipt    model.Document            `json:"offer_receipt"`
	OfferRevision   model.Document            `json:"offer_revision"`
	Assessment      *decisionEvidenceEnvelope `json:"assessment"`
	Forecast        *decisionEvidenceEnvelope `json:"forecast"`
	InputRefs       []Ref                     `json:"input_refs"`
	OwnershipScope  *DecisionOwnershipScope   `json:"ownership_scope"`
}

func decisionCurrentScope(base decisionBase, offer Offer, now time.Time) (DecisionScope, []string, error) {
	inventory, err := PrepareDecisionSnapshot(base.PortfolioInputs, now)
	if err != nil {
		return DecisionScope{}, nil, err
	}
	resources := []string{}
	seen := map[string]bool{}
	accounts := map[string]bool{}
	for _, id := range inventory.UsageAccountIDs {
		accounts[id] = true
	}
	for _, resource := range base.Resources {
		if first(resource, "workload_id") != base.WorkloadID || first(resource, "provider") != "AWS" || !accounts[first(resource, "account_id")] {
			return DecisionScope{}, nil, ErrEvidence
		}
		nativeID := first(resource, "provider_resource_id")
		if nativeID == "" || seen[nativeID] {
			return DecisionScope{}, nil, ErrEvidence
		}
		seen[nativeID] = true
		resources = append(resources, nativeID)
	}
	sort.Strings(resources)
	if len(resources) > 2000 {
		return DecisionScope{}, nil, ErrEvidence
	}
	start := now.UTC().Truncate(time.Hour).Add(time.Hour)
	scope := DecisionScope{TenantID: base.TenantID, WorkloadID: base.WorkloadID, PayerAccountID: inventory.PayerAccountID, UsageAccountIDs: inventory.UsageAccountIDs, ResourceIDs: resources, Class: offer.Class, Currency: offer.Currency, ConfigurationSHA256: Hash(map[string]any{"workload": base.Workload, "resources": base.Resources}), HistoryPeriod: inventory.Selection.Period, ProjectionPeriod: Period{Start: start, End: start.Add(8760 * time.Hour)}}
	if base.OwnershipScope != nil && ownershipScope(*base.OwnershipScope) && base.OwnershipScope.TenantID == base.TenantID && base.OwnershipScope.WorkloadID == base.WorkloadID {
		scope.ConfigurationSHA256 = base.OwnershipScope.ConfigurationSHA256
	}
	scope.SHA256 = Hash(scope)
	// This is only a current configuration checksum. Without a separately
	// authenticated interval journal it does not establish historical ownership.
	reasons := []string{"HISTORICAL_OWNERSHIP_ARCHIVE_UNAVAILABLE"}
	if base.OwnershipScope == nil {
		reasons = append(reasons, "CURRENT_ATTESTED_CONFIGURATION_UNAVAILABLE")
	}
	if len(resources) == 0 {
		reasons = append(reasons, "WORKLOAD_NATIVE_RESOURCE_POPULATION_UNAVAILABLE")
	}
	return scope, reasons, nil
}

func decisionUnavailableForecast(requestID string, scope DecisionScope, refs []Ref, reasons []string, now time.Time) DecisionForecastProduction {
	result := DecisionForecastProduction{SchemaVersion: "2", RequestID: requestID, ScopeSHA256: scope.SHA256, RecalculatedAt: now.UTC(), Status: "UNAVAILABLE", Hours: []ForecastHour{}, ReasonCodes: reasons, InputRefs: refs}
	result.ID = Hash(result)
	return result
}

func prepareDecisionArtifacts(base decisionBase, requestID string, now time.Time, ownership *DecisionOwnershipEvidence, ownershipReasons []string) (DecisionAssessment, DecisionForecastProduction, *DecisionForecastRequest, error) {
	inventory, err := PrepareDecisionSnapshot(base.PortfolioInputs, now)
	if err != nil {
		return DecisionAssessment{}, DecisionForecastProduction{}, nil, err
	}
	if base.Portfolio.RequestID == "" || base.Portfolio.RequestID != selectionPortfolioID(base.Selection) {
		return DecisionAssessment{}, DecisionForecastProduction{}, nil, ErrEvidence
	}
	quotes, err := prepareDecisionQuotes(base.OfferReceipt, base.OfferRevision, inventory, nil, now)
	if err != nil || quotes.Offer == nil {
		return DecisionAssessment{}, DecisionForecastProduction{}, nil, ErrEvidence
	}
	scope, reasons, err := decisionCurrentScope(base, *quotes.Offer, now)
	if err != nil {
		return DecisionAssessment{}, DecisionForecastProduction{}, nil, err
	}
	if ownership != nil {
		reference, e := ownership.HistoricalReference()
		if e != nil || base.OwnershipScope == nil || Hash(ownership.Scope) != Hash(*base.OwnershipScope) || ownership.Period.Start.After(scope.HistoryPeriod.Start) || ownership.Period.End.Before(scope.HistoryPeriod.End) {
			return DecisionAssessment{}, DecisionForecastProduction{}, nil, ErrEvidence
		}
		scope.OwnershipRef = reference
		scope.ConfigurationSHA256 = ownership.Scope.ConfigurationSHA256
		scope.SHA256 = ""
		scope.SHA256 = Hash(scope)
		reasons = []string{}
	}
	reasons = append(reasons, ownershipReasons...)
	refs, err := decisionRefs(append(append([]Ref{}, base.InputRefs...), quotes.InputRefs...))
	if err != nil {
		return DecisionAssessment{}, DecisionForecastProduction{}, nil, err
	}
	if ownership != nil {
		refs, err = decisionRefs(append(append(refs, ownership.InputRefs...), scope.OwnershipRef))
		if err != nil {
			return DecisionAssessment{}, DecisionForecastProduction{}, nil, err
		}
	}
	assessment := unavailableDecisionAssessment(requestID, scope, refs, now)
	assessment.ReasonCodes = append(assessment.ReasonCodes, reasons...)
	assessment.ReasonCodes = append(assessment.ReasonCodes, "COMPLETE_POST_OPTIMIZATION_TRAINING_HISTORY_UNAVAILABLE")
	assessment.ID = ""
	assessment.ID = Hash(assessment)
	forecast := decisionUnavailableForecast(requestID, scope, refs, append([]string{}, assessment.ReasonCodes...), now)
	return assessment, forecast, nil, nil
}

func selectionPortfolioID(raw []byte) string {
	var value DecisionPreparationSelection
	_ = json.Unmarshal(raw, &value)
	return value.PortfolioAnalysisRequestID
}

func buildDecisionInput(base decisionBase, requestID string, now time.Time) (DecisionInput, error) {
	var selection DecisionSelection
	if decodeDecisionPrivate(base.Selection, &selection, 8192) != nil || base.Assessment == nil || base.Forecast == nil {
		return DecisionInput{}, ErrEvidence
	}
	a, f := base.Assessment, base.Forecast
	if a.ID != selection.PostOptimizationAssessmentID || f.ID != selection.ForecastID || a.Kind != "OPTIMIZATION_ASSESSMENT" || f.Kind != "POST_OPTIMIZATION_FORECAST" || a.WriterRole != "finops_commitment_portfolio" || f.WriterRole != "finops_commitment_portfolio" || a.WorkloadID != base.WorkloadID || f.WorkloadID != base.WorkloadID || Hash(a.Selection) != Hash(f.Selection) || a.Selection.PortfolioAnalysisRequestID != selection.PortfolioAnalysisRequestID || a.Selection.OfferReceiptID != selection.OfferReceiptID || a.BaseSHA256 != f.BaseSHA256 || a.PayloadSHA256 != Hash(documentFromRaw(a.Payload)) || f.PayloadSHA256 != Hash(documentFromRaw(f.Payload)) {
		return DecisionInput{}, ErrEvidence
	}
	var assessment DecisionAssessment
	var production DecisionForecastProduction
	if decodeDecisionPrivate(a.Payload, &assessment, 1<<20) != nil || decodeDecisionPrivate(f.Payload, &production, 8<<20) != nil || assessment.Scope.SHA256 != f.ScopeSHA256 || assessment.Scope.WorkloadID != base.WorkloadID || assessment.Scope.TenantID != base.TenantID {
		return DecisionInput{}, ErrEvidence
	}
	inventory, err := PrepareDecisionSnapshot(base.PortfolioInputs, now)
	if err != nil {
		return DecisionInput{}, err
	}
	usage, err := PrepareDecisionUsage(base.PortfolioInputs, assessment.Scope, now)
	if err != nil {
		return DecisionInput{}, err
	}
	quotes, err := prepareDecisionQuotes(base.OfferReceipt, base.OfferRevision, inventory, usage.Hours, now)
	if err != nil {
		return DecisionInput{}, err
	}
	forecast, err := assembleDecisionForecast(PersistedForecast{Production: production, ForecastRef: Ref{Kind: "POST_OPTIMIZATION_FORECAST", ID: f.ID, SHA256: f.PayloadSHA256}, CalibrationRef: f.CalibrationRef})
	if err != nil {
		return DecisionInput{}, err
	}
	refs := append(append(append(append([]Ref{}, base.InputRefs...), assessment.InputRefs...), production.InputRefs...), quotes.InputRefs...)
	if f.CalibrationRef != nil {
		refs = append(refs, *f.CalibrationRef)
	}
	refs, err = decisionRefs(refs)
	if err != nil {
		return DecisionInput{}, err
	}
	out := DecisionInput{SchemaVersion: "2", RequestID: requestID, Selection: selection, Scope: assessment.Scope, Portfolio: base.Portfolio, UsageStatus: usage.Status, Usage: usage.Hours, ContractRates: quotes.ContractRates, ContractRateStatus: quotes.ContractStatus, ContractRatePlanIDs: quotes.ContractPlanIDs, ContractRateRefs: quotes.ContractRefs, Offer: quotes.Offer, PAYGBasis: usage.PAYGBasis, OptimizationOrder: assessment.OptimizationOrder, Forecast: &forecast, InputRefs: refs, ObservedAt: now.UTC(), ReasonCodes: append(append([]string{}, usage.ReasonCodes...), quotes.ReasonCodes...)}
	return out, nil
}
