package commitmentportfolio

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// resolvePreparationOwnership selects an actual issued aggregate for the full
// training interval. No current-membership checksum becomes interval evidence.
func (w *Worker) resolvePreparationOwnership(ctx context.Context, requestID string, base decisionBase, training Period) (*DecisionResolvedOwnership, error) {
	if base.OwnershipScope == nil {
		return nil, nil
	}
	tx, err := w.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	var raw []byte
	if err = tx.QueryRow(ctx, "SELECT public.commitment_decision_ownership_discover($1,$2,$3,$4)", w.Tenant, requestID, training.Start, training.End).Scan(&raw); err != nil {
		return nil, decisionSourceError(err)
	}
	if len(raw) == 0 || string(raw) == "null" {
		if err = tx.Commit(ctx); err != nil {
			return nil, err
		}
		// Live journals have their separate actual recording-clock rules. They
		// can qualify only when they genuinely cover this entire old interval;
		// this path never writes journal history or changes those clocks.
		live, e := VerifyDecisionOwnership(ctx, postgresDecisionOwnershipReader{worker: w}, DecisionOwnershipQuery{Scope: *base.OwnershipScope, Period: training}, time.Now().UTC())
		if e != nil && !errors.Is(e, ErrDecisionOwnershipEvidence) {
			return nil, e
		}
		if live.Status != DecisionOwnershipObserved {
			return nil, nil
		}
		reference, e := w.publishDecisionOwnership(ctx, requestID, live)
		if e != nil {
			return nil, decisionSourceError(e)
		}
		check, e := w.begin(ctx)
		if e != nil {
			return nil, e
		}
		defer check.Rollback(ctx)
		pin, e := json.Marshal(reference)
		if e != nil {
			return nil, e
		}
		if e = check.QueryRow(ctx, "SELECT public.commitment_decision_ownership_assert($1,$2,$3::jsonb,$4,$5)", w.Tenant, base.WorkloadID, pin, training.Start, training.End).Scan(&raw); e != nil {
			return nil, decisionSourceError(e)
		}
		if e = check.Commit(ctx); e != nil {
			return nil, e
		}
	}
	var value DecisionResolvedOwnership
	if decodeDecisionPrivate(raw, &value, 1<<20) != nil || validateResolvedDecisionOwnership(value, *base.OwnershipScope, training, time.Now().UTC()) != nil {
		return nil, ErrEvidence
	}
	// The discovery transaction may already be committed before live issuance.
	if err = tx.Commit(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
		return nil, err
	}
	return &value, nil
}

func sealPreparationAssessment(value *DecisionAssessment) { value.ID = ""; value.ID = Hash(*value) }

// prepareConnectedDecisionArtifacts reuses the same restricted worker. Missing
// issuers produce a persisted BLOCKED preparation, never a fabricated final
// recommendation. A real four-stage prefix is required before history/model IO.
func (w *Worker) prepareConnectedDecisionArtifacts(ctx context.Context, base decisionBase, requestID string, now time.Time, calculator DecisionCalculator) (DecisionAssessment, DecisionForecastProduction, error) {
	assessment, forecast, _, err := prepareDecisionArtifacts(base, requestID, now, nil, nil)
	if err != nil {
		return assessment, forecast, err
	}
	training, err := DecisionHistoryTrainingPeriod(assessment.Scope.HistoryPeriod, assessment.Scope.ProjectionPeriod.Start)
	if err != nil {
		return assessment, forecast, nil
	}
	ownership, err := w.resolvePreparationOwnership(ctx, requestID, base, training)
	if err != nil {
		return assessment, forecast, err
	}
	if ownership == nil {
		return assessment, forecast, nil
	}
	// Resolver-time authority checks happen after the initial worker clock.
	now = time.Now().UTC()
	assessment.Scope.OwnershipRef = ownership.Reference
	assessment.Scope.ConfigurationSHA256 = ownership.Scope.ConfigurationSHA256
	assessment.Scope.SHA256 = ""
	assessment.Scope.SHA256 = Hash(assessment.Scope)
	assessment.InputRefs, err = decisionRefs(append(append(assessment.InputRefs, ownership.InputRefs...), ownership.Reference))
	if err != nil {
		return assessment, forecast, err
	}
	prefix, err := ResolveDecisionOptimizationPrefix(ctx, postgresDecisionStageRepository{worker: w}, DecisionOptimizationQuery{RequestID: requestID, Scope: assessment.Scope}, now)
	if err != nil {
		return assessment, forecast, err
	}
	// The actual first stage assessment follows ownership resolution. Producer
	// observation must follow both issued facts rather than predate their clocks.
	now = time.Now().UTC()
	assessment.OptimizationOrder = prefix.OptimizationOrder
	assessment.ReasonCodes = append([]string{}, prefix.ReasonCodes...)
	assessment.InputRefs, err = decisionRefs(append(assessment.InputRefs, prefix.InputRefs...))
	if err != nil {
		return assessment, forecast, err
	}
	assessment.ObservedAt = now
	// Stage five has no proof until the actual numerical producer completes.
	assessment.OptimizationOrder = append(assessment.OptimizationOrder, PostOptimizationStage{Stage: "RECALCULATE_STABLE_DEMAND", Disposition: "UNAVAILABLE", ScopeSHA256: assessment.Scope.SHA256, ReasonCodes: []string{"RECALCULATE_STABLE_DEMAND_ISSUED_OUTCOME_UNAVAILABLE"}})
	assessment.ReasonCodes = append(assessment.ReasonCodes, "RECALCULATE_STABLE_DEMAND_ISSUED_OUTCOME_UNAVAILABLE")
	sealPreparationAssessment(&assessment)
	forecast = decisionUnavailableForecast(requestID, assessment.Scope, assessment.InputRefs, append([]string{}, assessment.ReasonCodes...), now)
	if prefix.Status != "READY" {
		return assessment, forecast, nil
	}
	inventory, err := PrepareDecisionSnapshot(base.PortfolioInputs, now)
	if err != nil {
		return assessment, forecast, err
	}
	request := DecisionForecastRequest{SchemaVersion: "2", RequestID: requestID, Scope: assessment.Scope, ObservedAt: now, OptimizationOrder: prefix.OptimizationOrder, InputRefs: assessment.InputRefs, History: []DecisionHistoryHour{}}
	reader := postgresDecisionHistoryReader{worker: w, requestID: requestID}
	request, pins, err := AssembleDecisionForecastHistory(ctx, reader, request, inventory.Selection, training, *ownership, now)
	if err != nil {
		if !errors.Is(err, ErrDecisionHistory) {
			return assessment, forecast, err
		}
		assessment.ReasonCodes = append(assessment.ReasonCodes, "COMPLETE_POST_OPTIMIZATION_TRAINING_HISTORY_UNAVAILABLE")
		sealPreparationAssessment(&assessment)
		forecast = decisionUnavailableForecast(requestID, assessment.Scope, assessment.InputRefs, append([]string{}, assessment.ReasonCodes...), now)
		return assessment, forecast, nil
	}
	query := DecisionHistoryQuery{Selection: inventory.Selection, Scope: assessment.Scope, TrainingPeriod: training, OwnershipRef: ownership.Reference}
	historyRef, historyRefs, err := w.publishDecisionHistory(ctx, requestID, query, pins)
	if err != nil {
		return assessment, forecast, err
	}
	request.InputRefs, err = decisionRefs(append(append(request.InputRefs, historyRefs...), historyRef))
	if err != nil {
		return assessment, forecast, err
	}
	// No fifth-stage outcome is an input to the producer that creates it.
	forecast, err = calculator.ProduceDecisionForecast(ctx, request)
	if err != nil {
		return assessment, forecast, err
	}
	assessment.InputRefs = forecast.InputRefs
	assessment.ObservedAt = time.Now().UTC()
	if forecast.Status != "CALIBRATED" {
		assessment.ReasonCodes = append([]string{"RECALCULATE_STABLE_DEMAND_FORECAST_UNAVAILABLE"}, forecast.ReasonCodes...)
		sealPreparationAssessment(&assessment)
		return assessment, forecast, nil
	}
	stage, refs := decisionRecalculationOutcome(requestID, assessment.Scope, forecast, assessment.ObservedAt)
	assessment.OptimizationOrder = append(append([]PostOptimizationStage{}, prefix.OptimizationOrder...), stage)
	assessment.InputRefs, err = decisionRefs(append(assessment.InputRefs, refs...))
	if err != nil {
		return assessment, forecast, err
	}
	assessment.Status = "ASSESSED"
	assessment.ReasonCodes = []string{}
	sealPreparationAssessment(&assessment)
	return assessment, forecast, nil
}

// These deterministic proposals are authenticated only when the restricted
// final SQL publisher independently reconstructs and atomically persists them.
// The forecast input closure excludes its own later completion references.
func decisionRecalculationOutcome(requestID string, scope DecisionScope, forecast DecisionForecastProduction, completed time.Time) (PostOptimizationStage, []Ref) {
	decision := map[string]any{"request_id": requestID, "stage": "RECALCULATE_STABLE_DEMAND", "scope_sha256": scope.SHA256, "forecast_sha256": Hash(forecast), "calibration_sha256": Hash(forecast.Calibration), "completed_at": completed.UTC()}
	decisionRef := Ref{Kind: "OPTIMIZATION_DECISION", ID: Hash(decision), SHA256: Hash(decision)}
	reasons := []string{"ACTUAL_TERM_FORECAST_AND_EMPIRICAL_CALIBRATION_PUBLISHED"}
	outcome := map[string]any{"request_id": requestID, "stage": "RECALCULATE_STABLE_DEMAND", "scope_sha256": scope.SHA256, "decision_ref": decisionRef, "disposition": "COMPLETED", "completed_at": completed.UTC(), "reason_codes": reasons}
	outcomeRef := Ref{Kind: "OPTIMIZATION_OUTCOME", ID: Hash(outcome), SHA256: Hash(outcome)}
	return PostOptimizationStage{Stage: "RECALCULATE_STABLE_DEMAND", Disposition: "COMPLETED", DecisionRef: decisionRef, OutcomeRef: outcomeRef, ScopeSHA256: scope.SHA256, CompletedAt: completed.UTC(), ReasonCodes: reasons}, []Ref{decisionRef, outcomeRef}
}
