package commitmentportfolio

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/slo"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/workload"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// ErrDecisionStageInputsAbsent is reserved for a missing mandatory issued
// preparation/ownership scope. Optional absent producers are represented by nil
// or empty typed inputs, so the factory emits their explicit UNAVAILABLE result.
var ErrDecisionStageInputsAbsent = errors.New("COMMITMENT_OPTIMIZATION_ISSUED_SCOPE_UNAVAILABLE")

// The same credentialed portfolio process implements this private boundary.
// SQL selects every input and repeats the selection under publication fences;
// the caller can neither submit an observation nor confer an issuer role.
type postgresDecisionStageRepository struct{ worker *Worker }

var _ DecisionOptimizationRepository = postgresDecisionStageRepository{}

func decisionStageReadError(err error) error {
	var database *pgconn.PgError
	if errors.Is(err, pgx.ErrNoRows) || errors.As(err, &database) && database.Code == "P0002" {
		return ErrDecisionStageInputsAbsent
	}
	return err
}

func (r postgresDecisionStageRepository) transaction(ctx context.Context, run func(pgx.Tx) error) error {
	if r.worker == nil || r.worker.Pool == nil || !tenantPattern.MatchString(r.worker.Tenant) {
		return ErrEvidence
	}
	tx, err := r.worker.begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err = run(tx); err != nil {
		return decisionStageReadError(err)
	}
	return tx.Commit(ctx)
}

func (r postgresDecisionStageRepository) valid(q DecisionOptimizationQuery) bool {
	return r.worker != nil && idPattern.MatchString(q.RequestID) && stageScope(q.Scope) && q.Scope.TenantID == r.worker.Tenant
}

func (r postgresDecisionStageRepository) DecisionOptimizationInputs(ctx context.Context, q DecisionOptimizationQuery) (DecisionStageInputs, error) {
	var out DecisionStageInputs
	if !r.valid(q) {
		return out, ErrEvidence
	}
	scope, err := json.Marshal(q.Scope)
	if err != nil {
		return out, ErrEvidence
	}
	err = r.transaction(ctx, func(tx pgx.Tx) error {
		var raw []byte
		if e := tx.QueryRow(ctx, "SELECT public.commitment_optimization_stage_inputs($1,$2,$3::jsonb)", r.worker.Tenant, q.RequestID, scope).Scan(&raw); e != nil {
			return e
		}
		if len(raw) == 0 || string(raw) == "null" {
			return ErrDecisionStageInputsAbsent
		}
		if decodeDecisionPrivate(raw, &out, 32<<20) != nil || Hash(out) != Hash(documentFromRaw(raw)) || Hash(out.Scope) != Hash(q.Scope) || len(out.Resources) != len(q.Scope.ResourceIDs) || out.AssessedAt.IsZero() {
			return ErrEvidence
		}
		for _, id := range q.Scope.ResourceIDs {
			if !idPattern.MatchString(out.Resources[id]) {
				return ErrEvidence
			}
		}
		if out.Profile != nil && (out.ProfileReference == nil || workload.Validate(*out.Profile) != nil || out.Profile.ID != out.ProfileReference.ID || out.Profile.WorkloadID != q.Scope.WorkloadID) {
			return ErrEvidence
		}
		for _, objective := range out.Objectives {
			if slo.ValidateObjective(objective.Objective) != nil || objective.Reference.ID != objective.Objective.ID || objective.Objective.WorkloadID != q.Scope.WorkloadID {
				return ErrEvidence
			}
		}
		// No complete source-owned issuer exists for these producer types yet.
		// Refusing nonempty projections here prevents a later SQL edit alone
		// from promoting a current native point into broader proof authority.
		if out.Work == nil || out.Objectives == nil || out.ScheduleActions == nil || out.Controllers == nil || out.UnmanagedResourceIDs == nil || out.CurrentRefs == nil || len(out.Work) > 0 || len(out.ScheduleActions) > 0 || len(out.UnmanagedResourceIDs) > 0 {
			return ErrEvidence
		}
		return nil
	})
	if err != nil {
		return DecisionStageInputs{}, err
	}
	// Validate the typed policy projection after releasing the earlier graph
	// transaction; nested transactions holding that same lock would self-block.
	policy, err := r.loadDecisionStagePolicy(ctx, q, time.Now().UTC())
	if err != nil {
		return DecisionStageInputs{}, err
	}
	if Hash(out.Sizing) != Hash(policy.Sizing) || Hash(out.Controllers) != Hash(policy.Controllers) || Hash(out.ControllerDiscoveryRef) != Hash(policy.ControllerDiscoveryRef) || Hash(out.ControllerScopeReference) != Hash(policy.ControllerScopeReference) {
		return DecisionStageInputs{}, ErrEvidence
	}
	refs, err := decisionRefs(append(append([]Ref{}, out.CurrentRefs...), policy.CurrentRefs...))
	if err != nil || Hash(refs) != Hash(out.CurrentRefs) {
		return DecisionStageInputs{}, ErrEvidence
	}
	return out, nil
}

func (r postgresDecisionStageRepository) PublishDecisionOptimizationPrefix(ctx context.Context, q DecisionOptimizationQuery, inputSHA string, values []DecisionStageOutcome) ([]PostOptimizationStage, error) {
	if !r.valid(q) || !shaPattern.MatchString(inputSHA) || len(values) != 4 {
		return nil, ErrEvidence
	}
	stages := []string{"REMOVE_IDLE", "SCHEDULE", "RIGHTSIZE", "AUTOSCALE"}
	for i, value := range values {
		blank := value
		blank.ID = ""
		if value.SchemaVersion != "1" || value.RequestID != q.RequestID || value.Stage != stages[i] || value.ScopeSHA256 != q.Scope.SHA256 || value.ID != Hash(blank) || value.ExecutionAuthorized || value.VerifiedSaving != nil || value.AssessedAt.IsZero() {
			return nil, ErrEvidence
		}
	}
	scope, err := json.Marshal(q.Scope)
	if err != nil {
		return nil, ErrEvidence
	}
	outcomes, err := json.Marshal(values)
	if err != nil || len(outcomes) > 256<<10 {
		return nil, ErrEvidence
	}
	var answer []PostOptimizationStage
	err = r.transaction(ctx, func(tx pgx.Tx) error {
		// Publication's fixed four-argument SQL contract carries the exact
		// scope and outcomes together; it never accepts a caller status body.
		payload, err := json.Marshal(map[string]json.RawMessage{"scope": scope, "outcomes": outcomes})
		if err != nil {
			return ErrEvidence
		}
		var raw []byte
		if err = tx.QueryRow(ctx, "SELECT public.commitment_optimization_prefix_publish($1,$2,$3,$4::jsonb)", r.worker.Tenant, q.RequestID, inputSHA, payload).Scan(&raw); err != nil {
			return err
		}
		if decodeDecisionPrivate(raw, &answer, 256<<10) != nil || len(answer) != 4 {
			return ErrEvidence
		}
		for i, value := range answer {
			if value.Stage != values[i].Stage || value.ScopeSHA256 != q.Scope.SHA256 || value.Disposition != values[i].Disposition || !value.CompletedAt.Equal(values[i].AssessedAt) || !stageRef(value.DecisionRef) || !stageRef(value.OutcomeRef) || value.DecisionRef.Kind != "OPTIMIZATION_DECISION" || value.OutcomeRef.Kind != "OPTIMIZATION_OUTCOME" {
				return ErrEvidence
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return answer, nil
}
