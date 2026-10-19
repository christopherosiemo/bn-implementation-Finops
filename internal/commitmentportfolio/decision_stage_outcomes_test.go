package commitmentportfolio

import (
	"context"
	"testing"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/slo"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/workload"
)

// A private repository double exercises crash replay of the analytical anchor.
// It does not claim a PostgreSQL issuer, source acquisition or optimization.
type stageReplayRepository struct {
	input     DecisionStageInputs
	published []DecisionStageOutcome
}

func (r *stageReplayRepository) DecisionOptimizationInputs(context.Context, DecisionOptimizationQuery) (DecisionStageInputs, error) {
	return r.input, nil
}
func (r *stageReplayRepository) PublishDecisionOptimizationPrefix(_ context.Context, q DecisionOptimizationQuery, _ string, values []DecisionStageOutcome) ([]PostOptimizationStage, error) {
	if r.published != nil && Hash(r.published) != Hash(values) {
		return nil, ErrEvidence
	}
	r.published = values
	result := make([]PostOptimizationStage, 0, len(values))
	for _, value := range values {
		result = append(result, PostOptimizationStage{Stage: value.Stage, Disposition: value.Disposition, DecisionRef: Ref{Kind: "OPTIMIZATION_DECISION", ID: Hash(value.Stage + value.ID), SHA256: Hash(value)}, OutcomeRef: Ref{Kind: "OPTIMIZATION_OUTCOME", ID: value.ID, SHA256: Hash(value)}, ScopeSHA256: q.Scope.SHA256, CompletedAt: value.AssessedAt, ReasonCodes: value.ReasonCodes})
	}
	return result, nil
}

func TestDecisionStageRetainedActualAssessmentIsStableAcrossWorkerReplay(t *testing.T) {
	q := stageTestQuery()
	first := q.Scope.HistoryPeriod.End.Add(time.Hour)
	repository := &stageReplayRepository{input: DecisionStageInputs{Scope: q.Scope, AssessedAt: first, Resources: map[string]string{q.Scope.ResourceIDs[0]: "resource-a"}, CurrentRefs: []Ref{q.Scope.OwnershipRef}}}
	initial, err := ResolveDecisionOptimizationPrefix(context.Background(), repository, q, first.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := ResolveDecisionOptimizationPrefix(context.Background(), repository, q, first.Add(30*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if Hash(initial) != Hash(replayed) || initial.Status != "BLOCKED" || len(initial.OptimizationOrder) != 4 {
		t.Fatal("worker replay changed issued identity or promoted missing optimization evidence")
	}
	for _, stage := range replayed.OptimizationOrder {
		if !stage.CompletedAt.Equal(first) || stage.Disposition != "UNAVAILABLE" {
			t.Fatal("an absent issuer became a completed action")
		}
	}
	repository.input.AssessedAt = time.Now().UTC().Add(time.Hour)
	if _, err = ResolveDecisionOptimizationPrefix(context.Background(), repository, q, time.Now().UTC()); err == nil {
		t.Fatal("future private assessment clock was accepted")
	}
}

func stageTestRef(kind, id string) Ref { return Ref{Kind: kind, ID: id, SHA256: Hash(id)} }
func stageTestQuery() DecisionOptimizationQuery {
	end := time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC)
	s := DecisionScope{TenantID: "tenant-a", WorkloadID: "workload-a", ResourceIDs: []string{"i-0f040000000000001"}, ConfigurationSHA256: Hash("configuration"), OwnershipRef: stageTestRef("HISTORICAL_OWNERSHIP", "ownership"), HistoryPeriod: Period{Start: end.Add(-24 * time.Hour), End: end}}
	s.SHA256 = Hash(s)
	return DecisionOptimizationQuery{RequestID: "preparation", Scope: s}
}

func TestDecisionStageAlwaysAvailabilityIsAConstraintNotMissingEvidence(t *testing.T) {
	q := stageTestQuery()
	now := q.Scope.HistoryPeriod.End.Add(time.Hour)
	objective := slo.Objective{SchemaVersion: "1", ID: "objective", Version: 1, WorkloadID: q.Scope.WorkloadID, Limits: slo.Limits{MaxErrorRatePPM: 10000, MinAvailabilityPPM: 990000, MaxP95LatencyMS: 180, MaxP99LatencyMS: 250, MinLatencySamples: 10}, EvaluationMinutes: 2, Availability: slo.Availability{Mode: "ALWAYS", Timezone: "UTC", Windows: []slo.Window{}}}
	in := DecisionStageInputs{Objectives: []DecisionStageObjective{{Objective: objective, Reference: stageTestRef("SLO_OBJECTIVE", objective.ID)}}}
	out, err := assessDecisionSchedule(q, in, now)
	if err != nil || out.Disposition != "EVIDENCED_NO_CHANGE" || out.OriginalActionCompletedAt != nil || out.ExecutionAuthorized || out.VerifiedSaving != nil {
		t.Fatal("genuine availability constraint did not remain separate from an execution", err)
	}
	out, err = assessDecisionSchedule(q, DecisionStageInputs{}, now)
	if err != nil || out.Disposition != "UNAVAILABLE" {
		t.Fatal("missing schedule evidence acquired no-change authority", err)
	}
	objective.WorkloadID = "foreign"
	in.Objectives[0].Objective = objective
	if _, err = assessDecisionSchedule(q, in, now); err == nil {
		t.Fatal("unrelated workload constraint was accepted")
	}
}

func TestDecisionStageNativeFixedCapacityMustEqualActualOwnerFloor(t *testing.T) {
	q := stageTestQuery()
	now := q.Scope.HistoryPeriod.End.Add(time.Hour)
	p := workload.Profile{SchemaVersion: "1", ID: "profile", WorkloadID: q.Scope.WorkloadID, Version: 1, Criticality: "NON_PRODUCTION", Statefulness: "UNKNOWN", Timezone: "UTC", MinReplicas: 1, MinZones: 1, Headroom: workload.Headroom{CPUFreePPM: 300000, MemoryFreePPM: 300000}, Saturation: workload.Saturation{CPUP99PPM: 850000, MemoryP99PPM: 900000}, RTOSeconds: 300, MaxSimultaneousChangePPM: 250000, VMCooldownSeconds: 86400}
	profileRef, discoveryRef := stageTestRef("WORKLOAD_SAFETY_PROFILE", "profile"), stageTestRef("AWS_AUTOSCALER_DISCOVERY", "discovery")
	controllerScopeRef := stageTestRef("WORKLOAD_CONTROLLER_SCOPE", "controller-scope")
	in := DecisionStageInputs{Resources: map[string]string{q.Scope.ResourceIDs[0]: "resource-a"}, Profile: &p, ProfileReference: &profileRef, ControllerDiscoveryRef: &discoveryRef, ControllerScopeReference: &controllerScopeRef, Controllers: []DecisionStageController{{Reference: stageTestRef("AWS_AUTOSCALING_GROUP", "asg"), ConfigurationSHA256: q.Scope.ConfigurationSHA256, MemberIDs: q.Scope.ResourceIDs, Minimum: 1, Maximum: 1, Desired: 1}}}
	out, err := assessDecisionAutoscale(q, in, now)
	if err != nil || out.Disposition != "EVIDENCED_NO_CHANGE" {
		t.Fatal("native fixed count equal to mandatory floor was refused", err)
	}
	in.ControllerScopeReference = nil
	out, err = assessDecisionAutoscale(q, in, now)
	if err != nil || out.Disposition != "UNAVAILABLE" {
		t.Fatal("ASG point alone acquired full controller-family authority", err)
	}
	in.ControllerScopeReference = &controllerScopeRef
	in.Controllers[0].Maximum = 2
	out, err = assessDecisionAutoscale(q, in, now)
	if err != nil || out.Disposition != "UNAVAILABLE" {
		t.Fatal("dynamic policy was mistaken for an optimized fixed policy", err)
	}
	in.Controllers = []DecisionStageController{}
	out, err = assessDecisionAutoscale(q, in, now)
	if err != nil || out.Disposition != "UNAVAILABLE" {
		t.Fatal("absent controller was treated as proven absent", err)
	}
}

func TestDecisionStageSingleCandidateNeedsActualBusinessConstraintIssuer(t *testing.T) {
	q := stageTestQuery()
	now := q.Scope.HistoryPeriod.End.Add(time.Hour)
	in := DecisionStageInputs{Sizing: &DecisionStageSizingCatalog{Reference: stageTestRef("AWS_HARDWARE", "current-hardware"), ConfigurationSHA256: q.Scope.ConfigurationSHA256, AllowedInstanceTypes: []string{"m6i.large"}}}
	out, err := assessDecisionRightsize(q, in, now)
	if err != nil || out.Disposition != "UNAVAILABLE" {
		t.Fatal("current hardware was promoted into a one-type business constraint", err)
	}
}

func TestDecisionStageRightsizeMustIncludeAndProveEveryCurrentType(t *testing.T) {
	q := stageTestQuery()
	now := q.Scope.HistoryPeriod.End.Add(time.Hour)
	for name, current := range map[string]map[string]string{
		"missing":  {},
		"empty":    {q.Scope.ResourceIDs[0]: ""},
		"excluded": {q.Scope.ResourceIDs[0]: "m6i.xlarge"},
	} {
		t.Run(name, func(t *testing.T) {
			in := DecisionStageInputs{Sizing: &DecisionStageSizingCatalog{Reference: stageTestRef("APPROVED_CANDIDATE_CATALOG", "catalog"), ConfigurationSHA256: q.Scope.ConfigurationSHA256, AllowedInstanceTypes: []string{"m6i.large", "m6i.medium"}, CurrentInstanceTypes: current}}
			if _, err := assessDecisionRightsize(q, in, now); err == nil {
				t.Fatal("an excluded/missing current candidate could be mistaken for optimized capacity")
			}
		})
	}
	for _, tc := range []struct {
		candidate, status string
		want              bool
	}{{"m6i.large", "FAIL", false}, {"m6i.large", "UNKNOWN", false}, {"m6i.large", "PASS", true}, {"m6i.medium", "PASS", false}, {"m6i.medium", "UNKNOWN", false}, {"m6i.medium", "FAIL", true}} {
		if got := stageSizingPhysicalDisposition("m6i.large", tc.candidate, tc.status); got != tc.want {
			t.Fatalf("current/alternative dimensional evidence accepted incorrectly: %s %s", tc.candidate, tc.status)
		}
	}
}
