package commitmentportfolio

import (
	"context"
	"sort"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/fleetcapacity"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/fleetdecision"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/slo"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/workload"
)

// This private factory consumes repository-selected records. Checksums check
// consistency; only the repository's scoped loaders and publication fences
// establish the issuer and currentness of the records. It has no upload API.
// Scope is the final post-optimization scope, including its ownership reference.
type DecisionOptimizationQuery struct {
	RequestID string
	Scope     DecisionScope
}

type DecisionOptimizationPrefix struct {
	Status            string                  `json:"status"`
	OptimizationOrder []PostOptimizationStage `json:"optimization_order"`
	InputRefs         []Ref                   `json:"input_refs"`
	ReasonCodes       []string                `json:"reason_codes"`
}

// StageOutcome is a new analytical assessment of the selected original facts.
// Its assessment timestamp never replaces an original execution timestamp.
type DecisionStageOutcome struct {
	SchemaVersion             string     `json:"schema_version"`
	ID                        string     `json:"id"`
	RequestID                 string     `json:"request_id"`
	Stage                     string     `json:"stage"`
	ScopeSHA256               string     `json:"scope_sha256"`
	Disposition               string     `json:"disposition"`
	InputRefs                 []Ref      `json:"input_refs"`
	ReasonCodes               []string   `json:"reason_codes"`
	OriginalActionCompletedAt *time.Time `json:"original_action_completed_at"`
	AssessedAt                time.Time  `json:"assessed_at"`
	ExecutionAuthorized       bool       `json:"execution_authorized"`
	VerifiedSaving            *string    `json:"verified_saving"`
}

// DecisionStageWork is a complete, original guarded minute receipt. Its source
// and metric definition are loaded from activity_sources, not from its body.
type DecisionStageWork struct {
	Source    store.ActivitySource
	Receipt   store.ActivityReceipt
	Reference Ref
}

type DecisionStageObjective struct {
	Objective slo.Objective
	Reference Ref
}

// A schedule action must have a genuine signed plan, accepted execution and
// provider ownership/restoration record selected by the repository. A generic
// COMPLETED entity or a failed/rolled-back occurrence cannot qualify.
type DecisionStageScheduleAction struct {
	Plan               model.Envelope
	PlanReference      Ref
	Execution          model.Document
	ExecutionReference Ref
	ProviderOperation  model.Document
	OperationReference Ref
}

// The allowed catalog is a separately issued configuration-policy selection,
// never the list of candidates that happened to finish. Native catalog and
// policy issuer implementations are still required before a restricted
// repository can return this type. A lone failing036 candidate is insufficient.
type DecisionStageSizingCatalog struct {
	Reference            Ref
	ConfigurationSHA256  string
	AllowedInstanceTypes []string
	CurrentInstanceTypes map[string]string
	Joins                []DecisionStageSizingJoin
}

type DecisionStageSizingJoin struct {
	Input     fleetdecision.Input
	Reference Ref
	// Actual persisted037 decision timestamp, independently hash-bound below.
	ObservedAt time.Time
}

// Native controller discovery must cover the whole scoped population. Unknown
// or unenumerated controllers cannot be represented as an empty list.
type DecisionStageController struct {
	Reference           Ref
	ConfigurationSHA256 string
	MemberIDs           []string
	Minimum             int
	Maximum             int
	Desired             int
}

type DecisionStageInputs struct {
	Scope DecisionScope
	// The actual first assessment timestamp is selected by the repository, then
	// retained with its immutable prefix. Every retry repeats currentness checks.
	AssessedAt               time.Time
	Resources                map[string]string // exact native ID -> internal resource ID
	Work                     []DecisionStageWork
	Objectives               []DecisionStageObjective
	ScheduleActions          []DecisionStageScheduleAction
	Sizing                   *DecisionStageSizingCatalog
	Profile                  *workload.Profile
	ProfileReference         *Ref
	Controllers              []DecisionStageController
	UnmanagedResourceIDs     []string // only from complete native controller discovery
	ControllerDiscoveryRef   *Ref
	ControllerScopeReference *Ref
	CurrentRefs              []Ref
}

// The existing credentialed daemon can implement this boundary in its
// preparation transaction. Publish must reacquire graph/source/credential and
// configuration fences, repeat the input selection and compare its exact hash.
// It returns actual immutable issued refs; this factory never fabricates them.
type DecisionOptimizationRepository interface {
	DecisionOptimizationInputs(context.Context, DecisionOptimizationQuery) (DecisionStageInputs, error)
	PublishDecisionOptimizationPrefix(context.Context, DecisionOptimizationQuery, string, []DecisionStageOutcome) ([]PostOptimizationStage, error)
}

func stageRef(r Ref) bool {
	return r.Kind != "" && idPattern.MatchString(r.ID) && shaPattern.MatchString(r.SHA256)
}

func stageScope(s DecisionScope) bool {
	c := s
	c.SHA256 = ""
	if !shaPattern.MatchString(s.SHA256) || Hash(c) != s.SHA256 || s.OwnershipRef.Kind != "HISTORICAL_OWNERSHIP" || !stageRef(s.OwnershipRef) || !shaPattern.MatchString(s.ConfigurationSHA256) || len(s.ResourceIDs) == 0 || len(s.ResourceIDs) > 128 || !s.HistoryPeriod.Start.Before(s.HistoryPeriod.End) {
		return false
	}
	for i, id := range s.ResourceIDs {
		if !idPattern.MatchString(id) || i > 0 && s.ResourceIDs[i-1] >= id {
			return false
		}
	}
	return true
}

func stageOutcome(q DecisionOptimizationQuery, stage string, now time.Time) DecisionStageOutcome {
	return DecisionStageOutcome{SchemaVersion: "1", RequestID: q.RequestID, Stage: stage, ScopeSHA256: q.Scope.SHA256, Disposition: "UNAVAILABLE", InputRefs: []Ref{}, ReasonCodes: []string{}, AssessedAt: now.UTC()}
}

func stageSeal(out DecisionStageOutcome) (DecisionStageOutcome, error) {
	var err error
	out.InputRefs, err = decisionRefs(out.InputRefs)
	if err != nil {
		return out, err
	}
	out.ID = ""
	out.ID = Hash(out)
	return out, nil
}

// REMOVE_IDLE is deliberately limited to entirely unused resource removal.
// One resource's work cannot be extrapolated to another. Every minute must have
// an original independent receipt and every scoped resource must perform work
// in every hour; gaps/zero work trigger further assessment, never deletion.
func assessDecisionRemoveIdle(q DecisionOptimizationQuery, in DecisionStageInputs, now time.Time) (DecisionStageOutcome, error) {
	out := stageOutcome(q, "REMOVE_IDLE", now)
	if in.Profile != nil && in.ProfileReference != nil && workload.Validate(*in.Profile) == nil && in.Profile.WorkloadID == q.Scope.WorkloadID && stageRef(*in.ProfileReference) && in.Profile.MinReplicas == len(q.Scope.ResourceIDs) {
		out.InputRefs = append(out.InputRefs, *in.ProfileReference)
		out.Disposition = "EVIDENCED_NO_CHANGE"
		out.ReasonCodes = append(out.ReasonCodes, "OWNER_REQUIRED_REPLICA_FLOOR_FORBIDS_RESOURCE_REMOVAL")
		return stageSeal(out)
	}
	if len(in.Work) == 0 {
		out.ReasonCodes = append(out.ReasonCodes, "REMOVE_IDLE_COMPLETE_BUSINESS_WORK_HISTORY_UNAVAILABLE")
		return stageSeal(out)
	}
	expected := int(q.Scope.HistoryPeriod.End.Sub(q.Scope.HistoryPeriod.Start) / time.Minute)
	if expected < 1 || expected > 31*24*60 || len(in.Work) > 128*31*24*60 {
		return out, ErrEvidence
	}
	minutes := map[string]map[time.Time]bool{}
	hours := map[string]map[time.Time]bool{}
	for _, w := range in.Work {
		r, s := w.Receipt, w.Source
		if in.Resources[s.ProviderResourceID] != s.ResourceID || s.WorkloadID != q.Scope.WorkloadID || !s.Enabled || r.TenantID != q.Scope.TenantID || r.ResourceID != s.ResourceID || r.SourceID != s.ID || r.Subject != s.Subject || r.MetricDefinition != s.MetricDefinition || r.IntervalEnd.Sub(r.IntervalStart) != time.Minute || r.IntervalStart.Before(q.Scope.HistoryPeriod.Start) || r.IntervalEnd.After(q.Scope.HistoryPeriod.End) || !r.Heartbeat || r.Accepted < 0 || r.Completed < 0 || r.Rejected < 0 || r.Backlog < 0 || r.Inflight < 0 || !stageRef(w.Reference) || w.Reference.ID != r.ID || w.Reference.SHA256 != Hash(r) {
			return out, ErrEvidence
		}
		if minutes[s.ProviderResourceID] == nil {
			minutes[s.ProviderResourceID] = map[time.Time]bool{}
			hours[s.ProviderResourceID] = map[time.Time]bool{}
		}
		if minutes[s.ProviderResourceID][r.IntervalStart] {
			return out, ErrEvidence
		}
		minutes[s.ProviderResourceID][r.IntervalStart] = true
		if r.Completed > 0 {
			hours[s.ProviderResourceID][r.IntervalStart.Truncate(time.Hour)] = true
		}
		out.InputRefs = append(out.InputRefs, w.Reference)
	}
	for _, id := range q.Scope.ResourceIDs {
		if len(minutes[id]) != expected {
			out.ReasonCodes = append(out.ReasonCodes, "REMOVE_IDLE_BUSINESS_WORK_COVERAGE_INCOMPLETE")
			return stageSeal(out)
		}
		for at := q.Scope.HistoryPeriod.Start; at.Before(q.Scope.HistoryPeriod.End); at = at.Add(time.Hour) {
			if !hours[id][at] {
				out.ReasonCodes = append(out.ReasonCodes, "REMOVE_IDLE_ZERO_WORK_HOUR_REQUIRES_INDEPENDENT_REVIEW")
				return stageSeal(out)
			}
		}
	}
	out.Disposition = "EVIDENCED_NO_CHANGE"
	out.ReasonCodes = append(out.ReasonCodes, "EVERY_SCOPED_RESOURCE_PERFORMS_OBSERVED_COMPLETED_WORK_EACH_HOUR")
	return stageSeal(out)
}

func assessDecisionSchedule(q DecisionOptimizationQuery, in DecisionStageInputs, now time.Time) (DecisionStageOutcome, error) {
	out := stageOutcome(q, "SCHEDULE", now)
	// Availability is a current owner-approved constraint, not usage evidence.
	// An ALWAYS objective leaves no admissible STOP window under that constraint.
	if len(in.Objectives) == 1 {
		o := in.Objectives[0]
		if slo.ValidateObjective(o.Objective) != nil || o.Objective.WorkloadID != q.Scope.WorkloadID || !stageRef(o.Reference) || o.Reference.ID != o.Objective.ID {
			return out, ErrEvidence
		}
		out.InputRefs = append(out.InputRefs, o.Reference)
		if o.Objective.Availability.Mode == "ALWAYS" {
			out.Disposition = "EVIDENCED_NO_CHANGE"
			out.ReasonCodes = append(out.ReasonCodes, "CURRENT_SLO_REQUIRES_CONTINUOUS_AVAILABILITY")
			return stageSeal(out)
		}
	}
	byResource := map[string]time.Time{}
	for _, a := range in.ScheduleActions {
		p := a.Plan.Plan
		x, op := a.Execution, a.ProviderOperation
		if p.Fixture || p.SchemaVersion != "3" || p.TenantID != q.Scope.TenantID || p.WorkloadID != q.Scope.WorkloadID || model.String(x, "change_plan_id") != p.ID || model.String(x, "status") != "COMPLETED" || model.String(x, "stage") != "VERIFY_ECONOMICS" || model.Bool(x, "restoration_owned") || model.String(x, "error") != "" || model.String(op, "execution_id") != model.String(x, "id") || !model.Bool(op, "stop_intent") || !model.Bool(op, "stop_owned") || !model.Bool(op, "restored") || !stageRef(a.PlanReference) || a.PlanReference.ID != p.ID || a.PlanReference.SHA256 != Hash(a.Plan) || !stageRef(a.ExecutionReference) || a.ExecutionReference.ID != model.String(x, "id") || a.ExecutionReference.SHA256 != Hash(x) || !stageRef(a.OperationReference) || a.OperationReference.ID != model.String(x, "id") || a.OperationReference.SHA256 != Hash(op) {
			return out, ErrEvidence
		}
		completed, e := time.Parse(time.RFC3339Nano, model.String(x, "completed_at"))
		if e != nil || completed.After(now) {
			return out, ErrEvidence
		}
		matched := ""
		for _, action := range p.Operations {
			if action.Type == "STOP" {
				if matched != "" || in.Resources[action.ProviderResourceID] != action.ResourceID || action.ResourceID != model.String(x, "resource_id") {
					return out, ErrEvidence
				}
				matched = action.ProviderResourceID
			}
		}
		if matched == "" {
			return out, ErrEvidence
		}
		if completed.After(byResource[matched]) {
			byResource[matched] = completed
		}
		out.InputRefs = append(out.InputRefs, a.PlanReference, a.ExecutionReference, a.OperationReference)
	}
	if len(byResource) != len(q.Scope.ResourceIDs) {
		out.ReasonCodes = append(out.ReasonCodes, "SCHEDULE_SCOPED_COMPLETED_OUTCOME_UNAVAILABLE")
		return stageSeal(out)
	}
	latest := time.Time{}
	for _, at := range byResource {
		if at.After(latest) {
			latest = at
		}
	}
	out.OriginalActionCompletedAt = &latest
	out.Disposition = "COMPLETED"
	out.ReasonCodes = append(out.ReasonCodes, "EXACT_SCOPED_SCHEDULE_RESTORED_AND_HEALTH_COMPLETED")
	return stageSeal(out)
}

func assessDecisionRightsize(q DecisionOptimizationQuery, in DecisionStageInputs, now time.Time) (DecisionStageOutcome, error) {
	out := stageOutcome(q, "RIGHTSIZE", now)
	if in.Sizing == nil {
		out.ReasonCodes = append(out.ReasonCodes, "RIGHTSIZE_EXHAUSTIVE_APPROVED_CATALOG_AND_MEMBER_ASSESSMENTS_UNAVAILABLE")
		return stageSeal(out)
	}
	c := in.Sizing
	if !stageRef(c.Reference) || c.ConfigurationSHA256 != q.Scope.ConfigurationSHA256 || len(c.AllowedInstanceTypes) < 1 || len(c.AllowedInstanceTypes) > 256 {
		return out, ErrEvidence
	}
	// A single permitted type is valid only as an actual separately issued
	// business/license constraint. Current launch-template configuration alone
	// cannot invent such a restriction or pretend an exhaustive catalog.
	if len(c.AllowedInstanceTypes) == 1 && c.Reference.Kind != "WORKLOAD_SIZE_CONSTRAINT" {
		out.ReasonCodes = append(out.ReasonCodes, "RIGHTSIZE_EXHAUSTIVE_CATALOG_OR_BUSINESS_CONSTRAINT_REQUIRED")
		return stageSeal(out)
	}
	allowed := map[string]bool{}
	for _, kind := range c.AllowedInstanceTypes {
		if kind == "" || allowed[kind] {
			return out, ErrEvidence
		}
		allowed[kind] = true
	}
	for _, id := range q.Scope.ResourceIDs {
		if c.CurrentInstanceTypes[id] == "" || !allowed[c.CurrentInstanceTypes[id]] {
			return out, ErrEvidence
		}
	}
	seen := map[string]bool{}
	out.InputRefs = append(out.InputRefs, c.Reference)
	for _, join := range c.Joins {
		j := join.Input
		if j.Scope.CandidateTemplate == nil || !allowed[j.Scope.CandidateTemplate.InstanceType] || !stageRef(join.Reference) || join.Reference.ID != j.RequestID || j.Profile.WorkloadID != q.Scope.WorkloadID {
			return out, ErrEvidence
		}
		// Reuse037's independent five-dimension arithmetic and closure checks.
		// Overall036/037 BLOCKED never stands in for physical FAIL.
		if join.ObservedAt.IsZero() || join.ObservedAt.After(now) || j.Assessment.ObservedAt.Before(now.Add(-2*time.Minute)) || j.Scope.Scope.ObservedAt.Before(now.Add(-5*time.Minute)) {
			return out, ErrEvidence
		}
		for _, member := range j.Members {
			if member.Document.ObservedAt.Before(now.Add(-5 * time.Minute)) {
				return out, ErrEvidence
			}
		}
		decision, e := fleetdecision.Build(j, join.ObservedAt)
		if e != nil || join.Reference.SHA256 != Hash(decision) {
			return out, ErrEvidence
		}
		if len(decision.Members) != len(q.Scope.ResourceIDs) {
			return out, ErrEvidence
		}
		for _, m := range decision.Members {
			if _, ok := in.Resources[m.InstanceID]; !ok {
				return out, ErrEvidence
			}
			kind := j.Scope.CandidateTemplate.InstanceType
			var selected *fleetcapacity.MemberResult
			for index := range j.Members {
				if j.Members[index].Document.InstanceID == m.InstanceID {
					if selected != nil {
						return out, ErrEvidence
					}
					selected = &j.Members[index].Document
				}
			}
			if selected == nil {
				return out, ErrEvidence
			}
			key := m.InstanceID + ":" + kind
			if seen[key] {
				return out, ErrEvidence
			}
			seen[key] = true
			if !stageSizingPhysicalDisposition(c.CurrentInstanceTypes[m.InstanceID], kind, m.Status) {
				out.ReasonCodes = append(out.ReasonCodes, "RIGHTSIZE_CURRENT_OR_ALTERNATIVE_PHYSICAL_VERDICT_UNRESOLVED")
				return stageSeal(out)
			}
			if !stageSizingModelKind(*selected, c.CurrentInstanceTypes[m.InstanceID], kind) {
				return out, ErrEvidence
			}
		}
		out.InputRefs = append(out.InputRefs, join.Reference)
	}
	for _, id := range q.Scope.ResourceIDs {
		for kind := range allowed {
			if !seen[id+":"+kind] {
				out.ReasonCodes = append(out.ReasonCodes, "RIGHTSIZE_CANDIDATE_OR_MEMBER_POPULATION_INCOMPLETE")
				return stageSeal(out)
			}
		}
	}
	out.Disposition = "EVIDENCED_NO_CHANGE"
	out.ReasonCodes = append(out.ReasonCodes, "ALL_OTHER_APPROVED_CANDIDATES_HAVE_AN_OBSERVED_PHYSICAL_FAILURE")
	return stageSeal(out)
}

func stageSizingPhysicalDisposition(current, candidate, status string) bool {
	if current == "" || candidate == "" {
		return false
	}
	if candidate == current {
		return status == "PASS"
	}
	return status == "FAIL"
}

func stageSizingModelKind(member fleetcapacity.MemberResult, current, candidate string) bool {
	baseline := member.InputKind == "CURRENT_CONFIGURATION_BASELINE_MODEL_REQUEST"
	reason := false
	for _, code := range member.ReasonCodes {
		reason = reason || code == "CURRENT_CONFIGURATION_BASELINE_ONLY"
	}
	if current != candidate {
		return member.InputKind == "MODEL_REQUEST" && !baseline && !reason
	}
	mapping := member.HardwareMapping
	return baseline && reason && mapping != nil && len(mapping.Candidates) == 1 && mapping.Current.ID == current && mapping.Candidates[0].ID == current && Hash(mapping.Current) == Hash(mapping.Candidates[0]) && member.CandidateTemplate != nil && member.CandidateTemplate.InstanceType == current
}

func assessDecisionAutoscale(q DecisionOptimizationQuery, in DecisionStageInputs, now time.Time) (DecisionStageOutcome, error) {
	out := stageOutcome(q, "AUTOSCALE", now)
	if in.Profile == nil || in.ProfileReference == nil || in.ControllerDiscoveryRef == nil || in.ControllerScopeReference == nil {
		out.ReasonCodes = append(out.ReasonCodes, "AUTOSCALE_COMPLETE_CONTROLLER_AND_POLICY_SCOPE_UNAVAILABLE")
		return stageSeal(out)
	}
	p := in.Profile
	if workload.Validate(*p) != nil || p.WorkloadID != q.Scope.WorkloadID || !stageRef(*in.ProfileReference) || !stageRef(*in.ControllerDiscoveryRef) || !stageRef(*in.ControllerScopeReference) || in.ControllerScopeReference.Kind != "WORKLOAD_CONTROLLER_SCOPE" {
		return out, ErrEvidence
	}
	out.InputRefs = append(out.InputRefs, *in.ProfileReference, *in.ControllerDiscoveryRef, *in.ControllerScopeReference)
	seen := map[string]bool{}
	minimum := 0
	for _, id := range in.UnmanagedResourceIDs {
		if _, ok := in.Resources[id]; !ok || seen[id] {
			return out, ErrEvidence
		}
		seen[id] = true
		minimum++
	}
	for _, c := range in.Controllers {
		if !stageRef(c.Reference) || c.ConfigurationSHA256 != q.Scope.ConfigurationSHA256 || c.Minimum < 1 || c.Maximum < c.Minimum || c.Desired < c.Minimum || c.Desired > c.Maximum || len(c.MemberIDs) != c.Desired {
			return out, ErrEvidence
		}
		for _, id := range c.MemberIDs {
			if _, ok := in.Resources[id]; !ok || seen[id] {
				return out, ErrEvidence
			}
			seen[id] = true
		}
		minimum += c.Minimum
		out.InputRefs = append(out.InputRefs, c.Reference)
	}
	if len(seen) != len(q.Scope.ResourceIDs) {
		out.ReasonCodes = append(out.ReasonCodes, "AUTOSCALE_CONTROLLER_MEMBERSHIP_INCOMPLETE")
		return stageSeal(out)
	}
	if minimum != p.MinReplicas || minimum != len(q.Scope.ResourceIDs) {
		out.ReasonCodes = append(out.ReasonCodes, "AUTOSCALE_CAPACITY_ABOVE_MINIMUM_REQUIRES_OPTIMIZATION")
		return stageSeal(out)
	}
	for _, c := range in.Controllers {
		if c.Maximum != c.Minimum {
			out.ReasonCodes = append(out.ReasonCodes, "AUTOSCALE_DYNAMIC_POLICY_ASSESSMENT_REQUIRED")
			return stageSeal(out)
		}
	}
	// Within this owner-imposed replica floor, native fixed min=max=desired
	// leaves no permissible capacity reduction. This does not predict demand,
	// prove autoscaler efficiency or claim every workload should be fixed-size.
	out.Disposition = "EVIDENCED_NO_CHANGE"
	out.ReasonCodes = append(out.ReasonCodes, "NATIVE_FIXED_CAPACITY_EQUALS_OWNER_REQUIRED_REPLICA_FLOOR")
	return stageSeal(out)
}

func ResolveDecisionOptimizationPrefix(ctx context.Context, repository DecisionOptimizationRepository, q DecisionOptimizationQuery, now time.Time) (DecisionOptimizationPrefix, error) {
	out := DecisionOptimizationPrefix{Status: "BLOCKED", OptimizationOrder: []PostOptimizationStage{}, InputRefs: []Ref{}, ReasonCodes: []string{}}
	if repository == nil || !idPattern.MatchString(q.RequestID) || !stageScope(q.Scope) || now.IsZero() {
		return out, ErrEvidence
	}
	in, err := repository.DecisionOptimizationInputs(ctx, q)
	if err != nil {
		return out, err
	}
	// The private SQL read happens after caller now was captured. Compare its
	// real first-assessment clock with the actual clock after that read; this
	// does not permit a caller-supplied future observation or alter source gates.
	checkedAt := time.Now().UTC()
	if Hash(in.Scope) != Hash(q.Scope) || len(in.Resources) != len(q.Scope.ResourceIDs) || in.AssessedAt.IsZero() || in.AssessedAt.After(checkedAt) {
		return out, ErrEvidence
	}
	for _, id := range q.Scope.ResourceIDs {
		if !idPattern.MatchString(in.Resources[id]) {
			return out, ErrEvidence
		}
	}
	out.InputRefs = append(out.InputRefs, in.CurrentRefs...)
	functions := []func(DecisionOptimizationQuery, DecisionStageInputs, time.Time) (DecisionStageOutcome, error){assessDecisionRemoveIdle, assessDecisionSchedule, assessDecisionRightsize, assessDecisionAutoscale}
	values := make([]DecisionStageOutcome, 0, 4)
	for _, factory := range functions {
		value, e := factory(q, in, in.AssessedAt)
		if e != nil {
			return out, e
		}
		values = append(values, value)
		out.InputRefs = append(out.InputRefs, value.InputRefs...)
		out.ReasonCodes = append(out.ReasonCodes, value.ReasonCodes...)
	}
	stages, err := repository.PublishDecisionOptimizationPrefix(ctx, q, Hash(in), values)
	if err != nil {
		return out, err
	}
	if len(stages) != 4 {
		return out, ErrEvidence
	}
	ready := true
	for i, s := range stages {
		v := values[i]
		if s.Stage != v.Stage || s.ScopeSHA256 != q.Scope.SHA256 || s.Disposition != v.Disposition || !s.CompletedAt.Equal(v.AssessedAt) || !stageRef(s.DecisionRef) || !stageRef(s.OutcomeRef) || s.DecisionRef.Kind != "OPTIMIZATION_DECISION" || s.OutcomeRef.Kind != "OPTIMIZATION_OUTCOME" {
			return out, ErrEvidence
		}
		if s.Disposition != "COMPLETED" && s.Disposition != "EVIDENCED_NO_CHANGE" {
			ready = false
		}
		out.InputRefs = append(out.InputRefs, s.DecisionRef, s.OutcomeRef)
	}
	out.OptimizationOrder = stages
	out.InputRefs, err = decisionRefs(out.InputRefs)
	if err != nil {
		return out, err
	}
	sort.Strings(out.ReasonCodes)
	if ready {
		out.Status = "READY"
	}
	return out, nil
}
