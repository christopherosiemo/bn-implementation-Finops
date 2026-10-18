package fleet

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"regexp"
	"sort"
	"strings"
	"time"
)

var hashPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
var commitPattern = regexp.MustCompile(`^[a-f0-9]{40}$`)
var accountPattern = regexp.MustCompile(`^[0-9]{12}$`)
var moneyPattern = regexp.MustCompile(`^(0|[1-9][0-9]*)(\.[0-9]{1,12})?$`)
var addressPattern = regexp.MustCompile(`^(module\.[A-Za-z0-9_-]+(\[[0-9]+\]|\["[A-Za-z0-9_-]+"\])?\.)*aws_[a-z0-9_]+\.[A-Za-z0-9_-]+(\[[0-9]+\]|\["[A-Za-z0-9_-]+"\])?$`)

func Digest(v any) string         { b, _ := json.Marshal(v); return BytesDigest(b) }
func BytesDigest(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func decodeStrict(raw []byte, out any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if e := d.Decode(out); e != nil {
		return e
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("FLEET_TRAILING_JSON")
	}
	return nil
}
func DecodePlan(raw []byte) (FleetPlanV4, error) {
	var p FleetPlanV4
	e := decodeStrict(raw, &p)
	return p, e
}
func DecodeChild(raw []byte) (ChildPlan, error) {
	var p ChildPlan
	e := decodeStrict(raw, &p)
	return p, e
}
func invalid(code string) error { return errors.New(code) }
func positiveDecimal(s string) (*big.Rat, error) {
	if len(s) > 80 || !moneyPattern.MatchString(s) {
		return nil, invalid("FLEET_COST_INVALID")
	}
	v, ok := new(big.Rat).SetString(s)
	if !ok || v.Sign() <= 0 {
		return nil, invalid("FLEET_COST_INVALID")
	}
	return v, nil
}

func ValidateBinding(b Binding) error {
	if b.TenantID == "" || b.ResourceID == "" || b.WorkloadID == "" || b.Provider != "AWS" || b.ProviderResourceID == "" || !accountPattern.MatchString(b.AccountID) || b.Region != "eu-west-1" {
		return invalid("FLEET_BINDING_INVALID")
	}
	return nil
}
func validateIaC(b IaCBinding) error {
	if b.Authority != "TERRAFORM" || b.Repository == "" || !commitPattern.MatchString(b.GitCommit) || b.Workspace == "" || b.StateLineage == "" || !hashPattern.MatchString(b.ConfigurationSHA256) || b.TerraformVersion == "" || b.PipelineID == "" {
		return invalid("BLOCKED_CONFIGURATION_AUTHORITY_UNKNOWN")
	}
	return nil
}
func validateProofs(refs []ProofRef, required []string, now time.Time) error {
	seen := map[string]bool{}
	for _, r := range refs {
		if r.Kind == "" || r.ID == "" || r.Version == "" || !hashPattern.MatchString(r.SHA256) || seen[r.Kind] || r.ObservedAt.IsZero() || r.ObservedAt.After(now.Add(5*time.Second)) || !r.ExpiresAt.After(now) || !r.ExpiresAt.After(r.ObservedAt) {
			return invalid("FLEET_PROOF_INVALID_OR_STALE")
		}
		seen[r.Kind] = true
	}
	for _, kind := range required {
		if !seen[kind] {
			return fmt.Errorf("FLEET_PROOF_REQUIRED:%s", kind)
		}
	}
	return nil
}

var parentProofKinds = []string{"NATIVE_HISTORY", "CAPACITY_ASSESSMENT", "WORKLOAD_SAFETY_PROFILE", "CONFIGURATION_AUTHORITY", "DEPENDENCY_REVIEW", "SLO_EVALUATION", "BILLING_PRICE"}
var childProofKinds = []string{"NATIVE_CURRENT", "WORKLOAD_SAFETY_PROFILE", "DEPENDENCY_REVIEW", "SLO_EVALUATION", "INCIDENT_STATE", "HEALTH_CHECK"}

func ValidatePlan(p FleetPlanV4, expected Binding, now time.Time) error {
	if p.SchemaVersion != SchemaVersion || p.Kind != Kind || p.ID == "" || p.CreatorID == "" || p.Nonce == "" || p.Binding != expected {
		return invalid("FLEET_PLAN_BINDING_INVALID")
	}
	if e := ValidateBinding(p.Binding); e != nil {
		return e
	}
	if e := validateIaC(p.IaC); e != nil {
		return e
	}
	// Production requires a separately accepted future-risk model. This bounded
	// reference has no calibrated <1% production forecast claim.
	if p.Environment != "NON_PRODUCTION" {
		return invalid("FLEET_PRODUCTION_NOT_ENABLED")
	}
	g := p.Governance
	if !g.Enabled || g.RiskClass != "R2" || g.PolicyID == "" || g.PolicyVersion < 1 || !hashPattern.MatchString(g.PolicySHA256) || g.ApproverRole != ApproverRole {
		return invalid("FLEET_R2_POLICY_REQUIRED")
	}
	if p.CreatedAt.IsZero() || p.CreatedAt.After(now.Add(5*time.Second)) || !p.ExpiresAt.After(now) || !p.ExpiresAt.After(p.CreatedAt) || p.ExpiresAt.Sub(p.CreatedAt) > 24*time.Hour {
		return invalid("FLEET_PLAN_EXPIRED")
	}
	if p.Old.ID == "" || p.Binding.ProviderResourceID != p.Old.ID || p.Candidate.ID == "" || p.Old.ID == p.Candidate.ID || p.Old.DesiredCount < 1 || p.Candidate.DesiredCount != 0 || p.Old.ASGAddress == p.Candidate.ASGAddress {
		return invalid("FLEET_BLUE_GREEN_REQUIRED")
	}
	for _, c := range []Cohort{p.Old, p.Candidate} {
		if !addressPattern.MatchString(c.ASGAddress) || !strings.Contains(c.ASGAddress, "aws_autoscaling_group.") || !addressPattern.MatchString(c.LaunchTemplateAddress) || !strings.Contains(c.LaunchTemplateAddress, "aws_launch_template.") || c.LaunchTemplateVersion < 1 || c.InstanceType == "" || !c.Stateless || c.DataVolumes || c.IndependentScaling {
			return invalid("FLEET_STATELESS_PINNED_COHORT_REQUIRED")
		}
	}
	if p.Traffic.Authority != "CUSTOMER_TERRAFORM_PIPELINE" || !addressPattern.MatchString(p.Traffic.Address) || !strings.Contains(p.Traffic.Address, "aws_lb_listener_rule.") || p.Traffic.OldTargetGroupARN == p.Traffic.CandidateTargetGroupARN {
		return invalid("FLEET_EXPLICIT_TRAFFIC_CONTROL_REQUIRED")
	}
	arnPrefix := "arn:aws:elasticloadbalancing:" + p.Binding.Region + ":" + p.Binding.AccountID + ":targetgroup/"
	if !strings.HasPrefix(p.Traffic.OldTargetGroupARN, arnPrefix) || !strings.HasPrefix(p.Traffic.CandidateTargetGroupARN, arnPrefix) {
		return invalid("FLEET_TRAFFIC_BINDING_INVALID")
	}
	b := p.Budget
	if b.BaselineCount < 1 || b.BaselineCount > 500000 {
		return invalid("FLEET_BASELINE_COUNT_INVALID")
	}
	cap := int(int64(b.BaselineCount) * int64(b.MaxBlastRadiusPPM) / 1000000)
	if b.BaselineCount != p.Old.DesiredCount || b.MaxBlastRadiusPPM < 1 || b.MaxBlastRadiusPPM > 100000 || b.MaxInFlight < 1 || b.MaxInFlight > 2 || b.MaxInFlight > cap || b.MaxUnavailable < 1 || b.MaxUnavailable > cap || b.MaxUnavailable > 2 || b.MaxSurgeCount != b.BaselineCount || b.MaximumDurationSeconds < 1 || b.MaximumDurationSeconds > 86400 || b.MaximumDurationSeconds > int64(p.ExpiresAt.Sub(p.CreatedAt)/time.Second) || !regexp.MustCompile(`^[A-Z]{3}$`).MatchString(b.Currency) {
		return invalid("FLEET_BLAST_OR_COST_BUDGET_INVALID")
	}
	if _, e := WorstCaseCost(b); e != nil {
		return e
	}
	if !ForwardDeadline(p).After(now) {
		return invalid("FLEET_COST_DURATION_EXPIRED")
	}
	if e := validateProofs(p.Proofs, parentProofKinds, now); e != nil {
		return e
	}
	// A parent is immutable: it cannot replace an expired authority reference
	// halfway through its signed program. Current child evidence and source
	// revocations are still checked independently before every forward stage.
	programEnd := p.CreatedAt.Add(time.Duration(b.MaximumDurationSeconds) * time.Second)
	for _, proof := range p.Proofs {
		if proof.ExpiresAt.Before(programEnd) {
			return invalid("FLEET_PARENT_PROOF_DURATION_INSUFFICIENT")
		}
	}
	expectedKinds := []string{Prepare, Canary10, Expand25, Expand50, Expand100, DrainOld}
	if len(p.Stages) != 5 && len(p.Stages) != 6 {
		return invalid("FLEET_STAGE_DAG_INVALID")
	}
	ids := map[string]bool{}
	var minimumObservation int64
	for i, s := range p.Stages {
		if s.ID == "" || ids[s.ID] || s.Kind != expectedKinds[i] || !hashPattern.MatchString(s.ConfigurationSHA256) {
			return invalid("FLEET_STAGE_DAG_INVALID")
		}
		ids[s.ID] = true
		if s.MinimumObservationSeconds < 0 || s.MinimumObservationSeconds > 86400 {
			return invalid("FLEET_OBSERVATION_DURATION_INVALID")
		}
		minimumObservation += s.MinimumObservationSeconds
		if i == 0 && len(s.DependsOn) != 0 || i > 0 && (len(s.DependsOn) != 1 || s.DependsOn[0] != p.Stages[i-1].ID) {
			return invalid("FLEET_STAGE_DAG_INVALID")
		}
		percent := []int{0, 10, 25, 50, 100, 100}[i]
		count := (b.BaselineCount*percent + 99) / 100
		if s.TargetTrafficPercent != percent || s.TargetCandidateCount != count || s.Kind == Canary10 && count > b.MaxInFlight || s.Kind == DrainOld && !s.CleanupReviewed || i > 0 && s.MinimumObservationSeconds < 60 {
			return invalid("FLEET_STAGE_TARGET_INVALID")
		}
		prior := 0
		if i > 0 {
			prior = p.Stages[i-1].TargetCandidateCount
		}
		if !sameInts(s.IntermediateCandidateCounts, intermediates(prior, count, b.MaxInFlight)) {
			return invalid("FLEET_INTERMEDIATE_STEPS_REQUIRED")
		}
		for _, permission := range s.Permissions {
			if e := validatePermission(p, s, permission); e != nil {
				return e
			}
		}
	}
	if minimumObservation > b.MaximumDurationSeconds {
		return invalid("FLEET_OBSERVATIONS_EXCEED_DURATION_BUDGET")
	}
	return nil
}

// ForwardDeadline bounds new forward effects. Owned recovery and continuing
// provider costs remain obligations after this planning estimate expires.
func ForwardDeadline(p FleetPlanV4) time.Time {
	deadline := p.CreatedAt.Add(time.Duration(p.Budget.MaximumDurationSeconds) * time.Second)
	if p.ExpiresAt.Before(deadline) {
		return p.ExpiresAt
	}
	return deadline
}

// WorstCaseCost includes retained old capacity and every allowed candidate surge
// for the entire bounded duration. It is a planning estimate, never a saving or
// an enforceable cloud spending ceiling: uncertain recovery can last longer.
func WorstCaseCost(b Budget) (string, error) {
	old, e := positiveDecimal(b.OldInstanceHourlyCost)
	if e != nil {
		return "", e
	}
	candidate, e := positiveDecimal(b.CandidateInstanceHourlyCost)
	if e != nil {
		return "", e
	}
	limit, e := positiveDecimal(b.MaximumCost)
	if e != nil {
		return "", e
	}
	if b.BaselineCount < 1 || b.MaxSurgeCount < 1 || b.MaximumDurationSeconds < 1 {
		return "", invalid("FLEET_COST_INVALID")
	}
	rate := new(big.Rat).Add(new(big.Rat).Mul(old, big.NewRat(int64(b.BaselineCount), 1)), new(big.Rat).Mul(candidate, big.NewRat(int64(b.MaxSurgeCount), 1)))
	cost := new(big.Rat).Mul(rate, big.NewRat(b.MaximumDurationSeconds, 3600))
	if cost.Cmp(limit) > 0 {
		return "", invalid("FLEET_COST_CEILING_EXCEEDED")
	}
	return cost.FloatString(12), nil
}

func validatePermission(p FleetPlanV4, s Stage, a Permission) error {
	expectedType := ""
	allowed := map[string]bool{}
	switch a.Address {
	case p.Candidate.ASGAddress:
		expectedType = "aws_autoscaling_group"
		for _, path := range []string{"/desired_capacity", "/min_size", "/max_size", "/launch_template/0/version"} {
			allowed[path] = true
		}
	case p.Old.ASGAddress:
		expectedType = "aws_autoscaling_group"
		if s.Kind != DrainOld {
			return invalid("FLEET_OLD_CAPACITY_PROTECTED")
		}
		for _, path := range []string{"/desired_capacity", "/min_size", "/max_size"} {
			allowed[path] = true
		}
	case p.Candidate.LaunchTemplateAddress:
		expectedType = "aws_launch_template"
		if s.Kind != Prepare || len(a.Paths) != 0 || len(a.ComputedPaths) != 0 || len(a.Actions) != 1 || a.Actions[0] != "no-op" {
			return invalid("FLEET_TARGET_TEMPLATE_MUST_ALREADY_EXIST")
		}
	case p.Traffic.Address:
		expectedType = "aws_lb_listener_rule"
		for i := 0; i < 2; i++ {
			allowed[fmt.Sprintf("/action/0/forward/0/target_group/%d/weight", i)] = true
		}
	default:
		return invalid("FLEET_UNRELATED_ADDRESS")
	}
	if a.Type != expectedType || len(a.Actions) == 0 {
		return invalid("FLEET_PERMISSION_INVALID")
	}
	for _, action := range a.Actions {
		if action != "update" && action != "no-op" {
			return invalid("FLEET_DELETION_OR_REPLACEMENT_FORBIDDEN")
		}
	}
	for _, path := range a.Paths {
		if !allowed[path] {
			return invalid("FLEET_UNDELEGATED_FIELD")
		}
	}
	for _, path := range a.ComputedPaths {
		if !safeComputed(a.Type, path) {
			return invalid("FLEET_UNKNOWN_ACTIONABLE_VALUE")
		}
	}
	return nil
}
func safeComputed(kind, path string) bool {
	if path == "/id" || path == "/arn" {
		return true
	}
	return kind == "aws_launch_template" && (path == "/latest_version" || path == "/default_version")
}
func stageFor(p FleetPlanV4, id string) (Stage, error) {
	for _, s := range p.Stages {
		if s.ID == id {
			return s, nil
		}
	}
	return Stage{}, invalid("FLEET_STAGE_UNKNOWN")
}

func ValidateChild(c ChildPlan, p FleetPlanV4, now time.Time) error {
	if c.CompensationFor != "" {
		return invalid("FLEET_OWNERSHIP_RECEIPT_REQUIRED")
	}
	if e := ValidatePlan(p, c.Binding, now); e != nil {
		return e
	}
	s, e := stageFor(p, c.StageID)
	if e != nil {
		return e
	}
	if c.SchemaVersion != SchemaVersion || c.ID == "" || c.ParentID != p.ID || c.ParentSHA256 != Digest(p) || c.StageSHA256 != Digest(s) || c.Sequence < 1 || c.Nonce == "" || !hashPattern.MatchString(c.SavedPlanSHA256) || !hashPattern.MatchString(c.PlanJSONSHA256) {
		return invalid("FLEET_CHILD_BINDING_INVALID")
	}
	if e = validateIaC(c.IaC); e != nil {
		return e
	}
	if c.IaC.Authority != p.IaC.Authority || c.IaC.Repository != p.IaC.Repository || c.IaC.GitCommit != p.IaC.GitCommit || c.IaC.Workspace != p.IaC.Workspace || c.IaC.StateLineage != p.IaC.StateLineage || c.IaC.StateSerial < p.IaC.StateSerial || c.IaC.ConfigurationSHA256 != s.ConfigurationSHA256 || c.IaC.PipelineID != p.IaC.PipelineID || c.IaC.TerraformVersion != p.IaC.TerraformVersion {
		return invalid("FLEET_CHILD_IAC_BINDING_INVALID")
	}
	if c.CreatedAt.Before(p.CreatedAt) || c.CreatedAt.After(now.Add(5*time.Second)) || now.Sub(c.CreatedAt) > 5*time.Minute || !c.ExpiresAt.After(now) || !c.ExpiresAt.After(c.CreatedAt) || c.ExpiresAt.After(ForwardDeadline(p)) || c.ExpiresAt.Sub(c.CreatedAt) > 15*time.Minute {
		return invalid("FLEET_CHILD_PLAN_STALE")
	}
	if e = validateProofs(c.Proofs, childProofKinds, now); e != nil {
		return e
	}
	for _, proof := range c.Proofs {
		if now.Sub(proof.ObservedAt) > 5*time.Minute {
			return invalid("FLEET_CHILD_SIGNAL_STALE")
		}
	}
	if c.Transition.TrafficAfter > c.Transition.TrafficBefore || c.Transition.CandidateBefore > 0 && c.Transition.CandidateAfter > c.Transition.CandidateBefore {
		if e = validateProofs(c.Proofs, []string{"CANDIDATE_HEALTH"}, now); e != nil {
			return e
		}
	}
	permissions := map[string]Permission{}
	for _, a := range s.Permissions {
		if _, ok := permissions[a.Address]; ok {
			return invalid("FLEET_PERMISSION_DUPLICATE")
		}
		permissions[a.Address] = a
	}
	seen := map[string]bool{}
	for _, a := range c.Changes {
		perm, ok := permissions[a.Address]
		if !ok || seen[a.Address] || a.Type != perm.Type || !contains(perm.Actions, a.Action) {
			return invalid("FLEET_CHILD_CHANGE_UNDELEGATED")
		}
		seen[a.Address] = true
		paths := map[string]bool{}
		for _, f := range a.Fields {
			if paths[f.Path] || !contains(perm.Paths, f.Path) || !json.Valid(f.Before) || !json.Valid(f.After) {
				return invalid("FLEET_CHILD_FIELD_INVALID")
			}
			paths[f.Path] = true
		}
		for _, path := range a.ComputedPaths {
			if !contains(perm.ComputedPaths, path) {
				return invalid("FLEET_CHILD_UNKNOWN_UNDELEGATED")
			}
		}
	}
	return validateTransition(p, s, c.Transition, false)
}
func contains(a []string, s string) bool {
	for _, v := range a {
		if v == s {
			return true
		}
	}
	return false
}
func abs(v int) int {
	if v < 0 {
		return -v
	}
	return v
}
func validateTransition(p FleetPlanV4, s Stage, t Transition, compensating bool) error {
	b := p.Budget
	for _, n := range []int{t.OldBefore, t.OldAfter, t.CandidateBefore, t.CandidateAfter, t.InFlight, t.Unavailable} {
		if n < 0 {
			return invalid("FLEET_TRANSITION_INVALID")
		}
	}
	if t.TrafficBefore < 0 || t.TrafficBefore > 100 || t.TrafficAfter < 0 || t.TrafficAfter > 100 || t.CandidateAfter > b.MaxSurgeCount || t.OldBefore > b.BaselineCount || t.OldAfter > b.BaselineCount {
		return invalid("FLEET_TRANSITION_INVALID")
	}
	impact := abs(t.OldAfter-t.OldBefore) + abs(t.CandidateAfter-t.CandidateBefore)
	if impact > t.InFlight || t.InFlight > b.MaxInFlight || t.Unavailable > b.MaxUnavailable {
		return invalid("FLEET_BLAST_RADIUS_EXCEEDED")
	}
	if compensating {
		if t.CandidateAfter > t.CandidateBefore || t.OldAfter < t.OldBefore || t.TrafficAfter > t.TrafficBefore {
			return invalid("FLEET_COMPENSATION_NOT_RECOVERY")
		}
		return nil
	}
	if s.Kind == DrainOld {
		if !s.CleanupReviewed || t.CandidateBefore != b.BaselineCount || t.CandidateAfter != b.BaselineCount || t.TrafficBefore != 100 || t.TrafficAfter != 100 || t.OldAfter > t.OldBefore {
			return invalid("FLEET_CLEANUP_NOT_REVIEWED")
		}
		return nil
	}
	if t.OldBefore != b.BaselineCount || t.OldAfter != b.BaselineCount || t.CandidateAfter < t.CandidateBefore || t.CandidateAfter > s.TargetCandidateCount || t.TrafficAfter < t.TrafficBefore || t.TrafficAfter > s.TargetTrafficPercent || t.TrafficAfter > t.CandidateAfter*100/b.BaselineCount {
		return invalid("FLEET_COHORT_TRANSITION_UNSAFE")
	}
	if t.CandidateAfter != t.CandidateBefore {
		position := -1
		for i, n := range s.IntermediateCandidateCounts {
			if n == t.CandidateBefore {
				position = i
			}
		}
		if position < 0 || position+1 >= len(s.IntermediateCandidateCounts) || s.IntermediateCandidateCounts[position+1] != t.CandidateAfter || t.TrafficAfter != t.TrafficBefore {
			return invalid("FLEET_INTERMEDIATE_STEP_OR_HEALTH_GATE_REQUIRED")
		}
	}
	if s.Kind == Prepare && (t.CandidateBefore != 0 || t.CandidateAfter != 0 || t.TrafficBefore != 0 || t.TrafficAfter != 0) {
		return invalid("FLEET_PREPARE_MUST_PRESERVE_ZERO_CANDIDATES")
	}
	return nil
}

func CheckConcurrentBudget(p FleetPlanV4, next Transition, flights []Flight) error {
	inFlight, unavailable := next.InFlight, next.Unavailable
	seen := map[string]bool{}
	for _, f := range flights {
		if f.ID == "" || seen[f.ID] || f.TenantID != p.Binding.TenantID || f.WorkloadID == "" || f.InFlight < 0 || f.Unavailable < 0 {
			return invalid("FLEET_FLIGHT_BINDING_INVALID")
		}
		seen[f.ID] = true
		if f.WorkloadID == p.Binding.WorkloadID {
			inFlight += f.InFlight
			unavailable += f.Unavailable
		}
	}
	if inFlight > p.Budget.MaxInFlight || unavailable > p.Budget.MaxUnavailable {
		return invalid("FLEET_CONCURRENT_BUDGET_EXCEEDED")
	}
	return nil
}
func NextStage(p FleetPlanV4, observations []StageObservation, now time.Time) (Stage, error) {
	byID := map[string]StageObservation{}
	for _, o := range observations {
		if _, err := stageFor(p, o.StageID); err != nil {
			return Stage{}, err
		}
		if _, ok := byID[o.StageID]; ok {
			return Stage{}, invalid("FLEET_STAGE_OBSERVATION_DUPLICATE")
		}
		byID[o.StageID] = o
	}
	missing := false
	for _, stage := range p.Stages {
		_, ok := byID[stage.ID]
		if !ok {
			missing = true
		} else if missing {
			return Stage{}, invalid("FLEET_STAGE_OBSERVATION_OUT_OF_ORDER")
		}
	}
	for _, s := range p.Stages {
		o, ok := byID[s.ID]
		if !ok {
			return s, nil
		}
		if o.ChildID == "" || o.Outcome != "HEALTHY" || !hashPattern.MatchString(o.ReceiptSHA256) || o.CompletedAt.IsZero() || o.CompletedAt.After(now) || o.ObservedUntil.After(now) || o.ObservedUntil.Before(o.CompletedAt.Add(time.Duration(s.MinimumObservationSeconds)*time.Second)) {
			return Stage{}, invalid("FLEET_STAGE_PRECONDITION_UNMET")
		}
	}
	return Stage{}, invalid("FLEET_DAG_COMPLETE")
}
func Recovery(e DispatchEvidence) RecoveryDecision {
	if e.Restored && e.Owned && e.ReceiptID != "" && hashPattern.MatchString(e.ReceiptSHA256) {
		return RecoveryDecision{"COMPLETE", "OWNED_RESTORATION_ALREADY_RECORDED"}
	}
	if e.Dispatched && !e.OutcomeKnown || e.IntentRecorded && !e.OutcomeKnown {
		return RecoveryDecision{"RECONCILE", "PROVIDER_OUTCOME_UNKNOWN_NO_REDISPATCH"}
	}
	if e.Owned && e.OutcomeKnown && e.ReceiptID != "" && hashPattern.MatchString(e.ReceiptSHA256) {
		return RecoveryDecision{"RESTORE_OWNED", "FRESH_COMPENSATION_PLAN_REQUIRED"}
	}
	return RecoveryDecision{"BLOCKED", "NO_OWNED_CHANGE_TO_RESTORE"}
}

// DefaultStages is an immutable-intent template. IaC must already define the
// candidate ASG at zero capacity. Every later apply receives a fresh child plan;
// aggregate targets never permit a single oversized capacity transition.
func DefaultStages(p FleetPlanV4, includeReviewedCleanup bool) []Stage {
	kinds := []string{Prepare, Canary10, Expand25, Expand50, Expand100}
	if includeReviewedCleanup {
		kinds = append(kinds, DrainOld)
	}
	out := []Stage{}
	for i, k := range kinds {
		percent := []int{0, 10, 25, 50, 100, 100}[i]
		s := Stage{ID: strings.ToLower(k), Kind: k, DependsOn: []string{}, TargetCandidateCount: (p.Budget.BaselineCount*percent + 99) / 100, TargetTrafficPercent: percent, MinimumObservationSeconds: 900, ConfigurationSHA256: p.IaC.ConfigurationSHA256, CleanupReviewed: k == DrainOld, Permissions: []Permission{}}
		prior := 0
		if i > 0 {
			prior = out[i-1].TargetCandidateCount
		}
		s.IntermediateCandidateCounts = intermediates(prior, s.TargetCandidateCount, p.Budget.MaxInFlight)
		if i > 0 {
			s.DependsOn = []string{out[i-1].ID}
		} else {
			s.MinimumObservationSeconds = 0
		}
		if k == Canary10 {
			s.MinimumObservationSeconds = 3600
		}
		if k == Prepare {
			s.Permissions = append(s.Permissions, Permission{p.Candidate.LaunchTemplateAddress, "aws_launch_template", []string{"no-op"}, []string{}, []string{}})
		}
		s.Permissions = append(s.Permissions, Permission{p.Candidate.ASGAddress, "aws_autoscaling_group", []string{"no-op", "update"}, []string{"/desired_capacity", "/min_size", "/max_size", "/launch_template/0/version"}, []string{"/id", "/arn"}}, Permission{p.Traffic.Address, "aws_lb_listener_rule", []string{"no-op", "update"}, []string{"/action/0/forward/0/target_group/0/weight", "/action/0/forward/0/target_group/1/weight"}, []string{"/id", "/arn"}})
		if k == DrainOld {
			s.Permissions = append(s.Permissions, Permission{p.Old.ASGAddress, "aws_autoscaling_group", []string{"no-op", "update"}, []string{"/desired_capacity", "/min_size", "/max_size"}, []string{"/id", "/arn"}})
		}
		sort.Slice(s.Permissions, func(i, j int) bool { return s.Permissions[i].Address < s.Permissions[j].Address })
		out = append(out, s)
	}
	return out
}
func intermediates(from, to, step int) []int {
	out := []int{from}
	if step < 1 {
		return out
	}
	for from < to {
		from += step
		if from > to {
			from = to
		}
		out = append(out, from)
	}
	return out
}
func sameInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}
