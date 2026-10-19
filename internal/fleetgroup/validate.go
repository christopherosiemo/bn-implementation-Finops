package fleetgroup

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"regexp"
	"strings"
	"time"
)

var (
	idPattern      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)
	hashPattern    = regexp.MustCompile(`^[a-f0-9]{64}$`)
	accountPattern = regexp.MustCompile(`^[0-9]{12}$`)
	commitPattern  = regexp.MustCompile(`^[a-f0-9]{40}$|^[a-f0-9]{64}$`)
	decimalPattern = regexp.MustCompile(`^(0|[1-9][0-9]{0,25})(\.[0-9]{1,12})?$`)
	versionPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
	typePattern    = regexp.MustCompile(`^[a-z][a-z0-9]*\.[a-z0-9]+$`)
	uuidPattern    = regexp.MustCompile(`^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$`)
	addressPattern = regexp.MustCompile(`^(module\.[A-Za-z0-9_-]+(\[[0-9]+\]|\["[A-Za-z0-9_-]+"\])?\.)*([a-z][a-z0-9_]*)\.[A-Za-z0-9_-]+(\[[0-9]+\]|\["[A-Za-z0-9_-]+"\])?$`)
)

func invalid(reason string) error   { return errors.New(reason) }
func BytesDigest(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }

// Digest hashes the exact typed JSON, including the signed realm. No v4
// projection or semantic timestamp/member normalization is performed.
func Digest(v any) string {
	raw, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return BytesDigest(raw)
}

// DecodeProgram rejects unknown fields, duplicate keys and additional values.
// It is only syntax decoding; callers still need ValidateProgram and resolution
// of server-owned records. There is no public evidence-upload contract here.
func DecodeProgram(raw []byte) (Program, error) {
	var p Program
	if err := decode(raw, &p); err != nil {
		return p, err
	}
	return p, nil
}

func DecodeChild(raw []byte) (Child, error) {
	var c Child
	if err := decode(raw, &c); err != nil {
		return c, err
	}
	return c, nil
}

func decode(raw []byte, out any) error {
	if len(raw) == 0 || len(raw) > 256<<10 {
		return invalid("GROUP_JSON_BOUNDS")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if err := uniqueValue(d, 0); err != nil {
		return invalid("GROUP_JSON_FIELDS_INVALID")
	}
	if _, err := d.Token(); err != io.EOF {
		return invalid("GROUP_JSON_FIELDS_INVALID")
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return invalid("GROUP_JSON_FIELDS_INVALID")
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return invalid("GROUP_JSON_FIELDS_INVALID")
	}
	return nil
}

func uniqueValue(d *json.Decoder, depth int) error {
	if depth > 32 {
		return invalid("depth")
	}
	t, err := d.Token()
	if err != nil {
		return err
	}
	delim, ok := t.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			key, e := d.Token()
			if e != nil {
				return e
			}
			s, ok := key.(string)
			if !ok || seen[s] {
				return invalid("duplicate")
			}
			seen[s] = true
			if e = uniqueValue(d, depth+1); e != nil {
				return e
			}
		}
	case '[':
		for d.More() {
			if e := uniqueValue(d, depth+1); e != nil {
				return e
			}
		}
	default:
		return invalid("delimiter")
	}
	_, err = d.Token()
	return err
}

func canonicalTime(t time.Time) bool {
	_, offset := t.Zone()
	return !t.IsZero() && t.Year() >= 1970 && t.Year() <= 9999 && offset == 0
}

func ValidateRealm(r Realm) error {
	if r.Kind != IsolatedFixture || !idPattern.MatchString(r.FixtureID) || !idPattern.MatchString(r.Generation) || !hashPattern.MatchString(r.ModelSHA256) {
		return invalid("GROUP_REALM_NOT_ENABLED")
	}
	return nil
}

func ValidateTarget(t GroupTarget) error {
	if !idPattern.MatchString(t.TenantID) || !idPattern.MatchString(t.WorkloadID) || !idPattern.MatchString(t.FleetID) || t.Provider != "AWS" || !accountPattern.MatchString(t.AccountID) || t.Region != "eu-west-1" {
		return invalid("GROUP_TARGET_INVALID")
	}
	prefix := "arn:aws:autoscaling:" + t.Region + ":" + t.AccountID + ":autoScalingGroup:"
	if !strings.HasPrefix(t.ASGARN, prefix) || len(t.ASGARN) > 512 {
		return invalid("GROUP_ASG_BINDING_INVALID")
	}
	parts := strings.Split(strings.TrimPrefix(t.ASGARN, prefix), ":autoScalingGroupName/")
	if len(parts) != 2 || !uuidPattern.MatchString(parts[0]) || !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,254}$`).MatchString(parts[1]) {
		return invalid("GROUP_ASG_BINDING_INVALID")
	}
	return nil
}

func validRef(r VersionedRef) bool {
	return idPattern.MatchString(r.ID) && r.Version > 0 && hashPattern.MatchString(r.SHA256)
}
func validSnapshot(r SnapshotRef) bool {
	return idPattern.MatchString(r.ID) && hashPattern.MatchString(r.SHA256)
}

func ValidateBinding(b Binding) error {
	for _, s := range []Selection{b.Old, b.Candidate} {
		if err := ValidateTarget(s.Target); err != nil {
			return err
		}
		if !validRef(s.Registration) || !validRef(s.Declaration) || !validSnapshot(s.Scope) || !idPattern.MatchString(s.SourceID) || s.SourceRegistrationVersion < 1 || !hashPattern.MatchString(s.SourceConfigSHA256) {
			return invalid("GROUP_SELECTION_INVALID")
		}
	}
	o, c := b.Old.Target, b.Candidate.Target
	if o.TenantID != c.TenantID || o.WorkloadID != c.WorkloadID || o.Provider != c.Provider || o.AccountID != c.AccountID || o.Region != c.Region || o.FleetID == c.FleetID || o.ASGARN == c.ASGARN || b.Old.Registration.ID == b.Candidate.Registration.ID || b.Old.Declaration.ID == b.Candidate.Declaration.ID || b.Old.Scope.ID == b.Candidate.Scope.ID {
		return invalid("GROUP_PAIR_BINDING_INVALID")
	}
	return nil
}

func address(s, kind string) bool {
	if len(s) > 512 || !addressPattern.MatchString(s) {
		return false
	}
	parts := strings.Split(s, ".")
	return len(parts) >= 2 && parts[len(parts)-2] == kind
}

func ValidateArtifactContext(c ArtifactContext) error {
	if c.Kind != BuiltinFixtureArtifact || c.ProviderSource != BuiltinProvider || !idPattern.MatchString(c.RepositoryID) || !commitPattern.MatchString(c.GitCommit) || !commitPattern.MatchString(c.GitTree) || !hashPattern.MatchString(c.ConfigurationSHA256) || !hashPattern.MatchString(c.ToolchainImageSHA256) || len(c.TerraformVersion) > 32 || !versionPattern.MatchString(c.TerraformVersion) || !idPattern.MatchString(c.PipelineID) || !idPattern.MatchString(c.Workspace) || !idPattern.MatchString(c.StateLineage) {
		return invalid("GROUP_FIXTURE_ARTIFACT_CONTEXT_INVALID")
	}
	m := c.Mapping
	if !address(m.OldDeclaredASG, "aws_autoscaling_group") || !address(m.CandidateDeclaredASG, "aws_autoscaling_group") || m.OldDeclaredASG == m.CandidateDeclaredASG || !address(m.DeclaredListenerRule, "aws_lb_listener_rule") || !address(m.OldModel, "terraform_data") || !address(m.CandidateModel, "terraform_data") || !address(m.TrafficModel, "terraform_data") || m.OldModel == m.CandidateModel || m.OldModel == m.TrafficModel || m.CandidateModel == m.TrafficModel {
		return invalid("GROUP_FIXTURE_MAPPING_INVALID")
	}
	return nil
}

func template(t Template) bool {
	return regexp.MustCompile(`^lt-([a-f0-9]{8}|[a-f0-9]{17})$`).MatchString(t.ID) && t.Version > 0 && len(t.InstanceType) <= 64 && typePattern.MatchString(t.InstanceType) && hashPattern.MatchString(t.SHA256)
}

func positive(s string) (*big.Rat, error) {
	if !decimalPattern.MatchString(s) {
		return nil, invalid("GROUP_MODEL_COST_INVALID")
	}
	r, ok := new(big.Rat).SetString(s)
	if !ok || r.Sign() <= 0 {
		return nil, invalid("GROUP_MODEL_COST_INVALID")
	}
	return r, nil
}

func ValidateBudget(b ModelBudget) error {
	if b.CostBasis != FixtureModelCost || !regexp.MustCompile(`^[A-Z]{3}$`).MatchString(b.Currency) || b.BaselineCount < 10 || b.BaselineCount > 256 || b.MaxInFlight < 1 || b.MaxInFlight > b.BaselineCount || b.MaxBlastRadiusPPM < 1 || b.MaxBlastRadiusPPM > 100000 || b.MaxInFlight*1000000 > b.BaselineCount*b.MaxBlastRadiusPPM || b.MaxUnavailable < 0 || b.MaxUnavailable > b.MaxInFlight || b.MaxSurgeCount != b.BaselineCount || b.MaximumDurationSeconds < 1 || b.MaximumDurationSeconds > 24*60*60 {
		return invalid("GROUP_MODEL_BUDGET_INVALID")
	}
	old, e := positive(b.OldHourlyCost)
	if e != nil {
		return e
	}
	candidate, e := positive(b.CandidateHourlyCost)
	if e != nil {
		return e
	}
	maximum, e := positive(b.MaximumModelCost)
	if e != nil {
		return e
	}
	// Both complete cohorts may remain present for the whole program. This
	// deliberately conservative bound concerns this model's declared rates only.
	worst := new(big.Rat).Add(old, candidate)
	worst.Mul(worst, big.NewRat(int64(b.BaselineCount)*b.MaximumDurationSeconds, 3600))
	if maximum.Cmp(worst) < 0 {
		return invalid("GROUP_MODEL_COST_ENVELOPE_EXCEEDED")
	}
	return nil
}

func DefaultStages(count int) []Stage {
	kinds := []string{Prepare, Canary10, Expand25, Expand50, Expand100, DrainOld}
	traffic := []int{0, 10, 25, 50, 100, 100}
	out := make([]Stage, len(kinds))
	for i, kind := range kinds {
		seconds := int64(900)
		if kind == Prepare {
			seconds = 0
		}
		if kind == Canary10 {
			seconds = 3600
		}
		out[i] = Stage{strings.ToLower(kind), kind, (count*traffic[i] + 99) / 100, traffic[i], seconds}
	}
	return out
}

// MinimumProgramObservationSeconds includes every bounded capacity step plus
// terminal traffic/drain windows. It preserves the existing 20-member default
// protocol's 26 children and 160 minutes of observations; process time is extra.
func MinimumProgramObservationSeconds(p Program) int64 {
	step, count := p.Budget.MaxInFlight, p.Budget.BaselineCount
	if step < 1 || count < 1 || len(p.Stages) != 6 {
		return 0
	}
	var total int64
	previous := 0
	for i := 1; i < 5; i++ {
		target := p.Stages[i].TargetCandidateCount
		if target < previous {
			return 0
		}
		total += int64((target-previous+step-1)/step)*120 + p.Stages[i].MinimumObservationSeconds
		previous = target
	}
	drainSteps := (count + step - 1) / step
	total += int64(drainSteps-1)*120 + p.Stages[5].MinimumObservationSeconds
	return total
}

// CommandDeliveryMarginSeconds is the same conservative per-command feasibility
// allowance as the existing v4 protocol. It does not shorten health observation
// or promise that a pipeline completes; forward expiry retains owned recovery.
const CommandDeliveryMarginSeconds int64 = 300

// MinimumProgramDuration adds a delivery/planning margin for each separately
// authorized capacity, traffic, prepare and drain child. The 20-member default
// therefore has160 minutes of observations and a290-minute feasibility floor.
func MinimumProgramDuration(p Program) int64 {
	observations := MinimumProgramObservationSeconds(p)
	if observations == 0 {
		return 0
	}
	steps, previous := int64(1), 0
	for i := 1; i < 5; i++ {
		target := p.Stages[i].TargetCandidateCount
		steps += int64((target-previous+p.Budget.MaxInFlight-1)/p.Budget.MaxInFlight) + 1
		previous = target
	}
	steps += int64((p.Budget.BaselineCount + p.Budget.MaxInFlight - 1) / p.Budget.MaxInFlight)
	return observations + steps*CommandDeliveryMarginSeconds
}

var parentEvidence = []string{"FIXTURE_HISTORY", "FIXTURE_DEMAND", "FIXTURE_CAPACITY", "FIXTURE_CONFIGURATION", "FIXTURE_DEPENDENCY", "FIXTURE_SLO", "FIXTURE_ECONOMICS"}
var childEvidence = []string{"FIXTURE_CURRENT", "FIXTURE_DEPENDENCY", "FIXTURE_SLO"}

func evidence(refs []EvidenceRef, required []string, binding Binding, realm Realm, now, horizon time.Time, fresh bool) error {
	if len(refs) != len(required) {
		return invalid("GROUP_EVIDENCE_REQUIRED")
	}
	allowed := map[string]bool{}
	for _, kind := range required {
		allowed[kind] = true
	}
	seen := map[string]bool{}
	for _, r := range refs {
		if !allowed[r.Kind] || seen[r.Kind] || !idPattern.MatchString(r.ID) || !hashPattern.MatchString(r.SHA256) || r.BindingSHA256 != Digest(binding) || r.RealmSHA256 != Digest(realm) || !canonicalTime(r.ObservedAt) || !canonicalTime(r.ValidUntil) || r.ObservedAt.After(now.Add(5*time.Second)) || !r.ValidUntil.After(now) || r.ValidUntil.Before(horizon) || !r.ValidUntil.After(r.ObservedAt) || fresh && now.Sub(r.ObservedAt) > 5*time.Minute {
			return invalid("GROUP_EVIDENCE_INVALID_OR_STALE")
		}
		seen[r.Kind] = true
	}
	return nil
}

func ForwardDeadline(p Program) time.Time {
	return p.CreatedAt.Add(time.Duration(p.Budget.MaximumDurationSeconds) * time.Second)
}

func ValidateProgram(p Program, expected Expected, now time.Time) error {
	if p.SchemaVersion != SchemaVersion || p.Kind != Kind || !idPattern.MatchString(p.ID) || !idPattern.MatchString(p.CreatorID) || !idPattern.MatchString(p.Nonce) || p.Binding != expected.Binding || p.Realm != expected.Realm {
		return invalid("GROUP_PROGRAM_BINDING_INVALID")
	}
	if e := ValidateRealm(p.Realm); e != nil {
		return e
	}
	if e := ValidateBinding(p.Binding); e != nil {
		return e
	}
	if p.Environment != "NON_PRODUCTION" {
		return invalid("GROUP_PRODUCTION_NOT_ENABLED")
	}
	if !idPattern.MatchString(p.Policy.ID) || p.Policy.Version < 1 || !hashPattern.MatchString(p.Policy.SHA256) || p.Policy.ApproverRole != ApproverRole {
		return invalid("GROUP_APPROVAL_POLICY_REQUIRED")
	}
	if e := ValidateArtifactContext(p.ArtifactContext); e != nil {
		return e
	}
	if !template(p.OldTemplate) || !template(p.CandidateTemplate) || p.OldTemplate.ID == p.CandidateTemplate.ID {
		return invalid("GROUP_TEMPLATE_BINDING_INVALID")
	}
	if e := ValidateBudget(p.Budget); e != nil {
		return e
	}
	if !canonicalTime(now) || !canonicalTime(p.CreatedAt) || !canonicalTime(p.ExpiresAt) || p.CreatedAt.After(now.Add(5*time.Second)) || !p.ExpiresAt.After(now) || p.ExpiresAt.Sub(p.CreatedAt) > 24*time.Hour || p.ExpiresAt.Before(ForwardDeadline(p)) || !ForwardDeadline(p).After(now) {
		return invalid("GROUP_PROGRAM_LIFETIME_INVALID")
	}
	defaults := DefaultStages(p.Budget.BaselineCount)
	if len(p.Stages) != len(defaults) {
		return invalid("GROUP_STAGES_INVALID")
	}
	for i, s := range p.Stages {
		d := defaults[i]
		if s.ID != d.ID || s.Kind != d.Kind || s.TargetCandidateCount != d.TargetCandidateCount || s.TargetTrafficPercent != d.TargetTrafficPercent || s.MinimumObservationSeconds < d.MinimumObservationSeconds || s.MinimumObservationSeconds > 24*3600 || i == 0 && s.MinimumObservationSeconds != 0 {
			return invalid("GROUP_STAGES_INVALID")
		}
	}
	if p.Budget.MaximumDurationSeconds < MinimumProgramDuration(p) {
		return invalid("GROUP_PROGRAM_DURATION_TOO_SHORT")
	}
	return evidence(p.Evidence, parentEvidence, p.Binding, p.Realm, now, ForwardDeadline(p), false)
}

func model(s ModelState, p Program) bool {
	return s.BindingSHA256 == Digest(p.Binding) && s.RealmSHA256 == Digest(p.Realm) && s.OldCount >= 0 && s.OldCount <= p.Budget.BaselineCount && s.CandidateCount >= 0 && s.CandidateCount <= p.Budget.BaselineCount && s.OldCount+s.CandidateCount <= p.Budget.BaselineCount+p.Budget.MaxSurgeCount && s.CandidateTrafficPercent >= 0 && s.CandidateTrafficPercent <= 100
}

func ValidateArtifact(a Artifact, p Program) error {
	if a.Kind != BuiltinFixtureArtifact || !validSnapshot(a.Receipt) || a.ContextSHA256 != Digest(p.ArtifactContext) || a.BeforeStateSerial < p.ArtifactContext.InitialStateSerial || !hashPattern.MatchString(a.BeforeStateSHA256) || !hashPattern.MatchString(a.SavedPlanSHA256) || !hashPattern.MatchString(a.PlanJSONSHA256) || !model(a.Before, p) || !model(a.After, p) {
		return invalid("GROUP_ARTIFACT_BINDING_INVALID")
	}
	return nil
}

// VerifyArtifactBytes checks exact retained bytes only. Successful validation
// does not substitute for an independent Terraform plan/show semantic attestor.
func VerifyArtifactBytes(a Artifact, savedPlan, planJSON, beforeState []byte) error {
	if len(savedPlan) == 0 || len(savedPlan) > 64<<20 || len(planJSON) == 0 || len(planJSON) > 64<<20 || len(beforeState) == 0 || len(beforeState) > 64<<20 || BytesDigest(savedPlan) != a.SavedPlanSHA256 || BytesDigest(planJSON) != a.PlanJSONSHA256 || BytesDigest(beforeState) != a.BeforeStateSHA256 {
		return invalid("GROUP_ARTIFACT_BYTES_MISMATCH")
	}
	return nil
}

func stage(p Program, id string) (Stage, int, error) {
	for i, s := range p.Stages {
		if s.ID == id {
			return s, i, nil
		}
	}
	return Stage{}, 0, invalid("GROUP_STAGE_UNKNOWN")
}
func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

func childBinding(c Child, p Program, now time.Time) (Stage, int, error) {
	s, i, e := stage(p, c.StageID)
	if e != nil {
		return s, i, e
	}
	if c.SchemaVersion != SchemaVersion || !idPattern.MatchString(c.ID) || c.ID == p.ID || c.ParentID != p.ID || c.ParentSHA256 != Digest(p) || c.BindingSHA256 != Digest(p.Binding) || c.RealmSHA256 != Digest(p.Realm) || c.StageSHA256 != Digest(s) || c.Sequence == 0 || !idPattern.MatchString(c.Nonce) || c.Nonce == p.Nonce {
		return s, i, invalid("GROUP_CHILD_BINDING_INVALID")
	}
	if !canonicalTime(c.CreatedAt) || !canonicalTime(c.ExpiresAt) || !canonicalTime(now) || c.CreatedAt.Before(p.CreatedAt) || c.CreatedAt.After(now.Add(5*time.Second)) || now.Sub(c.CreatedAt) > 5*time.Minute || !c.ExpiresAt.After(now) || !c.ExpiresAt.After(c.CreatedAt) || c.ExpiresAt.Sub(c.CreatedAt) > 15*time.Minute {
		return s, i, invalid("GROUP_CHILD_LIFETIME_INVALID")
	}
	return s, i, ValidateArtifact(c.Artifact, p)
}

// ValidateChild checks a single intended effect, not predecessor health or the
// current pipeline state. A future repository must also serialize the complete
// stage/command chain and require an accepted full window before stage advance.
func ValidateChild(c Child, p Program, now time.Time) error {
	if err := ValidateProgram(p, Expected{p.Binding, p.Realm}, now); err != nil {
		return err
	}
	s, index, err := childBinding(c, p, now)
	if err != nil {
		return err
	}
	if c.Mode != Forward || c.CompensationFor != "" || c.OwnedReceiptSHA256 != "" || c.ExpiresAt.After(ForwardDeadline(p)) {
		return invalid("GROUP_FORWARD_MODE_INVALID")
	}
	b, a := c.Artifact.Before, c.Artifact.After
	impact := abs(a.OldCount-b.OldCount) + abs(a.CandidateCount-b.CandidateCount)
	if impact > p.Budget.MaxInFlight {
		return invalid("GROUP_BLAST_RADIUS_EXCEEDED")
	}
	var minimum int64
	switch s.Kind {
	case Prepare:
		if b != a || a.OldCount != p.Budget.BaselineCount || a.CandidateCount != 0 || a.CandidateTrafficPercent != 0 || c.Sequence != 1 {
			return invalid("GROUP_PREPARE_STATE_INVALID")
		}
	case DrainOld:
		if b.CandidateCount != p.Budget.BaselineCount || a.CandidateCount != b.CandidateCount || b.CandidateTrafficPercent != 100 || a.CandidateTrafficPercent != 100 || a.OldCount >= b.OldCount {
			return invalid("GROUP_DRAIN_TRANSITION_INVALID")
		}
		minimum = 120
		if a.OldCount == 0 {
			minimum = s.MinimumObservationSeconds
		}
	default:
		previous := p.Stages[index-1]
		if a.OldCount != p.Budget.BaselineCount || b.OldCount != a.OldCount || b.CandidateTrafficPercent != previous.TargetTrafficPercent {
			return invalid("GROUP_FORWARD_TRANSITION_INVALID")
		}
		if impact > 0 {
			if a.CandidateCount <= b.CandidateCount || b.CandidateCount < previous.TargetCandidateCount || a.CandidateCount > s.TargetCandidateCount || a.CandidateTrafficPercent != b.CandidateTrafficPercent {
				return invalid("GROUP_FORWARD_TRANSITION_INVALID")
			}
			minimum = 120
		} else {
			if a.CandidateCount != s.TargetCandidateCount || b.CandidateCount != a.CandidateCount || a.CandidateTrafficPercent != s.TargetTrafficPercent {
				return invalid("GROUP_FORWARD_TRANSITION_INVALID")
			}
			minimum = s.MinimumObservationSeconds
		}
	}
	if c.MinimumObservationSeconds < minimum || c.MinimumObservationSeconds > 24*3600 || s.Kind == Prepare && c.MinimumObservationSeconds != 0 || now.Add(time.Duration(c.MinimumObservationSeconds)*time.Second).After(ForwardDeadline(p)) {
		return invalid("GROUP_OBSERVATION_WINDOW_INVALID")
	}
	return evidence(c.Evidence, childEvidence, p.Binding, p.Realm, now, c.ExpiresAt, true)
}

// Reservations must come from the store's locked current set. This function
// cannot establish that the supplied concurrent population is complete.
type Reservation struct {
	RealmSHA256, TenantID, WorkloadID, CommandID string
	InFlight, Unavailable                        int
}

func CheckConcurrentBudget(p Program, c Child, reservations []Reservation) error {
	if err := ValidateBudget(p.Budget); err != nil {
		return err
	}
	if err := ValidateArtifact(c.Artifact, p); err != nil {
		return err
	}
	if len(reservations) > 256 {
		return invalid("GROUP_RESERVATION_POPULATION_INVALID")
	}
	inFlight := abs(c.Artifact.After.OldCount-c.Artifact.Before.OldCount) + abs(c.Artifact.After.CandidateCount-c.Artifact.Before.CandidateCount)
	unavailable := 0
	seen := map[string]bool{}
	for _, r := range reservations {
		if r.RealmSHA256 != Digest(p.Realm) || r.TenantID != p.Binding.Old.Target.TenantID || r.WorkloadID != p.Binding.Old.Target.WorkloadID || !idPattern.MatchString(r.CommandID) || seen[r.CommandID] || r.InFlight < 0 || r.InFlight > p.Budget.MaxInFlight || r.Unavailable < 0 || r.Unavailable > p.Budget.MaxUnavailable {
			return invalid("GROUP_RESERVATION_POPULATION_INVALID")
		}
		seen[r.CommandID] = true
		inFlight += r.InFlight
		unavailable += r.Unavailable
	}
	if inFlight > p.Budget.MaxInFlight || unavailable > p.Budget.MaxUnavailable {
		return invalid("GROUP_CONCURRENT_BUDGET_EXCEEDED")
	}
	return nil
}
