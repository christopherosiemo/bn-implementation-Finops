package fleetgroup

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"
)

// GitSchemaVersion is a separate signed contract. A v5 signature or artifact is
// never converted into this family. Existing v5 serializers remain unchanged.
const GitSchemaVersion = "5.1"

const (
	GitMainPath          = "main.tf.json"
	GitDesiredPath       = "desired.auto.tfvars.json"
	gitParentDomain      = "finops/fleet-group/v5.1/isolated-fixture/parent\x00"
	gitChildDomain       = "finops/fleet-group/v5.1/isolated-fixture/child\x00"
	gitRecoveryDomain    = "finops/fleet-group/v5.1/isolated-fixture/owned-recovery\x00"
	gitParentAlgorithm   = "Ed25519-FleetGroup-v5.1-fixture"
	gitChildAlgorithm    = "Ed25519-FleetGroup-v5.1-fixture-child"
	gitRecoveryAlgorithm = "Ed25519-FleetGroup-v5.1-fixture-owned-recovery"
)

// GitRevision pins the complete two-file configuration. ConfigurationSHA256 is
// the static main file; DesiredSHA256 is the committed automatic variable file.
type GitRevision struct {
	Commit              string `json:"commit"`
	Tree                string `json:"tree"`
	ConfigurationSHA256 string `json:"configuration_sha256"`
	DesiredSHA256       string `json:"desired_sha256"`
}

type GitManifestEntry struct {
	Sequence                  uint64      `json:"sequence"`
	StageID                   string      `json:"stage_id"`
	StageSHA256               string      `json:"stage_sha256"`
	PredecessorCommit         string      `json:"predecessor_commit"`
	Revision                  GitRevision `json:"revision"`
	Before                    ModelState  `json:"before"`
	After                     ModelState  `json:"after"`
	MinimumObservationSeconds int64       `json:"minimum_observation_seconds"`
}

// The producer materializes actual commits before approval. Planning happens
// later against current state. Neither a manifest nor a commit attests to AWS.
type GitManifest struct {
	SchemaVersion string             `json:"schema_version"`
	Ref           string             `json:"ref"`
	Base          GitRevision        `json:"base"`
	Entries       []GitManifestEntry `json:"entries"`
}

type GitProgram struct {
	SchemaVersion string  `json:"schema_version"`
	Kind          string  `json:"kind"`
	ID            string  `json:"id"`
	Binding       Binding `json:"binding"`
	Realm         Realm   `json:"realm"`
	CreatorID     string  `json:"creator_id"`
	Environment   string  `json:"environment"`
	Policy        Policy  `json:"policy"`
	// This is immutable base authority, not the effective stage Git revision.
	ArtifactContext   ArtifactContext `json:"artifact_context"`
	Manifest          GitManifest     `json:"manifest"`
	ManifestSHA256    string          `json:"manifest_sha256"`
	OldTemplate       Template        `json:"old_template"`
	CandidateTemplate Template        `json:"candidate_template"`
	Budget            ModelBudget     `json:"budget"`
	Stages            []Stage         `json:"stages"`
	Evidence          []EvidenceRef   `json:"evidence"`
	CreatedAt         time.Time       `json:"created_at"`
	ExpiresAt         time.Time       `json:"expires_at"`
	Nonce             string          `json:"nonce"`
}

type GitArtifact struct {
	Kind                string      `json:"kind"`
	Receipt             SnapshotRef `json:"receipt"`
	BaseContextSHA256   string      `json:"base_context_sha256"`
	ManifestSHA256      string      `json:"manifest_sha256"`
	ManifestEntrySHA256 string      `json:"manifest_entry_sha256,omitempty"`
	PreviousRevision    GitRevision `json:"previous_revision"`
	Revision            GitRevision `json:"revision"`
	BeforeStateSerial   uint64      `json:"before_state_serial"`
	BeforeStateSHA256   string      `json:"before_state_sha256"`
	SavedPlanSHA256     string      `json:"saved_plan_sha256"`
	PlanJSONSHA256      string      `json:"plan_json_sha256"`
	Before              ModelState  `json:"before"`
	After               ModelState  `json:"after"`
}

type GitChild struct {
	SchemaVersion             string        `json:"schema_version"`
	ID                        string        `json:"id"`
	ParentID                  string        `json:"parent_id"`
	ParentSHA256              string        `json:"parent_sha256"`
	BindingSHA256             string        `json:"binding_sha256"`
	RealmSHA256               string        `json:"realm_sha256"`
	Mode                      string        `json:"mode"`
	StageID                   string        `json:"stage_id"`
	StageSHA256               string        `json:"stage_sha256"`
	Sequence                  uint64        `json:"sequence"`
	Artifact                  GitArtifact   `json:"artifact"`
	MinimumObservationSeconds int64         `json:"minimum_observation_seconds"`
	Evidence                  []EvidenceRef `json:"evidence"`
	CompensationFor           string        `json:"compensation_for,omitempty"`
	OwnedReceiptSHA256        string        `json:"owned_receipt_sha256,omitempty"`
	OwnershipSHA256           string        `json:"ownership_sha256,omitempty"`
	CreatedAt                 time.Time     `json:"created_at"`
	ExpiresAt                 time.Time     `json:"expires_at"`
	Nonce                     string        `json:"nonce"`
}

type GitEnvelope struct {
	Program   GitProgram `json:"program"`
	Approvals []Approval `json:"approvals"`
	Algorithm string     `json:"algorithm"`
	Signature string     `json:"signature"`
}

type GitChildEnvelope struct {
	Child     GitChild `json:"child"`
	Algorithm string   `json:"algorithm"`
	Signature string   `json:"signature"`
}

// APPLIED is historical evidence, not an unconsumed recovery capability.
type GitOwnedReceipt struct {
	SchemaVersion     string    `json:"schema_version"`
	ID                string    `json:"id"`
	CommandID         string    `json:"command_id"`
	ParentSHA256      string    `json:"parent_sha256"`
	ChildSHA256       string    `json:"child_sha256"`
	ArtifactSHA256    string    `json:"artifact_sha256"`
	SavedPlanSHA256   string    `json:"saved_plan_sha256"`
	BeforeGitCommit   string    `json:"before_git_commit"`
	AfterGitCommit    string    `json:"after_git_commit"`
	BeforeStateSerial uint64    `json:"before_state_serial"`
	AfterStateSerial  uint64    `json:"after_state_serial"`
	AfterStateSHA256  string    `json:"after_state_sha256"`
	AfterModelSHA256  string    `json:"after_model_sha256"`
	PipelineID        string    `json:"pipeline_id"`
	Outcome           string    `json:"outcome"`
	ReceivedAt        time.Time `json:"received_at"`
}

// GitOwnership MUST be resolved from a locked durable current store head, not
// an upload. Pure validation checks its bindings, not its authenticity. A store
// must serialize version, consumption and command intent through dispatch.
// Git-only/unknown apply duties additionally need a durable reconciler. This
// version supports the exact latest APPLIED child only. A newer same-model head
// is not accepted without a future authenticated complete transition journal.
// It cannot compose whole-program rollback or blindly redispatch uncertainty.
type GitOwnership struct {
	ID            string      `json:"id"`
	Version       int64       `json:"version"`
	Status        string      `json:"status"`
	CommandID     string      `json:"command_id"`
	ParentSHA256  string      `json:"parent_sha256"`
	ChildSHA256   string      `json:"child_sha256"`
	ReceiptSHA256 string      `json:"receipt_sha256"`
	BindingSHA256 string      `json:"binding_sha256"`
	RealmSHA256   string      `json:"realm_sha256"`
	Revision      GitRevision `json:"revision"`
	StateLineage  string      `json:"state_lineage"`
	StateSerial   uint64      `json:"state_serial"`
	StateSHA256   string      `json:"state_sha256"`
	Model         ModelState  `json:"model"`
	ObservedAt    time.Time   `json:"observed_at"`
	ValidUntil    time.Time   `json:"valid_until"`
}

// gitModelView reuses only unsigned fixed model/input/math helpers. It has no
// v5 schema/identity and MUST NOT be passed to v5 validators or signers. No
// artifact, signature, Git revision or approval is adapted to v5.
func gitModelView(p GitProgram) Program {
	return Program{Binding: p.Binding, Realm: p.Realm, ArtifactContext: p.ArtifactContext, OldTemplate: p.OldTemplate, CandidateTemplate: p.CandidateTemplate, Budget: p.Budget, Stages: p.Stages}
}

func GitFixtureConfiguration(p GitProgram) ([]byte, error) {
	return FixtureConfiguration(gitModelView(p))
}
func GitFixtureDesired(p GitProgram, state ModelState) ([]byte, error) {
	if _, err := FixtureInputs(gitModelView(p), state); err != nil {
		return nil, err
	}
	return json.Marshal(map[string]int{"old_count": state.OldCount, "candidate_count": state.CandidateCount, "candidate_traffic_percent": state.CandidateTrafficPercent})
}
func GitFixtureInputs(p GitProgram, state ModelState) (map[string]map[string]any, error) {
	return FixtureInputs(gitModelView(p), state)
}
func GitForwardDeadline(p GitProgram) time.Time {
	return p.CreatedAt.Add(time.Duration(p.Budget.MaximumDurationSeconds) * time.Second)
}
func GitMinimumProgramDuration(p GitProgram) int64 { return MinimumProgramDuration(gitModelView(p)) }

func gitStages(p GitProgram) error {
	if err := ValidateBudget(p.Budget); err != nil {
		return err
	}
	defaults := DefaultStages(p.Budget.BaselineCount)
	if len(p.Stages) != len(defaults) {
		return invalid("GROUP_GIT_STAGES_INVALID")
	}
	for i, s := range p.Stages {
		d := defaults[i]
		if s.ID != d.ID || s.Kind != d.Kind || s.TargetCandidateCount != d.TargetCandidateCount || s.TargetTrafficPercent != d.TargetTrafficPercent || s.MinimumObservationSeconds < d.MinimumObservationSeconds || s.MinimumObservationSeconds > 24*3600 || i == 0 && s.MinimumObservationSeconds != 0 {
			return invalid("GROUP_GIT_STAGES_INVALID")
		}
	}
	return nil
}

// GitStageSpecifications derives the complete deterministic effect sequence.
// Revision/predecessor fields remain empty until actual Git commits are made.
func GitStageSpecifications(p GitProgram) ([]GitManifestEntry, error) {
	if err := gitStages(p); err != nil {
		return nil, err
	}
	state := ModelState{Digest(p.Binding), Digest(p.Realm), p.Budget.BaselineCount, 0, 0}
	out := []GitManifestEntry{}
	add := func(stage Stage, after ModelState, seconds int64) {
		out = append(out, GitManifestEntry{Sequence: uint64(len(out) + 1), StageID: stage.ID, StageSHA256: Digest(stage), Before: state, After: after, MinimumObservationSeconds: seconds})
		state = after
	}
	add(p.Stages[0], state, 0)
	for i := 1; i < 5; i++ {
		s := p.Stages[i]
		for state.CandidateCount < s.TargetCandidateCount {
			a := state
			a.CandidateCount += p.Budget.MaxInFlight
			if a.CandidateCount > s.TargetCandidateCount {
				a.CandidateCount = s.TargetCandidateCount
			}
			add(s, a, 120)
		}
		a := state
		a.CandidateTrafficPercent = s.TargetTrafficPercent
		add(s, a, s.MinimumObservationSeconds)
	}
	for state.OldCount > 0 {
		a := state
		a.OldCount -= p.Budget.MaxInFlight
		if a.OldCount < 0 {
			a.OldCount = 0
		}
		seconds := int64(120)
		if a.OldCount == 0 {
			seconds = p.Stages[5].MinimumObservationSeconds
		}
		add(p.Stages[5], a, seconds)
	}
	return out, nil
}

func validGitRevision(r GitRevision, static string) bool {
	return commitPattern.MatchString(r.Commit) && commitPattern.MatchString(r.Tree) && len(r.Commit) == len(r.Tree) && r.ConfigurationSHA256 == static && hashPattern.MatchString(r.DesiredSHA256)
}
func safeGitRef(ref string) bool {
	if !strings.HasPrefix(ref, "refs/heads/") || len(ref) > 200 || strings.HasSuffix(ref, "/") || strings.HasSuffix(ref, ".") || strings.Contains(ref, "..") || strings.Contains(ref, "//") || strings.Contains(ref, "@{") {
		return false
	}
	for _, part := range strings.Split(strings.TrimPrefix(ref, "refs/heads/"), "/") {
		if part == "" || strings.HasPrefix(part, ".") || strings.HasSuffix(part, ".lock") {
			return false
		}
		for _, c := range part {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
				return false
			}
		}
	}
	return true
}

func ValidateGitManifest(p GitProgram) error {
	m := p.Manifest
	if m.SchemaVersion != "1" || !safeGitRef(m.Ref) || !hashPattern.MatchString(p.ManifestSHA256) || p.ManifestSHA256 != Digest(m) || !validGitRevision(m.Base, p.ArtifactContext.ConfigurationSHA256) || m.Base.Commit != p.ArtifactContext.GitCommit || m.Base.Tree != p.ArtifactContext.GitTree {
		return invalid("GROUP_GIT_MANIFEST_BINDING_INVALID")
	}
	steps, err := GitStageSpecifications(p)
	if err != nil {
		return err
	}
	if len(m.Entries) != len(steps) || len(steps) > 1024 {
		return invalid("GROUP_GIT_MANIFEST_SEQUENCE_INVALID")
	}
	source, err := GitFixtureConfiguration(p)
	if err != nil {
		return err
	}
	if BytesDigest(source) != m.Base.ConfigurationSHA256 {
		return invalid("GROUP_GIT_STATIC_CONFIGURATION_INVALID")
	}
	desired, _ := GitFixtureDesired(p, steps[0].Before)
	if BytesDigest(desired) != m.Base.DesiredSHA256 {
		return invalid("GROUP_GIT_BASE_DESIRED_INVALID")
	}
	previous := m.Base
	seen := map[string]bool{previous.Commit: true}
	for i, e := range m.Entries {
		s := steps[i]
		if e.Sequence != s.Sequence || e.StageID != s.StageID || e.StageSHA256 != s.StageSHA256 || e.Before != s.Before || e.After != s.After || e.MinimumObservationSeconds != s.MinimumObservationSeconds || e.PredecessorCommit != previous.Commit || !validGitRevision(e.Revision, m.Base.ConfigurationSHA256) || len(e.Revision.Commit) != len(m.Base.Commit) {
			return invalid("GROUP_GIT_MANIFEST_SEQUENCE_INVALID")
		}
		desired, _ = GitFixtureDesired(p, e.After)
		if BytesDigest(desired) != e.Revision.DesiredSHA256 {
			return invalid("GROUP_GIT_DESIRED_STATE_INVALID")
		}
		if i == 0 {
			if e.Revision != m.Base {
				return invalid("GROUP_GIT_PREPARE_REVISION_INVALID")
			}
		} else if seen[e.Revision.Commit] || e.Revision.Tree == previous.Tree {
			return invalid("GROUP_GIT_REVISION_REUSED")
		}
		seen[e.Revision.Commit] = true
		previous = e.Revision
	}
	return nil
}

func ValidateGitProgram(p GitProgram, expected Expected, now time.Time) error {
	if p.SchemaVersion != GitSchemaVersion || p.Kind != Kind || !idPattern.MatchString(p.ID) || !idPattern.MatchString(p.CreatorID) || !idPattern.MatchString(p.Nonce) || p.Binding != expected.Binding || p.Realm != expected.Realm {
		return invalid("GROUP_GIT_PROGRAM_BINDING_INVALID")
	}
	if err := ValidateRealm(p.Realm); err != nil {
		return err
	}
	if err := ValidateBinding(p.Binding); err != nil {
		return err
	}
	if p.Environment != "NON_PRODUCTION" {
		return invalid("GROUP_PRODUCTION_NOT_ENABLED")
	}
	if !idPattern.MatchString(p.Policy.ID) || p.Policy.Version < 1 || !hashPattern.MatchString(p.Policy.SHA256) || p.Policy.ApproverRole != ApproverRole {
		return invalid("GROUP_APPROVAL_POLICY_REQUIRED")
	}
	if err := ValidateArtifactContext(p.ArtifactContext); err != nil {
		return err
	}
	if !template(p.OldTemplate) || !template(p.CandidateTemplate) || p.OldTemplate.ID == p.CandidateTemplate.ID {
		return invalid("GROUP_TEMPLATE_BINDING_INVALID")
	}
	if err := gitStages(p); err != nil {
		return err
	}
	if err := ValidateGitManifest(p); err != nil {
		return err
	}
	if !canonicalTime(now) || !canonicalTime(p.CreatedAt) || !canonicalTime(p.ExpiresAt) || p.CreatedAt.After(now.Add(5*time.Second)) || !p.ExpiresAt.After(now) || p.ExpiresAt.Sub(p.CreatedAt) > 24*time.Hour || p.ExpiresAt.Before(GitForwardDeadline(p)) || !GitForwardDeadline(p).After(now) || p.Budget.MaximumDurationSeconds < GitMinimumProgramDuration(p) {
		return invalid("GROUP_GIT_PROGRAM_LIFETIME_INVALID")
	}
	return evidence(p.Evidence, parentEvidence, p.Binding, p.Realm, now, GitForwardDeadline(p), false)
}

func gitArtifactBinding(a GitArtifact, p GitProgram) error {
	if a.Kind != BuiltinFixtureArtifact || !validSnapshot(a.Receipt) || a.BaseContextSHA256 != Digest(p.ArtifactContext) || a.ManifestSHA256 != p.ManifestSHA256 || a.BeforeStateSerial < p.ArtifactContext.InitialStateSerial || !hashPattern.MatchString(a.BeforeStateSHA256) || !hashPattern.MatchString(a.SavedPlanSHA256) || !hashPattern.MatchString(a.PlanJSONSHA256) || !model(a.Before, gitModelView(p)) || !model(a.After, gitModelView(p)) || !validGitRevision(a.PreviousRevision, p.ArtifactContext.ConfigurationSHA256) || !validGitRevision(a.Revision, p.ArtifactContext.ConfigurationSHA256) || len(a.Revision.Commit) != len(p.Manifest.Base.Commit) || len(a.PreviousRevision.Commit) != len(p.Manifest.Base.Commit) {
		return invalid("GROUP_GIT_ARTIFACT_BINDING_INVALID")
	}
	return nil
}

func gitChildBinding(c GitChild, p GitProgram, now time.Time) error {
	if c.SchemaVersion != GitSchemaVersion || !idPattern.MatchString(c.ID) || c.ID == p.ID || c.ParentID != p.ID || c.ParentSHA256 != Digest(p) || c.BindingSHA256 != Digest(p.Binding) || c.RealmSHA256 != Digest(p.Realm) || !idPattern.MatchString(c.Nonce) || c.Nonce == p.Nonce || c.Sequence == 0 {
		return invalid("GROUP_GIT_CHILD_BINDING_INVALID")
	}
	if !canonicalTime(c.CreatedAt) || !canonicalTime(c.ExpiresAt) || !canonicalTime(now) || c.CreatedAt.Before(p.CreatedAt) || c.CreatedAt.After(now.Add(5*time.Second)) || now.Sub(c.CreatedAt) > 5*time.Minute || !c.ExpiresAt.After(now) || !c.ExpiresAt.After(c.CreatedAt) || c.ExpiresAt.Sub(c.CreatedAt) > 15*time.Minute {
		return invalid("GROUP_GIT_CHILD_LIFETIME_INVALID")
	}
	return gitArtifactBinding(c.Artifact, p)
}

func ValidateGitChild(c GitChild, p GitProgram, now time.Time) error {
	if err := ValidateGitProgram(p, Expected{p.Binding, p.Realm}, now); err != nil {
		return err
	}
	if err := gitChildBinding(c, p, now); err != nil {
		return err
	}
	if c.Mode != Forward || c.CompensationFor != "" || c.OwnedReceiptSHA256 != "" || c.OwnershipSHA256 != "" || c.ExpiresAt.After(GitForwardDeadline(p)) || c.Sequence > uint64(len(p.Manifest.Entries)) {
		return invalid("GROUP_GIT_FORWARD_INVALID")
	}
	e := p.Manifest.Entries[c.Sequence-1]
	previous := p.Manifest.Base
	if c.Sequence > 1 {
		previous = p.Manifest.Entries[c.Sequence-2].Revision
	}
	if c.StageID != e.StageID || c.StageSHA256 != e.StageSHA256 || c.Artifact.ManifestEntrySHA256 != Digest(e) || c.Artifact.PreviousRevision != previous || c.Artifact.Revision != e.Revision || c.Artifact.Before != e.Before || c.Artifact.After != e.After || c.MinimumObservationSeconds != e.MinimumObservationSeconds || now.Add(time.Duration(c.MinimumObservationSeconds)*time.Second).After(GitForwardDeadline(p)) {
		return invalid("GROUP_GIT_STAGE_CONTEXT_INVALID")
	}
	return evidence(c.Evidence, childEvidence, p.Binding, p.Realm, now, c.ExpiresAt, true)
}

func ValidateGitRecovery(c, original GitChild, p GitProgram, applied GitOwnedReceipt, ownership GitOwnership, now time.Time) error {
	if err := ValidateGitChild(original, p, original.CreatedAt); err != nil {
		return err
	}
	if err := gitChildBinding(c, p, now); err != nil {
		return err
	}
	if applied.SchemaVersion != GitSchemaVersion || !idPattern.MatchString(applied.ID) || !idPattern.MatchString(applied.CommandID) || applied.ParentSHA256 != Digest(p) || applied.ChildSHA256 != Digest(original) || applied.ArtifactSHA256 != Digest(original.Artifact) || applied.SavedPlanSHA256 != original.Artifact.SavedPlanSHA256 || applied.BeforeGitCommit != original.Artifact.PreviousRevision.Commit || applied.AfterGitCommit != original.Artifact.Revision.Commit || applied.BeforeStateSerial != original.Artifact.BeforeStateSerial || applied.AfterStateSerial <= applied.BeforeStateSerial || !hashPattern.MatchString(applied.AfterStateSHA256) || applied.AfterModelSHA256 != Digest(original.Artifact.After) || applied.PipelineID != p.ArtifactContext.PipelineID || applied.Outcome != "APPLIED" || !canonicalTime(applied.ReceivedAt) || applied.ReceivedAt.Before(original.CreatedAt) || applied.ReceivedAt.After(now.Add(5*time.Second)) || original.Artifact.Before == original.Artifact.After {
		return invalid("GROUP_GIT_APPLIED_RECEIPT_INVALID")
	}
	if !idPattern.MatchString(ownership.ID) || ownership.Version < 1 || ownership.Status != "OWNED" || ownership.CommandID != applied.CommandID || ownership.ParentSHA256 != Digest(p) || ownership.ChildSHA256 != Digest(original) || ownership.ReceiptSHA256 != Digest(applied) || ownership.BindingSHA256 != Digest(p.Binding) || ownership.RealmSHA256 != Digest(p.Realm) || ownership.Revision != c.Artifact.PreviousRevision || ownership.Revision != original.Artifact.Revision || ownership.StateLineage != p.ArtifactContext.StateLineage || ownership.StateSerial != c.Artifact.BeforeStateSerial || ownership.StateSerial != applied.AfterStateSerial || ownership.StateSHA256 != c.Artifact.BeforeStateSHA256 || ownership.StateSHA256 != applied.AfterStateSHA256 || ownership.Model != original.Artifact.After || !canonicalTime(ownership.ObservedAt) || ownership.ObservedAt.Before(applied.ReceivedAt) || ownership.ObservedAt.After(now.Add(5*time.Second)) || now.Sub(ownership.ObservedAt) > 5*time.Minute || !canonicalTime(ownership.ValidUntil) || ownership.ValidUntil.Before(c.ExpiresAt) || !ownership.ValidUntil.After(now) {
		return invalid("GROUP_GIT_CURRENT_OWNERSHIP_REQUIRED")
	}
	if c.Mode != OwnedRecovery || c.ID == original.ID || c.Nonce == original.Nonce || c.Sequence <= original.Sequence || c.StageID != original.StageID || c.StageSHA256 != original.StageSHA256 || c.CompensationFor != original.ID || c.OwnedReceiptSHA256 != Digest(applied) || c.OwnershipSHA256 != Digest(ownership) || c.CreatedAt.Before(ownership.ObservedAt) || c.Artifact.ManifestEntrySHA256 != "" || c.Artifact.Revision.Commit == ownership.Revision.Commit || c.Artifact.Revision.Commit == original.Artifact.PreviousRevision.Commit || c.Artifact.Before != original.Artifact.After || c.Artifact.After != original.Artifact.Before {
		return invalid("GROUP_GIT_RECOVERY_NOT_NEW_OWNED_INVERSE")
	}
	desired, _ := GitFixtureDesired(p, c.Artifact.After)
	if c.Artifact.Revision.DesiredSHA256 != BytesDigest(desired) || c.MinimumObservationSeconds < 120 || c.MinimumObservationSeconds > 3600 {
		return invalid("GROUP_GIT_RECOVERY_SPEC_INVALID")
	}
	return evidence(c.Evidence, []string{"FIXTURE_CURRENT", "FIXTURE_RECOVERY_SLO"}, p.Binding, p.Realm, now, c.ExpiresAt, true)
}

func gitParentMessage(p GitProgram, a []Approval) []byte {
	raw, _ := json.Marshal(struct {
		Program   GitProgram `json:"program"`
		Approvals []Approval `json:"approvals"`
	}{p, a})
	return append([]byte(gitParentDomain), raw...)
}
func gitChildMessage(c GitChild, domain string) []byte {
	raw, _ := json.Marshal(c)
	return append([]byte(domain), raw...)
}
func gitApprovals(p GitProgram, a []Approval, now time.Time) error {
	if len(a) < 1 || len(a) > 16 {
		return invalid("GROUP_INDEPENDENT_APPROVAL_REQUIRED")
	}
	ids, actors := map[string]bool{}, map[string]bool{}
	for _, r := range a {
		if !idPattern.MatchString(r.ID) || ids[r.ID] || !idPattern.MatchString(r.ActorID) || actors[r.ActorID] || r.ActorID == p.CreatorID || r.TenantID != p.Binding.Old.Target.TenantID || r.Role != ApproverRole || r.ProgramSHA256 != Digest(p) || r.RealmSHA256 != Digest(p.Realm) || !canonicalTime(r.ApprovedAt) || r.ApprovedAt.Before(p.CreatedAt) || r.ApprovedAt.After(now.Add(5*time.Second)) || !r.ApprovedAt.Before(p.ExpiresAt) {
			return invalid("GROUP_GIT_APPROVAL_INVALID")
		}
		ids[r.ID], actors[r.ActorID] = true, true
	}
	return nil
}
func SignGitProgram(p GitProgram, a []Approval, key ed25519.PrivateKey, now time.Time) (GitEnvelope, error) {
	if len(key) != ed25519.PrivateKeySize {
		return GitEnvelope{}, invalid("GROUP_SIGNING_KEY_INVALID")
	}
	if e := ValidateGitProgram(p, Expected{p.Binding, p.Realm}, now); e != nil {
		return GitEnvelope{}, e
	}
	if e := gitApprovals(p, a, now); e != nil {
		return GitEnvelope{}, e
	}
	return GitEnvelope{p, a, gitParentAlgorithm, base64.StdEncoding.EncodeToString(ed25519.Sign(key, gitParentMessage(p, a)))}, nil
}
func VerifyGitProgram(e GitEnvelope, key ed25519.PublicKey, expected Expected, now time.Time) error {
	if len(key) != ed25519.PublicKeySize || e.Algorithm != gitParentAlgorithm {
		return invalid("GROUP_GIT_SIGNATURE_INVALID")
	}
	sig, err := base64.StdEncoding.DecodeString(e.Signature)
	if err != nil || !ed25519.Verify(key, gitParentMessage(e.Program, e.Approvals), sig) {
		return invalid("GROUP_GIT_SIGNATURE_INVALID")
	}
	if err = ValidateGitProgram(e.Program, expected, now); err != nil {
		return err
	}
	return gitApprovals(e.Program, e.Approvals, now)
}
func SignGitChild(c GitChild, parent GitEnvelope, key ed25519.PrivateKey, now time.Time) (GitChildEnvelope, error) {
	if len(key) != ed25519.PrivateKeySize {
		return GitChildEnvelope{}, invalid("GROUP_SIGNING_KEY_INVALID")
	}
	if e := VerifyGitProgram(parent, key.Public().(ed25519.PublicKey), Expected{parent.Program.Binding, parent.Program.Realm}, now); e != nil {
		return GitChildEnvelope{}, e
	}
	if e := ValidateGitChild(c, parent.Program, now); e != nil {
		return GitChildEnvelope{}, e
	}
	return GitChildEnvelope{c, gitChildAlgorithm, base64.StdEncoding.EncodeToString(ed25519.Sign(key, gitChildMessage(c, gitChildDomain)))}, nil
}
func VerifyGitChild(e GitChildEnvelope, parent GitEnvelope, key ed25519.PublicKey, expected Expected, now time.Time) error {
	if err := VerifyGitProgram(parent, key, expected, now); err != nil {
		return err
	}
	if len(key) != ed25519.PublicKeySize || e.Algorithm != gitChildAlgorithm {
		return invalid("GROUP_GIT_CHILD_SIGNATURE_INVALID")
	}
	sig, err := base64.StdEncoding.DecodeString(e.Signature)
	if err != nil || !ed25519.Verify(key, gitChildMessage(e.Child, gitChildDomain), sig) {
		return invalid("GROUP_GIT_CHILD_SIGNATURE_INVALID")
	}
	return ValidateGitChild(e.Child, parent.Program, now)
}
func SignGitRecovery(c GitChild, original GitChildEnvelope, parent GitEnvelope, applied GitOwnedReceipt, ownership GitOwnership, key ed25519.PrivateKey, now time.Time) (GitChildEnvelope, error) {
	if len(key) != ed25519.PrivateKeySize {
		return GitChildEnvelope{}, invalid("GROUP_SIGNING_KEY_INVALID")
	}
	if err := VerifyGitChild(original, parent, key.Public().(ed25519.PublicKey), Expected{parent.Program.Binding, parent.Program.Realm}, original.Child.CreatedAt); err != nil {
		return GitChildEnvelope{}, err
	}
	if err := ValidateGitRecovery(c, original.Child, parent.Program, applied, ownership, now); err != nil {
		return GitChildEnvelope{}, err
	}
	return GitChildEnvelope{c, gitRecoveryAlgorithm, base64.StdEncoding.EncodeToString(ed25519.Sign(key, gitChildMessage(c, gitRecoveryDomain)))}, nil
}
func VerifyGitRecovery(e, original GitChildEnvelope, parent GitEnvelope, applied GitOwnedReceipt, ownership GitOwnership, key ed25519.PublicKey, expected Expected, now time.Time) error {
	if err := VerifyGitChild(original, parent, key, expected, original.Child.CreatedAt); err != nil {
		return err
	}
	if len(key) != ed25519.PublicKeySize || e.Algorithm != gitRecoveryAlgorithm {
		return invalid("GROUP_GIT_RECOVERY_SIGNATURE_INVALID")
	}
	sig, err := base64.StdEncoding.DecodeString(e.Signature)
	if err != nil || !ed25519.Verify(key, gitChildMessage(e.Child, gitRecoveryDomain), sig) {
		return invalid("GROUP_GIT_RECOVERY_SIGNATURE_INVALID")
	}
	return ValidateGitRecovery(e.Child, original.Child, parent.Program, applied, ownership, now)
}
func DecodeGitProgram(raw []byte) (GitProgram, error) {
	var p GitProgram
	err := decode(raw, &p)
	return p, err
}
func DecodeGitChild(raw []byte) (GitChild, error) {
	var c GitChild
	err := decode(raw, &c)
	return c, err
}

// Reservations must be the complete current set from the shared durable
// workload lock. A caller-supplied slice cannot establish absence/completeness.
func CheckGitConcurrentBudget(p GitProgram, c GitChild, reservations []Reservation) error {
	if err := ValidateBudget(p.Budget); err != nil {
		return err
	}
	if err := gitArtifactBinding(c.Artifact, p); err != nil {
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

// GitIntegrationBoundary is not an enablement switch. Before any connected
// dispatch: authenticate real Git/CLI producers; issue and read back pinned
// receipts; hold shared cross-family workload exclusion; reserve/record intent
// BEFORE Git CAS; lease the sole writer; reconcile unknown Git/apply outcomes;
// serialize current ownership; and require complete real-clock health before
// consuming it. No CLI flags, TF_VAR or untracked configuration are allowed.
// These preconditions require durable services, not caller booleans or hashes.
const GitIntegrationBoundary = "PURE_GIT_GROUP_V5_1_FIXTURE_CONTRACT_ONLY"

const GitRecoveryLimitation = "LATEST_SINGLE_APPLIED_CHILD_ONLY_COMPLETE_JOURNAL_REQUIRED_FOR_COMPOSITION"
