package fleetgroup

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"time"
)

func validateJournalGitRepair(r JournalGitRepair, parent GitEnvelope, e JournalEnvelope, projection JournalProjection, head JournalHeadEnvelope, now time.Time) error {
	if projection.Pending == nil || projection.Pending.NoApply == nil || !projection.Pending.GitAdvanced {
		return invalid("JOURNAL_DEFINITIVE_NO_APPLY_REQUIRED")
	}
	pending := projection.Pending
	c := pending.Command
	p := parent.Program
	if pending.Phase != "GIT_REPAIR_REQUIRED" && pending.Phase != JournalGitRepairIntent {
		return invalid("JOURNAL_GIT_REPAIR_DUTY_REQUIRED")
	}
	if r.SchemaVersion != JournalSchemaVersion || !idPattern.MatchString(r.ID) || !idPattern.MatchString(r.Nonce) || r.Nonce == p.Nonce || r.CommandID != c.ID || r.AuthorizationSHA256 != Digest(e) || r.HeadSHA256 != Digest(head) || r.PreparationSHA256 != Digest(c.Preparation) || r.NoApplyReceiptSHA256 != Digest(*pending.NoApply) || r.Before != pending.NoApply.Receipt.After || r.Before != journalAtRevision(c.Before, c.Preparation.Revision) || !validGitRevision(r.Revision, p.ArtifactContext.ConfigurationSHA256) || r.Revision.Commit == r.Before.Revision.Commit {
		return invalid("JOURNAL_GIT_REPAIR_BINDING_INVALID")
	}
	if !canonicalTime(r.CreatedAt) || !canonicalTime(r.ExpiresAt) || r.CreatedAt.Before(pending.NoApply.Receipt.ReceivedAt) || r.CreatedAt.After(now.Add(5*time.Second)) || now.Sub(r.CreatedAt) > 5*time.Minute || !r.ExpiresAt.After(now) || r.ExpiresAt.Sub(r.CreatedAt) > 15*time.Minute {
		return invalid("JOURNAL_GIT_REPAIR_LIFETIME_INVALID")
	}
	desired, err := GitFixtureDesired(p, c.Before.Model)
	if err != nil {
		return err
	}
	if r.Revision.DesiredSHA256 != BytesDigest(desired) {
		return invalid("JOURNAL_GIT_REPAIR_DESIRED_INVALID")
	}
	for _, entry := range p.Manifest.Entries {
		if r.Revision.Commit == entry.Revision.Commit {
			return invalid("JOURNAL_GIT_REPAIR_MUST_APPEND")
		}
	}
	return nil
}

func SignJournalGitRepair(r JournalGitRepair, v JournalView, keys JournalKeys, expected JournalHeadRef, key ed25519.PrivateKey, now time.Time) (JournalGitRepairEnvelope, error) {
	if len(key) != 64 || !bytes.Equal(key.Public().(ed25519.PublicKey), keys.Signer) {
		return JournalGitRepairEnvelope{}, invalid("JOURNAL_SIGNING_KEY_INVALID")
	}
	p, err := VerifyJournal(v, keys, expected, now)
	if err != nil {
		return JournalGitRepairEnvelope{}, err
	}
	if err = validateJournalGitRepair(r, v.Parent, v.Authorization, p, v.Head, now); err != nil {
		return JournalGitRepairEnvelope{}, err
	}
	return JournalGitRepairEnvelope{r, v.Head, journalGitRepairAlgorithm, journalSignature(journalGitRepairDomain, r, key)}, nil
}

// No CLI is involved in Git-only repair. Both exact raw states are retained to
// show that this publication changes only desired configuration, not instances.
type JournalGitRepairCapture struct {
	Context          ArtifactContext
	Configuration    []byte
	DesiredVariables []byte
	BeforeState      []byte
	AfterState       []byte
	GitCommitObject  []byte
	GitTreeObject    []byte
	Ref              string
	RefBefore        string
	RefAfter         string
}

func ValidateJournalGitRepairCapture(v JournalView, keys JournalKeys, expected JournalHeadRef, r JournalGitRepair, capture JournalGitRepairCapture, now time.Time) error {
	projection, err := VerifyJournal(v, keys, expected, now)
	if err != nil {
		return err
	}
	head := v.Head
	if projection.Pending != nil && projection.Pending.GitRepair != nil {
		head = projection.Pending.GitRepair.Head
		if Digest(r) != Digest(projection.Pending.GitRepair.Repair) {
			return invalid("JOURNAL_GIT_REPAIR_BINDING_INVALID")
		}
	}
	if err = validateJournalGitRepair(r, v.Parent, v.Authorization, projection, head, now); err != nil {
		return err
	}
	p := v.Parent.Program
	if capture.Context != p.ArtifactContext || capture.Ref != v.Authorization.Authorization.Ref || capture.RefBefore != r.Before.Revision.Commit || capture.RefAfter != r.Revision.Commit || !bytes.Equal(capture.BeforeState, capture.AfterState) || BytesDigest(capture.BeforeState) != r.Before.StateSHA256 {
		return invalid("JOURNAL_GIT_REPAIR_CHANGED_NATIVE_STATE")
	}
	configuration, err := GitFixtureConfiguration(p)
	if err != nil {
		return err
	}
	desired, _ := GitFixtureDesired(p, r.Before.Model)
	if !bytes.Equal(configuration, capture.Configuration) || !bytes.Equal(desired, capture.DesiredVariables) || BytesDigest(capture.DesiredVariables) != r.Revision.DesiredSHA256 {
		return invalid("JOURNAL_GIT_REPAIR_DESIRED_INVALID")
	}
	// Only unsigned raw Git/state readers are reused; no5.1 recovery validation.
	a := GitArtifact{PreviousRevision: r.Before.Revision, Revision: r.Revision, BeforeStateSerial: r.Before.StateSerial}
	gitCapture := GitTerraformArtifactCapture{Revision: r.Revision, Configuration: capture.Configuration, DesiredVariables: capture.DesiredVariables, GitCommitObject: capture.GitCommitObject, GitTreeObject: capture.GitTreeObject}
	if err = validateGitCaptureObjects(GitChild{Artifact: a}, gitCapture); err != nil {
		return err
	}
	inputs, _ := GitFixtureInputs(p, r.Before.Model)
	_, _, err = gitRawState(capture.BeforeState, p, GitChild{Artifact: a}, inputs)
	return err
}

// Independent journal-recovery semantic validation. It never calls/adapts the
// old latest-single-child ValidateGitRecovery/ValidateGitTerraformArtifact.
func ValidateJournalTerraformArtifact(v JournalView, keys JournalKeys, expected JournalHeadRef, r JournalRecovery, capture GitTerraformArtifactCapture, now time.Time) (ArtifactReview, error) {
	var out ArtifactReview
	projection, err := VerifyJournal(v, keys, expected, now)
	if err != nil {
		return out, err
	}
	if err = validateJournalRecovery(r, v.Parent, v.Authorization, projection, journalRecoverySigningHead(projection, r, v.Head), now); err != nil {
		return out, err
	}
	p, a := v.Parent.Program, r.Artifact
	if capture.Context != p.ArtifactContext || capture.Revision != a.Revision || capture.Recovery != nil || capture.Ref != v.Authorization.Authorization.Ref || capture.RefBefore != a.PreviousRevision.Commit || capture.RefAfter != a.Revision.Commit {
		return out, invalid("JOURNAL_RECOVERY_CAPTURE_CONTEXT_INVALID")
	}
	if err = ValidateGitPlanInvocation(capture.Invocation); err != nil {
		return out, err
	}
	if len(capture.Configuration)+len(capture.DesiredVariables)+len(capture.SavedPlan)+len(capture.PlanJSON)+len(capture.BeforeState) > fixtureArtifactLimit || len(capture.SavedPlan) == 0 || len(capture.PlanJSON) == 0 || len(capture.BeforeState) == 0 || BytesDigest(capture.SavedPlan) != a.SavedPlanSHA256 || BytesDigest(capture.PlanJSON) != a.PlanJSONSHA256 || BytesDigest(capture.BeforeState) != a.BeforeStateSHA256 {
		return out, invalid("JOURNAL_RECOVERY_ARTIFACT_BYTES_INVALID")
	}
	configuration, err := GitFixtureConfiguration(p)
	if err != nil {
		return out, err
	}
	desired, _ := GitFixtureDesired(p, a.After)
	if !bytes.Equal(configuration, capture.Configuration) || !bytes.Equal(desired, capture.DesiredVariables) || BytesDigest(configuration) != a.Revision.ConfigurationSHA256 || BytesDigest(desired) != a.Revision.DesiredSHA256 {
		return out, invalid("JOURNAL_RECOVERY_COMMITTED_SOURCE_INVALID")
	}
	if err = validateGitCaptureObjects(GitChild{Artifact: a}, capture); err != nil {
		return out, err
	}
	beforeInputs, _ := GitFixtureInputs(p, a.Before)
	afterInputs, _ := GitFixtureInputs(p, a.After)
	before, ids, err := gitRawState(capture.BeforeState, p, GitChild{Artifact: a}, beforeInputs)
	if err != nil {
		return out, err
	}
	if err = validateFixtureContainer(TerraformArtifactCapture{Context: capture.Context, Configuration: capture.Configuration, SavedPlan: capture.SavedPlan}, before); err != nil {
		return out, err
	}
	source, err := fixtureObject(capture.Configuration, 256<<10)
	if err != nil {
		return out, err
	}
	plan, err := fixtureObject(capture.PlanJSON, fixtureArtifactLimit)
	if err != nil {
		return out, err
	}
	if !tfKeys(plan, []string{"format_version", "terraform_version", "variables", "planned_values", "resource_changes", "prior_state", "configuration", "timestamp", "applyable", "complete", "errored"}, []string{"resource_drift", "output_changes", "relevant_attributes", "checks"}) || plan["format_version"] != "1.2" || plan["terraform_version"] != FixtureTerraformVersion || plan["complete"] != true || plan["errored"] != false || !tfEmpty(plan["resource_drift"]) || !tfEmpty(plan["output_changes"]) || !tfEmpty(plan["relevant_attributes"]) || !tfEmpty(plan["checks"]) {
		return out, invalid("JOURNAL_RECOVERY_NATIVE_PLAN_INVALID")
	}
	stamp, err := time.Parse(time.RFC3339Nano, tfText(plan["timestamp"]))
	if err != nil || !canonicalTime(stamp) || stamp.Before(projection.Pending.Command.CreatedAt.Truncate(time.Second)) || stamp.After(r.CreatedAt.Add(5*time.Second)) || stamp.After(now.Add(5*time.Second)) || now.Sub(stamp) > 5*time.Minute {
		return out, invalid("JOURNAL_RECOVERY_PLAN_STALE")
	}
	variables := tfObject(plan["variables"])
	wanted := map[string]int{"old_count": a.After.OldCount, "candidate_count": a.After.CandidateCount, "candidate_traffic_percent": a.After.CandidateTrafficPercent}
	if len(variables) != 3 {
		return out, invalid("JOURNAL_RECOVERY_VARIABLE_OVERRIDE")
	}
	for name, n := range wanted {
		value := tfObject(variables[name])
		actual, ok := tfUint(value["value"])
		if !tfKeys(value, []string{"value"}, nil) || !ok || actual != uint64(n) {
			return out, invalid("JOURNAL_RECOVERY_VARIABLE_OVERRIDE")
		}
	}
	if err = reviewPlanConfiguration(plan, gitModelView(p), source); err != nil {
		return out, err
	}
	prior := tfObject(plan["prior_state"])
	if !tfKeys(prior, []string{"format_version", "terraform_version", "values"}, nil) || prior["format_version"] != "1.0" || prior["terraform_version"] != FixtureTerraformVersion {
		return out, invalid("JOURNAL_RECOVERY_PRIOR_STATE_INVALID")
	}
	if err = modelValues(prior["values"], beforeInputs, ids, nil); err != nil {
		return out, err
	}
	changed, unknown, err := reviewChanges(plan, beforeInputs, afterInputs, ids)
	if err != nil {
		return out, err
	}
	if plan["applyable"] != (len(changed) > 0) {
		return out, invalid("JOURNAL_RECOVERY_APPLYABILITY_INVALID")
	}
	if err = modelValues(plan["planned_values"], afterInputs, ids, unknown); err != nil {
		return out, err
	}
	out = ArtifactReview{Status: "FIXTURE_JOURNAL_RECOVERY_SEMANTICS_MATCHED", Kind: BuiltinFixtureArtifact, ProgramSHA256: Digest(p), ChildSHA256: Digest(r), BindingSHA256: Digest(p.Binding), RealmSHA256: Digest(p.Realm), ArtifactSHA256: Digest(a), ConfigurationSHA256: a.Revision.ConfigurationSHA256, SavedPlanSHA256: a.SavedPlanSHA256, PlanJSONSHA256: a.PlanJSONSHA256, BeforeStateSHA256: a.BeforeStateSHA256, StateLineage: p.ArtifactContext.StateLineage, BeforeStateSerial: a.BeforeStateSerial, ChangedAddresses: changed, NoOp: false}
	return out, nil
}

const JournalRecordByteLimit = 64 << 10
const JournalByteLimit = 32 << 20

// File-backed fixture framing is strict: no missing/torn/trailing/blank tail is
// silently truncated. A real store must separately fsync records and head CAS.
func EncodeJournalRecord(r JournalRecord) ([]byte, error) {
	raw, err := json.Marshal(r)
	if err != nil || len(raw)+1 > JournalRecordByteLimit {
		return nil, invalid("JOURNAL_FRAME_BOUNDS")
	}
	return append(raw, '\n'), nil
}
func DecodeJournalRecords(raw []byte) ([]JournalRecord, error) {
	if len(raw) > JournalByteLimit {
		return nil, invalid("JOURNAL_FRAME_BOUNDS")
	}
	if len(raw) == 0 {
		return []JournalRecord{}, nil
	}
	if raw[len(raw)-1] != '\n' {
		return nil, invalid("JOURNAL_TORN_TAIL")
	}
	lines := bytes.Split(raw[:len(raw)-1], []byte{'\n'})
	if len(lines) > 512 {
		return nil, invalid("JOURNAL_FRAME_BOUNDS")
	}
	out := make([]JournalRecord, 0, len(lines))
	for _, line := range lines {
		if len(line) == 0 || len(line)+1 > JournalRecordByteLimit {
			return nil, invalid("JOURNAL_FRAME_BOUNDS")
		}
		var r JournalRecord
		if decode(line, &r) != nil {
			return nil, invalid("JOURNAL_FRAME_INVALID")
		}
		canonical, _ := json.Marshal(r)
		if !bytes.Equal(canonical, line) {
			return nil, invalid("JOURNAL_NONCANONICAL_FRAME")
		}
		out = append(out, r)
	}
	return out, nil
}
