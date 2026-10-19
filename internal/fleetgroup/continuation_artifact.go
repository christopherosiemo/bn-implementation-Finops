package fleetgroup

import (
	"bytes"
	"context"
	"time"
)

// ValidateContinuationTerraformArtifact evaluates the recovery segment's own
// typed ownership and finalization. It never converts a continuation into an
// old parent/child, invents an original journal root, or trusts a projection
// uploaded by a caller. Only unsigned native Git/plan/state readers are shared.
func ValidateContinuationTerraformArtifact(ctx context.Context, v ContinuationView, keys JournalKeys, authority ContinuationAuthority, f ContinuationFinalization, capture GitTerraformArtifactCapture, now time.Time) (ArtifactReview, error) {
	var out ArtifactReview
	projection, err := VerifyContinuation(ctx, v, keys, authority, now)
	if err != nil {
		return out, err
	}
	q := projection.Pending
	if q == nil || q.Command.Mode != ContinuationInverse || !q.GitAdvanced {
		return out, invalid("CONTINUATION_NATIVE_OWNED_INVERSE_REQUIRED")
	}
	head := v.Head
	if q.Finalized != nil {
		if Digest(q.Finalized.Finalization) != Digest(f) {
			return out, invalid("CONTINUATION_NATIVE_FINALIZATION_MISMATCH")
		}
		head = q.Finalized.Head
	}
	if err = continuationValidateFinalization(f, v, projection, head, now, q.ApplyIntent); err != nil {
		return out, err
	}
	p, a := v.Origin.Parent.Program, f.Artifact
	if capture.Context != p.ArtifactContext || capture.Revision != a.Revision || capture.Recovery != nil || capture.Ref != p.Manifest.Ref || capture.RefBefore != a.PreviousRevision.Commit || capture.RefAfter != a.Revision.Commit {
		return out, invalid("CONTINUATION_NATIVE_CAPTURE_BINDING_INVALID")
	}
	if err = ValidateGitPlanInvocation(capture.Invocation); err != nil {
		return out, err
	}
	if len(capture.Configuration)+len(capture.DesiredVariables)+len(capture.SavedPlan)+len(capture.PlanJSON)+len(capture.BeforeState) > fixtureArtifactLimit || len(capture.SavedPlan) == 0 || len(capture.PlanJSON) == 0 || len(capture.BeforeState) == 0 || BytesDigest(capture.SavedPlan) != a.SavedPlanSHA256 || BytesDigest(capture.PlanJSON) != a.PlanJSONSHA256 || BytesDigest(capture.BeforeState) != a.BeforeStateSHA256 {
		return out, invalid("CONTINUATION_NATIVE_ARTIFACT_BYTES_INVALID")
	}
	configuration, err := GitFixtureConfiguration(p)
	if err != nil {
		return out, err
	}
	desired, err := GitFixtureDesired(p, a.After)
	if err != nil {
		return out, err
	}
	if !bytes.Equal(configuration, capture.Configuration) || !bytes.Equal(desired, capture.DesiredVariables) || BytesDigest(configuration) != a.Revision.ConfigurationSHA256 || BytesDigest(desired) != a.Revision.DesiredSHA256 {
		return out, invalid("CONTINUATION_NATIVE_COMMITTED_SOURCE_INVALID")
	}
	if err = validateGitCaptureObjects(GitChild{Artifact: a}, capture); err != nil {
		return out, err
	}
	beforeInputs, err := GitFixtureInputs(p, a.Before)
	if err != nil {
		return out, err
	}
	afterInputs, err := GitFixtureInputs(p, a.After)
	if err != nil {
		return out, err
	}
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
		return out, invalid("CONTINUATION_NATIVE_PLAN_INVALID")
	}
	stamp, err := time.Parse(time.RFC3339Nano, tfText(plan["timestamp"]))
	if err != nil || !canonicalTime(stamp) || stamp.Before(q.Command.CreatedAt.Truncate(time.Second)) || stamp.After(f.CreatedAt.Add(5*time.Second)) || stamp.After(now.Add(5*time.Second)) || now.Sub(stamp) > 5*time.Minute {
		return out, invalid("CONTINUATION_NATIVE_PLAN_STALE")
	}
	variables := tfObject(plan["variables"])
	wanted := map[string]int{"old_count": a.After.OldCount, "candidate_count": a.After.CandidateCount, "candidate_traffic_percent": a.After.CandidateTrafficPercent}
	if len(variables) != 3 {
		return out, invalid("CONTINUATION_NATIVE_VARIABLE_OVERRIDE")
	}
	for name, n := range wanted {
		value := tfObject(variables[name])
		actual, ok := tfUint(value["value"])
		if !tfKeys(value, []string{"value"}, nil) || !ok || actual != uint64(n) {
			return out, invalid("CONTINUATION_NATIVE_VARIABLE_OVERRIDE")
		}
	}
	if err = reviewPlanConfiguration(plan, gitModelView(p), source); err != nil {
		return out, err
	}
	prior := tfObject(plan["prior_state"])
	if !tfKeys(prior, []string{"format_version", "terraform_version", "values"}, nil) || prior["format_version"] != "1.0" || prior["terraform_version"] != FixtureTerraformVersion {
		return out, invalid("CONTINUATION_NATIVE_PRIOR_STATE_INVALID")
	}
	if err = modelValues(prior["values"], beforeInputs, ids, nil); err != nil {
		return out, err
	}
	changed, unknown, err := reviewChanges(plan, beforeInputs, afterInputs, ids)
	if err != nil {
		return out, err
	}
	if len(changed) == 0 || plan["applyable"] != true {
		return out, invalid("CONTINUATION_NATIVE_INVERSE_EFFECT_REQUIRED")
	}
	if err = modelValues(plan["planned_values"], afterInputs, ids, unknown); err != nil {
		return out, err
	}
	out = ArtifactReview{Status: "FIXTURE_CONTINUATION_RECOVERY_SEMANTICS_MATCHED", Kind: BuiltinFixtureArtifact, ProgramSHA256: Digest(p), ChildSHA256: Digest(f), BindingSHA256: Digest(p.Binding), RealmSHA256: Digest(p.Realm), ArtifactSHA256: Digest(a), ConfigurationSHA256: a.Revision.ConfigurationSHA256, SavedPlanSHA256: a.SavedPlanSHA256, PlanJSONSHA256: a.PlanJSONSHA256, BeforeStateSHA256: a.BeforeStateSHA256, StateLineage: p.ArtifactContext.StateLineage, BeforeStateSerial: a.BeforeStateSerial, ChangedAddresses: changed, NoOp: false}
	return out, nil
}
