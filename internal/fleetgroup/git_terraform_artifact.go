package fleetgroup

import (
	"bytes"
	"encoding/hex"
	"sort"
	"strings"
	"time"
)

const GitFixtureStatePath = "/workspace/private/current.tfstate"
const GitFixturePlanPath = "/workspace/private/next.tfplan"

// Invocation is observed by the isolated trusted producer. It is not a caller
// attestation that an arbitrary CLI ran. The producer must execute the pinned
// absolute binary with this actual environment and no inherited credentials.
type GitPlanInvocation struct {
	Arguments       []string
	EnvironmentKeys []string
}

type GitTerraformRecoveryAuthority struct {
	Original  GitChild
	Applied   GitOwnedReceipt
	Ownership GitOwnership
}

// This private capture is never a public upload. The independently authenticated
// producer observes the real ref CAS, clean Git tree/index, pinned process image,
// actual arguments/environment, and show derived from the exact saved plan.
// Values-file provenance is Git + native variables, not an invented ZIP entry:
// Terraform1.16 config snapshots deliberately omit values files.
type GitTerraformArtifactCapture struct {
	Context          ArtifactContext
	Revision         GitRevision
	Configuration    []byte
	DesiredVariables []byte
	SavedPlan        []byte
	PlanJSON         []byte
	BeforeState      []byte
	GitCommitObject  []byte
	GitTreeObject    []byte
	Ref              string
	RefBefore        string
	RefAfter         string
	Invocation       GitPlanInvocation
	Recovery         *GitTerraformRecoveryAuthority
}

func ValidateGitPlanInvocation(in GitPlanInvocation) error {
	wanted := map[string]bool{"-input=false": true, "-no-color": true, "-refresh=false": true, "-state=" + GitFixtureStatePath: true, "-out=" + GitFixturePlanPath: true}
	if len(in.Arguments) != 6 || in.Arguments[0] != "plan" {
		return invalid("GROUP_GIT_PLAN_INVOCATION_INVALID")
	}
	for _, arg := range in.Arguments[1:] {
		if !wanted[arg] {
			return invalid("GROUP_GIT_PLAN_INVOCATION_INVALID")
		}
		delete(wanted, arg)
	}
	allowed := map[string]bool{"PATH": true, "HOME": true, "TMPDIR": true, "LANG": true, "LC_ALL": true, "TF_IN_AUTOMATION": true, "TF_INPUT": true, "TF_DATA_DIR": true}
	seen := map[string]bool{}
	for _, key := range in.EnvironmentKeys {
		if !allowed[key] || seen[key] {
			return invalid("GROUP_GIT_PLAN_ENVIRONMENT_INVALID")
		}
		seen[key] = true
	}
	if !seen["PATH"] || !seen["HOME"] {
		return invalid("GROUP_GIT_PLAN_ENVIRONMENT_INVALID")
	}
	return nil
}

func ValidateGitRefTransition(p GitProgram, c GitChild, ref, before, after string) error {
	if ref != p.Manifest.Ref || before != c.Artifact.PreviousRevision.Commit || after != c.Artifact.Revision.Commit {
		return invalid("GROUP_GIT_REF_CAS_MISMATCH")
	}
	return nil
}

func validateGitCaptureObjects(c GitChild, capture GitTerraformArtifactCapture) error {
	r := capture.Revision
	width := len(r.Commit)
	if width != len(r.Tree) || width != 40 && width != 64 || len(capture.GitCommitObject) == 0 || len(capture.GitCommitObject) > 64<<10 || len(capture.GitTreeObject) > 4096 || gitObjectOID("commit", capture.GitCommitObject, width) != r.Commit || gitObjectOID("tree", capture.GitTreeObject, width) != r.Tree {
		return invalid("GROUP_GIT_RAW_OBJECT_BINDING_INVALID")
	}
	parts := strings.SplitN(string(capture.GitCommitObject), "\n\n", 2)
	if len(parts) != 2 || strings.ContainsAny(parts[0], "\x00\r") || !strings.HasPrefix(parts[0], "tree "+r.Tree+"\n") {
		return invalid("GROUP_GIT_RAW_COMMIT_INVALID")
	}
	parents := []string{}
	seen := map[string]int{}
	for _, line := range strings.Split(parts[0], "\n") {
		pair := strings.SplitN(line, " ", 2)
		if len(pair) != 2 || pair[1] == "" || len(pair[1]) > 2048 {
			return invalid("GROUP_GIT_RAW_COMMIT_INVALID")
		}
		seen[pair[0]]++
		switch pair[0] {
		case "tree":
			if pair[1] != r.Tree || seen["tree"] != 1 {
				return invalid("GROUP_GIT_RAW_COMMIT_INVALID")
			}
		case "parent":
			if !commitPattern.MatchString(pair[1]) || len(pair[1]) != width {
				return invalid("GROUP_GIT_RAW_PARENT_INVALID")
			}
			parents = append(parents, pair[1])
		case "author", "committer":
			if seen[pair[0]] != 1 {
				return invalid("GROUP_GIT_RAW_COMMIT_INVALID")
			}
		default:
			return invalid("GROUP_GIT_RAW_COMMIT_INVALID")
		}
	}
	if seen["author"] != 1 || seen["committer"] != 1 || len(parents) > 1 {
		return invalid("GROUP_GIT_RAW_PARENT_INVALID")
	}
	if r != c.Artifact.PreviousRevision && (len(parents) != 1 || parents[0] != c.Artifact.PreviousRevision.Commit) {
		return invalid("GROUP_GIT_RAW_PARENT_INVALID")
	}
	wanted := []byte{}
	for _, file := range []struct {
		name string
		raw  []byte
	}{{GitDesiredPath, capture.DesiredVariables}, {GitMainPath, capture.Configuration}} {
		oid, err := hex.DecodeString(gitObjectOID("blob", file.raw, width))
		if err != nil {
			return invalid("GROUP_GIT_RAW_OBJECT_BINDING_INVALID")
		}
		wanted = append(wanted, []byte("100644 "+file.name+"\x00")...)
		wanted = append(wanted, oid...)
	}
	if !bytes.Equal(wanted, capture.GitTreeObject) {
		return invalid("GROUP_GIT_TWO_FILE_TREE_REQUIRED")
	}
	return nil
}

// This native-state reader shares the strict unsigned state schema, not the v5
// signed artifact contract. The temporary value carries only a serial into the
// existing low-level parser; no v5 validation/signature or receipt is produced.
func gitRawState(raw []byte, p GitProgram, c GitChild, inputs map[string]map[string]any) (map[string]any, map[string]string, error) {
	return rawFixtureState(raw, gitModelView(p), Child{Artifact: Artifact{BeforeStateSerial: c.Artifact.BeforeStateSerial}}, inputs)
}

// ValidateGitTerraformArtifact does not execute Git/Terraform, authenticate a
// producer or publish proof. It checks this new signed family's exact context
// and semantics directly. No v5 artifact or signature is adapted or reused.
func ValidateGitTerraformArtifact(p GitProgram, c GitChild, capture GitTerraformArtifactCapture, now time.Time) (ArtifactReview, error) {
	var out ArtifactReview
	if capture.Context != p.ArtifactContext || capture.Revision != c.Artifact.Revision {
		return out, invalid("GROUP_GIT_CAPTURE_CONTEXT_MISMATCH")
	}
	if c.Mode == Forward {
		if capture.Recovery != nil {
			return out, invalid("GROUP_GIT_RECOVERY_CONTEXT_INVALID")
		}
		if err := ValidateGitChild(c, p, now); err != nil {
			return out, err
		}
	} else if c.Mode == OwnedRecovery && capture.Recovery != nil {
		r := capture.Recovery
		if err := ValidateGitRecovery(c, r.Original, p, r.Applied, r.Ownership, now); err != nil {
			return out, err
		}
	} else {
		return out, invalid("GROUP_GIT_RECOVERY_CONTEXT_INVALID")
	}
	if err := ValidateGitPlanInvocation(capture.Invocation); err != nil {
		return out, err
	}
	if err := ValidateGitRefTransition(p, c, capture.Ref, capture.RefBefore, capture.RefAfter); err != nil {
		return out, err
	}
	if len(capture.Configuration)+len(capture.DesiredVariables)+len(capture.SavedPlan)+len(capture.PlanJSON)+len(capture.BeforeState) > fixtureArtifactLimit {
		return out, invalid("GROUP_GIT_CAPTURE_BOUNDS")
	}
	a := c.Artifact
	if len(capture.SavedPlan) == 0 || len(capture.PlanJSON) == 0 || len(capture.BeforeState) == 0 || BytesDigest(capture.SavedPlan) != a.SavedPlanSHA256 || BytesDigest(capture.PlanJSON) != a.PlanJSONSHA256 || BytesDigest(capture.BeforeState) != a.BeforeStateSHA256 {
		return out, invalid("GROUP_GIT_ARTIFACT_BYTES_MISMATCH")
	}
	configuration, err := GitFixtureConfiguration(p)
	if err != nil {
		return out, err
	}
	desired, err := GitFixtureDesired(p, a.After)
	if err != nil {
		return out, err
	}
	if !bytes.Equal(configuration, capture.Configuration) || !bytes.Equal(desired, capture.DesiredVariables) || BytesDigest(capture.Configuration) != a.Revision.ConfigurationSHA256 || BytesDigest(capture.DesiredVariables) != a.Revision.DesiredSHA256 {
		return out, invalid("GROUP_GIT_COMMITTED_CONFIGURATION_MISMATCH")
	}
	if err = validateGitCaptureObjects(c, capture); err != nil {
		return out, err
	}
	source, err := fixtureObject(capture.Configuration, 256<<10)
	if err != nil {
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
	before, ids, err := gitRawState(capture.BeforeState, p, c, beforeInputs)
	if err != nil {
		return out, err
	}
	// Native plan archives contain configuration, not automatic values files.
	// Reuse only the native ZIP/state reader, never ValidateTerraformArtifact.
	if err = validateFixtureContainer(TerraformArtifactCapture{Context: capture.Context, Configuration: capture.Configuration, SavedPlan: capture.SavedPlan}, before); err != nil {
		return out, err
	}
	plan, err := fixtureObject(capture.PlanJSON, fixtureArtifactLimit)
	if err != nil {
		return out, err
	}
	if !tfKeys(plan, []string{"format_version", "terraform_version", "variables", "planned_values", "resource_changes", "prior_state", "configuration", "timestamp", "applyable", "complete", "errored"}, []string{"resource_drift", "output_changes", "relevant_attributes", "checks"}) || plan["format_version"] != "1.2" || plan["terraform_version"] != FixtureTerraformVersion || plan["complete"] != true || plan["errored"] != false || !tfEmpty(plan["resource_drift"]) || !tfEmpty(plan["output_changes"]) || !tfEmpty(plan["relevant_attributes"]) || !tfEmpty(plan["checks"]) {
		return out, invalid("GROUP_GIT_PLAN_FORMAT_OR_DRIFT_INVALID")
	}
	stamp, e := time.Parse(time.RFC3339Nano, tfText(plan["timestamp"]))
	if e != nil || !canonicalTime(stamp) || stamp.Before(p.CreatedAt.Truncate(time.Second)) || stamp.After(c.CreatedAt.Add(5*time.Second)) || stamp.After(now.Add(5*time.Second)) || now.Sub(stamp) > 5*time.Minute {
		return out, invalid("GROUP_GIT_PLAN_TIMESTAMP_INVALID")
	}
	variables := tfObject(plan["variables"])
	want := map[string]int{"old_count": a.After.OldCount, "candidate_count": a.After.CandidateCount, "candidate_traffic_percent": a.After.CandidateTrafficPercent}
	if len(variables) != 3 {
		return out, invalid("GROUP_GIT_VARIABLE_OVERRIDE_OR_MISSING")
	}
	for name, count := range want {
		value := tfObject(variables[name])
		n, ok := tfUint(value["value"])
		if !tfKeys(value, []string{"value"}, nil) || !ok || n != uint64(count) {
			return out, invalid("GROUP_GIT_VARIABLE_OVERRIDE_OR_MISSING")
		}
	}
	if err = reviewPlanConfiguration(plan, gitModelView(p), source); err != nil {
		return out, err
	}
	prior := tfObject(plan["prior_state"])
	if !tfKeys(prior, []string{"format_version", "terraform_version", "values"}, nil) || prior["format_version"] != "1.0" || prior["terraform_version"] != FixtureTerraformVersion {
		return out, invalid("GROUP_GIT_PRIOR_STATE_INVALID")
	}
	if err = modelValues(prior["values"], beforeInputs, ids, nil); err != nil {
		return out, err
	}
	changed, unknown, err := reviewChanges(plan, beforeInputs, afterInputs, ids)
	if err != nil {
		return out, err
	}
	if plan["applyable"] != (len(changed) > 0) {
		return out, invalid("GROUP_GIT_APPLYABILITY_MISMATCH")
	}
	if err = modelValues(plan["planned_values"], afterInputs, ids, unknown); err != nil {
		return out, err
	}
	sort.Strings(changed)
	out = ArtifactReview{Status: "FIXTURE_GIT_SEMANTICS_MATCHED", Kind: BuiltinFixtureArtifact, ProgramSHA256: Digest(p), ChildSHA256: Digest(c), BindingSHA256: Digest(p.Binding), RealmSHA256: Digest(p.Realm), ArtifactSHA256: Digest(a), ConfigurationSHA256: a.Revision.ConfigurationSHA256, SavedPlanSHA256: a.SavedPlanSHA256, PlanJSONSHA256: a.PlanJSONSHA256, BeforeStateSHA256: a.BeforeStateSHA256, StateLineage: p.ArtifactContext.StateLineage, BeforeStateSerial: a.BeforeStateSerial, ChangedAddresses: changed, NoOp: len(changed) == 0}
	return out, nil
}
