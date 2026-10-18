package configuration

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/fleet"
)

func artifactDecode(raw []byte) (map[string]any, error) {
	var d map[string]any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if len(raw) == 0 || len(raw) > ArtifactMaxBytes || dec.Decode(&d) != nil || dec.Decode(new(any)) != io.EOF || d == nil {
		return nil, errors.New("CONFIGURATION_ARTIFACT_JSON_INVALID")
	}
	return d, nil
}
func artifactObject(x any) map[string]any              { d, _ := x.(map[string]any); return d }
func artifactArray(x any) []any                        { d, _ := x.([]any); return d }
func artifactString(d map[string]any, k string) string { s, _ := d[k].(string); return s }
func artifactFilesDigest(files []ArtifactFile) string {
	type entry struct{ Path, Mode, SHA256 string }
	list := []entry{}
	for _, f := range files {
		list = append(list, entry{f.Path, f.Mode, f.SHA256})
	}
	return artifactHash(list)
}
func artifactDependencyDigest(b ArtifactBundle) string {
	return artifactHash(map[string]any{"source": artifactFilesDigest(b.Files), "modules": artifactBytesHash(b.ModuleManifest), "toolchain": b.Toolchain})
}
func artifactResourceAddresses(module map[string]any, out map[string]bool) error {
	for _, x := range artifactArray(module["resources"]) {
		r := artifactObject(x)
		address := artifactString(r, "address")
		if address == "" || out[address] {
			return errors.New("CONFIGURATION_ARTIFACT_RESOURCE_AMBIGUOUS")
		}
		out[address] = true
	}
	for _, x := range artifactArray(module["child_modules"]) {
		if e := artifactResourceAddresses(artifactObject(x), out); e != nil {
			return e
		}
	}
	return nil
}
func ValidateArtifactBundle(reg ArtifactRegistration, b ArtifactBundle) (ArtifactMetadata, error) {
	var m ArtifactMetadata
	if e := ValidateArtifactRegistration(reg); e != nil {
		return m, e
	}
	if b.SchemaVersion != "1" || b.Toolchain != reg.Toolchain || !artifactCommit.MatchString(b.Git.Commit) || !artifactCommit.MatchString(b.Git.Tree) || b.Git.Ref != reg.Declaration.Repository.Ref || len(b.Files) == 0 || len(b.Files) > 4096 || len(b.SavedPlan) == 0 {
		return m, errors.New("CONFIGURATION_ARTIFACT_BUNDLE_INVALID")
	}
	var size int64
	seen := map[string]bool{}
	last := ""
	reasons := []string{"NO_EXECUTION_AUTHORITY", "REMOTE_GIT_HEAD_UNVERIFIED", "NATIVE_STATE_FRESHNESS_UNPROVEN"}
	for _, f := range b.Files {
		if f.Path == "" || f.Path != path.Clean(f.Path) || strings.HasPrefix(f.Path, "/") || strings.HasPrefix(f.Path, "../") || strings.ContainsAny(f.Path, "\\\x00\r\n") || seen[f.Path] || last > f.Path || (f.Mode != "100644" && f.Mode != "100755") || f.SHA256 != artifactBytesHash(f.Body) {
			return m, errors.New("CONFIGURATION_ARTIFACT_SOURCE_INVALID")
		}
		seen[f.Path] = true
		last = f.Path
		size += int64(len(f.Body))
		if strings.HasSuffix(f.Path, ".tf") || strings.HasSuffix(f.Path, ".tf.json") {
			// First scope has no external process, filesystem or uncommitted variable
			// inputs. Unsupported HCL is a blocker, never silently assumed complete.
			inspect := f.Body
			if strings.HasSuffix(f.Path, ".tf.json") {
				if decoded, e := artifactDecode(f.Body); e == nil {
					inspect, _ = json.Marshal(decoded)
				} else {
					return m, errors.New("CONFIGURATION_ARTIFACT_SOURCE_JSON_INVALID")
				}
			}
			if regexp.MustCompile(`(?i)\b(file[a-z0-9_]*|templatefile|pathexpand|abspath)\s*\(|\b(variable|data|ephemeral|import)\s+["A-Za-z_{]|\b(local-exec|remote-exec)\b`).Match(inspect) {
				reasons = append(reasons, "CONFIGURATION_EXTERNAL_INPUT_CLOSURE_UNSUPPORTED")
			}
		}
	}
	for _, raw := range [][]byte{b.SavedPlan, b.PlanJSON, b.StateRaw, b.StateJSON, b.VersionJSON, b.ModuleManifest} {
		size += int64(len(raw))
	}
	if size > ArtifactMaxBytes {
		return m, errors.New("CONFIGURATION_ARTIFACT_BUNDLE_LIMIT")
	}
	if b.Git.ConfigurationSHA256 != artifactFilesDigest(b.Files) || b.Git.DependencySHA256 != artifactDependencyDigest(b) {
		return m, errors.New("CONFIGURATION_ARTIFACT_SOURCE_DIGEST_CHANGED")
	}
	if e := validateArtifactPlanContainer(reg, b); e != nil {
		return m, e
	}
	version, e := artifactDecode(b.VersionJSON)
	if e != nil {
		return m, e
	}
	if artifactString(version, "terraform_version") != reg.Toolchain.TerraformVersion || artifactString(version, "platform") != reg.Toolchain.OS+"_"+reg.Toolchain.Architecture {
		return m, errors.New("CONFIGURATION_ARTIFACT_TOOLCHAIN_CHANGED")
	}
	if len(artifactObject(version["provider_selections"])) > 0 {
		reasons = append(reasons, "CONFIGURATION_EXTERNAL_PROVIDER_UNSUPPORTED")
	}
	state, e := artifactDecode(b.StateRaw)
	if e != nil {
		return m, e
	}
	serial, ok := state["serial"].(json.Number)
	if !ok {
		return m, errors.New("CONFIGURATION_ARTIFACT_STATE_INVALID")
	}
	sv, e := serial.Int64()
	if e != nil || sv < 0 || uint64(sv) != b.State.Serial || artifactString(state, "lineage") != b.State.Lineage || !uuidPattern.MatchString(b.State.Lineage) || b.State.Lineage != reg.Declaration.Terraform.StateLineage || b.State.Workspace != reg.Declaration.Terraform.Workspace || state["version"] != json.Number("4") || artifactString(state, "terraform_version") != reg.Toolchain.TerraformVersion {
		return m, errors.New("CONFIGURATION_ARTIFACT_STATE_CHANGED")
	}
	for _, x := range artifactArray(state["resources"]) {
		if artifactString(artifactObject(x), "provider") != `provider["terraform.io/builtin/terraform"]` {
			reasons = append(reasons, "CONFIGURATION_EXTERNAL_PROVIDER_UNSUPPORTED")
		}
	}
	stateJSON, e := artifactDecode(b.StateJSON)
	if e != nil {
		return m, e
	}
	plan, e := artifactDecode(b.PlanJSON)
	if e != nil {
		return m, e
	}
	if !strings.HasPrefix(artifactString(plan, "format_version"), "1.") || !strings.HasPrefix(artifactString(stateJSON, "format_version"), "1.") || artifactString(plan, "terraform_version") != reg.Toolchain.TerraformVersion || artifactString(stateJSON, "terraform_version") != reg.Toolchain.TerraformVersion || plan["errored"] == true {
		return m, errors.New("CONFIGURATION_ARTIFACT_PLAN_FORMAT_UNSUPPORTED")
	}
	if artifactHash(artifactObject(plan["prior_state"])["values"]) != artifactHash(stateJSON["values"]) {
		return m, errors.New("CONFIGURATION_ARTIFACT_PRIOR_STATE_CHANGED")
	}
	for _, x := range artifactArray(plan["resource_drift"]) {
		if artifactHash(artifactObject(artifactObject(x)["change"])["actions"]) != artifactHash([]string{"no-op"}) {
			return m, errors.New("CONFIGURATION_ARTIFACT_DRIFT_DETECTED")
		}
	}
	for _, x := range artifactArray(plan["resource_changes"]) {
		if artifactHash(artifactObject(artifactObject(x)["change"])["actions"]) != artifactHash([]string{"no-op"}) {
			return m, errors.New("CONFIGURATION_ARTIFACT_BASELINE_PLAN_NOT_NOOP")
		}
	}
	for _, x := range artifactObject(artifactObject(plan["configuration"])["provider_config"]) {
		if artifactString(artifactObject(x), "full_name") != "terraform.io/builtin/terraform" {
			reasons = append(reasons, "CONFIGURATION_EXTERNAL_PROVIDER_UNSUPPORTED")
		}
	}
	modules, e := artifactDecode(b.ModuleManifest)
	if e != nil {
		return m, e
	}
	if len(artifactArray(modules["Modules"])) == 0 {
		return m, errors.New("CONFIGURATION_ARTIFACT_MODULE_MANIFEST_REQUIRED")
	}
	for _, x := range artifactArray(modules["Modules"]) {
		entry := artifactObject(x)
		source := artifactString(entry, "Source")
		dir := artifactString(entry, "Dir")
		if source != "" && !strings.HasPrefix(source, "./") && !strings.HasPrefix(source, "../") || dir == "" || strings.HasPrefix(dir, "/") || path.Clean(dir) != dir || strings.HasPrefix(dir, "../") || strings.ContainsAny(dir, "\\\x00") {
			reasons = append(reasons, "CONFIGURATION_EXTERNAL_MODULE_UNSUPPORTED")
			continue
		}
		prefix := strings.TrimPrefix(path.Join(reg.Declaration.Repository.Directory, dir)+"/", "./")
		if prefix == "./" {
			prefix = ""
		}
		found := false
		for file := range seen {
			if strings.HasPrefix(file, prefix) {
				found = true
			}
		}
		if !found {
			reasons = append(reasons, "CONFIGURATION_LOCAL_MODULE_UNCAPTURED")
		}
	}
	addresses := map[string]bool{}
	if e = artifactResourceAddresses(artifactObject(artifactObject(stateJSON["values"])["root_module"]), addresses); e != nil {
		return m, e
	}
	for _, address := range reg.Declaration.Terraform.Addresses {
		if !addresses[address] {
			reasons = append(reasons, "CONFIGURATION_DECLARED_ADDRESS_UNOBSERVED")
		}
	}
	status := "OBSERVED"
	for _, r := range reasons {
		if strings.HasPrefix(r, "CONFIGURATION_") {
			status = "BLOCKED"
		}
	}
	raw, e := json.Marshal(b)
	if e != nil || len(raw) > ArtifactMaxBytes {
		return m, errors.New("CONFIGURATION_ARTIFACT_BUNDLE_LIMIT")
	}
	reasons = artifactUnique(reasons)
	sort.Strings(reasons)
	m = ArtifactMetadata{SchemaVersion: "1", RegistrationID: reg.ID, RegistrationVersion: reg.Version, RegistrationHash: artifactHash(reg), Binding: reg.Binding, AuthorityID: reg.AuthorityID, AuthorityVersion: reg.AuthorityVersion, AuthorityHash: reg.AuthorityHash, Git: b.Git, Toolchain: b.Toolchain, State: b.State, BundleSHA256: artifactBytesHash(raw), SavedPlanSHA256: artifactBytesHash(b.SavedPlan), PlanJSONSHA256: artifactBytesHash(b.PlanJSON), StateSHA256: artifactBytesHash(b.StateRaw), Status: status, ReasonCodes: reasons}
	return m, nil
}

// These offline reviewers never sign or authorize a plan. Future private child
// factories must still select current state, proofs and exact owned effects.
func ReviewArtifactFleetPlan(b ArtifactBundle, c fleet.ChildPlan, p fleet.FleetPlanV4, provenance fleet.IaCBinding, now time.Time) (fleet.PlanReview, error) {
	return fleet.ValidateTerraformPlan(b.PlanJSON, b.SavedPlan, c, p, provenance, now)
}
