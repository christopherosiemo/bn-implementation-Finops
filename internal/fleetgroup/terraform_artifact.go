package fleetgroup

import (
	"archive/zip"
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	// The binary container check is intentionally version-specific. Terraform's
	// saved-plan protobuf remains opaque and must be read by the pinned real CLI.
	FixtureTerraformVersion = "1.16.0"
	FixtureWorkingDirectory = "/workspace/fixture"
	fixtureArtifactLimit    = 64 << 20
)

// TerraformArtifactCapture is private producer input, never an upload API.
// The producer must independently inspect its immutable image, actual Git
// commit/tree and clean workspace, copy only committed main.tf.json, and derive
// PlanJSON by running that pinned CLI's show on these exact saved-plan bytes.
// Context equality alone cannot authenticate those observations.
type TerraformArtifactCapture struct {
	Context         ArtifactContext
	Configuration   []byte
	SavedPlan       []byte
	PlanJSON        []byte
	BeforeState     []byte
	GitCommitObject []byte
	GitTreeObject   []byte
	Recovery        *TerraformRecoveryAuthority
}

type TerraformRecoveryAuthority struct {
	Original Child
	Owned    OwnedReceipt
}

type ArtifactReview struct {
	Status                  string   `json:"status"`
	Kind                    string   `json:"kind"`
	ProgramSHA256           string   `json:"program_sha256"`
	ChildSHA256             string   `json:"child_sha256"`
	BindingSHA256           string   `json:"binding_sha256"`
	RealmSHA256             string   `json:"realm_sha256"`
	ArtifactSHA256          string   `json:"artifact_sha256"`
	ConfigurationSHA256     string   `json:"configuration_sha256"`
	SavedPlanSHA256         string   `json:"saved_plan_sha256"`
	PlanJSONSHA256          string   `json:"plan_json_sha256"`
	BeforeStateSHA256       string   `json:"before_state_sha256"`
	StateLineage            string   `json:"state_lineage"`
	BeforeStateSerial       uint64   `json:"before_state_serial"`
	ChangedAddresses        []string `json:"changed_addresses"`
	NoOp                    bool     `json:"no_op"`
	CustomerNativeExecution bool     `json:"customer_native_execution"`
	CustomerVerifiedSaving  *string  `json:"customer_verified_saving"`
}

func fixtureMapping(p Program) (map[string]string, error) {
	if err := ValidateRealm(p.Realm); err != nil {
		return nil, err
	}
	if err := ValidateBinding(p.Binding); err != nil {
		return nil, err
	}
	if !template(p.OldTemplate) || !template(p.CandidateTemplate) || p.ArtifactContext.TerraformVersion != FixtureTerraformVersion {
		return nil, invalid("GROUP_TERRAFORM_MODEL_UNSUPPORTED")
	}
	m := p.ArtifactContext.Mapping
	roles := map[string]string{m.OldModel: "old", m.CandidateModel: "candidate", m.TrafficModel: "traffic"}
	if len(roles) != 3 {
		return nil, invalid("GROUP_TERRAFORM_MODEL_ADDRESS_INVALID")
	}
	for address := range roles {
		parts := strings.Split(address, ".")
		if len(parts) != 2 || parts[0] != "terraform_data" || !regexpName(parts[1]) {
			return nil, invalid("GROUP_TERRAFORM_MODEL_ADDRESS_INVALID")
		}
	}
	return roles, nil
}

func regexpName(s string) bool {
	if len(s) == 0 || len(s) > 128 {
		return false
	}
	for i, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_' || i > 0 && (c >= '0' && c <= '9' || c == '-')) {
			return false
		}
	}
	return true
}

// FixtureInputs derives the complete allowed model input schema. These native-
// shaped identities describe a lab model, never an AWS resource observation.
func FixtureInputs(p Program, state ModelState) (map[string]map[string]any, error) {
	roles, err := fixtureMapping(p)
	if err != nil {
		return nil, err
	}
	if err = ValidateBudget(p.Budget); err != nil {
		return nil, err
	}
	if !model(state, p) {
		return nil, invalid("GROUP_TERRAFORM_MODEL_STATE_INVALID")
	}
	out := map[string]map[string]any{}
	for address, role := range roles {
		input := map[string]any{"binding_sha256": Digest(p.Binding), "realm_sha256": Digest(p.Realm)}
		if role == "traffic" {
			input["old_asg_arn"], input["candidate_asg_arn"], input["candidate_percent"] = p.Binding.Old.Target.ASGARN, p.Binding.Candidate.Target.ASGARN, state.CandidateTrafficPercent
		} else {
			selection, pinned, count := p.Binding.Old, p.OldTemplate, state.OldCount
			if role == "candidate" {
				selection, pinned, count = p.Binding.Candidate, p.CandidateTemplate, state.CandidateCount
			}
			input["asg_arn"], input["registration_id"], input["desired_count"] = selection.Target.ASGARN, selection.Registration.ID, count
			input["launch_template_id"], input["launch_template_version"], input["instance_type"], input["template_sha256"] = pinned.ID, pinned.Version, pinned.InstanceType, pinned.SHA256
		}
		out[address] = input
	}
	return out, nil
}

// FixtureConfiguration emits the sole supported committed Terraform JSON file.
// Only three numeric variables can vary by child. There are no outputs, local
// or remote modules, providers, data sources, provisioners or external inputs.
// ConfigurationSHA256 must subsequently bind these exact bytes in the context.
func FixtureConfiguration(p Program) ([]byte, error) {
	state := ModelState{Digest(p.Binding), Digest(p.Realm), p.Budget.BaselineCount, 0, 0}
	inputs, err := FixtureInputs(p, state)
	if err != nil {
		return nil, err
	}
	resources := map[string]any{}
	for address, input := range inputs {
		variable := "old_count"
		if address == p.ArtifactContext.Mapping.CandidateModel {
			variable = "candidate_count"
		}
		if address == p.ArtifactContext.Mapping.TrafficModel {
			input["candidate_percent"] = "${var.candidate_traffic_percent}"
		} else {
			input["desired_count"] = "${var." + variable + "}"
		}
		resources[strings.TrimPrefix(address, "terraform_data.")] = map[string]any{"input": input}
	}
	return json.Marshal(map[string]any{
		"terraform": map[string]any{"required_version": "= " + FixtureTerraformVersion},
		"variable":  map[string]any{"old_count": map[string]any{"type": "number"}, "candidate_count": map[string]any{"type": "number"}, "candidate_traffic_percent": map[string]any{"type": "number"}},
		"resource":  map[string]any{"terraform_data": resources},
	})
}

func gitObjectOID(kind string, body []byte, width int) string {
	framed := append([]byte(kind+" "+strconv.Itoa(len(body))+"\x00"), body...)
	if width == 40 {
		sum := sha1.Sum(framed)
		return hex.EncodeToString(sum[:])
	}
	if width == 64 {
		return BytesDigest(framed)
	}
	return ""
}

// The approved commit/tree come from the server's pinned registration. Native
// Git object framing binds the exact sole configuration blob to both IDs. This
// does not claim a remote branch head is fresh or that a caller owns a repository.
func validateFixtureGit(capture TerraformArtifactCapture) error {
	context := capture.Context
	width := len(context.GitCommit)
	if width != len(context.GitTree) || width != 40 && width != 64 || len(capture.GitCommitObject) == 0 || len(capture.GitCommitObject) > 64<<10 || len(capture.GitTreeObject) > 4096 || gitObjectOID("commit", capture.GitCommitObject, width) != context.GitCommit || gitObjectOID("tree", capture.GitTreeObject, width) != context.GitTree {
		return invalid("GROUP_TERRAFORM_GIT_OBJECT_BINDING_INVALID")
	}
	headers := strings.SplitN(string(capture.GitCommitObject), "\n\n", 2)
	if len(headers) != 2 || !strings.HasPrefix(headers[0], "tree "+context.GitTree+"\n") || strings.Contains(headers[0], "\ntree ") || strings.ContainsAny(headers[0], "\x00\r") {
		return invalid("GROUP_TERRAFORM_GIT_COMMIT_TREE_INVALID")
	}
	blob, err := hex.DecodeString(gitObjectOID("blob", capture.Configuration, width))
	if err != nil {
		return invalid("GROUP_TERRAFORM_GIT_OBJECT_BINDING_INVALID")
	}
	wanted := append([]byte("100644 main.tf.json\x00"), blob...)
	if !bytes.Equal(capture.GitTreeObject, wanted) {
		return invalid("GROUP_TERRAFORM_GIT_SOURCE_CLOSURE_INVALID")
	}
	return nil
}

func fixtureObject(raw []byte, limit int) (map[string]any, error) {
	if len(raw) == 0 || len(raw) > limit {
		return nil, invalid("GROUP_TERRAFORM_JSON_BOUNDS")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if err := uniqueValue(d, 0); err != nil {
		return nil, invalid("GROUP_TERRAFORM_JSON_INVALID")
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, invalid("GROUP_TERRAFORM_JSON_INVALID")
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var out map[string]any
	if err := d.Decode(&out); err != nil || out == nil {
		return nil, invalid("GROUP_TERRAFORM_JSON_INVALID")
	}
	return out, nil
}

func tfObject(v any) map[string]any { out, _ := v.(map[string]any); return out }
func tfArray(v any) []any           { out, _ := v.([]any); return out }
func tfText(v any) string           { out, _ := v.(string); return out }
func tfEqual(a, b any) bool         { return Digest(a) != "" && Digest(a) == Digest(b) }

func tfKeys(o map[string]any, required, optional []string) bool {
	if o == nil {
		return false
	}
	allowed := map[string]bool{}
	for _, key := range required {
		if _, ok := o[key]; !ok {
			return false
		}
		allowed[key] = true
	}
	for _, key := range optional {
		allowed[key] = true
	}
	for key := range o {
		if !allowed[key] {
			return false
		}
	}
	return true
}

func tfEmpty(v any) bool {
	return v == nil || tfObject(v) != nil && len(tfObject(v)) == 0 || tfArray(v) != nil && len(tfArray(v)) == 0
}

func tfUint(v any) (uint64, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	s := string(n)
	if s == "" || len(s) > 20 || len(s) > 1 && s[0] == '0' {
		return 0, false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	u, err := strconv.ParseUint(s, 10, 64)
	return u, err == nil
}

func noSensitive(v any) bool {
	switch x := v.(type) {
	case nil:
		return true
	case bool:
		return !x
	case map[string]any:
		for _, sub := range x {
			if !noSensitive(sub) {
				return false
			}
		}
		return true
	case []any:
		for _, sub := range x {
			if !noSensitive(sub) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func inputType(input map[string]any) []any {
	types := map[string]any{}
	for key, value := range input {
		typeName := "number"
		if _, ok := value.(string); ok {
			typeName = "string"
		}
		types[key] = typeName
	}
	return []any{"object", types}
}

func dynamic(v any, input map[string]any) bool {
	d := tfObject(v)
	return tfKeys(d, []string{"value", "type"}, nil) && tfEqual(d["value"], input) && tfEqual(d["type"], inputType(input))
}

func rawFixtureState(raw []byte, p Program, c Child, inputs map[string]map[string]any) (map[string]any, map[string]string, error) {
	s, err := fixtureObject(raw, fixtureArtifactLimit)
	if err != nil {
		return nil, nil, err
	}
	serial, validSerial := tfUint(s["serial"])
	if !tfKeys(s, []string{"version", "terraform_version", "serial", "lineage", "outputs", "resources"}, []string{"check_results"}) || s["version"] != json.Number("4") || s["terraform_version"] != FixtureTerraformVersion || !validSerial || serial != c.Artifact.BeforeStateSerial || s["lineage"] != p.ArtifactContext.StateLineage || !uuidPattern.MatchString(tfText(s["lineage"])) || !tfEmpty(s["outputs"]) || !tfEmpty(s["check_results"]) {
		return nil, nil, invalid("GROUP_TERRAFORM_BEFORE_STATE_INVALID")
	}
	resources := tfArray(s["resources"])
	if len(resources) != 3 {
		return nil, nil, invalid("GROUP_TERRAFORM_STATE_RESOURCE_SET_INVALID")
	}
	ids := map[string]string{}
	for _, rawResource := range resources {
		r := tfObject(rawResource)
		address := "terraform_data." + tfText(r["name"])
		input, ok := inputs[address]
		if !ok || ids[address] != "" || !tfKeys(r, []string{"mode", "type", "name", "provider", "instances"}, nil) || r["mode"] != "managed" || r["type"] != "terraform_data" || r["provider"] != `provider["terraform.io/builtin/terraform"]` {
			return nil, nil, invalid("GROUP_TERRAFORM_STATE_RESOURCE_SET_INVALID")
		}
		instances := tfArray(r["instances"])
		if len(instances) != 1 {
			return nil, nil, invalid("GROUP_TERRAFORM_STATE_INSTANCE_INVALID")
		}
		i := tfObject(instances[0])
		attributes := tfObject(i["attributes"])
		if !tfKeys(i, []string{"schema_version", "attributes", "sensitive_attributes"}, []string{"identity_schema_version"}) || i["schema_version"] != json.Number("0") || !tfEmpty(i["sensitive_attributes"]) || i["identity_schema_version"] != nil && i["identity_schema_version"] != json.Number("0") || !tfKeys(attributes, []string{"id", "input", "output", "store", "triggers_replace"}, nil) || !uuidPattern.MatchString(tfText(attributes["id"])) || !dynamic(attributes["input"], input) || !dynamic(attributes["output"], input) || attributes["store"] != nil || attributes["triggers_replace"] != nil {
			return nil, nil, invalid("GROUP_TERRAFORM_STATE_INSTANCE_INVALID")
		}
		ids[address] = tfText(attributes["id"])
	}
	return s, ids, nil
}

// validateFixtureContainer binds the supported native saved-plan archive's
// complete source and embedded state. It never extracts paths, interprets the
// opaque tfplan protobuf or substitutes for the independently pinned real CLI.
func validateFixtureContainer(capture TerraformArtifactCapture, before map[string]any) error {
	if capture.Context.TerraformVersion != FixtureTerraformVersion {
		return invalid("GROUP_TERRAFORM_CONTAINER_VERSION_UNSUPPORTED")
	}
	z, err := zip.NewReader(bytes.NewReader(capture.SavedPlan), int64(len(capture.SavedPlan)))
	if err != nil || len(z.File) != 6 {
		return invalid("GROUP_TERRAFORM_SAVED_CONTAINER_INVALID")
	}
	allowed := map[string]bool{"tfplan": true, "tfstate": true, "tfstate-prev": true, "tfconfig/modules.json": true, "tfconfig/m-/main.tf.json": true, ".terraform.lock.hcl": true}
	entries := map[string][]byte{}
	total := 0
	for _, f := range z.File {
		if !allowed[f.Name] || entries[f.Name] != nil || f.FileInfo().Mode()&os.ModeType != 0 || f.UncompressedSize64 > fixtureArtifactLimit {
			return invalid("GROUP_TERRAFORM_SAVED_CONTAINER_INVALID")
		}
		r, e := f.Open()
		if e != nil {
			return invalid("GROUP_TERRAFORM_SAVED_CONTAINER_INVALID")
		}
		body, e := io.ReadAll(io.LimitReader(r, fixtureArtifactLimit+1))
		_ = r.Close()
		total += len(body)
		if e != nil || total > fixtureArtifactLimit || len(body) > fixtureArtifactLimit {
			return invalid("GROUP_TERRAFORM_SAVED_CONTAINER_BOUNDS")
		}
		entries[f.Name] = body
	}
	if len(entries["tfplan"]) == 0 || !bytes.Equal(entries["tfconfig/m-/main.tf.json"], capture.Configuration) {
		return invalid("GROUP_TERRAFORM_EMBEDDED_SOURCE_INVALID")
	}
	for _, name := range []string{"tfstate", "tfstate-prev"} {
		s, e := fixtureObject(entries[name], fixtureArtifactLimit)
		if e != nil {
			return e
		}
		if name == "tfstate-prev" && s["lineage"] == "" && s["serial"] == json.Number("0") {
			s["lineage"], s["serial"] = before["lineage"], before["serial"]
		}
		if !tfEqual(s, before) {
			return invalid("GROUP_TERRAFORM_EMBEDDED_STATE_INVALID")
		}
	}
	var modules []map[string]any
	unique := json.NewDecoder(bytes.NewReader(entries["tfconfig/modules.json"]))
	unique.UseNumber()
	if uniqueValue(unique, 0) != nil {
		return invalid("GROUP_TERRAFORM_EMBEDDED_MODULE_INVALID")
	}
	if _, e := unique.Token(); e != io.EOF {
		return invalid("GROUP_TERRAFORM_EMBEDDED_MODULE_INVALID")
	}
	d := json.NewDecoder(bytes.NewReader(entries["tfconfig/modules.json"]))
	d.UseNumber()
	if d.Decode(&modules) != nil || len(modules) != 1 || !tfKeys(modules[0], []string{"Key", "Dir"}, []string{"Source", "Version"}) || modules[0]["Key"] != "" || modules[0]["Dir"] != FixtureWorkingDirectory && modules[0]["Dir"] != "." {
		return invalid("GROUP_TERRAFORM_EMBEDDED_MODULE_INVALID")
	}
	// Terraform1.16's native root manifest omits empty Source/Version fields.
	// Presence remains typed: null or a nonempty source is not a root module.
	for _, key := range []string{"Source", "Version"} {
		if value, present := modules[0][key]; present && value != "" {
			return invalid("GROUP_TERRAFORM_EMBEDDED_MODULE_INVALID")
		}
	}
	if d.Decode(new(any)) != io.EOF {
		return invalid("GROUP_TERRAFORM_EMBEDDED_MODULE_INVALID")
	}
	emptyLock := []byte("# This file is maintained automatically by \"terraform init\".\n# Manual edits may be lost in future updates.")
	if !bytes.Equal(bytes.TrimSpace(entries[".terraform.lock.hcl"]), emptyLock) {
		return invalid("GROUP_TERRAFORM_EXTERNAL_PROVIDER_LOCK")
	}
	return nil
}

func modelValues(values any, inputs map[string]map[string]any, ids map[string]string, unknownOutput map[string]bool) error {
	v := tfObject(values)
	if !tfKeys(v, []string{"root_module"}, []string{"outputs"}) || !tfEmpty(v["outputs"]) {
		return invalid("GROUP_TERRAFORM_OUTPUTS_OR_MODULES_FORBIDDEN")
	}
	root := tfObject(v["root_module"])
	if !tfKeys(root, []string{"resources"}, nil) || len(tfArray(root["resources"])) != 3 {
		return invalid("GROUP_TERRAFORM_PLAN_RESOURCE_SET_INVALID")
	}
	seen := map[string]bool{}
	for _, entry := range tfArray(root["resources"]) {
		r := tfObject(entry)
		address := tfText(r["address"])
		input, ok := inputs[address]
		if !ok || seen[address] || !tfKeys(r, []string{"address", "mode", "type", "name", "provider_name", "schema_version", "values", "sensitive_values"}, nil) || r["mode"] != "managed" || r["type"] != "terraform_data" || r["name"] != strings.TrimPrefix(address, "terraform_data.") || r["provider_name"] != BuiltinProvider || r["schema_version"] != json.Number("0") || !noSensitive(r["sensitive_values"]) {
			return invalid("GROUP_TERRAFORM_PLAN_RESOURCE_SET_INVALID")
		}
		attributes := tfObject(r["values"])
		if !tfKeys(attributes, []string{"id", "input", "store", "triggers_replace"}, []string{"output"}) || attributes["id"] != ids[address] || !tfEqual(attributes["input"], input) || attributes["store"] != nil || attributes["triggers_replace"] != nil {
			return invalid("GROUP_TERRAFORM_PLAN_MODEL_INPUT_INVALID")
		}
		if unknownOutput[address] {
			if attributes["output"] != nil {
				return invalid("GROUP_TERRAFORM_COMPUTED_OUTPUT_INVALID")
			}
		} else if !tfEqual(attributes["output"], input) {
			return invalid("GROUP_TERRAFORM_COMPUTED_OUTPUT_INVALID")
		}
		seen[address] = true
	}
	return nil
}

func knownMask(v any) bool { return v == false || tfObject(v) != nil && len(tfObject(v)) == 0 }

func changeAttributes(v any, input map[string]any, id string, outputUnknown bool) bool {
	a := tfObject(v)
	if !tfKeys(a, []string{"id", "input", "store", "triggers_replace"}, []string{"output"}) || a["id"] != id || !tfEqual(a["input"], input) || a["store"] != nil || a["triggers_replace"] != nil {
		return false
	}
	if outputUnknown {
		return a["output"] == nil
	}
	return tfEqual(a["output"], input)
}

func reviewChanges(plan map[string]any, before, after map[string]map[string]any, ids map[string]string) ([]string, map[string]bool, error) {
	changes := tfArray(plan["resource_changes"])
	if len(changes) != 3 {
		return nil, nil, invalid("GROUP_TERRAFORM_CHANGE_SET_INVALID")
	}
	seen := map[string]bool{}
	unknownOutput := map[string]bool{}
	changed := []string{}
	for _, entry := range changes {
		r := tfObject(entry)
		address := tfText(r["address"])
		input, ok := before[address]
		if !ok || seen[address] || !tfKeys(r, []string{"address", "mode", "type", "name", "provider_name", "change"}, nil) || r["mode"] != "managed" || r["type"] != "terraform_data" || r["name"] != strings.TrimPrefix(address, "terraform_data.") || r["provider_name"] != BuiltinProvider {
			return nil, nil, invalid("GROUP_TERRAFORM_CHANGE_SET_INVALID")
		}
		ch := tfObject(r["change"])
		if !tfKeys(ch, []string{"actions", "before", "after", "after_unknown", "before_sensitive", "after_sensitive"}, nil) || !noSensitive(ch["before_sensitive"]) || !noSensitive(ch["after_sensitive"]) {
			return nil, nil, invalid("GROUP_TERRAFORM_SENSITIVE_OR_UNREVIEWED_CHANGE")
		}
		update := !tfEqual(input, after[address])
		action := "no-op"
		if update {
			action = "update"
			changed = append(changed, address)
			unknownOutput[address] = true
		}
		if !tfEqual(ch["actions"], []string{action}) || !changeAttributes(ch["before"], input, ids[address], false) || !changeAttributes(ch["after"], after[address], ids[address], update) {
			return nil, nil, invalid("GROUP_TERRAFORM_CHANGE_NOT_EXACT_MODEL_EFFECT")
		}
		mask := tfObject(ch["after_unknown"])
		if !tfKeys(mask, nil, []string{"id", "input", "output", "store", "triggers_replace"}) {
			return nil, nil, invalid("GROUP_TERRAFORM_UNKNOWN_ACTIONABLE_VALUE")
		}
		for key, value := range mask {
			if key == "output" && update {
				if value != true {
					return nil, nil, invalid("GROUP_TERRAFORM_COMPUTED_OUTPUT_INVALID")
				}
				continue
			}
			if !knownMask(value) {
				return nil, nil, invalid("GROUP_TERRAFORM_UNKNOWN_ACTIONABLE_VALUE")
			}
		}
		if update && mask["output"] != true {
			return nil, nil, invalid("GROUP_TERRAFORM_COMPUTED_OUTPUT_INVALID")
		}
		seen[address] = true
	}
	sort.Strings(changed)
	return changed, unknownOutput, nil
}

func reviewPlanConfiguration(plan map[string]any, p Program, source map[string]any) error {
	config := tfObject(plan["configuration"])
	if !tfKeys(config, []string{"provider_config", "root_module"}, nil) {
		return invalid("GROUP_TERRAFORM_CONFIGURATION_UNSUPPORTED")
	}
	providers := tfObject(config["provider_config"])
	if len(providers) != 1 {
		return invalid("GROUP_TERRAFORM_EXTERNAL_PROVIDER_FORBIDDEN")
	}
	for key, raw := range providers {
		provider := tfObject(raw)
		if key != "terraform" || !tfKeys(provider, []string{"name", "full_name"}, nil) || provider["name"] != "terraform" || provider["full_name"] != BuiltinProvider {
			return invalid("GROUP_TERRAFORM_EXTERNAL_PROVIDER_FORBIDDEN")
		}
	}
	root := tfObject(config["root_module"])
	if !tfKeys(root, []string{"resources", "variables"}, nil) {
		return invalid("GROUP_TERRAFORM_OUTPUTS_OR_MODULES_FORBIDDEN")
	}
	variables := tfObject(root["variables"])
	if !tfKeys(variables, []string{"old_count", "candidate_count", "candidate_traffic_percent"}, nil) {
		return invalid("GROUP_TERRAFORM_VARIABLES_INVALID")
	}
	for _, raw := range variables {
		if !tfKeys(tfObject(raw), nil, nil) {
			return invalid("GROUP_TERRAFORM_VARIABLES_INVALID")
		}
	}
	resources := tfArray(root["resources"])
	if len(resources) != 3 {
		return invalid("GROUP_TERRAFORM_CONFIGURATION_UNSUPPORTED")
	}
	seen := map[string]bool{}
	sourceResources := tfObject(tfObject(source["resource"])["terraform_data"])
	for _, raw := range resources {
		r := tfObject(raw)
		address := tfText(r["address"])
		name := strings.TrimPrefix(address, "terraform_data.")
		expected := tfObject(sourceResources[name])
		if expected == nil || seen[address] || !tfKeys(r, []string{"address", "mode", "type", "name", "provider_config_key", "expressions", "schema_version"}, nil) || address != "terraform_data."+name || r["mode"] != "managed" || r["type"] != "terraform_data" || r["name"] != name || r["provider_config_key"] != "terraform" || r["schema_version"] != json.Number("0") {
			return invalid("GROUP_TERRAFORM_CONFIGURATION_UNSUPPORTED")
		}
		expressions := tfObject(r["expressions"])
		expression := tfObject(expressions["input"])
		variable := "var.old_count"
		if address == p.ArtifactContext.Mapping.CandidateModel {
			variable = "var.candidate_count"
		}
		if address == p.ArtifactContext.Mapping.TrafficModel {
			variable = "var.candidate_traffic_percent"
		}
		if !tfKeys(expressions, []string{"input"}, nil) || !tfKeys(expression, []string{"constant_value", "references"}, nil) || !tfEqual(expression["constant_value"], expected["input"]) || !tfEqual(expression["references"], []string{variable}) {
			return invalid("GROUP_TERRAFORM_EXTERNAL_EXPRESSION_FORBIDDEN")
		}
		seen[address] = true
	}
	return nil
}

// ValidateTerraformArtifact performs strict, version-specific semantic review
// of a REAL independently captured built-in-provider artifact. It also verifies
// the existing independent exact byte hashes. This function does not execute a
// CLI, verify Git or machine identities, issue a receipt, sign or dispatch.
func ValidateTerraformArtifact(p Program, c Child, capture TerraformArtifactCapture, now time.Time) (ArtifactReview, error) {
	var out ArtifactReview
	if capture.Context != p.ArtifactContext || capture.Context.Kind != BuiltinFixtureArtifact || capture.Context.ProviderSource != BuiltinProvider {
		return out, invalid("GROUP_TERRAFORM_CAPTURE_CONTEXT_MISMATCH")
	}
	if c.Mode == Forward {
		if capture.Recovery != nil {
			return out, invalid("GROUP_TERRAFORM_RECOVERY_CONTEXT_INVALID")
		}
		if err := ValidateChild(c, p, now); err != nil {
			return out, err
		}
	} else if c.Mode == OwnedRecovery && capture.Recovery != nil {
		if err := ValidateRecovery(c, capture.Recovery.Original, p, capture.Recovery.Owned, now); err != nil {
			return out, err
		}
	} else {
		return out, invalid("GROUP_TERRAFORM_RECOVERY_CONTEXT_INVALID")
	}
	if len(capture.Configuration)+len(capture.SavedPlan)+len(capture.PlanJSON)+len(capture.BeforeState)+len(capture.GitCommitObject)+len(capture.GitTreeObject) > fixtureArtifactLimit {
		return out, invalid("GROUP_TERRAFORM_CAPTURE_BOUNDS")
	}
	if err := VerifyArtifactBytes(c.Artifact, capture.SavedPlan, capture.PlanJSON, capture.BeforeState); err != nil {
		return out, err
	}
	if err := validateFixtureGit(capture); err != nil {
		return out, err
	}
	expectedSource, err := FixtureConfiguration(p)
	if err != nil {
		return out, err
	}
	source, err := fixtureObject(capture.Configuration, 256<<10)
	if err != nil {
		return out, err
	}
	expected, _ := fixtureObject(expectedSource, 256<<10)
	if BytesDigest(capture.Configuration) != p.ArtifactContext.ConfigurationSHA256 || !tfEqual(source, expected) {
		return out, invalid("GROUP_TERRAFORM_COMMITTED_CONFIGURATION_MISMATCH")
	}
	beforeInputs, err := FixtureInputs(p, c.Artifact.Before)
	if err != nil {
		return out, err
	}
	afterInputs, err := FixtureInputs(p, c.Artifact.After)
	if err != nil {
		return out, err
	}
	before, ids, err := rawFixtureState(capture.BeforeState, p, c, beforeInputs)
	if err != nil {
		return out, err
	}
	if err = validateFixtureContainer(capture, before); err != nil {
		return out, err
	}
	plan, err := fixtureObject(capture.PlanJSON, fixtureArtifactLimit)
	if err != nil {
		return out, err
	}
	if !tfKeys(plan, []string{"format_version", "terraform_version", "variables", "planned_values", "resource_changes", "prior_state", "configuration", "timestamp", "applyable", "complete", "errored"}, []string{"resource_drift", "output_changes", "relevant_attributes", "checks"}) || plan["format_version"] != "1.2" || plan["terraform_version"] != FixtureTerraformVersion || plan["complete"] != true || plan["errored"] != false || !tfEmpty(plan["resource_drift"]) || !tfEmpty(plan["output_changes"]) || !tfEmpty(plan["relevant_attributes"]) || !tfEmpty(plan["checks"]) {
		return out, invalid("GROUP_TERRAFORM_PLAN_FORMAT_OR_DRIFT_INVALID")
	}
	stamp, e := time.Parse(time.RFC3339Nano, tfText(plan["timestamp"]))
	if e != nil || !canonicalTime(stamp) || stamp.Before(p.CreatedAt.Truncate(time.Second)) || stamp.After(c.CreatedAt.Add(5*time.Second)) || stamp.After(now.Add(5*time.Second)) || now.Sub(stamp) > 5*time.Minute {
		return out, invalid("GROUP_TERRAFORM_PLAN_TIMESTAMP_INVALID")
	}
	variables := tfObject(plan["variables"])
	wanted := map[string]int{"old_count": c.Artifact.After.OldCount, "candidate_count": c.Artifact.After.CandidateCount, "candidate_traffic_percent": c.Artifact.After.CandidateTrafficPercent}
	if len(variables) != 3 {
		return out, invalid("GROUP_TERRAFORM_VARIABLES_INVALID")
	}
	for name, count := range wanted {
		value := tfObject(variables[name])
		n, ok := tfUint(value["value"])
		if !tfKeys(value, []string{"value"}, nil) || !ok || n != uint64(count) {
			return out, invalid("GROUP_TERRAFORM_VARIABLES_INVALID")
		}
	}
	if err = reviewPlanConfiguration(plan, p, source); err != nil {
		return out, err
	}
	prior := tfObject(plan["prior_state"])
	if !tfKeys(prior, []string{"format_version", "terraform_version", "values"}, nil) || prior["format_version"] != "1.0" || prior["terraform_version"] != FixtureTerraformVersion {
		return out, invalid("GROUP_TERRAFORM_PRIOR_STATE_INVALID")
	}
	if err = modelValues(prior["values"], beforeInputs, ids, nil); err != nil {
		return out, err
	}
	changed, unknown, err := reviewChanges(plan, beforeInputs, afterInputs, ids)
	if err != nil {
		return out, err
	}
	if plan["applyable"] != (len(changed) > 0) {
		return out, invalid("GROUP_TERRAFORM_APPLYABILITY_MISMATCH")
	}
	if err = modelValues(plan["planned_values"], afterInputs, ids, unknown); err != nil {
		return out, err
	}
	out = ArtifactReview{Status: "FIXTURE_SEMANTICS_MATCHED", Kind: BuiltinFixtureArtifact, ProgramSHA256: Digest(p), ChildSHA256: Digest(c), BindingSHA256: Digest(p.Binding), RealmSHA256: Digest(p.Realm), ArtifactSHA256: Digest(c.Artifact), ConfigurationSHA256: p.ArtifactContext.ConfigurationSHA256, SavedPlanSHA256: c.Artifact.SavedPlanSHA256, PlanJSONSHA256: c.Artifact.PlanJSONSHA256, BeforeStateSHA256: c.Artifact.BeforeStateSHA256, StateLineage: p.ArtifactContext.StateLineage, BeforeStateSerial: c.Artifact.BeforeStateSerial, ChangedAddresses: changed, NoOp: len(changed) == 0}
	return out, nil
}
