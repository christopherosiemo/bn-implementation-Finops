package fleet

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

type PlanReview struct {
	Changes         int      `json:"changes"`
	Addresses       []string `json:"addresses"`
	NoOp            bool     `json:"no_op"`
	SavedPlanSHA256 string   `json:"saved_plan_sha256"`
	PlanJSONSHA256  string   `json:"plan_json_sha256"`
}

func object(v any) map[string]any { m, _ := v.(map[string]any); return m }
func array(v any) []any           { a, _ := v.([]any); return a }
func text(v any) string           { s, _ := v.(string); return s }
func integer(v any) (int, error) {
	switch x := v.(type) {
	case json.Number:
		n, e := strconv.Atoi(string(x))
		return n, e
	case string:
		n, e := strconv.Atoi(x)
		return n, e
	}
	return 0, invalid("FLEET_CONCRETE_INTEGER_REQUIRED")
}
func sameJSON(a, b any) bool {
	aa, e := json.Marshal(a)
	bb, f := json.Marshal(b)
	return e == nil && f == nil && bytes.Equal(aa, bb)
}
func jsonValue(raw json.RawMessage) (any, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var v any
	e := d.Decode(&v)
	return v, e
}
func pointerToken(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "~", "~0"), "/", "~1")
}
func leaves(v any, path string, out map[string]any) {
	switch x := v.(type) {
	case map[string]any:
		if len(x) == 0 {
			out[path] = x
		}
		for k, val := range x {
			leaves(val, path+"/"+pointerToken(k), out)
		}
	case []any:
		if len(x) == 0 {
			out[path] = x
		}
		for i, val := range x {
			leaves(val, fmt.Sprintf("%s/%d", path, i), out)
		}
	default:
		out[path] = v
	}
}
func under(path string, parents []string) bool {
	for _, p := range parents {
		if path == p || strings.HasPrefix(path, p+"/") {
			return true
		}
	}
	return false
}
func resourceValues(module map[string]any, out map[string]map[string]any) {
	for _, raw := range array(module["resources"]) {
		r := object(raw)
		out[text(r["address"])] = r
	}
	for _, raw := range array(module["child_modules"]) {
		resourceValues(object(raw), out)
	}
}
func expressionMatches(v any, variable string, constant any) bool {
	m := object(v)
	for _, ref := range array(m["references"]) {
		if ref == "var."+variable {
			return true
		}
	}
	return sameJSON(m["constant_value"], constant)
}

// ValidateTerraformPlan compares an exact saved binary and its trusted-pipeline
// JSON rendering to a signed child manifest. The separately supplied provenance
// must come from that customer pipeline (state pull/workspace/Git checkout).
// Terraform show JSON alone does not attest state lineage/serial or derivation
// from a binary. This function never invokes Terraform or applies anything.
func ValidateTerraformPlan(raw, binary []byte, c ChildPlan, p FleetPlanV4, provenance IaCBinding, now time.Time) (PlanReview, error) {
	if e := ValidateChild(c, p, now); e != nil {
		return PlanReview{}, e
	}
	return validateTerraformPlan(raw, binary, c, p, provenance, now)
}
func validateTerraformPlan(raw, binary []byte, c ChildPlan, p FleetPlanV4, provenance IaCBinding, now time.Time) (PlanReview, error) {
	out := PlanReview{Addresses: []string{}, SavedPlanSHA256: BytesDigest(binary), PlanJSONSHA256: BytesDigest(raw)}
	if len(binary) == 0 || len(raw) == 0 || len(raw) > 64<<20 || out.SavedPlanSHA256 != c.SavedPlanSHA256 || out.PlanJSONSHA256 != c.PlanJSONSHA256 {
		return out, invalid("FLEET_SAVED_PLAN_DIGEST_MISMATCH")
	}
	if provenance != c.IaC {
		return out, invalid("FLEET_PIPELINE_PROVENANCE_MISMATCH")
	}
	var plan map[string]any
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if e := d.Decode(&plan); e != nil {
		return out, invalid("FLEET_TERRAFORM_JSON_INVALID")
	}
	if !strings.HasPrefix(text(plan["format_version"]), "1.") || text(plan["terraform_version"]) != c.IaC.TerraformVersion || plan["complete"] != true || plan["errored"] == true || len(array(plan["deferred_changes"])) != 0 {
		return out, invalid("FLEET_TERRAFORM_PLAN_INCOMPLETE")
	}
	vars := object(plan["variables"])
	if object(vars["expected_account_id"])["value"] != p.Binding.AccountID || object(vars["region"])["value"] != p.Binding.Region {
		return out, invalid("FLEET_TERRAFORM_TARGET_MISMATCH")
	}
	providers := object(object(plan["configuration"])["provider_config"])
	awsProviders := 0
	for _, rawProvider := range providers {
		provider := object(rawProvider)
		if text(provider["full_name"]) != "registry.terraform.io/hashicorp/aws" && provider["name"] != "aws" {
			continue
		}
		awsProviders++
		expressions := object(provider["expressions"])
		if !expressionMatches(expressions["region"], "region", p.Binding.Region) || !expressionMatches(expressions["allowed_account_ids"], "expected_account_id", []string{p.Binding.AccountID}) {
			return out, invalid("FLEET_PROVIDER_TARGET_GUARD_REQUIRED")
		}
	}
	if awsProviders == 0 {
		return out, invalid("FLEET_AWS_PROVIDER_REQUIRED")
	}
	values := map[string]map[string]any{}
	resourceValues(object(object(plan["planned_values"])["root_module"]), values)
	caller := false
	for _, r := range values {
		kind := text(r["type"])
		v := object(r["values"])
		if kind == "aws_caller_identity" {
			if v["account_id"] != p.Binding.AccountID {
				return out, invalid("FLEET_CALLER_ACCOUNT_MISMATCH")
			}
			caller = true
		}
		if kind == "aws_autoscaling_policy" || kind == "aws_autoscaling_schedule" || kind == "aws_appautoscaling_target" || kind == "aws_appautoscaling_policy" {
			return out, invalid("FLEET_INDEPENDENT_AUTOSCALING_COLLISION")
		}
		if arn := text(v["arn"]); strings.HasPrefix(arn, "arn:aws:") {
			parts := strings.SplitN(arn, ":", 6)
			if len(parts) != 6 || parts[4] != "" && parts[4] != p.Binding.AccountID || parts[3] != "" && parts[3] != p.Binding.Region {
				return out, invalid("FLEET_RESOURCE_TARGET_MISMATCH")
			}
		}
	}
	if !caller {
		return out, invalid("FLEET_CONCRETE_CALLER_IDENTITY_REQUIRED")
	}
	for _, rawDrift := range array(plan["resource_drift"]) {
		actions := array(object(object(rawDrift)["change"])["actions"])
		if len(actions) != 1 || actions[0] != "no-op" {
			return out, invalid("FLEET_UNREVIEWED_DRIFT")
		}
	}
	manifests := map[string]AllowedChange{}
	for _, a := range c.Changes {
		manifests[a.Address] = a
	}
	changes, ok := plan["resource_changes"].([]any)
	if !ok {
		return out, invalid("FLEET_RESOURCE_CHANGES_REQUIRED")
	}
	seen := map[string]bool{}
	priorValues := map[string]map[string]any{}
	for _, rawChange := range changes {
		r := object(rawChange)
		address := text(r["address"])
		change := object(r["change"])
		actions := array(change["actions"])
		if address == p.Traffic.Address && r["mode"] == "managed" && text(r["type"]) == "aws_lb_listener_rule" {
			for _, side := range []string{"before", "after"} {
				if e := canonicalTrafficTargets(change[side], p); e != nil {
					return out, e
				}
			}
		}
		if r["mode"] == "managed" && object(change["before"]) != nil {
			priorValues[address] = map[string]any{"type": r["type"], "values": change["before"]}
		}
		if address == "" || seen[address] || len(actions) != 1 || r["deposed"] != nil || r["previous_address"] != nil || change["importing"] != nil || len(array(change["replace_paths"])) != 0 {
			return out, invalid("FLEET_MOVE_IMPORT_REPLACEMENT_FORBIDDEN")
		}
		seen[address] = true
		action := text(actions[0])
		if action == "read" && r["mode"] == "data" {
			continue
		}
		if action == "no-op" {
			continue
		}
		// Runtime stages update pre-provisioned explicit cohorts. Provisioning, IAM,
		// deletion and replacement are outside this workload-plan protocol entirely.
		a, exists := manifests[address]
		if !exists || a.Action != action || action != "update" || a.Type != text(r["type"]) || r["mode"] != "managed" || text(r["provider_name"]) != "registry.terraform.io/hashicorp/aws" {
			return out, fmt.Errorf("FLEET_UNRELATED_OR_DESTRUCTIVE_CHANGE:%s", address)
		}
		if e := validateExactFields(a, change); e != nil {
			return out, e
		}
		out.Changes++
		out.Addresses = append(out.Addresses, address)
		delete(manifests, address)
	}
	for _, a := range manifests {
		if a.Action != "no-op" {
			return out, invalid("FLEET_EXPECTED_CHANGE_MISSING")
		}
	}
	if e := validateCohortValues(values, p, c.Transition); e != nil {
		return out, e
	}
	prior := Transition{OldAfter: c.Transition.OldBefore, CandidateAfter: c.Transition.CandidateBefore, TrafficAfter: c.Transition.TrafficBefore}
	if e := validateCohortValues(priorValues, p, prior); e != nil {
		return out, e
	}
	template := object(values[p.Candidate.LaunchTemplateAddress]["values"])
	version, versionError := integer(template["latest_version"])
	if template["instance_type"] != p.Candidate.InstanceType || versionError != nil || version < 1 || uint64(version) != p.Candidate.LaunchTemplateVersion {
		return out, invalid("FLEET_CANDIDATE_TYPE_NOT_PINNED")
	}
	sort.Strings(out.Addresses)
	out.NoOp = out.Changes == 0
	return out, nil
}

// The provider represents forward.target_group as a TypeSet whose element hash
// includes weight. A legitimate weight change can reorder it. Signed field
// paths use stable cohort order (old=0, candidate=1); normalize only these two
// exact approved ARNs before leaf comparison. The raw plan digest is untouched.
func canonicalTrafficTargets(value any, p FleetPlanV4) error {
	actions := array(object(value)["action"])
	if len(actions) != 1 || object(actions[0])["type"] != "forward" {
		return invalid("FLEET_TRAFFIC_NOT_EXPLICIT_FORWARD")
	}
	forward := array(object(actions[0])["forward"])
	if len(forward) != 1 {
		return invalid("FLEET_TRAFFIC_NOT_EXPLICIT_FORWARD")
	}
	groups := array(object(forward[0])["target_group"])
	if len(groups) != 2 {
		return invalid("FLEET_TRAFFIC_TARGET_UNKNOWN")
	}
	indexed := map[string]any{}
	for _, g := range groups {
		arn := text(object(g)["arn"])
		if arn != p.Traffic.OldTargetGroupARN && arn != p.Traffic.CandidateTargetGroupARN {
			return invalid("FLEET_TRAFFIC_TARGET_UNKNOWN")
		}
		if indexed[arn] != nil {
			return invalid("FLEET_TRAFFIC_DUPLICATE_TARGET")
		}
		indexed[arn] = g
	}
	groups[0], groups[1] = indexed[p.Traffic.OldTargetGroupARN], indexed[p.Traffic.CandidateTargetGroupARN]
	return nil
}

func validateExactFields(a AllowedChange, change map[string]any) error {
	before, after, unknown := map[string]any{}, map[string]any{}, map[string]any{}
	leaves(change["before"], "", before)
	leaves(change["after"], "", after)
	leaves(change["after_unknown"], "", unknown)
	for path, value := range unknown {
		if value == true && !under(path, a.ComputedPaths) {
			return fmt.Errorf("FLEET_UNKNOWN_ACTIONABLE_VALUE:%s:%s", a.Address, path)
		}
	}
	declared := map[string]FieldChange{}
	for _, f := range a.Fields {
		declared[f.Path] = f
	}
	paths := map[string]bool{}
	for path := range before {
		paths[path] = true
	}
	for path := range after {
		paths[path] = true
	}
	for path := range paths {
		if under(path, a.ComputedPaths) || sameJSON(before[path], after[path]) {
			continue
		}
		f, ok := declared[path]
		if !ok {
			return fmt.Errorf("FLEET_UNDECLARED_FIELD_CHANGE:%s:%s", a.Address, path)
		}
		b, e := jsonValue(f.Before)
		if e != nil {
			return e
		}
		v, e := jsonValue(f.After)
		if e != nil {
			return e
		}
		if !sameJSON(b, before[path]) || !sameJSON(v, after[path]) {
			return invalid("FLEET_EXACT_FIELD_VALUE_MISMATCH")
		}
		delete(declared, path)
	}
	if len(declared) != 0 {
		return invalid("FLEET_DECLARED_FIELD_NOT_CHANGED")
	}
	return nil
}
func validateCohortValues(values map[string]map[string]any, p FleetPlanV4, t Transition) error {
	for i, c := range []Cohort{p.Old, p.Candidate} {
		r, ok := values[c.ASGAddress]
		if !ok || r["type"] != "aws_autoscaling_group" {
			return invalid("FLEET_COHORT_STATE_UNKNOWN")
		}
		v := object(r["values"])
		if v["name"] != c.ID {
			return invalid("FLEET_ASG_PHYSICAL_NAME_MISMATCH")
		}
		desired, e := integer(v["desired_capacity"])
		if e != nil {
			return e
		}
		want := t.OldAfter
		if i == 1 {
			want = t.CandidateAfter
		}
		minimum, e := integer(v["min_size"])
		if e != nil {
			return e
		}
		maximum, e := integer(v["max_size"])
		if e != nil {
			return e
		}
		if desired != want || minimum != desired || maximum != desired || len(array(v["instance_refresh"])) != 0 || len(array(v["mixed_instances_policy"])) != 0 || v["capacity_rebalance"] == true {
			return invalid("FLEET_ASG_CONTROLLER_COLLISION")
		}
		suspended := []string{}
		for _, s := range array(v["suspended_processes"]) {
			suspended = append(suspended, text(s))
		}
		for _, process := range []string{"ReplaceUnhealthy", "AZRebalance", "InstanceRefresh", "ScheduledActions", "AlarmNotification"} {
			if !contains(suspended, process) {
				return invalid("FLEET_NATIVE_AUTONOMOUS_REPLACEMENT_NOT_SUSPENDED")
			}
		}
		templates := array(v["launch_template"])
		if len(templates) != 1 {
			return invalid("FLEET_LAUNCH_TEMPLATE_PIN_REQUIRED")
		}
		version, e := integer(object(templates[0])["version"])
		if e != nil || version < 1 || uint64(version) != c.LaunchTemplateVersion || text(object(templates[0])["id"]) == "" {
			return invalid("FLEET_LAUNCH_TEMPLATE_PIN_REQUIRED")
		}
	}
	r, ok := values[p.Traffic.Address]
	if !ok || r["type"] != "aws_lb_listener_rule" {
		return invalid("FLEET_TRAFFIC_STATE_UNKNOWN")
	}
	actions := array(object(r["values"])["action"])
	if len(actions) != 1 || object(actions[0])["type"] != "forward" {
		return invalid("FLEET_TRAFFIC_NOT_EXPLICIT_FORWARD")
	}
	forward := array(object(actions[0])["forward"])
	if len(forward) != 1 {
		return invalid("FLEET_TRAFFIC_NOT_EXPLICIT_FORWARD")
	}
	groups := array(object(forward[0])["target_group"])
	if len(groups) != 2 {
		return invalid("FLEET_TRAFFIC_TARGET_UNKNOWN")
	}
	weights := map[string]int{}
	for _, raw := range groups {
		g := object(raw)
		n, e := integer(g["weight"])
		if e != nil || n < 0 || n > 100 {
			return invalid("FLEET_TRAFFIC_WEIGHT_INVALID")
		}
		arn := text(g["arn"])
		if _, exists := weights[arn]; exists {
			return invalid("FLEET_TRAFFIC_DUPLICATE_TARGET")
		}
		weights[arn] = n
	}
	_, candidateKnown := weights[p.Traffic.CandidateTargetGroupARN]
	_, oldKnown := weights[p.Traffic.OldTargetGroupARN]
	if len(weights) != 2 || !candidateKnown || !oldKnown || weights[p.Traffic.CandidateTargetGroupARN] != t.TrafficAfter || weights[p.Traffic.OldTargetGroupARN] != 100-t.TrafficAfter {
		return invalid("FLEET_TRAFFIC_TRANSITION_MISMATCH")
	}
	return nil
}

// CanonicalJSON is exposed for customer-pipeline fixtures and exact field
// manifests. It preserves JSON numbers, rather than routing money through float.
func CanonicalJSON(v any) json.RawMessage { b, _ := json.Marshal(v); return b }
