package configuration

import (
	"encoding/json"
	"strings"
	"testing"
)

// Synthetic Terraform bytes only: this exercises analytical identity binding,
// never a real provider read, apply, or historical ownership claim.
func artifactDecisionTestBundle(t *testing.T) (ArtifactRegistration, ArtifactBundle) {
	t.Helper()
	reg := artifactTestRegistration()
	reg.Binding.ProviderResourceID = "i-0123456789abcdef0"
	bundle := artifactTestBundle(reg)
	attributes := map[string]any{"id": reg.Binding.ProviderResourceID, "arn": "arn:aws:ec2:eu-west-1:111122223333:instance/" + reg.Binding.ProviderResourceID, "instance_type": "m6i.large"}
	resource := map[string]any{"address": "aws_instance.api", "mode": "managed", "type": "aws_instance", "name": "api", "provider_name": "registry.terraform.io/hashicorp/aws", "values": attributes}
	values := map[string]any{"root_module": map[string]any{"resources": []any{resource}}}
	encode := func(value any) []byte {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	body := []byte(`resource "aws_instance" "api" { ami = "ami-0123456789abcdef0" instance_type = "m6i.large" }`)
	bundle.Files = []ArtifactFile{{Path: "main.tf", Mode: "100644", SHA256: artifactBytesHash(body), Body: body}}
	bundle.StateRaw = encode(map[string]any{"version": 4, "terraform_version": reg.Toolchain.TerraformVersion, "lineage": bundle.State.Lineage, "serial": bundle.State.Serial, "resources": []any{map[string]any{"mode": "managed", "type": "aws_instance", "name": "api", "provider": `provider["registry.terraform.io/hashicorp/aws"]`, "instances": []any{map[string]any{"schema_version": 1, "attributes": attributes}}}}})
	bundle.StateJSON = encode(map[string]any{"format_version": "1.0", "terraform_version": reg.Toolchain.TerraformVersion, "values": values})
	bundle.PlanJSON = encode(map[string]any{"format_version": "1.2", "terraform_version": reg.Toolchain.TerraformVersion, "prior_state": map[string]any{"values": values}, "planned_values": values, "resource_changes": []any{map[string]any{"address": "aws_instance.api", "mode": "managed", "type": "aws_instance", "name": "api", "provider_name": "registry.terraform.io/hashicorp/aws", "change": map[string]any{"actions": []string{"no-op"}, "before": attributes, "after": attributes}}}, "configuration": map[string]any{"provider_config": map[string]any{"aws": map[string]any{"full_name": "registry.terraform.io/hashicorp/aws"}}}})
	bundle.VersionJSON = encode(map[string]any{"terraform_version": reg.Toolchain.TerraformVersion, "platform": "linux_amd64", "provider_selections": map[string]any{"registry.terraform.io/hashicorp/aws": "6.0.0"}})
	artifactDecisionReseal(&bundle)
	return reg, bundle
}

func artifactDecisionReseal(bundle *ArtifactBundle) {
	for index := range bundle.Files {
		bundle.Files[index].SHA256 = artifactBytesHash(bundle.Files[index].Body)
	}
	artifactTestPlanZip(bundle)
	bundle.Git.ConfigurationSHA256 = artifactFilesDigest(bundle.Files)
	bundle.Git.DependencySHA256 = artifactDependencyDigest(*bundle)
}

func artifactDecisionRewriteAttributes(t *testing.T, raw []byte, key, value string, remove bool) []byte {
	t.Helper()
	document, err := artifactDecode(raw)
	if err != nil {
		t.Fatal(err)
	}
	var visit func(any)
	visit = func(valueAny any) {
		switch node := valueAny.(type) {
		case map[string]any:
			if _, ok := node["id"]; ok {
				if _, ok = node[key]; ok {
					if remove {
						delete(node, key)
					} else {
						node[key] = value
					}
				}
			}
			for _, child := range node {
				visit(child)
			}
		case []any:
			for _, child := range node {
				visit(child)
			}
		}
	}
	visit(document)
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestArtifactDecisionBoundResourceRetainsExternalProviderBlock(t *testing.T) {
	reg, bundle := artifactDecisionTestBundle(t)
	metadata, err := ValidateArtifactBundle(reg, bundle)
	if err != nil || metadata.Status != "BLOCKED" || !artifactHasReason(metadata, "CONFIGURATION_EXTERNAL_PROVIDER_UNSUPPORTED") {
		t.Fatal("provider-shaped bundle must retain execution blocker", err)
	}
	before, _ := json.Marshal(metadata)
	binding, err := artifactDecisionBinding(reg, bundle, metadata)
	if err != nil || binding == nil || binding.TerraformAddress != "aws_instance.api" || binding.ResourceARN != "arn:aws:ec2:eu-west-1:111122223333:instance/"+reg.Binding.ProviderResourceID || binding.InstanceType != "m6i.large" || binding.Binding != reg.Binding {
		t.Fatal("exact current resource did not bind", err)
	}
	after, _ := json.Marshal(metadata)
	if string(before) != string(after) || metadata.ExecutionAuthorized || metadata.VerifiedSaving != nil {
		t.Fatal("analytical projection changed legacy authority/metadata")
	}
}

func TestArtifactDecisionBindingRejectsAuthenticButUnrelatedCurrentResource(t *testing.T) {
	for _, test := range []struct {
		name, key, value string
		remove           bool
	}{
		{"other-native-id", "id", "i-0fedcba9876543210", false},
		{"foreign-account", "arn", "arn:aws:ec2:eu-west-1:999988887777:instance/i-0123456789abcdef0", false},
		{"foreign-region", "arn", "arn:aws:ec2:us-east-1:111122223333:instance/i-0123456789abcdef0", false},
		{"missing-arn", "arn", "", true},
		{"missing-current-type", "instance_type", "", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			reg, bundle := artifactDecisionTestBundle(t)
			bundle.StateRaw = artifactDecisionRewriteAttributes(t, bundle.StateRaw, test.key, test.value, test.remove)
			bundle.StateJSON = artifactDecisionRewriteAttributes(t, bundle.StateJSON, test.key, test.value, test.remove)
			bundle.PlanJSON = artifactDecisionRewriteAttributes(t, bundle.PlanJSON, test.key, test.value, test.remove)
			artifactDecisionReseal(&bundle)
			// All view hashes and native saved-state bytes are legitimately reissued;
			// ordinary artifact capture still accepts these non-executable facts.
			metadata, err := ValidateArtifactBundle(reg, bundle)
			if err != nil {
				t.Fatal("control must pass existing capture", err)
			}
			if _, err = artifactDecisionBinding(reg, bundle, metadata); err == nil {
				t.Fatal("unrelated native identity acquired a decision baseline")
			}
		})
	}
}

func TestArtifactDecisionBindingRejectsMissingAddressAndCurrentClosure(t *testing.T) {
	for _, name := range []string{"missing-address", "external-input", "uncaptured-module"} {
		t.Run(name, func(t *testing.T) {
			reg, bundle := artifactDecisionTestBundle(t)
			switch name {
			case "missing-address":
				reg.Declaration.Terraform.Addresses = []string{"aws_instance.absent"}
			case "external-input":
				bundle.Files[0].Body = []byte(`resource "aws_instance" "api" { user_data = file("/untracked") }`)
			case "uncaptured-module":
				bundle.ModuleManifest = []byte(`{"Modules":[{"Key":"","Source":"","Dir":"absent"}]}`)
			}
			artifactDecisionReseal(&bundle)
			metadata, err := ValidateArtifactBundle(reg, bundle)
			if err != nil {
				t.Fatal("existing capture control failed", err)
			}
			if _, err = artifactDecisionBinding(reg, bundle, metadata); err == nil {
				t.Fatal("missing current closure acquired a decision baseline")
			}
		})
	}
}

func TestArtifactDecisionBindingRejectsRawStateAndPlanIdentityDrift(t *testing.T) {
	for _, name := range []string{"raw-state-id", "raw-state-type", "prior-state", "after-state-type", "duplicate-change"} {
		t.Run(name, func(t *testing.T) {
			reg, bundle := artifactDecisionTestBundle(t)
			switch name {
			case "raw-state-id":
				bundle.StateRaw = artifactDecisionRewriteAttributes(t, bundle.StateRaw, "id", "i-0fedcba9876543210", false)
			case "raw-state-type":
				bundle.StateRaw = artifactDecisionRewriteAttributes(t, bundle.StateRaw, "instance_type", "m6i.xlarge", false)
			case "prior-state", "after-state-type", "duplicate-change":
				plan, _ := artifactDecode(bundle.PlanJSON)
				changes := artifactArray(plan["resource_changes"])
				if name == "prior-state" {
					prior := artifactObject(plan["prior_state"])
					raw, _ := json.Marshal(prior)
					changed := artifactDecisionRewriteAttributes(t, raw, "id", "i-0fedcba9876543210", false)
					priorChanged, _ := artifactDecode(changed)
					plan["prior_state"] = priorChanged
				}
				if name == "after-state-type" {
					artifactObject(artifactObject(artifactObject(changes[0])["change"])["after"])["instance_type"] = "m6i.xlarge"
				}
				if name == "duplicate-change" {
					plan["resource_changes"] = append(changes, changes[0])
				}
				bundle.PlanJSON, _ = json.Marshal(plan)
			}
			artifactDecisionReseal(&bundle)
			metadata, err := ValidateArtifactBundle(reg, bundle)
			if name == "prior-state" {
				if err == nil {
					t.Fatal("existing prior-state guard regressed")
				}
				return
			}
			if err != nil {
				t.Fatal("existing artifact control failed", err)
			}
			if _, err = artifactDecisionBinding(reg, bundle, metadata); err == nil {
				t.Fatal("state/plan native drift acquired decision baseline")
			}
		})
	}
	reg := artifactTestRegistration()
	bundle := artifactTestBundle(reg)
	metadata, err := ValidateArtifactBundle(reg, bundle)
	if err != nil || !strings.Contains(strings.Join(metadata.ReasonCodes, ","), "DECLARED_ADDRESS_UNOBSERVED") {
		t.Fatal("legacy local negative no longer observable", err)
	}
	if _, err = artifactDecisionBinding(reg, bundle, metadata); err == nil {
		t.Fatal("legacy local negative acquired resource mapping")
	}
}
