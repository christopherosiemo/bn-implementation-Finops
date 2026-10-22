package configuration

import (
	"encoding/json"
	"errors"
	"regexp"
	"strconv"
	"strings"
)

// This private analytical projection is issued only after the attestor has
// opened and revalidated the immutable bundle. It does not make an external
// provider executable or change any legacy artifact signature/status.
type artifactDecisionResourceBinding struct {
	SchemaVersion    string  `json:"schema_version"`
	Basis            string  `json:"basis"`
	TerraformAddress string  `json:"terraform_address"`
	Binding          Binding `json:"binding"`
	ResourceARN      string  `json:"resource_arn"`
	InstanceType     string  `json:"instance_type"`
	StateLineage     string  `json:"state_lineage"`
	StateSerial      uint64  `json:"state_serial"`
	BundleSHA256     string  `json:"bundle_sha256"`
	StateSHA256      string  `json:"state_sha256"`
}

var errArtifactDecisionBinding = errors.New("CONFIGURATION_ARTIFACT_DECISION_RESOURCE_BINDING_UNSUPPORTED")

func artifactDecisionClosureSupported(metadata ArtifactMetadata) bool {
	for _, reason := range metadata.ReasonCodes {
		// AWS provider execution is deliberately unsupported. Every other
		// configuration closure gap remains a blocker for post-config advice.
		if strings.HasPrefix(reason, "CONFIGURATION_") && reason != "CONFIGURATION_EXTERNAL_PROVIDER_UNSUPPORTED" {
			return false
		}
	}
	return true
}

func artifactDecisionStateResources(module map[string]any, found map[string]map[string]any) bool {
	if module == nil {
		return false
	}
	for _, value := range artifactArray(module["resources"]) {
		resource := artifactObject(value)
		address := artifactString(resource, "address")
		if address == "" || found[address] != nil {
			return false
		}
		found[address] = resource
	}
	for _, value := range artifactArray(module["child_modules"]) {
		if !artifactDecisionStateResources(artifactObject(value), found) {
			return false
		}
	}
	return true
}

func artifactDecisionIdentity(values map[string]any, id, arn string) bool {
	return artifactString(values, "id") == id && artifactString(values, "arn") == arn
}

func artifactDecisionCurrentIdentity(values map[string]any, id, arn, instanceType string) bool {
	return artifactDecisionIdentity(values, id, arn) && artifactString(values, "instance_type") == instanceType
}

func artifactDecisionBinding(reg ArtifactRegistration, bundle ArtifactBundle, metadata ArtifactMetadata) (*artifactDecisionResourceBinding, error) {
	if metadata.Binding != reg.Binding || metadata.AuthorityID != reg.AuthorityID || metadata.AuthorityHash != reg.AuthorityHash || metadata.Git != bundle.Git || metadata.State != bundle.State || metadata.BundleSHA256 == "" || metadata.StateSHA256 != artifactBytesHash(bundle.StateRaw) || metadata.ExecutionAuthorized || metadata.VerifiedSaving != nil || !artifactDecisionClosureSupported(metadata) || reg.Binding.Provider != "AWS" || !regexp.MustCompile(`^i-[a-f0-9]{17}$`).MatchString(reg.Binding.ProviderResourceID) {
		return nil, errArtifactDecisionBinding
	}
	state, err := artifactDecode(bundle.StateJSON)
	if err != nil {
		return nil, errArtifactDecisionBinding
	}
	plan, err := artifactDecode(bundle.PlanJSON)
	if err != nil {
		return nil, errArtifactDecisionBinding
	}
	if artifactHash(artifactObject(plan["prior_state"])["values"]) != artifactHash(state["values"]) {
		return nil, errArtifactDecisionBinding
	}
	resources := map[string]map[string]any{}
	if !artifactDecisionStateResources(artifactObject(artifactObject(state["values"])["root_module"]), resources) {
		return nil, errArtifactDecisionBinding
	}
	arn := "arn:aws:ec2:" + reg.Binding.Region + ":" + reg.Binding.AccountID + ":instance/" + reg.Binding.ProviderResourceID
	selected, instanceType := "", ""
	for _, address := range reg.Declaration.Terraform.Addresses {
		resource := resources[address]
		if resource == nil {
			return nil, errArtifactDecisionBinding
		}
		if artifactString(resource, "type") != "aws_instance" {
			continue
		}
		if artifactString(resource, "mode") != "managed" || artifactString(resource, "provider_name") != "registry.terraform.io/hashicorp/aws" {
			return nil, errArtifactDecisionBinding
		}
		if artifactDecisionIdentity(artifactObject(resource["values"]), reg.Binding.ProviderResourceID, arn) {
			if selected != "" {
				return nil, errArtifactDecisionBinding
			}
			selected = address
			instanceType = artifactString(artifactObject(resource["values"]), "instance_type")
		}
	}
	if selected == "" || !regexp.MustCompile(`^[a-z][a-z0-9-]*\.[a-z0-9]+$`).MatchString(instanceType) {
		return nil, errArtifactDecisionBinding
	}
	changes := 0
	for _, value := range artifactArray(plan["resource_changes"]) {
		resource := artifactObject(value)
		if artifactString(resource, "address") != selected {
			continue
		}
		changes++
		change := artifactObject(resource["change"])
		if artifactString(resource, "mode") != "managed" || artifactString(resource, "type") != "aws_instance" || artifactString(resource, "provider_name") != "registry.terraform.io/hashicorp/aws" || artifactHash(change["actions"]) != artifactHash([]string{"no-op"}) || !artifactDecisionCurrentIdentity(artifactObject(change["before"]), reg.Binding.ProviderResourceID, arn, instanceType) || !artifactDecisionCurrentIdentity(artifactObject(change["after"]), reg.Binding.ProviderResourceID, arn, instanceType) {
			return nil, errArtifactDecisionBinding
		}
	}
	if changes != 1 {
		return nil, errArtifactDecisionBinding
	}
	planned := map[string]map[string]any{}
	if !artifactDecisionStateResources(artifactObject(artifactObject(plan["planned_values"])["root_module"]), planned) || !artifactDecisionCurrentIdentity(artifactObject(planned[selected]["values"]), reg.Binding.ProviderResourceID, arn, instanceType) {
		return nil, errArtifactDecisionBinding
	}
	// The native state file is also inside the saved-plan container. Match its
	// exact address, including module/count/for_each indices, to the show output.
	raw, err := artifactDecode(bundle.StateRaw)
	if err != nil {
		return nil, errArtifactDecisionBinding
	}
	matches := 0
	for _, value := range artifactArray(raw["resources"]) {
		resource := artifactObject(value)
		base := artifactString(resource, "module")
		if base != "" {
			base += "."
		}
		base += artifactString(resource, "type") + "." + artifactString(resource, "name")
		for _, entry := range artifactArray(resource["instances"]) {
			instance := artifactObject(entry)
			address := base
			switch index := instance["index_key"].(type) {
			case nil:
			case json.Number:
				n, e := index.Int64()
				if e != nil || n < 0 || strconv.FormatInt(n, 10) != string(index) {
					return nil, errArtifactDecisionBinding
				}
				address += "[" + string(index) + "]"
			case string:
				encoded, _ := json.Marshal(index)
				address += "[" + string(encoded) + "]"
			default:
				return nil, errArtifactDecisionBinding
			}
			if address != selected {
				continue
			}
			matches++
			if artifactString(resource, "mode") != "managed" || artifactString(resource, "provider") != `provider["registry.terraform.io/hashicorp/aws"]` || artifactString(instance, "deposed") != "" || !artifactDecisionCurrentIdentity(artifactObject(instance["attributes"]), reg.Binding.ProviderResourceID, arn, instanceType) {
				return nil, errArtifactDecisionBinding
			}
		}
	}
	if matches != 1 {
		return nil, errArtifactDecisionBinding
	}
	return &artifactDecisionResourceBinding{SchemaVersion: "1", Basis: "ATTESTED_TERRAFORM_AWS_INSTANCE_CURRENT_STATE", TerraformAddress: selected, Binding: reg.Binding, ResourceARN: arn, InstanceType: instanceType, StateLineage: metadata.State.Lineage, StateSerial: metadata.State.Serial, BundleSHA256: metadata.BundleSHA256, StateSHA256: metadata.StateSHA256}, nil
}
