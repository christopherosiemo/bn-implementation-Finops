package configuration

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
)

// FleetDeclaration is operator intent for a registered ASG. It contains no
// resource binding, observed Git/state data, artifact, price or action authority.
// The repository resolves the group identity from fleet-history registration.
// This family is separate from the existing per-instance declaration contract.
type FleetDeclaration struct {
	SchemaVersion string         `json:"schema_version"`
	Authority     string         `json:"authority"`
	Repository    Repository     `json:"repository"`
	Pipeline      Pipeline       `json:"pipeline"`
	Terraform     FleetTerraform `json:"terraform"`
}

type FleetTerraform struct {
	Workspace             string        `json:"workspace"`
	StateLineage          string        `json:"state_lineage"`
	ASGAddress            string        `json:"asg_address"`
	LaunchTemplateAddress string        `json:"launch_template_address"`
	Traffic               *FleetTraffic `json:"traffic,omitempty"`
}

// Addresses name declared Terraform configuration, not native ARN mappings.
// No pipeline identity is enrolled or trusted merely by this declaration.
type FleetTraffic struct {
	ListenerRuleAddress  string   `json:"listener_rule_address"`
	TargetGroupAddresses []string `json:"target_group_addresses"`
}

// FleetProposalSelection is the entire caller-selectable proposal input.
// All referenced documents, bindings, hashes, lifecycle and amounts are selected
// by the repository. A caller cannot upload evidence through this contract.
type FleetProposalSelection struct {
	DeclarationID string `json:"declaration_id"`
	ScopeID       string `json:"scope_id"`
}

func DecodeFleetDeclaration(raw []byte) (FleetDeclaration, error) {
	var d FleetDeclaration
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if len(raw) > 32<<10 || decoder.Decode(&d) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return d, invalid("FLEET_CONFIGURATION_DECLARATION_FIELDS_INVALID")
	}
	return d, ValidateFleetDeclaration(d)
}

func fleetManagedAddress(address, kind string) bool {
	if len(address) > 512 || !addressPattern.MatchString(address) {
		return false
	}
	// Resource address indices contain no dots in the shared bounded grammar;
	// the final managed type/name pair therefore remains unambiguous.
	parts := strings.Split(address, ".")
	return len(parts) >= 2 && parts[len(parts)-2] == kind
}

func ValidateFleetDeclaration(d FleetDeclaration) error {
	if d.SchemaVersion != "1" || d.Authority != "TERRAFORM" {
		return invalid("FLEET_CONFIGURATION_AUTHORITY_UNSUPPORTED")
	}
	f := d.Terraform
	if !fleetManagedAddress(f.ASGAddress, "aws_autoscaling_group") || !fleetManagedAddress(f.LaunchTemplateAddress, "aws_launch_template") {
		return invalid("FLEET_CONFIGURATION_GROUP_ADDRESS_INVALID")
	}
	addresses := []string{f.ASGAddress, f.LaunchTemplateAddress}
	if f.Traffic != nil {
		if !fleetManagedAddress(f.Traffic.ListenerRuleAddress, "aws_lb_listener_rule") || len(f.Traffic.TargetGroupAddresses) != 2 {
			return invalid("FLEET_CONFIGURATION_TRAFFIC_ADDRESS_INVALID")
		}
		addresses = append(addresses, f.Traffic.ListenerRuleAddress)
		for _, address := range f.Traffic.TargetGroupAddresses {
			if !fleetManagedAddress(address, "aws_lb_target_group") {
				return invalid("FLEET_CONFIGURATION_TRAFFIC_ADDRESS_INVALID")
			}
			addresses = append(addresses, address)
		}
	}
	// Reuse metadata validation without ever constructing an instance binding.
	metadata := Declaration{SchemaVersion: "1", Authority: "TERRAFORM", Repository: d.Repository, Pipeline: d.Pipeline, Terraform: Terraform{Workspace: f.Workspace, StateLineage: f.StateLineage, Addresses: addresses}}
	return Validate(metadata)
}

func DecodeFleetProposalSelection(raw []byte) (FleetProposalSelection, error) {
	var d FleetProposalSelection
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if len(raw) > 2048 || decoder.Decode(&d) != nil || decoder.Decode(&struct{}{}) != io.EOF || !scalar(d.DeclarationID, 256) || !scalar(d.ScopeID, 256) {
		return d, invalid("FLEET_CONFIGURATION_PROPOSAL_IDS_INVALID")
	}
	return d, nil
}

func FleetDeclarationReasons() []string {
	return []string{"CONFIGURATION_ADDRESS_MAPPING_UNVERIFIED", "CONFIGURATION_GIT_HEAD_UNOBSERVED", "CONFIGURATION_STATE_UNOBSERVED", "DECLARED_NOT_ATTESTED", "PIPELINE_ATTESTATION_REQUIRED"}
}

func FleetProposalReasons() []string {
	return []string{"CONFIGURATION_ADDRESS_MAPPING_UNVERIFIED", "CONFIGURATION_GIT_HEAD_UNOBSERVED", "CONFIGURATION_STATE_UNOBSERVED", "DECLARED_NOT_ATTESTED", "FLEET_CAPACITY_UNPROVEN", "FLEET_ECONOMICS_UNPROVEN", "FLEET_EXECUTION_NOT_ENABLED", "FLEET_OWNERSHIP_UNPROVEN", "HISTORICAL_MEMBERSHIP_INTERVAL_OWNERSHIP_UNPROVEN", "PIPELINE_ATTESTATION_REQUIRED", "WORK_PRESERVATION_UNPROVEN"}
}
