package configuration

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func fleetDeclarationFixture() FleetDeclaration {
	v1 := declaration()
	return FleetDeclaration{SchemaVersion: "1", Authority: "TERRAFORM", Repository: v1.Repository, Pipeline: v1.Pipeline, Terraform: FleetTerraform{Workspace: v1.Terraform.Workspace, StateLineage: v1.Terraform.StateLineage, ASGAddress: `module.api["dev"].aws_autoscaling_group.api[0]`, LaunchTemplateAddress: `module.api["dev"].aws_launch_template.api[0]`}}
}

func TestFleetDeclarationMetadataAndTrafficAddresses(t *testing.T) {
	d := fleetDeclarationFixture()
	if e := ValidateFleetDeclaration(d); e != nil {
		t.Fatal(e)
	}
	d.Terraform.Traffic = &FleetTraffic{ListenerRuleAddress: "aws_lb_listener_rule.api", TargetGroupAddresses: []string{"aws_lb_target_group.old", "aws_lb_target_group.candidate"}}
	raw, _ := json.Marshal(d)
	decoded, e := DecodeFleetDeclaration(raw)
	if e != nil || decoded.Terraform.Traffic.TargetGroupAddresses[1] != "aws_lb_target_group.candidate" {
		t.Fatal("bounded operator address intent did not round-trip", e)
	}
	for name, mutate := range map[string]func(*FleetDeclaration){
		"individual instance": func(d *FleetDeclaration) { d.Terraform.ASGAddress = "aws_instance.one" },
		"other provider":      func(d *FleetDeclaration) { d.Terraform.ASGAddress = "azurerm_linux_virtual_machine.one" },
		"data address":        func(d *FleetDeclaration) { d.Terraform.ASGAddress = "data.aws_autoscaling_group.api" },
		"wrong template":      func(d *FleetDeclaration) { d.Terraform.LaunchTemplateAddress = "aws_instance.template" },
		"noncanonical module": func(d *FleetDeclaration) { d.Terraform.ASGAddress = "module..aws_autoscaling_group.api" },
		"shell address":       func(d *FleetDeclaration) { d.Terraform.ASGAddress = "aws_autoscaling_group.api;echo" },
		"wildcard":            func(d *FleetDeclaration) { d.Terraform.ASGAddress = "aws_autoscaling_group.api[*]" },
		"traffic missing pair": func(d *FleetDeclaration) {
			d.Terraform.Traffic = &FleetTraffic{ListenerRuleAddress: "aws_lb_listener_rule.api", TargetGroupAddresses: []string{"aws_lb_target_group.old"}}
		},
		"traffic duplicate": func(d *FleetDeclaration) {
			d.Terraform.Traffic = &FleetTraffic{ListenerRuleAddress: "aws_lb_listener_rule.api", TargetGroupAddresses: []string{"aws_lb_target_group.old", "aws_lb_target_group.old"}}
		},
		"traffic wrong type": func(d *FleetDeclaration) {
			d.Terraform.Traffic = &FleetTraffic{ListenerRuleAddress: "aws_lb_listener.api", TargetGroupAddresses: []string{"aws_lb_target_group.old", "aws_lb_target_group.candidate"}}
		},
		"credential URL":         func(d *FleetDeclaration) { d.Repository.URL = "https://token:secret@github.com/org/repo" },
		"query credential":       func(d *FleetDeclaration) { d.Repository.URL += "?token=secret" },
		"non dedicated audience": func(d *FleetDeclaration) { d.Pipeline.Identity.Audience = "finops" },
		"wildcard subject":       func(d *FleetDeclaration) { d.Pipeline.Identity.Subject = "repo:example/*" },
		"path traversal":         func(d *FleetDeclaration) { d.Repository.Directory = "../other" },
		"bad state lineage":      func(d *FleetDeclaration) { d.Terraform.StateLineage = "observed-state" },
	} {
		t.Run(name, func(t *testing.T) {
			d := fleetDeclarationFixture()
			mutate(&d)
			if ValidateFleetDeclaration(d) == nil {
				t.Fatal("invalid group metadata accepted")
			}
		})
	}
}

func TestFleetDeclarationRejectsUploadedBindingsAuthorityAndFacts(t *testing.T) {
	raw, _ := json.Marshal(fleetDeclarationFixture())
	for _, extra := range []string{
		`"resource_id":"representative-member"`, `"binding":{"tenant_id":"other"}`, `"registration_id":"caller"`, `"asg_arn":"caller"`,
		`"observed_commit":"abc"`, `"observed_state_serial":2`, `"artifact_id":"private020"`, `"proof_set_id":"caller"`,
		`"execution_authorized":true`, `"currency":"USD"`, `"estimated_saving":"100"`, `"verified_saving":"100"`, `"credentials":{"token":"secret"}`,
	} {
		bad := strings.TrimSuffix(string(raw), "}") + "," + extra + "}"
		if _, e := DecodeFleetDeclaration([]byte(bad)); e == nil {
			t.Fatalf("accepted caller authority field %s", extra)
		}
	}
	for _, path := range []string{"repository", "pipeline", "terraform"} {
		var obj map[string]any
		_ = json.Unmarshal(raw, &obj)
		obj[path].(map[string]any)["trusted"] = true
		bad, _ := json.Marshal(obj)
		if _, e := DecodeFleetDeclaration(bad); e == nil {
			t.Fatal("accepted nested authority field", path)
		}
	}
	if _, e := DecodeFleetDeclaration(append(raw, []byte(` {"authority":"TERRAFORM"}`)...)); e == nil {
		t.Fatal("accepted trailing metadata document")
	}
	if _, e := DecodeFleetDeclaration(bytes.Repeat([]byte(" "), 32769)); e == nil {
		t.Fatal("accepted oversized declaration")
	}
}

func TestFleetProposalSelectionOnlyStoredIDs(t *testing.T) {
	valid := []byte(`{"declaration_id":"decl-1","scope_id":"scope-1"}`)
	if _, e := DecodeFleetProposalSelection(valid); e != nil {
		t.Fatal(e)
	}
	for _, raw := range []string{
		`{"declaration_id":"decl-1","scope_id":"scope-1","observations":[]}`,
		`{"declaration_id":"decl-1","scope_id":"scope-1","estimated_saving":"1"}`,
		`{"declaration_id":"decl-1","scope_id":"scope-1","capacity_assessment_id":"one-member"}`,
		`{"declaration_id":"decl-1","scope_id":"scope-1","trusted":true}`,
		`{"declaration_id":"decl-1","scope_id":"scope-1","plan":{}}`,
		`{"declaration_id":"decl-1","scope_id":""}`,
		`{"declaration_id":"*","scope_id":"scope-1"}`,
		`{"declaration_id":"decl-1","scope_id":" scope-1"}`,
		`{"declaration_id":"decl-1","scope_id":"scope-1"} {}`,
	} {
		if _, e := DecodeFleetProposalSelection([]byte(raw)); e == nil {
			t.Fatal("accepted unbounded/caller evidence selector", raw)
		}
	}
}

func TestFleetMetadataDoesNotChangeLegacyDeclarationContract(t *testing.T) {
	legacy := declaration()
	before, _ := json.Marshal(legacy)
	meta, _ := json.Marshal(fleetDeclarationFixture())
	if _, e := DecodeFleetDeclaration(meta); e != nil {
		t.Fatal(e)
	}
	after, _ := json.Marshal(legacy)
	if !bytes.Equal(before, after) {
		t.Fatal("Fleet metadata modified legacy configuration serialization")
	}
	if _, e := Decode(meta); e == nil {
		t.Fatal("new group metadata was accepted as legacy instance declaration")
	}
	if _, e := DecodeFleetDeclaration(before); e == nil {
		t.Fatal("legacy singleton metadata was silently reinterpreted as Fleet")
	}
}
