package configuration

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
)

func declaration() Declaration {
	return Declaration{SchemaVersion: "1", Authority: "TERRAFORM", Repository: Repository{URL: "https://github.com/example/infrastructure.git", Ref: "main", Directory: "envs/development"}, Pipeline: Pipeline{System: "GITHUB_ACTIONS", Identity: PipelineIdentity{Issuer: "https://token.actions.githubusercontent.com", Audience: ObserverAudience, Subject: "repo:example/infrastructure:ref:refs/heads/main", PipelineID: ".github/workflows/deploy.yml"}}, Terraform: Terraform{Workspace: "dev-eu", StateLineage: "0f5a34b0-a480-4cda-9f6a-9b205ced7937", Addresses: []string{`module.api["dev"].aws_instance.api[0]`}}}
}

func TestDeclarationRejectsAuthorityAndCredentialClaims(t *testing.T) {
	d := declaration()
	raw, _ := json.Marshal(d)
	if _, err := Decode(raw); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{`"execution_authorized":true`, `"observed_commit":"abc"`, `"observed_state_serial":12`, `"proof_set_id":"proof"`, `"credentials":{"token":"secret"}`} {
		bad := strings.TrimSuffix(string(raw), "}") + "," + field + "}"
		if _, err := Decode([]byte(bad)); err == nil {
			t.Fatalf("accepted server-only field %s", field)
		}
	}
	for _, audience := range []string{"console", "finops", "finops-activity", "finops-slo", "finops-native-telemetry", "*", ""} {
		x := declaration()
		x.Pipeline.Identity.Audience = audience
		if Validate(x) == nil {
			t.Fatalf("accepted non-dedicated audience %q", audience)
		}
	}
}

func TestDeclarationRequiresCanonicalExactMetadata(t *testing.T) {
	cases := map[string]func(*Declaration){
		"credentials":            func(d *Declaration) { d.Repository.URL = "https://token:password@github.com/org/repo" },
		"query":                  func(d *Declaration) { d.Repository.URL += "?token=secret" },
		"fragment":               func(d *Declaration) { d.Repository.URL += "#main" },
		"http":                   func(d *Declaration) { d.Repository.URL = "http://github.com/org/repo" },
		"issuer credentials":     func(d *Declaration) { d.Pipeline.Identity.Issuer = "https://token@issuer.example" },
		"wildcard subject":       func(d *Declaration) { d.Pipeline.Identity.Subject = "repo:example/*" },
		"control subject":        func(d *Declaration) { d.Pipeline.Identity.Subject += "\n" },
		"absolute directory":     func(d *Declaration) { d.Repository.Directory = "/etc" },
		"traversal":              func(d *Declaration) { d.Repository.Directory = "env/../../etc" },
		"noncanonical directory": func(d *Declaration) { d.Repository.Directory = "env/../dev" },
		"ref command":            func(d *Declaration) { d.Repository.Ref = "main:other" },
		"ref traversal":          func(d *Declaration) { d.Repository.Ref = "refs/heads/../main" },
		"ref wildcard":           func(d *Declaration) { d.Repository.Ref = "refs/heads/*" },
		"state UUID":             func(d *Declaration) { d.Terraform.StateLineage = "declared-state" },
		"missing state":          func(d *Declaration) { d.Terraform.StateLineage = "" },
		"data address":           func(d *Declaration) { d.Terraform.Addresses = []string{"data.aws_instance.api"} },
		"module only":            func(d *Declaration) { d.Terraform.Addresses = []string{"module.api"} },
		"wildcard address":       func(d *Declaration) { d.Terraform.Addresses = []string{"aws_instance.api[*]"} },
		"leading zero":           func(d *Declaration) { d.Terraform.Addresses = []string{"aws_instance.api[01]"} },
		"duplicate":              func(d *Declaration) { d.Terraform.Addresses = append(d.Terraform.Addresses, d.Terraform.Addresses[0]) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			d := declaration()
			mutate(&d)
			if Validate(d) == nil {
				t.Fatal("invalid declaration accepted")
			}
		})
	}
}

func TestBindingNeverGrantsProviderExecution(t *testing.T) {
	r := model.Document{"id": "r", "version": 3, "workload_id": "w", "provider": "AWS", "provider_resource_id": "i-123", "account_id": "111122223333", "region": "eu-west-1"}
	b, err := NewBinding("tenant", r)
	if err != nil || b.ResourceVersion != 3 || len(b.ResourceSnapshotHash) != 64 || ValidateBinding(declaration(), b) != nil {
		t.Fatal("explicit resource binding failed", err)
	}
	if len(Reasons(b)) != 2 {
		t.Fatal("AWS declaration lost attestation blockers")
	}
	b.Provider = "GCP"
	if ValidateBinding(declaration(), b) == nil || !strings.Contains(strings.Join(Reasons(b), ","), "PROVIDER_ACTION_NOT_ENABLED") {
		t.Fatal("provider mismatch or disabled action disappeared")
	}
	delete(r, "account_id")
	if _, err := NewBinding("tenant", r); err == nil {
		t.Fatal("unknown provider account accepted")
	}
}
