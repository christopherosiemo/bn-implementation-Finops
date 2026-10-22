package fleetgroup

import (
	"archive/zip"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// These builders test semantic branches using labelled unit-only containers.
// Their opaque tfplan member is not a Terraform plan. Actual Git/CLI plan/show/
// apply acceptance belongs to the separate isolated real-tool lab.
func unitFixtureContainer(t *testing.T, source, state []byte, mutate func(map[string][]byte)) []byte {
	t.Helper()
	previous, err := fixtureObject(state, fixtureArtifactLimit)
	if err != nil {
		t.Fatal(err)
	}
	previous["lineage"], previous["serial"] = "", 0
	previousRaw, _ := json.Marshal(previous)
	modules, _ := json.Marshal([]map[string]any{{"Key": "", "Dir": FixtureWorkingDirectory}})
	entries := map[string][]byte{"tfplan": []byte("unit-only-opaque-tfplan-not-real-CLI-output"), "tfstate": state, "tfstate-prev": previousRaw, "tfconfig/modules.json": modules, "tfconfig/m-/main.tf.json": source, ".terraform.lock.hcl": []byte("# This file is maintained automatically by \"terraform init\".\n# Manual edits may be lost in future updates.")}
	if mutate != nil {
		mutate(entries)
	}
	var out bytes.Buffer
	writer := zip.NewWriter(&out)
	for name, body := range entries {
		w, e := writer.Create(name)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = w.Write(body); e != nil {
			t.Fatal(e)
		}
	}
	if err = writer.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func unitModelAttributes(input map[string]any, id string, unknown bool) map[string]any {
	a := map[string]any{"id": id, "input": input, "store": nil, "triggers_replace": nil}
	if !unknown {
		a["output"] = input
	}
	return a
}

func unitGitObjects(p *Program, source []byte) ([]byte, []byte) {
	blob, _ := hex.DecodeString(gitObjectOID("blob", source, 40))
	tree := append([]byte("100644 main.tf.json\x00"), blob...)
	p.ArtifactContext.GitTree = gitObjectOID("tree", tree, 40)
	commit := []byte("tree " + p.ArtifactContext.GitTree + "\nauthor Unit fixture <fixture@example.invalid> 1792411200 +0000\ncommitter Unit fixture <fixture@example.invalid> 1792411200 +0000\n\nUnit fixture, no real Git CLI acceptance\n")
	p.ArtifactContext.GitCommit = gitObjectOID("commit", commit, 40)
	return commit, tree
}

func unitArtifactCapture(t *testing.T) (Program, Child, TerraformArtifactCapture, time.Time) {
	t.Helper()
	p, now := programFixture()
	p.ArtifactContext.StateLineage = "11111111-2222-3333-4444-555555555555"
	source, err := FixtureConfiguration(p)
	if err != nil {
		t.Fatal(err)
	}
	p.ArtifactContext.ConfigurationSHA256 = BytesDigest(source)
	unitGitObjects(&p, source)
	c := childFixture(p, now)
	c.Artifact.Receipt = SnapshotRef{"semantic-artifact", sha("a")}
	return unitCaptureForChild(t, p, c, source, now)
}

func unitCaptureForChild(t *testing.T, p Program, c Child, source []byte, now time.Time) (Program, Child, TerraformArtifactCapture, time.Time) {
	t.Helper()
	beforeInputs, _ := FixtureInputs(p, c.Artifact.Before)
	afterInputs, _ := FixtureInputs(p, c.Artifact.After)
	parsed, _ := fixtureObject(source, 256<<10)
	sourceResources := tfObject(tfObject(parsed["resource"])["terraform_data"])
	rawResources, priorResources, plannedResources, changes, configuration := []any{}, []any{}, []any{}, []any{}, []any{}
	for address, before := range beforeInputs {
		after := afterInputs[address]
		name := strings.TrimPrefix(address, "terraform_data.")
		id := map[string]string{"old": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "candidate": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", "traffic": "cccccccc-cccc-cccc-cccc-cccccccccccc"}[name]
		rawResources = append(rawResources, map[string]any{"mode": "managed", "type": "terraform_data", "name": name, "provider": `provider["terraform.io/builtin/terraform"]`, "instances": []any{map[string]any{"schema_version": 0, "attributes": map[string]any{"id": id, "input": map[string]any{"value": before, "type": inputType(before)}, "output": map[string]any{"value": before, "type": inputType(before)}, "store": nil, "triggers_replace": nil}, "sensitive_attributes": []any{}, "identity_schema_version": 0}}})
		resource := func(input map[string]any, unknown bool) map[string]any {
			return map[string]any{"address": address, "mode": "managed", "type": "terraform_data", "name": name, "provider_name": BuiltinProvider, "schema_version": 0, "values": unitModelAttributes(input, id, unknown), "sensitive_values": map[string]any{"input": map[string]any{}, "output": map[string]any{}}}
		}
		update := !tfEqual(before, after)
		priorResources = append(priorResources, resource(before, false))
		plannedResources = append(plannedResources, resource(after, update))
		action := "no-op"
		unknown := map[string]any{"input": map[string]any{}, "output": map[string]any{}}
		if update {
			action = "update"
			unknown["output"] = true
		}
		changes = append(changes, map[string]any{"address": address, "mode": "managed", "type": "terraform_data", "name": name, "provider_name": BuiltinProvider, "change": map[string]any{"actions": []string{action}, "before": unitModelAttributes(before, id, false), "after": unitModelAttributes(after, id, update), "after_unknown": unknown, "before_sensitive": map[string]any{"input": map[string]any{}, "output": map[string]any{}}, "after_sensitive": map[string]any{"input": map[string]any{}, "output": map[string]any{}}}})
		variable := "var.old_count"
		if name == "candidate" {
			variable = "var.candidate_count"
		}
		if name == "traffic" {
			variable = "var.candidate_traffic_percent"
		}
		configuration = append(configuration, map[string]any{"address": address, "mode": "managed", "type": "terraform_data", "name": name, "provider_config_key": "terraform", "expressions": map[string]any{"input": map[string]any{"constant_value": tfObject(sourceResources[name])["input"], "references": []string{variable}}}, "schema_version": 0})
	}
	state, _ := json.Marshal(map[string]any{"version": 4, "terraform_version": FixtureTerraformVersion, "serial": c.Artifact.BeforeStateSerial, "lineage": p.ArtifactContext.StateLineage, "outputs": map[string]any{}, "resources": rawResources, "check_results": nil})
	plan, _ := json.Marshal(map[string]any{"format_version": "1.2", "terraform_version": FixtureTerraformVersion, "variables": map[string]any{"old_count": map[string]any{"value": c.Artifact.After.OldCount}, "candidate_count": map[string]any{"value": c.Artifact.After.CandidateCount}, "candidate_traffic_percent": map[string]any{"value": c.Artifact.After.CandidateTrafficPercent}}, "planned_values": map[string]any{"root_module": map[string]any{"resources": plannedResources}}, "resource_changes": changes, "prior_state": map[string]any{"format_version": "1.0", "terraform_version": FixtureTerraformVersion, "values": map[string]any{"root_module": map[string]any{"resources": priorResources}}}, "configuration": map[string]any{"provider_config": map[string]any{"terraform": map[string]any{"name": "terraform", "full_name": BuiltinProvider}}, "root_module": map[string]any{"resources": configuration, "variables": map[string]any{"old_count": map[string]any{}, "candidate_count": map[string]any{}, "candidate_traffic_percent": map[string]any{}}}}, "timestamp": now.Add(-time.Second).Format(time.RFC3339), "applyable": true, "complete": true, "errored": false})
	commit, tree := unitGitObjects(&p, source)
	capture := TerraformArtifactCapture{Context: p.ArtifactContext, Configuration: source, SavedPlan: unitFixtureContainer(t, source, state, nil), PlanJSON: plan, BeforeState: state, GitCommitObject: commit, GitTreeObject: tree}
	if c.Artifact.Before == c.Artifact.After {
		parsed, _ := fixtureObject(capture.PlanJSON, fixtureArtifactLimit)
		parsed["applyable"] = false
		capture.PlanJSON, _ = json.Marshal(parsed)
	}
	bindArtifactBytes(&c, capture)
	return p, c, capture, now
}

func bindArtifactBytes(c *Child, capture TerraformArtifactCapture) {
	c.Artifact.SavedPlanSHA256 = BytesDigest(capture.SavedPlan)
	c.Artifact.PlanJSONSHA256 = BytesDigest(capture.PlanJSON)
	c.Artifact.BeforeStateSHA256 = BytesDigest(capture.BeforeState)
}

func mutateArtifactPlan(t *testing.T, c *Child, capture *TerraformArtifactCapture, mutate func(map[string]any)) {
	t.Helper()
	plan, err := fixtureObject(capture.PlanJSON, fixtureArtifactLimit)
	if err != nil {
		t.Fatal(err)
	}
	mutate(plan)
	capture.PlanJSON, err = json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	bindArtifactBytes(c, *capture)
}

func TestFixtureTerraformSemanticUnitContractBindsCompleteModelStateSourceAndBytes(t *testing.T) {
	p, c, capture, now := unitArtifactCapture(t)
	review, err := ValidateTerraformArtifact(p, c, capture, now)
	if err != nil {
		t.Fatal(err)
	}
	if review.Status != "FIXTURE_SEMANTICS_MATCHED" || review.NoOp || len(review.ChangedAddresses) != 1 || review.ChangedAddresses[0] != p.ArtifactContext.Mapping.CandidateModel || review.CustomerNativeExecution || review.CustomerVerifiedSaving != nil {
		t.Fatalf("bad bounded review: %+v", review)
	}
	if review.ChildSHA256 != Digest(c) || review.ArtifactSHA256 != Digest(c.Artifact) || review.BeforeStateSHA256 != BytesDigest(capture.BeforeState) || review.StateLineage != p.ArtifactContext.StateLineage {
		t.Fatal("review lost exact artifact binding")
	}
	// A plan is generated before it is signed, possibly across a second boundary.
	c.CreatedAt = now.Add(2 * time.Second)
	if _, err = ValidateTerraformArtifact(p, c, capture, now.Add(2*time.Second)); err != nil {
		t.Fatal("legitimate plan→show→sign order:", err)
	}
	for name, change := range map[string]func(*TerraformArtifactCapture){
		"different saved plan":   func(x *TerraformArtifactCapture) { x.SavedPlan = append(append([]byte{}, x.SavedPlan...), 0) },
		"different show":         func(x *TerraformArtifactCapture) { x.PlanJSON = append(append([]byte{}, x.PlanJSON...), ' ') },
		"different state":        func(x *TerraformArtifactCapture) { x.BeforeState = append(append([]byte{}, x.BeforeState...), ' ') },
		"different Git commit":   func(x *TerraformArtifactCapture) { x.Context.GitCommit = strings.Repeat("c", 40) },
		"different image":        func(x *TerraformArtifactCapture) { x.Context.ToolchainImageSHA256 = sha("e") },
		"different source bytes": func(x *TerraformArtifactCapture) { x.Configuration = append(append([]byte{}, x.Configuration...), ' ') },
	} {
		t.Run(name, func(t *testing.T) {
			p, c, x, now := unitArtifactCapture(t)
			change(&x)
			if _, err := ValidateTerraformArtifact(p, c, x, now); err == nil {
				t.Fatal("accepted mismatched capture")
			}
		})
	}
}

func TestFixtureTerraformRejectsRehashedUnreviewedPlanEffectsAndUnknownSensitiveOrExternalFeatures(t *testing.T) {
	changeResource := func(plan map[string]any) map[string]any { return tfObject(tfArray(plan["resource_changes"])[0]) }
	cases := map[string]func(map[string]any){
		"external provider": func(p map[string]any) {
			tfObject(tfObject(p["configuration"])["provider_config"])["aws"] = map[string]any{"name": "aws", "full_name": "registry.terraform.io/hashicorp/aws"}
		},
		"provider alias": func(p map[string]any) {
			tfObject(tfObject(tfObject(p["configuration"])["provider_config"])["terraform"])["alias"] = "another"
		},
		"module": func(p map[string]any) {
			tfObject(tfObject(p["configuration"])["root_module"])["module_calls"] = map[string]any{"remote": map[string]any{"source": "https://module.invalid"}}
		},
		"provisioner": func(p map[string]any) {
			tfObject(tfArray(tfObject(tfObject(p["configuration"])["root_module"])["resources"])[0])["provisioners"] = []any{map[string]any{"type": "local-exec"}}
		},
		"external reference": func(p map[string]any) {
			r := tfObject(tfArray(tfObject(tfObject(p["configuration"])["root_module"])["resources"])[0])
			tfObject(tfObject(r["expressions"])["input"])["references"] = []string{"data.external.command.result"}
		},
		"hidden output": func(p map[string]any) {
			tfObject(p["planned_values"])["outputs"] = map[string]any{"secret": map[string]any{"value": "must-never-appear"}}
		},
		"output configuration": func(p map[string]any) {
			tfObject(tfObject(p["configuration"])["root_module"])["outputs"] = map[string]any{"leak": map[string]any{}}
		},
		"output change": func(p map[string]any) {
			p["output_changes"] = map[string]any{"secret": map[string]any{"after": "must-never-appear"}}
		},
		"sensitive plaintext input": func(p map[string]any) {
			tfObject(changeResource(p)["change"])["before_sensitive"] = map[string]any{"input": true}
		},
		"sensitive planned value": func(p map[string]any) {
			tfObject(tfArray(tfObject(tfObject(p["planned_values"])["root_module"])["resources"])[0])["sensitive_values"] = map[string]any{"output": true}
		},
		"unknown actionable input": func(p map[string]any) {
			tfObject(changeResource(p)["change"])["after_unknown"] = map[string]any{"input": true}
		},
		"replacement": func(p map[string]any) {
			tfObject(changeResource(p)["change"])["actions"] = []string{"delete", "create"}
		},
		"delete": func(p map[string]any) { tfObject(changeResource(p)["change"])["actions"] = []string{"delete"} },
		"import": func(p map[string]any) {
			tfObject(changeResource(p)["change"])["importing"] = map[string]any{"id": "another"}
		},
		"move":    func(p map[string]any) { changeResource(p)["previous_address"] = "terraform_data.unrelated" },
		"deposed": func(p map[string]any) { changeResource(p)["deposed"] = "old" },
		"unrelated resource": func(p map[string]any) {
			p["resource_changes"] = append(tfArray(p["resource_changes"]), changeResource(p))
		},
		"missing resource":  func(p map[string]any) { p["resource_changes"] = tfArray(p["resource_changes"])[:2] },
		"duplicate address": func(p map[string]any) { r := tfArray(p["resource_changes"]); r[1] = r[0] },
		"bad physical count": func(p map[string]any) {
			a := tfObject(tfObject(changeResource(p)["change"])["after"])
			tfObject(a["input"])["desired_count"] = 123
		},
		"replaced identity": func(p map[string]any) {
			tfObject(tfObject(changeResource(p)["change"])["after"])["id"] = "dddddddd-dddd-dddd-dddd-dddddddddddd"
		},
		"extra variable": func(p map[string]any) {
			tfObject(p["variables"])["secret"] = map[string]any{"value": "must-never-appear"}
		},
		"numeric string variable": func(p map[string]any) { tfObject(tfObject(p["variables"])["candidate_count"])["value"] = "2" },
		"fractional variable": func(p map[string]any) {
			tfObject(tfObject(p["variables"])["candidate_count"])["value"] = json.Number("2.0")
		},
		"drift":              func(p map[string]any) { p["resource_drift"] = []any{changeResource(p)} },
		"incomplete":         func(p map[string]any) { p["complete"] = false },
		"errored":            func(p map[string]any) { p["errored"] = true },
		"unapplyable change": func(p map[string]any) { p["applyable"] = false },
		"unsupported format": func(p map[string]any) { p["format_version"] = "2.0" },
		"future feature":     func(p map[string]any) { p["deferred_changes"] = []any{} },
		"stale plan":         func(p map[string]any) { p["timestamp"] = "2026-10-19T11:00:00Z" },
		"future plan":        func(p map[string]any) { p["timestamp"] = "2026-10-19T12:01:00Z" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			p, c, capture, now := unitArtifactCapture(t)
			mutateArtifactPlan(t, &c, &capture, mutate)
			if _, err := ValidateTerraformArtifact(p, c, capture, now); err == nil {
				t.Fatal("accepted rehashed unreviewed plan")
			}
		})
	}
}

func TestFixtureTerraformRejectsRehashedSourceStateAndSavedContainerTampering(t *testing.T) {
	for name, mutate := range map[string]func(map[string]any){
		"other lineage": func(s map[string]any) { s["lineage"] = "99999999-9999-9999-9999-999999999999" },
		"other serial":  func(s map[string]any) { s["serial"] = 8 },
		"output leak": func(s map[string]any) {
			s["outputs"] = map[string]any{"secret": map[string]any{"value": "must-never-appear"}}
		},
		"unrelated state resource": func(s map[string]any) { s["resources"] = append(tfArray(s["resources"]), tfArray(s["resources"])[0]) },
		"external state provider": func(s map[string]any) {
			tfObject(tfArray(s["resources"])[0])["provider"] = `provider["registry.terraform.io/hashicorp/aws"]`
		},
		"state module": func(s map[string]any) { tfObject(tfArray(s["resources"])[0])["module"] = "module.remote" },
		"tainted state": func(s map[string]any) {
			tfObject(tfArray(tfObject(tfArray(s["resources"])[0])["instances"])[0])["status"] = "tainted"
		},
		"sensitive state": func(s map[string]any) {
			tfObject(tfArray(tfObject(tfArray(s["resources"])[0])["instances"])[0])["sensitive_attributes"] = []any{map[string]any{"type": "get_attr", "value": "input"}}
		},
		"unknown state feature": func(s map[string]any) { s["new_authority"] = true },
	} {
		t.Run(name, func(t *testing.T) {
			p, c, x, now := unitArtifactCapture(t)
			state, _ := fixtureObject(x.BeforeState, fixtureArtifactLimit)
			mutate(state)
			x.BeforeState, _ = json.Marshal(state)
			x.SavedPlan = unitFixtureContainer(t, x.Configuration, x.BeforeState, nil)
			bindArtifactBytes(&c, x)
			if _, err := ValidateTerraformArtifact(p, c, x, now); err == nil {
				t.Fatal("accepted rehashed state")
			}
		})
	}
	for name, mutate := range map[string]func(map[string][]byte){
		"source substitution": func(e map[string][]byte) { e["tfconfig/m-/main.tf.json"] = []byte(`{"module":{}}`) },
		"extra source":        func(e map[string][]byte) { e["tfconfig/m-/override.tf"] = []byte(`provider "aws" {}`) },
		"traversal":           func(e map[string][]byte) { e["../outside"] = []byte("escape") },
		"unexpected module": func(e map[string][]byte) {
			e["tfconfig/modules.json"] = []byte(`[{"Key":"child","Source":"./child","Dir":"/workspace/fixture/child"}]`)
		},
		"null root source": func(e map[string][]byte) {
			e["tfconfig/modules.json"] = []byte(`[{"Key":"","Source":null,"Dir":"/workspace/fixture"}]`)
		},
		"nonempty root source": func(e map[string][]byte) {
			e["tfconfig/modules.json"] = []byte(`[{"Key":"","Source":"./elsewhere","Dir":"/workspace/fixture"}]`)
		},
		"null root version": func(e map[string][]byte) {
			e["tfconfig/modules.json"] = []byte(`[{"Key":"","Version":null,"Dir":"/workspace/fixture"}]`)
		},
		"module directory escape": func(e map[string][]byte) {
			e["tfconfig/modules.json"] = []byte(`[{"Key":"","Source":"","Dir":"/etc"}]`)
		},
		"duplicate module field": func(e map[string][]byte) {
			e["tfconfig/modules.json"] = []byte(`[{"Key":"","Source":"","Dir":"/etc","Dir":"."}]`)
		},
		"external provider lock": func(e map[string][]byte) {
			e[".terraform.lock.hcl"] = []byte(`provider "registry.terraform.io/hashicorp/aws" {}`)
		},
		"embedded state substitution": func(e map[string][]byte) { e["tfstate"] = []byte(`{"lineage":"another"}`) },
		"empty protobuf":              func(e map[string][]byte) { e["tfplan"] = nil },
	} {
		t.Run(name, func(t *testing.T) {
			p, c, x, now := unitArtifactCapture(t)
			x.SavedPlan = unitFixtureContainer(t, x.Configuration, x.BeforeState, mutate)
			bindArtifactBytes(&c, x)
			if _, err := ValidateTerraformArtifact(p, c, x, now); err == nil {
				t.Fatal("accepted rehashed saved container")
			}
		})
	}
	for name, mutate := range map[string]func(map[string]any){
		"external provider source": func(s map[string]any) { s["provider"] = map[string]any{"aws": map[string]any{}} },
		"data source":              func(s map[string]any) { s["data"] = map[string]any{"external": map[string]any{}} },
		"external function": func(s map[string]any) {
			tfObject(tfObject(tfObject(tfObject(s["resource"])["terraform_data"])["old"])["input"])["desired_count"] = "${file(\"/etc/secret\")}"
		},
		"source output": func(s map[string]any) { s["output"] = map[string]any{"leak": map[string]any{"value": "secret"}} },
	} {
		t.Run(name, func(t *testing.T) {
			p, c, x, now := unitArtifactCapture(t)
			source, _ := fixtureObject(x.Configuration, 256<<10)
			mutate(source)
			x.Configuration, _ = json.Marshal(source)
			p.ArtifactContext.ConfigurationSHA256 = BytesDigest(x.Configuration)
			x.GitCommitObject, x.GitTreeObject = unitGitObjects(&p, x.Configuration)
			x.Context = p.ArtifactContext
			c.ParentSHA256 = Digest(p)
			c.Artifact.ContextSHA256 = Digest(p.ArtifactContext)
			x.SavedPlan = unitFixtureContainer(t, x.Configuration, x.BeforeState, nil)
			bindArtifactBytes(&c, x)
			if _, err := ValidateTerraformArtifact(p, c, x, now); err == nil {
				t.Fatal("accepted rehashed committed source")
			}
		})
	}
}

func TestFixtureTerraformNoopAndExpiredOwnedInverseRemainSeparateFromForwardAuthority(t *testing.T) {
	p, c, originalCapture, now := unitArtifactCapture(t)
	prepare := c
	prepare.ID = "prepare-a"
	prepare.Sequence = 1
	prepare.StageID = p.Stages[0].ID
	prepare.StageSHA256 = Digest(p.Stages[0])
	prepare.MinimumObservationSeconds = 0
	prepare.Artifact.After = prepare.Artifact.Before
	_, prepare, prepareCapture, _ := unitCaptureForChild(t, p, prepare, originalCapture.Configuration, now)
	review, err := ValidateTerraformArtifact(p, prepare, prepareCapture, now)
	if err != nil || !review.NoOp || len(review.ChangedAddresses) != 0 {
		t.Fatalf("no-op semantic contract failed: %v", err)
	}
	original := c
	owned := OwnedReceipt{SchemaVersion: SchemaVersion, ID: "owned-artifact-a", CommandID: "command-artifact-a", ParentID: p.ID, ParentSHA256: Digest(p), ChildID: original.ID, ChildSHA256: Digest(original), BindingSHA256: Digest(p.Binding), RealmSHA256: Digest(p.Realm), ArtifactSHA256: Digest(original.Artifact), SavedPlanSHA256: original.Artifact.SavedPlanSHA256, PipelineID: p.ArtifactContext.PipelineID, Outcome: "APPLIED", BeforeStateSerial: 7, AfterStateSerial: 8, AfterModelSHA256: Digest(original.Artifact.After), ReceivedAt: now.Add(time.Second)}
	later := now.Add(7 * time.Hour)
	recovery := original
	recovery.ID = "semantic-recovery-a"
	recovery.Nonce = "semantic-recovery-nonce"
	recovery.Mode = OwnedRecovery
	recovery.Sequence = 3
	recovery.CompensationFor = original.ID
	recovery.OwnedReceiptSHA256 = Digest(owned)
	recovery.CreatedAt = later
	recovery.ExpiresAt = later.Add(10 * time.Minute)
	recovery.Artifact.Before = original.Artifact.After
	recovery.Artifact.After = original.Artifact.Before
	recovery.Artifact.BeforeStateSerial = 8
	recovery.Artifact.Receipt = SnapshotRef{"semantic-recovery-artifact", sha("b")}
	recovery.Evidence = nil
	for _, kind := range []string{"FIXTURE_CURRENT", "FIXTURE_RECOVERY_SLO"} {
		recovery.Evidence = append(recovery.Evidence, EvidenceRef{kind, "recovery-" + strings.ToLower(kind), sha("a"), Digest(p.Binding), Digest(p.Realm), later, later.Add(15 * time.Minute)})
	}
	_, recovery, capture, _ := unitCaptureForChild(t, p, recovery, originalCapture.Configuration, later)
	capture.Recovery = &TerraformRecoveryAuthority{Original: original, Owned: owned}
	if _, err = ValidateTerraformArtifact(p, recovery, capture, later); err != nil {
		t.Fatal("expired parent's exact owned inverse rejected:", err)
	}
	capture.Recovery = nil
	if _, err = ValidateTerraformArtifact(p, recovery, capture, later); err == nil {
		t.Fatal("recovery semantic review without exact ownership")
	}
	capture.Recovery = &TerraformRecoveryAuthority{Original: original, Owned: owned}
	capture.Recovery.Owned.Outcome = "UNKNOWN"
	if _, err = ValidateTerraformArtifact(p, recovery, capture, later); err == nil {
		t.Fatal("unknown effect borrowed APPLIED semantic authority")
	}
}

func TestFixtureTerraformGitObjectClosureRejectsCopiedMetadataOrExtraInputs(t *testing.T) {
	for name, change := range map[string]func(*TerraformArtifactCapture){
		"missing commit":         func(x *TerraformArtifactCapture) { x.GitCommitObject = nil },
		"missing tree":           func(x *TerraformArtifactCapture) { x.GitTreeObject = nil },
		"copied commit metadata": func(x *TerraformArtifactCapture) { x.GitCommitObject = append(x.GitCommitObject, ' ') },
		"copied tree metadata":   func(x *TerraformArtifactCapture) { x.GitTreeObject = append(x.GitTreeObject, 0) },
	} {
		t.Run(name, func(t *testing.T) {
			p, c, x, now := unitArtifactCapture(t)
			change(&x)
			if _, err := ValidateTerraformArtifact(p, c, x, now); err == nil {
				t.Fatal("accepted unbound Git object")
			}
		})
	}
	p, c, x, now := unitArtifactCapture(t)
	x.GitTreeObject = append(x.GitTreeObject, []byte("100644 override.tf.json\x00")...)
	x.GitTreeObject = append(x.GitTreeObject, make([]byte, 20)...)
	p.ArtifactContext.GitTree = gitObjectOID("tree", x.GitTreeObject, 40)
	x.GitCommitObject = []byte("tree " + p.ArtifactContext.GitTree + "\nauthor Fixture <fixture@example.invalid> 1792411200 +0000\n\nextra tracked configuration\n")
	p.ArtifactContext.GitCommit = gitObjectOID("commit", x.GitCommitObject, 40)
	x.Context = p.ArtifactContext
	c.ParentSHA256 = Digest(p)
	c.Artifact.ContextSHA256 = Digest(p.ArtifactContext)
	if _, err := ValidateTerraformArtifact(p, c, x, now); err == nil {
		t.Fatal("accepted rehashed Git tree with additional tracked inputs")
	}
	// Native SHA-256 Git repositories retain their actual object format; never
	// relabel a40-character object ID or silently substitute a SHA-256 source hash.
	p, c, x, now = unitArtifactCapture(t)
	blob, _ := hex.DecodeString(gitObjectOID("blob", x.Configuration, 64))
	x.GitTreeObject = append([]byte("100644 main.tf.json\x00"), blob...)
	p.ArtifactContext.GitTree = gitObjectOID("tree", x.GitTreeObject, 64)
	x.GitCommitObject = []byte("tree " + p.ArtifactContext.GitTree + "\nauthor Fixture <fixture@example.invalid> 1792411200 +0000\n\nSHA256 repository fixture\n")
	p.ArtifactContext.GitCommit = gitObjectOID("commit", x.GitCommitObject, 64)
	x.Context = p.ArtifactContext
	c.ParentSHA256 = Digest(p)
	c.Artifact.ContextSHA256 = Digest(p.ArtifactContext)
	if _, err := ValidateTerraformArtifact(p, c, x, now); err != nil {
		t.Fatal("native SHA256 object closure rejected:", err)
	}
}
