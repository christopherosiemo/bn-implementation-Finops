// Command fleet-group-fixture is a private, credential-free local artifact lab.
// It never waits for or claims acceptance of the real-clock fleet protocol.
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	g "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetgroup"
)

const repository = "/workspace/fixture"
const terraform = "/usr/local/bin/terraform"

var diagnosticArchive *archive

type archive struct {
	key     cipher.AEAD
	runID   string
	objects []object
}
type object struct {
	Child        string `json:"child_id"`
	Kind         string `json:"kind"`
	Path         string `json:"path"`
	PlainSHA256  string `json:"plain_sha256"`
	CipherSHA256 string `json:"cipher_sha256"`
	Size         int    `json:"plain_size"`
	AAD          string `json:"aad"`
}

func require(ok bool, message string) {
	if !ok {
		panic(message)
	}
}
func must(err error) {
	if err != nil {
		panic(err)
	}
}
func exactJSON(v any) []byte { raw, err := json.Marshal(v); must(err); return raw }
func read(name string) []byte {
	raw, err := os.ReadFile(name)
	must(err)
	require(len(raw) > 0 && len(raw) <= 64<<20, "artifact bounds invalid")
	return raw
}
func write(name string, raw []byte) { must(os.WriteFile(name, raw, 0600)) }
func command(binary string, args ...string) []byte {
	c := exec.Command(binary, args...)
	c.Dir = repository
	c.Env = []string{"PATH=/usr/local/bin:/usr/bin:/bin", "HOME=/tmp/home", "LANG=C", "LC_ALL=C", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_SYSTEM=/dev/null", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_TERMINAL_PROMPT=0", "GIT_NO_LAZY_FETCH=1", "CHECKPOINT_DISABLE=1", "TF_IN_AUTOMATION=1", "TF_INPUT=0", "TF_DATA_DIR=/workspace/data", "TF_CLI_CONFIG_FILE=/workspace/terraform.rc"}
	var stderr bytes.Buffer
	c.Stderr = &stderr
	raw, err := c.Output()
	if err != nil {
		diagnostic := append(append(raw, '\n'), stderr.Bytes()...)
		if diagnosticArchive != nil && len(diagnostic) > 0 && len(diagnostic) <= 64<<20 {
			diagnosticArchive.put("failure", "command-output", diagnostic)
		}
		panic("isolated command failed: " + filepath.Base(binary) + " " + args[0])
	}
	require(len(raw) <= 64<<20, "command output bounds invalid")
	return raw
}
func git(args ...string) string {
	return strings.TrimSpace(string(command("/usr/bin/git", append([]string{"-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", "-c", "diff.external=", "-c", "core.attributesFile=/dev/null"}, args...)...)))
}

func (a *archive) put(child, kind string, raw []byte) {
	require(len(raw) > 0 && len(raw) <= 64<<20, "archive bounds invalid")
	plainHash := g.BytesDigest(raw)
	aad := exactJSON(map[string]string{"schema_version": "1", "realm": "ISOLATED_FIXTURE", "run_id": a.runID, "child_id": child, "kind": kind, "plain_sha256": plainHash})
	nonce := make([]byte, a.key.NonceSize())
	_, err := rand.Read(nonce)
	must(err)
	sealed := append(nonce, a.key.Seal(nil, nonce, raw, aad)...)
	name := child + "." + kind + ".aesgcm"
	f, err := os.OpenFile(filepath.Join("/results", name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	must(err)
	_, err = f.Write(sealed)
	must(err)
	must(f.Sync())
	must(f.Close())
	stored := read(filepath.Join("/results", name))
	require(bytes.Equal(stored, sealed), "encrypted pinned readback changed")
	opened, err := a.key.Open(nil, stored[:a.key.NonceSize()], stored[a.key.NonceSize():], aad)
	must(err)
	require(bytes.Equal(opened, raw), "encrypted plaintext readback changed")
	wrong := append([]byte(nil), aad...)
	wrong[0] ^= 1
	_, err = a.key.Open(nil, stored[:a.key.NonceSize()], stored[a.key.NonceSize():], wrong)
	require(err != nil, "encrypted context was not bound")
	tampered := append([]byte(nil), stored...)
	tampered[len(tampered)-1] ^= 1
	_, err = a.key.Open(nil, tampered[:a.key.NonceSize()], tampered[a.key.NonceSize():], aad)
	require(err != nil, "encrypted tampering was not detected")
	a.objects = append(a.objects, object{child, kind, name, plainHash, g.BytesDigest(stored), len(raw), string(aad)})
	// Hash/context metadata is retained separately from ciphertext so even a
	// failed capture can be authenticated and decrypted by its private owner.
	// No plaintext artifact values or key are written to this append-only index.
	index, err := os.OpenFile("/results/object-index.jsonl", os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
	must(err)
	_, err = index.Write(append(exactJSON(a.objects[len(a.objects)-1]), '\n'))
	must(err)
	must(index.Sync())
	must(index.Close())
}

type nativeState struct {
	Version          int    `json:"version"`
	TerraformVersion string `json:"terraform_version"`
	Serial           uint64 `json:"serial"`
	Lineage          string `json:"lineage"`
	Resources        []struct {
		Mode, Type, Name string
		Instances        []struct {
			Attributes struct {
				Input struct {
					Value json.RawMessage `json:"value"`
				} `json:"input"`
			} `json:"attributes"`
		} `json:"instances"`
	} `json:"resources"`
}

func state(raw []byte, p g.Program) (nativeState, g.ModelState) {
	var s nativeState
	must(json.Unmarshal(raw, &s))
	require(s.Version == 4 && s.TerraformVersion == "1.16.0" && s.Lineage != "" && len(s.Resources) == 3, "native state header/resource closure invalid")
	model := g.ModelState{BindingSHA256: g.Digest(p.Binding), RealmSHA256: g.Digest(p.Realm)}
	seen := map[string]bool{}
	for _, r := range s.Resources {
		require(r.Mode == "managed" && r.Type == "terraform_data" && !seen[r.Name] && len(r.Instances) == 1, "native state model resource invalid")
		seen[r.Name] = true
		var input map[string]any
		d := json.NewDecoder(bytes.NewReader(r.Instances[0].Attributes.Input.Value))
		d.UseNumber()
		must(d.Decode(&input))
		require(input["binding_sha256"] == g.Digest(p.Binding) && input["realm_sha256"] == g.Digest(p.Realm), "native state group/realm changed")
		count := func(key string) int {
			n, ok := input[key].(json.Number)
			require(ok, "native state count missing")
			v, err := strconv.Atoi(string(n))
			must(err)
			return v
		}
		switch r.Name {
		case "old", "candidate":
			require(len(input) == 9, "native capacity model field closure changed")
			selection, template := p.Binding.Old, p.OldTemplate
			if r.Name == "candidate" {
				selection, template = p.Binding.Candidate, p.CandidateTemplate
			}
			require(input["asg_arn"] == selection.Target.ASGARN && input["registration_id"] == selection.Registration.ID && input["launch_template_id"] == template.ID && input["instance_type"] == template.InstanceType && input["template_sha256"] == template.SHA256 && count("launch_template_version") == int(template.Version), "native capacity model binding changed")
			if r.Name == "old" {
				model.OldCount = count("desired_count")
			} else {
				model.CandidateCount = count("desired_count")
			}
		case "traffic":
			require(len(input) == 5 && input["old_asg_arn"] == p.Binding.Old.Target.ASGARN && input["candidate_asg_arn"] == p.Binding.Candidate.Target.ASGARN, "native traffic model binding changed")
			model.CandidateTrafficPercent = count("candidate_percent")
		default:
			panic("native state contains undeclared resource")
		}
	}
	return s, model
}

func fixtureProgram(runID, imageID string, now time.Time) g.Program {
	hash := func(value string) string { return g.BytesDigest([]byte(value)) }
	selection := func(name, uuid string) g.Selection {
		return g.Selection{Target: g.GroupTarget{TenantID: "fixture-tenant", WorkloadID: "fixture-workload", Provider: "AWS", AccountID: "123456789012", Region: "eu-west-1", FleetID: "fixture-" + name, ASGARN: "arn:aws:autoscaling:eu-west-1:123456789012:autoScalingGroup:" + uuid + ":autoScalingGroupName/fixture-" + name}, Registration: g.VersionedRef{ID: "fixture-registration-" + name, Version: 1, SHA256: hash("registration-" + name)}, Declaration: g.VersionedRef{ID: "fixture-declaration-" + name, Version: 1, SHA256: hash("declaration-" + name)}, Scope: g.SnapshotRef{ID: "fixture-scope-" + name, SHA256: hash("scope-" + name)}, SourceID: "fixture-source", SourceRegistrationVersion: 1, SourceConfigSHA256: hash("fixture-source")}
	}
	p := g.Program{SchemaVersion: g.SchemaVersion, Kind: g.Kind, ID: "fixture-program-" + runID, Binding: g.Binding{Old: selection("old", "11111111-1111-1111-1111-111111111111"), Candidate: selection("candidate", "22222222-2222-2222-2222-222222222222")}, Realm: g.Realm{Kind: g.IsolatedFixture, FixtureID: "local-terraform-component", Generation: runID, ModelSHA256: hash("builtin-three-resource-fixture-v1")}, CreatorID: "fixture-creator", Environment: "NON_PRODUCTION", Policy: g.Policy{ID: "fixture-policy", Version: 1, SHA256: hash("fixture-policy"), ApproverRole: g.ApproverRole}, OldTemplate: g.Template{ID: "lt-12345678", Version: 1, InstanceType: "m6i.large", SHA256: hash("old-template")}, CandidateTemplate: g.Template{ID: "lt-87654321", Version: 1, InstanceType: "m6i.medium", SHA256: hash("candidate-template")}, Budget: g.ModelBudget{CostBasis: g.FixtureModelCost, Currency: "USD", BaselineCount: 20, MaxInFlight: 2, MaxUnavailable: 0, MaxBlastRadiusPPM: 100000, MaxSurgeCount: 20, OldHourlyCost: "0.5", CandidateHourlyCost: "0.3", MaximumModelCost: "100", MaximumDurationSeconds: 21600}, Stages: g.DefaultStages(20), CreatedAt: now, ExpiresAt: now.Add(8 * time.Hour), Nonce: "fixture-parent-" + runID}
	p.ArtifactContext = g.ArtifactContext{Kind: g.BuiltinFixtureArtifact, ProviderSource: g.BuiltinProvider, RepositoryID: "local-committed-fixture", ToolchainImageSHA256: strings.TrimPrefix(imageID, "sha256:"), TerraformVersion: "1.16.0", PipelineID: "local-fixture-pipeline", Workspace: "default", StateLineage: "initial", Mapping: g.ModelMapping{OldDeclaredASG: "aws_autoscaling_group.old", CandidateDeclaredASG: "aws_autoscaling_group.candidate", DeclaredListenerRule: "aws_lb_listener_rule.workload", OldModel: "terraform_data.old", CandidateModel: "terraform_data.candidate", TrafficModel: "terraform_data.traffic"}}
	return p
}

func main() {
	defer func() {
		if reason := recover(); reason != nil {
			fmt.Fprintln(os.Stderr, "isolated fleet artifact component failed; raw command output withheld; diagnostic:", reason)
			os.Exit(1)
		}
	}()
	runID, imageID := os.Getenv("FLEET_FIXTURE_RUN_ID"), os.Getenv("FLEET_FIXTURE_IMAGE_ID")
	require(len(os.Args) == 1 && len(runID) == 36 && strings.HasPrefix(imageID, "sha256:") && len(imageID) == 71, "fixture identity invalid")
	for _, key := range []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_ROLE_ARN", "GOOGLE_APPLICATION_CREDENTIALS", "AZURE_CLIENT_SECRET", "TF_TOKEN_app_terraform_io"} {
		require(os.Getenv(key) == "", "cloud credential rejected")
	}
	require(os.Getuid() != 0, "fixture runtime must be unprivileged")
	entries, err := os.ReadDir("/workspace")
	must(err)
	require(len(entries) == 0, "fresh tmpfs workspace required")
	must(os.MkdirAll(repository, 0700))
	must(os.MkdirAll("/workspace/private", 0700))
	must(os.MkdirAll("/tmp/home", 0700))
	write("/workspace/terraform.rc", []byte("provider_installation { direct { exclude = [\"*/*\"] } }\n"))
	key := read("/secrets/key")
	require(len(key) == 32, "local fixture encryption key invalid")
	block, err := aes.NewCipher(key)
	must(err)
	aead, err := cipher.NewGCM(block)
	must(err)
	archive := &archive{key: aead, runID: runID}
	diagnosticArchive = archive
	var version struct {
		TerraformVersion string `json:"terraform_version"`
		Platform         string `json:"platform"`
	}
	must(json.Unmarshal(command(terraform, "version", "-json"), &version))
	require(version.TerraformVersion == "1.16.0", "unexpected Terraform binary")
	require(version.Platform == runtime.GOOS+"_"+runtime.GOARCH, "actual Terraform platform differs from tooling runtime")
	p := fixtureProgram(runID, imageID, time.Now().UTC())
	configuration, err := g.FixtureConfiguration(p)
	must(err)
	write(filepath.Join(repository, "main.tf.json"), configuration)
	git("init", "--initial-branch=main")
	git("config", "user.name", "Local fixture")
	git("config", "user.email", "fixture@example.invalid")
	git("add", "--", "main.tf.json")
	git("commit", "--message", "Committed isolated three-resource model")
	p.ArtifactContext.GitCommit = git("rev-parse", "HEAD")
	p.ArtifactContext.GitTree = git("rev-parse", p.ArtifactContext.GitCommit+"^{tree}")
	p.ArtifactContext.ConfigurationSHA256 = g.BytesDigest(configuration)
	gitCommitObject := command("/usr/bin/git", "cat-file", "commit", p.ArtifactContext.GitCommit)
	gitTreeObject := command("/usr/bin/git", "cat-file", "tree", p.ArtifactContext.GitTree)
	checkGit := func() {
		require(git("rev-parse", "HEAD") == p.ArtifactContext.GitCommit && git("rev-parse", p.ArtifactContext.GitCommit+"^{tree}") == p.ArtifactContext.GitTree, "Git commit/tree changed")
		require(git("ls-tree", "-r", "--name-only", p.ArtifactContext.GitCommit) == "main.tf.json", "committed input closure changed")
		require(bytes.Equal(command("/usr/bin/git", "cat-file", "blob", p.ArtifactContext.GitCommit+":main.tf.json"), configuration) && bytes.Equal(read(filepath.Join(repository, "main.tf.json")), configuration), "configuration bytes changed")
		index := strings.Fields(git("ls-files", "--stage"))
		require(len(index) == 4 && index[0] == "100644" && index[2] == "0" && index[3] == "main.tf.json", "index closure changed")
		require(index[1] == git("rev-parse", p.ArtifactContext.GitCommit+":main.tf.json"), "index differs from committed blob")
		require(bytes.Equal(command("/usr/bin/git", "cat-file", "commit", p.ArtifactContext.GitCommit), gitCommitObject) && bytes.Equal(command("/usr/bin/git", "cat-file", "tree", p.ArtifactContext.GitTree), gitTreeObject), "actual Git objects changed")
	}
	checkGit()
	command(terraform, "init", "-backend=false", "-input=false", "-no-color")
	p.ArtifactContext.Workspace = strings.TrimSpace(string(command(terraform, "workspace", "show")))
	require(p.ArtifactContext.Workspace == "default", "unexpected native workspace")
	statePath, planPath, varsPath := "/workspace/private/current.tfstate", "/workspace/private/next.tfplan", "/workspace/private/inputs.tfvars.json"
	current := g.ModelState{BindingSHA256: g.Digest(p.Binding), RealmSHA256: g.Digest(p.Realm), OldCount: 20}
	inputs := func(m g.ModelState) {
		write(varsPath, exactJSON(map[string]int{"old_count": m.OldCount, "candidate_count": m.CandidateCount, "candidate_traffic_percent": m.CandidateTrafficPercent}))
	}
	inputs(current)
	command(terraform, "apply", "-auto-approve", "-input=false", "-no-color", "-state="+statePath, "-var-file="+varsPath)
	initial, initialModel := state(read(statePath), p)
	require(initialModel == current, "initial model differs")
	p.ArtifactContext.StateLineage, p.ArtifactContext.InitialStateSerial = initial.Lineage, initial.Serial
	for _, kind := range []string{"FIXTURE_HISTORY", "FIXTURE_DEMAND", "FIXTURE_CAPACITY", "FIXTURE_CONFIGURATION", "FIXTURE_DEPENDENCY", "FIXTURE_SLO", "FIXTURE_ECONOMICS"} {
		p.Evidence = append(p.Evidence, g.EvidenceRef{Kind: kind, ID: "synthetic-" + strings.ToLower(kind), SHA256: g.BytesDigest([]byte("synthetic " + kind)), BindingSHA256: g.Digest(p.Binding), RealmSHA256: g.Digest(p.Realm), ObservedAt: p.CreatedAt, ValidUntil: p.ExpiresAt})
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	must(err)
	approval := g.Approval{ID: "local-independent-fixture-approval", TenantID: p.Binding.Old.Target.TenantID, ActorID: "fixture-approver", Role: g.ApproverRole, ProgramSHA256: g.Digest(p), RealmSHA256: g.Digest(p.Realm), ApprovedAt: time.Now().UTC()}
	parent, err := g.Sign(p, []g.Approval{approval}, priv, time.Now().UTC())
	must(err)
	must(g.Verify(parent, pub, g.Expected{Binding: p.Binding, Realm: p.Realm}, time.Now().UTC()))
	archive.put("parent", "envelope", exactJSON(parent))
	archive.put("parent", "configuration", configuration)
	archive.put("parent", "initial-state", read(statePath))
	archive.put("parent", "git-commit-object", gitCommitObject)
	archive.put("parent", "git-tree-object", gitTreeObject)
	sequence, observationSeconds, tamperChecks := 0, int64(0), 0
	apply := func(stageIndex, old, candidate, traffic int, seconds int64) {
		sequence++
		checkGit()
		beforeRaw := read(statePath)
		before, observedBefore := state(beforeRaw, p)
		require(before.Lineage == p.ArtifactContext.StateLineage && observedBefore == current, "current state drifted")
		after := g.ModelState{BindingSHA256: current.BindingSHA256, RealmSHA256: current.RealmSHA256, OldCount: old, CandidateCount: candidate, CandidateTrafficPercent: traffic}
		inputs(after)
		command(terraform, "plan", "-input=false", "-no-color", "-state="+statePath, "-var-file="+varsPath, "-out="+planPath)
		planRaw := read(planPath)
		planJSON := command(terraform, "show", "-json", planPath)
		now := time.Now().UTC()
		childID := fmt.Sprintf("child-%02d", sequence)
		artifactHash := g.Digest(map[string]string{"run_id": runID, "child_id": childID, "configuration_sha256": g.BytesDigest(configuration), "context_sha256": g.Digest(p.ArtifactContext), "saved_plan_sha256": g.BytesDigest(planRaw), "plan_json_sha256": g.BytesDigest(planJSON), "before_state_sha256": g.BytesDigest(beforeRaw)})
		child := g.Child{SchemaVersion: g.SchemaVersion, ID: childID, ParentID: p.ID, ParentSHA256: g.Digest(p), BindingSHA256: g.Digest(p.Binding), RealmSHA256: g.Digest(p.Realm), Mode: g.Forward, StageID: p.Stages[stageIndex].ID, StageSHA256: g.Digest(p.Stages[stageIndex]), Sequence: uint64(sequence), Artifact: g.Artifact{Kind: g.BuiltinFixtureArtifact, Receipt: g.SnapshotRef{ID: "local-artifact-" + childID, SHA256: artifactHash}, ContextSHA256: g.Digest(p.ArtifactContext), BeforeStateSerial: before.Serial, BeforeStateSHA256: g.BytesDigest(beforeRaw), SavedPlanSHA256: g.BytesDigest(planRaw), PlanJSONSHA256: g.BytesDigest(planJSON), Before: current, After: after}, MinimumObservationSeconds: seconds, CreatedAt: now, ExpiresAt: now.Add(10 * time.Minute), Nonce: "fixture-nonce-" + childID}
		for _, kind := range []string{"FIXTURE_CURRENT", "FIXTURE_DEPENDENCY", "FIXTURE_SLO"} {
			child.Evidence = append(child.Evidence, g.EvidenceRef{Kind: kind, ID: "synthetic-" + strings.ToLower(kind), SHA256: g.BytesDigest([]byte("synthetic " + kind)), BindingSHA256: g.Digest(p.Binding), RealmSHA256: g.Digest(p.Realm), ObservedAt: now, ValidUntil: now.Add(15 * time.Minute)})
		}
		signed, err := g.SignChild(child, parent, priv, now)
		must(err)
		must(g.VerifyChild(signed, parent, pub, g.Expected{Binding: p.Binding, Realm: p.Realm}, now))
		capture := g.TerraformArtifactCapture{Context: p.ArtifactContext, Configuration: configuration, SavedPlan: planRaw, PlanJSON: planJSON, BeforeState: beforeRaw, GitCommitObject: gitCommitObject, GitTreeObject: gitTreeObject}
		review, err := g.ValidateTerraformArtifact(p, child, capture, now)
		if err != nil {
			archive.put(childID, "saved-plan", planRaw)
			archive.put(childID, "show-json", planJSON)
			archive.put(childID, "before-state", beforeRaw)
		}
		must(err)
		require(review.Status == "FIXTURE_SEMANTICS_MATCHED" && review.ChildSHA256 == g.Digest(child) && review.ProgramSHA256 == g.Digest(p) && review.BindingSHA256 == g.Digest(p.Binding) && review.RealmSHA256 == g.Digest(p.Realm) && review.NoOp == (current == after) && !review.CustomerNativeExecution && review.CustomerVerifiedSaving == nil, "semantic review binding or authority changed")
		if sequence == 2 {
			changed := capture
			changed.SavedPlan = append(append([]byte(nil), planRaw...), byte(0))
			_, err = g.ValidateTerraformArtifact(p, child, changed, now)
			require(err != nil, "different binary plan accepted")
			tamperChecks++
			changed = capture
			changed.BeforeState = append(append([]byte(nil), beforeRaw...), byte(' '))
			_, err = g.ValidateTerraformArtifact(p, child, changed, now)
			require(err != nil, "different exact before state accepted")
			tamperChecks++
			changed = capture
			changed.Configuration = append(append([]byte(nil), configuration...), byte(' '))
			_, err = g.ValidateTerraformArtifact(p, child, changed, now)
			require(err != nil, "different exact committed source accepted")
			tamperChecks++
			changed = capture
			changed.Context.GitCommit = strings.Repeat("f", 40)
			_, err = g.ValidateTerraformArtifact(p, child, changed, now)
			require(err != nil, "different commit accepted")
			tamperChecks++
			var wrongShow map[string]any
			decoder := json.NewDecoder(bytes.NewReader(planJSON))
			decoder.UseNumber()
			must(decoder.Decode(&wrongShow))
			planned := wrongShow["planned_values"].(map[string]any)["root_module"].(map[string]any)["resources"].([]any)
			for _, entry := range planned {
				resource := entry.(map[string]any)
				if resource["address"] == "terraform_data.candidate" {
					resource["values"].(map[string]any)["input"].(map[string]any)["desired_count"] = after.CandidateCount + 1
				}
			}
			changed = capture
			changed.PlanJSON = exactJSON(wrongShow)
			wrongChild := child
			wrongChild.Artifact.PlanJSONSHA256 = g.BytesDigest(changed.PlanJSON)
			_, err = g.ValidateTerraformArtifact(p, wrongChild, changed, now)
			require(err != nil, "rehashed but wrong native planned model accepted")
			tamperChecks++
			changed = capture
			changed.GitTreeObject = append(append([]byte(nil), gitTreeObject...), byte(0))
			_, err = g.ValidateTerraformArtifact(p, child, changed, now)
			require(err != nil, "different actual Git tree object accepted")
			tamperChecks++
		}
		archive.put(childID, "saved-plan", planRaw)
		archive.put(childID, "show-json", planJSON)
		archive.put(childID, "before-state", beforeRaw)
		archive.put(childID, "envelope", exactJSON(signed))
		archive.put(childID, "semantic-review", exactJSON(review))
		checkGit()
		require(bytes.Equal(read(planPath), planRaw) && bytes.Equal(read(statePath), beforeRaw), "plan/state changed at exact apply boundary")
		command(terraform, "apply", "-input=false", "-auto-approve", "-no-color", "-state="+statePath, planPath)
		postRaw := read(statePath)
		post, observedAfter := state(postRaw, p)
		require(post.Lineage == before.Lineage && observedAfter == after, "actual applied result differs from signed model")
		if current == after {
			require(post.Serial == before.Serial, "no-op prepare changed state serial")
		} else {
			require(post.Serial > before.Serial, "applied state serial failed to advance")
		}
		archive.put(childID, "after-state", postRaw)
		current = after
		observationSeconds += seconds
	}
	apply(0, 20, 0, 0, 0)
	for i := 1; i < 5; i++ {
		for current.CandidateCount < p.Stages[i].TargetCandidateCount {
			apply(i, current.OldCount, min(current.CandidateCount+2, p.Stages[i].TargetCandidateCount), current.CandidateTrafficPercent, 120)
		}
		apply(i, current.OldCount, current.CandidateCount, p.Stages[i].TargetTrafficPercent, p.Stages[i].MinimumObservationSeconds)
	}
	for current.OldCount > 0 {
		old := max(0, current.OldCount-2)
		seconds := int64(120)
		if old == 0 {
			seconds = p.Stages[5].MinimumObservationSeconds
		}
		apply(5, old, 20, 100, seconds)
	}
	require(sequence == 26 && observationSeconds == 9600 && current.OldCount == 0 && current.CandidateCount == 20 && current.CandidateTrafficPercent == 100 && tamperChecks == 6, "full component transition algebra incomplete")
	archive.put("manifest", "object-index", exactJSON(archive.objects))
	result := map[string]any{"schema_version": "1", "status": "PASS", "scope": "ISOLATED_FIXTURE_ARTIFACT_COMPONENT", "child_count": sequence, "exact_saved_plan_applies": sequence, "semantic_attestor_calls": sequence, "negative_tamper_checks": tamperChecks, "encrypted_objects": len(archive.objects), "encrypted_readback": true, "git_commit": p.ArtifactContext.GitCommit, "git_tree": p.ArtifactContext.GitTree, "configuration_sha256": p.ArtifactContext.ConfigurationSHA256, "toolchain_image_sha256": p.ArtifactContext.ToolchainImageSHA256, "terraform_version": version.TerraformVersion, "declared_observation_seconds_not_waited": observationSeconds, "real_clock_health_accepted": false, "customer_native_execution": false, "customer_verified_savings": false, "synthetic_refs_resolved_from_025_027": false, "main_stack_accessed": false, "state_lineage": initial.Lineage, "final_model": current}
	result["toolchain_platform"], result["workspace"] = version.Platform, p.ArtifactContext.Workspace
	write("/results/component-result.json", append(exactJSON(result), '\n'))
	fmt.Println("Fleet artifact component: 26 semantic reviews/exact saved-plan applies and authenticated encrypted readbacks; real-clock health NOT executed.")
}
