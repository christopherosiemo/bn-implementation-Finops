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

const controlRepository = "/workspace/control"
const executionRef = "refs/heads/approved"
const proposalRef = "refs/heads/proposals"

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
func terraformEnvironment() []string {
	return []string{"PATH=/usr/local/bin:/usr/bin:/bin", "HOME=/tmp/home", "LANG=C", "LC_ALL=C", "TF_IN_AUTOMATION=1", "TF_INPUT=0", "TF_DATA_DIR=/workspace/data"}
}
func nativeCommand(directory, binary string, input []byte, args ...string) ([]byte, error) {
	c := exec.Command(binary, args...)
	c.Dir = directory
	c.Stdin = bytes.NewReader(input)
	c.Env = terraformEnvironment()
	if binary != "/usr/local/bin/terraform" {
		c.Env = append(c.Env, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_SYSTEM=/dev/null", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_TERMINAL_PROMPT=0", "GIT_NO_LAZY_FETCH=1")
	}
	var stderr bytes.Buffer
	c.Stderr = &stderr
	raw, err := c.Output()
	if err != nil {
		return append(append(raw, '\n'), stderr.Bytes()...), err
	}
	return raw, nil
}
func command(binary string, args ...string) []byte {
	raw, err := nativeCommand(repository, binary, nil, args...)
	if err != nil {
		if diagnosticArchive != nil && len(raw) > 0 && len(raw) <= 64<<20 {
			diagnosticArchive.put("failure", "command-output", raw)
		}
		panic("isolated command failed: " + filepath.Base(binary) + " " + args[0])
	}
	require(len(raw) <= 64<<20, "command bounds invalid")
	return raw
}
func gitRaw(directory string, input []byte, args ...string) []byte {
	raw, err := nativeCommand(directory, "/usr/bin/git", input, append([]string{"-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", "-c", "core.attributesFile=/dev/null", "-c", "user.name=Local Git fixture", "-c", "user.email=fixture@example.invalid"}, args...)...)
	if err != nil {
		if diagnosticArchive != nil && len(raw) > 0 {
			diagnosticArchive.put("failure", "git-output", raw)
		}
		panic("isolated Git failed: " + args[0])
	}
	return raw
}
func gitAt(directory string, args ...string) string {
	return strings.TrimSpace(string(gitRaw(directory, nil, args...)))
}
func git(args ...string) string { return gitAt(repository, args...) }
func casRef(directory, ref, target, expected string) error {
	_, err := nativeCommand(directory, "/usr/bin/git", nil, "-c", "core.hooksPath=/dev/null", "update-ref", ref, target, expected)
	return err
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

func state(raw []byte, p g.GitProgram) (nativeState, g.ModelState) {
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

func fixtureProgram(runID, imageID string, now time.Time) g.GitProgram {
	hash := func(value string) string { return g.BytesDigest([]byte(value)) }
	selection := func(name, uuid string) g.Selection {
		return g.Selection{Target: g.GroupTarget{TenantID: "fixture-tenant", WorkloadID: "fixture-workload", Provider: "AWS", AccountID: "123456789012", Region: "eu-west-1", FleetID: "fixture-" + name, ASGARN: "arn:aws:autoscaling:eu-west-1:123456789012:autoScalingGroup:" + uuid + ":autoScalingGroupName/fixture-" + name}, Registration: g.VersionedRef{ID: "fixture-registration-" + name, Version: 1, SHA256: hash("registration-" + name)}, Declaration: g.VersionedRef{ID: "fixture-declaration-" + name, Version: 1, SHA256: hash("declaration-" + name)}, Scope: g.SnapshotRef{ID: "fixture-scope-" + name, SHA256: hash("scope-" + name)}, SourceID: "fixture-source", SourceRegistrationVersion: 1, SourceConfigSHA256: hash("fixture-source")}
	}
	p := g.GitProgram{SchemaVersion: g.GitSchemaVersion, Kind: g.Kind, ID: "fixture-program-" + runID, Binding: g.Binding{Old: selection("old", "11111111-1111-1111-1111-111111111111"), Candidate: selection("candidate", "22222222-2222-2222-2222-222222222222")}, Realm: g.Realm{Kind: g.IsolatedFixture, FixtureID: "local-terraform-component", Generation: runID, ModelSHA256: hash("builtin-three-resource-fixture-v1")}, CreatorID: "fixture-creator", Environment: "NON_PRODUCTION", Policy: g.Policy{ID: "fixture-policy", Version: 1, SHA256: hash("fixture-policy"), ApproverRole: g.ApproverRole}, OldTemplate: g.Template{ID: "lt-12345678", Version: 1, InstanceType: "m6i.large", SHA256: hash("old-template")}, CandidateTemplate: g.Template{ID: "lt-87654321", Version: 1, InstanceType: "m6i.medium", SHA256: hash("candidate-template")}, Budget: g.ModelBudget{CostBasis: g.FixtureModelCost, Currency: "USD", BaselineCount: 20, MaxInFlight: 2, MaxUnavailable: 0, MaxBlastRadiusPPM: 100000, MaxSurgeCount: 20, OldHourlyCost: "0.5", CandidateHourlyCost: "0.3", MaximumModelCost: "100", MaximumDurationSeconds: 21600}, Stages: g.DefaultStages(20), CreatedAt: now, ExpiresAt: now.Add(8 * time.Hour), Nonce: "fixture-parent-" + runID}
	p.ArtifactContext = g.ArtifactContext{Kind: g.BuiltinFixtureArtifact, ProviderSource: g.BuiltinProvider, RepositoryID: "local-committed-fixture", ToolchainImageSHA256: strings.TrimPrefix(imageID, "sha256:"), TerraformVersion: "1.16.0", PipelineID: "local-fixture-pipeline", Workspace: "default", StateLineage: "initial", Mapping: g.ModelMapping{OldDeclaredASG: "aws_autoscaling_group.old", CandidateDeclaredASG: "aws_autoscaling_group.candidate", DeclaredListenerRule: "aws_lb_listener_rule.workload", OldModel: "terraform_data.old", CandidateModel: "terraform_data.candidate", TrafficModel: "terraform_data.traffic"}}
	return p
}

func revision(p g.GitProgram, configuration, desired []byte, parent, message string) g.GitRevision {
	mainBlob := strings.TrimSpace(string(gitRaw(controlRepository, configuration, "hash-object", "-w", "--stdin", "--no-filters")))
	desiredBlob := strings.TrimSpace(string(gitRaw(controlRepository, desired, "hash-object", "-w", "--stdin", "--no-filters")))
	treeInput := []byte("100644 blob " + desiredBlob + "\t" + g.GitDesiredPath + "\n100644 blob " + mainBlob + "\t" + g.GitMainPath + "\n")
	tree := strings.TrimSpace(string(gitRaw(controlRepository, treeInput, "mktree")))
	args := []string{"commit-tree", tree}
	if parent != "" {
		args = append(args, "-p", parent)
	}
	args = append(args, "-m", message)
	commit := gitAt(controlRepository, args...)
	return g.GitRevision{Commit: commit, Tree: tree, ConfigurationSHA256: g.BytesDigest(configuration), DesiredSHA256: g.BytesDigest(desired)}
}

func cleanRevision(expected g.GitRevision, configuration, desired []byte) error {
	if git("rev-parse", "HEAD") != expected.Commit || git("symbolic-ref", "HEAD") != executionRef || git("rev-parse", executionRef) != expected.Commit || git("rev-parse", expected.Commit+"^{tree}") != expected.Tree {
		return fmt.Errorf("fixture Git ref changed")
	}
	if git("rev-parse", "--show-toplevel") != repository || git("rev-parse", "--git-common-dir") != controlRepository {
		return fmt.Errorf("fixture Git repository changed")
	}
	allowed := map[string]bool{".git": true, g.GitMainPath: true, g.GitDesiredPath: true, ".terraform.lock.hcl": true}
	entries, err := os.ReadDir(repository)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		info, e := os.Lstat(filepath.Join(repository, entry.Name()))
		if e != nil {
			return e
		}
		if !allowed[entry.Name()] || !info.Mode().IsRegular() {
			return fmt.Errorf("unapproved fixture input")
		}
	}
	if !bytes.Equal(read(filepath.Join(repository, g.GitMainPath)), configuration) || !bytes.Equal(read(filepath.Join(repository, g.GitDesiredPath)), desired) || g.BytesDigest(configuration) != expected.ConfigurationSHA256 || g.BytesDigest(desired) != expected.DesiredSHA256 {
		return fmt.Errorf("fixture worktree changed")
	}
	if raw, err := os.ReadFile(filepath.Join(repository, ".terraform.lock.hcl")); err == nil {
		if string(bytes.TrimSpace(raw)) != "# This file is maintained automatically by \"terraform init\".\n# Manual edits may be lost in future updates." {
			return fmt.Errorf("unapproved provider lock")
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	index := strings.Split(git("ls-files", "--stage"), "\n")
	if len(index) != 2 {
		return fmt.Errorf("fixture index changed")
	}
	for _, line := range index {
		parts := strings.Fields(line)
		if len(parts) != 4 || parts[0] != "100644" || parts[2] != "0" || (parts[3] != g.GitMainPath && parts[3] != g.GitDesiredPath) || parts[1] != git("rev-parse", expected.Commit+":"+parts[3]) {
			return fmt.Errorf("fixture index changed")
		}
	}
	return nil
}

func advance(previous, target g.GitRevision, configuration, previousDesired, targetDesired []byte) error {
	if err := cleanRevision(previous, configuration, previousDesired); err != nil {
		return err
	}
	if err := casRef(repository, executionRef, target.Commit, previous.Commit); err != nil {
		return err
	}
	// Two-tree read-tree refuses changes to an edited tracked file; it does not
	// force-reset/checkout over manual work. Unrelated edits are also caught by
	// the complete closure before and after this native Git operation.
	_, err := nativeCommand(repository, "/usr/bin/git", nil, "-c", "core.hooksPath=/dev/null", "read-tree", "-u", "-m", previous.Commit, target.Commit)
	if err != nil {
		return err
	}
	return cleanRevision(target, configuration, targetDesired)
}

func currentState(raw []byte, p g.GitProgram, expectedSHA string, expectedModel g.ModelState) (nativeState, error) {
	if g.BytesDigest(raw) != expectedSHA {
		return nativeState{}, fmt.Errorf("current state bytes changed")
	}
	native, model := state(raw, p)
	if native.Lineage != p.ArtifactContext.StateLineage || model != expectedModel {
		return nativeState{}, fmt.Errorf("current state lineage or model changed")
	}
	return native, nil
}

func rejectNativeStalePlan(configuration, desired, beforeRaw []byte, mainStatePath string, archive *archive) {
	const probe = "/workspace/stale-probe"
	must(os.Mkdir(probe, 0700))
	defer func() { must(os.RemoveAll(probe)); must(os.RemoveAll("/workspace/stale-probe-data")) }()
	write(filepath.Join(probe, g.GitMainPath), configuration)
	write(filepath.Join(probe, g.GitDesiredPath), desired)
	probeState, probePlan := filepath.Join(probe, "current.tfstate"), filepath.Join(probe, "stale.tfplan")
	write(probeState, beforeRaw)
	run := func(args ...string) ([]byte, error) {
		c := exec.Command(terraform, args...)
		c.Dir = probe
		c.Env = terraformEnvironment()
		for i, value := range c.Env {
			if strings.HasPrefix(value, "TF_DATA_DIR=") {
				c.Env[i] = "TF_DATA_DIR=/workspace/stale-probe-data"
			}
		}
		return c.CombinedOutput()
	}
	_, err := run("init", "-backend=false", "-input=false", "-no-color")
	must(err)
	_, err = run("plan", "-input=false", "-no-color", "-refresh=false", "-state="+probeState, "-out="+probePlan)
	must(err)
	planBytes := read(probePlan)
	var modified map[string]any
	decoder := json.NewDecoder(bytes.NewReader(beforeRaw))
	decoder.UseNumber()
	must(decoder.Decode(&modified))
	serial, err := strconv.ParseUint(string(modified["serial"].(json.Number)), 10, 64)
	must(err)
	modified["serial"] = serial + 1
	changedState := exactJSON(modified)
	write(probeState, changedState)
	output, applyErr := run("apply", "-input=false", "-auto-approve", "-no-color", "-state="+probeState, probePlan)
	archive.put("stale-probe", "saved-plan", planBytes)
	archive.put("stale-probe", "before-state", beforeRaw)
	archive.put("stale-probe", "changed-clone-state", changedState)
	archive.put("stale-probe", "rejected-apply-output", output)
	require(applyErr != nil && bytes.Contains(output, []byte("Saved plan is stale")), "native Terraform did not reject stale saved plan")
	require(bytes.Equal(read(probePlan), planBytes) && bytes.Equal(read(probeState), changedState), "rejected stale apply changed owned probe state or plan")
	require(bytes.Equal(read(mainStatePath), beforeRaw), "native stale probe touched forward model state")
}

func main() {
	defer func() {
		if reason := recover(); reason != nil {
			fmt.Fprintln(os.Stderr, "isolated Git fleet artifact failed; raw command output withheld; diagnostic:", reason)
			os.Exit(1)
		}
	}()
	runID, imageID := os.Getenv("FLEET_GIT_FIXTURE_RUN_ID"), os.Getenv("FLEET_GIT_FIXTURE_IMAGE_ID")
	require(len(os.Args) == 1 && len(runID) == 36 && strings.HasPrefix(imageID, "sha256:") && len(imageID) == 71 && os.Getuid() != 0, "fixture identity invalid")
	for _, entry := range os.Environ() {
		key := strings.SplitN(entry, "=", 2)[0]
		require(!strings.HasPrefix(key, "TF_VAR_") && !strings.HasPrefix(key, "TF_CLI_ARGS") && !strings.HasPrefix(key, "AWS_") && !strings.HasPrefix(key, "AZURE_") && !strings.HasPrefix(key, "GOOGLE_") && !strings.HasPrefix(key, "ARM_"), "ambient authority or variable override rejected")
	}
	entries, err := os.ReadDir("/workspace")
	must(err)
	require(len(entries) == 0, "fresh tmpfs required")
	must(os.MkdirAll(controlRepository, 0700))
	must(os.MkdirAll("/workspace/private", 0700))
	must(os.MkdirAll("/tmp/home", 0700))
	write("/tmp/home/.terraformrc", []byte("disable_checkpoint = true\nprovider_installation { direct { exclude = [\"*/*\"] } }\n"))
	key := read("/secrets/key")
	require(len(key) == 32, "private fixture key invalid")
	block, err := aes.NewCipher(key)
	must(err)
	aead, err := cipher.NewGCM(block)
	must(err)
	archive := &archive{key: aead, runID: runID}
	diagnosticArchive = archive
	p := fixtureProgram(runID, imageID, time.Now().UTC())
	p.Realm.FixtureID = "local-git-terraform-component"
	p.Realm.ModelSHA256 = g.BytesDigest([]byte("builtin-git-two-file-fixture-5.1"))
	configuration, err := g.GitFixtureConfiguration(p)
	must(err)
	specs, err := g.GitStageSpecifications(p)
	must(err)
	require(len(specs) == 26, "unexpected forward manifest size")
	current := specs[0].Before
	initialDesired, err := g.GitFixtureDesired(p, current)
	must(err)
	gitAt(controlRepository, "init", "--bare", "--initial-branch=proposals")
	base := revision(p, configuration, initialDesired, "", "Committed isolated two-file base")
	must(casRef(controlRepository, proposalRef, base.Commit, strings.Repeat("0", len(base.Commit))))
	previous := base
	for i := range specs {
		entry := &specs[i]
		entry.PredecessorCommit = previous.Commit
		if i == 0 {
			entry.Revision = base
		} else {
			desired, e := g.GitFixtureDesired(p, entry.After)
			must(e)
			entry.Revision = revision(p, configuration, desired, previous.Commit, fmt.Sprintf("Approved fixture stage %02d", entry.Sequence))
			must(casRef(controlRepository, proposalRef, entry.Revision.Commit, previous.Commit))
		}
		previous = entry.Revision
	}
	p.Manifest = g.GitManifest{SchemaVersion: "1", Ref: executionRef, Base: base, Entries: specs}
	p.ManifestSHA256 = g.Digest(p.Manifest)
	p.ArtifactContext.GitCommit, p.ArtifactContext.GitTree, p.ArtifactContext.ConfigurationSHA256 = base.Commit, base.Tree, base.ConfigurationSHA256
	must(casRef(controlRepository, executionRef, base.Commit, strings.Repeat("0", len(base.Commit))))
	gitAt(controlRepository, "worktree", "add", repository, "approved")
	must(cleanRevision(base, configuration, initialDesired))
	var version struct {
		TerraformVersion string `json:"terraform_version"`
		Platform         string `json:"platform"`
	}
	must(json.Unmarshal(command(terraform, "version", "-json"), &version))
	require(version.TerraformVersion == "1.16.0" && version.Platform == runtime.GOOS+"_"+runtime.GOARCH, "unexpected native Terraform toolchain")
	command(terraform, "init", "-backend=false", "-input=false", "-no-color")
	p.ArtifactContext.Workspace = strings.TrimSpace(string(command(terraform, "workspace", "show")))
	require(p.ArtifactContext.Workspace == "default", "unexpected workspace")
	const statePath = "/workspace/private/current.tfstate"
	const planPath = "/workspace/private/next.tfplan"
	command(terraform, "apply", "-auto-approve", "-input=false", "-no-color", "-state="+statePath)
	initial, initialModel := state(read(statePath), p)
	require(initialModel == current, "initial actual model mismatch")
	p.ArtifactContext.StateLineage, p.ArtifactContext.InitialStateSerial = initial.Lineage, initial.Serial
	for _, kind := range []string{"FIXTURE_HISTORY", "FIXTURE_DEMAND", "FIXTURE_CAPACITY", "FIXTURE_CONFIGURATION", "FIXTURE_DEPENDENCY", "FIXTURE_SLO", "FIXTURE_ECONOMICS"} {
		p.Evidence = append(p.Evidence, g.EvidenceRef{Kind: kind, ID: "synthetic-" + strings.ToLower(kind), SHA256: g.BytesDigest([]byte("synthetic " + kind)), BindingSHA256: g.Digest(p.Binding), RealmSHA256: g.Digest(p.Realm), ObservedAt: p.CreatedAt, ValidUntil: p.ExpiresAt})
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	must(err)
	approvedAt := time.Now().UTC()
	approval := g.Approval{ID: "local-fixture-approval", TenantID: p.Binding.Old.Target.TenantID, ActorID: "fixture-approver", Role: g.ApproverRole, ProgramSHA256: g.Digest(p), RealmSHA256: g.Digest(p.Realm), ApprovedAt: approvedAt}
	parent, err := g.SignGitProgram(p, []g.Approval{approval}, priv, approvedAt)
	must(err)
	must(g.VerifyGitProgram(parent, pub, g.Expected{Binding: p.Binding, Realm: p.Realm}, approvedAt))
	archive.put("parent", "envelope", exactJSON(parent))
	archive.put("parent", "manifest", exactJSON(p.Manifest))
	archive.put("parent", "configuration", configuration)
	archive.put("parent", "base-desired", initialDesired)
	archive.put("parent", "initial-state", read(statePath))
	currentRevision, currentDesired, currentStateSHA := base, initialDesired, g.BytesDigest(read(statePath))
	negativeChecks, applies, observationSeconds := 0, 0, int64(0)
	var lastSigned g.GitChildEnvelope
	var lastApplied g.GitOwnedReceipt
	var lastOwnership g.GitOwnership
	forwardsTerminal := current
	for step := 0; step < 27; step++ {
		recovery := step == 26
		entry := specs[min(step, 25)]
		target := entry.Revision
		after := entry.After
		if recovery {
			after = lastSigned.Child.Artifact.Before
			desired, e := g.GitFixtureDesired(p, after)
			must(e)
			target = revision(p, configuration, desired, currentRevision.Commit, "Owned exact inverse of final child; retain forward history")
			must(casRef(controlRepository, proposalRef, target.Commit, currentRevision.Commit))
		}
		targetDesired, e := g.GitFixtureDesired(p, after)
		must(e)
		must(cleanRevision(currentRevision, configuration, currentDesired))
		beforeRaw := read(statePath)
		before, e := currentState(beforeRaw, p, currentStateSHA, current)
		must(e)
		if step == 1 {
			// A manual ref move must make the actual expected-old-value Git CAS
			// fail. Only this test actor undoes its own unissued edit afterward.
			foreign := specs[len(specs)-1].Revision.Commit
			must(casRef(repository, executionRef, foreign, currentRevision.Commit))
			require(casRef(repository, executionRef, target.Commit, currentRevision.Commit) != nil, "manual Git ref overwritten")
			require(git("rev-parse", executionRef) == foreign, "failed CAS changed manual ref")
			must(casRef(repository, executionRef, currentRevision.Commit, foreign))
			negativeChecks++
			write(filepath.Join(repository, g.GitMainPath), append(append([]byte(nil), configuration...), byte(' ')))
			require(cleanRevision(currentRevision, configuration, currentDesired) != nil, "changed configuration accepted")
			write(filepath.Join(repository, g.GitMainPath), configuration)
			negativeChecks++
			write(filepath.Join(repository, "terraform.tfvars"), []byte("old_count = 999\n"))
			require(cleanRevision(currentRevision, configuration, currentDesired) != nil, "untracked variable override accepted")
			must(os.Remove(filepath.Join(repository, "terraform.tfvars")))
			negativeChecks++
			var altered map[string]any
			decoder := json.NewDecoder(bytes.NewReader(beforeRaw))
			decoder.UseNumber()
			must(decoder.Decode(&altered))
			altered["serial"] = before.Serial + 1
			write(statePath, exactJSON(altered))
			_, driftErr := currentState(read(statePath), p, currentStateSHA, current)
			require(driftErr != nil, "state drift not rejected")
			write(statePath, beforeRaw)
			negativeChecks++
			rejectNativeStalePlan(configuration, targetDesired, beforeRaw, statePath, archive)
			negativeChecks++
		}
		if recovery {
			lastOwnership = g.GitOwnership{ID: "fixture-current-ownership", Version: 1, Status: "OWNED", CommandID: lastApplied.CommandID, ParentSHA256: g.Digest(p), ChildSHA256: g.Digest(lastSigned.Child), ReceiptSHA256: g.Digest(lastApplied), BindingSHA256: g.Digest(p.Binding), RealmSHA256: g.Digest(p.Realm), Revision: currentRevision, StateLineage: before.Lineage, StateSerial: before.Serial, StateSHA256: g.BytesDigest(beforeRaw), Model: current, ObservedAt: time.Now().UTC(), ValidUntil: time.Now().UTC().Add(15 * time.Minute)}
		}
		refBefore := git("rev-parse", executionRef)
		must(advance(currentRevision, target, configuration, currentDesired, targetDesired))
		refAfter := git("rev-parse", executionRef)
		planArgs := []string{"plan", "-input=false", "-no-color", "-refresh=false", "-state=" + statePath, "-out=" + planPath}
		command(terraform, planArgs...)
		planRaw, show := read(planPath), command(terraform, "show", "-json", planPath)
		now := time.Now().UTC()
		id := fmt.Sprintf("git-child-%02d", step+1)
		minimum := entry.MinimumObservationSeconds
		mode := g.Forward
		if recovery {
			minimum = 120
			mode = g.OwnedRecovery
		}
		artifactHash := g.Digest(map[string]string{"child_id": id, "manifest_sha256": p.ManifestSHA256, "revision": target.Commit, "saved_plan_sha256": g.BytesDigest(planRaw), "plan_json_sha256": g.BytesDigest(show), "before_state_sha256": g.BytesDigest(beforeRaw)})
		child := g.GitChild{SchemaVersion: g.GitSchemaVersion, ID: id, ParentID: p.ID, ParentSHA256: g.Digest(p), BindingSHA256: g.Digest(p.Binding), RealmSHA256: g.Digest(p.Realm), Mode: mode, StageID: entry.StageID, StageSHA256: entry.StageSHA256, Sequence: uint64(step + 1), Artifact: g.GitArtifact{Kind: g.BuiltinFixtureArtifact, Receipt: g.SnapshotRef{ID: "fixture-artifact-" + id, SHA256: artifactHash}, BaseContextSHA256: g.Digest(p.ArtifactContext), ManifestSHA256: p.ManifestSHA256, PreviousRevision: currentRevision, Revision: target, BeforeStateSerial: before.Serial, BeforeStateSHA256: g.BytesDigest(beforeRaw), SavedPlanSHA256: g.BytesDigest(planRaw), PlanJSONSHA256: g.BytesDigest(show), Before: current, After: after}, MinimumObservationSeconds: minimum, CreatedAt: now, ExpiresAt: now.Add(10 * time.Minute), Nonce: "nonce-" + id}
		kinds := []string{"FIXTURE_CURRENT", "FIXTURE_DEPENDENCY", "FIXTURE_SLO"}
		if recovery {
			kinds = []string{"FIXTURE_CURRENT", "FIXTURE_RECOVERY_SLO"}
			child.CompensationFor = lastSigned.Child.ID
			child.OwnedReceiptSHA256 = g.Digest(lastApplied)
			child.OwnershipSHA256 = g.Digest(lastOwnership)
		} else {
			child.Artifact.ManifestEntrySHA256 = g.Digest(entry)
		}
		for _, kind := range kinds {
			child.Evidence = append(child.Evidence, g.EvidenceRef{Kind: kind, ID: "synthetic-" + strings.ToLower(kind), SHA256: g.BytesDigest([]byte("synthetic " + kind)), BindingSHA256: g.Digest(p.Binding), RealmSHA256: g.Digest(p.Realm), ObservedAt: now, ValidUntil: now.Add(15 * time.Minute)})
		}
		var signed g.GitChildEnvelope
		if recovery {
			signed, err = g.SignGitRecovery(child, lastSigned, parent, lastApplied, lastOwnership, priv, now)
			must(err)
			must(g.VerifyGitRecovery(signed, lastSigned, parent, lastApplied, lastOwnership, pub, g.Expected{Binding: p.Binding, Realm: p.Realm}, now))
		} else {
			signed, err = g.SignGitChild(child, parent, priv, now)
			must(err)
			must(g.VerifyGitChild(signed, parent, pub, g.Expected{Binding: p.Binding, Realm: p.Realm}, now))
		}
		environmentKeys := []string{}
		for _, setting := range terraformEnvironment() {
			environmentKeys = append(environmentKeys, strings.SplitN(setting, "=", 2)[0])
		}
		capture := g.GitTerraformArtifactCapture{Context: p.ArtifactContext, Revision: target, Ref: executionRef, RefBefore: refBefore, RefAfter: refAfter, Configuration: configuration, DesiredVariables: targetDesired, SavedPlan: planRaw, PlanJSON: show, BeforeState: beforeRaw, GitCommitObject: gitRaw(repository, nil, "cat-file", "commit", target.Commit), GitTreeObject: gitRaw(repository, nil, "cat-file", "tree", target.Tree), Invocation: g.GitPlanInvocation{Arguments: planArgs, EnvironmentKeys: environmentKeys}}
		if recovery {
			capture.Recovery = &g.GitTerraformRecoveryAuthority{Original: lastSigned.Child, Applied: lastApplied, Ownership: lastOwnership}
		}
		review, reviewErr := g.ValidateGitTerraformArtifact(p, child, capture, now)
		archive.put(id, "saved-plan", planRaw)
		archive.put(id, "show-json", show)
		archive.put(id, "before-state", beforeRaw)
		archive.put(id, "desired", targetDesired)
		archive.put(id, "git-commit", capture.GitCommitObject)
		archive.put(id, "git-tree", capture.GitTreeObject)
		must(reviewErr)
		require(review.Status == "FIXTURE_GIT_SEMANTICS_MATCHED" && review.ProgramSHA256 == g.Digest(p) && review.ChildSHA256 == g.Digest(child) && review.BindingSHA256 == g.Digest(p.Binding) && review.RealmSHA256 == g.Digest(p.Realm) && review.NoOp == (current == after) && !review.CustomerNativeExecution && review.CustomerVerifiedSaving == nil, "artifact review binding or authority changed")
		if step == 1 {
			changed := capture
			changed.DesiredVariables = append(append([]byte(nil), targetDesired...), byte(' '))
			_, e = g.ValidateGitTerraformArtifact(p, child, changed, now)
			require(e != nil, "uncommitted desired bytes accepted")
			negativeChecks++
			changed = capture
			changed.Invocation.Arguments = append(append([]string(nil), planArgs...), "-var=old_count=99")
			_, e = g.ValidateGitTerraformArtifact(p, child, changed, now)
			require(e != nil, "CLI variable override accepted")
			negativeChecks++
		}
		archive.put(id, "envelope", exactJSON(signed))
		archive.put(id, "semantic-review", exactJSON(review))
		must(cleanRevision(target, configuration, targetDesired))
		require(bytes.Equal(read(planPath), planRaw) && bytes.Equal(read(statePath), beforeRaw), "plan or state changed at exact apply boundary")
		command(terraform, "apply", "-input=false", "-auto-approve", "-no-color", "-state="+statePath, planPath)
		postRaw := read(statePath)
		post, postModel := state(postRaw, p)
		require(post.Lineage == before.Lineage && postModel == after, "actual applied model changed")
		if current == after {
			require(post.Serial == before.Serial, "no-op changed serial")
		} else {
			require(post.Serial > before.Serial, "actual serial failed to advance")
		}
		archive.put(id, "after-state", postRaw)
		applies++
		if !recovery {
			observationSeconds += minimum
			lastSigned = signed
			lastApplied = g.GitOwnedReceipt{SchemaVersion: g.GitSchemaVersion, ID: "fixture-applied-" + id, CommandID: "fixture-command-" + id, ParentSHA256: g.Digest(p), ChildSHA256: g.Digest(child), ArtifactSHA256: g.Digest(child.Artifact), SavedPlanSHA256: child.Artifact.SavedPlanSHA256, BeforeGitCommit: currentRevision.Commit, AfterGitCommit: target.Commit, BeforeStateSerial: before.Serial, AfterStateSerial: post.Serial, AfterStateSHA256: g.BytesDigest(postRaw), AfterModelSHA256: g.Digest(after), PipelineID: p.ArtifactContext.PipelineID, Outcome: "APPLIED", ReceivedAt: time.Now().UTC()}
			archive.put(id, "fixture-applied", exactJSON(lastApplied))
		}
		current, currentRevision, currentDesired, currentStateSHA = after, target, targetDesired, g.BytesDigest(postRaw)
		if step == 25 {
			forwardsTerminal = current
		}
	}
	require(applies == 27 && negativeChecks == 7 && observationSeconds == 9600 && forwardsTerminal.OldCount == 0 && forwardsTerminal.CandidateCount == 20 && current.OldCount == 2 && current.CandidateCount == 20, "component sequence incomplete")
	archive.put("recovery", "fixture-ownership", exactJSON(lastOwnership))
	archive.put("manifest", "object-index", exactJSON(archive.objects))
	result := map[string]any{"schema_version": "1", "status": "PASS", "scope": "ISOLATED_GIT_5_1_ARTIFACT_COMPONENT", "git_owned_manifest": true, "manifest_sha256": p.ManifestSHA256, "child_count": 26, "forward_saved_plan_applies": 26, "owned_child_inverse_applies": 1, "exact_saved_plan_applies": applies, "owned_inverse_new_commit": true, "whole_program_rollback_accepted": false, "real_clock_health_accepted": false, "durable_current_ownership_service": false, "ownership_consumed": false, "customer_native_execution": false, "customer_verified_savings": false, "synthetic_refs_resolved_from_025_027": false, "main_stack_accessed": false, "encrypted_objects": len(archive.objects), "encrypted_readback": true, "negative_tamper_checks": negativeChecks, "declared_observation_seconds_not_waited": observationSeconds, "terraform_version": version.TerraformVersion, "toolchain_platform": version.Platform, "workspace": p.ArtifactContext.Workspace, "forward_terminal_model": forwardsTerminal, "final_model_after_one_child_inverse": current, "base_commit": base.Commit, "recovery_new_commit": currentRevision.Commit, "retained_forward_commits": len(specs), "ref_transition": "ACTUAL_EXPECTED_OLD_VALUE_CAS", "unknown_apply_reconciliation_accepted": false}
	result["native_stale_plan_rejection"], result["native_stale_probe_apply_attempts"] = true, 1
	write("/results/component-result.json", append(exactJSON(result), '\n'))
	fmt.Println("Git 5.1 artifact component: 26 forward exact saved-plan applies plus one owned child's NEW-commit inverse; whole-program recovery and real-clock health NOT accepted.")
}
