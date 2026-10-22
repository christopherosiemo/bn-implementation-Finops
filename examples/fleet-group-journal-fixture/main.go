// A private append-only file journal and real Git/Terraform fixture. It does
// not commission PostgreSQL, Temporal, external pipeline identities or health.
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
func requireRefused(run func(), expected string) {
	var refused any
	func() { defer func() { refused = recover() }(); run() }()
	require(refused != nil && fmt.Sprint(refused) == expected, "expected exact private refusal: "+expected)
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
	if binary == terraform {
		// Fsync before subprocess delivery. Reopening a terminal journal never
		// calls Terraform, which is checked against this actual wrapper audit.
		f, err := os.OpenFile("/workspace/private/terraform-invocations.jsonl", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			return nil, err
		}
		_, err = f.Write(append(exactJSON(map[string]any{"arguments": args, "at": time.Now().UTC()}), '\n'))
		if err == nil {
			err = f.Sync()
		}
		closeErr := f.Close()
		if err != nil {
			return nil, err
		}
		if closeErr != nil {
			return nil, closeErr
		}
	}
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
	return advanceGated(previous, target, configuration, previousDesired, targetDesired, nil)
}
func advanceGated(previous, target g.GitRevision, configuration, previousDesired, targetDesired []byte, gate func()) error {
	if err := cleanRevision(previous, configuration, previousDesired); err != nil {
		return err
	}
	if gate != nil {
		gate()
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

func main() {
	defer func() {
		if reason := recover(); reason != nil {
			fmt.Fprintln(os.Stderr, "isolated journal fixture failed; raw artifacts withheld; diagnostic:", reason)
			os.Exit(1)
		}
	}()
	if len(os.Args) == 2 {
		switch os.Args[1] {
		case "--verify-journal", "--probe-writer-lock":
			reopenProcess(os.Args[1])
			return
		case "--apply-and-crash", "--cas-and-crash":
			cutpointProcess(os.Args[1])
			return
		}
		panic("unknown private subprocess mode")
	}
	runID, imageID := os.Getenv("FLEET_JOURNAL_FIXTURE_RUN_ID"), os.Getenv("FLEET_JOURNAL_FIXTURE_IMAGE_ID")
	require(len(os.Args) == 1 && len(runID) == 36 && strings.HasPrefix(imageID, "sha256:") && len(imageID) == 71 && os.Getuid() != 0, "fixture identity invalid")
	for _, entry := range os.Environ() {
		key := strings.SplitN(entry, "=", 2)[0]
		require(!strings.HasPrefix(key, "TF_VAR_") && !strings.HasPrefix(key, "TF_CLI_ARGS") && !strings.HasPrefix(key, "AWS_") && !strings.HasPrefix(key, "AZURE_") && !strings.HasPrefix(key, "GOOGLE_") && !strings.HasPrefix(key, "ARM_"), "ambient authority rejected")
	}
	entries, err := os.ReadDir("/workspace")
	must(err)
	require(len(entries) == 0, "fresh tmpfs required")
	for _, directory := range []string{controlRepository, "/workspace/private/operations", "/tmp/home"} {
		must(os.MkdirAll(directory, 0700))
	}
	write("/tmp/home/.terraformrc", []byte("disable_checkpoint = true\nprovider_installation { direct { exclude = [\"*/*\"] } }\n"))
	key := read("/secrets/key")
	require(len(key) == 32, "private fixture encryption key invalid")
	block, err := aes.NewCipher(key)
	must(err)
	aead, err := cipher.NewGCM(block)
	must(err)
	archive := &archive{key: aead, runID: runID}
	diagnosticArchive = archive
	p := fixtureProgram(runID, imageID, time.Now().UTC())
	p.Realm.FixtureID = "local-file-journal-component"
	p.Realm.ModelSHA256 = g.BytesDigest([]byte("builtin-git-two-file-journal-v1"))
	configuration, err := g.GitFixtureConfiguration(p)
	must(err)
	specs, err := g.GitStageSpecifications(p)
	must(err)
	require(len(specs) == 26, "unexpected immutable manifest population")
	initialDesired, err := g.GitFixtureDesired(p, specs[0].Before)
	must(err)
	gitAt(controlRepository, "init", "--bare", "--initial-branch=proposals")
	base := revision(p, configuration, initialDesired, "", "Committed isolated journal base")
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
			entry.Revision = revision(p, configuration, desired, previous.Commit, fmt.Sprintf("Approved fixture manifest stage %02d", entry.Sequence))
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
	require(version.TerraformVersion == "1.16.0" && version.Platform == runtime.GOOS+"_"+runtime.GOARCH, "native toolchain changed")
	command(terraform, "init", "-backend=false", "-input=false", "-no-color")
	p.ArtifactContext.Workspace = strings.TrimSpace(string(command(terraform, "workspace", "show")))
	require(p.ArtifactContext.Workspace == "default", "workspace changed")
	// This bootstrap creates the initial fixture only. All seven subsequent
	// journal-controlled applies require explicit journal authorization.
	command(terraform, "apply", "-auto-approve", "-input=false", "-no-color", "-state="+statePath)
	initial, model := state(read(statePath), p)
	require(model == specs[0].Before, "initial actual model changed")
	p.ArtifactContext.StateLineage, p.ArtifactContext.InitialStateSerial = initial.Lineage, initial.Serial
	for _, kind := range []string{"FIXTURE_HISTORY", "FIXTURE_DEMAND", "FIXTURE_CAPACITY", "FIXTURE_CONFIGURATION", "FIXTURE_DEPENDENCY", "FIXTURE_SLO", "FIXTURE_ECONOMICS"} {
		p.Evidence = append(p.Evidence, g.EvidenceRef{Kind: kind, ID: "synthetic-" + strings.ToLower(kind), SHA256: g.BytesDigest([]byte("synthetic " + kind)), BindingSHA256: g.Digest(p.Binding), RealmSHA256: g.Digest(p.Realm), ObservedAt: p.CreatedAt, ValidUntil: p.ExpiresAt})
	}
	signerPub, signer, err := ed25519.GenerateKey(rand.Reader)
	must(err)
	pipelinePub, pipeline, err := ed25519.GenerateKey(rand.Reader)
	must(err)
	ledgerPub, ledger, err := ed25519.GenerateKey(rand.Reader)
	must(err)
	keys := g.JournalKeys{Signer: signerPub, Pipeline: pipelinePub, Ledger: ledgerPub}
	now := time.Now().UTC()
	approval := g.Approval{ID: "fixture-parent-approval", TenantID: p.Binding.Old.Target.TenantID, ActorID: "fixture-approver", Role: g.ApproverRole, ProgramSHA256: g.Digest(p), RealmSHA256: g.Digest(p.Realm), ApprovedAt: now}
	parent, err := g.SignGitProgram(p, []g.Approval{approval}, signer, now)
	must(err)
	a := g.JournalAuthorization{SchemaVersion: g.JournalSchemaVersion, Kind: g.JournalKind, ID: "journal-authorization-" + runID, JournalID: "fixture-journal-" + runID, ParentEnvelopeSHA256: g.Digest(parent), ParentSHA256: g.Digest(p), BindingSHA256: g.Digest(p.Binding), RealmSHA256: g.Digest(p.Realm), PipelineID: p.ArtifactContext.PipelineID, Ref: executionRef, Policy: g.JournalPolicy, Base: journalNativeState(p, base), PipelineKeySHA256: g.BytesDigest(pipelinePub), LedgerKeySHA256: g.BytesDigest(ledgerPub), MaximumEffects: 32, MaximumRecords: 512, CreatedAt: now, ExpiresAt: p.ExpiresAt, Nonce: "journal-authorization-nonce-" + runID}
	journalApproval := g.JournalApproval{ID: "fixture-journal-approval", TenantID: p.Binding.Old.Target.TenantID, ActorID: "independent-fixture-journal-approver", Role: g.ApproverRole, AuthorizationSHA256: g.Digest(a), ApprovedAt: time.Now().UTC()}
	_, err = g.SignJournalAuthorization(a, nil, parent, keys, signer, time.Now().UTC())
	require(err != nil, "journal authority granted without independent approval")
	authorization, err := g.SignJournalAuthorization(a, []g.JournalApproval{journalApproval}, parent, keys, signer, time.Now().UTC())
	must(err)
	view, projection, err := g.SealJournalView(parent, authorization, nil, keys, ledger, time.Now().UTC())
	must(err)
	require(projection.Pending == nil && len(projection.Stack) == 0, "journal initialized with fabricated effects")
	disk := newJournalDisk(journalBootstrap{View: view, Signer: signerPub, Pipeline: pipelinePub, Ledger: ledgerPub})
	secrets := fixtureSecrets{Signer: signer, Pipeline: pipeline, Ledger: ledger}
	must(privateExclusive(fixtureSecretsPath, exactJSON(secrets)))
	j := fixtureJournal{disk, keys, secrets}
	for kind, raw := range map[string][]byte{"envelope": exactJSON(parent), "manifest": exactJSON(p.Manifest), "configuration": configuration, "base-desired": initialDesired, "initial-state": read(statePath), "journal-bootstrap": read(filepath.Join(journalDirectory, "bootstrap.json"))} {
		archive.put("parent", kind, raw)
	}
	var thirdApplied g.JournalReceiptEnvelope
	var thirdCommand g.JournalCommand
	for i := 0; i < 4; i++ {
		entry := specs[i]
		q := g.JournalPreparation{Mode: g.Forward, Sequence: entry.Sequence, ManifestEntrySHA256: g.Digest(entry), Revision: entry.Revision, Before: entry.Before, After: entry.After}
		c := j.prepare(q, fmt.Sprintf("journal-forward-%02d", i+1))
		if i == 0 {
			beforeRef := git("rev-parse", executionRef)
			beforeState := g.BytesDigest(read(statePath))
			calls := nativeApplyCount()
			changed := c
			changed.Preparation.Revision = specs[1].Revision
			requireRefused(func() { j.advance(changed) }, "fixture pending command changed")
			require(git("rev-parse", executionRef) == beforeRef && g.BytesDigest(read(statePath)) == beforeState && nativeApplyCount() == calls, "stale preparation mutated Git or native state")
			// Negative-only logical time is an ADDITIONAL refusal after the
			// mandatory actual-clock pre-CAS gate. No future head is persisted
			// or ever used to grant permission; no native expiry time is claimed.
			current, _ := j.current()
			requireRefused(func() {
				j.advanceWithAdditionalRefusal(c, func() {
					actual, _ := j.current()
					expiredAt := g.GitForwardDeadline(p).Add(time.Nanosecond)
					expiredView, _, e := g.SealJournalView(actual.Parent, actual.Authorization, actual.Records, keys, ledger, expiredAt)
					must(e)
					_, expiredErr := g.AuthorizeJournalGitAdvance(expiredView, keys, actual.Head.Head.Ref, g.Digest(c), expiredAt)
					require(expiredErr != nil, "logical expiry probe granted Git permission")
					must(expiredErr)
				})
			}, "JOURNAL_PREPARATION_EXPIRED")
			afterProbe, _ := j.current()
			require(git("rev-parse", executionRef) == beforeRef && g.BytesDigest(read(statePath)) == beforeState && nativeApplyCount() == calls && j.readOperation(c).Status == "NOT_DISPATCHED" && afterProbe.Head.Head.Ref == current.Head.Head.Ref, "expired forward probe changed Git/state/operation/head")
		}
		j.advance(c)
		c = j.finalize(c, archive)
		if i == 0 {
			stale := c
			gitState := atRevision(c.Before, c.Preparation.Revision)
			ready := j.receipt(c, g.JournalReadyToApply, gitState, gitState)
			must(j.commit(g.JournalReadyToApply, nil, &ready, nil))
			c = j.finalize(c, archive, c.ID+"-refinalized")
			j.ready(c)
			beforeRef := git("rev-parse", executionRef)
			beforeState := g.BytesDigest(read(statePath))
			calls := nativeApplyCount()
			head, _ := j.current()
			// Pure expiry check only; the real dispatch uses the actual producer
			// clock. No persisted timestamps or fixture clock are changed.
			_, expiredErr := g.AuthorizeJournalApply(head, keys, head.Head.Head.Ref, g.Digest(c), time.Now().UTC().Add(31*time.Second))
			require(expiredErr != nil && expiredErr.Error() == "JOURNAL_DISPATCH_PERMISSION_EXPIRED", "old intent became delivery permission")
			requireRefused(func() { j.apply(stale, false) }, "fixture pending command changed")
			afterHead, _ := j.current()
			require(git("rev-parse", executionRef) == beforeRef && g.BytesDigest(read(statePath)) == beforeState && nativeApplyCount() == calls && j.readOperation(c).Status == "NOT_DISPATCHED" && head.Head.Head.Ref == afterHead.Head.Head.Ref, "stale finalized command reached delivery")
		} else {
			j.ready(c)
		}
		if i == 3 {
			childProcess(j, "--apply-and-crash", 73)
			v, pending := j.current()
			require(pending.Pending != nil && pending.Pending.Phase == g.JournalUnknown && len(pending.Stack) == 2, "actual uncertain apply lost pending duty")
			archive.put("unknown-checkpoint", "records", read(filepath.Join(journalDirectory, "records.jsonl")))
			archive.put("unknown-checkpoint", "head", exactJSON(v.Head))
			calls := nativeApplyCount()
			head := v.Head.Head.Ref
			result := childProcess(j, "--verify-journal", 0)
			require(result.ProjectionSHA256 == g.Digest(pending) && result.ApplyInvocations == calls && nativeApplyCount() == calls, "UNKNOWN process reopen redispatched or lost duty")
			// A complete before/after observation cannot resolve an operation.
			// No signed terminal has been supplied to this current journal yet.
			other := g.JournalCommand{ID: "unresolved-new-command", OperationID: "unresolved-operation", IdempotencyKey: "unresolved-idempotency", Fence: pending.LastFence + 1, Head: v.Head, Before: pending.Current, Preparation: q, CreatedAt: time.Now().UTC()}
			require(j.commit(g.JournalPreparing, &other, nil, nil) != nil, "UNKNOWN allowed a competing command")
			bad := j.receipt(c, g.JournalNoApply, c.Before, journalNativeState(p, c.Preparation.Revision))
			require(j.commit(g.JournalNoApply, nil, &bad, nil) != nil, "actual applied state misclassified as NO_APPLY")
			v, _ = j.current()
			require(v.Head.Head.Ref == head, "refused UNKNOWN actions changed durable head")
			op := j.readOperation(c)
			require(op.Status == "APPLIED" && op.Terminal != nil, "surviving authenticated terminal receipt missing")
			thirdApplied = *op.Terminal
			thirdCommand = c
			must(j.commit(g.JournalApplied, nil, &thirdApplied, nil))
			afterView, afterProjection := j.current()
			reopened := childProcess(j, "--verify-journal", 0)
			require(reopened.ProjectionSHA256 == g.Digest(afterProjection) && reopened.ApplyInvocations == calls && nativeApplyCount() == calls && afterView.Head.Head.Ref != head, "terminal reconciliation called Terraform again")
			prior := g.Digest(afterProjection)
			must(j.commit(g.JournalApplied, nil, &thirdApplied, nil))
			_, afterProjection = j.current()
			require(g.Digest(afterProjection) == prior, "duplicate terminal callback created another effect")
			conflict := thirdApplied.Receipt
			conflict.After.StateSHA256 = g.BytesDigest([]byte("conflicting same-ID state"))
			signed, e := g.SignJournalReceipt(conflict, pipeline)
			must(e)
			require(j.commit(g.JournalApplied, nil, &signed, nil) != nil, "conflicting terminal callback accepted")
		} else {
			j.apply(c, false)
		}
		archive.put(c.ID, "after-state", read(statePath))
	}
	_, projection = j.current()
	require(len(projection.Stack) == 3 && projection.Pending == nil, "three actual effects not owned")
	// A separate process actually performs the next Git CAS, records it, and
	// exits before any plan or CLI delivery. Reopen preserves the Git duty.
	entry := specs[4]
	q := g.JournalPreparation{Mode: g.Forward, Sequence: entry.Sequence, ManifestEntrySHA256: g.Digest(entry), Revision: entry.Revision, Before: entry.Before, After: entry.After}
	c := j.prepare(q, "journal-cas-cutpoint")
	beforeCasState := read(statePath)
	calls := nativeApplyCount()
	childProcess(j, "--cas-and-crash", 73)
	v, projection := j.current()
	require(projection.Pending != nil && projection.Pending.GitAdvanced && !projection.Pending.ApplyIntent && len(projection.Stack) == 3, "CAS cutpoint did not preserve unissued Git duty")
	reopened := childProcess(j, "--verify-journal", 0)
	require(reopened.ApplyInvocations == calls && reopened.GitCommit == entry.Revision.Commit && bytes.Equal(read(statePath), beforeCasState), "CAS crash invoked apply or changed native state")
	archive.put(c.ID, "cas-cutpoint-head", exactJSON(v.Head))
	j.repair(archive)
	v, projection = j.current()
	require(projection.ForwardAborted && len(projection.Stack) == 3, "Git repair lost owned stack")
	aborted := g.JournalCommand{ID: "after-repair-forward", OperationID: "after-repair-operation", IdempotencyKey: "after-repair-idempotency", Fence: projection.LastFence + 1, Head: v.Head, Before: projection.Current, Preparation: q, CreatedAt: time.Now().UTC()}
	abortErr := j.commit(g.JournalPreparing, &aborted, nil, nil)
	require(abortErr != nil && abortErr.Error() == "JOURNAL_FORWARD_EXPIRED_OR_ABORTED", "Git repair did not permanently block otherwise selected forward preparation")
	// A private trusted-issuer renewal preserves the separately resolved ref.
	oldView, oldProjection := j.current()
	must(j.disk.refresh(ledger, time.Now().UTC()))
	v, projection = j.current()
	require(v.Head.Head.Ref == oldView.Head.Head.Ref && g.Digest(projection) == g.Digest(oldProjection), "head renewal changed obligations")
	for i := 0; i < 3; i++ {
		v, projection = j.current()
		top := projection.Stack[len(projection.Stack)-1]
		desired, e := g.GitFixtureDesired(p, top.Forward.Child.Artifact.Before)
		must(e)
		target := revision(p, configuration, desired, projection.Current.Revision.Commit, fmt.Sprintf("Journal LIFO inverse %d; retain all executed history", i+1))
		q := g.JournalPreparation{Mode: g.JournalRecoveryMode, EffectID: top.ID, Revision: target, Before: projection.Current.Model, After: top.Forward.Child.Artifact.Before}
		c := j.prepare(q, fmt.Sprintf("journal-inverse-%02d", i+1))
		j.advance(c)
		c = j.finalize(c, archive)
		j.ready(c)
		j.apply(c, false)
		archive.put(c.ID, "after-state", read(statePath))
		_, updated := j.current()
		require(len(updated.Stack) == 2-i && len(updated.Consumed) == i+1, "inverse did not consume exactly one current top")
		// Replaying the old signed APPLIED receipt cannot revive consumed duty.
		prior := g.Digest(updated)
		must(j.commit(g.JournalApplied, nil, &top.Applied, nil))
		_, updated = j.current()
		require(g.Digest(updated) == prior, "old APPLIED callback revived consumed ownership")
		bad := c.Preparation
		bad.EffectID = top.ID
		v, updated = j.current()
		duplicate := g.JournalCommand{ID: fmt.Sprintf("duplicate-inverse-%02d", i+1), OperationID: fmt.Sprintf("duplicate-operation-%02d", i+1), IdempotencyKey: fmt.Sprintf("duplicate-key-%02d", i+1), Fence: updated.LastFence + 1, Head: v.Head, Before: updated.Current, Preparation: bad, CreatedAt: time.Now().UTC()}
		require(j.commit(g.JournalPreparing, &duplicate, nil, nil) != nil, "consumed effect authorized another inverse")
	}
	v, projection = j.current()
	require(projection.Pending == nil && len(projection.Stack) == 0 && len(projection.Consumed) == 3 && len(projection.GitRepairs) == 1 && projection.ForwardAborted && projection.Current.Model == specs[0].Before, "journal final LIFO/repair state incomplete")
	require(journalNativeState(p, projection.Current.Revision) == projection.Current && nativeApplyCount() == 8, "native final model/apply count mismatch")
	// Inverses and Git repair do not reopen forward authority.
	blocked := g.JournalCommand{ID: "aborted-forward", OperationID: "aborted-operation", IdempotencyKey: "aborted-idempotency", Fence: projection.LastFence + 1, Head: v.Head, Before: projection.Current, Preparation: q, CreatedAt: time.Now().UTC()}
	finalAbortErr := j.commit(g.JournalPreparing, &blocked, nil, nil)
	require(finalAbortErr != nil && finalAbortErr.Error() == "JOURNAL_FORWARD_EXPIRED_OR_ABORTED", "permanently aborted program resumed forward")
	lock, e := j.disk.lock()
	must(e)
	probe := childProcess(j, "--probe-writer-lock", 0)
	unlock(lock)
	require(probe.WriterBlocked, "competing writer not excluded")
	storageNegatives := j.disk.negativeStorageChecks(ledger)
	reopened = childProcess(j, "--verify-journal", 0)
	require(reopened.ProjectionSHA256 == g.Digest(projection) && reopened.ApplyInvocations == 8, "final process reopen changed result")
	_ = thirdCommand
	for kind, raw := range map[string][]byte{"records": read(filepath.Join(journalDirectory, "records.jsonl")), "head": read(filepath.Join(journalDirectory, "head.json")), "projection": exactJSON(projection), "terraform-invocations": read("/workspace/private/terraform-invocations.jsonl")} {
		archive.put("journal-final", kind, raw)
	}
	operations, err := os.ReadDir("/workspace/private/operations")
	must(err)
	for _, entry := range operations {
		require(!entry.IsDir() && strings.HasSuffix(entry.Name(), ".json"), "unexpected operation registry file")
		id := strings.TrimSuffix(entry.Name(), ".json")
		archive.put(id, "pipeline-operation", read(operationPath(id)))
	}
	// Subprocesses write no raw retained files; all indexed artifacts are here.
	archive.put("manifest", "object-index", exactJSON(archive.objects))
	result := map[string]any{"schema_version": "1", "status": "PASS", "scope": "ISOLATED_FILE_JOURNAL_COMPONENT", "git_owned_manifest": true, "manifest_sha256": p.ManifestSHA256, "forward_saved_plan_applies": 4, "owned_child_inverse_applies": 3, "exact_saved_plan_applies": 7, "initial_fixture_bootstrap_applies": 1, "fixture_top_effects_consumed": 3, "precommand_journal_authorization": true, "actual_git_cas_cutpoint": true, "terminal_applied_reconciled_without_reapply": true, "unresolved_unknown_held": true, "unknown_later_resolved_by_authenticated_terminal": true, "duplicate_callback_idempotent": true, "conflicting_callback_rejected": true, "consumed_effect_cannot_revive": true, "git_only_repair_zero_apply": true, "git_only_repair_new_commit": true, "git_only_repair_kept_previous_effects": true, "forward_permanently_aborted": true, "stale_preparation_rejected_before_cas": true, "stale_finalization_rejected_before_delivery": true, "torn_tail_rejected": true, "storage_rejection_cases": storageNegatives, "concurrent_writer_rejected": true, "file_journal_process_reopen": true, "pg_runtime_acceptance": false, "customer_pipeline_oidc_acceptance": false, "durable_current_ownership_service": false, "whole_program_rollback_accepted": false, "real_clock_health_accepted": false, "customer_native_execution": false, "customer_verified_savings": false, "synthetic_refs_resolved_from_025_027": false, "main_stack_accessed": false, "encrypted_objects": len(archive.objects), "encrypted_readback": true, "terraform_version": version.TerraformVersion, "toolchain_platform": version.Platform, "workspace": p.ArtifactContext.Workspace, "final_model": projection.Current.Model, "final_commit": projection.Current.Revision.Commit, "journal_record_count": len(v.Records), "final_head": v.Head.Head.Ref, "ref_transition": "ACTUAL_EXPECTED_OLD_VALUE_CAS"}
	result["expired_forward_preparation_boundary_probe_rejected"] = true
	result["expiry_probes_use_logical_negative_time_only"] = true
	write("/results/component-result.json", append(exactJSON(result), '\n'))
	fmt.Println("File journal component: preparation plus three actual owned effects and three NEW-commit LIFO inverses; one no-apply Git-only repair; process reopen and terminal reconciliation checked. No PostgreSQL/runtime or real-clock health acceptance.")
}
