// Package groupfixtureproducer materializes actual local Git and built-in
// Terraform artifacts for a server-selected isolated fixture proposal. It
// contains no cloud adapter, AWS credentials or customer-native execution path.
package groupfixtureproducer

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	ff "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetfixture"
	g "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetgroup"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
)

const (
	workspace       = "/workspace"
	control         = "/workspace/control"
	repository      = "/workspace/fixture"
	executionRef    = "refs/heads/approved"
	proposalRef     = "refs/heads/proposals"
	terraform       = "/usr/local/bin/terraform"
	git             = "/usr/bin/git"
	maxCommandBytes = 16 << 20
)

var ErrBoundary = errors.New("GROUP_FIXTURE_PRODUCER_BOUNDARY_INVALID")
var ErrNative = errors.New("GROUP_FIXTURE_NATIVE_CAPTURE_FAILED")

// Archive must encrypt and authenticate exact versioned object readback before
// returning. It is a private commissioned dependency, never a public upload or
// an assertion that references supplied by a caller are trusted.
type Archive interface {
	Put(context.Context, ff.Proposal, string, []byte) (ff.ArtifactReference, error)
}

// Installation comes from the private producer registry and actual inspected
// process image. Mapping comes from the two current 027 declarations. The
// surrounding worker rechecks those selections before publishing preparation.
type Installation struct {
	ImageSHA256            string
	Mapping                g.ModelMapping
	PipelineKey, LedgerKey ed25519.PublicKey
}

type boundedOutput struct {
	bytes.Buffer
	limit int
}

func (b *boundedOutput) Write(p []byte) (int, error) {
	if len(p) > b.limit-b.Len() {
		return 0, ErrNative
	}
	return b.Buffer.Write(p)
}

func native(ctx context.Context, directory, binary string, input []byte, args ...string) ([]byte, error) {
	if binary != terraform && binary != git {
		return nil, ErrBoundary
	}
	c := exec.CommandContext(ctx, binary, args...)
	c.Dir = directory
	c.Stdin = bytes.NewReader(input)
	c.Env = []string{"PATH=/usr/local/bin:/usr/bin:/bin", "HOME=/tmp/group-fixture-home", "LANG=C", "LC_ALL=C", "TF_IN_AUTOMATION=1", "TF_INPUT=0", "TF_DATA_DIR=/workspace/data"}
	if binary == git {
		c.Env = append(c.Env, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_SYSTEM=/dev/null", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_TERMINAL_PROMPT=0", "GIT_NO_LAZY_FETCH=1", "GIT_NO_REPLACE_OBJECTS=1")
	}
	out, diagnostic := &boundedOutput{limit: maxCommandBytes}, &boundedOutput{limit: 64 << 10}
	c.Stdout, c.Stderr = out, diagnostic
	if binary == terraform {
		if len(args) == 0 {
			return nil, ErrBoundary
		}
		if err := recordTerraformInvocation(args[0]); err != nil {
			return nil, err
		}
	}
	if err := c.Run(); err != nil {
		return nil, ErrNative
	}
	return append([]byte{}, out.Bytes()...), nil
}
func gitCommand(ctx context.Context, directory string, input []byte, args ...string) ([]byte, error) {
	initializing := directory == control && len(args) > 0 && args[0] == "init"
	if err := verifyGitBoundary(initializing); err != nil {
		return nil, err
	}
	fixed := []string{"-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", "-c", "core.attributesFile=/dev/null", "-c", "user.name=Isolated group producer", "-c", "user.email=fixture@example.invalid"}
	return native(ctx, directory, git, input, append(fixed, args...)...)
}
func gitText(ctx context.Context, directory string, input []byte, args ...string) (string, error) {
	raw, err := gitCommand(ctx, directory, input, args...)
	return strings.TrimSpace(string(raw)), err
}
func revision(ctx context.Context, p g.GitProgram, configuration, desired []byte, parent, message string) (g.GitRevision, error) {
	mainBlob, err := gitText(ctx, control, configuration, "hash-object", "-w", "--stdin", "--no-filters")
	if err != nil {
		return g.GitRevision{}, err
	}
	desiredBlob, err := gitText(ctx, control, desired, "hash-object", "-w", "--stdin", "--no-filters")
	if err != nil {
		return g.GitRevision{}, err
	}
	tree, err := gitText(ctx, control, []byte("100644 blob "+desiredBlob+"\t"+g.GitDesiredPath+"\n100644 blob "+mainBlob+"\t"+g.GitMainPath+"\n"), "mktree")
	if err != nil {
		return g.GitRevision{}, err
	}
	args := []string{"commit-tree", tree}
	if parent != "" {
		args = append(args, "-p", parent)
	}
	args = append(args, "-m", message)
	commit, err := gitText(ctx, control, nil, args...)
	return g.GitRevision{Commit: commit, Tree: tree, ConfigurationSHA256: g.BytesDigest(configuration), DesiredSHA256: g.BytesDigest(desired)}, err
}
func cas(ctx context.Context, ref, after, before string) error {
	_, err := gitText(ctx, control, nil, "update-ref", ref, after, before)
	return err
}
func privateFile(path string, raw []byte) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return ErrBoundary
	}
	if _, err = f.Write(raw); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	return closeErr
}
func readPrivate(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > maxCommandBytes {
		return nil, ErrNative
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, ErrNative
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, info.Size()+1))
	if err != nil || int64(len(raw)) != info.Size() {
		return nil, ErrNative
	}
	return raw, nil
}

type stateEnvelope struct {
	Version          int    `json:"version"`
	TerraformVersion string `json:"terraform_version"`
	Serial           uint64 `json:"serial"`
	Lineage          string `json:"lineage"`
	Resources        []struct {
		Mode      string `json:"mode"`
		Type      string `json:"type"`
		Name      string `json:"name"`
		Instances []struct {
			Attributes struct {
				ID    string `json:"id"`
				Input struct {
					Value json.RawMessage `json:"value"`
				} `json:"input"`
			} `json:"attributes"`
		} `json:"instances"`
	} `json:"resources"`
}

func baseState(raw []byte, p g.GitProgram, wanted g.ModelState) (g.JournalState, error) {
	var s stateEnvelope
	if json.Unmarshal(raw, &s) != nil || s.Version != 4 || s.TerraformVersion != "1.16.0" || s.Serial == 0 || s.Lineage == "" || len(s.Resources) != 3 {
		return g.JournalState{}, ErrNative
	}
	inputs, err := g.GitFixtureInputs(p, wanted)
	if err != nil {
		return g.JournalState{}, err
	}
	seen := map[string]bool{}
	for _, r := range s.Resources {
		address := "terraform_data." + r.Name
		expected, ok := inputs[address]
		if !ok || seen[address] || r.Mode != "managed" || r.Type != "terraform_data" || len(r.Instances) != 1 || r.Instances[0].Attributes.ID == "" {
			return g.JournalState{}, ErrNative
		}
		seen[address] = true
		var actual map[string]any
		decoder := json.NewDecoder(bytes.NewReader(r.Instances[0].Attributes.Input.Value))
		decoder.UseNumber()
		if decoder.Decode(&actual) != nil {
			return g.JournalState{}, ErrNative
		}
		a, _ := json.Marshal(actual)
		b, _ := json.Marshal(expected)
		if !bytes.Equal(a, b) {
			return g.JournalState{}, ErrNative
		}
	}
	return g.JournalState{Revision: p.Manifest.Base, StateLineage: s.Lineage, StateSerial: s.Serial, StateSHA256: g.BytesDigest(raw), Model: wanted}, nil
}

// Prepare creates an isolated three-resource LOCAL model before approval. It
// does not execute a journal command or claim that a declared aws_* address has
// been attested. The fixed fresh workspace must be supplied by the bounded lab
// container, with no external network, host socket or customer credentials.
// The producer's private archive may reach its approved isolated object store;
// native subprocesses inherit only the fixed environment above.
func Prepare(ctx context.Context, selected ff.Proposal, installed Installation, archive Archive) (ff.Preparation, error) {
	var result ff.Preparation
	if archive == nil || runtime.GOOS != "linux" || os.Getuid() == 0 || selected.CustomerExecutionAuthorized || selected.EstimatedSaving != nil || selected.VerifiedSaving != nil || installed.ImageSHA256 != selected.Profile.Installation.ToolchainImageSHA256 || len(installed.PipelineKey) != 32 || len(installed.LedgerKey) != 32 || bytes.Equal(installed.PipelineKey, installed.LedgerKey) || g.ValidateBinding(selected.Binding) != nil || g.ValidateRealm(selected.Realm) != nil {
		return result, ErrBoundary
	}
	for _, entry := range os.Environ() {
		key := strings.SplitN(entry, "=", 2)[0]
		for _, prefix := range []string{"AWS_", "AZURE_", "GOOGLE_", "ARM_", "TF_VAR_", "TF_CLI_ARGS"} {
			if strings.HasPrefix(key, prefix) {
				return result, ErrBoundary
			}
		}
	}
	entries, err := os.ReadDir(workspace)
	if err != nil || len(entries) != 0 {
		return result, ErrBoundary
	}
	for _, directory := range []string{control, "/workspace/private", "/tmp/group-fixture-home"} {
		if err = os.MkdirAll(directory, 0700); err != nil {
			return result, ErrBoundary
		}
	}
	if err = privateFile("/tmp/group-fixture-home/.terraformrc", []byte("disable_checkpoint = true\nprovider_installation { direct { exclude = [\"*/*\"] } }\n")); err != nil {
		return result, err
	}
	now := time.Now().UTC()
	p := g.GitProgram{SchemaVersion: g.GitSchemaVersion, Kind: g.Kind, ID: model.ID(), Binding: selected.Binding, Realm: selected.Realm, CreatorID: selected.CreatorID, Environment: "NON_PRODUCTION", Policy: selected.Profile.Model.Policy, OldTemplate: selected.Profile.Model.OldTemplate, CandidateTemplate: selected.Profile.Model.CandidateTemplate, Budget: selected.Profile.Model.Budget, Stages: g.DefaultStages(selected.Profile.Model.Budget.BaselineCount), CreatedAt: now, ExpiresAt: now.Add(8 * time.Hour), Nonce: model.ID()}
	p.ArtifactContext = g.ArtifactContext{Kind: g.BuiltinFixtureArtifact, ProviderSource: g.BuiltinProvider, RepositoryID: selected.ID, ToolchainImageSHA256: installed.ImageSHA256, TerraformVersion: "1.16.0", PipelineID: "fixture-pipeline-" + selected.Profile.Generation, Workspace: "default", StateLineage: "initial", Mapping: installed.Mapping}
	configuration, err := g.GitFixtureConfiguration(p)
	if err != nil {
		return result, err
	}
	specs, err := g.GitStageSpecifications(p)
	if err != nil || len(specs) != 26 {
		return result, ErrBoundary
	}
	initialDesired, err := g.GitFixtureDesired(p, specs[0].Before)
	if err != nil {
		return result, err
	}
	if _, err = gitText(ctx, control, nil, "init", "--bare", "--initial-branch=proposals"); err != nil {
		return result, err
	}
	base, err := revision(ctx, p, configuration, initialDesired, "", "Isolated fixture base before approval")
	if err != nil {
		return result, err
	}
	if err = cas(ctx, proposalRef, base.Commit, strings.Repeat("0", len(base.Commit))); err != nil {
		return result, err
	}
	previous := base
	for i := range specs {
		entry := &specs[i]
		entry.PredecessorCommit = previous.Commit
		if i == 0 {
			entry.Revision = base
		} else {
			desired, err := g.GitFixtureDesired(p, entry.After)
			if err != nil {
				return result, err
			}
			entry.Revision, err = revision(ctx, p, configuration, desired, previous.Commit, fmt.Sprintf("Fixture stage %02d before approval", entry.Sequence))
			if err != nil {
				return result, err
			}
			if err = cas(ctx, proposalRef, entry.Revision.Commit, previous.Commit); err != nil {
				return result, err
			}
		}
		previous = entry.Revision
	}
	p.Manifest = g.GitManifest{SchemaVersion: "1", Ref: executionRef, Base: base, Entries: specs}
	p.ManifestSHA256 = g.Digest(p.Manifest)
	p.ArtifactContext.GitCommit, p.ArtifactContext.GitTree, p.ArtifactContext.ConfigurationSHA256 = base.Commit, base.Tree, base.ConfigurationSHA256
	if err = cas(ctx, executionRef, base.Commit, strings.Repeat("0", len(base.Commit))); err != nil {
		return result, err
	}
	if _, err = gitText(ctx, control, nil, "worktree", "add", repository, "approved"); err != nil {
		return result, err
	}
	var version struct {
		Version  string `json:"terraform_version"`
		Platform string `json:"platform"`
	}
	raw, err := native(ctx, repository, terraform, nil, "version", "-json")
	if err != nil || json.Unmarshal(raw, &version) != nil || version.Version != "1.16.0" || version.Platform != runtime.GOOS+"_"+runtime.GOARCH {
		return result, ErrNative
	}
	if _, err = native(ctx, repository, terraform, nil, "init", "-backend=false", "-input=false", "-no-color"); err != nil {
		return result, err
	}
	if _, err = native(ctx, repository, terraform, nil, "apply", "-auto-approve", "-input=false", "-no-color", "-state="+g.GitFixtureStatePath); err != nil {
		return result, err
	}
	initialState, err := readPrivate(g.GitFixtureStatePath)
	if err != nil {
		return result, err
	}
	state, err := baseState(initialState, p, specs[0].Before)
	if err != nil {
		return result, err
	}
	p.ArtifactContext.StateLineage, p.ArtifactContext.InitialStateSerial = state.StateLineage, state.StateSerial
	// These are explicitly synthetic installed-model receipts, never customer
	// billing/history authority. Their immutable payloads are archived below.
	for _, kind := range []string{"FIXTURE_HISTORY", "FIXTURE_DEMAND", "FIXTURE_CAPACITY", "FIXTURE_CONFIGURATION", "FIXTURE_DEPENDENCY", "FIXTURE_SLO", "FIXTURE_ECONOMICS"} {
		body, _ := json.Marshal(struct{ Kind, Proposal, Generation, Model string }{kind, selected.ID, selected.Profile.Generation, selected.Realm.ModelSHA256})
		ref, err := archive.Put(ctx, selected, kind, body)
		if err != nil || ref.SHA256 != g.BytesDigest(body) || ref.SizeBytes != int64(len(body)) {
			return result, ErrBoundary
		}
		result.Artifacts = append(result.Artifacts, ref)
		p.Evidence = append(p.Evidence, g.EvidenceRef{Kind: kind, ID: ref.ID, SHA256: ref.SHA256, BindingSHA256: g.Digest(p.Binding), RealmSHA256: g.Digest(p.Realm), ObservedAt: now, ValidUntil: p.ExpiresAt})
	}
	result.Program = p
	result.JournalReview = ff.JournalReview{SchemaVersion: "1", Policy: p.Policy, Ref: executionRef, PipelineID: p.ArtifactContext.PipelineID, PipelineKeySHA256: g.BytesDigest(installed.PipelineKey), LedgerKeySHA256: g.BytesDigest(installed.LedgerKey), Base: state, MaxEffects: 32, MaxRecords: 512, ExpiresAt: p.ExpiresAt}
	for _, entry := range specs {
		commitObject, err := gitCommand(ctx, control, nil, "cat-file", "commit", entry.Revision.Commit)
		if err != nil {
			return result, err
		}
		treeObject, err := gitCommand(ctx, control, nil, "cat-file", "tree", entry.Revision.Tree)
		if err != nil {
			return result, err
		}
		desired, err := g.GitFixtureDesired(p, entry.After)
		if err != nil {
			return result, err
		}
		result.GitProofs = append(result.GitProofs, ff.GitProof{Revision: entry.Revision, CommitObject: commitObject, TreeObject: treeObject, Configuration: configuration, DesiredVariables: desired})
	}
	proofs, err := ff.ProofBytes(result.GitProofs)
	if err != nil {
		return result, err
	}
	for _, item := range []struct {
		kind string
		raw  []byte
	}{{"GIT_PROOF_SET", proofs}, {"BASE_NATIVE_STATE", initialState}} {
		ref, err := archive.Put(ctx, selected, item.kind, item.raw)
		if err != nil || ref.SHA256 != g.BytesDigest(item.raw) || ref.SizeBytes != int64(len(item.raw)) {
			return result, ErrBoundary
		}
		result.Artifacts = append(result.Artifacts, ref)
	}
	if err = ff.ValidatePreparation(selected, result, time.Now().UTC()); err != nil {
		return result, err
	}
	return result, nil
}

// FixedPaths lets the isolated harness attest exact mount closure without
// accepting an alternate workspace or native binary from a request.
func FixedPaths() []string {
	return []string{workspace, control, repository, filepath.Dir(g.GitFixtureStatePath), terraform, git}
}
