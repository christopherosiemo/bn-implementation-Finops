package groupfixtureproducer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	ff "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetfixture"
	g "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetgroup"
)

var ErrUncertain = errors.New("GROUP_FIXTURE_OPERATION_REQUIRES_RECONCILIATION")

type ReadableArchive interface {
	Archive
	Read(context.Context, ff.Proposal, string, ff.ArtifactReference) ([]byte, error)
}

// NativeStage is a private Linux fixture worker. The caller must have committed
// the matching one-shot PostgreSQL delivery claim and resolved this view/keys
// under the current ledger fence. Browser data and an outbox label alone cannot
// supply that authority. This worker additionally fences its actual native files.
type NativeStage struct {
	selected ff.Proposal
	prepared ff.Preparation
	archive  ReadableArchive
}

// NativeOutcome is a private terminal observation, not a public callback. The
// independent pipeline signs it only after exact encrypted readback and a
// fresh native inspection under the same isolated operation fence.
type NativeOutcome struct {
	CommandSHA256 string               `json:"command_sha256"`
	Before        g.JournalState       `json:"before"`
	After         g.JournalState       `json:"after"`
	Artifact      ff.ArtifactReference `json:"artifact"`
}

type nativeCaptureTerminal struct {
	CaptureSHA256 string `json:"capture_sha256"`
	CommandSHA256 string `json:"command_sha256"`
	OperationID   string `json:"operation_id"`
	Fence         uint64 `json:"fence"`
	Before, After g.JournalState
}

type NotDispatchedProof struct {
	SchemaVersion  string         `json:"schema_version"`
	ProgramSHA256  string         `json:"program_sha256"`
	JournalID      string         `json:"journal_id"`
	CommandSHA256  string         `json:"command_sha256"`
	OperationID    string         `json:"operation_id"`
	Fence          uint64         `json:"fence"`
	CaptureSHA256  string         `json:"capture_sha256"`
	RegistrySHA256 string         `json:"registry_sha256"`
	Current        g.JournalState `json:"current"`
	ObservedAt     time.Time      `json:"observed_at"`
	ValidUntil     time.Time      `json:"valid_until"`
}

func nativeBoundary() error {
	if runtime.GOOS != "linux" || os.Getuid() == 0 {
		return ErrBoundary
	}
	for _, entry := range os.Environ() {
		key := strings.SplitN(entry, "=", 2)[0]
		for _, prefix := range []string{"AWS_", "AZURE_", "GOOGLE_", "GCP_", "ARM_", "TF_VAR_", "TF_CLI_ARGS", "TF_TOKEN_", "DOCKER_"} {
			if strings.HasPrefix(key, prefix) {
				return ErrBoundary
			}
		}
	}
	return nil
}

func OpenNativeStage(ctx context.Context, selected ff.Proposal, prepared ff.Preparation, archive ReadableArchive) (*NativeStage, error) {
	if nativeBoundary() != nil || archive == nil || selected.CustomerExecutionAuthorized || selected.EstimatedSaving != nil || selected.VerifiedSaving != nil {
		return nil, ErrBoundary
	}
	if err := verifyGitBoundary(false); err != nil {
		return nil, err
	}
	// Historical materialization is checked at its actual creation time. Reopen
	// must remain possible after forward expiry for already owned restoration;
	// fresh dispatch authorization is independently mandatory at each operation.
	if err := ff.ValidatePreparation(selected, prepared, prepared.Program.CreatedAt); err != nil {
		return nil, err
	}
	proofBytes, err := ff.ProofBytes(prepared.GitProofs)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for _, ref := range prepared.Artifacts {
		kind := ""
		for _, evidence := range prepared.Program.Evidence {
			if evidence.ID == ref.ID && evidence.SHA256 == ref.SHA256 {
				kind = evidence.Kind
			}
		}
		if ref.SHA256 == g.BytesDigest(proofBytes) {
			kind = "GIT_PROOF_SET"
		}
		if ref.SHA256 == prepared.JournalReview.Base.StateSHA256 {
			kind = "BASE_NATIVE_STATE"
		}
		if kind == "" || seen[kind] {
			return nil, ErrBoundary
		}
		raw, e := archive.Read(ctx, selected, kind, ref)
		if e != nil || g.BytesDigest(raw) != ref.SHA256 || int64(len(raw)) != ref.SizeBytes {
			return nil, ErrArchive
		}
		if kind == "GIT_PROOF_SET" && !bytes.Equal(raw, proofBytes) {
			return nil, ErrArchive
		}
		if kind == "BASE_NATIVE_STATE" {
			state, e := baseState(raw, prepared.Program, prepared.JournalReview.Base.Model)
			if e != nil || state != prepared.JournalReview.Base {
				return nil, ErrArchive
			}
		}
		seen[kind] = true
	}
	if len(seen) != 9 || !seen["BASE_NATIVE_STATE"] || !seen["GIT_PROOF_SET"] {
		return nil, ErrArchive
	}
	for _, directory := range []string{workspace, control, repository, "/workspace/private"} {
		info, err := os.Lstat(directory)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, ErrBoundary
		}
	}
	return &NativeStage{selected, prepared, archive}, nil
}

func (n *NativeStage) locked(fn func() error) error {
	if n == nil || nativeBoundary() != nil {
		return ErrBoundary
	}
	f, err := os.OpenFile("/workspace/private/native.lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return ErrBoundary
	}
	defer f.Close()
	if err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return ErrUncertain
	}
	defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	return fn()
}

func (n *NativeStage) inspect(ctx context.Context, revision g.GitRevision, wanted g.ModelState) (g.JournalState, error) {
	p := n.prepared.Program
	ref, err := gitText(ctx, control, nil, "rev-parse", "--verify", executionRef)
	if err != nil || ref != revision.Commit {
		return g.JournalState{}, ErrNative
	}
	commit, err := gitText(ctx, repository, nil, "rev-parse", "--verify", "HEAD")
	if err != nil || commit != revision.Commit {
		return g.JournalState{}, ErrNative
	}
	status, err := gitText(ctx, repository, nil, "status", "--porcelain", "--untracked-files=all")
	if err != nil || status != "" {
		return g.JournalState{}, ErrNative
	}
	configuration, err := readPrivate(filepath.Join(repository, g.GitMainPath))
	if err != nil || g.BytesDigest(configuration) != revision.ConfigurationSHA256 {
		return g.JournalState{}, ErrNative
	}
	desired, err := readPrivate(filepath.Join(repository, g.GitDesiredPath))
	if err != nil || g.BytesDigest(desired) != revision.DesiredSHA256 {
		return g.JournalState{}, ErrNative
	}
	raw, err := readPrivate(g.GitFixtureStatePath)
	if err != nil {
		return g.JournalState{}, err
	}
	state, err := baseState(raw, p, wanted)
	if err != nil || state.StateLineage != p.ArtifactContext.StateLineage {
		return g.JournalState{}, ErrNative
	}
	state.Revision = revision
	return state, nil
}

func (n *NativeStage) Inspect(ctx context.Context, revision g.GitRevision, wanted g.ModelState) (state g.JournalState, err error) {
	err = n.locked(func() error { var e error; state, e = n.inspect(ctx, revision, wanted); return e })
	return state, err
}

// RecoveryRevision writes Git objects only. Its exact new commit must then be
// bound into a typed owned-inverse preparation before any ref can be changed.
func (n *NativeStage) RecoveryRevision(ctx context.Context, before g.JournalState, target g.ModelState) (rev g.GitRevision, err error) {
	err = n.locked(func() error {
		actual, e := n.inspect(ctx, before.Revision, before.Model)
		if e != nil || actual != before {
			return ErrNative
		}
		configuration, e := g.GitFixtureConfiguration(n.prepared.Program)
		if e != nil {
			return e
		}
		desired, e := g.GitFixtureDesired(n.prepared.Program, target)
		if e != nil {
			return e
		}
		rev, e = revision(ctx, n.prepared.Program, configuration, desired, before.Revision.Commit, "Append owned fixture inverse "+time.Now().UTC().Format(time.RFC3339Nano))
		return e
	})
	return rev, err
}

func permitMatches(actual, issued g.JournalDispatchPermit, now time.Time) bool {
	return issued.ValidUntil.After(now) && !issued.ValidUntil.After(actual.ValidUntil) && issued.JournalID == actual.JournalID && issued.CommandID == actual.CommandID && issued.OperationID == actual.OperationID && issued.Fence == actual.Fence && issued.CommandSHA256 == actual.CommandSHA256 && issued.ArtifactSHA256 == actual.ArtifactSHA256 && issued.Head == actual.Head
}

func durableNativeFile(name string, body any) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return ErrNative
	}
	if err = privateFile(name, raw); err != nil {
		return ErrUncertain
	}
	dir, err := os.Open(filepath.Dir(name))
	if err != nil {
		return ErrUncertain
	}
	defer dir.Close()
	if err = dir.Sync(); err != nil {
		return ErrUncertain
	}
	return nil
}

func (n *NativeStage) operationFile(command g.JournalCommand, action string) string {
	identity := struct{ Tenant, Proposal, Program, Command, Operation, Action string }{n.selected.Binding.Old.Target.TenantID, n.selected.ID, g.Digest(n.prepared.Program), command.ID, command.OperationID, action}
	return "/workspace/private/operation-" + g.Digest(identity) + ".json"
}

// Capture consumes an already committed GIT_ADVANCE claim, then performs the
// exact CAS and a fresh saved plan. The caller persists the authenticated Git
// fact and independently validates/signs the complete captured artifact. A
// crash at any point retains the marker and cannot silently repeat native I/O.
func (n *NativeStage) Capture(ctx context.Context, view g.JournalView, keys g.JournalKeys, issued g.JournalDispatchPermit) (capture g.GitTerraformArtifactCapture, err error) {
	err = n.locked(func() error {
		now := time.Now().UTC()
		if g.Digest(view.Parent.Program) != g.Digest(n.prepared.Program) {
			return ErrBoundary
		}
		projection, e := g.VerifyJournal(view, keys, view.Head.Head.Ref, now)
		if e != nil || projection.Pending == nil {
			return ErrBoundary
		}
		c := projection.Pending.Command
		permit, e := g.AuthorizeJournalGitAdvance(view, keys, view.Head.Head.Ref, g.Digest(c), now)
		if e != nil || !permitMatches(permit, issued, now) {
			return ErrBoundary
		}
		if _, e = os.Lstat(n.operationFile(c, "GIT_ADVANCE")); !os.IsNotExist(e) {
			return ErrUncertain
		}
		actual, e := n.inspect(ctx, c.Before.Revision, c.Before.Model)
		if e != nil || actual != c.Before {
			return ErrNative
		}
		if e = durableNativeFile(n.operationFile(c, "GIT_ADVANCE"), issued); e != nil {
			return e
		}
		if !issued.ValidUntil.After(time.Now().UTC()) {
			return ErrUncertain
		}
		if e = cas(ctx, executionRef, c.Preparation.Revision.Commit, c.Before.Revision.Commit); e != nil {
			return ErrUncertain
		}
		// Two-tree checkout refuses a conflicting intervening working-file
		// edit. A CAS success never licenses overwriting operator changes.
		if _, e = gitText(ctx, repository, nil, "read-tree", "-u", "-m", c.Before.Revision.Commit, c.Preparation.Revision.Commit); e != nil {
			return ErrUncertain
		}
		expected := c.Before
		expected.Revision = c.Preparation.Revision
		if actual, e = n.inspect(ctx, expected.Revision, expected.Model); e != nil || actual != expected {
			return ErrUncertain
		}
		// This single fixed file is producer-owned temporary output, never a
		// request path. Old bytes are retained in encrypted immutable storage.
		if info, e := os.Lstat(g.GitFixturePlanPath); e == nil {
			if !info.Mode().IsRegular() || os.Remove(g.GitFixturePlanPath) != nil {
				return ErrBoundary
			}
		} else if !os.IsNotExist(e) {
			return ErrBoundary
		}
		args := []string{"plan", "-input=false", "-no-color", "-refresh=false", "-state=" + g.GitFixtureStatePath, "-out=" + g.GitFixturePlanPath}
		if _, e = native(ctx, repository, terraform, nil, args...); e != nil {
			return ErrUncertain
		}
		capture.Context, capture.Revision = n.prepared.Program.ArtifactContext, c.Preparation.Revision
		capture.Ref, capture.RefBefore, capture.RefAfter = executionRef, c.Before.Revision.Commit, c.Preparation.Revision.Commit
		capture.Invocation = g.GitPlanInvocation{Arguments: args, EnvironmentKeys: []string{"PATH", "HOME", "LANG", "LC_ALL", "TF_IN_AUTOMATION", "TF_INPUT", "TF_DATA_DIR"}}
		capture.Configuration, e = readPrivate(filepath.Join(repository, g.GitMainPath))
		if e == nil {
			capture.DesiredVariables, e = readPrivate(filepath.Join(repository, g.GitDesiredPath))
		}
		if e == nil {
			capture.SavedPlan, e = readPrivate(g.GitFixturePlanPath)
		}
		if e == nil {
			capture.BeforeState, e = readPrivate(g.GitFixtureStatePath)
		}
		if e == nil {
			capture.PlanJSON, e = native(ctx, repository, terraform, nil, "show", "-json", g.GitFixturePlanPath)
		}
		if e == nil {
			capture.GitCommitObject, e = gitCommand(ctx, control, nil, "cat-file", "commit", capture.Revision.Commit)
		}
		if e == nil {
			capture.GitTreeObject, e = gitCommand(ctx, control, nil, "cat-file", "tree", capture.Revision.Tree)
		}
		if e != nil {
			return ErrUncertain
		}
		return durableNativeFile(n.operationFile(c, "GIT_ADVANCE")+".terminal", nativeCaptureTerminal{g.Digest(capture), g.Digest(c), c.OperationID, c.Fence, c.Before, expected})
	})
	return capture, err
}

// VerifyNotDispatched positively resolves a known captured operation under the
// actual native writer fence. Absence of a callback or an elapsed lease cannot
// create this proof. The surrounding ledger transaction also checks its current
// operation/outbox and source authority before the independent pipeline signs
// READY. Any local apply-attempt marker permanently prevents another READY.
func (n *NativeStage) VerifyNotDispatched(ctx context.Context, view g.JournalView, keys g.JournalKeys, capture g.GitTerraformArtifactCapture) (proof NotDispatchedProof, err error) {
	err = n.locked(func() error {
		now := time.Now().UTC()
		if g.Digest(view.Parent.Program) != g.Digest(n.prepared.Program) {
			return ErrBoundary
		}
		projection, e := g.VerifyJournal(view, keys, view.Head.Head.Ref, now)
		if e != nil || projection.Pending == nil || projection.Pending.ApplyIntent || (projection.Pending.Phase != g.JournalReserved && projection.Pending.Phase != g.JournalReadyToApply) {
			return ErrBoundary
		}
		c := projection.Pending.Command
		var artifact g.GitArtifact
		if c.Forward != nil && c.Recovery == nil {
			artifact = c.Forward.Child.Artifact
			_, e = g.ValidateGitTerraformArtifact(view.Parent.Program, c.Forward.Child, capture, now)
		} else if c.Recovery != nil && c.Forward == nil {
			artifact = c.Recovery.Recovery.Artifact
			_, e = g.ValidateJournalTerraformArtifact(view, keys, view.Head.Head.Ref, c.Recovery.Recovery, capture, now)
		} else {
			return ErrBoundary
		}
		if e != nil {
			return e
		}
		raw, e := readPrivate(n.operationFile(c, "GIT_ADVANCE") + ".terminal")
		if e != nil {
			return ErrUncertain
		}
		var terminal nativeCaptureTerminal
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		preparation := c
		preparation.Forward = nil
		preparation.Recovery = nil
		expected := c.Before
		expected.Revision = artifact.Revision
		if decoder.Decode(&terminal) != nil || decoder.Decode(new(any)) != io.EOF || terminal.CaptureSHA256 != g.Digest(capture) || terminal.CommandSHA256 != g.Digest(preparation) || terminal.OperationID != c.OperationID || terminal.Fence != c.Fence || terminal.Before != c.Before || terminal.After != expected {
			return ErrUncertain
		}
		if _, e = os.Lstat(n.operationFile(c, "APPLY")); !os.IsNotExist(e) {
			return ErrUncertain
		}
		actual, e := n.inspect(ctx, expected.Revision, expected.Model)
		if e != nil || actual != expected {
			return ErrNative
		}
		saved, e := readPrivate(g.GitFixturePlanPath)
		if e != nil || !bytes.Equal(saved, capture.SavedPlan) {
			return ErrNative
		}
		until := now.Add(30 * time.Second)
		if view.Head.Head.ValidUntil.Before(until) {
			until = view.Head.Head.ValidUntil
		}
		if !until.After(time.Now().UTC()) {
			return ErrUncertain
		}
		proof = NotDispatchedProof{"1", g.Digest(n.prepared.Program), view.Authorization.Authorization.JournalID, g.Digest(c), c.OperationID, c.Fence, g.Digest(capture), g.BytesDigest(raw), actual, now, until}
		return nil
	})
	return proof, err
}

func (n *NativeStage) Apply(ctx context.Context, view g.JournalView, keys g.JournalKeys, issued g.JournalDispatchPermit, capture g.GitTerraformArtifactCapture) (after g.JournalState, err error) {
	err = n.locked(func() error {
		now := time.Now().UTC()
		if g.Digest(view.Parent.Program) != g.Digest(n.prepared.Program) {
			return ErrBoundary
		}
		projection, e := g.VerifyJournal(view, keys, view.Head.Head.Ref, now)
		if e != nil || projection.Pending == nil {
			return ErrBoundary
		}
		c := projection.Pending.Command
		permit, e := g.AuthorizeJournalApply(view, keys, view.Head.Head.Ref, g.Digest(c), now)
		if e != nil || !permitMatches(permit, issued, now) {
			return ErrBoundary
		}
		if _, e = os.Lstat(n.operationFile(c, "APPLY")); !os.IsNotExist(e) {
			return ErrUncertain
		}
		var artifact g.GitArtifact
		if c.Forward != nil && c.Recovery == nil {
			artifact = c.Forward.Child.Artifact
			_, e = g.ValidateGitTerraformArtifact(view.Parent.Program, c.Forward.Child, capture, now)
		} else if c.Recovery != nil && c.Forward == nil {
			artifact = c.Recovery.Recovery.Artifact
			// Semantic approval belongs to the exact signed preparation head,
			// before APPLY_INTENT. Replaying that authentic bounded prefix is
			// separate from the fresh current dispatch/ownership check above.
			review := view
			review.Head = c.Recovery.Head
			count := review.Head.Head.Ref.RecordCount
			if count < 0 || count > len(view.Records) {
				return ErrBoundary
			}
			review.Records = view.Records[:count]
			_, e = g.ValidateJournalTerraformArtifact(review, keys, review.Head.Head.Ref, c.Recovery.Recovery, capture, c.Recovery.Recovery.CreatedAt)
		} else {
			return ErrBoundary
		}
		if e != nil {
			return e
		}
		expected := c.Before
		expected.Revision = artifact.Revision
		actual, e := n.inspect(ctx, expected.Revision, expected.Model)
		if e != nil || actual != expected {
			return ErrNative
		}
		saved, e := readPrivate(g.GitFixturePlanPath)
		if e != nil || !bytes.Equal(saved, capture.SavedPlan) {
			return ErrNative
		}
		before, e := readPrivate(g.GitFixtureStatePath)
		if e != nil || !bytes.Equal(before, capture.BeforeState) {
			return ErrNative
		}
		if e = durableNativeFile(n.operationFile(c, "APPLY"), issued); e != nil {
			return e
		}
		if !issued.ValidUntil.After(time.Now().UTC()) {
			return ErrUncertain
		}
		if _, e = native(ctx, repository, terraform, nil, "apply", "-input=false", "-no-color", "-state="+g.GitFixtureStatePath, g.GitFixturePlanPath); e != nil {
			return ErrUncertain
		}
		after, e = n.inspect(ctx, artifact.Revision, artifact.After)
		if e != nil || after.StateLineage != c.Before.StateLineage {
			return ErrUncertain
		}
		if artifact.Before == artifact.After {
			if after.StateSerial != c.Before.StateSerial || after.StateSHA256 != c.Before.StateSHA256 {
				return ErrUncertain
			}
		} else if after.StateSerial <= c.Before.StateSerial {
			return ErrUncertain
		}
		afterRaw, e := readPrivate(g.GitFixtureStatePath)
		if e != nil || !sameResourceIDs(before, afterRaw) {
			return ErrUncertain
		}
		ref, e := n.archive.Put(ctx, n.selected, "AFTER_NATIVE_STATE", afterRaw)
		if e != nil || ref.SHA256 != after.StateSHA256 || ref.SizeBytes != int64(len(afterRaw)) {
			return ErrUncertain
		}
		return durableNativeFile(n.operationFile(c, "APPLY")+".terminal", NativeOutcome{g.Digest(c), c.Before, after, ref})
	})
	return after, err
}

// Outcome reopens a positively recorded terminal result without dispatching
// Terraform. An absent or partial terminal record remains UNKNOWN. Matching
// the old state alone is never converted into a NO_APPLY assertion.
func (n *NativeStage) Outcome(ctx context.Context, command g.JournalCommand) (out NativeOutcome, err error) {
	err = n.locked(func() error {
		raw, e := readPrivate(n.operationFile(command, "APPLY") + ".terminal")
		if e != nil {
			return ErrUncertain
		}
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&out) != nil || decoder.Decode(new(any)) != io.EOF || out.CommandSHA256 != g.Digest(command) || out.Before != command.Before || out.Artifact.SHA256 != out.After.StateSHA256 {
			return ErrUncertain
		}
		plain, e := n.archive.Read(ctx, n.selected, "AFTER_NATIVE_STATE", out.Artifact)
		if e != nil || g.BytesDigest(plain) != out.After.StateSHA256 {
			return ErrUncertain
		}
		parsed, e := baseState(plain, n.prepared.Program, out.After.Model)
		if e != nil {
			return ErrUncertain
		}
		parsed.Revision = out.After.Revision
		if parsed != out.After {
			return ErrUncertain
		}
		actual, e := n.inspect(ctx, out.After.Revision, out.After.Model)
		if e != nil || actual != out.After {
			return ErrUncertain
		}
		return nil
	})
	return out, err
}

func sameResourceIDs(a, b []byte) bool {
	read := func(raw []byte) (map[string]string, bool) {
		var s stateEnvelope
		if json.Unmarshal(raw, &s) != nil || len(s.Resources) != 3 {
			return nil, false
		}
		out := map[string]string{}
		for _, r := range s.Resources {
			if len(r.Instances) != 1 || r.Instances[0].Attributes.ID == "" || out[r.Name] != "" {
				return nil, false
			}
			out[r.Name] = r.Instances[0].Attributes.ID
		}
		return out, true
	}
	x, ok := read(a)
	if !ok {
		return false
	}
	y, ok := read(b)
	if !ok || len(x) != len(y) {
		return false
	}
	for k, v := range x {
		if y[k] != v {
			return false
		}
	}
	return true
}
