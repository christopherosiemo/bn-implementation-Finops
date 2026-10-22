package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	g "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetgroup"
)

const statePath = "/workspace/private/current.tfstate"
const planPath = "/workspace/private/next.tfplan"
const fixtureSecretsPath = "/workspace/private/fixture-keys.json"

type fixtureSecrets struct{ Signer, Pipeline, Ledger ed25519.PrivateKey }
type fixtureJournal struct {
	disk    journalDisk
	keys    g.JournalKeys
	secrets fixtureSecrets
}
type operationState struct {
	CommandID         string                    `json:"command_id"`
	OperationID       string                    `json:"operation_id"`
	Fence             uint64                    `json:"fence"`
	PreparationSHA256 string                    `json:"preparation_sha256"`
	Status            string                    `json:"status"`
	Terminal          *g.JournalReceiptEnvelope `json:"terminal,omitempty"`
}
type operationEnvelope struct {
	State     operationState `json:"state"`
	Signature string         `json:"signature"`
}

func operationMessage(s operationState) []byte {
	return append([]byte("finops/isolated-file-fixture/operation/v1\x00"), exactJSON(s)...)
}
func operationPath(commandID string) string {
	require(len(commandID) > 0 && len(commandID) < 128 && strings.Trim(commandID, "abcdefghijklmnopqrstuvwxyz0123456789-") == "", "fixed operation ID required")
	return filepath.Join("/workspace/private/operations", commandID+".json")
}
func (j fixtureJournal) operation(c g.JournalCommand, status string, terminal *g.JournalReceiptEnvelope) {
	name := operationPath(c.ID)
	prior, err := os.ReadFile(name)
	if err == nil {
		old := j.readOperation(c)
		require(old.Status == "NOT_DISPATCHED" && status == "DISPATCHING" || old.Status == "DISPATCHING" && status == "APPLIED", "pipeline operation transition rejected")
	} else {
		require(os.IsNotExist(err) && status == "NOT_DISPATCHED", "pipeline operation initialization rejected")
	}
	s := operationState{c.ID, c.OperationID, c.Fence, g.Digest(c.Preparation), status, terminal}
	e := operationEnvelope{s, base64.StdEncoding.EncodeToString(ed25519.Sign(j.secrets.Pipeline, operationMessage(s)))}
	must(privateExclusive(name+".next", exactJSON(e)))
	if len(prior) > 0 {
		require(bytes.Equal(read(name), prior), "pipeline operation changed concurrently")
	}
	must(os.Rename(name+".next", name))
	must(syncDirectory(filepath.Dir(name)))
}
func (j fixtureJournal) readOperation(c g.JournalCommand) operationState {
	raw, err := boundedRegular(operationPath(c.ID), 1<<20)
	must(err)
	var e operationEnvelope
	must(canonicalDecode(raw, &e))
	sig, err := base64.StdEncoding.DecodeString(e.Signature)
	must(err)
	s := e.State
	require(ed25519.Verify(j.keys.Pipeline, operationMessage(s), sig) && s.CommandID == c.ID && s.OperationID == c.OperationID && s.Fence == c.Fence && s.PreparationSHA256 == g.Digest(c.Preparation), "pipeline operation signature/binding rejected")
	return s
}
func loadFixtureJournal() fixtureJournal {
	s := journalDisk{journalDirectory, os.Getenv("FLEET_JOURNAL_BOOTSTRAP_SHA256")}
	require(len(s.bootstrapSHA) == 64, "fixed bootstrap pin required")
	_, keys, _, err := s.load(time.Now().UTC())
	must(err)
	raw, err := boundedRegular(fixtureSecretsPath, 1<<20)
	must(err)
	require(g.BytesDigest(raw) == os.Getenv("FLEET_JOURNAL_SECRETS_SHA256"), "fixture private-key snapshot changed")
	var secrets fixtureSecrets
	must(canonicalDecode(raw, &secrets))
	for i, key := range []ed25519.PrivateKey{secrets.Signer, secrets.Pipeline, secrets.Ledger} {
		require(len(key) == 64, "private key invalid")
		require(bytes.Equal(key.Public().(ed25519.PublicKey), []ed25519.PublicKey{keys.Signer, keys.Pipeline, keys.Ledger}[i]), "private key binding changed")
	}
	return fixtureJournal{s, keys, secrets}
}
func (j fixtureJournal) current() (g.JournalView, g.JournalProjection) {
	v, _, p, err := j.disk.load(time.Now().UTC())
	must(err)
	return v, p
}
func (j fixtureJournal) commit(kind string, c *g.JournalCommand, r *g.JournalReceiptEnvelope, repair *g.JournalGitRepairEnvelope) error {
	lock, err := j.disk.lock()
	if err != nil {
		return err
	}
	defer unlock(lock)
	return j.commitLocked(kind, c, r, repair)
}
func (j fixtureJournal) commitLocked(kind string, c *g.JournalCommand, r *g.JournalReceiptEnvelope, repair *g.JournalGitRepairEnvelope) error {
	now := time.Now().UTC()
	v, _, _, err := j.disk.load(now)
	if err != nil {
		return err
	}
	next := g.JournalRecord{Sequence: uint64(len(v.Records) + 1), PreviousSHA256: v.Head.Head.Ref.LastRecordSHA256, Kind: kind, Command: c, Receipt: r, GitRepair: repair, RecordedAt: now}
	records, _, err := g.AppendJournalRecord(v, j.keys, v.Head.Head.Ref, next, now)
	if err != nil {
		return err
	}
	sealed, _, err := g.SealJournalView(v.Parent, v.Authorization, records, j.keys, j.secrets.Ledger, now)
	if err != nil {
		return err
	}
	return j.disk.appendLocked(v.Head.Head.Ref, next, sealed.Head, now)
}
func (j fixtureJournal) receipt(c g.JournalCommand, kind string, before, after g.JournalState) g.JournalReceiptEnvelope {
	v, _ := j.current()
	now := time.Now().UTC()
	r := g.JournalReceipt{SchemaVersion: g.JournalSchemaVersion, ID: c.ID + "-" + strings.ToLower(strings.ReplaceAll(kind, "_", "-")), IdempotencyKey: c.IdempotencyKey + "-" + strings.ToLower(strings.ReplaceAll(kind, "_", "-")), JournalID: v.Authorization.Authorization.JournalID, AuthorizationSHA256: g.Digest(v.Authorization), CommandID: c.ID, OperationID: c.OperationID, Fence: c.Fence, PipelineID: v.Parent.Program.ArtifactContext.PipelineID, Kind: kind, PreparationSHA256: g.Digest(c.Preparation), Before: before, After: after, ReceivedAt: now}
	if c.Forward != nil {
		r.ArtifactSHA256 = g.Digest(c.Forward.Child.Artifact)
		r.SavedPlanSHA256 = c.Forward.Child.Artifact.SavedPlanSHA256
	}
	if c.Recovery != nil {
		r.ArtifactSHA256 = g.Digest(c.Recovery.Recovery.Artifact)
		r.SavedPlanSHA256 = c.Recovery.Recovery.Artifact.SavedPlanSHA256
	}
	if kind == g.JournalReadyToApply {
		r.ValidUntil = now.Add(20 * time.Second)
	}
	// A fresh pipeline observation has its own receipt/idempotency identity.
	// Exact callback retries retain this envelope instead of regenerating it.
	observation := g.Digest(r)[:16]
	r.ID += "-" + observation
	r.IdempotencyKey += "-" + observation
	e, err := g.SignJournalReceipt(r, j.secrets.Pipeline)
	must(err)
	return e
}
func atRevision(s g.JournalState, r g.GitRevision) g.JournalState { s.Revision = r; return s }
func journalNativeState(p g.GitProgram, revision g.GitRevision) g.JournalState {
	raw := read(statePath)
	native, model := state(raw, p)
	return g.JournalState{Revision: revision, StateLineage: native.Lineage, StateSerial: native.Serial, StateSHA256: g.BytesDigest(raw), Model: model}
}
func evidence(p g.GitProgram, kinds []string, now time.Time) []g.EvidenceRef {
	refs := []g.EvidenceRef{}
	for _, kind := range kinds {
		refs = append(refs, g.EvidenceRef{Kind: kind, ID: "synthetic-" + strings.ToLower(kind), SHA256: g.BytesDigest([]byte("synthetic " + kind)), BindingSHA256: g.Digest(p.Binding), RealmSHA256: g.Digest(p.Realm), ObservedAt: now, ValidUntil: now.Add(15 * time.Minute)})
	}
	return refs
}
func (j fixtureJournal) prepare(q g.JournalPreparation, id string) g.JournalCommand {
	v, p := j.current()
	now := time.Now().UTC()
	c := g.JournalCommand{ID: id, OperationID: id + "-operation", IdempotencyKey: id + "-idempotency", Fence: p.LastFence + 1, Head: v.Head, Before: p.Current, Preparation: q, CreatedAt: now}
	must(j.commit(g.JournalPreparing, &c, nil, nil))
	j.operation(c, "NOT_DISPATCHED", nil)
	return c
}
func (j fixtureJournal) advance(c g.JournalCommand) {
	j.advanceWithAdditionalRefusal(c, nil)
}

// Additional refusal is a private negative probe only. It cannot replace the
// mandatory real-clock authorization and cannot grant permission to dispatch.
func (j fixtureJournal) advanceWithAdditionalRefusal(c g.JournalCommand, additionalRefusal func()) {
	lock, err := j.disk.lock()
	must(err)
	defer unlock(lock)
	v, p := j.current()
	require(p.Pending != nil && g.Digest(c) == g.Digest(p.Pending.Command), "fixture pending command changed")
	c = p.Pending.Command
	require(p.Pending != nil && p.Pending.Command.ID == c.ID && !p.Pending.GitAdvanced && !p.Pending.ApplyIntent, "Git advancement requires unissued preparation")
	require(j.readOperation(c).Status == "NOT_DISPATCHED", "Git advancement operation already dispatched")
	configuration, err := g.GitFixtureConfiguration(v.Parent.Program)
	must(err)
	oldDesired, err := g.GitFixtureDesired(v.Parent.Program, c.Before.Model)
	must(err)
	desired, err := g.GitFixtureDesired(v.Parent.Program, c.Preparation.After)
	must(err)
	require(journalNativeState(v.Parent.Program, c.Before.Revision) == c.Before, "native state changed before Git CAS")
	must(advanceGated(c.Before.Revision, c.Preparation.Revision, configuration, oldDesired, desired, func() {
		current, _ := j.current()
		require(j.readOperation(c).Status == "NOT_DISPATCHED" && journalNativeState(current.Parent.Program, c.Before.Revision) == c.Before, "Git advance lost positive operation/native fence")
		permit, e := g.AuthorizeJournalGitAdvance(current, j.keys, current.Head.Head.Ref, g.Digest(c), time.Now().UTC())
		must(e)
		requirePermit(permit, current, c, g.Digest(c.Preparation))
		if additionalRefusal != nil {
			additionalRefusal()
		}
		require(permit.ValidUntil.After(time.Now().UTC()), "fixture Git advance permission expired before actual CAS")
	}))
	r := j.receipt(c, g.JournalGitAdvanced, c.Before, atRevision(c.Before, c.Preparation.Revision))
	must(j.commitLocked(g.JournalGitAdvanced, nil, &r, nil))
}
func (j fixtureJournal) finalize(c g.JournalCommand, archive *archive, retentionPrefix ...string) g.JournalCommand {
	lock, lockErr := j.disk.lock()
	must(lockErr)
	defer unlock(lock)
	v, p := j.current()
	require(p.Pending != nil && g.Digest(c) == g.Digest(p.Pending.Command), "fixture pending command changed")
	c = p.Pending.Command
	prefix := c.ID
	if len(retentionPrefix) > 0 {
		require(len(retentionPrefix) == 1, "single fixture retention prefix required")
		prefix = retentionPrefix[0]
		require(strings.Trim(prefix, "abcdefghijklmnopqrstuvwxyz0123456789-") == "" && len(prefix) < 128, "fixture retention prefix rejected")
	}
	require(p.Pending != nil && p.Pending.Command.ID == c.ID && p.Pending.GitAdvanced && !p.Pending.ApplyIntent, "finalization requires owned Git reservation")
	program := v.Parent.Program
	configuration, err := g.GitFixtureConfiguration(program)
	must(err)
	desired, err := g.GitFixtureDesired(program, c.Preparation.After)
	must(err)
	must(cleanRevision(c.Preparation.Revision, configuration, desired))
	beforeRaw := read(statePath)
	require(journalNativeState(program, c.Before.Revision) == c.Before, "state changed before fresh plan")
	planArgs := []string{"plan", "-input=false", "-no-color", "-refresh=false", "-state=" + statePath, "-out=" + planPath}
	command(terraform, planArgs...)
	saved, show := read(planPath), command(terraform, "show", "-json", planPath)
	now := time.Now().UTC()
	a := g.GitArtifact{Kind: g.BuiltinFixtureArtifact, Receipt: g.SnapshotRef{ID: prefix + "-artifact", SHA256: g.Digest(map[string]string{"command_id": c.ID, "saved": g.BytesDigest(saved), "show": g.BytesDigest(show), "state": g.BytesDigest(beforeRaw), "revision": c.Preparation.Revision.Commit})}, BaseContextSHA256: g.Digest(program.ArtifactContext), ManifestSHA256: program.ManifestSHA256, PreviousRevision: c.Before.Revision, Revision: c.Preparation.Revision, BeforeStateSerial: c.Before.StateSerial, BeforeStateSHA256: c.Before.StateSHA256, SavedPlanSHA256: g.BytesDigest(saved), PlanJSONSHA256: g.BytesDigest(show), Before: c.Preparation.Before, After: c.Preparation.After}
	keys := []string{}
	for _, setting := range terraformEnvironment() {
		keys = append(keys, strings.SplitN(setting, "=", 2)[0])
	}
	capture := g.GitTerraformArtifactCapture{Context: program.ArtifactContext, Revision: a.Revision, Configuration: configuration, DesiredVariables: desired, SavedPlan: saved, PlanJSON: show, BeforeState: beforeRaw, GitCommitObject: gitRaw(repository, nil, "cat-file", "commit", a.Revision.Commit), GitTreeObject: gitRaw(repository, nil, "cat-file", "tree", a.Revision.Tree), Ref: executionRef, RefBefore: a.PreviousRevision.Commit, RefAfter: a.Revision.Commit, Invocation: g.GitPlanInvocation{Arguments: planArgs, EnvironmentKeys: keys}}
	var review g.ArtifactReview
	if c.Preparation.Mode == g.Forward {
		entry := program.Manifest.Entries[c.Preparation.Sequence-1]
		a.ManifestEntrySHA256 = g.Digest(entry)
		child := g.GitChild{SchemaVersion: g.GitSchemaVersion, ID: prefix + "-child", ParentID: program.ID, ParentSHA256: g.Digest(program), BindingSHA256: g.Digest(program.Binding), RealmSHA256: g.Digest(program.Realm), Mode: g.Forward, StageID: entry.StageID, StageSHA256: entry.StageSHA256, Sequence: entry.Sequence, Artifact: a, MinimumObservationSeconds: entry.MinimumObservationSeconds, Evidence: evidence(program, []string{"FIXTURE_CURRENT", "FIXTURE_DEPENDENCY", "FIXTURE_SLO"}, now), CreatedAt: now, ExpiresAt: now.Add(10 * time.Minute), Nonce: prefix + "-nonce"}
		signed, e := g.SignGitChild(child, v.Parent, j.secrets.Signer, now)
		must(e)
		review, err = g.ValidateGitTerraformArtifact(program, child, capture, now)
		must(err)
		c.Forward = &signed
	} else {
		top := p.Stack[len(p.Stack)-1]
		r := g.JournalRecovery{SchemaVersion: g.JournalSchemaVersion, ID: c.ID + "-recovery", CommandID: c.ID, JournalID: v.Authorization.Authorization.JournalID, AuthorizationSHA256: g.Digest(v.Authorization), ParentEnvelopeSHA256: g.Digest(v.Parent), PreparationHeadSHA256: g.Digest(c.Head), SigningHeadSHA256: g.Digest(v.Head), EffectID: top.ID, OriginalChildSHA256: g.Digest(top.Forward.Child), OriginalReceiptSHA256: g.Digest(top.Applied), Artifact: a, MinimumObservationSeconds: 120, Evidence: evidence(program, []string{"FIXTURE_CURRENT", "FIXTURE_RECOVERY_SLO"}, now), CreatedAt: now, ExpiresAt: now.Add(10 * time.Minute), Nonce: c.ID + "-nonce"}
		signed, e := g.SignJournalRecovery(r, v, j.keys, v.Head.Head.Ref, j.secrets.Signer, now)
		must(e)
		review, err = g.ValidateJournalTerraformArtifact(v, j.keys, v.Head.Head.Ref, r, capture, now)
		must(err)
		c.Recovery = &signed
	}
	require(!review.CustomerNativeExecution && review.CustomerVerifiedSaving == nil, "semantic review granted external authority")
	for kind, raw := range map[string][]byte{"saved-plan": saved, "show-json": show, "before-state": beforeRaw, "desired": desired, "git-commit": capture.GitCommitObject, "git-tree": capture.GitTreeObject, "semantic-review": exactJSON(review), "final-command": exactJSON(c)} {
		archive.put(prefix, kind, raw)
	}
	must(j.commitLocked(g.JournalReserved, &c, nil, nil))
	return c
}
func (j fixtureJournal) ready(c g.JournalCommand) {
	lock, err := j.disk.lock()
	must(err)
	defer unlock(lock)
	v, p := j.current()
	require(p.Pending != nil && g.Digest(c) == g.Digest(p.Pending.Command), "fixture pending command changed")
	c = p.Pending.Command
	require(j.readOperation(c).Status == "NOT_DISPATCHED", "positive not-dispatched proof missing")
	gitState := atRevision(c.Before, c.Preparation.Revision)
	require(journalNativeState(v.Parent.Program, c.Preparation.Revision) == gitState, "native state changed before readiness")
	r := j.receipt(c, g.JournalReadyToApply, gitState, gitState)
	must(j.commitLocked(g.JournalReadyToApply, nil, &r, nil))
	r = j.receipt(c, g.JournalApplyIntent, gitState, gitState)
	must(j.commitLocked(g.JournalApplyIntent, nil, &r, nil))
}
func (j fixtureJournal) apply(c g.JournalCommand, cutpoint bool) g.JournalReceiptEnvelope {
	lock, lockErr := j.disk.lock()
	must(lockErr)
	defer unlock(lock)
	v, p := j.current()
	require(p.Pending != nil && g.Digest(c) == g.Digest(p.Pending.Command), "fixture pending command changed")
	c = p.Pending.Command
	require(p.Pending != nil && p.Pending.ApplyIntent && p.Pending.Command.ID == c.ID && p.Pending.Phase == g.JournalApplyIntent, "durable fresh apply intent required")
	require(j.readOperation(c).Status == "NOT_DISPATCHED", "duplicate CLI dispatch rejected")
	var artifact g.GitArtifact
	if c.Forward != nil {
		artifact = c.Forward.Child.Artifact
	} else {
		artifact = c.Recovery.Recovery.Artifact
	}
	configuration, err := g.GitFixtureConfiguration(v.Parent.Program)
	must(err)
	desired, err := g.GitFixtureDesired(v.Parent.Program, artifact.After)
	must(err)
	must(cleanRevision(artifact.Revision, configuration, desired))
	require(g.BytesDigest(read(planPath)) == artifact.SavedPlanSHA256 && g.BytesDigest(read(statePath)) == artifact.BeforeStateSHA256, "exact native dispatch boundary changed")
	v, _ = j.current()
	permit, err := g.AuthorizeJournalApply(v, j.keys, v.Head.Head.Ref, g.Digest(c), time.Now().UTC())
	must(err)
	requirePermit(permit, v, c, g.Digest(artifact))
	j.operation(c, "DISPATCHING", nil)
	require(permit.ValidUntil.After(time.Now().UTC()), "fixture apply permission expired before actual delivery")
	command(terraform, "apply", "-input=false", "-auto-approve", "-no-color", "-state="+statePath, planPath)
	after := journalNativeState(v.Parent.Program, artifact.Revision)
	require(after.Model == artifact.After && after.StateLineage == c.Before.StateLineage, "actual applied model binding changed")
	terminal := j.receipt(c, g.JournalApplied, c.Before, after)
	j.operation(c, "APPLIED", &terminal)
	if cutpoint {
		unknown := j.receipt(c, g.JournalUnknown, c.Before, c.Before)
		must(j.commitLocked(g.JournalUnknown, nil, &unknown, nil))
		os.Exit(73)
	}
	must(j.commitLocked(g.JournalApplied, nil, &terminal, nil))
	return terminal
}
func childProcess(j fixtureJournal, mode string, wantExit int) reopenResult {
	binary, err := os.Executable()
	must(err)
	c := exec.Command(binary, mode)
	c.Env = append(terraformEnvironment(), "FLEET_JOURNAL_BOOTSTRAP_SHA256="+j.disk.bootstrapSHA, "FLEET_JOURNAL_SECRETS_SHA256="+g.BytesDigest(read(fixtureSecretsPath)))
	var stderr bytes.Buffer
	c.Stderr = &stderr
	raw, err := c.Output()
	if wantExit != 0 {
		e, ok := err.(*exec.ExitError)
		require(ok && e.ExitCode() == wantExit, "actual child cutpoint did not terminate as expected")
		return reopenResult{}
	}
	if err != nil {
		if diagnosticArchive != nil && stderr.Len() > 0 && stderr.Len() <= 64<<20 {
			diagnosticArchive.put("child-failure", "stderr", stderr.Bytes())
		}
		panic("private journal subprocess failed: " + mode)
	}
	var result reopenResult
	must(canonicalDecode(bytes.TrimSpace(raw), &result))
	return result
}
func cutpointProcess(mode string) {
	j := loadFixtureJournal()
	v, p := j.current()
	require(p.Pending != nil, "cutpoint pending command required")
	c := p.Pending.Command
	if mode == "--cas-and-crash" {
		require(p.Pending.Phase == g.JournalPreparing, "CAS cutpoint phase invalid")
		j.advance(c)
		os.Exit(73)
	}
	if mode == "--apply-and-crash" {
		j.apply(c, true)
		panic("apply cutpoint failed")
	}
	_ = v
	panic("unknown private process mode")
}

func (j fixtureJournal) repair(archive *archive) {
	lock, lockErr := j.disk.lock()
	must(lockErr)
	defer unlock(lock)
	v, p := j.current()
	require(p.Pending != nil && p.Pending.GitAdvanced && !p.Pending.ApplyIntent, "Git-only repair requires unissued Git duty")
	c := p.Pending.Command
	require(j.readOperation(c).Status == "NOT_DISPATCHED", "definitive no-apply pipeline state missing")
	beforeNative := read(statePath)
	calls := nativeApplyCount()
	gitBefore := atRevision(c.Before, c.Preparation.Revision)
	require(journalNativeState(v.Parent.Program, c.Preparation.Revision) == gitBefore, "native state changed before no-apply proof")
	noApply := j.receipt(c, g.JournalNoApply, c.Before, gitBefore)
	must(j.commitLocked(g.JournalNoApply, nil, &noApply, nil))
	v, p = j.current()
	require(p.Pending != nil && p.Pending.NoApply != nil && len(p.Stack) == 3, "Git repair must retain prior effects")
	configuration, err := g.GitFixtureConfiguration(v.Parent.Program)
	must(err)
	desired, err := g.GitFixtureDesired(v.Parent.Program, c.Before.Model)
	must(err)
	currentDesired, err := g.GitFixtureDesired(v.Parent.Program, c.Preparation.After)
	must(err)
	target := revision(v.Parent.Program, configuration, desired, c.Preparation.Revision.Commit, "Journal definitive-no-apply Git-only repair; retain owned effects")
	now := time.Now().UTC()
	r := g.JournalGitRepair{SchemaVersion: g.JournalSchemaVersion, ID: c.ID + "-git-repair", CommandID: c.ID, AuthorizationSHA256: g.Digest(v.Authorization), HeadSHA256: g.Digest(v.Head), PreparationSHA256: g.Digest(c.Preparation), NoApplyReceiptSHA256: g.Digest(noApply), Before: gitBefore, Revision: target, CreatedAt: now, ExpiresAt: now.Add(10 * time.Minute), Nonce: c.ID + "-repair-nonce"}
	signed, err := g.SignJournalGitRepair(r, v, j.keys, v.Head.Head.Ref, j.secrets.Signer, now)
	must(err)
	must(j.commitLocked(g.JournalGitRepairIntent, nil, nil, &signed))
	v, _ = j.current()
	require(j.readOperation(c).Status == "NOT_DISPATCHED" && bytes.Equal(read(statePath), beforeNative), "Git repair lost positive no-apply fence")
	_, expiredErr := g.AuthorizeJournalGitRepair(v, j.keys, v.Head.Head.Ref, g.Digest(r), time.Now().UTC().Add(31*time.Second))
	require(expiredErr != nil && expiredErr.Error() == "JOURNAL_DISPATCH_PERMISSION_EXPIRED", "old repair intent became delivery permission")
	permit, err := g.AuthorizeJournalGitRepair(v, j.keys, v.Head.Head.Ref, g.Digest(r), time.Now().UTC())
	must(err)
	requirePermit(permit, v, c, g.Digest(r))
	must(advanceGated(c.Preparation.Revision, target, configuration, currentDesired, desired, func() {
		require(permit.ValidUntil.After(time.Now().UTC()), "fixture repair permission expired before actual CAS")
	}))
	v, _ = j.current()
	capture := g.JournalGitRepairCapture{Context: v.Parent.Program.ArtifactContext, Configuration: configuration, DesiredVariables: desired, BeforeState: beforeNative, AfterState: read(statePath), GitCommitObject: gitRaw(repository, nil, "cat-file", "commit", target.Commit), GitTreeObject: gitRaw(repository, nil, "cat-file", "tree", target.Tree), Ref: executionRef, RefBefore: c.Preparation.Revision.Commit, RefAfter: target.Commit}
	must(g.ValidateJournalGitRepairCapture(v, j.keys, v.Head.Head.Ref, r, capture, time.Now().UTC()))
	receipt := j.receipt(c, g.JournalGitRepaired, r.Before, atRevision(c.Before, target))
	receipt.Receipt.ArtifactSHA256 = g.Digest(r)
	receipt.Receipt.SavedPlanSHA256 = ""
	receipt, err = g.SignJournalReceipt(receipt.Receipt, j.secrets.Pipeline)
	must(err)
	must(j.commitLocked(g.JournalGitRepaired, nil, &receipt, nil))
	_, p = j.current()
	require(p.Pending == nil && p.ForwardAborted && len(p.Stack) == 3 && p.Current == atRevision(c.Before, target), "Git-only repair consumed effect or native state")
	require(nativeApplyCount() == calls && bytes.Equal(read(statePath), beforeNative), "Git-only repair executed Terraform or changed state")
	for kind, raw := range map[string][]byte{"git-repair-envelope": exactJSON(signed), "git-repair-receipt": exactJSON(receipt), "git-repair-commit": capture.GitCommitObject, "git-repair-tree": capture.GitTreeObject, "git-repair-before-state": beforeNative, "git-repair-after-state": read(statePath)} {
		archive.put(c.ID, kind, raw)
	}
	// Exact callback replay has no projection effect. A second repair intent
	// cannot consume the cleared duty or make forward progress available.
	prior := g.Digest(p)
	must(j.commitLocked(g.JournalGitRepaired, nil, &receipt, nil))
	_, p = j.current()
	require(g.Digest(p) == prior, "repair replay changed projection")
	require(j.commitLocked(g.JournalGitRepairIntent, nil, nil, &signed) != nil, "Git repair duty consumed twice")
}

func requirePermit(p g.JournalDispatchPermit, v g.JournalView, c g.JournalCommand, artifact string) {
	require(p.JournalID == v.Authorization.Authorization.JournalID && p.CommandID == c.ID && p.OperationID == c.OperationID && p.Fence == c.Fence && p.CommandSHA256 == g.Digest(c) && p.ArtifactSHA256 == artifact && p.Head == v.Head.Head.Ref && p.ValidUntil.After(time.Now().UTC()), "fixture immediate dispatch permit binding rejected")
}
