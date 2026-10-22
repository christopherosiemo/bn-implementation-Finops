package store

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	ff "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetfixture"
	g "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetgroup"
	native "github.com/christopherosiemo/bn-implementation-Finops/internal/groupfixtureproducer"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Restricted real PostgreSQL tests. Signed native observations and versioned
// objects here are explicitly dependency doubles, not Docker removal, Git/TF,
// encrypted archive, health, customer source or runtime acceptance.
type groupNativeTest struct {
	*groupJournalTest
	prepared   ff.Preparation
	workspace  native.NativeWorkspace
	controller ed25519.PrivateKey
}

func newGroupNativeTest(t *testing.T, managed bool) *groupNativeTest {
	t.Helper()
	h := newGroupJournalTest(t)
	dir := t.TempDir()
	for _, file := range []string{"032_group_artifacts.sql", "033_group_native_reconstruction.sql"} {
		raw, e := os.ReadFile(filepath.Join("..", "..", "migrations", file))
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join(dir, file), raw, 0600); e != nil {
			t.Fatal(e)
		}
	}
	if e := h.f.admin.Migrate(h.f.ctx, dir); e != nil {
		var p *pgconn.PgError
		if errors.As(e, &p) {
			t.Fatalf("draft migration at byte %d: %s (%s)", p.Position, p.Message, p.Where)
		}
		t.Fatal(e)
	}
	groupJournalTestLogin(t, h.f, "finops_group_workspace_controller")
	n := &groupNativeTest{groupJournalTest: h}
	_, n.controller, _ = ed25519.GenerateKey(rand.Reader)
	h.f.must("finops_group_ledger", func(tx *Tx) error {
		var raw, review, refs []byte
		var expected string
		if e := tx.QueryRow(h.f.ctx, `SELECT program_raw,journal_review_raw,artifact_refs,proof_hash FROM public.fleet_fixture_prepared_programs WHERE tenant_id=$1 AND id=$2`, h.f.tenant, h.b.PreparedProgramID).Scan(&raw, &review, &refs, &expected); e != nil {
			return e
		}
		if json.Unmarshal(raw, &n.prepared.Program) != nil || json.Unmarshal(review, &n.prepared.JournalReview) != nil || json.Unmarshal(refs, &n.prepared.Artifacts) != nil {
			return errors.New("invalid stored test preparation")
		}
		p := n.prepared.Program
		source, e := g.GitFixtureConfiguration(p)
		if e != nil {
			return e
		}
		previous := ""
		for i, entry := range p.Manifest.Entries {
			desired, e := g.GitFixtureDesired(p, entry.After)
			if e != nil {
				return e
			}
			parent := previous
			if i == 0 {
				parent = ""
			}
			revision, commit, tree := fixtureUnitGit(source, desired, parent, i)
			if revision != entry.Revision {
				return errors.New("regenerated proof differs from immutable program")
			}
			n.prepared.GitProofs = append(n.prepared.GitProofs, ff.GitProof{Revision: revision, CommitObject: commit, TreeObject: tree, Configuration: source, DesiredVariables: desired})
			previous = revision.Commit
		}
		proof, e := ff.ProofBytes(n.prepared.GitProofs)
		if e != nil || g.BytesDigest(proof) != expected {
			return errors.New("regenerated immutable proof hash differs")
		}
		return nil
	})
	n.workspace = native.NativeWorkspace{Generation: "installed-first", RuntimeID: strings.Repeat("1", 64), ImageSHA256: n.prepared.Program.ArtifactContext.ToolchainImageSHA256}
	if managed {
		if e := h.f.admin.Do(h.f.ctx, h.f.tenant, func(tx *Tx) error {
			p := n.prepared.Program
			if _, e := tx.Exec(h.f.ctx, `INSERT INTO public.fleet_group_workspace_keys(tenant_id,chain_id,id,profile_id,profile_generation,image_sha256,public_key) VALUES($1,$2,'workspace-controller',$3,$4,$5,$6)`, h.f.tenant, h.b.ChainID, p.Realm.FixtureID, p.Realm.Generation, n.workspace.ImageSHA256, n.controller.Public().(ed25519.PublicKey)); e != nil {
				return e
			}
			raw, hash, e := groupJournalBytes(groupNativeWorkspace{"1", n.workspace, "", nil})
			if e != nil {
				return e
			}
			_, e = tx.Exec(h.f.ctx, `INSERT INTO public.fleet_group_workspaces(tenant_id,chain_id,generation,ordinal,runtime_id,image_sha256,key_binding_id,previous_generation,document,raw_document,content_hash) VALUES($1,$2,$3,0,$4,$5,'workspace-controller',NULL,convert_from($6::bytea,'UTF8')::jsonb,$6,$7)`, h.f.tenant, h.b.ChainID, n.workspace.Generation, n.workspace.RuntimeID, n.workspace.ImageSHA256, raw, hash)
			return e
		}); e != nil {
			t.Fatal(e)
		}
	}
	return n
}
func (n *groupNativeTest) intent(t *testing.T, sequences ...uint64) g.JournalCommand {
	t.Helper()
	h := n.groupJournalTest
	p := h.b.Parent.Program
	sequence := uint64(1)
	if len(sequences) > 0 {
		sequence = sequences[0]
	}
	suffix := strconv.FormatUint(sequence, 10)
	entry := p.Manifest.Entries[sequence-1]
	var c g.JournalCommand
	h.f.must("finops_group_ledger", func(tx *Tx) error {
		v, keys, e := tx.FleetGroupJournalOriginal(h.f.ctx, h.b.ChainID)
		if e != nil {
			return e
		}
		projection, e := g.VerifyJournal(v, keys.Core(), v.Head.Head.Ref, time.Now().UTC())
		if e != nil {
			return e
		}
		c = g.JournalCommand{ID: "native-command-" + suffix, OperationID: "native-operation-" + suffix, IdempotencyKey: "native-key-" + suffix, Fence: projection.LastFence + 1, Head: v.Head, Before: projection.Current, Preparation: g.JournalPreparation{Mode: g.Forward, Sequence: sequence, ManifestEntrySHA256: g.Digest(entry), Revision: entry.Revision, Before: entry.Before, After: entry.After}, CreatedAt: time.Now().UTC()}
		return nil
	})
	h.originalEvent(t, g.JournalRecord{Kind: g.JournalPreparing, Command: &c})
	git := h.protocolOriginalReceipt(t, g.JournalGitAdvanced)
	h.originalEvent(t, g.JournalRecord{Kind: g.JournalGitAdvanced, Receipt: &git})
	now := time.Now().UTC()
	child := g.GitChild{SchemaVersion: g.GitSchemaVersion, ID: "native-child-" + suffix, ParentID: p.ID, ParentSHA256: g.Digest(p), BindingSHA256: g.Digest(p.Binding), RealmSHA256: g.Digest(p.Realm), Mode: g.Forward, StageID: entry.StageID, StageSHA256: entry.StageSHA256, Sequence: sequence, Artifact: g.GitArtifact{Kind: g.BuiltinFixtureArtifact, Receipt: g.SnapshotRef{ID: "native-review-" + suffix, SHA256: strings.Repeat("a", 64)}, BaseContextSHA256: g.Digest(p.ArtifactContext), ManifestSHA256: p.ManifestSHA256, ManifestEntrySHA256: g.Digest(entry), PreviousRevision: c.Before.Revision, Revision: entry.Revision, BeforeStateSerial: c.Before.StateSerial, BeforeStateSHA256: c.Before.StateSHA256, SavedPlanSHA256: strings.Repeat("b", 64), PlanJSONSHA256: strings.Repeat("c", 64), Before: entry.Before, After: entry.After}, MinimumObservationSeconds: entry.MinimumObservationSeconds, CreatedAt: now, ExpiresAt: now.Add(10 * time.Minute), Nonce: "native-child-nonce-" + suffix}
	for _, kind := range []string{"FIXTURE_CURRENT", "FIXTURE_DEPENDENCY", "FIXTURE_SLO"} {
		child.Evidence = append(child.Evidence, g.EvidenceRef{Kind: kind, ID: "native-" + kind, SHA256: strings.Repeat("d", 64), BindingSHA256: g.Digest(p.Binding), RealmSHA256: g.Digest(p.Realm), ObservedAt: now, ValidUntil: now.Add(time.Hour)})
	}
	signed, e := g.SignGitChild(child, h.b.Parent, h.signer, now)
	if e != nil {
		t.Fatal(e)
	}
	c.Forward = &signed
	h.originalEvent(t, g.JournalRecord{Kind: g.JournalReserved, Command: &c})
	for _, kind := range []string{g.JournalReadyToApply, g.JournalApplyIntent} {
		receipt := h.protocolOriginalReceipt(t, kind)
		h.originalEvent(t, g.JournalRecord{Kind: kind, Receipt: &receipt})
	}
	return c
}
func (n *groupNativeTest) claim(t *testing.T, c g.JournalCommand) (string, string) {
	t.Helper()
	id, attempt := "", "native-apply-attempt-"+c.ID
	n.f.must("finops_group_ledger", func(tx *Tx) error {
		if e := tx.QueryRow(n.f.ctx, `SELECT id FROM public.fleet_group_journal_outbox WHERE tenant_id=$1 AND chain_id=$2 AND command_id=$3 AND action='APPLY'`, n.f.tenant, n.b.ChainID, c.ID).Scan(&id); e != nil {
			return e
		}
		_, _, deliver, e := tx.FleetGroupJournalClaimOriginal(n.f.ctx, n.b.ChainID, id, attempt)
		if e == nil && !deliver {
			return errors.New("fresh apply claim not issued")
		}
		return e
	})
	return id, attempt
}
func (n *groupNativeTest) terminal(t *testing.T, c g.JournalCommand, sameArchiveID ...bool) (native.NativeTerminalEnvelope, ff.ArtifactReference) {
	t.Helper()
	after := c.Before
	after.Revision = c.Preparation.Revision
	after.Model = c.Preparation.After
	if c.Preparation.Before != c.Preparation.After {
		after.StateSerial++
		after.StateSHA256 = strings.Repeat("d", 64)
	}
	refs := native.NativeReconstructionRefs{Review: groupArtifactRef(t, n.groupJournalTest, c, c.Forward.Child.Artifact.Receipt.ID, c.Forward.Child.Artifact.Receipt.SHA256), Capture: groupArtifactRef(t, n.groupJournalTest, c, "native-capture-"+c.ID, strings.Repeat("e", 64)), After: groupArtifactRef(t, n.groupJournalTest, c, "native-after-"+c.ID, after.StateSHA256)}
	var v g.JournalView
	n.f.must("finops_group_ledger", func(tx *Tx) error {
		var e error
		v, _, e = tx.FleetGroupJournalOriginal(n.f.ctx, n.b.ChainID)
		return e
	})
	body := native.NativeTerminal{SchemaVersion: "1", ID: model.ID(), TenantID: n.f.tenant, ChainID: n.b.ChainID, ProgramSHA256: g.Digest(v.Parent.Program), AuthorizationSHA256: g.Digest(v.Authorization), CommandSHA256: g.Digest(c), OperationID: c.OperationID, Fence: c.Fence, ArtifactSHA256: g.Digest(c.Forward.Child.Artifact), PreparationSHA256: g.Digest(c.Preparation), Workspace: n.workspace, References: refs, Before: c.Before, After: after, Head: v.Head, ObservedAt: time.Now().UTC()}
	raw, _ := json.Marshal(body)
	env := native.NativeTerminalEnvelope{Terminal: body, Algorithm: "Ed25519/group-fixture-native/v1", Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(n.pipeline, append([]byte("finops/group-fixture/native-terminal/v1\x00"), raw...)))}
	encoded, _ := json.Marshal(env)
	archiveID := "archive-" + body.ID
	if len(sameArchiveID) > 0 && sameArchiveID[0] {
		archiveID = body.ID
	}
	proof := groupArtifactRef(t, n.groupJournalTest, c, archiveID, g.BytesDigest(encoded))
	proof.SizeBytes = int64(len(encoded))
	for _, ref := range []struct {
		kind string
		ref  ff.ArtifactReference
	}{{"NATIVE_ARTIFACT_REVIEW", refs.Review}, {"NATIVE_CAPTURE", refs.Capture}, {"AFTER_NATIVE_STATE", refs.After}, {"NATIVE_OPERATION_PROOF", proof}} {
		n.f.must("finops_group_pipeline", func(tx *Tx) error {
			_, _, e := tx.GroupArtifactAppend(n.f.ctx, n.b.ChainID, c.ID, ref.kind, groupArtifactIdentity(), ref.ref)
			return e
		})
	}
	return env, proof
}
func (n *groupNativeTest) append(t *testing.T, e native.NativeTerminalEnvelope, ref ff.ArtifactReference, replay bool) {
	t.Helper()
	n.f.must("finops_group_pipeline", func(tx *Tx) error {
		_, actual, err := tx.GroupNativeTerminalAppend(n.f.ctx, n.b.ChainID, groupArtifactIdentity(), n.prepared, e, ref)
		if err == nil && actual != replay {
			return errors.New("terminal replay changed")
		}
		return err
	})
}

func (n *groupNativeTest) applied(tx *Tx, receipt g.JournalReceiptEnvelope) error {
	v, keys, e := tx.FleetGroupJournalOriginal(n.f.ctx, n.b.ChainID)
	if e != nil {
		return e
	}
	now := time.Now().UTC()
	r := g.JournalRecord{Sequence: uint64(len(v.Records) + 1), PreviousSHA256: v.Head.Head.Ref.LastRecordSHA256, Kind: g.JournalApplied, Receipt: &receipt, RecordedAt: now}
	records, _, e := g.AppendJournalRecord(v, keys.Core(), v.Head.Head.Ref, r, now)
	if e != nil {
		return e
	}
	next, _, e := g.SealJournalView(v.Parent, v.Authorization, records, keys.Core(), n.ledger, now)
	if e != nil {
		return e
	}
	updated, _, e := tx.FleetGroupJournalAppendOriginal(n.f.ctx, n.b.ChainID, n.cursor, r, next.Head)
	if e == nil {
		n.cursor = updated
	}
	return e
}
func TestGroupNativeClaimSelectionReplayAndOwnedRestoration(t *testing.T) {
	n := newGroupNativeTest(t, true)
	f := n.f
	calls := 0
	f.must("finops_group_ledger", func(tx *Tx) error {
		return (GroupNativeReconstructionAuthority{Tx: tx, Prepared: n.prepared, Request: GroupNativeReconstructionRequest{Mode: native.ReconstructionInitial, WorkspaceGeneration: n.workspace.Generation}}).WithCurrentNativeFence(f.ctx, n.b.ChainID, func(s native.NativeReconstructionSnapshot) error {
			calls++
			if s.Workspace != n.workspace {
				return ErrGroupNative
			}
			return nil
		})
	})
	if calls != 1 {
		t.Fatal("initial callback count")
	}
	c := n.intent(t)
	terminal, proof := n.terminal(t, c)
	f.denied("finops_group_pipeline", func(tx *Tx) error {
		_, _, e := tx.GroupNativeTerminalAppend(f.ctx, n.b.ChainID, groupArtifactIdentity(), n.prepared, terminal, proof)
		return e
	})
	delivery, attempt := n.claim(t, c)
	n.append(t, terminal, proof, false)
	if proof.ID == terminal.Terminal.ID {
		t.Fatal("native test did not exercise independent archive identity")
	}
	for _, change := range []func(*ff.ArtifactReference){
		func(r *ff.ArtifactReference) { r.VersionID += "-swapped" },
		func(r *ff.ArtifactReference) { r.Key += "-swapped" },
	} {
		wrong := proof
		change(&wrong)
		f.denied("finops_group_pipeline", func(tx *Tx) error {
			_, _, e := tx.GroupNativeTerminalAppend(f.ctx, n.b.ChainID, groupArtifactIdentity(), n.prepared, terminal, wrong)
			return e
		})
	}
	copyRef := groupArtifactRef(t, n.groupJournalTest, c, "second-archive-"+terminal.Terminal.ID, proof.SHA256)
	copyRef.SizeBytes = proof.SizeBytes
	f.must("finops_group_pipeline", func(tx *Tx) error {
		_, _, e := tx.GroupArtifactAppend(f.ctx, n.b.ChainID, c.ID, "NATIVE_OPERATION_PROOF", groupArtifactIdentity(), copyRef)
		return e
	})
	copyError := f.run("finops_group_pipeline", func(tx *Tx) error {
		_, _, e := tx.GroupNativeTerminalAppend(f.ctx, n.b.ChainID, groupArtifactIdentity(), n.prepared, terminal, copyRef)
		return e
	})
	if !errors.Is(copyError, ErrGroupNativeConflict) {
		t.Fatal("same terminal changed its original archive identity", copyError)
	}
	applied := n.protocolOriginalReceipt(t, g.JournalApplied)
	n.inbox(t, g.ContinuationOriginal, applied)
	e := f.run("finops_group_ledger", func(tx *Tx) error { return n.applied(tx, applied) })
	var refusal *pgconn.PgError
	if !errors.As(e, &refusal) || !strings.Contains(refusal.Message, "managed native apply requires selected positive terminal") {
		t.Fatal("missing native selection failed at the wrong boundary", e)
	}
	f.must("finops_group_ledger", func(tx *Tx) error {
		replay, e := tx.GroupNativeTerminalSelect(f.ctx, n.b.ChainID, c.ID, terminal.Terminal.ID, n.prepared)
		if e == nil && replay {
			return ErrGroupNative
		}
		return e
	})
	f.must("finops_group_ledger", func(tx *Tx) error { return n.applied(tx, applied) })
	n.append(t, terminal, proof, true)
	f.must("finops_group_ledger", func(tx *Tx) error {
		replay, e := tx.GroupNativeTerminalSelect(f.ctx, n.b.ChainID, c.ID, terminal.Terminal.ID, n.prepared)
		if e == nil && !replay {
			return ErrGroupNative
		}
		return e
	})
	f.denied("finops_group_ledger", func(tx *Tx) error {
		_, e := tx.GroupNativeTerminalSelect(f.ctx, n.b.ChainID, c.ID, "conflicting-terminal", n.prepared)
		return e
	})
	// A genuine changed candidate-count effect, not only the no-change PREPARE,
	// must survive source revocation and an independently retired workspace.
	c = n.intent(t, 2)
	delivery, attempt = n.claim(t, c)
	unknown := n.protocolOriginalReceipt(t, g.JournalUnknown)
	unknown.Receipt.Before, unknown.Receipt.After = c.Before, c.Before
	unknown, e = g.SignJournalReceipt(unknown.Receipt, n.pipeline)
	if e != nil {
		t.Fatal(e)
	}
	n.originalEvent(t, g.JournalRecord{Kind: g.JournalUnknown, Receipt: &unknown})
	terminal, proof = n.terminal(t, c)
	n.append(t, terminal, proof, false)
	f.must("finops_group_ledger", func(tx *Tx) error {
		_, e := tx.GroupNativeTerminalSelect(f.ctx, n.b.ChainID, c.ID, terminal.Terminal.ID, n.prepared)
		return e
	})
	applied = n.protocolOriginalReceipt(t, g.JournalApplied)
	n.inbox(t, g.ContinuationOriginal, applied)
	f.must("finops_group_ledger", func(tx *Tx) error { return n.applied(tx, applied) })
	next := native.NativeWorkspace{Generation: "installed-second", RuntimeID: strings.Repeat("2", 64), ImageSHA256: n.workspace.ImageSHA256}
	retirement, e := native.SignNativeRetirement(native.NativeWorkspaceRetirement{SchemaVersion: "1", ID: model.ID(), TenantID: f.tenant, ChainID: n.b.ChainID, ProgramSHA256: g.Digest(n.prepared.Program), Method: "OWNED_DOCKER_CONTAINER_REMOVAL_CONFIRMED", Old: n.workspace, New: next, ObservedAt: time.Now().UTC()}, n.controller)
	if e != nil {
		t.Fatal(e)
	}
	_, foreignController, _ := ed25519.GenerateKey(rand.Reader)
	forgedRetirement, e := native.SignNativeRetirement(retirement.Retirement, foreignController)
	if e != nil {
		t.Fatal(e)
	}
	f.denied("finops_group_workspace_controller", func(tx *Tx) error {
		_, e := tx.GroupNativeWorkspaceActivate(f.ctx, n.b.ChainID, "workspace-controller", terminal.Terminal.ID, n.prepared, forgedRetirement)
		return e
	})
	f.must("finops_api", func(tx *Tx) error {
		source, e := tx.SourceGet(f.ctx, f.registration.SourceID)
		if e != nil {
			return e
		}
		source["enabled"] = false
		source["revoked"] = true
		_, e = tx.SourceUpdate(f.ctx, f.registration.SourceID, model.Number(source, "version"), source)
		return e
	})
	for i := 0; i < 2; i++ {
		f.must("finops_group_workspace_controller", func(tx *Tx) error {
			replay, e := tx.GroupNativeWorkspaceActivate(f.ctx, n.b.ChainID, "workspace-controller", terminal.Terminal.ID, n.prepared, retirement)
			if e == nil && replay != (i == 1) {
				return ErrGroupNative
			}
			return e
		})
	}
	request := GroupNativeReconstructionRequest{Mode: native.ReconstructionTerminal, WorkspaceGeneration: next.Generation, CommandID: c.ID, DeliveryID: delivery, AttemptID: attempt}
	for _, mutate := range []func(*GroupNativeReconstructionRequest){
		func(r *GroupNativeReconstructionRequest) { r.CommandID += "-foreign" },
		func(r *GroupNativeReconstructionRequest) { r.DeliveryID += "-foreign" },
		func(r *GroupNativeReconstructionRequest) { r.AttemptID += "-foreign" },
		func(r *GroupNativeReconstructionRequest) { r.CaptureID = "unselected-capture" },
	} {
		wrong := request
		mutate(&wrong)
		f.denied("finops_group_ledger", func(tx *Tx) error {
			return (GroupNativeReconstructionAuthority{Tx: tx, Prepared: n.prepared, Request: wrong}).WithCurrentNativeFence(f.ctx, n.b.ChainID, func(native.NativeReconstructionSnapshot) error {
				t.Error("foreign delivery binding reached native callback")
				return nil
			})
		})
	}
	f.must("finops_group_ledger", func(tx *Tx) error {
		return (GroupNativeReconstructionAuthority{Tx: tx, Prepared: n.prepared, Request: request}).WithCurrentNativeFence(f.ctx, n.b.ChainID, func(s native.NativeReconstructionSnapshot) error {
			if s.Workspace != next || s.TerminalRef != proof || s.Retirement == nil {
				return ErrGroupNative
			}
			p, e := g.VerifyJournal(s.View, s.Keys, s.ExpectedHead, time.Now().UTC())
			if e != nil || len(p.Stack) != 1 || p.Current.Model.CandidateCount != 2 || p.Current.StateSerial != terminal.Terminal.After.StateSerial {
				return ErrGroupNative
			}
			return nil
		})
	})
	request.WorkspaceGeneration = n.workspace.Generation
	f.denied("finops_group_ledger", func(tx *Tx) error {
		return (GroupNativeReconstructionAuthority{Tx: tx, Prepared: n.prepared, Request: request}).WithCurrentNativeFence(f.ctx, n.b.ChainID, func(native.NativeReconstructionSnapshot) error {
			t.Error("old generation reached callback")
			return nil
		})
	})
}
func TestGroupNativeUnregisteredLegacyAndRestrictedIdentity(t *testing.T) {
	n := newGroupNativeTest(t, false)
	n.protocolForward(t, 1)
	n.protocolForward(t, 2)
	for _, role := range []string{"finops_api", "finops_worker", "finops_signer", "finops_executor", "finops_ingester", "finops_group_fixture"} {
		n.f.denied(role, func(tx *Tx) error { _, e := tx.groupNativeScope(n.f.ctx, n.b.ChainID); return e })
	}
	cfg := n.f.roles["finops_group_workspace_controller"].Pool.Config().ConnConfig.Copy()
	cfg.RuntimeParams = map[string]string{}
	u := url.URL{Scheme: "postgres", User: url.UserPassword(cfg.User, cfg.Password), Host: net.JoinHostPort(cfg.Host, strconv.Itoa(int(cfg.Port))), Path: "/" + cfg.Database, RawQuery: "sslmode=disable"}
	dsn := u.String()
	db, e := OpenRuntime(n.f.ctx, dsn, "group-workspace-controller")
	if e != nil {
		t.Fatal(e)
	}
	db.Pool.Close()
	login := cfg.User
	if _, e = n.f.admin.Pool.Exec(n.f.ctx, "GRANT finops_api TO "+pgx.Identifier{login}.Sanitize()); e != nil {
		t.Fatal(e)
	}
	if bad, e := OpenRuntime(n.f.ctx, dsn, "group-workspace-controller"); e == nil {
		bad.Pool.Close()
		t.Fatal("mixed controller identity accepted")
	}
	if _, e = n.f.admin.Pool.Exec(n.f.ctx, "REVOKE finops_api FROM "+pgx.Identifier{login}.Sanitize()); e != nil {
		t.Fatal(e)
	}
	for _, flag := range []string{"REPLICATION", "BYPASSRLS"} {
		if _, e = n.f.admin.Pool.Exec(n.f.ctx, "ALTER ROLE "+pgx.Identifier{login}.Sanitize()+" "+flag); e != nil {
			t.Fatal(e)
		}
		if bad, e := OpenRuntime(n.f.ctx, dsn, "group-workspace-controller"); e == nil {
			bad.Pool.Close()
			t.Fatal("elevated controller identity accepted")
		}
		if _, e = n.f.admin.Pool.Exec(n.f.ctx, "ALTER ROLE "+pgx.Identifier{login}.Sanitize()+" NO"+flag); e != nil {
			t.Fatal(e)
		}
	}
	query := u.Query()
	query.Set("role", "finops_group_workspace_controller")
	u.RawQuery = query.Encode()
	if bad, e := OpenRuntime(context.Background(), u.String(), "group-workspace-controller"); e == nil {
		bad.Pool.Close()
		t.Fatal("startup role override accepted")
	} else if e.Error() != "RUNTIME_DATABASE_STARTUP_IDENTITY_OVERRIDE_FORBIDDEN" {
		t.Fatal("startup override rejected at wrong boundary", e)
	}
}

func TestGroupNativeSQLClosureTenantRolesAndUnclaimedDelivery(t *testing.T) {
	n := newGroupNativeTest(t, true)
	f := n.f
	c := n.intent(t)
	terminal, proof := n.terminal(t, c)
	insert := func(tx *Tx, raw []byte, ref ff.ArtifactReference) error {
		var observed struct {
			Terminal struct {
				ID string `json:"id"`
			} `json:"terminal"`
		}
		if e := json.Unmarshal(raw, &observed); e != nil {
			return e
		}
		_, e := tx.Exec(f.ctx, `INSERT INTO public.fleet_group_native_terminals(tenant_id,chain_id,id,command_id,operation_id,fence,workspace_generation,head_hash,artifact_id,review_id,capture_id,after_id,document,raw_document,content_hash) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,convert_from($13::bytea,'UTF8')::jsonb,$13,$14)`, f.tenant, n.b.ChainID, observed.Terminal.ID, c.ID, c.OperationID, c.Fence, n.workspace.Generation, g.Digest(terminal.Terminal.Head), ref.ID, terminal.Terminal.References.Review.ID, terminal.Terminal.References.Capture.ID, terminal.Terminal.References.After.ID, raw, ref.SHA256)
		return e
	}
	raw, _ := json.Marshal(terminal)
	e := f.run("finops_group_pipeline", func(tx *Tx) error { return insert(tx, raw, proof) })
	var sqlError *pgconn.PgError
	if !errors.As(e, &sqlError) || !strings.Contains(sqlError.Message, "claimed apply obligation") {
		t.Fatal("unclaimed direct SQL terminal was not refused by the actual delivery gate", e)
	}
	n.claim(t, c)
	mutations := []struct {
		name   string
		change func(model.Document, model.Document)
	}{
		{"null-observation", func(_ model.Document, b model.Document) { b["observed_at"] = nil }},
		{"string-fence", func(_ model.Document, b model.Document) { b["fence"] = "1" }},
		{"null-command-hash", func(_ model.Document, b model.Document) { b["command_sha256"] = nil }},
		{"different-command-hash", func(_ model.Document, b model.Document) { b["command_sha256"] = strings.Repeat("9", 64) }},
		{"foreign-tenant", func(_ model.Document, b model.Document) { b["tenant_id"] = "foreign-tenant" }},
		{"foreign-generation", func(_ model.Document, b model.Document) {
			w := fleetHistoryDocument(b["workspace"])
			w["generation"] = "foreign-generation"
			b["workspace"] = w
		}},
		{"extra-envelope-field", func(d model.Document, _ model.Document) { d["caller_authority"] = true }},
		{"extra-reference-kind", func(_ model.Document, b model.Document) {
			r := fleetHistoryDocument(b["references"])
			r["caller_upload"] = true
			b["references"] = r
		}},
		{"null-after-reference", func(_ model.Document, b model.Document) {
			r := fleetHistoryDocument(b["references"])
			r["after"] = nil
			b["references"] = r
		}},
		{"null-state-serial", func(_ model.Document, b model.Document) {
			a := fleetHistoryDocument(b["after"])
			a["state_serial"] = nil
			b["after"] = a
		}},
		{"extra-state-field", func(_ model.Document, b model.Document) {
			a := fleetHistoryDocument(b["after"])
			a["caller_authority"] = true
			b["after"] = a
		}},
		{"wrong-model", func(_ model.Document, b model.Document) {
			a := fleetHistoryDocument(b["after"])
			m := fleetHistoryDocument(a["model"])
			m["old_count"] = 19
			a["model"] = m
			b["after"] = a
		}},
	}
	for _, probe := range mutations {
		t.Run(probe.name, func(t *testing.T) {
			d := fleetHistoryDocument(terminal)
			body := fleetHistoryDocument(d["terminal"])
			id := model.ID()
			body["id"] = id
			probe.change(d, body)
			d["terminal"] = body
			bytes, _ := json.Marshal(d)
			r := groupArtifactRef(t, n.groupJournalTest, c, id, g.BytesDigest(bytes))
			r.SizeBytes = int64(len(bytes))
			f.must("finops_group_pipeline", func(tx *Tx) error {
				_, _, e := tx.GroupArtifactAppend(f.ctx, n.b.ChainID, c.ID, "NATIVE_OPERATION_PROOF", groupArtifactIdentity(), r)
				return e
			})
			err := f.run("finops_group_pipeline", func(tx *Tx) error { return insert(tx, bytes, r) })
			var p *pgconn.PgError
			if !errors.As(err, &p) || p.Code != "P0001" {
				t.Fatal("typed SQL boundary did not reject forged metadata", err)
			}
		})
	}
	n.append(t, terminal, proof, false)
	for _, role := range []string{"finops_api", "finops_worker", "finops_signer", "finops_executor", "finops_ingester", "finops_group_fixture"} {
		f.denied(role, func(tx *Tx) error {
			_, e := tx.Exec(f.ctx, `SELECT * FROM public.fleet_group_native_terminals WHERE tenant_id=$1`, f.tenant)
			return e
		})
	}
	f.denied("finops_group_pipeline", func(tx *Tx) error {
		_, e := tx.Exec(f.ctx, `UPDATE public.fleet_group_journal_outbox SET state=state WHERE tenant_id=$1`, f.tenant)
		return e
	})
	f.denied("finops_group_ledger", func(tx *Tx) error {
		_, e := tx.Exec(f.ctx, `UPDATE public.fleet_group_native_terminals SET document=document WHERE tenant_id=$1`, f.tenant)
		return e
	})
	f.denied("finops_group_workspace_controller", func(tx *Tx) error { return insert(tx, raw, proof) })
	for _, role := range []string{"finops_group_ledger", "finops_group_pipeline", "finops_group_workspace_controller"} {
		if e := f.roles[role].Do(f.ctx, f.tenant+"-other", func(tx *Tx) error {
			var count int
			if e := tx.QueryRow(f.ctx, `SELECT count(*) FROM public.fleet_group_workspaces`).Scan(&count); e != nil {
				return e
			}
			if count != 0 {
				return errors.New("foreign workspace leaked")
			}
			var scope []byte
			if e := tx.QueryRow(f.ctx, `SELECT public.fleet_group_reconstruction_scope($1,$2)`, tx.Tenant, n.b.ChainID).Scan(&scope); e != nil {
				return e
			}
			if len(scope) != 0 {
				return errors.New("foreign native root leaked")
			}
			return nil
		}); e != nil {
			t.Fatal(e)
		}
	}
	if e := f.admin.Do(f.ctx, f.tenant, func(tx *Tx) error {
		var count, bad, public int
		e := tx.QueryRow(f.ctx, `SELECT count(*),count(*) FILTER(WHERE replace(array_to_string(proconfig,','),' ','') NOT LIKE '%search_path=pg_catalog,public,pg_temp%'),count(*) FILTER(WHERE EXISTS(SELECT 1 FROM aclexplode(coalesce(proacl,acldefault('f',proowner))) a WHERE a.grantee=0 AND a.privilege_type='EXECUTE')) FROM pg_proc WHERE pronamespace='public'::regnamespace AND proname=ANY($1)`, []string{"fleet_group_reconstruction_scope", "fleet_group_reconstruction_lock", "fleet_group_reconstruction_journal", "fleet_group_reconstruction_delivery", "fleet_group_reconstruction_terminal_ref", "guard_group_workspace_key", "guard_group_workspace", "guard_group_native_terminal", "guard_group_terminal_selection", "guard_group_managed_applied"}).Scan(&count, &bad, &public)
		if e == nil && (count != 10 || bad != 0 || public != 0) {
			return errors.New("new function path or public execute widened")
		}
		return e
	}); e != nil {
		t.Fatal(e)
	}
}

func TestGroupNativeConcurrentSelectedReplayWaitsThenSurvivesApplied(t *testing.T) {
	n := newGroupNativeTest(t, true)
	f := n.f
	c := n.intent(t)
	n.claim(t, c)
	// Legacy same-ID storage remains compatible; real archives normally issue
	// their own independent object identity, exercised by the other families.
	terminal, ref := n.terminal(t, c, true)
	n.append(t, terminal, ref, false)
	applied := n.protocolOriginalReceipt(t, g.JournalApplied)
	n.inbox(t, g.ContinuationOriginal, applied)
	ctx, cancel := context.WithTimeout(f.ctx, 8*time.Second)
	defer cancel()
	held := make(chan struct{}, 1)
	release := make(chan struct{})
	var once sync.Once
	unlock := func() { once.Do(func() { close(release) }) }
	defer unlock()
	first := make(chan error, 1)
	go func() {
		first <- f.roles["finops_group_ledger"].Do(ctx, f.tenant, func(tx *Tx) error {
			replay, e := tx.GroupNativeTerminalSelect(ctx, n.b.ChainID, c.ID, terminal.Terminal.ID, n.prepared)
			if e != nil {
				return e
			}
			if replay {
				return errors.New("first selection replayed")
			}
			if e = n.applied(tx, applied); e != nil {
				return e
			}
			held <- struct{}{}
			select {
			case <-release:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		})
	}()
	select {
	case <-held:
	case e := <-first:
		t.Fatal("first selection/APPLIED failed", e)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	second := make(chan error, 1)
	pid := make(chan int, 1)
	go func() {
		second <- f.roles["finops_group_ledger"].Do(ctx, f.tenant, func(tx *Tx) error {
			var id int
			if e := tx.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&id); e != nil {
				return e
			}
			pid <- id
			replay, e := tx.GroupNativeTerminalSelect(ctx, n.b.ChainID, c.ID, terminal.Terminal.ID, n.prepared)
			if e == nil && !replay {
				return errors.New("concurrent exact selection did not replay")
			}
			return e
		})
	}()
	var backend int
	select {
	case backend = <-pid:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	waited := false
	for until := time.Now().Add(2 * time.Second); time.Now().Before(until); {
		if e := f.admin.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1 AND locktype='advisory' AND NOT granted)`, backend).Scan(&waited); e != nil {
			t.Fatal(e)
		}
		if waited {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !waited {
		t.Fatal("second real ledger transaction did not wait on the graph fence")
	}
	unlock()
	if e := <-first; e != nil {
		t.Fatal(e)
	}
	if e := <-second; e != nil {
		t.Fatal(e)
	}
	n.append(t, terminal, ref, true)
}
