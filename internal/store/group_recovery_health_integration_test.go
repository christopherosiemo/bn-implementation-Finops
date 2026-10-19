package store

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	ff "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetfixture"
	g "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetgroup"
	native "github.com/christopherosiemo/bn-implementation-Finops/internal/groupfixtureproducer"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
)

// These are actual restricted-role PostgreSQL storage tests with explicitly
// synthetic signed observation payloads, not real900s/HTTP/worker acceptance.
type recoveryHealthTest struct {
	n        *groupNativeTest
	key      ed25519.PrivateKey
	observer GroupRecoveryHealthObserver
}

func newRecoveryHealthTest(t *testing.T) *recoveryHealthTest {
	t.Helper()
	n := newGroupNativeTest(t, true)
	dir := t.TempDir()
	raw, e := os.ReadFile(filepath.Join("..", "..", "migrations", "034_group_recovery_health.sql"))
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(dir, "034_group_recovery_health.sql"), raw, 0600); e != nil {
		t.Fatal(e)
	}
	if e = n.f.admin.Migrate(n.f.ctx, dir); e != nil {
		t.Fatal(e)
	}
	groupJournalTestLogin(t, n.f, "finops_group_health_observer")
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	o := GroupRecoveryHealthObserver{ID: "fixture-observer", TenantID: n.f.tenant, ChainID: n.b.ChainID, DatabaseLogin: n.f.roles["finops_group_health_observer"].Pool.Config().ConnConfig.User, Identity: GroupRecoveryHealthIdentity{"fixture-health-source", "https://health.invalid", "fixture-health-observer", "fixture-group-health"}, PublicKey: key.Public().(ed25519.PublicKey), Limits: native.HealthLimits{MinimumSamples: 30, MaxP95NS: 2e9, MaxP99NS: 3e9, MaxErrorRatePPM: 10000, MinAvailabilityPPM: 990000, MaxInFlight: 2, MaxBacklog: 0}}
	limits, _ := json.Marshal(o.Limits)
	n.f.mustAdmin(func(tx *Tx) error {
		_, e := tx.Exec(n.f.ctx, `INSERT INTO public.fleet_group_recovery_health_observers(tenant_id,chain_id,id,profile_id,profile_generation,image_sha256,database_login,source_id,issuer,subject,audience,public_key,limits) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,convert_from($13::bytea,'UTF8')::jsonb)`, n.f.tenant, n.b.ChainID, o.ID, n.prepared.Program.Realm.FixtureID, n.prepared.Program.Realm.Generation, n.workspace.ImageSHA256, o.DatabaseLogin, o.Identity.SourceID, o.Identity.Issuer, o.Identity.Subject, o.Identity.Audience, o.PublicKey, limits)
		return e
	})
	return &recoveryHealthTest{n, key, o}
}

func recoveryHealthMigrate(t *testing.T, n *groupNativeTest) {
	t.Helper()
	dir := t.TempDir()
	raw, e := os.ReadFile(filepath.Join("..", "..", "migrations", "034_group_recovery_health.sql"))
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(dir, "034_group_recovery_health.sql"), raw, 0600); e != nil {
		t.Fatal(e)
	}
	if e = n.f.admin.Migrate(n.f.ctx, dir); e != nil {
		t.Fatal(e)
	}
}
func recoveryHealthForwardApplied(t *testing.T, n *groupNativeTest, c g.JournalCommand) {
	t.Helper()
	n.claim(t, c)
	terminal, ref := n.terminal(t, c)
	n.append(t, terminal, ref, false)
	n.f.must("finops_group_ledger", func(tx *Tx) error {
		_, e := tx.GroupNativeTerminalSelect(n.f.ctx, n.b.ChainID, c.ID, terminal.Terminal.ID, n.prepared)
		return e
	})
	receipt := n.protocolOriginalReceipt(t, g.JournalApplied)
	n.inbox(t, g.ContinuationOriginal, receipt)
	n.f.must("finops_group_ledger", func(tx *Tx) error { return n.applied(tx, receipt) })
}

// Genuine signed journal transitions; native/raw facts remain explicit storage
// dependency doubles. This is not a Terraform apply or elapsed health claim.
func recoveryHealthInverse(t *testing.T, n *groupNativeTest) {
	t.Helper()
	f := n.f
	var c g.JournalCommand
	var top g.JournalEffect
	f.must("finops_group_ledger", func(tx *Tx) error {
		v, k, e := tx.FleetGroupJournalOriginal(f.ctx, n.b.ChainID)
		if e != nil {
			return e
		}
		p, e := g.VerifyJournal(v, k.Core(), v.Head.Head.Ref, time.Now().UTC())
		if e != nil || len(p.Stack) != 1 {
			return errors.New("unit owned top missing")
		}
		top = p.Stack[0]
		source, _ := g.GitFixtureConfiguration(v.Parent.Program)
		desired, _ := g.GitFixtureDesired(v.Parent.Program, top.Forward.Child.Artifact.Before)
		revision, _, _ := fixtureUnitGit(source, desired, p.Current.Revision.Commit, 100)
		c = g.JournalCommand{ID: "health-owned-inverse", OperationID: "health-owned-inverse-op", IdempotencyKey: "health-owned-inverse-key", Fence: p.LastFence + 1, Head: v.Head, Before: p.Current, Preparation: g.JournalPreparation{Mode: g.JournalRecoveryMode, EffectID: top.ID, Revision: revision, Before: top.Forward.Child.Artifact.After, After: top.Forward.Child.Artifact.Before}, CreatedAt: time.Now().UTC()}
		return nil
	})
	n.originalEvent(t, g.JournalRecord{Kind: g.JournalPreparing, Command: &c})
	receipt := func(kind string) g.JournalReceiptEnvelope {
		t.Helper()
		var r g.JournalReceipt
		f.must("finops_group_ledger", func(tx *Tx) error {
			v, _, e := tx.FleetGroupJournalOriginal(f.ctx, n.b.ChainID)
			if e != nil {
				return e
			}
			before, after := c.Before, c.Before
			after.Revision = c.Preparation.Revision
			if kind == g.JournalReadyToApply || kind == g.JournalApplyIntent {
				before = after
			}
			if kind == g.JournalApplied {
				after.Model = c.Preparation.After
				after.StateSerial++
				after.StateSHA256 = strings.Repeat("9", 64)
			}
			r = g.JournalReceipt{SchemaVersion: "1", ID: model.ID(), IdempotencyKey: model.ID(), JournalID: v.Authorization.Authorization.JournalID, AuthorizationSHA256: g.Digest(v.Authorization), CommandID: c.ID, OperationID: c.OperationID, Fence: c.Fence, PipelineID: v.Authorization.Authorization.PipelineID, Kind: kind, PreparationSHA256: g.Digest(c.Preparation), Before: before, After: after, ReceivedAt: time.Now().UTC()}
			if c.Recovery != nil {
				r.ArtifactSHA256 = g.Digest(c.Recovery.Recovery.Artifact)
				r.SavedPlanSHA256 = c.Recovery.Recovery.Artifact.SavedPlanSHA256
			}
			if kind == g.JournalReadyToApply {
				r.ValidUntil = r.ReceivedAt.Add(30 * time.Second)
			}
			return nil
		})
		v, e := g.SignJournalReceipt(r, n.pipeline)
		if e != nil {
			t.Fatal(e)
		}
		return v
	}
	git := receipt(g.JournalGitAdvanced)
	n.originalEvent(t, g.JournalRecord{Kind: g.JournalGitAdvanced, Receipt: &git})
	f.must("finops_group_ledger", func(tx *Tx) error {
		v, k, e := tx.FleetGroupJournalOriginal(f.ctx, n.b.ChainID)
		if e != nil {
			return e
		}
		now := time.Now().UTC()
		a := g.GitArtifact{Kind: g.BuiltinFixtureArtifact, Receipt: g.SnapshotRef{ID: "health-inverse-review", SHA256: strings.Repeat("a", 64)}, BaseContextSHA256: g.Digest(v.Parent.Program.ArtifactContext), ManifestSHA256: v.Parent.Program.ManifestSHA256, PreviousRevision: c.Before.Revision, Revision: c.Preparation.Revision, BeforeStateSerial: c.Before.StateSerial, BeforeStateSHA256: c.Before.StateSHA256, SavedPlanSHA256: strings.Repeat("b", 64), PlanJSONSHA256: strings.Repeat("c", 64), Before: c.Preparation.Before, After: c.Preparation.After}
		r := g.JournalRecovery{SchemaVersion: "1", ID: "health-recovery", CommandID: c.ID, JournalID: v.Authorization.Authorization.JournalID, AuthorizationSHA256: g.Digest(v.Authorization), ParentEnvelopeSHA256: g.Digest(v.Parent), PreparationHeadSHA256: g.Digest(c.Head), SigningHeadSHA256: g.Digest(v.Head), EffectID: top.ID, OriginalChildSHA256: g.Digest(top.Forward.Child), OriginalReceiptSHA256: g.Digest(top.Applied), Artifact: a, MinimumObservationSeconds: 120, CreatedAt: now, ExpiresAt: now.Add(10 * time.Minute), Nonce: "health-recovery-nonce"}
		for _, kind := range []string{"FIXTURE_CURRENT", "FIXTURE_RECOVERY_SLO"} {
			r.Evidence = append(r.Evidence, g.EvidenceRef{Kind: kind, ID: "unit-" + kind, SHA256: strings.Repeat("f", 64), BindingSHA256: g.Digest(v.Parent.Program.Binding), RealmSHA256: g.Digest(v.Parent.Program.Realm), ObservedAt: now, ValidUntil: r.ExpiresAt})
		}
		signed, e := g.SignJournalRecovery(r, v, k.Core(), v.Head.Head.Ref, n.signer, now)
		c.Recovery = &signed
		return e
	})
	n.originalEvent(t, g.JournalRecord{Kind: g.JournalReserved, Command: &c})
	for _, kind := range []string{g.JournalReadyToApply, g.JournalApplyIntent} {
		r := receipt(kind)
		n.originalEvent(t, g.JournalRecord{Kind: kind, Receipt: &r})
	}
	n.claim(t, c)
	var view g.JournalView
	f.must("finops_group_ledger", func(tx *Tx) error {
		var e error
		view, _, e = tx.FleetGroupJournalOriginal(f.ctx, n.b.ChainID)
		return e
	})
	after := c.Before
	after.Revision = c.Preparation.Revision
	after.Model = c.Preparation.After
	after.StateSerial++
	after.StateSHA256 = strings.Repeat("9", 64)
	artifact := c.Recovery.Recovery.Artifact
	refs := native.NativeReconstructionRefs{Review: groupArtifactRef(t, n.groupJournalTest, c, artifact.Receipt.ID, artifact.Receipt.SHA256), Capture: groupArtifactRef(t, n.groupJournalTest, c, "health-recovery-capture", strings.Repeat("8", 64)), After: groupArtifactRef(t, n.groupJournalTest, c, "health-recovery-after", after.StateSHA256)}
	body := native.NativeTerminal{SchemaVersion: "1", ID: model.ID(), TenantID: f.tenant, ChainID: n.b.ChainID, ProgramSHA256: g.Digest(view.Parent.Program), AuthorizationSHA256: g.Digest(view.Authorization), CommandSHA256: g.Digest(c), OperationID: c.OperationID, Fence: c.Fence, ArtifactSHA256: g.Digest(artifact), PreparationSHA256: g.Digest(c.Preparation), Workspace: n.workspace, References: refs, Before: c.Before, After: after, Head: view.Head, ObservedAt: time.Now().UTC()}
	raw, _ := json.Marshal(body)
	envelope := native.NativeTerminalEnvelope{Terminal: body, Algorithm: "Ed25519/group-fixture-native/v1", Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(n.pipeline, append([]byte("finops/group-fixture/native-terminal/v1\x00"), raw...)))}
	encoded, _ := json.Marshal(envelope)
	ref := groupArtifactRef(t, n.groupJournalTest, c, "health-terminal-archive", g.BytesDigest(encoded))
	ref.SizeBytes = int64(len(encoded))
	for _, p := range []struct {
		kind string
		ref  ff.ArtifactReference
	}{{"NATIVE_ARTIFACT_REVIEW", refs.Review}, {"NATIVE_CAPTURE", refs.Capture}, {"AFTER_NATIVE_STATE", refs.After}, {"NATIVE_OPERATION_PROOF", ref}} {
		f.must("finops_group_pipeline", func(tx *Tx) error {
			_, _, e := tx.GroupArtifactAppend(f.ctx, n.b.ChainID, c.ID, p.kind, groupArtifactIdentity(), p.ref)
			return e
		})
	}
	n.append(t, envelope, ref, false)
	f.must("finops_group_ledger", func(tx *Tx) error {
		_, e := tx.GroupNativeTerminalSelect(f.ctx, n.b.ChainID, c.ID, body.ID, n.prepared)
		return e
	})
	applied := receipt(g.JournalApplied)
	n.inbox(t, g.ContinuationOriginal, applied)
	f.must("finops_group_ledger", func(tx *Tx) error { return n.applied(tx, applied) })
}

func TestGroupRecoveryHealth033OwnedUpgradeRetainsInverseAndRelease(t *testing.T) {
	n := newGroupNativeTest(t, true)
	recoveryHealthForwardApplied(t, n, n.intent(t, 1))
	recoveryHealthForwardApplied(t, n, n.intent(t, 2))
	recoveryHealthMigrate(t, n)
	n.f.must("finops_group_ledger", func(tx *Tx) error {
		var count int
		if e := tx.QueryRow(n.f.ctx, `SELECT count(*) FROM public.fleet_group_recovery_health_legacy WHERE tenant_id=$1 AND chain_id=$2 AND head_hash=$3`, n.f.tenant, n.b.ChainID, n.cursor.HeadSHA256).Scan(&count); e != nil {
			return e
		}
		if count != 1 {
			return errors.New("migration legacy exemption missing")
		}
		return nil
	})
	recoveryHealthInverse(t, n)
	n.f.must("finops_group_ledger", func(tx *Tx) error { return tx.FleetGroupJournalRelease(n.f.ctx, n.b.ChainID, n.cursor) })
	for _, role := range []string{"finops_api", "finops_group_ledger", "finops_group_pipeline"} {
		n.f.denied(role, func(tx *Tx) error {
			_, e := tx.Exec(n.f.ctx, `INSERT INTO public.fleet_group_recovery_health_legacy(tenant_id,chain_id,head_hash,reason) VALUES($1,$2,$3,'PRE034_ISSUED_INTENT_RECOVERY_ONLY')`, n.f.tenant, n.b.ChainID, n.cursor.HeadSHA256)
			return e
		})
	}
}
func (f *fleetHistoryDBTest) mustAdmin(fn func(*Tx) error) {
	f.t.Helper()
	if e := f.admin.Do(f.ctx, f.tenant, fn); e != nil {
		f.t.Fatal(e)
	}
}

func (h *recoveryHealthTest) preparing(t *testing.T) g.JournalCommand {
	n := h.n
	var c g.JournalCommand
	n.f.must("finops_group_ledger", func(tx *Tx) error {
		v, k, e := tx.FleetGroupJournalOriginal(n.f.ctx, n.b.ChainID)
		if e != nil {
			return e
		}
		p, e := g.VerifyJournal(v, k.Core(), v.Head.Head.Ref, time.Now().UTC())
		if e != nil {
			return e
		}
		entry := v.Parent.Program.Manifest.Entries[0]
		c = g.JournalCommand{ID: "baseline-prepare", OperationID: "baseline-operation", IdempotencyKey: "baseline-command-key", Fence: p.LastFence + 1, Head: v.Head, Before: p.Current, Preparation: g.JournalPreparation{Mode: g.Forward, Sequence: 1, ManifestEntrySHA256: g.Digest(entry), Revision: entry.Revision, Before: entry.Before, After: entry.After}, CreatedAt: time.Now().UTC()}
		return nil
	})
	n.originalEvent(t, g.JournalRecord{Kind: g.JournalPreparing, Command: &c})
	return c
}

// Finalizes only signed storage dependency facts, without claiming Terraform
// execution. Keeping intent separate lets the SQL dispatch guard be exercised.
func recoveryHealthReserved(t *testing.T, n *groupNativeTest, c g.JournalCommand) g.JournalCommand {
	t.Helper()
	git := n.protocolOriginalReceipt(t, g.JournalGitAdvanced)
	n.originalEvent(t, g.JournalRecord{Kind: g.JournalGitAdvanced, Receipt: &git})
	p := n.b.Parent.Program
	entry := p.Manifest.Entries[c.Preparation.Sequence-1]
	now := time.Now().UTC()
	child := g.GitChild{SchemaVersion: g.GitSchemaVersion, ID: "health-child-" + c.ID, ParentID: p.ID, ParentSHA256: g.Digest(p), BindingSHA256: g.Digest(p.Binding), RealmSHA256: g.Digest(p.Realm), Mode: g.Forward, StageID: entry.StageID, StageSHA256: entry.StageSHA256, Sequence: entry.Sequence, Artifact: g.GitArtifact{Kind: g.BuiltinFixtureArtifact, Receipt: g.SnapshotRef{ID: "health-review-" + c.ID, SHA256: strings.Repeat("a", 64)}, BaseContextSHA256: g.Digest(p.ArtifactContext), ManifestSHA256: p.ManifestSHA256, ManifestEntrySHA256: g.Digest(entry), PreviousRevision: c.Before.Revision, Revision: entry.Revision, BeforeStateSerial: c.Before.StateSerial, BeforeStateSHA256: c.Before.StateSHA256, SavedPlanSHA256: strings.Repeat("b", 64), PlanJSONSHA256: strings.Repeat("c", 64), Before: entry.Before, After: entry.After}, MinimumObservationSeconds: entry.MinimumObservationSeconds, CreatedAt: now, ExpiresAt: now.Add(10 * time.Minute), Nonce: "health-nonce-" + c.ID}
	for _, kind := range []string{"FIXTURE_CURRENT", "FIXTURE_DEPENDENCY", "FIXTURE_SLO"} {
		child.Evidence = append(child.Evidence, g.EvidenceRef{Kind: kind, ID: "unit-" + kind, SHA256: strings.Repeat("d", 64), BindingSHA256: g.Digest(p.Binding), RealmSHA256: g.Digest(p.Realm), ObservedAt: now, ValidUntil: now.Add(time.Hour)})
	}
	signed, e := g.SignGitChild(child, n.b.Parent, n.signer, now)
	if e != nil {
		t.Fatal(e)
	}
	c.Forward = &signed
	n.originalEvent(t, g.JournalRecord{Kind: g.JournalReserved, Command: &c})
	ready := n.protocolOriginalReceipt(t, g.JournalReadyToApply)
	n.originalEvent(t, g.JournalRecord{Kind: g.JournalReadyToApply, Receipt: &ready})
	return c
}
func recoveryHealthAppendIntent(t *testing.T, n *groupNativeTest) error {
	t.Helper()
	receipt := n.protocolOriginalReceipt(t, g.JournalApplyIntent)
	n.inbox(t, g.ContinuationOriginal, receipt)
	return n.f.run("finops_group_ledger", func(tx *Tx) error {
		v, k, e := tx.FleetGroupJournalOriginal(n.f.ctx, n.b.ChainID)
		if e != nil {
			return e
		}
		at := time.Now().UTC()
		r := g.JournalRecord{Kind: g.JournalApplyIntent, Receipt: &receipt, Sequence: uint64(len(v.Records) + 1), PreviousSHA256: v.Head.Head.Ref.LastRecordSHA256, RecordedAt: at}
		records, _, e := g.AppendJournalRecord(v, k.Core(), v.Head.Head.Ref, r, at)
		if e != nil {
			return e
		}
		sealed, _, e := g.SealJournalView(v.Parent, v.Authorization, records, k.Core(), n.ledger, at)
		if e != nil {
			return e
		}
		next, _, e := tx.FleetGroupJournalAppendOriginal(n.f.ctx, n.b.ChainID, n.cursor, r, sealed.Head)
		if e == nil {
			n.cursor = next
		}
		return e
	})
}
func TestGroupRecoveryHealth034ForbidsLegacyForwardAndUncommissionedDispatch(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		t.Run(strconv.FormatBool(legacy), func(t *testing.T) {
			n := newGroupNativeTest(t, true)
			sequence := uint64(1)
			if legacy {
				recoveryHealthForwardApplied(t, n, n.intent(t, 1))
				recoveryHealthForwardApplied(t, n, n.intent(t, 2))
				sequence = 3
			}
			recoveryHealthMigrate(t, n)
			var c g.JournalCommand
			n.f.must("finops_group_ledger", func(tx *Tx) error {
				v, k, e := tx.FleetGroupJournalOriginal(n.f.ctx, n.b.ChainID)
				if e != nil {
					return e
				}
				p, e := g.VerifyJournal(v, k.Core(), v.Head.Head.Ref, time.Now().UTC())
				if e != nil {
					return e
				}
				entry := v.Parent.Program.Manifest.Entries[sequence-1]
				c = g.JournalCommand{ID: "blocked-forward", OperationID: "blocked-operation", IdempotencyKey: "blocked-idempotency", Fence: p.LastFence + 1, Head: v.Head, Before: p.Current, Preparation: g.JournalPreparation{Mode: g.Forward, Sequence: sequence, ManifestEntrySHA256: g.Digest(entry), Revision: entry.Revision, Before: entry.Before, After: entry.After}, CreatedAt: time.Now().UTC()}
				return nil
			})
			n.originalEvent(t, g.JournalRecord{Kind: g.JournalPreparing, Command: &c})
			recoveryHealthReserved(t, n, c)
			err := recoveryHealthAppendIntent(t, n)
			wanted := "commissioned health observer"
			if legacy {
				wanted = "permanently recovery only"
			}
			if err == nil || !strings.Contains(err.Error(), wanted) {
				t.Fatalf("expected exact managed dispatch refusal %q: %v", wanted, err)
			}
		})
	}
}

func TestGroupRecoveryHealthCommissionedRolesScopeAndPre034Guard(t *testing.T) {
	h := newRecoveryHealthTest(t)
	n := h.n
	f := n.f
	cfg := f.roles["finops_group_health_observer"].Pool.Config().ConnConfig
	dsn := (&url.URL{Scheme: "postgres", User: url.UserPassword(cfg.User, cfg.Password), Host: net.JoinHostPort(cfg.Host, strconv.Itoa(int(cfg.Port))), Path: "/" + cfg.Database, RawQuery: "sslmode=disable"}).String()
	runtime, e := OpenRuntime(f.ctx, dsn, "group-health-observer")
	if e != nil {
		t.Fatal("dedicated observer OpenRuntime", e)
	}
	runtime.Pool.Close()
	f.must("finops_group_health_observer", func(tx *Tx) error {
		s, e := tx.GroupRecoveryHealthSnapshot(f.ctx, n.b.ChainID, h.observer.ID, n.workspace.Generation)
		if e == nil && (s.Released || s.Observer.ID != h.observer.ID || s.Workspace != n.workspace) {
			return ErrGroupRecoveryHealth
		}
		return e
	})
	for _, role := range []string{"finops_api", "finops_worker", "finops_signer", "finops_executor", "finops_group_pipeline", "finops_group_fixture"} {
		f.denied(role, func(tx *Tx) error {
			_, e := tx.GroupRecoveryHealthSnapshot(f.ctx, n.b.ChainID, h.observer.ID, n.workspace.Generation)
			return e
		})
	}
	f.denied("finops_group_ledger", func(tx *Tx) error {
		_, _, e := tx.GroupRecoveryHealthObservationAppend(f.ctx, h.observer.Identity, GroupRecoveryHealthObservationEnvelope{})
		return e
	})
	f.denied("finops_group_health_observer", func(tx *Tx) error { _, e := tx.FleetGroupJournalCursor(f.ctx, n.b.ChainID); return e })
	f.denied("finops_group_health_observer", func(tx *Tx) error {
		_, e := tx.Exec(f.ctx, `UPDATE public.fleet_group_journal_reservations SET released_at=clock_timestamp() WHERE tenant_id=$1 AND chain_id=$2`, f.tenant, n.b.ChainID)
		return e
	})
	f.denied("finops_group_ledger", func(tx *Tx) error {
		_, e := tx.Exec(f.ctx, `INSERT INTO public.fleet_group_recovery_health_outcomes(tenant_id,chain_id,id) VALUES($1,$2,'forged')`, f.tenant, n.b.ChainID)
		return e
	})
	f.must("finops_group_ledger", func(tx *Tx) error {
		e := tx.groupRecoveryHealthReleaseGuard(f.ctx, n.b.ChainID, n.cursor.HeadSHA256)
		if !errors.Is(e, ErrGroupRecoveryHealth) {
			return errors.New("managed release lacked health guard")
		}
		return nil
	})
	// New additive Go must remain usable against an older capped schema.
	legacy := newGroupNativeTest(t, false)
	legacy.f.must("finops_group_ledger", func(tx *Tx) error {
		if e := tx.groupRecoveryHealthReleaseGuard(legacy.f.ctx, legacy.b.ChainID, legacy.cursor.HeadSHA256); e != nil {
			return e
		}
		var one int
		return tx.QueryRow(legacy.f.ctx, `SELECT 1`).Scan(&one)
	})
}

func TestGroupRecoveryHealthSQLMeasurementClosure(t *testing.T) {
	h := newRecoveryHealthTest(t)
	f := h.n.f
	// This tests immutable SQL arithmetic on synthetic component JSON. It does
	// not publish observations, backdate database rows, or claim real900s.
	start := time.Now().UTC().Add(-901 * time.Second).Truncate(time.Microsecond)
	receipts := []model.Document{}
	hashes := []string{}
	var previous model.Document
	previousHash := ""
	for i := 0; i < 30; i++ {
		before := model.Document{"captured_at": start.Add(time.Duration(i) * 30 * time.Second)}
		if previous != nil {
			before = previous
		}
		after := model.Document{"captured_at": start.Add(time.Duration(i+1) * 30 * time.Second)}
		observations := []int{}
		for j := 0; j < 30; j++ {
			observations = append(observations, j)
		}
		hash := strings.Repeat("a", 63) + strconv.FormatInt(int64(i%10), 10)
		receipts = append(receipts, model.Document{"sequence": i + 1, "previous_sha256": previousHash, "sha256": hash, "before": before, "after": after, "clock": model.Document{"elapsed_ns": int64(30 * time.Second)}, "observations": observations})
		hashes = append(hashes, hash)
		previous = after
		previousHash = hash
	}
	window := model.Document{"status": "OBSERVED", "reason_codes": []string{}, "start": start, "required_end": start.Add(900 * time.Second), "observed_through": start.Add(900 * time.Second), "receipt_sha256s": hashes, "sample_count": 900, "p95_ns": int64(time.Second), "p99_ns": int64(time.Second), "baseline_p95_ns": int64(time.Second), "baseline_p99_ns": int64(time.Second), "error_rate_ppm": 0, "availability_ppm": 1000000, "backlog": 0, "inflight": 0, "definition": native.HealthCompletedOperation, "availability_basis": "OBSERVED_HTTP_REQUEST_SUCCESS", "customer_execution_authorized": false, "measurement_revision": "GO_MONOTONIC_HTTP_V2", "monotonic_duration_ns": int64(900 * time.Second)}
	check := func(win model.Document, raw []model.Document, started, asof time.Time, want bool) {
		t.Helper()
		w, _ := json.Marshal(win)
		r, _ := json.Marshal(raw)
		var actual bool
		if e := f.admin.Pool.QueryRow(f.ctx, `SELECT public.fleet_group_recovery_health_measurements(convert_from($1::bytea,'UTF8')::jsonb,convert_from($2::bytea,'UTF8')::jsonb,$3,$4)`, w, r, started, asof).Scan(&actual); e != nil || actual != want {
			t.Fatalf("SQL measurement verdict %v want%v: %v", actual, want, e)
		}
	}
	check(window, receipts, start, start.Add(901*time.Second), true)
	for _, change := range []func(model.Document){func(w model.Document) { delete(w, "monotonic_duration_ns") }, func(w model.Document) { w["monotonic_duration_ns"] = int64(899 * time.Second) }, func(w model.Document) { w["sample_count"] = 901 }, func(w model.Document) { w["p99_ns"] = int64(2 * time.Second) }, func(w model.Document) { w["customer_execution_authorized"] = true }, func(w model.Document) { w["required_end"] = start.Add(899 * time.Second) }} {
		raw, _ := json.Marshal(window)
		var bad model.Document
		_ = json.Unmarshal(raw, &bad)
		change(bad)
		check(bad, receipts, start, start.Add(901*time.Second), false)
	}
	check(window, receipts, start.Add(time.Second), start.Add(901*time.Second), false)
	check(window, receipts, start, start.Add(800*time.Second), false)
	encoded, _ := json.Marshal(receipts)
	var broken []model.Document
	_ = json.Unmarshal(encoded, &broken)
	broken[10]["previous_sha256"] = "foreign"
	check(window, broken, start, start.Add(901*time.Second), false)
}

func TestGroupRecoveryHealthSignedRawReplayTenantAndGeneration(t *testing.T) {
	h := newRecoveryHealthTest(t)
	n := h.n
	f := n.f
	c := h.preparing(t)
	now := time.Now().UTC()
	binding := native.HealthBinding{Binding: n.prepared.Program.Binding, Realm: n.prepared.Program.Realm, ProgramSHA256: g.Digest(n.prepared.Program), CommandID: "actual-observer", OperationID: "actual-health-operation", Fence: 1}
	r := native.HealthReceipt{SchemaVersion: "2", InstallationID: "synthetic-unit-installation", Binding: binding, Sequence: 1, MeasurementRevision: "GO_MONOTONIC_HTTP_V2", Before: native.HealthSnapshot{CapturedAt: now.Add(-2 * time.Second)}, After: native.HealthSnapshot{CapturedAt: now.Add(-time.Second)}}
	r.SHA256 = native.HealthReceiptSHA256(r)
	plain, _ := json.Marshal(r)
	ref := groupArtifactRef(t, n.groupJournalTest, c, "health-baseline-raw", g.BytesDigest(plain))
	ref.SizeBytes = int64(len(plain))
	f.must("finops_group_pipeline", func(tx *Tx) error {
		_, _, e := tx.GroupArtifactAppend(f.ctx, n.b.ChainID, c.ID, "HEALTH_BASELINE", groupArtifactIdentity(), ref)
		return e
	})
	body := GroupRecoveryHealthObservation{SchemaVersion: "1", ID: model.ID(), TenantID: f.tenant, ChainID: n.b.ChainID, ObserverID: h.observer.ID, Workspace: n.workspace, Phase: "BASELINE", CommandID: c.ID, Receipt: r, Reference: ref, SignedAt: now}
	envelope, e := SignGroupRecoveryHealthObservation(body, h.key)
	if e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 2; i++ {
		f.must("finops_group_health_observer", func(tx *Tx) error {
			_, replayed, e := tx.GroupRecoveryHealthObservationAppend(f.ctx, h.observer.Identity, envelope)
			if e == nil && replayed != (i == 1) {
				return errors.New("raw exact replay appended")
			}
			return e
		})
	}
	for _, change := range []func(*GroupRecoveryHealthObservation){func(v *GroupRecoveryHealthObservation) { v.TenantID += "-foreign" }, func(v *GroupRecoveryHealthObservation) { v.Workspace.Generation += "-old" }, func(v *GroupRecoveryHealthObservation) { v.Reference.VersionID += "-wrong" }, func(v *GroupRecoveryHealthObservation) {
		v.Receipt.Binding.ProgramSHA256 = strings.Repeat("f", 64)
		v.Receipt.SHA256 = native.HealthReceiptSHA256(v.Receipt)
	}} {
		wrong := body
		wrong.ID = model.ID()
		change(&wrong)
		bad, _ := SignGroupRecoveryHealthObservation(wrong, h.key)
		f.denied("finops_group_health_observer", func(tx *Tx) error {
			_, _, e := tx.GroupRecoveryHealthObservationAppend(f.ctx, h.observer.Identity, bad)
			return e
		})
	}
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	bad, _ := SignGroupRecoveryHealthObservation(body, other)
	f.denied("finops_group_health_observer", func(tx *Tx) error {
		_, _, e := tx.GroupRecoveryHealthObservationAppend(f.ctx, h.observer.Identity, bad)
		return e
	})
	// Revoked forward source cannot rewrite or erase already owned health scope.
	f.must("finops_api", func(tx *Tx) error {
		v, e := tx.SourceGet(f.ctx, f.registration.SourceID)
		if e != nil {
			return e
		}
		v["enabled"] = false
		v["revoked"] = true
		_, e = tx.SourceUpdate(f.ctx, f.registration.SourceID, model.Number(v, "version"), v)
		return e
	})
	f.must("finops_group_health_observer", func(tx *Tx) error {
		_, e := tx.GroupRecoveryHealthSnapshot(f.ctx, n.b.ChainID, h.observer.ID, n.workspace.Generation)
		return e
	})
}

// Commission another real025/027/029/030/033 chain in the SAME marked DB.
// Distinct workload IDs avoid the real cross-family admission reservation.
func recoveryHealthSibling(t *testing.T, base *recoveryHealthTest, tenant string) *recoveryHealthTest {
	t.Helper()
	old := base.n
	original := old.f
	suffix := strings.ReplaceAll(model.ID(), "-", "")
	copyF := *original
	f := &copyF
	f.tenant = tenant
	f.roles = map[string]*Store{}
	for k, v := range original.roles {
		f.roles[k] = v
	}
	f.activity = original.activity
	f.activity.ID += "-" + suffix
	f.activity.WorkloadID += "-" + suffix
	f.activity.ResourceID += "-" + suffix
	f.activity.ProviderResourceID = "i-" + suffix[:17]
	var source model.Document
	original.must("finops_api", func(tx *Tx) error {
		v, e := tx.SourceGet(original.ctx, original.registration.SourceID)
		source = model.Document{}
		for _, k := range []string{"kind", "payer_account_id", "usage_account_ids", "region", "export_arn", "bucket", "bucket_owner", "prefix", "read_role_binding_id", "enabled"} {
			source[k] = v[k]
		}
		return e
	})
	source["id"] = "sibling-source-" + suffix
	f.registration = original.registration
	f.registration.ID += "-" + suffix
	f.registration.FleetID += "-" + suffix
	f.registration.Binding.TenantID = tenant
	f.registration.Binding.WorkloadID = f.activity.WorkloadID
	f.registration.SourceID = model.String(source, "id")
	f.registration.ASGARN = "arn:aws:autoscaling:eu-west-1:111122223333:autoScalingGroup:" + model.ID() + ":autoScalingGroupName/old-" + suffix
	f.definition = original.definition
	f.definition.ID += "-" + suffix
	f.definition.Binding = f.registration.Binding
	f.definition.SourceID = f.activity.ID
	f.definition.SourceConfigHash = fleetHistoryHash(fleetHistoryDocument(f.activity))
	f.must("finops_api", func(tx *Tx) error {
		if _, e := tx.Create(f.ctx, "workloads", model.Document{"id": f.activity.WorkloadID, "name": "Independent RLS workload"}); e != nil {
			return e
		}
		if _, e := tx.Create(f.ctx, "resources", model.Document{"id": f.activity.ResourceID, "workload_id": f.activity.WorkloadID, "provider": "AWS", "provider_resource_id": f.activity.ProviderResourceID, "account_id": f.activity.AccountID, "region": f.activity.Region}); e != nil {
			return e
		}
		if _, e := tx.SourceCreate(f.ctx, source); e != nil {
			return e
		}
		_, e := tx.ActivityRegister(f.ctx, f.activity)
		return e
	})
	f.must("finops_ingester", func(tx *Tx) error {
		return tx.SourceCheckpointSet(f.ctx, f.registration.SourceID, "status", model.Document{"status": "HEALTHY", "config_hash": f.registration.SourceConfigHash, "last_sync_at": time.Now().UTC().Format(time.RFC3339Nano)})
	})
	selectedIDs := []string{}
	for i := 0; i < 2; i++ {
		r := f.registration
		d := f.definition
		if i == 1 {
			r.ID += "-candidate"
			r.FleetID += "-candidate"
			r.ASGARN = "arn:aws:autoscaling:eu-west-1:111122223333:autoScalingGroup:" + model.ID() + ":autoScalingGroupName/candidate-" + suffix
			d.ID += "-candidate"
		}
		metadata := fleetConfigurationFixture(t, "refs/heads/finops")
		if i == 1 {
			metadata.Terraform.ASGAddress = "module.fleet.aws_autoscaling_group.candidate"
			metadata.Terraform.LaunchTemplateAddress = "module.fleet.aws_launch_template.candidate"
		}
		f.must("finops_api", func(tx *Tx) error {
			if _, e := tx.FleetHistoryRegistrationAppend(f.ctx, 0, r); e != nil {
				return e
			}
			if _, e := tx.FleetDemandDefinitionAppend(f.ctx, r.ID, 0, d); e != nil {
				return e
			}
			decl, e := tx.FleetConfigurationAppend(f.ctx, r.ID, 0, "operator", metadata)
			if e != nil {
				return e
			}
			scope, e := tx.FleetHistoryScopeCapture(f.ctx, r.ID, d.ID)
			if e != nil {
				return e
			}
			p, e := tx.FleetConfigurationProposalCreate(f.ctx, r.ID, model.String(decl, "id"), model.String(scope, "id"), 1, "operator")
			if e == nil {
				selectedIDs = append(selectedIDs, model.String(p, "id"))
			}
			return e
		})
	}
	var selected model.Document
	f.must("finops_api", func(tx *Tx) error {
		var e error
		selected, e = tx.FleetFixtureProposalCreate(f.ctx, "sibling-creator", ff.SelectionRequest{OldConfigurationProposalID: selectedIDs[0], CandidateConfigurationProposalID: selectedIDs[1], FixtureProfileID: old.prepared.Program.Realm.FixtureID})
		return e
	})
	proposal, e := FleetFixtureProposalDocument(selected)
	if e != nil {
		t.Fatal(e)
	}
	prepared := fleetFixtureUnitPreparation(t, proposal)
	prepared.JournalReview.PipelineKeySHA256 = g.BytesDigest(old.pipeline.Public().(ed25519.PublicKey))
	prepared.JournalReview.LedgerKeySHA256 = g.BytesDigest(old.ledger.Public().(ed25519.PublicKey))
	var preparedRow, approved model.Document
	f.must("finops_group_fixture", func(tx *Tx) error {
		var e error
		preparedRow, e = tx.FleetFixturePreparedProgramAppend(f.ctx, proposal.ID, prepared)
		return e
	})
	f.must("finops_api", func(tx *Tx) error {
		var e error
		approved, e = tx.FleetFixtureApprove(f.ctx, proposal.ID, 2, "sibling-independent-approver")
		return e
	})
	keys := old.b.Keys
	b := FleetGroupJournalBootstrap{ChainID: "sibling-chain-" + suffix, KeyBindingID: old.b.KeyBindingID, PreparedProgramID: model.String(preparedRow, "id"), ApprovalID: model.String(fleetHistoryDocument(approved["approval"]), "id"), Keys: keys}
	if tenant != original.tenant {
		f.mustAdmin(func(tx *Tx) error {
			_, e := tx.Exec(f.ctx, `INSERT INTO public.fleet_group_journal_key_bindings(tenant_id,id,profile_id,profile_generation,realm,pipeline_id,source_id,issuer,subject,audience,signer_key,pipeline_key,ledger_key) VALUES($1,$2,$3,$4,$5,$6,'fixture-machine','https://fixture.example.invalid','group-pipeline','finops-group-pipeline',$7,$8,$9)`, tenant, b.KeyBindingID, prepared.Program.Realm.FixtureID, prepared.Program.Realm.Generation, groupJournalRealmBytes(prepared.Program.Realm), prepared.Program.ArtifactContext.PipelineID, keys.Signer, keys.Pipeline, keys.Ledger)
			return e
		})
	}
	var pa g.Approval
	f.must("finops_group_ledger", func(tx *Tx) error {
		var e error
		pa, e = tx.FleetGroupJournalParentApproval(f.ctx, b.PreparedProgramID, b.ApprovalID)
		return e
	})
	b.Parent, e = g.SignGitProgram(prepared.Program, []g.Approval{pa}, old.signer, time.Now().UTC())
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now().UTC()
	a := g.JournalAuthorization{SchemaVersion: "1", Kind: g.JournalKind, ID: "sibling-auth-" + suffix, JournalID: "sibling-journal-" + suffix, ParentEnvelopeSHA256: g.Digest(b.Parent), ParentSHA256: g.Digest(prepared.Program), BindingSHA256: g.Digest(prepared.Program.Binding), RealmSHA256: g.Digest(prepared.Program.Realm), PipelineID: prepared.Program.ArtifactContext.PipelineID, Ref: prepared.Program.Manifest.Ref, Policy: g.JournalPolicy, Base: prepared.JournalReview.Base, PipelineKeySHA256: g.BytesDigest(keys.Pipeline), LedgerKeySHA256: g.BytesDigest(keys.Ledger), MaximumEffects: 32, MaximumRecords: 512, CreatedAt: now, ExpiresAt: prepared.Program.ExpiresAt, Nonce: "sibling-nonce-" + suffix}
	var draft FleetGroupAuthorityDraft
	var ap FleetGroupAuthorityApproval
	f.must("finops_group_ledger", func(tx *Tx) error {
		var e error
		draft, e = tx.FleetGroupJournalDraftAuthorization(f.ctx, b, "JOURNAL", a)
		return e
	})
	f.must("finops_api", func(tx *Tx) error {
		var e error
		ap, e = tx.FleetGroupJournalApproveAuthority(f.ctx, draft.ID, draft.BodyHash, "sibling-independent-journal")
		return e
	})
	b.Authorization, e = g.SignJournalAuthorization(a, []g.JournalApproval{{ID: ap.ID, TenantID: tenant, ActorID: ap.ActorID, Role: ap.Role, AuthorizationSHA256: ap.AuthorizationSHA256, ApprovedAt: ap.ApprovedAt}}, b.Parent, keys.Core(), old.signer, time.Now().UTC())
	if e != nil {
		t.Fatal(e)
	}
	view, _, e := g.SealJournalView(b.Parent, b.Authorization, []g.JournalRecord{}, keys.Core(), old.ledger, time.Now().UTC())
	if e != nil {
		t.Fatal(e)
	}
	b.Head = view.Head
	h := &groupJournalTest{f: f, b: b, signer: old.signer, pipeline: old.pipeline, ledger: old.ledger}
	f.must("finops_group_ledger", func(tx *Tx) error {
		var e error
		h.cursor, e = tx.FleetGroupJournalBootstrap(f.ctx, b)
		if e != nil {
			return fmt.Errorf("sibling bootstrap: %w", e)
		}
		return nil
	})
	ca := g.ContinuationAuthorization{SchemaVersion: g.ContinuationSchemaVersion, ID: "sibling-continuation-" + suffix, ChainID: b.ChainID, Policy: g.ContinuationPolicy, ParentEnvelopeSHA256: g.Digest(b.Parent), JournalAuthorizationSHA256: g.Digest(b.Authorization), BindingSHA256: g.Digest(prepared.Program.Binding), RealmSHA256: g.Digest(prepared.Program.Realm), SignerKeySHA256: g.BytesDigest(keys.Signer), PipelineKeySHA256: g.BytesDigest(keys.Pipeline), LedgerKeySHA256: g.BytesDigest(keys.Ledger), BootstrapHead: view.Head, RecordLimit: 8, ByteLimit: 8 * g.JournalRecordByteLimit, CreatedAt: time.Now().UTC(), ForwardExpiresAt: b.Authorization.Authorization.ExpiresAt, Nonce: "sibling-continuation-nonce-" + suffix}
	f.must("finops_group_ledger", func(tx *Tx) error {
		var e error
		draft, e = tx.FleetGroupJournalDraftAuthorization(f.ctx, b, "CONTINUATION", ca)
		return e
	})
	f.must("finops_api", func(tx *Tx) error {
		var e error
		ap, e = tx.FleetGroupJournalApproveAuthority(f.ctx, draft.ID, draft.BodyHash, "sibling-independent-continuation")
		return e
	})
	f.must("finops_group_ledger", func(tx *Tx) error {
		envelope, e := g.SignContinuationAuthorization(f.ctx, ca, []g.ContinuationApproval{{ID: ap.ID, TenantID: tenant, ActorID: ap.ActorID, Role: ap.Role, AuthorizationSHA256: ap.AuthorizationSHA256, ApprovedAt: ap.ApprovedAt}}, view, keys.Core(), tx.FleetGroupJournalAuthority(), old.signer, time.Now().UTC())
		if e != nil {
			return e
		}
		return tx.FleetGroupJournalAttachContinuation(f.ctx, b.ChainID, envelope)
	})
	workspace := old.workspace
	workspace.Generation = "sibling-workspace-" + suffix
	workspace.RuntimeID = strings.Repeat("7", 64)
	f.mustAdmin(func(tx *Tx) error {
		if _, e := tx.Exec(f.ctx, `INSERT INTO public.fleet_group_workspace_keys(tenant_id,chain_id,id,profile_id,profile_generation,image_sha256,public_key) VALUES($1,$2,'workspace-controller',$3,$4,$5,$6)`, tenant, b.ChainID, prepared.Program.Realm.FixtureID, prepared.Program.Realm.Generation, workspace.ImageSHA256, old.controller.Public().(ed25519.PublicKey)); e != nil {
			return e
		}
		raw, hash, e := groupJournalBytes(groupNativeWorkspace{"1", workspace, "", nil})
		if e != nil {
			return e
		}
		_, e = tx.Exec(f.ctx, `INSERT INTO public.fleet_group_workspaces(tenant_id,chain_id,generation,ordinal,runtime_id,image_sha256,key_binding_id,previous_generation,document,raw_document,content_hash) VALUES($1,$2,$3,0,$4,$5,'workspace-controller',NULL,convert_from($6::bytea,'UTF8')::jsonb,$6,$7)`, tenant, b.ChainID, workspace.Generation, workspace.RuntimeID, workspace.ImageSHA256, raw, hash)
		return e
	})
	n := &groupNativeTest{groupJournalTest: h, prepared: prepared, workspace: workspace, controller: old.controller}
	groupJournalTestLogin(t, f, "finops_group_health_observer")
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	observer := base.observer
	observer.TenantID = tenant
	observer.ChainID = b.ChainID
	observer.DatabaseLogin = f.roles["finops_group_health_observer"].Pool.Config().ConnConfig.User
	observer.PublicKey = key.Public().(ed25519.PublicKey)
	limits, _ := json.Marshal(observer.Limits)
	f.mustAdmin(func(tx *Tx) error {
		_, e := tx.Exec(f.ctx, `INSERT INTO public.fleet_group_recovery_health_observers(tenant_id,chain_id,id,profile_id,profile_generation,image_sha256,database_login,source_id,issuer,subject,audience,public_key,limits) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,convert_from($13::bytea,'UTF8')::jsonb)`, tenant, b.ChainID, observer.ID, prepared.Program.Realm.FixtureID, prepared.Program.Realm.Generation, workspace.ImageSHA256, observer.DatabaseLogin, observer.Identity.SourceID, observer.Identity.Issuer, observer.Identity.Subject, observer.Identity.Audience, observer.PublicKey, limits)
		return e
	})
	return &recoveryHealthTest{n, key, observer}
}

func TestGroupRecoveryHealthMachineRLSRejectsPopulatedOtherTenantAndChain(t *testing.T) {
	base := newRecoveryHealthTest(t)
	for _, tenant := range []string{base.n.f.tenant + "-second", base.n.f.tenant} {
		other := recoveryHealthSibling(t, base, tenant)
		f := other.n.f
		c := other.preparing(t)
		now := time.Now().UTC()
		r := native.HealthReceipt{SchemaVersion: "2", InstallationID: "other-real-namespace", Binding: native.HealthBinding{Binding: other.n.prepared.Program.Binding, Realm: other.n.prepared.Program.Realm, ProgramSHA256: g.Digest(other.n.prepared.Program), CommandID: "observer", OperationID: "observer-op", Fence: 1}, Sequence: 1, MeasurementRevision: "GO_MONOTONIC_HTTP_V2", After: native.HealthSnapshot{CapturedAt: now.Add(-time.Second)}}
		r.SHA256 = native.HealthReceiptSHA256(r)
		plain, _ := json.Marshal(r)
		ref := groupArtifactRef(t, other.n.groupJournalTest, c, "other-private-raw", g.BytesDigest(plain))
		ref.SizeBytes = int64(len(plain))
		f.must("finops_group_pipeline", func(tx *Tx) error {
			_, _, e := tx.GroupArtifactAppend(f.ctx, other.n.b.ChainID, c.ID, "HEALTH_BASELINE", groupArtifactIdentity(), ref)
			return e
		})
		body := GroupRecoveryHealthObservation{SchemaVersion: "1", ID: model.ID(), TenantID: tenant, ChainID: other.n.b.ChainID, ObserverID: other.observer.ID, Workspace: other.n.workspace, Phase: "BASELINE", CommandID: c.ID, Receipt: r, Reference: ref, SignedAt: now}
		envelope, _ := SignGroupRecoveryHealthObservation(body, other.key)
		f.must("finops_group_health_observer", func(tx *Tx) error {
			_, _, e := tx.GroupRecoveryHealthObservationAppend(f.ctx, other.observer.Identity, envelope)
			return e
		})
		f.must("finops_group_ledger", func(tx *Tx) error {
			var count int
			e := tx.QueryRow(f.ctx, `SELECT count(*) FROM public.fleet_group_recovery_health_observations WHERE chain_id=$1`, other.n.b.ChainID).Scan(&count)
			if e == nil && count != 1 {
				return errors.New("foreign test population missing")
			}
			return e
		})
		for _, resetRole := range []bool{false, true} {
			if e := base.n.f.roles["finops_group_health_observer"].Do(f.ctx, tenant, func(tx *Tx) error {
				if resetRole {
					if _, e := tx.Exec(f.ctx, `RESET ROLE`); e != nil {
						return e
					}
				}
				for _, table := range []string{"fleet_group_recovery_health_observers", "fleet_group_recovery_health_observations", "fleet_group_recovery_health_baselines", "fleet_group_recovery_health_attempts", "fleet_group_recovery_health_outcomes", "fleet_group_recovery_health_selections"} {
					var count int
					if e := tx.QueryRow(f.ctx, `SELECT count(*) FROM public.`+table+` WHERE chain_id=$1`, other.n.b.ChainID).Scan(&count); e != nil {
						return e
					}
					if count != 0 {
						return errors.New("observer read another commissioned chain")
					}
				}
				var helperEmpty bool
				if e := tx.QueryRow(f.ctx, `SELECT public.fleet_group_recovery_health_artifact($1,$2,$3,'HEALTH_BASELINE',$4) IS NULL`, tenant, other.n.b.ChainID, c.ID, ref.ID).Scan(&helperEmpty); e != nil {
					return e
				}
				if !helperEmpty {
					return errors.New("observer SECDEF read another chain artifact")
				}
				return nil
			}); e != nil {
				t.Fatal(e)
			}
		}
	}
}
