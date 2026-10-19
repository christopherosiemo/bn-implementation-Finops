package store

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	g "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetgroup"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// These are private signed-protocol dependency fixtures, not native Terraform,
// Git, customer OIDC, real health or money acceptance. Every SQL call uses an
// isolated marked child database and separately authenticated restricted role.
type groupJournalTest struct {
	f                        *fleetHistoryDBTest
	b                        FleetGroupJournalBootstrap
	cursor                   g.ContinuationCursor
	signer, pipeline, ledger ed25519.PrivateKey
}

func groupJournalTestLogin(t *testing.T, f *fleetHistoryDBTest, role string) {
	t.Helper()
	login := "gj_" + strings.ReplaceAll(model.ID(), "-", "")
	password := model.ID()
	_, err := f.admin.Pool.Exec(f.ctx, "CREATE ROLE "+pgx.Identifier{login}.Sanitize()+" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '"+password+"' IN ROLE "+pgx.Identifier{role}.Sanitize())
	if err != nil {
		t.Fatal(err)
	}
	cfg := f.admin.Pool.Config().Copy()
	cfg.ConnConfig.User = login
	cfg.ConnConfig.Password = password
	cfg.ConnConfig.RuntimeParams = map[string]string{}
	cfg.AfterConnect = func(ctx context.Context, c *pgx.Conn) error {
		_, err := c.Exec(ctx, "SET ROLE "+pgx.Identifier{role}.Sanitize())
		return err
	}
	pool, err := pgxpool.NewWithConfig(f.ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	f.roles[role] = &Store{Pool: pool}
	t.Cleanup(func() {
		pool.Close()
		if _, e := f.admin.Pool.Exec(context.Background(), "DROP ROLE "+pgx.Identifier{login}.Sanitize()); e != nil {
			t.Error(e)
		}
	})
}
func newGroupJournalTest(t *testing.T) *groupJournalTest {
	return newGroupJournalTestSetup(t, true)
}
func newGroupJournalTestSetup(t *testing.T, attach bool) *groupJournalTest {
	t.Helper()
	f, pair := newFleetFixtureTest(t)
	dir := t.TempDir()
	files, err := os.ReadDir(filepath.Join("..", "..", "migrations"))
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		if file.IsDir() || !strings.HasSuffix(file.Name(), ".sql") || file.Name()[:3] > "031" {
			continue
		}
		raw, e := os.ReadFile(filepath.Join("..", "..", "migrations", file.Name()))
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join(dir, file.Name()), raw, 0600); e != nil {
			t.Fatal(e)
		}
	}
	if err = f.admin.Migrate(f.ctx, dir); err != nil {
		t.Fatal(err)
	}
	groupJournalTestLogin(t, f, "finops_group_ledger")
	groupJournalTestLogin(t, f, "finops_group_pipeline")
	h := &groupJournalTest{f: f}
	sp, sk, _ := ed25519.GenerateKey(rand.Reader)
	pp, pk, _ := ed25519.GenerateKey(rand.Reader)
	lp, lk, _ := ed25519.GenerateKey(rand.Reader)
	h.signer, h.pipeline, h.ledger = sk, pk, lk
	var selected, approved model.Document
	f.must("finops_api", func(tx *Tx) error {
		var e error
		selected, e = tx.FleetFixtureProposalCreate(f.ctx, "creator", pair.Request)
		return e
	})
	proposal, e := FleetFixtureProposalDocument(selected)
	if e != nil {
		t.Fatal(e)
	}
	prepared := fleetFixtureUnitPreparation(t, proposal)
	prepared.JournalReview.PipelineKeySHA256 = g.BytesDigest(pp)
	prepared.JournalReview.LedgerKeySHA256 = g.BytesDigest(lp)
	var preparedRow model.Document
	f.must("finops_group_fixture", func(tx *Tx) error {
		var e error
		preparedRow, e = tx.FleetFixturePreparedProgramAppend(f.ctx, proposal.ID, prepared)
		return e
	})
	f.must("finops_api", func(tx *Tx) error {
		var e error
		approved, e = tx.FleetFixtureApprove(f.ctx, proposal.ID, 2, "independent-approver")
		return e
	})
	now := time.Now().UTC()
	p := prepared.Program
	ap := fleetHistoryDocument(approved["approval"])
	h.b = FleetGroupJournalBootstrap{ChainID: "chain-protocol", KeyBindingID: "commissioned-keys", PreparedProgramID: model.String(preparedRow, "id"), ApprovalID: model.String(ap, "id"), Keys: FleetGroupJournalKeys{Signer: sp, Pipeline: pp, Ledger: lp}}
	var parentApproval g.Approval
	f.must("finops_group_ledger", func(tx *Tx) error {
		var e error
		parentApproval, e = tx.FleetGroupJournalParentApproval(f.ctx, h.b.PreparedProgramID, h.b.ApprovalID)
		return e
	})
	parent, e := g.SignGitProgram(p, []g.Approval{parentApproval}, sk, now)
	if e != nil {
		t.Fatal(e)
	}
	keys := FleetGroupJournalKeys{Signer: sp, Pipeline: pp, Ledger: lp}
	h.b.Parent = parent
	if err = f.admin.Do(f.ctx, f.tenant, func(tx *Tx) error {
		_, e := tx.Exec(f.ctx, `INSERT INTO public.fleet_group_journal_key_bindings(tenant_id,id,profile_id,profile_generation,realm,pipeline_id,source_id,issuer,subject,audience,signer_key,pipeline_key,ledger_key) VALUES($1,$2,$3,$4,$5,$6,'fixture-machine','https://fixture.example.invalid','group-pipeline','finops-group-pipeline',$7,$8,$9)`, f.tenant, h.b.KeyBindingID, pair.Profile.ID, pair.Profile.Generation, groupJournalRealmBytes(p.Realm), p.ArtifactContext.PipelineID, sp, pp, lp)
		return e
	}); err != nil {
		t.Fatal(err)
	}
	a := g.JournalAuthorization{SchemaVersion: g.JournalSchemaVersion, Kind: g.JournalKind, ID: "journal-authorization", JournalID: "journal-protocol", ParentEnvelopeSHA256: g.Digest(parent), ParentSHA256: g.Digest(p), BindingSHA256: g.Digest(p.Binding), RealmSHA256: g.Digest(p.Realm), PipelineID: p.ArtifactContext.PipelineID, Ref: p.Manifest.Ref, Policy: g.JournalPolicy, Base: prepared.JournalReview.Base, PipelineKeySHA256: g.BytesDigest(pp), LedgerKeySHA256: g.BytesDigest(lp), MaximumEffects: 32, MaximumRecords: 512, CreatedAt: now, ExpiresAt: p.ExpiresAt, Nonce: "journal-nonce"}
	var draft FleetGroupAuthorityDraft
	var authorityApproval FleetGroupAuthorityApproval
	f.must("finops_group_ledger", func(tx *Tx) error {
		var e error
		draft, e = tx.FleetGroupJournalDraftAuthorization(f.ctx, h.b, "JOURNAL", a)
		return e
	})
	f.must("finops_api", func(tx *Tx) error {
		var e error
		authorityApproval, e = tx.FleetGroupJournalApproveAuthority(f.ctx, draft.ID, draft.BodyHash, "independent-journal-approver")
		return e
	})
	authorization, e := g.SignJournalAuthorization(a, []g.JournalApproval{{ID: authorityApproval.ID, TenantID: f.tenant, ActorID: authorityApproval.ActorID, Role: authorityApproval.Role, AuthorizationSHA256: authorityApproval.AuthorizationSHA256, ApprovedAt: authorityApproval.ApprovedAt}}, parent, keys.Core(), sk, time.Now().UTC())
	if e != nil {
		t.Fatal(e)
	}
	view, _, e := g.SealJournalView(parent, authorization, []g.JournalRecord{}, keys.Core(), lk, time.Now().UTC())
	if e != nil {
		t.Fatal(e)
	}
	h.b.Authorization, h.b.Head = authorization, view.Head
	f.must("finops_group_ledger", func(tx *Tx) error { var e error; h.cursor, e = tx.FleetGroupJournalBootstrap(f.ctx, h.b); return e })
	if !attach {
		return h
	}
	at := time.Now().UTC()
	ca := g.ContinuationAuthorization{SchemaVersion: g.ContinuationSchemaVersion, ID: "chain-authorization", ChainID: h.b.ChainID, Policy: g.ContinuationPolicy, ParentEnvelopeSHA256: g.Digest(parent), JournalAuthorizationSHA256: g.Digest(authorization), BindingSHA256: g.Digest(p.Binding), RealmSHA256: g.Digest(p.Realm), SignerKeySHA256: g.BytesDigest(sp), PipelineKeySHA256: g.BytesDigest(pp), LedgerKeySHA256: g.BytesDigest(lp), BootstrapHead: view.Head, RecordLimit: 8, ByteLimit: 8 * g.JournalRecordByteLimit, CreatedAt: at, ForwardExpiresAt: authorization.Authorization.ExpiresAt, Nonce: "continuation-nonce"}
	f.must("finops_group_ledger", func(tx *Tx) error {
		var e error
		draft, e = tx.FleetGroupJournalDraftAuthorization(f.ctx, h.b, "CONTINUATION", ca)
		return e
	})
	f.must("finops_api", func(tx *Tx) error {
		var e error
		authorityApproval, e = tx.FleetGroupJournalApproveAuthority(f.ctx, draft.ID, draft.BodyHash, "independent-continuation-approver")
		return e
	})
	f.must("finops_group_ledger", func(tx *Tx) error {
		e, eerr := g.SignContinuationAuthorization(f.ctx, ca, []g.ContinuationApproval{{ID: authorityApproval.ID, TenantID: f.tenant, ActorID: authorityApproval.ActorID, Role: authorityApproval.Role, AuthorizationSHA256: authorityApproval.AuthorizationSHA256, ApprovedAt: authorityApproval.ApprovedAt}}, view, keys.Core(), tx.FleetGroupJournalAuthority(), sk, time.Now().UTC())
		if eerr != nil {
			return eerr
		}
		return tx.FleetGroupJournalAttachContinuation(f.ctx, h.b.ChainID, e)
	})
	return h
}
func (h *groupJournalTest) preparing(t *testing.T, id string) (g.JournalRecord, g.JournalHeadEnvelope) {
	t.Helper()
	now := time.Now().UTC()
	v := h.b.View()
	entry := v.Parent.Program.Manifest.Entries[0]
	c := g.JournalCommand{ID: id, OperationID: "op-" + id, IdempotencyKey: "key-" + id, Fence: 1, Head: v.Head, Before: v.Authorization.Authorization.Base, Preparation: g.JournalPreparation{Mode: g.Forward, Sequence: 1, ManifestEntrySHA256: g.Digest(entry), Revision: entry.Revision, Before: entry.Before, After: entry.After}, CreatedAt: now}
	r := g.JournalRecord{Sequence: 1, PreviousSHA256: v.Head.Head.Ref.LastRecordSHA256, Kind: g.JournalPreparing, Command: &c, RecordedAt: now}
	records, _, err := g.AppendJournalRecord(v, h.b.Keys.Core(), v.Head.Head.Ref, r, now)
	if err != nil {
		t.Fatal(err)
	}
	next, _, err := g.SealJournalView(v.Parent, v.Authorization, records, h.b.Keys.Core(), h.ledger, now)
	if err != nil {
		t.Fatal(err)
	}
	return r, next.Head
}
func (h *groupJournalTest) inbox(t *testing.T, kind string, envelope any) {
	t.Helper()
	raw, _, e := groupJournalBytes(envelope)
	if e != nil {
		t.Fatal(e)
	}
	h.f.must("finops_group_pipeline", func(tx *Tx) error {
		_, replay, e := tx.FleetGroupJournalInboxAppend(h.f.ctx, h.b.ChainID, kind, FleetGroupPipelineIdentity{"fixture-machine", "https://fixture.example.invalid", "group-pipeline", "finops-group-pipeline"}, raw)
		if replay {
			return errors.New("new receipt unexpectedly replayed")
		}
		return e
	})
}
func TestFleetGroupJournalCommissionedRootsRolesAndTenantIsolation(t *testing.T) {
	h := newGroupJournalTest(t)
	f := h.f
	for _, role := range []string{"finops_api", "finops_worker", "finops_executor", "finops_signer", "finops_group_fixture", "finops_group_pipeline"} {
		f.denied(role, func(tx *Tx) error { _, e := tx.FleetGroupJournalBootstrap(f.ctx, h.b); return e })
		f.denied(role, func(tx *Tx) error {
			_, e := tx.Exec(f.ctx, `INSERT INTO public.fleet_group_journal_key_bindings SELECT * FROM public.fleet_group_journal_key_bindings WHERE tenant_id=$1`, f.tenant)
			return e
		})
	}
	f.denied("finops_group_ledger", func(tx *Tx) error {
		_, e := tx.Exec(f.ctx, `UPDATE public.fleet_group_journal_key_bindings SET subject=subject WHERE tenant_id=$1`, f.tenant)
		return e
	})
	if err := f.roles["finops_group_ledger"].Do(f.ctx, f.tenant+"-foreign", func(tx *Tx) error {
		_, e := tx.FleetGroupJournalCursor(f.ctx, h.b.ChainID)
		if !errors.Is(e, pgx.ErrNoRows) {
			return fmt.Errorf("foreign cursor exposed: %w", e)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	f.must("finops_group_ledger", func(tx *Tx) error {
		c, e := tx.FleetGroupJournalBootstrap(f.ctx, h.b)
		if e == nil && c != h.cursor {
			return errors.New("exact bootstrap replay changed cursor")
		}
		return e
	})
	forged := h.b
	_, replacement, _ := ed25519.GenerateKey(rand.Reader)
	forged.Keys.Signer = replacement.Public().(ed25519.PublicKey)
	f.denied("finops_group_ledger", func(tx *Tx) error { _, e := tx.FleetGroupJournalBootstrap(f.ctx, forged); return e })
}
func TestFleetGroupJournalConcurrentAppendOneShotOutboxAndPersistentReservation(t *testing.T) {
	h := newGroupJournalTest(t)
	f := h.f
	r1, head1 := h.preparing(t, "command-one")
	r2, head2 := h.preparing(t, "command-two")
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for _, x := range []struct {
		r    g.JournalRecord
		head g.JournalHeadEnvelope
	}{{r1, head1}, {r2, head2}} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- f.run("finops_group_ledger", func(tx *Tx) error {
				_, _, e := tx.FleetGroupJournalAppendOriginal(f.ctx, h.b.ChainID, h.cursor, x.r, x.head)
				return e
			})
		}()
	}
	wg.Wait()
	close(results)
	success, conflict := 0, 0
	for e := range results {
		if e == nil {
			success++
		} else if errors.Is(e, ErrGroupJournalConflict) {
			conflict++
		} else {
			t.Fatal(e)
		}
	}
	if success != 1 || conflict != 1 {
		t.Fatal("CAS did not choose exactly one writer")
	}
	var outbox string
	f.must("finops_group_ledger", func(tx *Tx) error {
		var allowed bool
		if e := tx.QueryRow(f.ctx, `SELECT public.fleet_group_admission($1,$2,'R1',NULL)`, f.tenant, h.b.Parent.Program.Binding.Old.Target.WorkloadID).Scan(&allowed); e != nil {
			return e
		}
		if allowed {
			return errors.New("R1 admitted with unresolved group duty")
		}
		return tx.QueryRow(f.ctx, `SELECT id FROM public.fleet_group_journal_outbox WHERE tenant_id=$1 AND chain_id=$2 AND action='GIT_ADVANCE'`, f.tenant, h.b.ChainID).Scan(&outbox)
	})
	for i := 0; i < 2; i++ {
		f.must("finops_group_ledger", func(tx *Tx) error {
			_, permit, deliver, e := tx.FleetGroupJournalClaimOriginal(f.ctx, h.b.ChainID, outbox, "delivery-attempt")
			if e == nil && (deliver != (i == 0) || deliver && !permit.ValidUntil.After(time.Now())) {
				return errors.New("one-shot delivery or freshness invalid")
			}
			return e
		})
	}
	f.must("finops_group_ledger", func(tx *Tx) error { return tx.FleetGroupJournalReconcileAttempt(f.ctx, h.b.ChainID, outbox) })
	f.must("finops_group_ledger", func(tx *Tx) error {
		_, _, deliver, e := tx.FleetGroupJournalClaimOriginal(f.ctx, h.b.ChainID, outbox, "later-attempt")
		if e == nil && deliver {
			return errors.New("uncertain attempt became re-deliverable")
		}
		return e
	})
}

func TestFleetGroupJournalContinuationFullSegmentUnknownReplayRotationAndOwnedRelease(t *testing.T) {
	h := newGroupJournalTest(t)
	f := h.f
	r, head := h.preparing(t, "command-retained")
	f.must("finops_group_ledger", func(tx *Tx) error {
		var e error
		h.cursor, _, e = tx.FleetGroupJournalAppendOriginal(f.ctx, h.b.ChainID, h.cursor, r, head)
		return e
	})
	f.must("finops_group_ledger", func(tx *Tx) error {
		var e error
		h.cursor, e = tx.FleetGroupJournalOpenContinuation(f.ctx, h.b.ChainID, h.ledger, "checkpoint-first")
		return e
	})
	if h.cursor.Segment != 1 || h.cursor.Identities.Count == 0 {
		t.Fatal("original identities were not imported")
	}
	var last g.ContinuationRecord
	var firstAnchor g.ContinuationIdentityAnchor
	for i := 0; i < 8; i++ {
		f.must("finops_group_ledger", func(tx *Tx) error {
			v, keys, e := tx.FleetGroupJournalContinuation(f.ctx, h.b.ChainID)
			if e != nil {
				return e
			}
			p, e := g.VerifyContinuation(f.ctx, v, keys.Core(), tx.FleetGroupJournalAuthority(), time.Now().UTC())
			if e != nil {
				return e
			}
			if p.OriginalPending == nil {
				return errors.New("unknown original duty lost")
			}
			now := time.Now().UTC()
			c := p.OriginalPending.Command
			receipt, e := g.SignJournalReceipt(g.JournalReceipt{SchemaVersion: g.JournalSchemaVersion, ID: fmt.Sprintf("unknown-%d", i), IdempotencyKey: fmt.Sprintf("unknown-key-%d", i), JournalID: h.b.Authorization.Authorization.JournalID, AuthorizationSHA256: g.Digest(h.b.Authorization), CommandID: c.ID, OperationID: c.OperationID, Fence: c.Fence, PipelineID: h.b.Authorization.Authorization.PipelineID, Kind: g.JournalUnknown, PreparationSHA256: g.Digest(c.Preparation), Before: c.Before, After: c.Before, ReceivedAt: now}, h.pipeline)
			if e != nil {
				return e
			}
			last = g.ContinuationRecord{Sequence: uint64(len(v.Records) + 1), PreviousSHA256: v.Head.Head.LastRecordSHA256, Kind: g.ContinuationLegacy, OriginalReceipt: &receipt, RecordedAt: now}
			return nil
		})
		h.inbox(t, g.ContinuationOriginal, *last.OriginalReceipt)
		f.must("finops_group_ledger", func(tx *Tx) error {
			var e error
			h.cursor, _, e = tx.FleetGroupJournalAppendContinuation(f.ctx, h.b.ChainID, h.cursor, h.ledger, last)
			if i == 0 {
				firstAnchor = h.cursor.Identities
			}
			return e
		})
	}
	if h.cursor.RecordCount != 8 {
		t.Fatal("segment did not reach actual signed bound")
	}
	before := h.cursor
	var terminal g.ContinuationRecord
	f.must("finops_group_ledger", func(tx *Tx) error {
		c, replay, e := tx.FleetGroupJournalAppendContinuation(f.ctx, h.b.ChainID, h.cursor, h.ledger, last)
		if e == nil && (!replay || c != before) {
			return errors.New("full segment duplicate spent capacity")
		}
		return e
	})
	f.must("finops_group_ledger", func(tx *Tx) error {
		var e error
		h.cursor, e = tx.FleetGroupJournalRotate(f.ctx, h.b.ChainID, h.ledger, "checkpoint-second")
		return e
	})
	if h.cursor.Segment != 2 || h.cursor.RecordCount != 0 || h.cursor.GlobalCount != before.GlobalCount {
		t.Fatal("rotation spent old slot or rewound global ordinal")
	}
	f.must("finops_group_ledger", func(tx *Tx) error {
		a := tx.FleetGroupJournalAuthority()
		entry, ok, e := a.LookupIdentity(f.ctx, h.b.ChainID, firstAnchor, g.ContinuationIdentityKey{Namespace: "RECEIPT_ID", ID: "unknown-0"})
		if e != nil {
			return e
		}
		if !ok || entry.SHA256 == "" {
			return errors.New("committed historical prefix lost")
		}
		bad := firstAnchor
		bad.SHA256 = strings.Repeat("0", 64)
		if _, _, e = a.LookupIdentity(f.ctx, h.b.ChainID, bad, entry.Key); e == nil {
			return errors.New("uncommitted prefix accepted")
		}
		return nil
	})
	f.denied("finops_group_ledger", func(tx *Tx) error { return tx.FleetGroupJournalRelease(f.ctx, h.b.ChainID, h.cursor) })
	f.must("finops_group_ledger", func(tx *Tx) error {
		v, _, e := tx.FleetGroupJournalContinuation(f.ctx, h.b.ChainID)
		if e != nil {
			return e
		}
		now := time.Now().UTC()
		receipt := last.OriginalReceipt.Receipt
		receipt.ID = "definite-no-apply"
		receipt.IdempotencyKey = "definite-no-apply-key"
		receipt.Kind = g.JournalNoApply
		receipt.ReceivedAt = now
		signed, e := g.SignJournalReceipt(receipt, h.pipeline)
		if e != nil {
			return e
		}
		terminal = g.ContinuationRecord{Sequence: 1, PreviousSHA256: v.Head.Head.LastRecordSHA256, Kind: g.ContinuationLegacy, OriginalReceipt: &signed, RecordedAt: now}
		return nil
	})
	h.inbox(t, g.ContinuationOriginal, *terminal.OriginalReceipt)
	f.must("finops_group_ledger", func(tx *Tx) error {
		var e error
		h.cursor, _, e = tx.FleetGroupJournalAppendContinuation(f.ctx, h.b.ChainID, h.cursor, h.ledger, terminal)
		return e
	})
	f.must("finops_group_ledger", func(tx *Tx) error { return tx.FleetGroupJournalRelease(f.ctx, h.b.ChainID, h.cursor) })
	f.must("finops_group_ledger", func(tx *Tx) error {
		var allowed bool
		e := tx.QueryRow(f.ctx, `SELECT public.fleet_group_admission($1,$2,'R1',NULL)`, f.tenant, h.b.Parent.Program.Binding.Old.Target.WorkloadID).Scan(&allowed)
		if e == nil && !allowed {
			return errors.New("resolved obligation remained blocked")
		}
		return e
	})
}
