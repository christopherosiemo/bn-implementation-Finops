package store

import (
	"errors"
	"strings"
	"testing"
	"time"

	g "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetgroup"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestFleetGroupJournalDirectSQLChainOrderAndCurrentCursorCannotBeForged(t *testing.T) {
	h := newGroupJournalTest(t)
	f := h.f
	r, head := h.preparing(t, "sql-command")
	bad := r
	bad.PreviousSHA256 = strings.Repeat("0", 64)
	raw, hash, _ := groupJournalBytes(bad)
	hraw, hh, _ := groupJournalBytes(head)
	e := f.run("finops_group_ledger", func(tx *Tx) error {
		_, e := tx.Exec(f.ctx, `INSERT INTO public.fleet_group_journal_records(tenant_id,chain_id,segment,sequence,kind,content_hash,document,raw_document,head_hash,head,raw_head) VALUES($1,$2,0,1,'PREPARING',$3,convert_from($4::bytea,'UTF8')::jsonb,$4,$5,convert_from($6::bytea,'UTF8')::jsonb,$6)`, f.tenant, h.b.ChainID, hash, raw, hh, hraw)
		return e
	})
	var pg *pgconn.PgError
	if !errors.As(e, &pg) || pg.Code != "P0001" || !strings.Contains(pg.Message, "previous") {
		t.Fatal("actual restricted SQL did not reject record predecessor", e)
	}
	f.must("finops_group_ledger", func(tx *Tx) error {
		var valid bool
		for _, body := range []string{`{}`, `{"chain_id":"chain-protocol","kind":"ORIGINAL_JOURNAL","segment":null}`, `{"chain_id":"chain-protocol","kind":null}`} {
			if e := tx.QueryRow(f.ctx, `SELECT public.fleet_group_cursor_valid($1::jsonb,$2)`, body, h.b.ChainID).Scan(&valid); e != nil {
				return e
			}
			if valid {
				return errors.New("partial or null cursor passed")
			}
		}
		return nil
	})
	f.must("finops_group_ledger", func(tx *Tx) error {
		var e error
		h.cursor, _, e = tx.FleetGroupJournalAppendOriginal(f.ctx, h.b.ChainID, h.cursor, r, head)
		return e
	})
	for _, query := range []string{
		`UPDATE public.fleet_group_journal_current SET version=version+1,document=jsonb_set(document,'{record_count}','0') WHERE tenant_id=$1`,
		`UPDATE public.fleet_group_journal_records SET kind=kind WHERE tenant_id=$1`,
		`DELETE FROM public.fleet_group_journal_records WHERE tenant_id=$1`,
		`UPDATE public.fleet_group_journal_reservations SET released_at=clock_timestamp(),release_head_hash=(SELECT content_hash FROM public.fleet_group_journal_heads WHERE tenant_id=$1 AND record_count=0 LIMIT 1) WHERE tenant_id=$1`,
	} {
		f.denied("finops_group_ledger", func(tx *Tx) error { _, e := tx.Exec(f.ctx, query, f.tenant); return e })
	}
	f.must("finops_group_ledger", func(tx *Tx) error {
		var n int
		e := tx.QueryRow(f.ctx, `SELECT count(*) FROM public.fleet_group_journal_records WHERE tenant_id=$1 AND chain_id=$2`, f.tenant, h.b.ChainID).Scan(&n)
		if e == nil && n != 1 {
			return errors.New("refusal exposed partial journal")
		}
		return e
	})
}

func TestFleetGroupJournalExactPersistedApprovalsCannotBeCopiedOrBackdated(t *testing.T) {
	h := newGroupJournalTest(t)
	f := h.f
	altered := h.b
	ap := altered.Authorization.Approvals[0]
	ap.ApprovedAt = ap.ApprovedAt.Add(time.Microsecond)
	auth, e := g.SignJournalAuthorization(altered.Authorization.Authorization, []g.JournalApproval{ap}, altered.Parent, altered.Keys.Core(), h.signer, time.Now().UTC())
	if e != nil {
		t.Fatal(e)
	}
	v, _, e := g.SealJournalView(altered.Parent, auth, []g.JournalRecord{}, altered.Keys.Core(), h.ledger, time.Now().UTC())
	if e != nil {
		t.Fatal(e)
	}
	altered.Authorization, altered.Head = auth, v.Head
	e = f.run("finops_group_ledger", func(tx *Tx) error { _, e := tx.FleetGroupJournalBootstrap(f.ctx, altered); return e })
	if !errors.Is(e, ErrGroupJournalInvalid) {
		t.Fatal("valid signature relabelled actual approval time", e)
	}
	var draft FleetGroupAuthorityDraft
	f.must("finops_group_ledger", func(tx *Tx) error {
		a := h.b.Authorization.Authorization
		a.ID = "different-journal-draft"
		a.Nonce = "different-journal-nonce"
		a.CreatedAt = time.Now().UTC()
		var e error
		draft, e = tx.FleetGroupJournalDraftAuthorization(f.ctx, h.b, "JOURNAL", a)
		return e
	})
	for _, x := range []struct{ actor, hash string }{{h.b.Parent.Program.CreatorID, draft.BodyHash}, {"independent-approver", strings.Repeat("0", 64)}} {
		f.denied("finops_api", func(tx *Tx) error {
			_, e := tx.FleetGroupJournalApproveAuthority(f.ctx, draft.ID, x.hash, x.actor)
			return e
		})
	}
	for _, role := range []string{"finops_group_ledger", "finops_group_fixture", "finops_group_pipeline", "finops_signer", "finops_worker"} {
		f.denied(role, func(tx *Tx) error {
			_, e := tx.FleetGroupJournalApproveAuthority(f.ctx, draft.ID, draft.BodyHash, "independent-approver")
			return e
		})
	}
}

func TestFleetGroupJournalPipelineInboxReplayConflictCurrentIdentityAndSourceRevocation(t *testing.T) {
	h := newGroupJournalTest(t)
	f := h.f
	r, head := h.preparing(t, "source-command")
	f.must("finops_group_ledger", func(tx *Tx) error {
		var e error
		h.cursor, _, e = tx.FleetGroupJournalAppendOriginal(f.ctx, h.b.ChainID, h.cursor, r, head)
		return e
	})
	c := *r.Command
	now := time.Now().UTC()
	receipt, e := g.SignJournalReceipt(g.JournalReceipt{SchemaVersion: g.JournalSchemaVersion, ID: "inbox-unknown", IdempotencyKey: "inbox-key", JournalID: h.b.Authorization.Authorization.JournalID, AuthorizationSHA256: g.Digest(h.b.Authorization), CommandID: c.ID, OperationID: c.OperationID, Fence: c.Fence, PipelineID: h.b.Authorization.Authorization.PipelineID, Kind: g.JournalUnknown, PreparationSHA256: g.Digest(c.Preparation), Before: c.Before, After: c.Before, ReceivedAt: now}, h.pipeline)
	if e != nil {
		t.Fatal(e)
	}
	raw, _, _ := groupJournalBytes(receipt)
	identity := FleetGroupPipelineIdentity{"fixture-machine", "https://fixture.example.invalid", "group-pipeline", "finops-group-pipeline"}
	wrong := identity
	wrong.Subject = "human-console"
	f.denied("finops_group_pipeline", func(tx *Tx) error {
		_, _, e := tx.FleetGroupJournalInboxAppend(f.ctx, h.b.ChainID, g.ContinuationOriginal, wrong, raw)
		return e
	})
	var received time.Time
	for i := 0; i < 2; i++ {
		f.must("finops_group_pipeline", func(tx *Tx) error {
			row, replay, e := tx.FleetGroupJournalInboxAppend(f.ctx, h.b.ChainID, g.ContinuationOriginal, identity, raw)
			if e == nil {
				if replay != (i == 1) {
					return errors.New("stable inbox replay changed")
				}
				if i == 0 {
					received = row.ReceivedAt
				} else if received != row.ReceivedAt {
					return errors.New("replay refreshed original DB receive time")
				}
			}
			return e
		})
	}
	conflict := receipt
	conflict.Receipt.ReceivedAt = now.Add(time.Microsecond)
	changed, _, _ := groupJournalBytes(conflict)
	e = f.run("finops_group_pipeline", func(tx *Tx) error {
		_, _, e := tx.FleetGroupJournalInboxAppend(f.ctx, h.b.ChainID, g.ContinuationOriginal, identity, changed)
		return e
	})
	if !errors.Is(e, ErrGroupJournalConflict) {
		t.Fatal("conflicting receipt reused key", e)
	}
	f.must("finops_api", func(tx *Tx) error {
		s, e := tx.SourceGet(f.ctx, h.b.Parent.Program.Binding.Old.SourceID)
		if e != nil {
			return e
		}
		s["enabled"] = false
		_, e = tx.SourceUpdate(f.ctx, h.b.Parent.Program.Binding.Old.SourceID, model.Number(s, "version"), s)
		return e
	})
	var outbox string
	f.must("finops_group_ledger", func(tx *Tx) error {
		return tx.QueryRow(f.ctx, `SELECT id FROM public.fleet_group_journal_outbox WHERE tenant_id=$1 AND chain_id=$2 AND action='GIT_ADVANCE'`, f.tenant, h.b.ChainID).Scan(&outbox)
	})
	f.denied("finops_group_ledger", func(tx *Tx) error {
		_, _, _, e := tx.FleetGroupJournalClaimOriginal(f.ctx, h.b.ChainID, outbox, "after-source-revoke")
		return e
	})
	// A factual uncertainty is still recordable after selected source revocation;
	// it retains the duty instead of creating a new forward permission.
	f.must("finops_group_ledger", func(tx *Tx) error {
		v, keys, e := tx.FleetGroupJournalOriginal(f.ctx, h.b.ChainID)
		if e != nil {
			return e
		}
		at := time.Now().UTC()
		event := g.JournalRecord{Sequence: 2, PreviousSHA256: v.Head.Head.Ref.LastRecordSHA256, Kind: g.JournalUnknown, Receipt: &receipt, RecordedAt: at}
		records, _, e := g.AppendJournalRecord(v, keys.Core(), v.Head.Head.Ref, event, at)
		if e != nil {
			return e
		}
		sealed, _, e := g.SealJournalView(v.Parent, v.Authorization, records, keys.Core(), h.ledger, at)
		if e != nil {
			return e
		}
		h.cursor, _, e = tx.FleetGroupJournalAppendOriginal(f.ctx, h.b.ChainID, h.cursor, event, sealed.Head)
		return e
	})
	f.must("finops_group_ledger", func(tx *Tx) error {
		var e error
		h.cursor, e = tx.FleetGroupJournalOpenContinuation(f.ctx, h.b.ChainID, h.ledger, "recovery-after-source-revoke")
		return e
	})
}

func TestFleetGroupJournalPublicReviewCanonicalBytesScopedPaginationAndApproval(t *testing.T) {
	h := newGroupJournalTest(t)
	f := h.f
	var newest FleetGroupAuthorityDraft
	for i := 0; i < 3; i++ {
		f.must("finops_group_ledger", func(tx *Tx) error {
			a := h.b.Authorization.Authorization
			a.ID = model.ID()
			a.Nonce = model.ID()
			a.CreatedAt = time.Now().UTC()
			var e error
			newest, e = tx.FleetGroupJournalDraftAuthorization(f.ctx, h.b, "JOURNAL", a)
			return e
		})
	}
	f.must("finops_api", func(tx *Tx) error {
		_, e := tx.FleetGroupJournalApproveAuthority(f.ctx, newest.ID, newest.BodyHash, "reviewer-public")
		return e
	})
	var proposal string
	f.must("finops_group_ledger", func(tx *Tx) error {
		return tx.QueryRow(f.ctx, `SELECT proposal_id FROM public.fleet_fixture_prepared_programs WHERE tenant_id=$1 AND id=$2`, f.tenant, h.b.PreparedProgramID).Scan(&proposal)
	})
	f.must("finops_api", func(tx *Tx) error {
		d, e := tx.FleetGroupAuthorityReview(f.ctx, newest.ID)
		if e != nil {
			return e
		}
		canonical := model.String(d, "authorization_canonical_json")
		if canonical == "" || g.BytesDigest([]byte(canonical)) != model.String(d, "authorization_sha256") || model.Number(d, "version") != 2 || model.String(d, "status") != "APPROVED" || model.Bool(d, "customer_execution_authorized") {
			return errors.New("public exact-body review projection mismatch")
		}
		for _, key := range []string{"keys", "private_key", "raw_state", "artifact_refs", "raw_document"} {
			if _, exists := d[key]; exists {
				return errors.New("private field leaked in public review")
			}
		}
		seen := map[string]bool{}
		after := ""
		for {
			page, e := tx.FleetGroupAuthorityReviewPage(f.ctx, proposal, after, 1)
			if e != nil {
				return e
			}
			if len(page) == 0 {
				break
			}
			id := model.String(page[0], "id")
			if seen[id] || id == "" {
				return errors.New("review cursor repeated row")
			}
			seen[id] = true
			after = id
		}
		if len(seen) != 5 {
			return errors.New("scoped review page omitted immutable draft history")
		}
		runs, e := tx.sourceRows(f.ctx, `SELECT public.fleet_group_fixture_runs($1,$2,'',100)`, f.tenant, proposal)
		if e != nil {
			return e
		}
		if len(runs) != 1 {
			return errors.New("safe run inspection omitted issued cursor")
		}
		run := runs[0]
		if model.String(run, "segment") != "0" || model.String(run, "global_count") != "0" || model.String(run, "head_sha256") != h.cursor.HeadSHA256 || model.Bool(run, "customer_execution_authorized") || model.String(run, "financial_disposition") != "UNAVAILABLE" {
			return errors.New("safe run summary changed precision or authority")
		}
		for _, key := range []string{"projection", "current", "keys", "command", "raw_document", "artifact_refs", "state_sha256"} {
			if _, exists := run[key]; exists {
				return errors.New("private authority field leaked in run summary")
			}
		}
		if _, e = tx.FleetGroupAuthorityReviewPage(f.ctx, proposal, "", 102); !errors.Is(e, ErrGroupJournalInvalid) {
			return errors.New("review page bound not enforced")
		}
		return nil
	})
	if e := f.roles["finops_api"].Do(f.ctx, f.tenant+"-foreign", func(tx *Tx) error {
		if _, e := tx.FleetGroupAuthorityReview(f.ctx, newest.ID); !errors.Is(e, pgx.ErrNoRows) {
			return errors.New("foreign review visible")
		}
		rows, e := tx.FleetGroupAuthorityReviewPage(f.ctx, proposal, "", 100)
		if e == nil && len(rows) > 0 {
			return errors.New("foreign review page visible")
		}
		return e
	}); e != nil {
		t.Fatal(e)
	}
}

func TestFleetGroupJournalRenewedZeroHeadPreservesExactHumanApprovedContinuationDraft(t *testing.T) {
	h := newGroupJournalTestSetup(t, false)
	f := h.f
	f.must("finops_group_ledger", func(tx *Tx) error {
		var e error
		h.cursor, e = tx.FleetGroupJournalRenewOriginal(f.ctx, h.b.ChainID, h.ledger)
		return e
	})
	var draft FleetGroupAuthorityDraft
	var a g.ContinuationAuthorization
	f.must("finops_group_ledger", func(tx *Tx) error {
		v, _, e := tx.FleetGroupJournalOriginal(f.ctx, h.b.ChainID)
		if e != nil {
			return e
		}
		if g.Digest(v.Head) == g.Digest(h.b.Head) {
			return errors.New("renewal did not issue a distinct current head")
		}
		p := h.b.Parent.Program
		a = g.ContinuationAuthorization{SchemaVersion: g.ContinuationSchemaVersion, ID: "renewed-draft", ChainID: h.b.ChainID, Policy: g.ContinuationPolicy, ParentEnvelopeSHA256: g.Digest(h.b.Parent), JournalAuthorizationSHA256: g.Digest(h.b.Authorization), BindingSHA256: g.Digest(p.Binding), RealmSHA256: g.Digest(p.Realm), SignerKeySHA256: g.BytesDigest(h.b.Keys.Signer), PipelineKeySHA256: g.BytesDigest(h.b.Keys.Pipeline), LedgerKeySHA256: g.BytesDigest(h.b.Keys.Ledger), BootstrapHead: v.Head, RecordLimit: 8, ByteLimit: 8 * g.JournalRecordByteLimit, CreatedAt: time.Now().UTC(), ForwardExpiresAt: h.b.Authorization.Authorization.ExpiresAt, Nonce: "renewed-draft-nonce"}
		draft, e = tx.FleetGroupJournalDraftAuthorization(f.ctx, h.b, "CONTINUATION", a)
		return e
	})
	var approved FleetGroupAuthorityApproval
	f.must("finops_api", func(tx *Tx) error {
		var e error
		approved, e = tx.FleetGroupJournalApproveAuthority(f.ctx, draft.ID, draft.BodyHash, "human-reviewer")
		return e
	})
	f.must("finops_group_ledger", func(tx *Tx) error {
		var e error
		h.cursor, e = tx.FleetGroupJournalRenewOriginal(f.ctx, h.b.ChainID, h.ledger)
		return e
	})
	f.must("finops_group_ledger", func(tx *Tx) error {
		v, keys, e := tx.FleetGroupJournalOriginal(f.ctx, h.b.ChainID)
		if e != nil {
			return e
		}
		signed, e := g.SignContinuationAuthorization(f.ctx, a, []g.ContinuationApproval{{ID: approved.ID, TenantID: approved.TenantID, ActorID: approved.ActorID, Role: approved.Role, AuthorizationSHA256: approved.AuthorizationSHA256, ApprovedAt: approved.ApprovedAt}}, v, keys.Core(), tx.FleetGroupJournalAuthority(), h.signer, time.Now().UTC())
		if e != nil {
			return e
		}
		return tx.FleetGroupJournalAttachContinuation(f.ctx, h.b.ChainID, signed)
	})
}
