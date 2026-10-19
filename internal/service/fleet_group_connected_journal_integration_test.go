package service

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	ff "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetfixture"
	g "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetgroup"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type connectedJournal struct {
	f                                 *mutationReplayFixture
	ledger, pipeline                  *store.Store
	bootstrap                         store.FleetGroupJournalBootstrap
	view                              g.JournalView
	cursor                            g.ContinuationCursor
	signerKey, pipelineKey, ledgerKey ed25519.PrivateKey
}

func (h *connectedJournal) reopen(t *testing.T, ctx context.Context) {
	t.Helper()
	for _, slot := range []struct {
		value **store.Store
		mode  string
	}{{&h.ledger, "group-ledger"}, {&h.pipeline, "group-pipeline"}} {
		dsn := (*slot.value).Pool.Config().ConnString()
		(*slot.value).Pool.Close()
		next, err := store.OpenRuntime(ctx, dsn, slot.mode)
		if err != nil {
			t.Fatal("dedicated durable runtime pool reopen", err)
		}
		*slot.value = next
		t.Cleanup(next.Pool.Close)
	}
}

// Only the runner's child database administration is used to commission keys
// and three separate login identities. This is never an application endpoint.
func connectedJournalDatabase(t *testing.T, f *mutationReplayFixture) *store.Store {
	t.Helper()
	ctx := context.Background()
	cfg, err := pgxpool.ParseConfig(os.Getenv("TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal("owned test administrator invalid")
	}
	database := f.roles["api"].Pool.Config().ConnConfig.Database
	if !strings.HasPrefix(database, "fixture_http_") {
		t.Fatal("owned fixture database required")
	}
	cfg.ConnConfig.Database = database
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal("owned fixture database unavailable")
	}
	t.Cleanup(pool.Close)
	var marker string
	if err = pool.QueryRow(ctx, "SELECT coalesce(shobj_description(oid,'pg_database'),'') FROM pg_database WHERE datname=current_database()").Scan(&marker); err != nil || !strings.HasPrefix(marker, "owned-fixture-http-") {
		t.Fatal("owned fixture database marker differs")
	}
	admin := &store.Store{Pool: pool}
	if err = admin.Migrate(ctx, "../../migrations"); err != nil {
		t.Fatal("additive private journal migrations", err)
	}
	return admin
}

func connectedJournalLogin(t *testing.T, admin *store.Store, mode string) *store.Store {
	t.Helper()
	ctx := context.Background()
	group := map[string]string{"group-ledger": "finops_group_ledger", "group-pipeline": "finops_group_pipeline", "signer": "finops_signer"}[mode]
	if group == "" {
		t.Fatal("fixed connected role required")
	}
	login := "connected_" + strings.ReplaceAll(model.ID(), "-", "")
	password := model.ID() + model.ID()
	if _, err := admin.Pool.Exec(ctx, "CREATE ROLE "+pgx.Identifier{login}.Sanitize()+" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '"+password+"' IN ROLE "+pgx.Identifier{group}.Sanitize()); err != nil {
		t.Fatal("dedicated private login provisioning", err)
	}
	cfg := admin.Pool.Config().ConnConfig
	dsn := &url.URL{Scheme: "postgres", Host: cfg.Host + ":" + "5432", Path: "/" + cfg.Database, User: url.UserPassword(login, password)}
	dsn.RawQuery = "sslmode=disable"
	s, err := store.OpenRuntime(ctx, dsn.String(), mode)
	if err != nil {
		t.Fatal("dedicated connected runtime identity", err)
	}
	t.Cleanup(func() {
		s.Pool.Close()
		if _, e := admin.Pool.Exec(context.Background(), "DROP ROLE "+pgx.Identifier{login}.Sanitize()); e != nil {
			t.Error("connected login cleanup failed", e)
		}
	})
	return s
}

func (h *connectedJournal) approve(t *testing.T, ctx context.Context, draft store.FleetGroupAuthorityDraft, kind string) store.FleetGroupAuthorityApproval {
	t.Helper()
	f := h.f
	get := func(token string) (int, model.Document) {
		t.Helper()
		r := httptest.NewRequest(http.MethodGet, "/v1/fleet-group-authorizations/"+draft.ID, nil)
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		f.api.ServeHTTP(w, r)
		var d model.Document
		if json.Unmarshal(w.Body.Bytes(), &d) != nil {
			t.Fatal("authority review JSON", w.Code)
		}
		return w.Code, d
	}
	viewer := f.token(f.tenant, "connected-reviewer", "VIEWER")
	code, review := get(viewer)
	if code != 200 || model.String(review, "kind") != kind || model.String(review, "authorization_sha256") != draft.BodyHash || model.String(review, "authorization_canonical_json") != string(draft.Body) || model.Number(review, "version") != 1 {
		t.Fatal("exact immutable authorization review", code, review)
	}
	path := "fleet-group-authorizations/" + draft.ID + "/approvals"
	if code, _, _ := f.request(path, `"1"`, "connected-self-"+draft.ID, f.token(f.tenant, "connected-creator", "APPROVER"), model.Document{}); code != 403 {
		t.Fatal("self-approved exact journal body", code)
	}
	if code, _, _ := f.request(path, `"1"`, "connected-viewer-"+draft.ID, viewer, model.Document{}); code != 403 {
		t.Fatal("viewer approved exact journal body", code)
	}
	if code, _, _ := f.request(path, `"1"`, "connected-injected-"+draft.ID, f.token(f.tenant, "connected-journal-approver", "APPROVER"), model.Document{"body_hash": "caller"}); code != 422 {
		t.Fatal("authorization body upload accepted", code)
	}
	token := f.token(f.tenant, "connected-journal-approver", "APPROVER")
	code, approved, _ := f.request(path, `"1"`, "connected-exact-"+draft.ID, token, model.Document{})
	if code != 201 || model.String(approved, "status") != "APPROVED" || model.Number(approved, "version") != 2 {
		t.Fatal("actual independent HTTP authority approval", code, approved)
	}
	var a store.FleetGroupAuthorityApproval
	if err := f.roles["api"].Do(ctx, f.tenant, func(tx *store.Tx) error {
		return tx.QueryRow(ctx, `SELECT id,tenant_id,actor_id,role,body_hash,created_at FROM public.fleet_group_journal_authority_approvals WHERE tenant_id=$1 AND draft_id=$2`, f.tenant, draft.ID).Scan(&a.ID, &a.TenantID, &a.ActorID, &a.Role, &a.AuthorizationSHA256, &a.ApprovedAt)
	}); err != nil {
		t.Fatal(err)
	}
	a.ApprovedAt = a.ApprovedAt.UTC()
	if a.AuthorizationSHA256 != draft.BodyHash || a.ActorID == "connected-creator" || a.ApprovedAt.Before(draft.CreatedAt) || a.ApprovedAt.After(time.Now().UTC().Add(5*time.Second)) {
		t.Fatal("authority approval identity/real database time differs")
	}
	beforeAudit, beforeOutbox := f.counts()
	if code, _, _ := f.request(path, `"1"`, "connected-exact-"+draft.ID, token, model.Document{}); code != 201 {
		t.Fatal("exact authorization approval replay", code)
	}
	if a, b := f.counts(); a != beforeAudit || b != beforeOutbox {
		t.Fatal("authority approval replay repeated effects")
	}
	if code, _, _ := f.request(path, `"1"`, "connected-exact-"+draft.ID, f.token(f.tenant, "connected-journal-approver", "VIEWER"), model.Document{}); code != 403 {
		t.Fatal("authority cached replay skipped current role", code)
	}
	if code, _ := get(f.token(f.tenant+"-foreign", "connected-reviewer", "VIEWER")); code != 404 {
		t.Fatal("authority review escaped tenant", code)
	}
	return a
}

func connectedJournalBootstrap(t *testing.T, ctx context.Context, f *mutationReplayFixture, selected ff.Proposal, prepared ff.Preparation, preparedRow, approved model.Document, pipelineKey, ledgerKey ed25519.PrivateKey) *connectedJournal {
	t.Helper()
	admin := connectedJournalDatabase(t, f)
	h := &connectedJournal{f: f, ledger: connectedJournalLogin(t, admin, "group-ledger"), pipeline: connectedJournalLogin(t, admin, "group-pipeline"), pipelineKey: pipelineKey, ledgerKey: ledgerKey}
	signerDB := connectedJournalLogin(t, admin, "signer")
	_, h.signerKey, _ = ed25519.GenerateKey(rand.Reader)
	keys := store.FleetGroupJournalKeys{Signer: h.signerKey.Public().(ed25519.PublicKey), Pipeline: pipelineKey.Public().(ed25519.PublicKey), Ledger: ledgerKey.Public().(ed25519.PublicKey)}
	h.bootstrap = store.FleetGroupJournalBootstrap{ChainID: "connected-chain-" + model.ID(), KeyBindingID: "connected-commissioned-keys", PreparedProgramID: model.String(preparedRow, "id"), ApprovalID: model.String(sourceDocument(approved["approval"]), "id"), Keys: keys}
	if err := admin.Do(ctx, f.tenant, func(tx *store.Tx) error {
		realm, _ := json.Marshal(selected.Realm)
		_, e := tx.Exec(ctx, `INSERT INTO public.fleet_group_journal_key_bindings(tenant_id,id,profile_id,profile_generation,realm,pipeline_id,source_id,issuer,subject,audience,signer_key,pipeline_key,ledger_key) VALUES($1,$2,$3,$4,$5,$6,'connected-machine','https://connected-machine.invalid','connected-pipeline','finops-group-pipeline',$7,$8,$9)`, f.tenant, h.bootstrap.KeyBindingID, selected.Profile.ID, selected.Profile.Generation, realm, prepared.Program.ArtifactContext.PipelineID, keys.Signer, keys.Pipeline, keys.Ledger)
		return e
	}); err != nil {
		t.Fatal("operator-commissioned independent public keys", err)
	}
	if err := f.roles["api"].Do(ctx, f.tenant, func(tx *store.Tx) error {
		_, e := tx.Exec(ctx, "INSERT INTO public.fleet_group_journal_key_bindings SELECT * FROM public.fleet_group_journal_key_bindings WHERE tenant_id=$1", f.tenant)
		return e
	}); err == nil {
		t.Fatal("API acquired public-key installation authority")
	}
	var approval g.Approval
	if err := h.ledger.Do(ctx, f.tenant, func(tx *store.Tx) error {
		var e error
		approval, e = tx.FleetGroupJournalParentApproval(ctx, h.bootstrap.PreparedProgramID, h.bootstrap.ApprovalID)
		return e
	}); err != nil {
		t.Fatal(err)
	}
	parent, err := g.SignGitProgram(prepared.Program, []g.Approval{approval}, h.signerKey, time.Now().UTC())
	if err != nil {
		t.Fatal("exact persisted parent approval", err)
	}
	h.bootstrap.Parent = parent
	a := g.JournalAuthorization{SchemaVersion: g.JournalSchemaVersion, Kind: g.JournalKind, ID: "connected-journal-authorization", JournalID: "connected-journal", ParentEnvelopeSHA256: g.Digest(parent), ParentSHA256: g.Digest(parent.Program), BindingSHA256: g.Digest(parent.Program.Binding), RealmSHA256: g.Digest(parent.Program.Realm), PipelineID: prepared.JournalReview.PipelineID, Ref: prepared.JournalReview.Ref, Policy: g.JournalPolicy, Base: prepared.JournalReview.Base, PipelineKeySHA256: g.BytesDigest(keys.Pipeline), LedgerKeySHA256: g.BytesDigest(keys.Ledger), MaximumEffects: int(prepared.JournalReview.MaxEffects), MaximumRecords: int(prepared.JournalReview.MaxRecords), CreatedAt: time.Now().UTC(), ExpiresAt: prepared.JournalReview.ExpiresAt, Nonce: "connected-journal-nonce"}
	var draft store.FleetGroupAuthorityDraft
	if err = h.ledger.Do(ctx, f.tenant, func(tx *store.Tx) error {
		var e error
		draft, e = tx.FleetGroupJournalDraftAuthorization(ctx, h.bootstrap, "JOURNAL", a)
		return e
	}); err != nil {
		t.Fatal("persist exact journal draft", err)
	}
	authorityApproval := h.approve(t, ctx, draft, "JOURNAL")
	// The signing identity authenticates no ledger writes. Its key signs only the
	// exact publicly reviewed body carrying the persisted independent DB time.
	if err = signerDB.Do(ctx, f.tenant, func(tx *store.Tx) error {
		var e error
		h.bootstrap.Authorization, e = g.SignJournalAuthorization(a, []g.JournalApproval{{ID: authorityApproval.ID, TenantID: f.tenant, ActorID: authorityApproval.ActorID, Role: authorityApproval.Role, AuthorizationSHA256: authorityApproval.AuthorizationSHA256, ApprovedAt: authorityApproval.ApprovedAt}}, parent, keys.Core(), h.signerKey, time.Now().UTC())
		return e
	}); err != nil {
		t.Fatal(err)
	}
	h.view, _, err = g.SealJournalView(parent, h.bootstrap.Authorization, nil, keys.Core(), ledgerKey, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	h.bootstrap.Head = h.view.Head
	if err = h.ledger.Do(ctx, f.tenant, func(tx *store.Tx) error {
		var e error
		h.cursor, e = tx.FleetGroupJournalBootstrap(ctx, h.bootstrap)
		return e
	}); err != nil {
		t.Fatal("real private PG zero-head bootstrap", err)
	}
	ca := g.ContinuationAuthorization{SchemaVersion: g.ContinuationSchemaVersion, ID: "connected-continuation-authorization", ChainID: h.bootstrap.ChainID, Policy: g.ContinuationPolicy, ParentEnvelopeSHA256: g.Digest(parent), JournalAuthorizationSHA256: g.Digest(h.bootstrap.Authorization), BindingSHA256: g.Digest(parent.Program.Binding), RealmSHA256: g.Digest(parent.Program.Realm), SignerKeySHA256: g.BytesDigest(keys.Signer), PipelineKeySHA256: g.BytesDigest(keys.Pipeline), LedgerKeySHA256: g.BytesDigest(keys.Ledger), BootstrapHead: h.view.Head, RecordLimit: 512, ByteLimit: g.JournalByteLimit, CreatedAt: time.Now().UTC(), ForwardExpiresAt: a.ExpiresAt, Nonce: "connected-continuation-nonce"}
	if err = h.ledger.Do(ctx, f.tenant, func(tx *store.Tx) error {
		var e error
		draft, e = tx.FleetGroupJournalDraftAuthorization(ctx, h.bootstrap, "CONTINUATION", ca)
		return e
	}); err != nil {
		t.Fatal("persist exact continuation draft", err)
	}
	authorityApproval = h.approve(t, ctx, draft, "CONTINUATION")
	if err = h.ledger.Do(ctx, f.tenant, func(tx *store.Tx) error {
		signed, e := g.SignContinuationAuthorization(ctx, ca, []g.ContinuationApproval{{ID: authorityApproval.ID, TenantID: f.tenant, ActorID: authorityApproval.ActorID, Role: authorityApproval.Role, AuthorizationSHA256: authorityApproval.AuthorizationSHA256, ApprovedAt: authorityApproval.ApprovedAt}}, h.view, keys.Core(), tx.FleetGroupJournalAuthority(), h.signerKey, time.Now().UTC())
		if e != nil {
			return e
		}
		return tx.FleetGroupJournalAttachContinuation(ctx, h.bootstrap.ChainID, signed)
	}); err != nil {
		t.Fatal("independently approved precommand continuation", err)
	}
	if err = h.ledger.Do(ctx, f.tenant, func(tx *store.Tx) error {
		v, k, e := tx.FleetGroupJournalOriginal(ctx, h.bootstrap.ChainID)
		if e != nil {
			return e
		}
		if len(v.Records) != 0 || g.Digest(k) != g.Digest(keys) {
			return errors.New("bootstrap current root differs")
		}
		h.view = v
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return h
}

func sourceDocument(v any) model.Document {
	b, _ := json.Marshal(v)
	var d model.Document
	_ = json.Unmarshal(b, &d)
	return d
}
