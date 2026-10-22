package service

// Restricted PG component integration. Acquisition, canonicalization and model
// below are explicit doubles; this proves currentness/snapshot/ACL behavior,
// never native history, a calibrated forecast or a purchase recommendation.
import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	portfolio "github.com/christopherosiemo/bn-implementation-Finops/internal/commitmentportfolio"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/provider"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/source"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func decisionRenewalInstall(t *testing.T, ctx context.Context, admin *store.Store) {
	t.Helper()
	if err := admin.Migrate(ctx, "../../migrations"); err != nil {
		t.Fatal("financial renewal component migrations failed", err)
	}
}

func decisionRenewalPoint(ctx context.Context, tx *store.Tx, sourceID string, scope model.Document) error {
	id := model.ID()
	observed := time.Now().UTC().Format(time.RFC3339Nano)
	scope = model.Clone(scope)
	scope["receipt_id"], scope["observed_at"] = id, observed
	registration, err := tx.SourceGet(ctx, sourceID)
	if err != nil {
		return err
	}
	_, err = tx.SourceReceiptCreate(ctx, model.Document{"id": id, "kind": "AWS_COMMITMENT", "source_id": sourceID, "config_hash": source.ConfigurationHash(registration), "observed_at": observed, "commitment_scope": scope, "native_hash": source.Hash(scope)})
	if err != nil {
		return err
	}
	checkpoint, err := tx.SourceCheckpointGet(ctx, sourceID, "status")
	if err != nil {
		return err
	}
	checkpoint["commitment_receipt_id"], checkpoint["status"], checkpoint["last_sync_at"], checkpoint["last_sync_version"], checkpoint["config_hash"] = id, "HEALTHY", observed, model.Number(registration, "version"), source.ConfigurationHash(registration)
	return tx.SourceCheckpointSet(ctx, sourceID, "status", checkpoint)
}

func decisionRenewalBase(ctx context.Context, db *store.Store, tenant, workload string, selection model.Document) ([]byte, error) {
	var raw []byte
	body, err := json.Marshal(selection)
	if err != nil {
		return nil, err
	}
	err = db.Do(ctx, tenant, func(tx *store.Tx) error {
		return tx.QueryRow(ctx, "SELECT public.commitment_decision_base($1,$2,$3::jsonb)", tenant, workload, body).Scan(&raw)
	})
	return raw, err
}

// Mutations are transaction-local in this exact marked child database. No
// immutable source/request/result row is updated. Normal role-specific methods
// perform every new source receipt/checkpoint/config write before switching to
// the actual commissioned analyst LOGIN/OID and its existing NOLOGIN role.
func decisionRenewalRollbackProbe(t *testing.T, ctx context.Context, admin, analyst *store.Store, tenant, workload string, selection model.Document, mutate func(*store.Tx) error) ([]byte, error) {
	t.Helper()
	tx, err := admin.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, "SELECT set_config('app.tenant_id',$1,true)", tenant); err != nil {
		t.Fatal(err)
	}
	local := &store.Tx{Tx: tx, Tenant: tenant}
	if mutate != nil {
		if err = mutate(local); err != nil {
			t.Fatal("component currentness mutation did not reach its precondition", err)
		}
	}
	if _, err = tx.Exec(ctx, "RESET ROLE"); err != nil {
		t.Fatal(err)
	}
	login := analyst.Pool.Config().ConnConfig.User
	if !strings.HasPrefix(login, "portfolio_native_") {
		t.Fatal("financial renewal exact analyst login differs")
	}
	var expectedOID uint32
	if err = admin.Pool.QueryRow(ctx, "SELECT oid FROM pg_roles WHERE rolname=$1", login).Scan(&expectedOID); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, "SET LOCAL SESSION AUTHORIZATION "+pgx.Identifier{login}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, "SET LOCAL ROLE finops_commitment_portfolio"); err != nil {
		t.Fatal(err)
	}
	var actualLogin, actualRole string
	var oid uint32
	var scoped bool
	if err = tx.QueryRow(ctx, "SELECT session_user::text,current_user::text,(SELECT oid FROM pg_roles WHERE rolname=session_user),public.commitment_portfolio_scope($1)", tenant).Scan(&actualLogin, &actualRole, &oid, &scoped); err != nil || actualLogin != login || actualRole != "finops_commitment_portfolio" || oid != expectedOID || !scoped {
		t.Fatal("financial renewal actual LOGIN/OID/tenant/role differs")
	}
	var raw []byte
	body, _ := json.Marshal(selection)
	err = tx.QueryRow(ctx, "SELECT public.commitment_decision_base($1,$2,$3::jsonb)", tenant, workload, body).Scan(&raw)
	if rollback := tx.Rollback(ctx); rollback != nil {
		t.Fatal("financial renewal component rollback failed")
	}
	return raw, err
}

func decisionRenewalRejection(t *testing.T, err error) {
	t.Helper()
	var pg *pgconn.PgError
	if !errors.As(err, &pg) || pg.Code != "P0001" {
		t.Fatal("financial currentness did not refuse through the guarded resolver")
	}
	switch pg.Message {
	case "decision native financial inventory changed", "decision financial source or billing changed", "portfolio source not current", "portfolio inventory changed", "portfolio billing changed", "decision original financial snapshot unavailable":
	default:
		t.Fatal("financial currentness failed at an unrelated guard")
	}
}

// Correction transport retains every immutable native object version. The
// ordinary pipeline may re-read its prior checkpoint while selecting the new
// execution; replacing a map entry at the same key must not erase that version.
type decisionRenewalBillingReader struct {
	*source.FixtureReader
	versions map[string]provider.BillingObject
}

func (r *decisionRenewalBillingReader) BillingObject(ctx context.Context, bucket, key, version string) (provider.BillingObject, error) {
	if version != "" && bucket == r.Registration.Bucket {
		if object, ok := r.versions[key+"\x00"+version]; ok {
			object.Data = append([]byte{}, object.Data...)
			return object, nil
		}
	}
	return r.FixtureReader.BillingObject(ctx, bucket, key, version)
}

// Add one real pipeline-issued selected CUR window, so the moved-head control
// exercises an actual selected receipt instead of a fabricated checkpoint ID.
func decisionRenewalSelectedBilling(t *testing.T, ctx context.Context, f *mutationReplayFixture, sourceID, cost string, versions map[string]provider.BillingObject) portfolio.Selection {
	t.Helper()
	var registration model.Document
	if err := f.roles["ingester"].Do(ctx, f.tenant, func(tx *store.Tx) error { var err error; registration, err = tx.SourceGet(ctx, sourceID); return err }); err != nil {
		t.Fatal(err)
	}
	r, err := source.ParseRegistration(registration)
	if err != nil {
		t.Fatal(err)
	}
	end := time.Now().UTC().Truncate(24 * time.Hour)
	start := end.Add(-24 * time.Hour)
	rows := []model.Document{}
	if cost != "0.2" && cost != "0.3" {
		t.Fatal("component correction cost outside fixed fixture")
	}
	for at := start; at.Before(end); at = at.Add(time.Hour) {
		rows = append(rows, nativeAssessmentUsage("i-0f040000000000001", "m6i.large", "EXPLICIT-PG-COMPONENT-SKU", cost, cost, at, at.Add(time.Hour)))
	}
	month := time.Date(start.Year(), start.Month(), 1, 0, 0, 0, 0, time.UTC)
	frame := nativeAssessmentExport(t, r, month, rows, time.Now().UTC())
	if versions == nil {
		t.Fatal("component immutable version store required")
	}
	for _, object := range frame.Objects {
		versions[object.Key+"\x00"+object.VersionID] = object
	}
	reader := &decisionRenewalBillingReader{FixtureReader: frame, versions: versions}
	pipeline := source.Pipeline{Store: f.roles["ingester"], ProviderFactory: func(context.Context, source.Registration) (source.Reader, error) { return reader, nil }, Normalize: func(_ context.Context, raw model.Document) (model.Document, error) {
		canonical := []model.Document{}
		for _, row := range source.Rows(raw["records"]) {
			canonical = append(canonical, model.Document{"x_SourceRecordId": row["identity_line_item_id"], "x_ProviderFields": row})
		}
		total := "4.8"
		if cost == "0.3" {
			total = "7.2"
		}
		return model.Document{"records": canonical, "totals": model.Document{"USD": total}}, nil
	}, Persist: func(context.Context, string, string, model.Document, model.Document) error { return nil }, ArchiveObject: func(_ context.Context, _, _, _ string, raw []byte) error {
		if len(raw) == 0 {
			return errors.New("component raw transport empty")
		}
		return nil
	}}
	if err = pipeline.Sync(ctx, f.tenant, sourceID); err != nil {
		t.Fatal("actual selected CUR pipeline failed on explicit component transports", err)
	}
	var selection portfolio.Selection
	if err = f.roles["ingester"].Do(ctx, f.tenant, func(tx *store.Tx) error {
		current, err := tx.SourceGet(ctx, sourceID)
		if err != nil {
			return err
		}
		selection = portfolio.Selection{SourceID: sourceID, CommitmentReceiptID: model.String(current, "commitment_receipt_id"), BillingReceiptIDs: []string{model.String(current, "latest_receipt_id")}, Period: portfolio.Period{Start: start, End: end}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return selection
}

func TestCommitmentDecision040FinancialRenewalSnapshotAndCurrentness(t *testing.T) {
	f, admin, _, _ := newFleetNativeHTTPTest(t)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	decisionRenewalInstall(t, ctx, admin)
	analyst := commitmentPortfolioNativeRuntime(t, ctx, admin, f.tenant)
	prepareID := decision040PrepareBlocked(t, ctx, f, analyst, "fixture-workload")
	var originalSelection model.Document
	if err := f.roles["api"].Do(ctx, f.tenant, func(tx *store.Tx) error {
		var raw []byte
		if err := tx.QueryRow(ctx, "SELECT document->'selection' FROM entities WHERE tenant_id=$1 AND kind='recommendations' AND id=$2", f.tenant, prepareID).Scan(&raw); err != nil {
			return err
		}
		return json.Unmarshal(raw, &originalSelection)
	}); err != nil {
		t.Fatal(err)
	}
	versions := map[string]provider.BillingObject{}
	selected := decisionRenewalSelectedBilling(t, ctx, f, "ownership-component-source", "0.2", versions)
	finance := f.token(f.tenant, "financial-renewal-component-finance", "FINANCE")
	code, queued, _ := f.request("commitment-portfolio-analyses", `"0"`, "financial-renewal-selected-cur", finance, source.Object(selected))
	if code != 202 {
		t.Fatal("actual039 selected CUR request refused", code)
	}
	worker := portfolio.Worker{Pool: analyst.Pool, Tenant: f.tenant, Calculator: decision040Calculator{}}
	if replay, err := worker.Process(ctx, model.String(queued, "id")); err != nil || replay {
		t.Fatal("actual039 selected CUR assessment failed", err)
	}
	selection := model.Document{"portfolio_analysis_request_id": queued["id"], "offer_receipt_id": originalSelection["offer_receipt_id"]}
	before, err := decisionRenewalBase(ctx, analyst, f.tenant, "fixture-workload", selection)
	if err != nil {
		t.Fatal("otherwise-valid financial base unavailable before native renewal", err)
	}
	var snapshotBefore, inventoryRaw []byte
	var inputHash string
	if err = admin.Pool.QueryRow(ctx, "SELECT input_snapshot,input_hash,input_snapshot->'commitment' FROM commitment_portfolio_requests WHERE tenant_id=$1 AND id=$2", f.tenant, queued["id"]).Scan(&snapshotBefore, &inputHash, &inventoryRaw); err != nil || len(snapshotBefore) == 0 {
		t.Fatal("new actual039 request did not retain its immutable input snapshot")
	}
	var inventory model.Document
	decision040Decode(t, inventoryRaw, &inventory)
	scope := source.Object(inventory["commitment_scope"])
	if err = f.roles["ingester"].Do(ctx, f.tenant, func(tx *store.Tx) error { return decisionRenewalPoint(ctx, tx, selected.SourceID, scope) }); err != nil {
		t.Fatal("normal ingester native point renewal failed", err)
	}
	after, err := decisionRenewalBase(ctx, analyst, f.tenant, "fixture-workload", selection)
	if err != nil || source.BytesHash(before) != source.BytesHash(after) {
		t.Fatal("identical native renewal changed original040 base bytes", err)
	}
	var snapshotAfter []byte
	var afterHash string
	if err = admin.Pool.QueryRow(ctx, "SELECT input_snapshot,input_hash FROM commitment_portfolio_requests WHERE tenant_id=$1 AND id=$2", f.tenant, queued["id"]).Scan(&snapshotAfter, &afterHash); err != nil || source.BytesHash(snapshotBefore) != source.BytesHash(snapshotAfter) || inputHash != afterHash {
		t.Fatal("native renewal rewrote the immutable039 snapshot or input hash")
	}
	var proofs int
	if err = admin.Pool.QueryRow(ctx, "SELECT count(*) FROM commitment_financial_renewals WHERE tenant_id=$1 AND portfolio_request_id=$2 AND original_receipt_id<>current_receipt_id", f.tenant, queued["id"]).Scan(&proofs); err != nil || proofs != 1 {
		t.Fatal("actual source renewal was not separately persisted")
	}
	// Existing analyses retain their original selection through an equivalent
	// renewal. A NEW039 request must select the actual current receipt instead.
	code, refused, _ := f.request("commitment-portfolio-analyses", `"0"`, "financial-renewal-stale-new-request", finance, source.Object(selected))
	if code != 409 || model.String(refused, "error") != "PORTFOLIO_INPUTS_NOT_CURRENT" {
		t.Fatal("superseded inventory authorized a new039 analysis", code)
	}
	currentSelection := selected
	if err = f.roles["api"].Do(ctx, f.tenant, func(tx *store.Tx) error {
		current, err := tx.SourceGet(ctx, selected.SourceID)
		if err != nil {
			return err
		}
		currentSelection.CommitmentReceiptID = model.String(current, "commitment_receipt_id")
		return nil
	}); err != nil || currentSelection.CommitmentReceiptID == "" || currentSelection.CommitmentReceiptID == selected.CommitmentReceiptID {
		t.Fatal("actual renewed inventory selection unavailable", err)
	}
	code, currentRequest, _ := f.request("commitment-portfolio-analyses", `"0"`, "financial-renewal-current-new-request", finance, source.Object(currentSelection))
	if code != 202 || model.String(currentRequest, "id") == model.String(queued, "id") || portfolio.Hash(currentRequest["selection"]) != portfolio.Hash(currentSelection) {
		t.Fatal("new039 analysis did not bind the current issued inventory", code)
	}
	if err = admin.Pool.QueryRow(ctx, "SELECT input_snapshot,input_hash FROM commitment_portfolio_requests WHERE tenant_id=$1 AND id=$2", f.tenant, queued["id"]).Scan(&snapshotAfter, &afterHash); err != nil || source.BytesHash(snapshotBefore) != source.BytesHash(snapshotAfter) || inputHash != afterHash {
		t.Fatal("new039 selection changed the original immutable analysis")
	}
	// Internal helper remains owner-only; the existing public/private base is
	// the only granted route exercised above. No test grants are necessary.
	err = analyst.Do(ctx, f.tenant, func(tx *store.Tx) error {
		_, err := tx.Exec(ctx, "SELECT public.commitment_decision_financial_current($1,$2)", f.tenant, queued["id"])
		return err
	})
	var denied *pgconn.PgError
	if !errors.As(err, &denied) || denied.Code != "42501" {
		t.Fatal("analyst gained direct internal financial helper access")
	}
	for _, name := range []string{"same_native_control", "new_plan", "recurring_fee", "account_scope", "currency", "complete", "source_configuration", "source_version", "source_revocation"} {
		t.Run(name, func(t *testing.T) {
			body, err := decisionRenewalRollbackProbe(t, ctx, admin, analyst, f.tenant, "fixture-workload", selection, func(tx *store.Tx) error {
				if _, err := tx.Exec(ctx, "SET LOCAL ROLE finops_ingester"); err != nil {
					return err
				}
				change := model.Clone(scope)
				switch name {
				case "new_plan", "recurring_fee", "currency":
					// The qualified original inventory is genuinely empty. These
					// are complete new native position observations, retaining
					// their real SDK field names; none may count as an empty renewal.
					snapshot := source.Rows(change["native_snapshots"])[0]
					plan := model.Document{"savingsPlanArn": "arn:aws:savingsplans::111122223333:savingsplan/11111111-1111-4111-8111-111111111111", "state": "active", "savingsPlanType": "Compute", "currency": "USD", "commitment": "1", "upfrontPaymentAmount": "0", "recurringPaymentAmount": "1", "paymentOption": "No Upfront"}
					if name == "recurring_fee" {
						plan["recurringPaymentAmount"] = "2"
					}
					if name == "currency" {
						plan["currency"] = "EUR"
					}
					snapshot["savings_plans"] = []model.Document{plan}
					change["native_snapshots"] = []model.Document{snapshot}
					change["savings_plan_count"] = 1
				case "account_scope":
					change["usage_account_ids"] = []string{"111122223333", "444455556666"}
				case "complete":
					change["complete"] = false
				case "source_configuration", "source_version", "source_revocation":
					if _, err := tx.Exec(ctx, "SET LOCAL ROLE finops_api"); err != nil {
						return err
					}
					registration, err := tx.SourceGet(ctx, selected.SourceID)
					if err != nil {
						return err
					}
					if name == "source_configuration" {
						registration["prefix"] = "changed-cur/"
					}
					if name == "source_revocation" {
						registration["revoked"], registration["enabled"] = true, false
					}
					_, err = tx.SourceUpdate(ctx, selected.SourceID, model.Number(registration, "version"), registration)
					return err
				}
				return decisionRenewalPoint(ctx, tx, selected.SourceID, change)
			})
			if name == "same_native_control" {
				if err != nil || source.BytesHash(body) != source.BytesHash(before) {
					t.Fatal("positive renewal control is not qualified", err)
				}
			} else {
				decisionRenewalRejection(t, err)
			}
			// Rollback retained all committed actual source facts and original base.
			stable, err := decisionRenewalBase(ctx, analyst, f.tenant, "fixture-workload", selection)
			if err != nil || source.BytesHash(stable) != source.BytesHash(before) {
				t.Fatal("negative case leaked a currentness/source mutation")
			}
		})
	}
	t.Run("selected_cur_head", func(t *testing.T) {
		corrected := decisionRenewalSelectedBilling(t, ctx, f, selected.SourceID, "0.3", versions)
		if len(corrected.BillingReceiptIDs) != 1 || corrected.BillingReceiptIDs[0] == selected.BillingReceiptIDs[0] {
			t.Fatal("actual source correction did not issue a distinct current CUR head")
		}
		_, err := decisionRenewalBase(ctx, analyst, f.tenant, "fixture-workload", selection)
		decisionRenewalRejection(t, err)
		var frozen []byte
		if err = admin.Pool.QueryRow(ctx, "SELECT input_snapshot FROM commitment_portfolio_requests WHERE tenant_id=$1 AND id=$2", f.tenant, queued["id"]).Scan(&frozen); err != nil || source.BytesHash(frozen) != source.BytesHash(snapshotBefore) {
			t.Fatal("CUR correction changed the original selected snapshot")
		}
	})
	t.Log("FINANCIAL_RENEWAL_COMPONENT: actual039 snapshot, ingester point renewal,040 scoped resolver/currentness and rollback negatives; no native-history/forecast/recommendation claim")
}

// Make a genuine039 request/result BEFORE040 is applied. The additive migration
// must leave its snapshot NULL; no disabled trigger or immutable-row update is
// used to manufacture this legacy compatibility case.
func TestCommitmentDecision040FinancialRenewalLegacyNullSnapshotRefuses(t *testing.T) {
	f, admin, _, _ := newFleetNativeHTTPTest(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	analyst := commitmentPortfolioNativeRuntime(t, ctx, admin, f.tenant)
	var column bool
	if err := admin.Pool.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='commitment_portfolio_requests' AND column_name='input_snapshot')").Scan(&column); err != nil || column {
		t.Fatal("legacy component did not start at actual039 schema")
	}
	const sourceID = "legacy-financial-renewal-component"
	registration := source.FixtureRegistration(f.tenant, sourceID)
	if err := f.roles["api"].Do(ctx, f.tenant, func(tx *store.Tx) error { _, err := tx.SourceCreate(ctx, registration); return err }); err != nil {
		t.Fatal(err)
	}
	observed := time.Now().UTC().Format(time.RFC3339Nano)
	id := model.ID()
	// Explicit empty-inventory acquisition double, issued by the real ingester.
	scope := model.Document{"receipt_id": id, "observed_at": observed, "payer_account_id": "111122223333", "usage_account_ids": []string{"111122223333"}, "scope": "PAYER_ALL_LINKED_ACCOUNTS_ALL_REGIONS", "complete": true, "reserved_instance_count": 0, "savings_plan_count": 0, "native_snapshots": []model.Document{{"account_id": "111122223333", "reserved_instances": []model.Document{}, "savings_plans": []model.Document{}, "regions": []string{"eu-west-1"}}}}
	if err := f.roles["ingester"].Do(ctx, f.tenant, func(tx *store.Tx) error {
		if _, err := tx.SourceReceiptCreate(ctx, model.Document{"id": id, "kind": "AWS_COMMITMENT", "source_id": sourceID, "config_hash": source.ConfigurationHash(registration), "observed_at": observed, "commitment_scope": scope, "native_hash": source.Hash(scope)}); err != nil {
			return err
		}
		return tx.SourceCheckpointSet(ctx, sourceID, "status", model.Document{"status": "HEALTHY", "config_hash": source.ConfigurationHash(registration), "commitment_receipt_id": id, "last_sync_at": observed, "last_sync_version": 1})
	}); err != nil {
		t.Fatal(err)
	}
	day := time.Now().UTC().Truncate(24 * time.Hour)
	selected := portfolio.Selection{SourceID: sourceID, CommitmentReceiptID: id, BillingReceiptIDs: []string{}, Period: portfolio.Period{Start: day.Add(-24 * time.Hour), End: day}}
	finance := f.token(f.tenant, "legacy-renewal-finance", "FINANCE")
	code, queued, _ := f.request("commitment-portfolio-analyses", `"0"`, "legacy-financial-before040", finance, source.Object(selected))
	if code != 202 {
		t.Fatal("actual039 legacy request was not admitted", code)
	}
	worker := portfolio.Worker{Pool: analyst.Pool, Tenant: f.tenant, Calculator: decision040Calculator{}}
	if replay, err := worker.Process(ctx, model.String(queued, "id")); err != nil || replay {
		t.Fatal("actual039 legacy assessment failed", err)
	}
	var originalHash, originalStatus string
	if err := admin.Pool.QueryRow(ctx, "SELECT r.input_hash,x.status FROM commitment_portfolio_requests r JOIN commitment_portfolio_results x ON(x.tenant_id,x.request_id)=(r.tenant_id,r.id) WHERE r.tenant_id=$1 AND r.id=$2", f.tenant, queued["id"]).Scan(&originalHash, &originalStatus); err != nil || originalStatus != "ASSESSED" {
		t.Fatal("legacy positive precondition missing")
	}
	decisionRenewalInstall(t, ctx, admin)
	var nullSnapshot bool
	var retainedHash string
	if err := admin.Pool.QueryRow(ctx, "SELECT input_snapshot IS NULL,input_hash FROM commitment_portfolio_requests WHERE tenant_id=$1 AND id=$2", f.tenant, queued["id"]).Scan(&nullSnapshot, &retainedHash); err != nil || !nullSnapshot || originalHash != retainedHash {
		t.Fatal("040 backfilled or changed a legacy039 request")
	}
	selection := model.Document{"portfolio_analysis_request_id": queued["id"], "offer_receipt_id": "unreached-offer-after-legacy-snapshot-guard"}
	_, err := decisionRenewalBase(ctx, analyst, f.tenant, "fixture-workload", selection)
	decision040ExpectedSQL(t, err, "decision original financial snapshot unavailable")
	t.Log("LEGACY039_COMPONENT: actual before040 assessed row retained byte/hash identity and NULL snapshot; new040 financial path refuses, no historical backfill")
}
