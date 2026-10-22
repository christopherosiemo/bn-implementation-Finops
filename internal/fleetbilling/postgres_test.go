package fleetbilling

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/source"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type memoryArchive map[string]PinnedObject
type hookedArchive struct {
	memoryArchive
	afterRead func()
}

func (a hookedArchive) ReadPinned(ctx context.Context, tenant string, ref model.Document) (PinnedObject, error) {
	o, e := a.memoryArchive.ReadPinned(ctx, tenant, ref)
	if a.afterRead != nil {
		a.afterRead()
	}
	return o, e
}

func (a memoryArchive) ReadPinned(_ context.Context, tenant string, ref model.Document) (PinnedObject, error) {
	if !strings.HasPrefix(model.String(ref, "key"), "tenant/"+tenant+"/") {
		return PinnedObject{}, fmt.Errorf("PRICE_ARCHIVE_TENANT_INVALID")
	}
	raw, ok := a[model.String(ref, "body_sha256")]
	if !ok {
		return PinnedObject{}, fmt.Errorf("PRICE_ARCHIVE_VERSION_MISSING")
	}
	raw.Body = append([]byte{}, raw.Body...)
	return raw, nil
}
func archiveRef(a memoryArchive, tenant, kind string, raw []byte) model.Document {
	hash := BytesHash(raw)
	ref := model.Document{"bucket": "private-fixture", "key": "tenant/" + tenant + "/" + kind + "/" + hash, "version_id": "native-version-" + hash, "body_sha256": hash}
	a[hash] = PinnedObject{model.String(ref, "bucket"), model.String(ref, "key"), model.String(ref, "version_id"), raw}
	return ref
}

type billingPG struct {
	admin  *pgxpool.Pool
	writer *store.Store
}

func billingPostgres(t *testing.T) billingPG {
	t.Helper()
	adminURL := os.Getenv("TEST_FLEET_BILLING_ADMIN_URL")
	if adminURL == "" {
		t.Skip("TEST_FLEET_BILLING_ADMIN_URL enables an isolated disposable DB, never the application schema")
	}
	ctx := context.Background()
	master, e := pgxpool.New(ctx, adminURL)
	if e != nil {
		t.Fatal("private test admin unavailable")
	}
	suffix := strings.ReplaceAll(model.ID(), "-", "")
	database, login := "fleet_price_"+suffix, "fleet_price_"+suffix
	owner := "finops-local-fleet-price:" + suffix
	t.Logf("Owned disposable database=%s login=%s ownership=%s", database, login, owner)
	password := model.ID() + model.ID()
	if _, e = master.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{database}.Sanitize()); e != nil {
		t.Fatal(e)
	}
	var admin *pgxpool.Pool
	var writer *store.Store
	createdLogin := false
	t.Cleanup(func() {
		if writer != nil {
			writer.Pool.Close()
		}
		if admin != nil {
			admin.Close()
		}
		var value string
		if err := master.QueryRow(ctx, "SELECT coalesce(shobj_description(oid,'pg_database'),'') FROM pg_database WHERE datname=$1", database).Scan(&value); err != nil || value != owner {
			t.Error("owned price DB cleanup refused")
		} else if _, err = master.Exec(ctx, "DROP DATABASE "+pgx.Identifier{database}.Sanitize()+" WITH (FORCE)"); err != nil {
			t.Error("owned price DB cleanup failed")
		}
		if createdLogin {
			if err := master.QueryRow(ctx, "SELECT coalesce(shobj_description(oid,'pg_authid'),'') FROM pg_roles WHERE rolname=$1", login).Scan(&value); err != nil || value != owner {
				t.Error("owned price login cleanup refused")
			} else if _, err = master.Exec(ctx, "DROP ROLE "+pgx.Identifier{login}.Sanitize()); err != nil {
				t.Error("owned price login cleanup failed")
			}
		}
		master.Close()
	})
	if _, e = master.Exec(ctx, "COMMENT ON DATABASE "+pgx.Identifier{database}.Sanitize()+" IS '"+owner+"'"); e != nil {
		t.Fatal(e)
	}
	u, e := url.Parse(adminURL)
	if e != nil {
		t.Fatal("private test URL invalid")
	}
	u.Path = "/" + database
	admin, e = pgxpool.New(ctx, u.String())
	if e != nil {
		t.Fatal("owned test DB unavailable")
	}
	for _, file := range []string{"001_control_plane.sql", "002_ingestion_and_approval_boundary.sql", "005_trusted_sources.sql", "021_fleet_billing_price.sql"} {
		raw, e := os.ReadFile(filepath.Join("..", "..", "migrations", file))
		if e != nil {
			t.Fatal(e)
		}
		if _, e = admin.Exec(ctx, string(raw)); e != nil {
			t.Fatalf("isolated migration %s failed: %v", file, e)
		}
	}
	if _, e = master.Exec(ctx, "CREATE ROLE "+pgx.Identifier{login}.Sanitize()+" LOGIN PASSWORD '"+password+"'"); e != nil {
		t.Fatal(e)
	}
	createdLogin = true
	if _, e = master.Exec(ctx, "COMMENT ON ROLE "+pgx.Identifier{login}.Sanitize()+" IS '"+owner+"'"); e != nil {
		t.Fatal(e)
	}
	if _, e = master.Exec(ctx, "GRANT finops_ingester TO "+pgx.Identifier{login}.Sanitize()); e != nil {
		t.Fatal(e)
	}
	u.User = url.UserPassword(login, password)
	writer, e = store.OpenRuntime(ctx, u.String(), "ingester")
	if e != nil {
		t.Fatal("dedicated writer unavailable", e)
	}
	return billingPG{admin, writer}
}
func asRole(ctx context.Context, p *pgxpool.Pool, tenant, role string, f func(*store.Tx) error) error {
	tx, e := p.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	if _, e = tx.Exec(ctx, "SET LOCAL ROLE "+pgx.Identifier{role}.Sanitize()); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, "SELECT set_config('app.tenant_id',$1,true)", tenant); e != nil {
		return e
	}
	if e = f(&store.Tx{Tx: tx, Tenant: tenant}); e != nil {
		return e
	}
	return tx.Commit(ctx)
}

func seedBillingJob(ctx context.Context, tx *store.Tx, reg model.Document, records []model.Document, start, end time.Time, suffix string) (model.Document, error) {
	version := "source-version-" + suffix
	revisionID, receiptID, jobID := "revision-"+suffix, "receipt-"+suffix, "job-"+suffix
	raw := model.Document{"schema_version": "3", "source_id": reg["id"], "source_version": version, "records": records}
	canonical := []model.Document{}
	for _, r := range records {
		cost := rawString(r, "line_item_net_unblended_cost")
		if cost == "" {
			cost = rawString(r, "line_item_unblended_cost")
		}
		canonical = append(canonical, model.Document{"x_SourceRecordId": r["identity_line_item_id"], "x_SourceId": reg["id"], "x_SourceVersion": version, "x_ProviderFields": r, "SubAccountId": r["line_item_usage_account_id"], "ResourceId": r["line_item_resource_id"], "RegionId": r["product_region_code"], "BillingCurrency": r["line_item_currency_code"], "BillingAccountId": r["bill_payer_account_id"], "ChargePeriodStart": r["line_item_usage_start_date"], "ChargePeriodEnd": r["line_item_usage_end_date"], "BilledCost": cost})
	}
	can := model.Document{"records": canonical}
	proof := model.Document{"receipt_id": receiptID, "revision_id": revisionID, "manifest_hash": strings.Repeat("a", 64), "payer_account_id": account, "usage_account_ids": []string{account}, "region": "eu-west-1", "currency": "USD", "invoice_entity": "AWS EMEA", "period_start": start.Format(time.RFC3339Nano), "period_end": end.Format(time.RFC3339Nano), "billing_period_start": start.Format(time.RFC3339Nano), "state": "COMPLETE", "object_count": 1, "verified_object_count": 1, "row_count": len(records), "verified_row_count": len(records)}
	cfg := source.ConfigurationHash(reg)
	rev, e := tx.SourceRevisionCreate(ctx, model.Document{"id": revisionID, "source_id": reg["id"], "registration_id": reg["id"], "revision_hash": Hash(raw), "config_hash": cfg, "raw_hash": Hash(raw), "canonical_hash": Hash(can)})
	if e != nil {
		return nil, e
	}
	_ = rev
	receipt, e := tx.SourceReceiptCreate(ctx, model.Document{"id": receiptID, "kind": "AWS_CUR2", "source_id": reg["id"], "registration_id": reg["id"], "revision_id": revisionID, "ingestion_job_id": jobID, "source_version": version, "config_hash": cfg, "raw_hash": Hash(raw), "canonical_hash": Hash(can), "source_proof": proof})
	if e != nil {
		return nil, e
	}
	_, e = tx.Create(ctx, "ingestion_jobs", model.Document{"id": jobID, "status": "PERSISTED", "source_id": reg["id"], "source_registration_id": reg["id"], "source_receipt_id": receiptID, "source_revision_id": revisionID, "source_provenance": "AWS_CUR2_AUTHENTICATED", "raw": raw, "canonical": can})
	return receipt, e
}

func TestFleetBillingNativeBrokerPostgresIsolationCorrectionsAndRevocation(t *testing.T) {
	pg := billingPostgres(t)
	ctx := context.Background()
	now := time.Now().UTC()
	target := testTarget()
	archive := memoryArchive{}
	var reg model.Document
	if e := asRole(ctx, pg.admin, "tenant", "finops_api", func(tx *store.Tx) error {
		var e error
		reg, e = tx.SourceCreate(ctx, model.Document{"id": "source", "kind": "AWS_CUR2", "enabled": true, "payer_account_id": account, "usage_account_ids": []string{account}, "region": "eu-west-1", "read_role_binding_id": "private-read-binding"})
		if e != nil {
			return e
		}
		_, e = tx.Create(ctx, "resources", model.Document{"id": target.Binding.ResourceID, "workload_id": target.Binding.WorkloadID, "provider": "AWS", "provider_resource_id": target.OldASG, "account_id": account, "region": "eu-west-1", "environment": "NON_PRODUCTION"})
		return e
	}); e != nil {
		t.Fatal(e)
	}
	membership, membershipRaw := testMembership(target)
	templates, templatesRaw := testTemplates("default")
	hardware, hardwareRaw := testHardware(t, oldInstance, "m6i.xlarge", now)
	candidate, candidateRaw := testHardware(t, candidateInstance, "m6i.large", now)
	templates["membership_receipt_id"] = membership["id"]
	templates["binding"] = object(target.Binding)
	all := []model.Document{membership, templates, hardware, candidate}
	raws := [][]byte{membershipRaw, templatesRaw, hardwareRaw, candidateRaw}
	for n, d := range all {
		d["source_id"] = "source"
		d["config_hash"] = source.ConfigurationHash(reg)
		d["collected_at"] = now.Format(time.RFC3339Nano)
		d["raw_object"] = archiveRef(archive, "tenant", "fleet-price-native", raws[n])
		delete(d, "writer_role")
	}
	end := now.Truncate(24 * time.Hour)
	start := end.AddDate(0, 0, -14)
	periods := map[string][]model.Document{}
	for day := 0; day < 14; day++ {
		s := start.AddDate(0, 0, day)
		key := s.Format("2006-01")
		periods[key] = append(periods[key], usage(oldInstance, "m6i.xlarge", "OLD-NATIVE-SKU", "4.8", "0.2", s, s.Add(24*time.Hour)))
	}
	key := end.Add(-time.Hour).Format("2006-01")
	periods[key] = append(periods[key], usage(candidateInstance, "m6i.large", "CANDIDATE-NATIVE-SKU", "2.4", "0.1", end.Add(-24*time.Hour), end))
	// The registered workload allowlist is not the full payer export scope.
	// Ordinary rows from another linked account/region must remain visible for
	// portfolio corrections, while never supplying the target's selected price.
	other := usage("i-22222222222222222", "m6i.large", "OTHER-ACCOUNT-SKU", "2.4", "0.1", end.Add(-24*time.Hour), end)
	other["line_item_usage_account_id"] = "444455556666"
	other["product_region_code"] = "us-east-1"
	periods[key] = append(periods[key], other)
	keys := []string{}
	for key := range periods {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	if e := pg.writer.Do(ctx, "tenant", func(tx *store.Tx) error {
		if e := tx.SourceCheckpointSet(ctx, "source", "status", model.Document{"status": "HEALTHY", "last_sync_at": now.Format(time.RFC3339Nano)}); e != nil {
			return e
		}
		scope := model.Document{"receipt_id": "commitment", "payer_account_id": account, "usage_account_ids": []string{account, "444455556666"}, "observed_at": now.Format(time.RFC3339Nano), "scope": "PAYER_ALL_LINKED_ACCOUNTS_ALL_REGIONS", "complete": true, "reserved_instance_count": 0, "savings_plan_count": 0}
		if _, e := tx.SourceReceiptCreate(ctx, model.Document{"id": "commitment", "kind": "AWS_COMMITMENT", "source_id": "source", "config_hash": source.ConfigurationHash(reg), "commitment_scope": scope}); e != nil {
			return e
		}
		for _, d := range all {
			if _, e := tx.SourceReceiptCreate(ctx, d); e != nil {
				return e
			}
		}
		for n, key := range keys {
			left, _ := time.Parse("2006-01", key)
			right := left.AddDate(0, 1, 0)
			if right.After(end) {
				right = end
			}
			if _, e := seedBillingJob(ctx, tx, reg, periods[key], left, right, fmt.Sprint(n)); e != nil {
				return e
			}
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	broker := Broker{Store: pg.writer, Archive: archive, Targets: map[string]Target{"tenant:fleet-resource": target}, Now: func() time.Time { return now }}
	got, e := broker.Capture(ctx, "tenant", "fleet-resource", 5*time.Hour)
	if e != nil || got.Status != "READY" || got.ExecutionAuthorized || got.VerifiedSaving != nil || got.HardSpendCap || got.Candidate.Dimensions.SKU != "CANDIDATE-NATIVE-SKU" || *got.Old.ObservedComputeCost != "67.2" {
		t.Fatalf("native conditional account rate unavailable: status=%s reasons=%v error=%v", got.Status, got.ReasonCodes, e)
	}
	again, e := broker.Capture(ctx, "tenant", "fleet-resource", 5*time.Hour)
	if e != nil || again.ID != got.ID {
		t.Fatal("capture replay changed immutable evidence", e)
	}
	if e = broker.Revalidate(ctx, "tenant", got.ID, now.Add(5*time.Hour)); e != nil {
		t.Fatal(e)
	}
	t.Run("in-flight-source-sync-is-not-a-current-price-snapshot", func(t *testing.T) {
		connection, err := pg.admin.Acquire(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer connection.Release()
		key := "tenant:trusted-source:source"
		held := false
		lockSync := func() {
			if held {
				return
			}
			if _, err := connection.Exec(ctx, "SELECT pg_advisory_lock(hashtextextended($1,0))", key); err != nil {
				t.Fatal(err)
			}
			held = true
		}
		unlockSync := func() {
			if held {
				if _, err := connection.Exec(ctx, "SELECT pg_advisory_unlock(hashtextextended($1,0))", key); err != nil {
					t.Fatal(err)
				}
				held = false
			}
		}
		defer unlockSync()
		assertBlockedCapture := func(b Broker) {
			t.Helper()
			result, err := b.Capture(ctx, "tenant", "fleet-resource", 5*time.Hour)
			if err != nil || result.Status != "UNAVAILABLE" || result.ID != "" || result.ExecutionAuthorized || result.HardSpendCap || result.VerifiedSaving != nil || len(result.ReasonCodes) == 0 || result.ReasonCodes[0] != "PRICE_SOURCE_SYNC_IN_PROGRESS" {
				t.Fatalf("in-flight sync supplied current pricing: status=%s reasons=%v error=%v", result.Status, result.ReasonCodes, err)
			}
		}
		assertBlockedRevalidation := func(b Broker) {
			t.Helper()
			if err := b.Revalidate(ctx, "tenant", got.ID, now.Add(5*time.Hour)); err == nil || err.Error() != "PRICE_SOURCE_SYNC_IN_PROGRESS" {
				t.Fatal("in-flight sync passed current price revalidation", err)
			}
		}
		// The prior HEALTHY status deliberately remains unchanged, just as it can
		// during a multi-transaction sync. Current authority must still be denied.
		lockSync()
		assertBlockedCapture(broker)
		assertBlockedRevalidation(broker)
		if err := pg.writer.Do(ctx, "tenant", func(tx *store.Tx) error {
			stored, err := Get(ctx, tx, got.ID)
			if err == nil && stored.ID != got.ID {
				return errors.New("historical immutable price metadata changed")
			}
			return err
		}); err != nil {
			t.Fatal("sync denied historical metadata read", err)
		}
		unlockSync()
		// A sync can also begin after the initial snapshot, while pinned native
		// objects are being read. The final publication/validation transaction
		// must acquire the same shared guard rather than borrow the old HEALTHY.
		duringRead := broker
		duringRead.Archive = hookedArchive{archive, lockSync}
		assertBlockedCapture(duringRead)
		unlockSync()
		assertBlockedRevalidation(duringRead)
		unlockSync()
		result, err := broker.Capture(ctx, "tenant", "fleet-resource", 5*time.Hour)
		if err != nil || result.Status != "READY" || result.ID != got.ID {
			t.Fatal("completed sync retired unchanged immutable pricing", err, result.ReasonCodes)
		}
		if err := broker.Revalidate(ctx, "tenant", got.ID, now.Add(5*time.Hour)); err != nil {
			t.Fatal("completed sync left price validation blocked", err)
		}
	})
	clock := now
	slow := broker
	slow.Now = func() time.Time { return clock }
	slow.Archive = hookedArchive{archive, func() { clock = now.Add(time.Second) }}
	if e = slow.Revalidate(ctx, "tenant", got.ID, now.Add(500*time.Millisecond)); e == nil || e.Error() != "PRICE_EVIDENCE_EXPIRED_OR_UNSAFE" {
		t.Fatal("archive I/O crossed program horizon without final expiry check", e)
	}
	checks := 0
	lateLoad := broker
	lateLoad.Now = func() time.Time {
		checks++
		if checks >= 3 {
			return now.Add(time.Second)
		}
		return now
	}
	if e = lateLoad.Revalidate(ctx, "tenant", got.ID, now.Add(500*time.Millisecond)); e == nil || e.Error() != "PRICE_EVIDENCE_EXPIRED_OR_UNSAFE" {
		t.Fatal("database validation crossed program horizon without final expiry check", e)
	}
	// The final guard must serialize on the actual registration row. The graph
	// advisory key alone cannot stop SourceUpdate from revoking the source.
	held, e := pg.writer.Begin(ctx, "tenant")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = held.Exec(ctx, "SELECT fleet_billing_source_lock($1,$2)", "tenant", "source"); e != nil {
		held.Rollback(ctx)
		t.Fatal(e)
	}
	blocked := make(chan error, 1)
	go func() {
		blocked <- asRole(ctx, pg.admin, "tenant", "finops_api", func(tx *store.Tx) error {
			if _, e := tx.Exec(ctx, "SET LOCAL lock_timeout='200ms'"); e != nil {
				return e
			}
			r, e := tx.SourceGet(ctx, "source")
			if e != nil {
				return e
			}
			r["enabled"] = false
			_, e = tx.SourceUpdate(ctx, "source", model.Number(r, "version"), r)
			return e
		})
	}()
	blockedError := <-blocked
	_ = held.Rollback(ctx)
	var pgError *pgconn.PgError
	if !errors.As(blockedError, &pgError) || pgError.Code != "55P03" {
		t.Fatal("registration mutation did not wait for validation row lock", blockedError)
	}
	if e = broker.Revalidate(ctx, "tenant", got.ID, got.ValidUntil.Add(time.Second)); e == nil {
		t.Fatal("immutable price horizon silently extended")
	}
	if e := asRole(ctx, pg.admin, "tenant", "finops_api", func(tx *store.Tx) error {
		r, e := tx.Get(ctx, "resources", target.Binding.ResourceID)
		if e != nil {
			return e
		}
		r["currency"] = "GBP"
		_, e = tx.Update(ctx, "resources", target.Binding.ResourceID, model.Number(r, "version"), r)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	if result, e := broker.Capture(ctx, "tenant", target.Binding.ResourceID, 5*time.Hour); e != nil || result.Status != "UNAVAILABLE" || result.ReasonCodes[0] != "PRICE_RESOURCE_CURRENCY_MISMATCH" {
		t.Fatal("known resource currency ignored", result.ReasonCodes, e)
	}
	if e = broker.Revalidate(ctx, "tenant", got.ID, now.Add(5*time.Hour)); e == nil || e.Error() != "PRICE_RESOURCE_CURRENCY_MISMATCH" {
		t.Fatal("current known currency change ignored", e)
	}
	if e := asRole(ctx, pg.admin, "tenant", "finops_api", func(tx *store.Tx) error {
		r, e := tx.Get(ctx, "resources", target.Binding.ResourceID)
		if e != nil {
			return e
		}
		r["currency"] = "USD"
		_, e = tx.Update(ctx, "resources", target.Binding.ResourceID, model.Number(r, "version"), r)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	for hash, original := range archive {
		tampered := original
		tampered.Body = []byte("tampered pinned object")
		archive[hash] = tampered
		if e = broker.Revalidate(ctx, "tenant", got.ID, now.Add(5*time.Hour)); e == nil {
			t.Fatal("changed version-pinned native bytes accepted")
		}
		archive[hash] = original
		tampered = original
		tampered.VersionID = "different-version"
		archive[hash] = tampered
		if e = broker.Revalidate(ctx, "tenant", got.ID, now.Add(5*time.Hour)); e == nil || e.Error() != "PRICE_NATIVE_ARCHIVE_VERSION_MISMATCH" {
			t.Fatal("unobserved archive version accepted", e)
		}
		archive[hash] = original
		break
	}
	if e = broker.Revalidate(ctx, "tenant", got.ID, now.Add(5*time.Hour)); e != nil {
		t.Fatal("non-economic inventory update retired valid evidence", e)
	}
	if e := asRole(ctx, pg.admin, "tenant", "finops_api", func(tx *store.Tx) error {
		stored, e := Get(ctx, tx, got.ID)
		if e != nil || stored.ID != got.ID {
			return fmt.Errorf("API metadata read missing")
		}
		_, e = tx.Exec(ctx, "UPDATE fleet_billing_price_evidence SET document=document WHERE tenant_id=$1 AND id=$2", tx.Tenant, got.ID)
		return e
	}); e == nil {
		t.Fatal("API can mutate price evidence")
	}
	if e := pg.writer.Do(ctx, "other", func(tx *store.Tx) error { _, e := Get(ctx, tx, got.ID); return e }); e == nil {
		t.Fatal("cross-tenant immutable price visible")
	}
	if e := pg.writer.Do(ctx, "tenant", func(tx *store.Tx) error {
		forged := got
		forged.ID += "-forged"
		forged.ExecutionAuthorized = true
		return insert(ctx, tx, forged)
	}); e == nil {
		t.Fatal("price granted execution authority")
	}
	rawStored, _ := json.Marshal(got)
	for _, role := range []string{"finops_api", "finops_worker", "finops_signer", "finops_executor"} {
		if e := asRole(ctx, pg.admin, "tenant", role, func(tx *store.Tx) error {
			_, e := tx.Exec(ctx, `INSERT INTO fleet_billing_price_evidence(tenant_id,id,source_id,membership_receipt_id,templates_receipt_id,commitment_receipt_id,content_hash,document) VALUES($1,$2,'source','membership','templates','commitment',$3,$4)`, tx.Tenant, "forged-"+role, Hash(got), rawStored)
			return e
		}); e == nil {
			t.Fatal("non-ingester price writer", role)
		}
	}
	for name, mutate := range map[string]func(model.Document){"execution": func(d model.Document) { d["execution_authorized"] = true }, "saving": func(d model.Document) { d["verified_saving"] = "100" }, "future guarantee": func(d model.Document) { d["hard_spend_cap"] = true }, "changed source scope": func(d model.Document) {
		cfg := object(d["source_configuration"])
		cfg["read_role_binding_id"] = "other-binding"
		d["source_configuration"] = cfg
	}, "missing rate": func(d model.Document) {
		r := object(d["candidate"])
		delete(r, "observed_hourly_rate")
		d["candidate"] = r
	}} {
		t.Run(name, func(t *testing.T) {
			d := object(got)
			d["id"] = "forged-" + name
			mutate(d)
			raw, _ := json.Marshal(d)
			if e := pg.writer.Do(ctx, "tenant", func(tx *store.Tx) error {
				_, e := tx.Exec(ctx, `INSERT INTO fleet_billing_price_evidence(tenant_id,id,source_id,membership_receipt_id,templates_receipt_id,commitment_receipt_id,content_hash,document) VALUES($1,$2,'source','membership','templates','commitment',$3,$4)`, tx.Tenant, d["id"], Hash(d), raw)
				return e
			}); e == nil {
				t.Fatal("raw SQL bypassed private evidence contract")
			}
		})
	}
	if e := pg.writer.Do(ctx, "tenant", func(tx *store.Tx) error {
		var permitted bool
		if e := tx.QueryRow(ctx, `SELECT has_table_privilege(current_user,'signed_plans','INSERT') OR has_table_privilege(current_user,'provider_operations','UPDATE') OR has_table_privilege(current_user,'savings_ledger','INSERT')`).Scan(&permitted); e != nil {
			return e
		}
		if permitted {
			return fmt.Errorf("pricing reader acquired signing execution or financial write privilege")
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	// A full-payer global correction changes an existing baseline even though its
	// resource/region are outside the fleet. No immutable price row is rewritten.
	correction := append([]model.Document{}, periods[key]...)
	credit := model.Clone(correction[0])
	credit["identity_line_item_id"] = "global-credit"
	credit["line_item_resource_id"] = ""
	credit["line_item_usage_account_id"] = "444455556666"
	credit["product_region_code"] = ""
	credit["line_item_line_item_type"] = "Credit"
	credit["line_item_unblended_cost"] = "-1"
	correction = append(correction, credit)
	left, _ := time.Parse("2006-01", key)
	if e := pg.writer.Do(ctx, "tenant", func(tx *store.Tx) error {
		_, e := seedBillingJob(ctx, tx, reg, correction, left, end, "correction")
		return e
	}); e != nil {
		t.Fatal(e)
	}
	if e = broker.Revalidate(ctx, "tenant", got.ID, now.Add(5*time.Hour)); e == nil || e.Error() != "PRICE_PAYER_ECONOMIC_SCOPE_CHANGED" {
		t.Fatal("global correction left old evidence current", e)
	}
	if e := asRole(ctx, pg.admin, "tenant", "finops_api", func(tx *store.Tx) error {
		d, e := tx.SourceGet(ctx, "source")
		if e != nil {
			return e
		}
		d["enabled"] = false
		_, e = tx.SourceUpdate(ctx, "source", model.Number(d, "version"), d)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	if e = broker.Revalidate(ctx, "tenant", got.ID, now.Add(5*time.Hour)); e == nil {
		t.Fatal("revoked source still current")
	}
	if e = pg.writer.Do(ctx, "tenant", func(tx *store.Tx) error {
		stored, e := Get(ctx, tx, got.ID)
		if e == nil && stored.ID != got.ID {
			return fmt.Errorf("immutable historical evidence lost")
		}
		return e
	}); e != nil {
		t.Fatal(e)
	}
}
