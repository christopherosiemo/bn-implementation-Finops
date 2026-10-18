package source

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/provider"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type failingReader struct {
	*FixtureReader
	failed   bool
	versions []string
}

type historicalReader struct{ *FixtureReader }

type monthlyReader struct {
	*FixtureReader
	months     map[string]*FixtureReader
	latestOnly bool
	read       []string
	fail       string
}

func (f *monthlyReader) ListBillingExecutions(context.Context, string) ([]model.Document, error) {
	if f.latestOnly {
		return []model.Document{model.Clone(f.Execution)}, nil
	}
	out := []model.Document{}
	for _, r := range f.months {
		out = append(out, model.Clone(r.Execution))
	}
	return out, nil
}
func (f *monthlyReader) BillingExecution(ctx context.Context, arn, id string) (model.Document, error) {
	f.read = append(f.read, id)
	if f.fail == id {
		return nil, errors.New("native invoice source temporarily unavailable")
	}
	for _, r := range f.months {
		if model.String(r.Execution, "ExecutionId") == id {
			return r.BillingExecution(ctx, arn, id)
		}
	}
	return nil, errors.New("month execution unavailable")
}
func (f *monthlyReader) BillingManifestKeys(ctx context.Context, bucket, prefix, id string) ([]string, error) {
	for _, r := range f.months {
		if model.String(r.Execution, "ExecutionId") == id {
			return r.BillingManifestKeys(ctx, bucket, prefix, id)
		}
	}
	return nil, errors.New("month manifest unavailable")
}
func (f *monthlyReader) BillingObject(ctx context.Context, bucket, key, version string) (provider.BillingObject, error) {
	for _, r := range f.months {
		if _, ok := r.Objects[key]; ok {
			return r.BillingObject(ctx, bucket, key, version)
		}
	}
	return provider.BillingObject{}, errors.New("month object unavailable")
}
func (f *monthlyReader) BillingInvoices(ctx context.Context, payer string, year, month int) ([]model.Document, error) {
	r, ok := f.months[fmt.Sprintf("%04d-%02d", year, month)]
	if !ok {
		return nil, errors.New("month invoice unavailable")
	}
	return r.BillingInvoices(ctx, payer, year, month)
}

func renameFixtureExecution(f *FixtureReader, id string) {
	old := model.String(f.Execution, "ExecutionId")
	objects := map[string]provider.BillingObject{}
	for key, o := range f.Objects {
		o.Key = strings.ReplaceAll(key, old, id)
		if strings.HasSuffix(key, "Manifest.json") {
			o.Data = []byte(strings.ReplaceAll(string(o.Data), old, id))
			o.VersionID = "v1-" + BytesHash(o.Data)
			o.ETag = BytesHash(o.Data)
		}
		objects[o.Key] = o
	}
	f.Objects = objects
	for i, key := range f.ManifestKeys {
		f.ManifestKeys[i] = strings.ReplaceAll(key, old, id)
	}
	f.Execution["ExecutionId"] = id
}

func (f *historicalReader) BillingManifestKeys(_ context.Context, bucket, prefix, execution string) ([]string, error) {
	return []string{strings.ReplaceAll(f.ManifestKeys[0], "fixture-delivery", execution)}, nil
}
func (f *historicalReader) BillingObject(ctx context.Context, bucket, key, version string) (provider.BillingObject, error) {
	original := key
	for _, x := range f.Executions {
		key = strings.ReplaceAll(key, model.String(x, "ExecutionId"), "fixture-delivery")
	}
	o, e := f.FixtureReader.BillingObject(ctx, bucket, key, "")
	if e != nil {
		return o, e
	}
	o.Key = original
	if strings.HasSuffix(key, "Manifest.json") {
		for _, x := range f.Executions {
			if strings.Contains(original, "-"+model.String(x, "ExecutionId")+"/") {
				o.Data = []byte(strings.ReplaceAll(string(o.Data), "fixture-delivery", model.String(x, "ExecutionId")))
				created, _ := time.Parse(time.RFC3339, model.String(Object(x["ExecutionStatus"]), "CreatedAt"))
				o.LastModified = created.Add(time.Minute)
				break
			}
		}
	}
	o.VersionID = "v1-" + BytesHash(o.Data)
	if version != "" && version != o.VersionID {
		return o, errors.New("wrong history pin")
	}
	return o, nil
}

func (f *failingReader) BillingObject(ctx context.Context, bucket, key, version string) (provider.BillingObject, error) {
	f.versions = append(f.versions, key+"@"+version)
	if strings.Contains(key, "part-001") && !f.failed {
		f.failed = true
		return provider.BillingObject{}, errors.New("transient read failure")
	}
	return f.FixtureReader.BillingObject(ctx, bucket, key, version)
}

func TestTrustedPipelineResumesPinnedChunksAndRevisesNativeCancellation(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL requires a disposable administrator database")
	}
	ctx := context.Background()
	admin, e := store.Open(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer admin.Pool.Close()
	if e = admin.Migrate(ctx, "../../migrations"); e != nil {
		t.Fatal(e)
	}
	tenant := "source-" + model.ID()
	d := FixtureRegistration(tenant, "connection")
	r, e := ParseRegistration(d)
	if e != nil {
		t.Fatal(e)
	}
	if e = admin.Do(ctx, tenant, func(tx *store.Tx) error {
		if _, e := tx.Exec(ctx, "SET LOCAL ROLE finops_api"); e != nil {
			return e
		}
		_, e := tx.SourceCreate(ctx, d)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	config, e := pgxpool.ParseConfig(dsn)
	if e != nil {
		t.Fatal(e)
	}
	config.AfterConnect = func(ctx context.Context, c *pgx.Conn) error {
		_, e := c.Exec(ctx, "SET ROLE finops_ingester")
		return e
	}
	pool, e := pgxpool.NewWithConfig(ctx, config)
	if e != nil {
		t.Fatal(e)
	}
	defer pool.Close()
	ingest := &store.Store{Pool: pool}
	reader, e := NewFixtureReader(r, nil)
	if e != nil {
		t.Fatal(e)
	}
	flaky := &failingReader{FixtureReader: reader}
	archives := map[string]string{}
	persisted := 0
	clock := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	p := Pipeline{Store: ingest, ProviderFactory: func(context.Context, Registration) (Reader, error) { return flaky, nil }, Normalize: func(_ context.Context, raw model.Document) (model.Document, error) {
		return model.Document{"records": raw["records"], "totals": model.Document{"GBP": "340.440000000000"}}, nil
	}, ArchiveObject: func(_ context.Context, tenant, source, key string, b []byte) error {
		archives[key] = BytesHash(b)
		return nil
	}, Persist: func(_ context.Context, tenant, source string, raw, canonical model.Document) error {
		persisted++
		return nil
	}, Now: func() time.Time { return clock }}
	if e = p.Sync(ctx, tenant, r.ID); e == nil {
		t.Fatal("partial delivery published")
	}
	if persisted != 0 {
		t.Fatal("partial delivery persisted canonical evidence")
	}
	if e = ingest.Do(ctx, tenant, func(tx *store.Tx) error {
		rs, e := tx.SourceReceiptList(ctx, "AWS_CUR2", r.ID)
		if len(rs) != 0 {
			t.Fatal("partial receipt published")
		}
		status, e2 := tx.SourceGet(ctx, r.ID)
		if e2 != nil {
			return e2
		}
		if status["status"] != "DEGRADED" {
			t.Fatalf("missing visible failure: %#v", status)
		}
		return e
	}); e != nil {
		t.Fatal(e)
	}
	if e = p.Sync(ctx, tenant, r.ID); e != nil {
		t.Fatal(e)
	}
	var first model.Document
	if e = ingest.Do(ctx, tenant, func(tx *store.Tx) error {
		rs, e := tx.SourceReceiptList(ctx, "AWS_CUR2", r.ID)
		if e != nil {
			return e
		}
		if len(rs) != 1 {
			t.Fatalf("want one receipt, got %d", len(rs))
		}
		first = rs[0]
		if first["writer_role"] != "finops_ingester" {
			t.Fatal("writer role did not come from database")
		}
		proof := Object(first["source_proof"])
		if proof["state"] != "FINAL" || model.Number(proof, "verified_object_count") != 2 || model.Number(proof, "verified_row_count") != 710 {
			t.Fatalf("invalid whole-delivery proof: %#v", proof)
		}
		job, e := tx.Get(ctx, "ingestion_jobs", model.String(first, "ingestion_job_id"))
		if e != nil {
			return e
		}
		if job["status"] != "PERSISTED" || Hash(job["raw"]) != first["raw_hash"] || Hash(job["canonical"]) != first["canonical_hash"] {
			t.Fatal("receipt not bound to persisted source")
		}
		s, e := tx.SourceGet(ctx, r.ID)
		if e != nil {
			return e
		}
		if s["status"] != "HEALTHY" || s["latest_receipt_id"] != first["id"] {
			t.Fatal("checkpoint status missing from API projection")
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	pinned := false
	for _, read := range flaky.versions {
		if strings.Contains(read, "part-000.csv.gz@v1-") {
			pinned = true
		}
	}
	if !pinned {
		t.Fatal("resume did not pin previously read version")
	}
	if len(archives) < 5 || persisted != 1 {
		t.Fatalf("raw evidence not archived or persisted wrong count: %d/%d", len(archives), persisted)
	}
	// Normal minute refresh changes only commitment freshness, not financial
	// revision identity. Native invoice cancellation must append a new revision.
	clock = clock.Add(time.Minute)
	if e = p.Sync(ctx, tenant, r.ID); e != nil {
		t.Fatal(e)
	}
	if persisted != 1 {
		t.Fatal("unchanged delivery produced another financial revision")
	}
	reader.Invoices[0]["TaxAuthorityStatus"] = "CANCELLED"
	clock = clock.Add(time.Minute)
	if e = p.Sync(ctx, tenant, r.ID); e != nil {
		t.Fatal(e)
	}
	if e = ingest.Do(ctx, tenant, func(tx *store.Tx) error {
		rs, e := tx.SourceReceiptList(ctx, "AWS_CUR2", r.ID)
		if len(rs) != 2 || rs[0]["id"] == rs[1]["id"] {
			t.Fatal("native invoice correction did not append a new receipt")
		}
		if e != nil {
			return e
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	if persisted != 2 {
		t.Fatal("new native invoice state did not bind new immutable job")
	}
	reader.Invoices[0]["TaxAuthorityStatus"] = "ISSUED"
	clock = clock.Add(time.Minute)
	if e = p.Sync(ctx, tenant, r.ID); e != nil {
		t.Fatal(e)
	}
	if e = ingest.Do(ctx, tenant, func(tx *store.Tx) error {
		rs, e := tx.SourceReceiptList(ctx, "AWS_CUR2", r.ID)
		if e != nil {
			return e
		}
		if len(rs) != 3 {
			t.Fatalf("revived native authority must append a third receipt, got %d", len(rs))
		}
		if rs[2]["id"] == rs[0]["id"] || rs[2]["content_hash"] != rs[0]["content_hash"] || rs[2]["previous_receipt_id"] != rs[1]["id"] {
			t.Fatal("revived content did not retain a new observation after cancellation")
		}
		s, e := tx.SourceGet(ctx, r.ID)
		if e != nil {
			return e
		}
		if s["latest_receipt_id"] != rs[2]["id"] {
			t.Fatal("revived invoice not selected as current authority")
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	clock = clock.Add(time.Minute)
	if e = p.Sync(ctx, tenant, r.ID); e != nil {
		t.Fatal(e)
	}
	if persisted != 3 {
		t.Fatal("revival lost or unchanged fourth poll created a new revision")
	}
	for _, role := range []string{"finops_api", "finops_worker", "finops_signer", "finops_executor"} {
		e = admin.Do(ctx, tenant, func(tx *store.Tx) error {
			if _, e := tx.Exec(ctx, "SET LOCAL ROLE "+role); e != nil {
				return e
			}
			_, e := tx.SourceReceiptCreate(ctx, model.Document{"id": model.ID(), "source_id": r.ID, "kind": "AWS_CUR2", "trusted": true})
			return e
		})
		if e == nil {
			t.Fatalf("%s forged source authority", role)
		}
	}
	if e = admin.Do(ctx, tenant, func(tx *store.Tx) error {
		_, e := tx.Exec(ctx, "UPDATE source_receipts SET document=document||'{\"forged\":true}'::jsonb WHERE tenant_id=$1", tenant)
		return e
	}); e == nil {
		t.Fatal("immutable source history rewritten")
	}
	if e = admin.Do(ctx, "other-"+tenant, func(tx *store.Tx) error {
		if _, e := tx.Exec(ctx, "SET LOCAL ROLE finops_api"); e != nil {
			return e
		}
		rs, e := tx.SourceReceiptList(ctx, "AWS_CUR2", r.ID)
		if len(rs) != 0 {
			t.Fatal("cross tenant receipt leaked")
		}
		return e
	}); e != nil {
		t.Fatal(e)
	}
	if e = admin.Do(ctx, tenant, func(tx *store.Tx) error {
		s, e := tx.SourceGet(ctx, r.ID)
		if e != nil {
			return e
		}
		s["enabled"] = false
		_, e = tx.SourceUpdate(ctx, r.ID, model.Number(s, "version"), s)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	if e = p.Sync(ctx, tenant, r.ID); e == nil {
		t.Fatal("revoked source synced")
	}
	// Fresh installation may need an earlier month even when many daily export
	// executions precede it. Work is bounded and resumes without rolling a newer
	// month's source authority backwards to an older execution.
	d2 := FixtureRegistration(tenant, "history-connection")
	r2, _ := ParseRegistration(d2)
	if e = admin.Do(ctx, tenant, func(tx *store.Tx) error { _, e := tx.SourceCreate(ctx, d2); return e }); e != nil {
		t.Fatal(e)
	}
	base, e := NewFixtureReader(r2, FixtureBillingRows(r2, "i-history")[:1])
	if e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 70; i++ {
		x := model.Clone(base.Execution)
		x["ExecutionId"] = fmt.Sprintf("delivery-%03d", i)
		x["ExecutionStatus"] = model.Document{"StatusCode": "DELIVERY_SUCCESS", "CreatedAt": time.Date(2026, 10, 1, 1, i, 0, 0, time.UTC).Format(time.RFC3339)}
		base.Executions = append(base.Executions, x)
	}
	many := &historicalReader{FixtureReader: base}
	p.ProviderFactory = func(context.Context, Registration) (Reader, error) { return many, nil }
	before := persisted
	if e = p.Sync(ctx, tenant, r2.ID); e != nil {
		t.Fatal(e)
	}
	if e = ingest.Do(ctx, tenant, func(tx *store.Tx) error {
		s, e := tx.SourceGet(ctx, r2.ID)
		if model.Number(s, "backfill_pending") != 6 {
			t.Fatalf("unbounded or lost history cursor: %#v", s)
		}
		return e
	}); e != nil {
		t.Fatal(e)
	}
	if e = p.Sync(ctx, tenant, r2.ID); e != nil {
		t.Fatal(e)
	}
	if e = ingest.Do(ctx, tenant, func(tx *store.Tx) error {
		s, e := tx.SourceGet(ctx, r2.ID)
		if e != nil {
			return e
		}
		if model.Number(s, "backfill_pending") != 0 {
			t.Fatal("history did not resume")
		}
		rs, e := tx.SourceReceiptList(ctx, "AWS_CUR2", r2.ID)
		if e != nil {
			return e
		}
		if len(rs) != 1 || model.String(rs[0], "execution_id") != "delivery-069" {
			t.Fatal("older backfill replaced newest monthly authority")
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	if persisted != before+1 {
		t.Fatal("old same-month executions generated duplicate financial revisions")
	}
	// Known old month heads rotate in durable batches even if the provider no
	// longer includes them in the current ListExecutions page set.
	d3 := FixtureRegistration(tenant, "rotating-history")
	r3, _ := ParseRegistration(d3)
	if e = admin.Do(ctx, tenant, func(tx *store.Tx) error { _, e := tx.SourceCreate(ctx, d3); return e }); e != nil {
		t.Fatal(e)
	}
	months := map[string]*FixtureReader{}
	for _, month := range []string{"2025-01", "2025-02", "2025-03", "2025-04", "2025-05", "2026-09"} {
		at, _ := time.Parse("2006-01", month)
		row := model.Clone(FixtureBillingRows(r3, "i-rotating")[0])
		row["identity_line_item_id"] = month
		row["line_item_usage_start_date"], row["line_item_usage_end_date"] = at.Format(time.RFC3339), at.Add(time.Hour).Format(time.RFC3339)
		f, e := fixtureReaderForPeriod(r3, []model.Document{row}, at)
		if e != nil {
			t.Fatal(e)
		}
		renameFixtureExecution(f, "month-"+month)
		months[month] = f
	}
	rotating := &monthlyReader{FixtureReader: months["2026-09"], months: months}
	p.ProviderFactory = func(context.Context, Registration) (Reader, error) { return rotating, nil }
	if e = p.Sync(ctx, tenant, r3.ID); e != nil {
		t.Fatal(e)
	}
	rotating.latestOnly = true
	rotating.read = nil
	months["2025-05"].Invoices[0]["TaxAuthorityStatus"] = "CANCELLED"
	if e = p.Sync(ctx, tenant, r3.ID); e != nil {
		t.Fatal(e)
	}
	if len(rotating.read) != 5 {
		t.Fatalf("rotation must read newest plus four older heads, got %v", rotating.read)
	}
	historyKey := "history:" + ConfigurationHash(d3)
	if e = ingest.Do(ctx, tenant, func(tx *store.Tx) error {
		h, e := tx.SourceCheckpointGet(ctx, r3.ID, historyKey)
		if model.String(h, "older_month_cursor") != "2025-04" {
			t.Fatal("rotation cursor not persisted")
		}
		return e
	}); e != nil {
		t.Fatal(e)
	}
	// Simulate a restarted ingester and a failed next batch. Failure must not
	// advance the cursor past the month whose cancellation remains unread.
	restarted := p
	rotating.read = nil
	rotating.fail = "month-2025-05"
	if e = restarted.Sync(ctx, tenant, r3.ID); e == nil {
		t.Fatal("failed old source refresh reported success")
	}
	if e = ingest.Do(ctx, tenant, func(tx *store.Tx) error {
		h, e := tx.SourceCheckpointGet(ctx, r3.ID, historyKey)
		if model.String(h, "older_month_cursor") != "2025-04" {
			t.Fatal("failed rotation skipped an old month")
		}
		return e
	}); e != nil {
		t.Fatal(e)
	}
	rotating.fail = ""
	rotating.read = nil
	if e = restarted.Sync(ctx, tenant, r3.ID); e != nil {
		t.Fatal(e)
	}
	if len(rotating.read) != 5 {
		t.Fatalf("resumed rotation exceeded batch limit: %v", rotating.read)
	}
	if e = ingest.Do(ctx, tenant, func(tx *store.Tx) error {
		h, e := tx.SourceCheckpointGet(ctx, r3.ID, historyKey)
		if e != nil {
			return e
		}
		if model.String(h, "older_month_cursor") != "2025-03" {
			t.Fatal("older rotation failed to wrap")
		}
		rs, e := tx.SourceReceiptList(ctx, "AWS_CUR2", r3.ID)
		if e != nil {
			return e
		}
		old := []model.Document{}
		for _, receipt := range rs {
			if model.String(Object(receipt["source_proof"]), "billing_period_start") == "2025-05-01T00:00:00Z" {
				old = append(old, receipt)
			}
		}
		if len(old) != 2 || model.String(Object(Rows(old[1]["invoices"])[0]["native"]), "TaxAuthorityStatus") != "CANCELLED" {
			t.Fatal("old-month cancellation did not append current authority")
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
}
