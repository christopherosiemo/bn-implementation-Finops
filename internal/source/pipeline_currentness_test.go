package source

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestSuccessfulExecutionsUseInstantsWithoutMutatingNativeReferences(t *testing.T) {
	x := func(id, created string) model.Document {
		return model.Document{"ExecutionId": id, "ExecutionStatus": model.Document{"StatusCode": "DELIVERY_SUCCESS", "CreatedAt": created}}
	}
	in := []model.Document{x("whole-second", "2026-10-01T01:00:00Z"), x("fractional-newer", "2026-10-01T01:00:00.1Z"), x("offset-equal", "2026-10-01T02:00:00.100+01:00")}
	before := Hash(in)
	out, err := successfulExecutionOrder(in, time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC))
	if err != nil || len(out) != 3 || model.String(out[0], "ExecutionId") != "fractional-newer" || model.String(out[1], "ExecutionId") != "offset-equal" || model.String(out[2], "ExecutionId") != "whole-second" || Hash(in) != before {
		t.Fatal("native timestamps were lexically ordered or mutated", err)
	}
	for _, invalid := range []string{"", "not-an-instant", "2026-10-03T01:00:00Z"} {
		if _, err = successfulExecutionOrder([]model.Document{x("invalid", invalid)}, time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)); err == nil {
			t.Fatal("unknown/future native execution time was ordered")
		}
	}
}

func TestTrustedPipelineNativeCurrentnessAndDurableAmbiguity(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL requires a disposable administrator database")
	}
	ctx := context.Background()
	admin, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Pool.Close()
	if err = admin.Migrate(ctx, "../../migrations"); err != nil {
		t.Fatal(err)
	}
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	config.AfterConnect = func(ctx context.Context, c *pgx.Conn) error {
		_, err := c.Exec(ctx, "SET ROLE finops_ingester")
		return err
	}
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	ingester := &store.Store{Pool: pool}
	now := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)

	for _, scenario := range []string{"fractional-newer", "equal-native-instant"} {
		t.Run(scenario, func(t *testing.T) {
			tenant := "native-order-" + model.ID()
			d := FixtureRegistration(tenant, "connection")
			r, err := ParseRegistration(d)
			if err != nil {
				t.Fatal(err)
			}
			if err = admin.Do(ctx, tenant, func(tx *store.Tx) error {
				if _, err := tx.Exec(ctx, "SET LOCAL ROLE finops_api"); err != nil {
					return err
				}
				_, err := tx.SourceCreate(ctx, d)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			fixture := func(id, instant, cost string) *FixtureReader {
				t.Helper()
				rows := FixtureBillingRows(r, "i-order")[:1]
				rows[0]["line_item_unblended_cost"] = cost
				f, err := NewFixtureReader(r, rows)
				if err != nil {
					t.Fatal(err)
				}
				renameFixtureExecution(f, id)
				status := Object(f.Execution["ExecutionStatus"])
				status["CreatedAt"] = instant
				f.Execution["ExecutionStatus"] = status
				return f
			}
			old := fixture("z-old", "2026-09-30T23:59:00Z", "1.00")
			second := fixture("a-second", "2026-09-30T23:59:00.1Z", "2.00")
			reader := &monthlyReader{FixtureReader: old, latestOnly: true, months: map[string]*FixtureReader{"2026-09": old, "second": second}}
			persisted := 0
			pipeline := Pipeline{Store: ingester, ProviderFactory: func(context.Context, Registration) (Reader, error) { return reader, nil }, Normalize: func(_ context.Context, raw model.Document) (model.Document, error) {
				return model.Document{"records": raw["records"]}, nil
			}, Persist: func(context.Context, string, string, model.Document, model.Document) error { persisted++; return nil }, ArchiveObject: func(context.Context, string, string, string, []byte) error { return nil }, Now: func() time.Time { return now }}
			if err = pipeline.Sync(ctx, tenant, r.ID); err != nil {
				t.Fatal(err)
			}
			read := func() ([]model.Document, model.Document, model.Document) {
				t.Helper()
				var receipts []model.Document
				var status, head model.Document
				if err := ingester.Do(ctx, tenant, func(tx *store.Tx) error {
					var err error
					receipts, err = tx.SourceReceiptList(ctx, "AWS_CUR2", r.ID)
					if err != nil {
						return err
					}
					status, err = tx.SourceGet(ctx, r.ID)
					if err != nil {
						return err
					}
					head, err = tx.SourceCheckpointGet(ctx, r.ID, "month:"+ConfigurationHash(d)+":2026-09")
					return err
				}); err != nil {
					t.Fatal(err)
				}
				return receipts, status, head
			}
			before, _, head := read()
			oldReceipt := model.String(head, "receipt_id")
			if len(before) != 1 || persisted != 1 {
				t.Fatal("initial native delivery missing")
			}
			reader.FixtureReader = second
			reader.months["2026-09"] = second
			reader.months["old"] = old
			if scenario == "fractional-newer" {
				reader.latestOnly = false
				reader.read = nil
				if err = pipeline.Sync(ctx, tenant, r.ID); err != nil {
					t.Fatal(err)
				}
				receipts, status, head := read()
				if len(receipts) != 2 || persisted != 2 || len(reader.read) == 0 || reader.read[0] != "a-second" || model.String(head, "execution_id") != "a-second" || status["status"] != "HEALTHY" {
					t.Fatal("fractional later instant failed to replace whole-second source")
				}
				reader.FixtureReader = old
				reader.latestOnly = true
				if err = pipeline.Sync(ctx, tenant, r.ID); err != nil {
					t.Fatal(err)
				}
				receipts, _, head = read()
				if len(receipts) != 2 || model.String(head, "execution_id") != "a-second" || persisted != 2 {
					t.Fatal("late older native delivery regressed current head")
				}
				return
			}
			// Different representation, same instant; an opaque ID cannot choose
			// which native execution's different bill should be current.
			secondStatus := Object(second.Execution["ExecutionStatus"])
			secondStatus["CreatedAt"] = "2026-10-01T00:59:00.000+01:00"
			second.Execution["ExecutionStatus"] = secondStatus
			// Call the delivery boundary without Sync's deferred health writer:
			// refusal and BLOCKED projection must already be durable together.
			if _, err = pipeline.delivery(ctx, r, d, reader, second.Execution, "fixture-cur2", "a-second", second.ManifestKeys[0], FixtureBucketPolicy(r), second.Commitments, map[string][]model.Document{}); err == nil || err.Error() != executionOrderAmbiguous {
				t.Fatal("direct delivery did not durably reject ambiguous head", err)
			}
			_, atomicStatus, _ := read()
			if atomicStatus["status"] != "BLOCKED" || atomicStatus["reason_code"] != executionOrderAmbiguous {
				t.Fatal("source stayed healthy until an outer deferred writer ran")
			}
			if err = pipeline.Sync(ctx, tenant, r.ID); err == nil || err.Error() != executionOrderAmbiguous {
				t.Fatal("equal native time accepted arbitrary economic ordering", err)
			}
			receipts, status, head := read()
			if len(receipts) != 1 || persisted != 1 || model.String(head, "receipt_id") != oldReceipt || model.String(head, "ambiguous_at") == "" || status["status"] != "BLOCKED" || status["reason_code"] != executionOrderAmbiguous {
				t.Fatal("ambiguity published a head or left old source healthy")
			}
			reader.FixtureReader = old // Native list omission is not resolution.
			if err = pipeline.Sync(ctx, tenant, r.ID); err == nil || err.Error() != executionOrderAmbiguous {
				t.Fatal("omitted conflict refreshed earlier receipt", err)
			}
			later := fixture("later-resolution", "2026-09-30T23:59:00.2Z", "3.00")
			reader.FixtureReader = later
			reader.months["2026-09"] = later
			reader.months["later"] = later
			if err = pipeline.Sync(ctx, tenant, r.ID); err != nil {
				t.Fatal("strictly later native execution did not resolve ambiguity", err)
			}
			receipts, status, head = read()
			if len(receipts) != 2 || persisted != 2 || model.String(head, "execution_id") != "later-resolution" || head["ambiguous_at"] != nil || status["status"] != "HEALTHY" {
				t.Fatal("later resolution failed to append or clear exact-month ambiguity")
			}
			if model.String(receipts[0], "id") != oldReceipt {
				t.Fatal("old immutable native receipt was rewritten")
			}
			later.Invoices[0]["TaxAuthorityStatus"] = "CANCELLED"
			if err = pipeline.Sync(ctx, tenant, r.ID); err != nil {
				t.Fatal("same execution invoice correction blocked", err)
			}
			receipts, _, _ = read()
			if len(receipts) != 3 || persisted != 3 {
				t.Fatal("native invoice correction did not append")
			}
			if err = pipeline.Sync(ctx, tenant, r.ID); err != nil {
				t.Fatal(err)
			}
			receipts, _, _ = read()
			if len(receipts) != 3 || persisted != 3 {
				t.Fatal("same execution exact replay duplicated correction")
			}
		})
	}
}
