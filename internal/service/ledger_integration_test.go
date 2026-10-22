package service

import (
	"context"
	"encoding/json"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/jackc/pgx/v5"
	"math/big"
	"os"
	"testing"
	"time"
)

func TestSavingsCurrentProjectionRetiresVerifiedAndProvisionalHeads(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("disposable PostgreSQL required")
	}
	ctx := context.Background()
	db, e := store.Open(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Pool.Close()
	if e = db.Migrate(ctx, "../../migrations"); e != nil {
		t.Fatal(e)
	}
	tenant := "ledger-" + model.ID()
	do := func(fn func(*store.Tx) error) error {
		return db.Do(ctx, tenant, func(tx *store.Tx) error {
			if _, e := tx.Exec(ctx, "SET LOCAL ROLE finops_api"); e != nil {
				return e
			}
			return fn(tx)
		})
	}
	appendRevision := func(id, key, measurement, status string, at time.Time) model.Document {
		t.Helper()
		d := model.Document{"id": id, "resource_id": "resource", "measurement_id": measurement, "status": status, "fingerprint": id, "attribution_key": key, "claim_key": key, "verified_saving": nil}
		if status == "VERIFIED" {
			d["verified_saving"] = "5.160000000000"
		}
		if e := do(func(tx *store.Tx) error {
			prior, _, e := previousSavingsRevision(ctx, tx, key, measurement)
			if e == nil {
				d["supersedes_id"] = prior
			} else if e != pgx.ErrNoRows {
				return e
			}
			b, _ := json.Marshal(d)
			_, e = tx.Exec(ctx, "INSERT INTO savings_ledger(tenant_id,id,execution_id,fingerprint,document,created_at) VALUES($1,$2,$3,$4,$5,$6)", tenant, id, measurement, id, b, at)
			return e
		}); e != nil {
			t.Fatal(e)
		}
		return d
	}
	at := time.Now().UTC()
	a := appendRevision(model.ID(), "same-financial-period", "measurement-A", "VERIFIED", at)
	pending := appendRevision(model.ID(), "empty-coverage", "measurement-B", "MEASURING", at.Add(time.Second))
	b := appendRevision(model.ID(), "same-financial-period", "measurement-B", "VERIFIED", at.Add(2*time.Second))
	if model.String(pending, "supersedes_id") != "" {
		t.Fatal("new measurement provisional replaced prior financial claim")
	}
	if model.String(b, "supersedes_id") != model.String(a, "id") {
		t.Fatal("new verified result superseded provisional instead of exact prior financial claim")
	}
	if e := do(func(tx *store.Tx) error {
		rows, e := tx.Evidence(ctx, "savings_ledger")
		if e != nil {
			return e
		}
		if len(rows) != 3 {
			t.Fatalf("immutablehistory count=%d", len(rows))
		}
		currentVerified := 0
		total := new(big.Rat)
		for _, row := range rows {
			if model.Bool(row, "is_current") {
				if model.String(row, "id") == model.String(pending, "id") {
					t.Fatal("provisional head remained current after final same measurement")
				}
				if model.String(row, "status") == "VERIFIED" {
					currentVerified++
					value, _ := new(big.Rat).SetString(model.String(row, "verified_saving"))
					total.Add(total, value)
				}
			}
		}
		expected, _ := new(big.Rat).SetString("5.16")
		if currentVerified != 1 || total.Cmp(expected) != 0 {
			t.Fatalf("duplicateverifiedclaims count=%d total=%s", currentVerified, total.RatString())
		}
		var old []byte
		if e = tx.QueryRow(ctx, "SELECT document FROM savings_ledger WHERE tenant_id=$1 AND id=$2", tenant, a["id"]).Scan(&old); e != nil {
			return e
		}
		var original model.Document
		_ = json.Unmarshal(old, &original)
		if model.String(original, "supersedes_id") != "" {
			t.Fatal("oldimmutablehistoryrewritten")
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	correction := appendRevision(model.ID(), "same-financial-period", "measurement-B", "MEASURING", at.Add(3*time.Second))
	if model.String(correction, "supersedes_id") != model.String(b, "id") {
		t.Fatal("provisional correction did not retire prior exact claim")
	}
	if e := do(func(tx *store.Tx) error {
		rows, e := tx.Evidence(ctx, "savings_ledger")
		if e != nil {
			return e
		}
		for _, row := range rows {
			if model.String(row, "id") == model.String(correction, "id") && !model.Bool(row, "is_current") {
				t.Fatal("older verified result hid newer provisional correction")
			}
			if model.String(row, "id") == model.String(pending, "id") && model.Bool(row, "is_current") {
				t.Fatal("retired pending revision resurfaced")
			}
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
}
