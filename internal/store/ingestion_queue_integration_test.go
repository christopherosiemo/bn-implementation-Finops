package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
)

func newIngestionQueueTest(t *testing.T) *fleetHistoryDBTest {
	t.Helper()
	f := newFleetHistoryDBTest(t)
	applyIngestionQueueMigrations(t, f, "003_immutable_readiness.sql", "004_owned_receipt_ingestion.sql", "028_ingestion_queue.sql")
	return f
}

func applyIngestionQueueMigrations(t *testing.T, f *fleetHistoryDBTest, names ...string) {
	t.Helper()
	dir := t.TempDir()
	for _, name := range names {
		raw, err := os.ReadFile(filepath.Join("..", "..", "migrations", name))
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(dir, name), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.admin.Migrate(f.ctx, dir); err != nil {
		t.Fatal(err)
	}
}

func queueIDs(items []IngestionQueueItem) []string {
	ids := []string{}
	for _, item := range items {
		ids = append(ids, model.String(item.Job, "id"))
	}
	return ids
}

func TestIngestionQueueOmitsLargeSealedHistoryButKeepsAllRetryAndSealWork(t *testing.T) {
	f := newIngestionQueueTest(t)
	large := strings.Repeat("retained-immutable-billing-payload/", 8192)
	wantLive := []string{}
	wantFixture := []string{}
	f.must("finops_ingester", func(tx *Tx) error {
		for i := 0; i < 24; i++ {
			for _, kind := range []string{"ordinary", "baseline", "measurement"} {
				id := fmt.Sprintf("old-generation-%s-%03d", kind, i)
				d := model.Document{"id": id, "status": "PERSISTED", "raw": model.Document{"payload": large}, "canonical": model.Document{"payload": large}}
				if kind == "baseline" {
					d["fixture_baseline"] = model.Document{}
				}
				if kind == "measurement" {
					d["fixture_measurement"] = model.Document{"measurement_id": id}
				}
				if _, err := tx.Create(f.ctx, "ingestion_jobs", d); err != nil {
					return err
				}
				if kind != "ordinary" {
					evidenceKind, evidenceID := "baseline", id
					if kind == "measurement" {
						evidenceKind, evidenceID = "measurement_snapshot", "fixture-snapshot-"+id
					}
					if _, err := tx.EvidenceCreate(f.ctx, evidenceKind, model.Document{"id": evidenceID, "resource_id": "fixture-only-selection"}); err != nil {
						return err
					}
				}
			}
		}
		for i, status := range []any{"PENDING", "FAILED", "RETRYING", "unknown", "persisted", nil, 7, true, model.Document{"unexpected": "shape"}, []string{"PERSISTED"}} {
			id := fmt.Sprintf("retry-%02d", i)
			if _, err := tx.Create(f.ctx, "ingestion_jobs", model.Document{"id": id, "status": status, "canonical": model.Document{"marker": "preserve me"}}); err != nil {
				return err
			}
			wantLive = append(wantLive, id)
		}
		if _, err := tx.Create(f.ctx, "ingestion_jobs", model.Document{"id": "retry-missing"}); err != nil {
			return err
		}
		wantLive = append(wantLive, "retry-missing")
		for _, d := range []model.Document{
			{"id": "unsealed-old-baseline", "status": "PERSISTED", "fixture_baseline": model.Document{}},
			{"id": "unsealed-null-baseline", "status": "PERSISTED", "fixture_baseline": nil},
			{"id": "unsealed-old-measurement", "status": "PERSISTED", "fixture_measurement": model.Document{"measurement_id": "previous-generation"}},
			{"id": "unsealed-null-measurement", "status": "PERSISTED", "fixture_measurement": nil},
			{"id": "unsealed-numeric-measurement-id", "status": "PERSISTED", "fixture_measurement": model.Document{"measurement_id": 7}},
		} {
			if _, err := tx.Create(f.ctx, "ingestion_jobs", d); err != nil {
				return err
			}
			wantFixture = append(wantFixture, model.String(d, "id"))
		}
		// Existing behavior checks baseline first and returns once it is sealed,
		// even when a second fixture metadata key is present and unfinished.
		if _, err := tx.Create(f.ctx, "ingestion_jobs", model.Document{"id": "both-keys", "status": "PERSISTED", "fixture_baseline": nil, "fixture_measurement": model.Document{"measurement_id": "not-sealed"}}); err != nil {
			return err
		}
		_, err := tx.EvidenceCreate(f.ctx, "baseline", model.Document{"id": "both-keys", "resource_id": "fixture-only-selection"})
		return err
	})
	wantFixture = append(wantFixture, wantLive...)
	sort.Strings(wantFixture)
	sort.Strings(wantLive)
	f.must("finops_ingester", func(tx *Tx) error {
		for _, check := range []struct {
			id   string
			want bool
		}{{"old-generation-baseline-000", true}, {"unsealed-old-baseline", true}, {"missing-job", false}} {
			exists, err := tx.IngestionJobExists(f.ctx, check.id)
			if err != nil || exists != check.want {
				return fmt.Errorf("existence-only check changed behavior: %v", err)
			}
		}
		started := time.Now()
		history, err := tx.List(f.ctx, "ingestion_jobs")
		if err != nil {
			return err
		}
		oldJSON, _ := json.Marshal(history)
		oldElapsed := time.Since(started)
		cutoff, err := tx.IngestionQueueCutoff(f.ctx)
		if err != nil {
			return err
		}
		if os.Getenv("TEST_INGESTION_QUERY_PLAN") == "true" {
			var plan []byte
			if err = tx.QueryRow(f.ctx, "EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) "+ingestionQueueQuery, f.tenant, true, cutoff, "", time.Time{}, 256).Scan(&plan); err != nil {
				return err
			}
			var result []map[string]any
			if err = json.Unmarshal(plan, &result); err != nil {
				return err
			}
			var walk func(map[string]any)
			walk = func(node map[string]any) {
				t.Logf("plan node=%v index=%v actual_ms=%v loops=%v rows=%v", node["Node Type"], node["Index Name"], node["Actual Total Time"], node["Actual Loops"], node["Actual Rows"])
				if children, ok := node["Plans"].([]any); ok {
					for _, child := range children {
						walk(child.(map[string]any))
					}
				}
			}
			walk(result[0]["Plan"].(map[string]any))
			t.Logf("plan planning_ms=%v execution_ms=%v jit=%v", result[0]["Planning Time"], result[0]["Execution Time"], result[0]["JIT"])
		}
		started = time.Now()
		items, err := tx.IngestionQueuePage(f.ctx, true, IngestionPosition{}, cutoff, 256)
		if err != nil {
			return err
		}
		newJSON, _ := json.Marshal(items)
		if !reflect.DeepEqual(queueIDs(items), wantFixture) {
			return fmt.Errorf("fixture work omitted or historical sealed payload returned: got=%v", queueIDs(items))
		}
		if len(oldJSON) < 32<<20 || len(newJSON) > 64<<10 {
			return fmt.Errorf("terminal payload filtering ineffective: before=%d after=%d", len(oldJSON), len(newJSON))
		}
		t.Logf("restricted PostgreSQL queue payload before=%d bytes after=%d bytes; List=%s queue=%s (diagnostic, no latency SLO)", len(oldJSON), len(newJSON), oldElapsed, time.Since(started))
		live, err := tx.IngestionQueuePage(f.ctx, false, IngestionPosition{}, cutoff, 256)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(queueIDs(live), wantLive) {
			return fmt.Errorf("live retry status behavior changed: %v", queueIDs(live))
		}
		// A malformed measurement ID follows the same empty-string fallback as
		// model.String; a seal of another kind must never satisfy it.
		if _, err = tx.EvidenceCreate(f.ctx, "measurement_snapshot", model.Document{"id": "fixture-snapshot-", "resource_id": "fixture-only-selection"}); err != nil {
			return err
		}
		items, err = tx.IngestionQueuePage(f.ctx, true, IngestionPosition{}, cutoff, 256)
		if err != nil {
			return err
		}
		for _, item := range items {
			if strings.Contains(item.Position.ID, "null-measurement") || strings.Contains(item.Position.ID, "numeric-measurement") {
				return fmt.Errorf("legacy empty-ID snapshot seal was ignored")
			}
		}
		return nil
	})
	if err := f.roles["finops_ingester"].Do(f.ctx, f.tenant+"-foreign", func(tx *Tx) error {
		cutoff, err := tx.IngestionQueueCutoff(f.ctx)
		if err != nil {
			return err
		}
		items, err := tx.IngestionQueuePage(f.ctx, true, IngestionPosition{}, cutoff, 64)
		if err == nil && len(items) != 0 {
			return fmt.Errorf("queue leaked another tenant")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	f.denied("finops_activity", func(tx *Tx) error {
		cutoff, err := tx.IngestionQueueCutoff(f.ctx)
		if err != nil {
			return err
		}
		_, err = tx.IngestionQueuePage(f.ctx, true, IngestionPosition{}, cutoff, 64)
		return err
	})
	f.denied("finops_activity", func(tx *Tx) error { _, err := tx.IngestionJobExists(f.ctx, "old-generation-baseline-000"); return err })
}

func TestIngestionQueuePagesResumeWithoutStrandingJobsOrFollowingNewWrites(t *testing.T) {
	f := newIngestionQueueTest(t)
	f.must("finops_ingester", func(tx *Tx) error {
		for i := 0; i < 145; i++ {
			if _, err := tx.Create(f.ctx, "ingestion_jobs", model.Document{"id": fmt.Sprintf("queued-%03d", i), "status": "PENDING"}); err != nil {
				return err
			}
		}
		return nil
	})
	var cutoff time.Time
	var firstPosition IngestionPosition
	f.must("finops_ingester", func(tx *Tx) error {
		var err error
		cutoff, err = tx.IngestionQueueCutoff(f.ctx)
		if err != nil {
			return err
		}
		first, err := tx.IngestionQueuePage(f.ctx, false, IngestionPosition{}, cutoff, 64)
		if err != nil {
			return err
		}
		if len(first) != 64 {
			return fmt.Errorf("first page size=%d", len(first))
		}
		firstPosition = first[len(first)-1].Position
		for _, item := range first {
			item.Job["status"] = "PERSISTED"
			if _, err := tx.Update(f.ctx, "ingestion_jobs", item.Position.ID, model.Number(item.Job, "version"), item.Job); err != nil {
				return err
			}
		}
		return nil
	})
	// A new API transaction commits after the first tick watermark. No caller
	// clock override/backdated row is used to manufacture this boundary.
	f.must("finops_api", func(tx *Tx) error {
		_, err := tx.Create(f.ctx, "ingestion_jobs", model.Document{"id": "new-after-watermark", "status": "PENDING"})
		return err
	})
	f.must("finops_ingester", func(tx *Tx) error {
		position := firstPosition
		count := 0
		seen := map[string]bool{}
		for {
			items, err := tx.IngestionQueuePage(f.ctx, false, position, cutoff, 31)
			if err != nil {
				return err
			}
			if len(items) == 0 {
				break
			}
			for _, item := range items {
				if seen[item.Position.ID] || item.Position.ID == "new-after-watermark" {
					return fmt.Errorf("duplicate or unbounded new work")
				}
				seen[item.Position.ID] = true
				count++
			}
			position = items[len(items)-1].Position
		}
		if count != 81 {
			return fmt.Errorf("keyset lost remaining work: %d", count)
		}
		// Process restart resets the ephemeral cursor and still finds unfinished
		// earlier work; it also admits the previously deferred new job.
		nextCutoff, err := tx.IngestionQueueCutoff(f.ctx)
		if err != nil {
			return err
		}
		items, err := tx.IngestionQueuePage(f.ctx, false, IngestionPosition{}, nextCutoff, 256)
		if err != nil {
			return err
		}
		if len(items) != 82 {
			return fmt.Errorf("restart stranded prior/new work: %d", len(items))
		}
		return nil
	})
}

func TestIngestionQueueFailsClosedOnInvalidBoundsAndNonobjectJob(t *testing.T) {
	f := newIngestionQueueTest(t)
	f.must("finops_ingester", func(tx *Tx) error {
		cutoff, err := tx.IngestionQueueCutoff(f.ctx)
		if err != nil {
			return err
		}
		for _, limit := range []int{0, 257} {
			if _, err = tx.IngestionQueuePage(f.ctx, true, IngestionPosition{}, cutoff, limit); err == nil {
				return fmt.Errorf("unbounded page accepted")
			}
		}
		if _, err = tx.IngestionQueuePage(f.ctx, true, IngestionPosition{}, time.Time{}, 64); err == nil {
			return fmt.Errorf("missing server watermark accepted")
		}
		_, err = tx.Exec(f.ctx, "INSERT INTO entities(tenant_id,kind,id,document) VALUES($1,'ingestion_jobs','malformed-json-null','null'::jsonb)", f.tenant)
		if err != nil {
			return err
		}
		exists, err := tx.IngestionJobExists(f.ctx, "malformed-json-null")
		if err != nil || !exists {
			return fmt.Errorf("metadata-only existence check unnecessarily decoded invalid payload: %v", err)
		}
		cutoff, err = tx.IngestionQueueCutoff(f.ctx)
		if err != nil {
			return err
		}
		_, err = tx.IngestionQueuePage(f.ctx, true, IngestionPosition{}, cutoff, 64)
		if err == nil {
			return fmt.Errorf("nonobject job silently skipped or accepted")
		}
		return nil
	})
}

func TestIngestionQueueMigrationPreservesDocumentsAndDerivesUnforgeableMetadata(t *testing.T) {
	f := newFleetHistoryDBTest(t)
	f.must("finops_ingester", func(tx *Tx) error {
		_, err := tx.Create(f.ctx, "ingestion_jobs", model.Document{"id": "existing-job", "status": "PENDING", "fixture_baseline": nil, "fixture_measurement": model.Document{"measurement_id": "must-not-win"}, "canonical": model.Document{"value": "unchanged"}})
		return err
	})
	var document string
	var version int64
	var updated time.Time
	f.must("finops_ingester", func(tx *Tx) error {
		return tx.QueryRow(f.ctx, "SELECT document::text,version,updated_at FROM entities WHERE tenant_id=$1 AND kind='ingestion_jobs' AND id='existing-job'", f.tenant).Scan(&document, &version, &updated)
	})
	applyIngestionQueueMigrations(t, f, "003_immutable_readiness.sql", "004_owned_receipt_ingestion.sql", "028_ingestion_queue.sql")
	f.must("finops_ingester", func(tx *Tx) error {
		var after, status, kind, id string
		var afterVersion int64
		var afterUpdated time.Time
		if err := tx.QueryRow(f.ctx, "SELECT document::text,version,updated_at,ingestion_status,ingestion_seal_kind,ingestion_seal_id FROM entities WHERE tenant_id=$1 AND kind='ingestion_jobs' AND id='existing-job'", f.tenant).Scan(&after, &afterVersion, &afterUpdated, &status, &kind, &id); err != nil {
			return err
		}
		if after != document || afterVersion != version || !afterUpdated.Equal(updated) || status != "PENDING" || kind != "baseline" || id != "existing-job" {
			return fmt.Errorf("generated migration changed document/history or baseline precedence")
		}
		job, err := tx.Get(f.ctx, "ingestion_jobs", "existing-job")
		if err != nil {
			return err
		}
		job["status"] = "PERSISTED"
		if _, err = tx.Update(f.ctx, "ingestion_jobs", "existing-job", version, job); err != nil {
			return err
		}
		return tx.QueryRow(f.ctx, "SELECT ingestion_status FROM entities WHERE tenant_id=$1 AND kind='ingestion_jobs' AND id='existing-job'", f.tenant).Scan(&status)
	})
	f.denied("finops_ingester", func(tx *Tx) error {
		_, err := tx.Exec(f.ctx, "UPDATE entities SET ingestion_status='PENDING',ingestion_seal_kind=NULL,ingestion_seal_id=NULL WHERE tenant_id=$1 AND kind='ingestion_jobs' AND id='existing-job'", f.tenant)
		return err
	})
	f.denied("finops_ingester", func(tx *Tx) error {
		_, err := tx.Exec(f.ctx, "INSERT INTO entities(tenant_id,kind,id,document,ingestion_status) VALUES($1,'ingestion_jobs','forged-metadata','{}','PERSISTED')", f.tenant)
		return err
	})
	f.must("finops_ingester", func(tx *Tx) error {
		var status string
		if err := tx.QueryRow(f.ctx, "SELECT ingestion_status FROM entities WHERE tenant_id=$1 AND kind='ingestion_jobs' AND id='existing-job'", f.tenant).Scan(&status); err != nil {
			return err
		}
		if status != "PERSISTED" {
			return fmt.Errorf("generated metadata did not follow actual document update")
		}
		return nil
	})
}
