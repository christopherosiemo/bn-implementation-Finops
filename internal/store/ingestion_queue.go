package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
)

// IngestionPosition is process-local pagination, never a persisted high-water
// mark. Each tick starts from the beginning so a retried or newly unsealed job
// cannot be permanently skipped behind an earlier cursor.
type IngestionPosition struct {
	CreatedAt time.Time
	ID        string
}

type IngestionQueueItem struct {
	Job      model.Document
	Position IngestionPosition
}

const ingestionQueueQuery = `WITH candidates AS MATERIALIZED (
 SELECT id,created_at FROM entities e
 WHERE e.tenant_id=$1 AND e.kind='ingestion_jobs'
 AND e.ingestion_status IS DISTINCT FROM 'PERSISTED'
 AND e.created_at<=$3 AND ($4='' OR (e.created_at,e.id)>($5,$4))
 UNION ALL
 SELECT id,created_at FROM entities e
 WHERE $2 AND e.tenant_id=$1 AND e.kind='ingestion_jobs'
 AND e.ingestion_status='PERSISTED' AND e.ingestion_seal_kind IS NOT NULL
 AND e.created_at<=$3 AND ($4='' OR (e.created_at,e.id)>($5,$4))
 AND NOT EXISTS(SELECT 1 FROM readiness_evidence r WHERE r.tenant_id=e.tenant_id
 AND r.kind=e.ingestion_seal_kind AND r.id=e.ingestion_seal_id)
 ), page AS MATERIALIZED (
 SELECT id,created_at FROM candidates ORDER BY created_at,id LIMIT $6
 ) SELECT e.id,e.document,e.version,c.created_at FROM page c
 JOIN entities e ON e.tenant_id=$1 AND e.kind='ingestion_jobs' AND e.id=c.id
 ORDER BY c.created_at,c.id`

// IngestionJobExists deliberately returns no raw/canonical payload. Fixture
// preparation needs only to decide whether its deterministic job is missing.
func (t *Tx) IngestionJobExists(ctx context.Context, id string) (bool, error) {
	var exists bool
	err := t.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM entities WHERE tenant_id=$1 AND kind='ingestion_jobs' AND id=$2)", t.Tenant, id).Scan(&exists)
	return exists, err
}

func (t *Tx) IngestionQueueCutoff(ctx context.Context) (time.Time, error) {
	var cutoff time.Time
	err := t.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&cutoff)
	return cutoff, err
}

// IngestionQueuePage selects work before transporting full immutable billing
// payloads. Every non-PERSISTED status retains the previous retry behavior,
// including missing, malformed and unrecognized status values. Fixture jobs
// already persisted remain work until their exact baseline/snapshot is sealed.
// Baseline-key precedence deliberately matches SealFixtureEvidence, including
// legacy null/malformed fixture metadata. No generation is silently excluded.
func (t *Tx) IngestionQueuePage(ctx context.Context, fixture bool, after IngestionPosition, cutoff time.Time, limit int) ([]IngestionQueueItem, error) {
	if cutoff.IsZero() || limit < 1 || limit > 256 || after.CreatedAt.IsZero() != (after.ID == "") {
		return nil, errors.New("INGESTION_QUEUE_BOUNDS_INVALID")
	}
	rows, err := t.Query(ctx, ingestionQueueQuery, t.Tenant, fixture, cutoff, after.ID, after.CreatedAt, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []IngestionQueueItem{}
	for rows.Next() {
		var item IngestionQueueItem
		var raw []byte
		var version int64
		if err = rows.Scan(&item.Position.ID, &raw, &version, &item.Position.CreatedAt); err != nil {
			return nil, err
		}
		if err = json.Unmarshal(raw, &item.Job); err != nil {
			return nil, err
		}
		if item.Job == nil {
			return nil, errors.New("INGESTION_JOB_DOCUMENT_INVALID")
		}
		item.Job["id"], item.Job["version"] = item.Position.ID, version
		items = append(items, item)
	}
	return items, rows.Err()
}
