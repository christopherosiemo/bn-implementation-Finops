package store

import (
	"context"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
)

func (t *Tx) TelemetryConnectionPage(ctx context.Context, after, workload string, limit int) ([]model.Document, error) {
	if limit < 1 || limit > 101 {
		return nil, ErrConflict
	}
	rows, err := t.Query(ctx, `SELECT c.id FROM telemetry_connections c WHERE c.tenant_id=$1 AND c.id>$2 AND ($3='' OR c.config->'binding'->>'workload_id'=$3) AND NOT EXISTS(SELECT 1 FROM telemetry_connections n WHERE n.tenant_id=c.tenant_id AND n.id=c.id AND n.version>c.version) ORDER BY c.id LIMIT $4`, t.Tenant, after, workload, limit)
	if err != nil {
		return nil, err
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	out := []model.Document{}
	for _, id := range ids {
		d, e := t.TelemetryConnection(ctx, id)
		if e != nil {
			return nil, e
		}
		out = append(out, d)
	}
	return out, nil
}
func (t *Tx) TelemetryReceiptPage(ctx context.Context, connection, after string, limit int) ([]model.Document, error) {
	if limit < 1 || limit > 101 {
		return nil, ErrConflict
	}
	return t.sourceRows(ctx, "SELECT "+telemetryReceiptProjection+" FROM telemetry_receipts r WHERE r.tenant_id=$1 AND r.connection_id=$2 AND r.id>$3 ORDER BY r.id LIMIT $4", t.Tenant, connection, after, limit)
}
func (t *Tx) TelemetryEvaluationPage(ctx context.Context, connection, after string, limit int) ([]model.Document, error) {
	if limit < 1 || limit > 101 {
		return nil, ErrConflict
	}
	return t.sourceRows(ctx, "SELECT document FROM telemetry_evaluations WHERE tenant_id=$1 AND connection_id=$2 AND id>$3 ORDER BY id LIMIT $4", t.Tenant, connection, after, limit)
}
