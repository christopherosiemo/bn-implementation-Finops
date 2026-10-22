package store

import (
	"context"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
)

// NativeCapacityResultPage exposes bounded analytical summaries only. Full
// native populations remain in versioned source objects under ingestion roles.
func (t *Tx) NativeCapacityResultPage(ctx context.Context, workload, after string, limit int) ([]model.Document, error) {
	if workload == "" || limit < 1 || limit > 101 {
		return nil, ErrConflict
	}
	return t.sourceRows(ctx, "SELECT document FROM native_capacity_results WHERE tenant_id=$1 AND workload_id=$2 AND id>$3 ORDER BY id LIMIT $4", t.Tenant, workload, after, limit)
}
