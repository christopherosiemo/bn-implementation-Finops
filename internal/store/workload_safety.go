package store

import (
	"context"
	"encoding/json"
	"math"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/workload"
	"github.com/jackc/pgx/v5"
)

func (t *Tx) WorkloadSafetyLatest(ctx context.Context, id string) (model.Document, error) {
	return t.sourceOne(ctx, "SELECT document FROM workload_safety_profiles WHERE tenant_id=$1 AND workload_id=$2 ORDER BY version DESC LIMIT 1", t.Tenant, id)
}
func (t *Tx) WorkloadSafetyGet(ctx context.Context, id string) (model.Document, error) {
	return t.sourceOne(ctx, "SELECT document FROM workload_safety_profiles WHERE tenant_id=$1 AND id=$2", t.Tenant, id)
}
func (t *Tx) WorkloadSafetyHistory(ctx context.Context, id string, afterVersion int64, limit int) ([]model.Document, error) {
	if limit < 1 || limit > 100 {
		return nil, ErrConflict
	}
	return t.sourceRows(ctx, "SELECT document FROM workload_safety_profiles WHERE tenant_id=$1 AND workload_id=$2 AND version>$3 ORDER BY version LIMIT $4", t.Tenant, id, afterVersion, limit)
}
func (t *Tx) WorkloadSafetyAppend(ctx context.Context, id string, expected int64, profile workload.Profile) (model.Document, error) {
	if expected < 0 || expected == math.MaxInt64 {
		return nil, ErrConflict
	}
	if _, err := t.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", t.Tenant+":dependency-graph"); err != nil {
		return nil, err
	}
	latest, err := t.WorkloadSafetyLatest(ctx, id)
	if err != nil && err != pgx.ErrNoRows {
		return nil, err
	}
	if model.Number(latest, "version") != expected {
		return nil, ErrConflict
	}
	if _, err = t.Get(ctx, "workloads", id); err != nil {
		return nil, err
	}
	profile.ID, profile.WorkloadID, profile.Version = model.ID(), id, expected+1
	if err = workload.Validate(profile); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(profile)
	if err != nil {
		return nil, err
	}
	return t.sourceOne(ctx, "INSERT INTO workload_safety_profiles(tenant_id,id,workload_id,version,content_hash,document) VALUES($1,$2,$3,$4,$5,$6) RETURNING document", t.Tenant, profile.ID, id, profile.Version, workload.Hash(profile), raw)
}
