package store

import (
	"context"
	"encoding/json"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/telemetry"
)

func (t *Tx) CapacityAssessmentCreate(ctx context.Context, d model.Document) (model.Document, error) {
	// Registration, requirements, inventory updates and this publication share
	// the same lock. SQL independently rechecks immutable source/profile binding.
	if _, err := t.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", t.Tenant+":dependency-graph"); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(d)
	if err != nil {
		return nil, err
	}
	return t.sourceOne(ctx, "INSERT INTO capacity_assessments(tenant_id,id,workload_id,resource_id,connection_id,revision_id,safety_profile_id,content_hash,document) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING document", t.Tenant, model.ID(), model.String(d, "workload_id"), model.String(d, "resource_id"), model.String(d, "connection_id"), model.String(d, "revision_id"), model.String(d, "safety_profile_id"), telemetry.Hash(d), raw)
}

func (t *Tx) CapacityAssessmentGet(ctx context.Context, id string) (model.Document, error) {
	return t.sourceOne(ctx, "SELECT document FROM capacity_assessments WHERE tenant_id=$1 AND id=$2", t.Tenant, id)
}

func (t *Tx) CapacityAssessmentPage(ctx context.Context, workload, after string, limit int) ([]model.Document, error) {
	if workload == "" || limit < 1 || limit > 101 {
		return nil, ErrConflict
	}
	return t.sourceRows(ctx, "SELECT document FROM capacity_assessments WHERE tenant_id=$1 AND workload_id=$2 AND id>$3 ORDER BY id LIMIT $4", t.Tenant, workload, after, limit)
}
