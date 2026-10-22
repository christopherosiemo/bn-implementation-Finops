package store

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/jackc/pgx/v5"
)

func (t *Tx) AWSServiceAssessmentGet(ctx context.Context, id string) (model.Document, error) {
	return t.sourceOne(ctx, "SELECT document FROM aws_service_assessments WHERE tenant_id=$1 AND id=$2", t.Tenant, id)
}
func (t *Tx) AWSServiceAssessmentPage(ctx context.Context, after, resource, family string, limit int) ([]model.Document, error) {
	if limit < 1 || limit > 101 {
		return nil, ErrConflict
	}
	return t.sourceRows(ctx, "SELECT document FROM aws_service_assessments WHERE tenant_id=$1 AND id>$2 AND ($3='' OR resource_id=$3) AND ($4='' OR family=$4) ORDER BY id LIMIT $5", t.Tenant, after, resource, family, limit)
}
func (t *Tx) AWSServiceAssessmentCreate(ctx context.Context, resource, actor string) (model.Document, error) {
	if actor == "" {
		return nil, errors.New("AWS_SERVICE_ACTOR_REQUIRED")
	}
	if _, e := t.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", t.Tenant+":dependency-graph"); e != nil {
		return nil, e
	}
	r, e := t.Get(ctx, "resources", resource)
	if e != nil {
		return nil, e
	}
	family := model.String(r, "service_family")
	switch family {
	case "ECS", "DYNAMODB", "ELASTICACHE", "ELB":
	default:
		return nil, errors.New("AWS_SERVICE_ASSESSMENT_RESOURCE_REQUIRED")
	}
	snapshot, e := t.AWSServiceEvidenceLatest(ctx, resource)
	if e != nil && !errors.Is(e, pgx.ErrNoRows) {
		return nil, e
	}
	profile, e := t.WorkloadSafetyLatest(ctx, model.String(r, "workload_id"))
	if e != nil && !errors.Is(e, pgx.ErrNoRows) {
		return nil, e
	}
	var snapshotID, profileID any
	if snapshot != nil {
		snapshotID = snapshot["id"]
	}
	if profile != nil {
		profileID = profile["id"]
	}
	raw, _ := json.Marshal(model.Document{"assessment": nil})
	id := model.ID()
	out, e := t.sourceOne(ctx, "INSERT INTO aws_service_assessments(tenant_id,id,resource_id,workload_id,family,snapshot_id,safety_profile_id,resource_version,document,created_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING document", t.Tenant, id, resource, r["workload_id"], family, snapshotID, profileID, r["version"], raw, actor)
	if e == nil {
		e = t.Event(ctx, "aws_service.assessment.requested", model.Document{"id": id, "resource_id": resource, "family": family})
	}
	return out, e
}
