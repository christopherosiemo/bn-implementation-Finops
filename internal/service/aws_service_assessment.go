package service

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/auth"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/jackc/pgx/v5"
	"net/http"
	"strings"
)

func awsServiceAssessmentResource(r model.Document) bool {
	if r["provider"] != "AWS" {
		return false
	}
	switch model.String(r, "resource_type") {
	case "ECS_SERVICE", "DYNAMODB_TABLE", "DYNAMODB_GSI", "ELASTICACHE_REPLICATION_GROUP", "ELASTICACHE_SERVERLESS_CACHE", "LOAD_BALANCER":
		return true
	case "ELASTICACHE_CLUSTER":
		return model.String(storageObject(r["aws_service_configuration"]), "ReplicationGroupId") == ""
	}
	return false
}
func (a *API) awsServiceAssessmentMutate(ctx context.Context, t *store.Tx, i auth.Identity, r *http.Request, in model.Document) (model.Document, int, bool, error) {
	if r.URL.Path != "/v1/aws-service-assessments" {
		return nil, 0, false, nil
	}
	if e := requireRole(i, "FINOPS_ADMIN", "PLATFORM_ADMIN", "APPLICATION_OWNER"); e != nil {
		return nil, 0, true, e
	}
	if len(in) != 1 || model.String(in, "resource_id") == "" {
		return nil, 0, true, problem(422, "AWS_SERVICE_IDS_ONLY", "select resource_id; source evidence, policy and monetary amounts are server-selected")
	}
	if e := match(r, model.Document{"version": 0}); e != nil {
		return nil, 0, true, e
	}
	rid := model.String(in, "resource_id")
	if e := storageReadScope(ctx, t, i, rid); e != nil {
		return nil, 0, true, e
	}
	res, e := t.Get(ctx, "resources", rid)
	if e != nil {
		return nil, 0, true, e
	}
	if !awsServiceAssessmentResource(res) {
		return nil, 0, true, problem(422, "AWS_SERVICE_ASSESSMENT_RESOURCE_REQUIRED", "select a stable ECS service, DynamoDB table/index, cache topology root or load balancer")
	}
	out, e := t.AWSServiceAssessmentCreate(ctx, rid, i.Subject)
	if e == nil {
		e = t.Audit(ctx, i.Subject, "aws_service.assessment.requested", model.String(out, "id"), model.Document{"resource_id": rid, "family": res["service_family"], "execution_authorized": false})
	}
	return out, 202, true, e
}
func (a *API) awsServiceAssessmentGet(ctx context.Context, t *store.Tx, i auth.Identity, r *http.Request) (any, bool, error) {
	p := strings.Split(strings.TrimPrefix(r.URL.Path, "/v1/"), "/")
	assessment := p[0] == "aws-service-assessments"
	recommendation := p[0] == "recommendations" && (len(p) == 2 && strings.HasPrefix(p[1], "aws-service-") || len(p) == 1 && r.URL.Query().Get("model_kind") == "AWS_SERVICE_ASSESSMENT_V1")
	if !assessment && !recommendation {
		return nil, false, nil
	}
	if len(p) == 2 {
		var d model.Document
		var e error
		if recommendation {
			d, e = a.awsServiceRecommendation(ctx, t, strings.TrimPrefix(p[1], "aws-service-"))
		} else {
			d, e = t.AWSServiceAssessmentGet(ctx, p[1])
			if e == nil {
				d, e = a.awsServiceAssessmentCurrent(ctx, t, d)
			}
		}
		if e == nil {
			e = storageReadScope(ctx, t, i, model.String(d, "resource_id"))
		}
		return d, true, e
	}
	if len(p) != 1 {
		return nil, true, problem(404, "NOT_FOUND", "unknown AWS service assessment")
	}
	rid, family := r.URL.Query().Get("resource_id"), r.URL.Query().Get("family")
	if family != "" && (family == "EKS" || !awsServiceFamily(family)) {
		return nil, true, problem(422, "AWS_SERVICE_FAMILY_INVALID", "EKS uses the existing Kubernetes optimiser")
	}
	if e := storageReadScope(ctx, t, i, rid); e != nil {
		return nil, true, e
	}
	after, n, e := storagePage(r, t.Tenant, i.Subject)
	if e != nil {
		return nil, true, e
	}
	rows, e := t.AWSServiceAssessmentPage(ctx, after, rid, family, n+1)
	if e != nil {
		return nil, true, e
	}
	next := ""
	if len(rows) > n {
		rows = rows[:n]
		next = model.String(rows[n-1], "id")
	}
	out := []model.Document{}
	for _, d := range rows {
		var v model.Document
		if recommendation {
			v, e = a.awsServiceRecommendation(ctx, t, model.String(d, "id"))
			if errors.Is(e, pgx.ErrNoRows) {
				continue
			}
		} else {
			v, e = a.awsServiceAssessmentCurrent(ctx, t, d)
		}
		if e != nil {
			return nil, true, e
		}
		out = append(out, v)
	}
	return model.Document{"items": out, "next_cursor": storageNextCursor(r, t.Tenant, i.Subject, next)}, true, nil
}
func (a *API) awsServiceRecommendation(ctx context.Context, t *store.Tx, id string) (model.Document, error) {
	var raw []byte
	if e := t.QueryRow(ctx, "SELECT document FROM aws_service_recommendation_publications WHERE tenant_id=$1 AND assessment_id=$2", t.Tenant, id).Scan(&raw); e != nil {
		return nil, e
	}
	d := storageObject(json.RawMessage(raw))
	record, e := t.AWSServiceAssessmentGet(ctx, id)
	if e != nil {
		return nil, e
	}
	record, e = a.awsServiceAssessmentCurrent(ctx, t, record)
	if e != nil {
		return nil, e
	}
	return recommendationCurrentnessCopy(d, record), nil
}
