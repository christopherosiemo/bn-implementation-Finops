package service

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/auth"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/awsservice"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/jackc/pgx/v5"
	"net/http"
	"strings"
	"time"
)

func awsServiceFamily(f string) bool {
	switch f {
	case "ECS", "EKS", "ELASTICACHE", "DYNAMODB", "ELB":
		return true
	}
	return false
}
func awsServiceResourceType(k string) bool {
	switch k {
	case "ECS_CLUSTER", "ECS_SERVICE", "ECS_TASK_DEFINITION", "ECS_TASK", "ECS_CAPACITY_PROVIDER", "ECS_CONTAINER_INSTANCE", "EKS_CLUSTER", "EKS_NODE_GROUP", "EKS_FARGATE_PROFILE", "EKS_ADDON", "ELASTICACHE_REPLICATION_GROUP", "ELASTICACHE_CLUSTER", "ELASTICACHE_SERVERLESS_CACHE", "DYNAMODB_TABLE", "DYNAMODB_GSI", "LOAD_BALANCER", "ELB_LISTENER", "ELB_TARGET_GROUP":
		return true
	}
	return false
}
func AWSServiceConfigurationHash(r model.Document) string { return awsservice.ConfigurationHash(r) }

// These are ordinary inventory queries with the same tenant/workload cursor
// binding as other analytical resources. Native relationships are analytical;
// they never become EC2 STOP dependencies or execution authority.
func (a *API) awsServiceGet(ctx context.Context, t *store.Tx, i auth.Identity, r *http.Request) (any, bool, error) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/v1/"), "/")
	if len(parts) == 3 && parts[0] == "resources" && parts[2] == "aws-service-evidence" {
		if e := storageReadScope(ctx, t, i, parts[1]); e != nil {
			return nil, true, e
		}
		resource, e := t.Get(ctx, "resources", parts[1])
		if e != nil {
			return nil, true, e
		}
		if !awsServiceFamily(model.String(resource, "service_family")) {
			return nil, true, problem(422, "AWS_SERVICE_RESOURCE_REQUIRED", "select a discovered AWS service resource")
		}
		snapshot, e := t.AWSServiceEvidenceLatest(ctx, parts[1])
		if errors.Is(e, pgx.ErrNoRows) {
			return model.Document{"resource_id": parts[1], "family": resource["service_family"], "current": false, "reason_codes": []string{"AWS_SERVICE_NATIVE_SNAPSHOT_REQUIRED"}, "snapshot": nil}, true, nil
		}
		if e != nil {
			return nil, true, e
		}
		reasons := []string{}
		registration, e := t.SourceGet(ctx, model.String(snapshot, "source_id"))
		if e != nil {
			return nil, true, e
		}
		if !model.Bool(registration, "enabled") || model.Bool(registration, "revoked") || model.Number(registration, "version") != model.Number(snapshot, "registration_version") {
			reasons = append(reasons, "AWS_SERVICE_SOURCE_CHANGED_OR_REVOKED")
		}
		if model.String(snapshot, "config_hash") != AWSServiceConfigurationHash(resource) {
			reasons = append(reasons, "AWS_SERVICE_CONFIGURATION_CHANGED")
		}
		at, stampError := time.Parse(time.RFC3339Nano, model.String(snapshot, "observed_at"))
		if stampError != nil || at.After(a.now().Add(time.Minute)) || a.now().Sub(at) > 30*time.Minute {
			reasons = append(reasons, "AWS_SERVICE_POINT_INVENTORY_STALE")
		}
		return model.Document{"resource_id": parts[1], "family": resource["service_family"], "current": len(reasons) == 0, "reason_codes": reasons, "snapshot": snapshot}, true, nil
	}
	if len(parts) != 1 || parts[0] != "resources" {
		return nil, false, nil
	}
	family, kind := r.URL.Query().Get("service_family"), r.URL.Query().Get("resource_type")
	if family == "" && !awsServiceResourceType(kind) {
		return nil, false, nil
	}
	if family != "" && !awsServiceFamily(family) || kind != "" && !awsServiceResourceType(kind) {
		return nil, true, problem(422, "AWS_SERVICE_FILTER_INVALID", "select a supported native service family or resource type")
	}
	after, n, e := storagePage(r, t.Tenant, i.Subject)
	if e != nil {
		return nil, true, e
	}
	workload := r.URL.Query().Get("workload_id")
	rows, e := t.Query(ctx, `SELECT r.document||jsonb_build_object('id',r.id,'version',r.version) FROM entities r WHERE r.tenant_id=$1 AND r.kind='resources' AND r.id>$2 AND ($3='' OR r.document->>'service_family'=$3) AND ($4='' OR r.document->>'resource_type'=$4) AND ($5='' OR r.document->>'workload_id'=$5) AND (NOT $6 OR EXISTS(SELECT FROM entities w WHERE w.tenant_id=r.tenant_id AND w.kind='workloads' AND w.id=r.document->>'workload_id' AND w.document->>'owner_subject'=$7)) ORDER BY r.id LIMIT $8`, t.Tenant, after, family, kind, workload, scopedOwner(i), i.Subject, n+1)
	if e != nil {
		return nil, true, e
	}
	out := []model.Document{}
	for rows.Next() {
		var raw []byte
		if e = rows.Scan(&raw); e != nil {
			break
		}
		out = append(out, storageObject(json.RawMessage(raw)))
	}
	if e == nil {
		e = rows.Err()
	}
	rows.Close()
	if e != nil {
		return nil, true, e
	}
	next := ""
	if len(out) > n {
		out = out[:n]
		next = model.String(out[n-1], "id")
	}
	return model.Document{"items": out, "next_cursor": storageNextCursor(r, t.Tenant, i.Subject, next)}, true, nil
}
