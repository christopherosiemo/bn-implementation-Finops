package service

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/auth"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/evidence"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/jackc/pgx/v5"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func storageResource(d model.Document) bool {
	k := model.String(d, "resource_type")
	return k == "EBS_VOLUME" || k == "EBS_SNAPSHOT"
}

// A current explicit dependency review supports analysis only. Its scheduling
// STOP status is never reused as storage execution authority.
func storageReviewCurrent(review, graph model.Document, resource string, now time.Time) bool {
	expires, ee := time.Parse(time.RFC3339Nano, model.String(review, "expires_at"))
	reviewed, re := time.Parse(time.RFC3339Nano, model.String(review, "reviewed_at"))
	return model.String(review, "writer_role") == "finops_api" && model.String(review, "resource_id") == resource && model.String(review, "reviewed_by") != "" && model.String(review, "acknowledgement") == "REVIEWED_DISCOVERED_AND_EXTERNAL_DEPENDENCIES" && ee == nil && re == nil && expires.After(now) && !reviewed.After(now.Add(30*time.Second)) && expires.After(reviewed) && expires.Sub(reviewed) <= 24*time.Hour && model.String(graph, "status") == "DECLARED" && model.Number(review, "graph_version") == model.Number(graph, "version") && model.String(review, "graph_hash") == model.String(graph, "graph_hash") && model.String(review, "inventory_hash") == model.String(graph, "inventory_hash")
}

func storageAuthorityReferencesCurrent(ctx context.Context, t *store.Tx, resource model.Document, refs []model.Document, now time.Time) (bool, error) {
	for _, ref := range refs {
		switch model.String(ref, "kind") {
		case "REVIEWED_DEPENDENCY_GRAPH":
			review, e := t.DependencyReviewLatest(ctx, model.String(resource, "id"))
			if errors.Is(e, pgx.ErrNoRows) {
				return false, nil
			}
			if e != nil {
				return false, e
			}
			g, e := dependencyGraph(ctx, t)
			if e != nil {
				return false, e
			}
			if model.String(review, "id") != model.String(ref, "id") || evidence.Hash(review) != model.String(ref, "sha256") || !storageReviewCurrent(review, g, model.String(resource, "id"), now) {
				return false, nil
			}
		case "DECLARED_CONFIGURATION_AUTHORITY":
			authority, e := storageConfigurationAuthority(ctx, t, model.String(resource, "id"))
			if errors.Is(e, pgx.ErrNoRows) {
				return false, nil
			}
			if e != nil {
				return false, e
			}
			if !storageBoundAuthority(authority, resource, t.Tenant) || model.String(authority, "id") != model.String(ref, "id") || evidence.Hash(storageAuthorityDocument(authority)) != model.String(ref, "sha256") {
				return false, nil
			}
		}
	}
	return true, nil
}

// Collection clocks cannot renew the authority of an old configuration.
func StorageConfigurationHash(r model.Document) string {
	c := storageObject(r["storage_configuration"])
	for _, k := range []string{"last_seen_at", "collected_at", "raw_ref", "raw_page_sha256"} {
		delete(c, k)
	}
	storageStripAcquisitionRefs(c)
	return evidence.Hash(model.Document{"resource_id": r["id"], "provider_resource_id": r["provider_resource_id"], "account_id": r["account_id"], "region": r["region"], "resource_type": r["resource_type"], "workload_id": r["workload_id"], "owner": r["owner"], "environment": r["environment"], "configuration_authority": r["configuration_authority"], "native": c})
}

func storageStripAcquisitionRefs(value any) {
	switch v := value.(type) {
	case model.Document:
		for k, child := range v {
			if k == "raw_ref" || k == "raw_page_sha256" {
				delete(v, k)
			} else {
				storageStripAcquisitionRefs(child)
			}
		}
	case map[string]any:
		for k, child := range v {
			if k == "raw_ref" || k == "raw_page_sha256" {
				delete(v, k)
			} else {
				storageStripAcquisitionRefs(child)
			}
		}
	case []any:
		for _, child := range v {
			storageStripAcquisitionRefs(child)
		}
	}
}
func (a *API) storageMutate(ctx context.Context, t *store.Tx, i auth.Identity, r *http.Request, in model.Document) (model.Document, int, bool, error) {
	if r.URL.Path != "/v1/storage-assessments" {
		return nil, 0, false, nil
	}
	if e := requireRole(i, "PLATFORM_ADMIN", "FINOPS_ADMIN", "APPLICATION_OWNER"); e != nil {
		return nil, 0, true, e
	}
	if len(in) != 1 || model.String(in, "resource_id") == "" {
		return nil, 0, true, problem(422, "STORAGE_IDS_ONLY", "select a resource_id; native observations, policy and costs are resolved by the service")
	}
	if e := match(r, model.Document{"version": 0}); e != nil {
		return nil, 0, true, e
	}
	resource, e := t.Get(ctx, "resources", model.String(in, "resource_id"))
	if e != nil {
		return nil, 0, true, e
	}
	if !storageResource(resource) {
		return nil, 0, true, problem(422, "STORAGE_RESOURCE_REQUIRED", "select a discovered EBS volume or snapshot")
	}
	if e = storageReadScope(ctx, t, i, model.String(resource, "id")); e != nil {
		return nil, 0, true, e
	}
	out, e := t.StorageAssessmentCreate(ctx, model.String(resource, "id"), i.Subject)
	if e == nil {
		e = t.Audit(ctx, i.Subject, "storage.assessment.requested", model.String(out, "id"), model.Document{"resource_id": resource["id"], "execution_authorized": false})
	}
	return out, 202, true, e
}
func storageReadScope(ctx context.Context, t *store.Tx, i auth.Identity, id string) error {
	if !scopedOwner(i) {
		return nil
	}
	if id == "" {
		return problem(403, "WORKLOAD_SCOPE_DENIED", "select an owned storage resource")
	}
	r, e := t.Get(ctx, "resources", id)
	if e != nil {
		return e
	}
	w, e := t.Get(ctx, "workloads", model.String(r, "workload_id"))
	if e != nil {
		return e
	}
	return workloadAccess(i, w)
}
func storageCursorScope(r *http.Request, tenant, subject string) string {
	q := r.URL.Query()
	q.Del("cursor")
	q.Del("limit")
	return evidence.Hash(model.Document{"tenant": tenant, "subject": subject, "path": r.URL.Path, "query": q.Encode()})
}
func storageNextCursor(r *http.Request, tenant, subject, after string) any {
	if after == "" {
		return nil
	}
	raw, _ := json.Marshal(model.Document{"after": after, "scope": storageCursorScope(r, tenant, subject)})
	return base64.RawURLEncoding.EncodeToString(raw)
}
func storagePage(r *http.Request, tenant, subject string) (string, int, error) {
	after := ""
	if cursor := r.URL.Query().Get("cursor"); cursor != "" {
		raw, e := base64.RawURLEncoding.DecodeString(cursor)
		var d model.Document
		if len(cursor) > 1024 || e != nil || json.Unmarshal(raw, &d) != nil || len(d) != 2 || model.String(d, "scope") != storageCursorScope(r, tenant, subject) {
			return "", 0, problem(422, "INVALID_CURSOR", "storage cursor does not match this tenant and query")
		}
		after = model.String(d, "after")
		if after == "" {
			return "", 0, problem(422, "INVALID_CURSOR", "storage cursor has no position")
		}
	}
	if !databaseCursor.MatchString(after) {
		return "", 0, problem(422, "INVALID_CURSOR", "invalid storage cursor")
	}
	n := 25
	if raw := r.URL.Query().Get("limit"); raw != "" {
		v, e := strconv.Atoi(raw)
		if e != nil || v < 1 || v > 100 {
			return "", 0, problem(422, "INVALID_LIMIT", "limit must be 1 through 100")
		}
		n = v
	}
	return after, n, nil
}
func (a *API) storageGet(ctx context.Context, t *store.Tx, i auth.Identity, r *http.Request) (any, bool, error) {
	path := strings.TrimPrefix(r.URL.Path, "/v1/")
	parts := strings.Split(path, "/")
	if parts[0] == "storage-assessments" {
		if len(parts) == 2 {
			d, e := t.StorageAssessmentGet(ctx, parts[1])
			if e == nil {
				e = storageReadScope(ctx, t, i, model.String(d, "resource_id"))
			}
			if e == nil {
				d, e = a.storageAssessmentCurrent(ctx, t, d)
			}
			return d, true, e
		}
		if len(parts) != 1 {
			return nil, true, problem(404, "NOT_FOUND", "storage assessment not found")
		}
		rid := r.URL.Query().Get("resource_id")
		if e := storageReadScope(ctx, t, i, rid); e != nil {
			return nil, true, e
		}
		after, n, e := storagePage(r, t.Tenant, i.Subject)
		if e != nil {
			return nil, true, e
		}
		rows, e := t.StorageAssessmentPage(ctx, after, rid, n+1)
		if e != nil {
			return nil, true, e
		}
		next := ""
		if len(rows) > n {
			rows = rows[:n]
			next = model.String(rows[n-1], "id")
		}
		for j := range rows {
			rows[j], e = a.storageAssessmentCurrent(ctx, t, rows[j])
			if e != nil {
				return nil, true, e
			}
		}
		return model.Document{"items": rows, "next_cursor": storageNextCursor(r, t.Tenant, i.Subject, next)}, true, nil
	}
	if parts[0] == "recommendations" && len(parts) == 2 && strings.HasPrefix(parts[1], "storage-") {
		d, e := a.storageRecommendationGet(ctx, t, strings.TrimPrefix(parts[1], "storage-"))
		if e == nil {
			e = storageReadScope(ctx, t, i, model.String(d, "resource_id"))
		}
		return d, true, e
	}
	if path == "recommendations" && r.URL.Query().Get("model_kind") == "STORAGE_ASSESSMENT_V1" {
		rid := r.URL.Query().Get("resource_id")
		if e := storageReadScope(ctx, t, i, rid); e != nil {
			return nil, true, e
		}
		after, n, e := storagePage(r, t.Tenant, i.Subject)
		if e != nil {
			return nil, true, e
		}
		rows, e := t.Query(ctx, "SELECT assessment_id FROM storage_recommendation_publications WHERE tenant_id=$1 AND assessment_id>$2 AND ($3='' OR resource_id=$3) ORDER BY assessment_id LIMIT $4", t.Tenant, after, rid, n+1)
		if e != nil {
			return nil, true, e
		}
		ids := []string{}
		for rows.Next() {
			var id string
			if e = rows.Scan(&id); e != nil {
				break
			}
			ids = append(ids, id)
		}
		if e == nil {
			e = rows.Err()
		}
		rows.Close()
		if e != nil {
			return nil, true, e
		}
		next := ""
		if len(ids) > n {
			ids = ids[:n]
			next = ids[n-1]
		}
		out := []model.Document{}
		for _, id := range ids {
			d, e := a.storageRecommendationGet(ctx, t, id)
			if e != nil {
				return nil, true, e
			}
			out = append(out, d)
		}
		return model.Document{"items": out, "next_cursor": storageNextCursor(r, t.Tenant, i.Subject, next)}, true, nil
	}
	if path == "resources" && (r.URL.Query().Get("resource_type") == "EBS_VOLUME" || r.URL.Query().Get("resource_type") == "EBS_SNAPSHOT") {
		after, n, e := storagePage(r, t.Tenant, i.Subject)
		if e != nil {
			return nil, true, e
		}
		rows, e := t.Query(ctx, `SELECT r.id FROM entities r WHERE r.tenant_id=$1 AND r.kind='resources' AND r.document->>'resource_type'=$2 AND r.id>$3
 AND (NOT $4 OR EXISTS(SELECT FROM entities w WHERE w.tenant_id=r.tenant_id AND w.kind='workloads' AND w.id=r.document->>'workload_id' AND w.document->>'owner_subject'=$5)) ORDER BY r.id LIMIT $6`, t.Tenant, r.URL.Query().Get("resource_type"), after, scopedOwner(i), i.Subject, n+1)
		if e != nil {
			return nil, true, e
		}
		ids := []string{}
		for rows.Next() {
			var id string
			if e = rows.Scan(&id); e != nil {
				break
			}
			ids = append(ids, id)
		}
		if e == nil {
			e = rows.Err()
		}
		rows.Close()
		if e != nil {
			return nil, true, e
		}
		next := ""
		if len(ids) > n {
			ids = ids[:n]
			next = ids[n-1]
		}
		out := []model.Document{}
		for _, id := range ids {
			d, e := t.Get(ctx, "resources", id)
			if e != nil {
				return nil, true, e
			}
			out = append(out, d)
		}
		return model.Document{"items": out, "next_cursor": storageNextCursor(r, t.Tenant, i.Subject, next)}, true, nil
	}
	return nil, false, nil
}
func (a *API) storageAssessmentCurrent(ctx context.Context, t *store.Tx, d model.Document) (model.Document, error) {
	if model.String(d, "status") == "QUEUED" || model.String(d, "status") == "RUNNING" {
		return d, nil
	}
	resource, e := t.Get(ctx, "resources", model.String(d, "resource_id"))
	if e != nil {
		return nil, e
	}
	var snapshotID, profileID string
	if e = t.QueryRow(ctx, "SELECT coalesce(snapshot_id,''),coalesce(safety_profile_id,'') FROM storage_assessments WHERE tenant_id=$1 AND id=$2", t.Tenant, d["id"]).Scan(&snapshotID, &profileID); e != nil {
		return nil, e
	}
	current := false
	if snapshotID != "" {
		s, e := t.StorageEvidenceGet(ctx, snapshotID)
		if e != nil {
			return nil, e
		}
		latest, e := t.StorageEvidenceLatest(ctx, model.String(resource, "id"))
		if e != nil {
			return nil, e
		}
		observed, oe := time.Parse(time.RFC3339Nano, model.String(s, "observed_at"))
		current = oe == nil && !observed.After(a.now().Add(time.Minute)) && a.now().Sub(observed) <= 24*time.Hour && model.String(s, "config_hash") == StorageConfigurationHash(resource) && model.String(s, "content_hash") == model.String(latest, "content_hash")
	}
	if wid := model.String(resource, "workload_id"); wid != "" {
		p, e := t.WorkloadSafetyLatest(ctx, wid)
		if e != nil && !errors.Is(e, pgx.ErrNoRows) {
			return nil, e
		}
		if model.String(p, "id") != profileID {
			current = false
		}
	}
	if current {
		refs := storageRows(storageObject(d["assessment"])["source_refs"])
		for _, ref := range refs {
			if model.String(ref, "kind") == "AWS_CUR2_CONNECTION" {
				current, e = databaseBillingReferencesCurrent(ctx, t, refs)
				if e != nil {
					return nil, e
				}
				break
			}
		}
	}
	if current {
		current, e = storageAuthorityReferencesCurrent(ctx, t, resource, storageRows(storageObject(d["assessment"])["source_refs"]), a.now())
		if e != nil {
			return nil, e
		}
	}
	d["current"] = current
	if !current {
		d["currentness_blockers"] = []string{"STORAGE_SOURCE_OR_CONFIGURATION_CHANGED"}
	}
	return a.recommendationCurrentness(ctx, t, "STORAGE", d)
}
func (a *API) storageRecommendationGet(ctx context.Context, t *store.Tx, id string) (model.Document, error) {
	var raw []byte
	if e := t.QueryRow(ctx, "SELECT document FROM storage_recommendation_publications WHERE tenant_id=$1 AND assessment_id=$2", t.Tenant, id).Scan(&raw); e != nil {
		return nil, e
	}
	var d model.Document
	if e := json.Unmarshal(raw, &d); e != nil {
		return nil, e
	}
	return a.storageRecommendationCurrent(ctx, t, d)
}
func (a *API) storageRecommendationCurrent(ctx context.Context, t *store.Tx, d model.Document) (model.Document, error) {
	row, e := t.StorageAssessmentGet(ctx, model.String(d, "storage_assessment_id"))
	if e != nil {
		return nil, e
	}
	row, e = a.storageAssessmentCurrent(ctx, t, row)
	if e != nil {
		return nil, e
	}
	return recommendationCurrentnessCopy(d, row), nil
}
func (a *API) storageRecommendations(ctx context.Context, t *store.Tx) ([]model.Document, error) {
	var exists bool
	if e := t.QueryRow(ctx, "SELECT EXISTS(SELECT FROM entities WHERE tenant_id=$1 AND kind='resources' AND document->>'resource_type' IN('EBS_VOLUME','EBS_SNAPSHOT'))", t.Tenant).Scan(&exists); e != nil {
		return nil, e
	}
	if !exists {
		return []model.Document{}, nil
	}
	rows, e := t.Query(ctx, `SELECT p.document FROM storage_recommendation_publications p WHERE p.tenant_id=$1 AND NOT EXISTS(SELECT FROM storage_recommendation_publications n WHERE n.tenant_id=p.tenant_id AND n.resource_id=p.resource_id AND (n.created_at,n.assessment_id)>(p.created_at,p.assessment_id)) ORDER BY p.created_at,p.assessment_id LIMIT 100`, t.Tenant)
	if e != nil {
		return nil, e
	}
	out := []model.Document{}
	for rows.Next() {
		var raw []byte
		if e = rows.Scan(&raw); e != nil {
			break
		}
		var d model.Document
		if e = json.Unmarshal(raw, &d); e != nil {
			break
		}
		out = append(out, d)
	}
	if e == nil {
		e = rows.Err()
	}
	rows.Close()
	if e != nil {
		return nil, e
	}
	for j := range out {
		out[j], e = a.storageRecommendationCurrent(ctx, t, out[j])
		if e != nil {
			return nil, e
		}
	}
	return out, nil
}
