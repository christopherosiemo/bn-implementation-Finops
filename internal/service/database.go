package service

import (
	"context"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/auth"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
)

var databaseCursor = regexp.MustCompile(`^[a-f0-9-]{0,64}$`)

func databaseResource(d model.Document) bool {
	return model.String(d, "resource_type") == "RDS_INSTANCE" || model.String(d, "resource_type") == "RDS_CLUSTER"
}

func (a *API) databaseMutate(ctx context.Context, t *store.Tx, i auth.Identity, r *http.Request, in model.Document) (model.Document, int, bool, error) {
	if r.URL.Path != "/v1/database-assessments" {
		return nil, 0, false, nil
	}
	if e := requireRole(i, "PLATFORM_ADMIN", "FINOPS_ADMIN", "APPLICATION_OWNER"); e != nil {
		return nil, 0, true, e
	}
	if len(in) != 1 || model.String(in, "resource_id") == "" {
		return nil, 0, true, problem(422, "DATABASE_IDS_ONLY", "select a resource_id; evidence, configuration and amounts are server-resolved")
	}
	if e := match(r, model.Document{"version": 0}); e != nil {
		return nil, 0, true, e
	}
	resource, e := t.Get(ctx, "resources", model.String(in, "resource_id"))
	if e != nil {
		return nil, 0, true, e
	}
	if !databaseResource(resource) {
		return nil, 0, true, problem(422, "DATABASE_RESOURCE_REQUIRED", "select a discovered RDS instance or database cluster")
	}
	if i.Roles["APPLICATION_OWNER"] && !i.Can("PLATFORM_ADMIN", "FINOPS_ADMIN") {
		wid := model.String(resource, "workload_id")
		w, e := t.Get(ctx, "workloads", wid)
		if e != nil || model.String(w, "owner_subject") != i.Subject {
			return nil, 0, true, problem(403, "FORBIDDEN", "only the registered workload owner can request its assessment")
		}
	}
	out, e := t.DatabaseAssessmentCreate(ctx, model.String(resource, "id"), i.Subject)
	if e == nil {
		e = t.Audit(ctx, i.Subject, "database.assessment.requested", model.String(out, "id"), model.Document{"resource_id": resource["id"], "execution_authorized": false})
	}
	return out, 202, true, e
}

func (a *API) databaseGet(ctx context.Context, t *store.Tx, i auth.Identity, r *http.Request) (any, bool, error) {
	path := strings.TrimPrefix(r.URL.Path, "/v1/")
	parts := strings.Split(path, "/")
	if scopedOwner(i) && path == "coverage" {
		return nil, true, problem(403, "WORKLOAD_SCOPE_DENIED", "coverage requires an organisation-wide financial role")
	}
	if path == "coverage" {
		out, e := a.databaseCoverage(ctx, t)
		return out, true, e
	}
	if parts[0] == "database-assessments" {
		if len(parts) == 2 {
			d, e := t.DatabaseAssessmentGet(ctx, parts[1])
			if e == nil {
				e = databaseReadScope(ctx, t, i, model.String(d, "resource_id"))
			}
			if e == nil {
				d, e = a.databaseAssessmentCurrent(ctx, t, d)
			}
			return d, true, e
		}
		if len(parts) != 1 {
			return nil, true, problem(404, "NOT_FOUND", "database assessment not found")
		}
		if e := databaseReadScope(ctx, t, i, r.URL.Query().Get("resource_id")); e != nil {
			return nil, true, e
		}
		after := r.URL.Query().Get("cursor")
		if !databaseCursor.MatchString(after) {
			return nil, true, problem(422, "INVALID_CURSOR", "invalid assessment cursor")
		}
		n := 25
		if raw := r.URL.Query().Get("limit"); raw != "" {
			var e error
			n, e = strconv.Atoi(raw)
			if e != nil || n < 1 || n > 100 {
				return nil, true, problem(422, "INVALID_LIMIT", "limit must be 1 through 100")
			}
		}
		rows, e := t.DatabaseAssessmentPage(ctx, after, r.URL.Query().Get("resource_id"), n+1)
		if e != nil {
			return nil, true, e
		}
		next := ""
		if len(rows) > n {
			rows = rows[:n]
			next = model.String(rows[len(rows)-1], "id")
		}
		for j := range rows {
			rows[j], e = a.databaseAssessmentCurrent(ctx, t, rows[j])
			if e != nil {
				return nil, true, e
			}
		}
		return model.Document{"items": rows, "next_cursor": nullableDatabaseString(next)}, true, nil
	}
	if parts[0] == "recommendations" && len(parts) == 2 && strings.HasPrefix(parts[1], "database-") {
		d, e := a.databaseRecommendationGet(ctx, t, strings.TrimPrefix(parts[1], "database-"))
		if e == nil {
			e = databaseReadScope(ctx, t, i, model.String(d, "resource_id"))
		}
		return d, true, e
	}
	if path == "recommendations" && r.URL.Query().Get("model_kind") == "DATABASE_ASSESSMENT_V1" {
		if e := databaseReadScope(ctx, t, i, r.URL.Query().Get("resource_id")); e != nil {
			return nil, true, e
		}
		after := r.URL.Query().Get("cursor")
		if !databaseCursor.MatchString(after) {
			return nil, true, problem(422, "INVALID_CURSOR", "invalid recommendation cursor")
		}
		n := 25
		if raw := r.URL.Query().Get("limit"); raw != "" {
			var e error
			n, e = strconv.Atoi(raw)
			if e != nil || n < 1 || n > 100 {
				return nil, true, problem(422, "INVALID_LIMIT", "limit must be 1 through 100")
			}
		}
		rows, e := t.Query(ctx, "SELECT assessment_id FROM database_recommendation_publications WHERE tenant_id=$1 AND assessment_id>$2 AND ($3='' OR resource_id=$3) ORDER BY assessment_id LIMIT $4", t.Tenant, after, r.URL.Query().Get("resource_id"), n+1)
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
			d, e := a.databaseRecommendationGet(ctx, t, id)
			if e != nil {
				return nil, true, e
			}
			out = append(out, d)
		}
		return model.Document{"items": out, "next_cursor": nullableDatabaseString(next)}, true, nil
	}
	if path == "resources" && r.URL.Query().Get("resource_type") != "" {
		kind := r.URL.Query().Get("resource_type")
		if kind != "RDS_INSTANCE" && kind != "RDS_CLUSTER" {
			return nil, true, problem(422, "DATABASE_RESOURCE_TYPE_REQUIRED", "use RDS_INSTANCE or RDS_CLUSTER")
		}
		after := r.URL.Query().Get("cursor")
		if !databaseCursor.MatchString(after) {
			return nil, true, problem(422, "INVALID_CURSOR", "invalid resource cursor")
		}
		n := 50
		if raw := r.URL.Query().Get("limit"); raw != "" {
			var e error
			n, e = strconv.Atoi(raw)
			if e != nil || n < 1 || n > 100 {
				return nil, true, problem(422, "INVALID_LIMIT", "limit must be 1 through 100")
			}
		}
		rows, e := t.Query(ctx, `SELECT r.id FROM entities r WHERE r.tenant_id=$1 AND r.kind='resources' AND r.document->>'resource_type'=$2 AND r.id>$3
  AND (NOT $4 OR EXISTS(SELECT FROM entities w WHERE w.tenant_id=r.tenant_id AND w.kind='workloads' AND w.id=r.document->>'workload_id' AND w.document->>'owner_subject'=$5)) ORDER BY r.id LIMIT $6`, t.Tenant, kind, after, scopedOwner(i), i.Subject, n+1)
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
		return model.Document{"items": out, "next_cursor": nullableDatabaseString(next)}, true, nil
	}
	return nil, false, nil
}
func nullableDatabaseString(s string) any {
	if s == "" {
		return nil
	}
	return s
}
func databaseReadScope(ctx context.Context, t *store.Tx, i auth.Identity, resourceID string) error {
	if !scopedOwner(i) {
		return nil
	}
	if resourceID == "" {
		return problem(403, "WORKLOAD_SCOPE_DENIED", "select an owned database resource")
	}
	r, e := t.Get(ctx, "resources", resourceID)
	if e != nil {
		return e
	}
	w, e := t.Get(ctx, "workloads", model.String(r, "workload_id"))
	if e != nil || model.String(w, "owner_subject") != i.Subject {
		return problem(403, "WORKLOAD_SCOPE_DENIED", "database belongs to another workload owner")
	}
	return nil
}

func (a *API) databaseAssessmentCurrent(ctx context.Context, t *store.Tx, d model.Document) (model.Document, error) {
	if model.String(d, "status") == "QUEUED" || model.String(d, "status") == "RUNNING" {
		return d, nil
	}
	row, e := t.Get(ctx, "resources", model.String(d, "resource_id"))
	if e != nil {
		return nil, e
	}
	var snapshotID, profileID string
	if e = t.QueryRow(ctx, "SELECT coalesce(snapshot_id,''),coalesce(safety_profile_id,'') FROM database_assessments WHERE tenant_id=$1 AND id=$2", t.Tenant, d["id"]).Scan(&snapshotID, &profileID); e != nil {
		return nil, e
	}
	if snapshotID == "" {
		d["current"] = false
		return d, nil
	}
	snap, e := t.DatabaseEvidenceGet(ctx, snapshotID)
	if e != nil {
		return nil, e
	}
	current := model.String(snap, "config_hash") == DatabaseConfigurationHash(row)
	observed, observedErr := time.Parse(time.RFC3339Nano, model.String(snap, "observed_at"))
	if observedErr != nil || observed.After(a.now().UTC().Add(time.Minute)) || a.now().UTC().Sub(observed) > 24*time.Hour {
		current = false
	}
	latest, snapshotErr := t.DatabaseEvidenceLatest(ctx, model.String(row, "id"))
	if snapshotErr != nil {
		return nil, snapshotErr
	}
	if model.String(latest, "content_hash") != model.String(snap, "content_hash") {
		current = false
	}
	profile, profileErr := t.WorkloadSafetyLatest(ctx, model.String(row, "workload_id"))
	if profileErr != nil || profileID == "" || model.String(profile, "id") != profileID {
		current = false
	}
	if current {
		current, e = databaseBillingReferencesCurrent(ctx, t, documentList(databaseObject(d["assessment"])["source_refs"]))
		if e != nil {
			return nil, e
		}
	}
	d["current"] = current
	if !current {
		d["currentness_blockers"] = []string{"DATABASE_SOURCE_OR_CONFIGURATION_CHANGED"}
	}
	return d, nil
}
func (a *API) databaseRecommendationGet(ctx context.Context, t *store.Tx, id string) (model.Document, error) {
	var raw []byte
	e := t.QueryRow(ctx, "SELECT document FROM database_recommendation_publications WHERE tenant_id=$1 AND assessment_id=$2", t.Tenant, id).Scan(&raw)
	if e != nil {
		return nil, e
	}
	d, e := decodeDatabaseDocument(raw)
	if e != nil {
		return nil, e
	}
	return a.databaseRecommendationCurrent(ctx, t, d)
}
func (a *API) databaseRecommendations(ctx context.Context, t *store.Tx) ([]model.Document, error) {
	var hasDatabases bool
	if e := t.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM entities WHERE tenant_id=$1 AND kind='resources' AND document->>'resource_type' IN ('RDS_INSTANCE','RDS_CLUSTER'))`, t.Tenant).Scan(&hasDatabases); e != nil {
		return nil, e
	}
	if !hasDatabases {
		return []model.Document{}, nil
	}
	rows, e := t.Query(ctx, `SELECT p.document FROM database_recommendation_publications p JOIN database_assessments a ON a.tenant_id=p.tenant_id AND a.id=p.assessment_id
 WHERE p.tenant_id=$1 AND NOT EXISTS(SELECT FROM database_recommendation_publications n WHERE n.tenant_id=p.tenant_id AND n.resource_id=p.resource_id AND (n.created_at,n.assessment_id)>(p.created_at,p.assessment_id)) ORDER BY p.created_at,p.assessment_id LIMIT 100`, t.Tenant)
	if e != nil {
		return nil, e
	}
	out := []model.Document{}
	for rows.Next() {
		var raw []byte
		if e = rows.Scan(&raw); e != nil {
			break
		}
		d, decodeErr := decodeDatabaseDocument(raw)
		if decodeErr != nil {
			e = decodeErr
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
		out[j], e = a.databaseRecommendationCurrent(ctx, t, out[j])
		if e != nil {
			return nil, e
		}
	}
	return out, nil
}

func (a *API) databaseRecommendationCurrent(ctx context.Context, t *store.Tx, d model.Document) (model.Document, error) {
	row, e := t.DatabaseAssessmentGet(ctx, model.String(d, "database_assessment_id"))
	if e != nil {
		return nil, e
	}
	row, e = a.databaseAssessmentCurrent(ctx, t, row)
	if e != nil {
		return nil, e
	}
	d["current"] = model.Bool(row, "current")
	if row["currentness_blockers"] != nil {
		d["currentness_blockers"] = row["currentness_blockers"]
	}
	return d, nil
}
