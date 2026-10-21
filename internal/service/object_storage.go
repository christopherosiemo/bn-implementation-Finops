package service

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/auth"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/evidence"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/objectstorage"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/jackc/pgx/v5"
	"math/big"
	"net/http"
	"strings"
)

func objectStorageResource(r model.Document) bool {
	return model.String(r, "provider") == "AWS" && model.String(r, "resource_type") == "S3_BUCKET"
}
func (a *API) objectStorageMutate(ctx context.Context, t *store.Tx, i auth.Identity, r *http.Request, in model.Document) (model.Document, int, bool, error) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/v1/"), "/")
	if parts[0] != "object-storage-datasets" && parts[0] != "object-storage-assessments" {
		return nil, 0, false, nil
	}
	if e := requireRole(i, "FINOPS_ADMIN", "PLATFORM_ADMIN", "APPLICATION_OWNER"); e != nil {
		return nil, 0, true, e
	}
	if parts[0] == "object-storage-assessments" {
		if len(parts) != 1 {
			return nil, 0, true, problem(404, "NOT_FOUND", "unknown object assessment operation")
		}
		if len(in) < 1 || len(in) > 2 || model.String(in, "resource_id") == "" {
			return nil, 0, true, problem(422, "OBJECT_STORAGE_IDS_ONLY", "select resource_id and optional registered dataset_id")
		}
		for k := range in {
			if k != "resource_id" && k != "dataset_id" {
				return nil, 0, true, problem(422, "OBJECT_STORAGE_IDS_ONLY", "observations and economics are server-selected")
			}
		}
		if e := match(r, model.Document{"version": 0}); e != nil {
			return nil, 0, true, e
		}
		if e := storageReadScope(ctx, t, i, model.String(in, "resource_id")); e != nil {
			return nil, 0, true, e
		}
		out, e := t.ObjectStorageAssessmentCreate(ctx, model.String(in, "resource_id"), model.String(in, "dataset_id"), i.Subject)
		if e == nil {
			e = t.Audit(ctx, i.Subject, "object_storage.assessment.requested", model.String(out, "id"), model.Document{"resource_id": in["resource_id"], "execution_authorized": false})
		}
		return out, 202, true, e
	}
	if len(parts) != 1 && (len(parts) != 3 || parts[2] != "revisions") {
		return nil, 0, true, problem(404, "NOT_FOUND", "unknown dataset operation")
	}
	d := model.Clone(in)
	for k := range d {
		if k != "resource_id" && k != "name" && k != "selector" && k != "policy" {
			return nil, 0, true, problem(422, "DATASET_FIELDS_INVALID", "only declaration fields are accepted")
		}
	}
	if len(parts) == 3 {
		if _, e := t.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", t.Tenant+":object-dataset:"+parts[1]); e != nil {
			return nil, 0, true, e
		}
		old, e := t.ObjectStorageDatasetGet(ctx, parts[1])
		if e != nil {
			return nil, 0, true, e
		}
		if e = match(r, old); e != nil {
			return nil, 0, true, e
		}
		if v := model.String(d, "resource_id"); v != "" && v != model.String(old, "resource_id") {
			return nil, 0, true, problem(422, "DATASET_RESOURCE_IMMUTABLE", "dataset bucket is immutable")
		}
		d["id"], d["version"], d["resource_id"] = old["id"], model.Number(old, "version")+1, old["resource_id"]
	} else {
		if e := match(r, model.Document{"version": 0}); e != nil {
			return nil, 0, true, e
		}
		d["id"], d["version"] = model.ID(), 1
	}
	rid := model.String(d, "resource_id")
	if e := storageReadScope(ctx, t, i, rid); e != nil {
		return nil, 0, true, e
	}
	resource, e := t.Get(ctx, "resources", rid)
	if e != nil {
		return nil, 0, true, e
	}
	if !objectStorageResource(resource) {
		return nil, 0, true, problem(422, "S3_BUCKET_REQUIRED", "select a discovered S3 bucket")
	}
	if e = validateObjectStorageDataset(d); e != nil {
		return nil, 0, true, e
	}
	if wid := model.String(storageObject(d["selector"]), "workload_id"); wid != "" && wid != model.String(resource, "workload_id") {
		return nil, 0, true, problem(422, "OBJECT_STORAGE_DATASET_WORKLOAD_MISMATCH", "selector workload must match the registered bucket workload")
	}
	out, e := t.ObjectStorageDatasetAppend(ctx, d, i.Subject)
	if e == nil {
		e = t.Audit(ctx, i.Subject, "object_storage.dataset.declared", model.String(out, "id"), model.Document{"resource_id": rid, "version": out["version"], "execution_authorized": false})
	}
	return out, 201, true, e
}
func validateObjectStorageDataset(d model.Document) error {
	bad := func() error {
		return problem(422, "OBJECT_STORAGE_DATASET_INVALID", "provide a bounded named selector and declared safety policy; unknown values remain null")
	}
	if n := model.String(d, "name"); n == "" || len(n) > 200 {
		return bad()
	}
	s := storageObject(d["selector"])
	if len(s) == 0 {
		return bad()
	}
	for k := range s {
		if k != "kind" && k != "prefix" && k != "tags" && k != "workload_id" && k != "storage_classes" {
			return bad()
		}
	}
	var typed objectstorage.DatasetSelector
	raw, e := json.Marshal(d["selector"])
	if e != nil || json.Unmarshal(raw, &typed) != nil {
		return bad()
	}
	if len(typed.StorageClasses) > 16 {
		return bad()
	}
	seenClasses := map[string]bool{}
	for _, class := range typed.StorageClasses {
		switch class {
		case "STANDARD", "STANDARD_IA", "ONEZONE_IA", "INTELLIGENT_TIERING", "GLACIER_IR", "GLACIER", "DEEP_ARCHIVE":
		default:
			return bad()
		}
		if seenClasses[class] {
			return bad()
		}
		seenClasses[class] = true
	}
	for key, value := range typed.Tags {
		if key == "" || len(key) > 128 || len(value) > 256 || strings.ContainsAny(key+value, "\x00\r\n") {
			return bad()
		}
	}
	switch model.String(s, "kind") {
	case "BUCKET", "PREFIX", "TAG_GROUP", "WORKLOAD_DATASET", "STORAGE_POLICY":
	default:
		return bad()
	}
	if p := model.String(s, "prefix"); len(p) > 1024 || strings.ContainsAny(p, "\x00\r\n") {
		return bad()
	}
	if model.String(s, "kind") == "PREFIX" && model.String(s, "prefix") == "" {
		return bad()
	}
	tags := storageObject(s["tags"])
	if len(tags) > 20 {
		return bad()
	}
	if model.String(s, "kind") == "TAG_GROUP" && len(tags) == 0 {
		return bad()
	}
	p := storageObject(d["policy"])
	for k, v := range p {
		switch k {
		case "criticality":
			switch v {
			case "NON_PRODUCTION", "TIER_0", "TIER_1", "TIER_2", "TIER_3", nil:
			default:
				return bad()
			}
		case "high_seasonality", "retention_known", "compliance_clear", "recovery_known", "allow_onezone", "dependencies_reviewed":
			if v != nil {
				if _, ok := v.(bool); !ok {
					return bad()
				}
			}
		case "remaining_lifetime_days", "rto_seconds":
			if v != nil {
				n, ok := databaseDecimal(v)
				if _, str := v.(string); !ok || !str || n.Sign() < 0 {
					return bad()
				}
				if k == "remaining_lifetime_days" && (n.Sign() == 0 || n.Cmp(big.NewRat(36500, 1)) > 0) {
					return bad()
				}
			}
		default:
			return bad()
		}
	}
	return nil
}
func (a *API) objectStorageGet(ctx context.Context, t *store.Tx, i auth.Identity, r *http.Request) (any, bool, error) {
	p := strings.Split(strings.TrimPrefix(r.URL.Path, "/v1/"), "/")
	if p[0] == "object-storage-assessments" || p[0] == "object-storage-datasets" {
		dataset := p[0] == "object-storage-datasets"
		if len(p) == 2 {
			var d model.Document
			var e error
			if dataset {
				d, e = t.ObjectStorageDatasetGet(ctx, p[1])
			} else {
				d, e = t.ObjectStorageAssessmentGet(ctx, p[1])
			}
			if e == nil {
				e = storageReadScope(ctx, t, i, model.String(d, "resource_id"))
			}
			if e == nil && !dataset {
				d, e = a.objectStorageCurrent(ctx, t, d)
			}
			return d, true, e
		}
		if len(p) != 1 {
			return nil, true, problem(404, "NOT_FOUND", "unknown object storage resource")
		}
		rid := r.URL.Query().Get("resource_id")
		if e := storageReadScope(ctx, t, i, rid); e != nil {
			return nil, true, e
		}
		after, n, e := storagePage(r, t.Tenant, i.Subject)
		if e != nil {
			return nil, true, e
		}
		var rows []model.Document
		if dataset {
			rows, e = t.ObjectStorageDatasetPage(ctx, after, rid, n+1)
		} else {
			rows, e = t.ObjectStorageAssessmentPage(ctx, after, rid, n+1)
		}
		if e != nil {
			return nil, true, e
		}
		next := ""
		if len(rows) > n {
			rows = rows[:n]
			next = model.String(rows[n-1], "id")
		}
		if !dataset {
			for j := range rows {
				rows[j], e = a.objectStorageCurrent(ctx, t, rows[j])
				if e != nil {
					return nil, true, e
				}
			}
		}
		return model.Document{"items": rows, "next_cursor": storageNextCursor(r, t.Tenant, i.Subject, next)}, true, nil
	}
	if p[0] == "recommendations" && len(p) == 2 && strings.HasPrefix(p[1], "object-storage-") {
		d, e := a.objectStorageRecommendation(ctx, t, strings.TrimPrefix(p[1], "object-storage-"))
		if e == nil {
			e = storageReadScope(ctx, t, i, model.String(d, "resource_id"))
		}
		return d, true, e
	}
	if p[0] == "recommendations" && len(p) == 1 && r.URL.Query().Get("model_kind") == "OBJECT_STORAGE_ASSESSMENT_V1" {
		rid := r.URL.Query().Get("resource_id")
		if e := storageReadScope(ctx, t, i, rid); e != nil {
			return nil, true, e
		}
		after, n, e := storagePage(r, t.Tenant, i.Subject)
		if e != nil {
			return nil, true, e
		}
		rows, e := t.ObjectStorageAssessmentPage(ctx, after, rid, n+1)
		if e != nil {
			return nil, true, e
		}
		next := ""
		if len(rows) > n {
			rows = rows[:n]
			next = model.String(rows[n-1], "id")
		}
		out := []model.Document{}
		for _, row := range rows {
			d, e := a.objectStorageRecommendation(ctx, t, model.String(row, "id"))
			if errors.Is(e, pgx.ErrNoRows) {
				continue
			}
			if e != nil {
				return nil, true, e
			}
			out = append(out, d)
		}
		return model.Document{"items": out, "next_cursor": storageNextCursor(r, t.Tenant, i.Subject, next)}, true, nil
	}
	if p[0] == "resources" && len(p) == 1 && r.URL.Query().Get("resource_type") == "S3_BUCKET" {
		after, n, e := storagePage(r, t.Tenant, i.Subject)
		if e != nil {
			return nil, true, e
		}
		rows, e := t.Query(ctx, `SELECT r.document||jsonb_build_object('id',r.id,'version',r.version) FROM entities r WHERE r.tenant_id=$1 AND r.kind='resources' AND r.document->>'resource_type'='S3_BUCKET' AND r.id>$2 AND (NOT $3 OR EXISTS(SELECT FROM entities w WHERE w.tenant_id=r.tenant_id AND w.kind='workloads' AND w.id=r.document->>'workload_id' AND w.document->>'owner_subject'=$4)) ORDER BY r.id LIMIT $5`, t.Tenant, after, scopedOwner(i), i.Subject, n+1)
		if e != nil {
			return nil, true, e
		}
		out := []model.Document{}
		for rows.Next() {
			var raw []byte
			if e = rows.Scan(&raw); e != nil {
				break
			}
			out = append(out, storageObject(jsonRaw(raw)))
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
	return nil, false, nil
}
func (a *API) objectStorageRecommendation(ctx context.Context, t *store.Tx, id string) (model.Document, error) {
	var raw []byte
	if e := t.QueryRow(ctx, "SELECT document FROM object_storage_recommendation_publications WHERE tenant_id=$1 AND assessment_id=$2", t.Tenant, id).Scan(&raw); e != nil {
		return nil, e
	}
	d := storageObject(jsonRaw(raw))
	row, e := t.ObjectStorageAssessmentGet(ctx, id)
	if e != nil {
		return nil, e
	}
	row, e = a.objectStorageCurrent(ctx, t, row)
	if e != nil {
		return nil, e
	}
	return recommendationCurrentnessCopy(d, row), nil
}
func jsonRaw(b []byte) any { return json.RawMessage(b) }
func objectStorageDatasetHash(d model.Document) string {
	return evidence.Hash(model.Document{"id": d["id"], "version": d["version"], "resource_id": d["resource_id"], "selector": d["selector"], "policy": d["policy"]})
}
