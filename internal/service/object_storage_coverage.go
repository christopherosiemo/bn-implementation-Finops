package service

import (
	"context"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
)

type objectStorageCoveragePublication struct {
	blocked bool
	lines   map[string]bool
}

// Prefix allocations remain modelled. Only a complete bucket population with a
// native-cost comparison for every observed cohort can classify its exact lines.
func (a *API) objectStorageCoveragePublications(ctx context.Context, t *store.Tx) (map[string]objectStorageCoveragePublication, error) {
	rows, e := t.Query(ctx, `SELECT document FROM (SELECT DISTINCT ON(resource_id,coalesce(dataset_id,'')) resource_id,dataset_id,document FROM object_storage_assessments WHERE tenant_id=$1 AND status IN('ASSESSED','BLOCKED') ORDER BY resource_id,coalesce(dataset_id,''),created_at DESC,id DESC) x LIMIT $2`, t.Tenant, databaseCoverageLimit+1)
	if e != nil {
		return nil, e
	}
	records := []model.Document{}
	for rows.Next() {
		var raw []byte
		if e = rows.Scan(&raw); e != nil {
			break
		}
		records = append(records, storageObject(jsonRaw(raw)))
	}
	if e == nil {
		e = rows.Err()
	}
	rows.Close()
	if e != nil {
		return nil, e
	}
	if len(records) > databaseCoverageLimit {
		return nil, problem(422, "OBJECT_STORAGE_COVERAGE_LIMIT", "assessment coverage bound exceeded")
	}
	out := map[string]objectStorageCoveragePublication{}
	for _, d := range records {
		rid := model.String(d, "resource_id")
		p := out[rid]
		if p.lines == nil {
			p.lines = map[string]bool{}
		}
		current, e := a.objectStorageCurrent(ctx, t, d)
		if e != nil {
			return nil, e
		}
		assessment := storageObject(d["assessment"])
		if model.String(assessment, "status") == "BLOCKED" {
			p.blocked = true
		}
		if current["current"] != true {
			out[rid] = p
			continue
		}
		did := model.String(d, "dataset_id")
		if did == "" {
			out[rid] = p
			continue
		}
		dataset, e := t.ObjectStorageDatasetGet(ctx, did)
		if e != nil {
			return nil, e
		}
		selector := storageObject(dataset["selector"])
		if model.String(selector, "kind") != "BUCKET" || model.String(selector, "prefix") != "" || len(storageObject(selector["tags"])) > 0 || len(model.Strings(selector, "storage_classes")) > 0 || model.String(selector, "workload_id") != "" {
			out[rid] = p
			continue
		}
		eligible := map[string]bool{}
		for _, c := range storageRows(assessment["candidates"]) {
			status := model.String(c, "status")
			econ := storageObject(c["economics"])
			if (status == "RECOMMENDED" || status == "NO_CHANGE") && model.String(econ, "status") == "AVAILABLE" && model.String(econ, "basis") == "AWS_CUR_NET_USAGE" {
				eligible[model.String(c, "cohort_id")] = true
			}
		}
		complete := true
		cohorts := storageRows(assessment["cohorts"])
		if len(cohorts) == 0 {
			complete = false
		}
		for _, c := range cohorts {
			if !eligible[model.String(c, "id")] || !model.Bool(c, "inventory_complete") {
				complete = false
			}
		}
		if complete {
			for _, ref := range storageRows(assessment["financial_references"]) {
				for _, id := range model.Strings(ref, "economic_record_ids") {
					p.lines[databaseCoverageLineKey(ref, id)] = true
				}
			}
		}
		out[rid] = p
	}
	return out, nil
}
