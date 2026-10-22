package service

import (
	"context"
	"encoding/json"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
)

func awsServiceCoverageLines(result model.Document) map[string]bool {
	out := map[string]bool{}
	economics := storageObject(result["economics"])
	if result["model_kind"] != "AWS_SERVICE_ASSESSMENT_V1" || result["family"] == "ELB" || result["read_only"] != true || result["execution_authorized"] != false || result["pre_execution_ready"] != false || result["verified_saving"] != nil || result["status"] != "RECOMMENDED" && result["status"] != "NO_CHANGE" || economics["status"] != "NATIVE_CUSTOMER_ECONOMICS" {
		return out
	}
	claimed := map[string]bool{}
	for _, id := range model.Strings(result, "economically_analysed_source_record_ids") {
		claimed[id] = true
	}
	for _, ref := range storageRows(result["financial_references"]) {
		if ref["kind"] != "AWS_CUR2_CONNECTION" {
			continue
		}
		for _, id := range model.Strings(ref, "economic_record_ids") {
			if claimed[id] {
				out[databaseCoverageLineKey(ref, id)] = true
			}
		}
	}
	return out
}

func (a *API) awsServiceCoveragePublications(ctx context.Context, t *store.Tx) (map[string]lambdaCoveragePublication, error) {
	rows, e := t.Query(ctx, `SELECT document FROM (SELECT DISTINCT ON(resource_id) resource_id,document,created_at,id FROM aws_service_assessments WHERE tenant_id=$1 ORDER BY resource_id,created_at DESC,id DESC) q ORDER BY resource_id LIMIT $2`, t.Tenant, databaseCoverageLimit+1)
	if e != nil {
		return nil, e
	}
	docs := []model.Document{}
	for rows.Next() {
		var raw []byte
		if e = rows.Scan(&raw); e != nil {
			break
		}
		docs = append(docs, storageObject(json.RawMessage(raw)))
	}
	if e == nil {
		e = rows.Err()
	}
	rows.Close()
	if e != nil {
		return nil, e
	}
	if len(docs) > databaseCoverageLimit {
		return nil, problem(422, "AWS_SERVICE_COVERAGE_BOUND", "assessment coverage bound exceeded")
	}
	out := map[string]lambdaCoveragePublication{}
	for _, record := range docs {
		result := storageObject(record["assessment"])
		p := lambdaCoveragePublication{lines: map[string]bool{}, blocked: record["status"] == "BLOCKED" || result["status"] == "BLOCKED", currency: model.String(storageObject(result["economics"]), "currency")}
		if record["status"] == "ASSESSED" {
			current, e := a.awsServiceAssessmentCurrent(ctx, t, record)
			if e != nil {
				return nil, e
			}
			if current["current"] == true {
				p.lines = awsServiceCoverageLines(result)
			} else {
				p.blocked = true
			}
		}
		out[model.String(record, "resource_id")] = p
		// Native Fargate billing keeps task ResourceId. Service analysis claims
		// only the exact immutable charge keys, never an alias for every task.
		for line := range p.lines {
			key := "line:" + line
			if _, exists := out[key]; exists {
				out[key] = lambdaCoveragePublication{blocked: true, lines: map[string]bool{}}
			} else {
				out[key] = p
			}
		}
	}
	return out, nil
}

func awsServiceCoverageLineCategory(publications map[string]lambdaCoveragePublication, line, currency string) (string, bool) {
	p, ok := publications["line:"+line]
	if !ok {
		return "", false
	}
	if p.blocked || p.currency != currency || !p.lines[line] {
		return "blocked_spend", true
	}
	return "analysed_spend", true
}
