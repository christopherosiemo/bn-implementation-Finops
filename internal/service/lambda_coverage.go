package service

import (
	"context"
	"encoding/json"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
)

type lambdaCoveragePublication struct {
	blocked  bool
	currency string
	lines    map[string]bool
}

func lambdaCoverageEconomicLines(a model.Document) map[string]bool {
	out := map[string]bool{}
	e := storageObject(a["economics"])
	if model.String(a, "model_kind") != "LAMBDA_ASSESSMENT_V1" || a["read_only"] != true || a["pre_execution_ready"] != false || a["execution_authorized"] != false || a["verified_saving"] != nil || (a["status"] != "RECOMMENDED" && a["status"] != "NO_CHANGE") || model.String(e, "status") != "NATIVE_CUSTOMER_ECONOMICS" {
		return out
	}
	claimed := map[string]bool{}
	for _, id := range model.Strings(a, "economically_analysed_source_record_ids") {
		claimed[id] = true
	}
	for _, r := range storageRows(a["financial_references"]) {
		if model.String(r, "kind") != "AWS_CUR2_CONNECTION" {
			continue
		}
		for _, id := range model.Strings(r, "economic_record_ids") {
			if claimed[id] {
				out[databaseCoverageLineKey(r, id)] = true
			}
		}
	}
	return out
}
func (a *API) lambdaCoveragePublications(ctx context.Context, t *store.Tx) (map[string]lambdaCoveragePublication, error) {
	records, e := t.Query(ctx, `SELECT document FROM (SELECT DISTINCT ON(resource_id,qualifier) resource_id,qualifier,document,created_at,id FROM lambda_assessments WHERE tenant_id=$1 ORDER BY resource_id,qualifier,created_at DESC,id DESC) q ORDER BY resource_id,qualifier LIMIT $2`, t.Tenant, databaseCoverageLimit+1)
	if e != nil {
		return nil, e
	}
	docs := []model.Document{}
	for records.Next() {
		var raw []byte
		if e = records.Scan(&raw); e != nil {
			break
		}
		docs = append(docs, storageObject(json.RawMessage(raw)))
	}
	if e == nil {
		e = records.Err()
	}
	records.Close()
	if e != nil {
		return nil, e
	}
	if len(docs) > databaseCoverageLimit {
		return nil, problem(422, "LAMBDA_COVERAGE_ASSESSMENT_LIMIT", "Lambda coverage bound exceeded")
	}
	out := map[string]lambdaCoveragePublication{}
	for _, d := range docs {
		result := storageObject(d["assessment"])
		rid := model.String(d, "resource_id")
		p := out[rid]
		if p.lines == nil {
			p.lines = map[string]bool{}
		}
		if d["status"] == "BLOCKED" || result["status"] == "BLOCKED" {
			p.blocked = true
		}
		if d["status"] == "ASSESSED" {
			current, e := a.lambdaCurrent(ctx, t, d)
			if e != nil {
				return nil, e
			}
			if current["current"] == true {
				currency := model.String(storageObject(result["economics"]), "currency")
				if p.currency != "" && p.currency != currency {
					p.lines = map[string]bool{}
					p.blocked = true
				} else {
					p.currency = currency
					for k := range lambdaCoverageEconomicLines(result) {
						p.lines[k] = true
					}
				}
			} else {
				p.blocked = true
			}
		}
		out[rid] = p
	}
	return out, nil
}
func lambdaCharge(record model.Document) bool {
	return model.String(record, "ServiceName") == "AWSLambda" || model.String(record, "ServiceName") == "AmazonLambda" || model.String(storageObject(record["x_ProviderFields"]), "product_servicecode") == "AWSLambda"
}
