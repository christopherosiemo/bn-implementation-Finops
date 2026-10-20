package service

import (
	"context"
	"encoding/json"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"math/big"
)

// Add storage classifications to the existing all-service denominator. Only
// canonical line IDs used by a current assessment can count as analysed spend.
func (a *API) storageCoveragePublications(ctx context.Context, t *store.Tx) (map[string]databaseCoveragePublication, error) {
	out := map[string]databaseCoveragePublication{}
	var exists bool
	if e := t.QueryRow(ctx, "SELECT EXISTS(SELECT FROM entities WHERE tenant_id=$1 AND kind='resources' AND document->>'resource_type' IN('EBS_VOLUME','EBS_SNAPSHOT'))", t.Tenant).Scan(&exists); e != nil {
		return nil, e
	}
	if !exists {
		return out, nil
	}
	rows, e := t.Query(ctx, `SELECT a.id,a.resource_id,a.document,p.currency,p.current_hourly_cost::text FROM (SELECT DISTINCT ON(resource_id) * FROM storage_assessments WHERE tenant_id=$1 ORDER BY resource_id,created_at DESC,id DESC) a LEFT JOIN storage_recommendation_publications p ON p.tenant_id=a.tenant_id AND p.assessment_id=a.id ORDER BY a.resource_id LIMIT $2`, t.Tenant, databaseCoverageLimit+1)
	if e != nil {
		return nil, e
	}
	type saved struct {
		id, resource     string
		raw              []byte
		currency, hourly *string
	}
	all := []saved{}
	for rows.Next() {
		var s saved
		if e = rows.Scan(&s.id, &s.resource, &s.raw, &s.currency, &s.hourly); e != nil {
			break
		}
		all = append(all, s)
	}
	if e == nil {
		e = rows.Err()
	}
	rows.Close()
	if e != nil {
		return nil, e
	}
	if len(all) > databaseCoverageLimit {
		return nil, problem(422, "STORAGE_COVERAGE_ASSESSMENT_LIMIT", "storage coverage bound exceeded")
	}
	for _, s := range all {
		var record model.Document
		if e = json.Unmarshal(s.raw, &record); e != nil {
			return nil, e
		}
		record["id"] = s.id
		record["resource_id"] = s.resource
		current, e := a.storageAssessmentCurrent(ctx, t, record)
		if e != nil {
			return nil, e
		}
		p := databaseCoveragePublication{status: model.String(record, "status"), assessment: storageObject(record["assessment"]), current: model.Bool(current, "current")}
		if s.currency != nil {
			p.currency = *s.currency
		}
		if s.hourly != nil && databaseCoverageDecimal.MatchString(*s.hourly) {
			p.hourly, _ = new(big.Rat).SetString(*s.hourly)
		}
		p.economicLines = databaseCoverageEconomicLines(p.assessment)
		out[s.resource] = p
	}
	return out, nil
}
