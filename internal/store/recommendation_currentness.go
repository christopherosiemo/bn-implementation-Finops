package store

import (
	"context"
	"encoding/json"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
)

// RecommendationCurrentnessContext reads only tenant-bound fingerprints. Older
// installed schema prefixes retain their existing family-specific validators.
func (t *Tx) RecommendationCurrentnessContext(ctx context.Context, family, id string) (model.Document, error) {
	var installed bool
	if e := t.QueryRow(ctx, "SELECT to_regclass('public.recommendation_currentness_contexts') IS NOT NULL").Scan(&installed); e != nil || !installed {
		return nil, e
	}
	var raw []byte
	if e := t.QueryRow(ctx, "SELECT public.recommendation_currentness_context($1,$2)", family, id).Scan(&raw); e != nil {
		return nil, e
	}
	if raw == nil {
		return nil, nil
	}
	var d model.Document
	e := json.Unmarshal(raw, &d)
	return d, e
}

func (t *Tx) RecommendationCurrentnessSummary(ctx context.Context, account, region string) ([]model.Document,error) {
	var installed bool
	if e:=t.QueryRow(ctx,"SELECT to_regclass('public.recommendation_currentness_contexts') IS NOT NULL").Scan(&installed);e!=nil || !installed { return nil,e }
	return t.sourceRows(ctx,"SELECT public.recommendation_currentness_summary($1,$2)",account,region)
}
