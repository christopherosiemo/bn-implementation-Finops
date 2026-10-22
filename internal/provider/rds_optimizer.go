package provider

import (
	"context"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
)

type RDSOptimizerEvidence struct {
	RDSReadEvidence
	Recommendations []model.Document `json:"recommendations"`
}

// Optional evidence only. Not opted-in/permission denied is returned explicitly
// to the optional caller; it never changes core discovery into an empty fleet.
// Provider savings estimates are not customer NET price or measured savings.
func (a *AWS) RDSComputeOptimizer(ctx context.Context, s RDSScope, arn string) (RDSOptimizerEvidence, error) {
	var out RDSOptimizerEvidence
	r, e := newRDSRead(a, s)
	if e != nil {
		return out, e
	}
	if _, e = rdsARN(s, arn, "db"); e != nil {
		if _, e = rdsARN(s, arn, "cluster"); e != nil {
			return out, e
		}
	}
	out.Recommendations = []model.Document{}
	tokens := map[string]bool{}
	seen := map[string]bool{}
	token := ""
	for page := 0; page < 20; page++ {
		p := model.Document{"accountIds": []string{s.AccountID}, "resourceArns": []string{arn}, "maxResults": 100}
		if token != "" {
			p["nextToken"] = token
		}
		raw, e := r.jsonRead(ctx, "compute-optimizer", "GetRDSDatabaseRecommendations", p)
		if e != nil {
			return RDSOptimizerEvidence{}, e
		}
		var response struct {
			Recommendations []model.Document `json:"rdsDBRecommendations"`
			Next            string           `json:"nextToken"`
			Errors          []model.Document `json:"errors"`
		}
		if rdsJSON(raw, &response) != nil || len(response.Errors) > 0 || response.Recommendations == nil {
			return RDSOptimizerEvidence{}, ErrRDSRead
		}
		for _, v := range response.Recommendations {
			if model.String(v, "accountId") != s.AccountID || model.String(v, "resourceArn") != arn || seen[arn] {
				return RDSOptimizerEvidence{}, ErrRDSRead
			}
			seen[arn] = true
			v["raw_page_sha256"] = rdsSHA(raw)
			out.Recommendations = append(out.Recommendations, v)
		}
		if response.Next == "" {
			out.RDSReadEvidence = r.evidence()
			out.ObservationBasis = "OPTIONAL_NATIVE_COMPUTE_OPTIMIZER_RECOMMENDATION_NOT_CUSTOMER_PRICE"
			return out, nil
		}
		token = response.Next
		if len(token) > 4096 || tokens[token] {
			return RDSOptimizerEvidence{}, ErrRDSRead
		}
		tokens[token] = true
	}
	return RDSOptimizerEvidence{}, ErrRDSRead
}
