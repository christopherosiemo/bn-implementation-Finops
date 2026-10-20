package provider

import (
	"context"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/lambdacost"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"math/big"
	"sort"
)

// LambdaPriceDimensions reads exact CUR SKU dimensions only. Public numeric
// prices never become customer NET prices or marginal savings evidence.
func (a *AWS) LambdaPriceDimensions(ctx context.Context, s lambdacost.Scope, skus []string) (model.Document, error) {
	if lambdacost.ValidateScope(s) != nil || len(skus) == 0 || len(skus) > 32 {
		return nil, lambdacost.ErrEvidence
	}
	r, e := newRDSRead(a, RDSScope{s.TenantID, s.AccountID, s.Region})
	if e != nil {
		return nil, e
	}
	dimensions := []model.Document{}
	seen := map[string]bool{}
	for _, sku := range skus {
		if !rdsPart.MatchString(sku) || len(sku) > 64 || seen[sku] {
			return nil, lambdacost.ErrEvidence
		}
		seen[sku] = true
		token := ""
		tokens := map[string]bool{}
		found, complete := false, false
		for page := 0; page < 16; page++ {
			q := model.Document{"ServiceCode": "AWSLambda", "FormatVersion": "aws_v1", "MaxResults": 100, "Filters": []model.Document{{"Type": "TERM_MATCH", "Field": "sku", "Value": sku}}}
			if token != "" {
				q["NextToken"] = token
			}
			raw, e := r.jsonRead(ctx, "pricing", "GetProducts", q)
			if e != nil {
				return nil, e
			}
			var response struct {
				PriceList []string
				NextToken string
			}
			if rdsJSON(raw, &response) != nil || response.PriceList == nil {
				return nil, lambdacost.ErrEvidence
			}
			for _, item := range response.PriceList {
				var p struct {
					Product struct {
						SKU        string
						Attributes map[string]string
					}
					PublicationDate string
					Terms           map[string]map[string]struct {
						EffectiveDate   string
						PriceDimensions map[string]struct {
							RateCode, BeginRange, EndRange, Unit string
							AppliesTo                            []string
						}
					}
				}
				if rdsJSON([]byte(item), &p) != nil || p.Product.SKU != sku || p.Product.Attributes["regionCode"] != s.Region || p.Product.Attributes["servicecode"] != "" && p.Product.Attributes["servicecode"] != "AWSLambda" {
					return nil, lambdacost.ErrEvidence
				}
				found = true
				for _, term := range p.Terms["OnDemand"] {
					for key, d := range term.PriceDimensions {
						begin, ok := new(big.Rat).SetString(d.BeginRange)
						if !ok || begin.Sign() < 0 || d.RateCode != key || d.Unit == "" {
							return nil, lambdacost.ErrEvidence
						}
						if d.EndRange != "Inf" {
							end, ok := new(big.Rat).SetString(d.EndRange)
							if !ok || end.Cmp(begin) <= 0 {
								return nil, lambdacost.ErrEvidence
							}
						}
						dimensions = append(dimensions, model.Document{"sku": sku, "rate_code": d.RateCode, "service_code": "AWSLambda", "unit": d.Unit, "begin_range": d.BeginRange, "end_range": d.EndRange, "applies_to": d.AppliesTo, "effective_date": term.EffectiveDate, "publication_date": p.PublicationDate, "term_type": "OnDemand", "attributes": p.Product.Attributes, "basis": "NATIVE_CATALOGUE_DIMENSIONS_ONLY_NOT_CUSTOMER_PRICE"})
						if len(dimensions) > 4096 {
							return nil, lambdacost.ErrEvidence
						}
					}
				}
			}
			token = response.NextToken
			if token == "" {
				complete = true
				break
			}
			if tokens[token] || len(token) > 4096 {
				return nil, lambdacost.ErrEvidence
			}
			tokens[token] = true
		}
		if !found || !complete {
			return nil, lambdacost.ErrEvidence
		}
	}
	sort.Slice(dimensions, func(i, j int) bool {
		return model.String(dimensions[i], "rate_code") < model.String(dimensions[j], "rate_code")
	})
	evidence := r.evidence()
	return model.Document{"schema_version": "LAMBDA_PRICE_DIMENSIONS_V1", "dimensions": dimensions, "raw": evidence.Raw, "raw_sha256": evidence.RawSHA256, "basis": "NATIVE_CATALOGUE_DIMENSIONS_ONLY_NOT_CUSTOMER_PRICE"}, nil
}
