package provider

import (
	"context"
	"math/big"
	"sort"
	"strings"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/network"
)

// NetworkPriceDimensions binds native CUR SKU/rateCode to catalogue units and
// tier ranges. It never interprets pricePerUnit as the customer's NET rate.
func (a *AWS) NetworkPriceDimensions(ctx context.Context, s network.Scope, skus []string) (model.Document, error) {
	if network.ValidateScope(s) != nil || len(skus) == 0 || len(skus) > 32 {
		return nil, network.ErrEvidence
	}
	read, e := newRDSRead(a, RDSScope{TenantID: s.TenantID, AccountID: s.AccountID, Region: s.Region})
	if e != nil {
		return nil, e
	}
	sorted := append([]string{}, skus...)
	sort.Strings(sorted)
	seen := map[string]bool{}
	dimensions := []model.Document{}
	for _, sku := range sorted {
		if !rdsPart.MatchString(sku) || len(sku) > 64 || seen[sku] {
			return nil, network.ErrEvidence
		}
		seen[sku] = true
		found := false
		for _, service := range []string{"AmazonEC2", "AmazonVPC", "AWSELB", "AWSDataTransfer"} {
			token := ""
			tokens := map[string]bool{}
			complete := false
			for page := 0; page < 10; page++ {
				q := model.Document{"ServiceCode": service, "FormatVersion": "aws_v1", "MaxResults": 100, "Filters": []model.Document{{"Type": "TERM_MATCH", "Field": "sku", "Value": sku}}}
				if token != "" {
					q["NextToken"] = token
				}
				raw, e := read.jsonRead(ctx, "pricing", "GetProducts", q)
				if e != nil {
					return nil, e
				}
				var result struct {
					Products []string `json:"PriceList"`
					Next     string   `json:"NextToken"`
				}
				if rdsJSON(raw, &result) != nil || result.Products == nil {
					return nil, network.ErrEvidence
				}
				for _, encoded := range result.Products {
					var p struct {
						Product struct {
							SKU        string            `json:"sku"`
							Attributes map[string]string `json:"attributes"`
						} `json:"product"`
						Publication string `json:"publicationDate"`
						Terms       map[string]map[string]struct {
							Effective  string `json:"effectiveDate"`
							Dimensions map[string]struct {
								RateCode string   `json:"rateCode"`
								Begin    string   `json:"beginRange"`
								End      string   `json:"endRange"`
								Unit     string   `json:"unit"`
								Applies  []string `json:"appliesTo"`
							} `json:"priceDimensions"`
						} `json:"terms"`
					}
					if rdsJSON([]byte(encoded), &p) != nil || p.Product.SKU != sku || p.Product.Attributes["servicecode"] != "" && p.Product.Attributes["servicecode"] != service {
						return nil, network.ErrEvidence
					}
					// Inter-region native transfer products may use from/to region
					// rather than regionCode. They remain dimensionally distinct.
					attrs := p.Product.Attributes
					if attrs["regionCode"] != s.Region && attrs["fromRegionCode"] != s.Region && attrs["toRegionCode"] != s.Region {
						return nil, network.ErrEvidence
					}
					found = true
					for _, term := range p.Terms["OnDemand"] {
						for key, d := range term.Dimensions {
							begin, ok := new(big.Rat).SetString(d.Begin)
							if !ok || begin.Sign() < 0 || d.Unit == "" || d.RateCode != key {
								return nil, network.ErrEvidence
							}
							if d.End != "Inf" {
								end, ok := new(big.Rat).SetString(d.End)
								if !ok || end.Cmp(begin) <= 0 {
									return nil, network.ErrEvidence
								}
							}
							dimensions = append(dimensions, model.Document{"sku": sku, "rate_code": d.RateCode, "service_code": service, "unit": d.Unit, "begin_range": d.Begin, "end_range": d.End, "applies_to": d.Applies, "term_type": "OnDemand", "effective_date": term.Effective, "publication_date": p.Publication, "attributes": attrs, "basis": "NATIVE_CATALOGUE_DIMENSIONS_ONLY_NOT_CUSTOMER_PRICE"})
							if len(dimensions) > 4096 {
								return nil, network.ErrEvidence
							}
						}
					}
				}
				if result.Next == "" {
					complete = true
					break
				}
				if tokens[result.Next] {
					return nil, network.ErrEvidence
				}
				tokens[result.Next] = true
				token = result.Next
			}
			if !complete {
				return nil, network.ErrEvidence
			}
		}
		if !found {
			return nil, network.ErrEvidence
		}
	}
	sort.Slice(dimensions, func(i, j int) bool {
		return strings.Compare(model.String(dimensions[i], "rate_code"), model.String(dimensions[j], "rate_code")) < 0
	})
	evidence := read.evidence()
	return model.Document{"schema_version": "NETWORK_PRICE_DIMENSIONS_V1", "scope": s, "dimensions": dimensions, "collected_at": time.Now().UTC(), "raw": evidence.Raw, "raw_sha256": evidence.RawSHA256, "basis": "NATIVE_CATALOGUE_DIMENSIONS_ONLY_NOT_CUSTOMER_PRICE"}, nil
}
