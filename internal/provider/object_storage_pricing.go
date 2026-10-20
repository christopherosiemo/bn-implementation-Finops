package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/objectstorage"
	"io"
	"math/big"
	"net/http"
	"sort"
	"strings"
	"time"
)

// S3PriceDimensions retains catalogue units/tier ranges only. Public price
// amounts are excluded from interpreted output; customer rates must remain
// independently bound to exact native CUR SKU and rateCode evidence.
func (a *AWS) S3PriceDimensions(ctx context.Context, s objectstorage.Scope, skus []string) (model.Document, error) {
	if len(skus) == 0 || len(skus) > 64 {
		return nil, errors.New("S3_CATALOGUE_SKU_LIMIT")
	}
	cfg, capture, e := objectSDK(a, s)
	if e != nil {
		return nil, e
	}
	if e = objectIdentity(ctx, cfg, s); e != nil {
		return nil, e
	}
	sorted := append([]string{}, skus...)
	sort.Strings(sorted)
	seenSKU := map[string]bool{}
	dimensions := []model.Document{}
	for _, sku := range sorted {
		if !rdsPart.MatchString(sku) || len(sku) > 64 || seenSKU[sku] {
			return nil, errors.New("S3_CATALOGUE_SKU_INVALID")
		}
		seenSKU[sku] = true
		token := ""
		seenToken := map[string]bool{}
		found := false
		complete := false
		for page := 0; page < 10; page++ {
			query := model.Document{"ServiceCode": "AmazonS3", "FormatVersion": "aws_v1", "MaxResults": 100, "Filters": []model.Document{{"Type": "TERM_MATCH", "Field": "sku", "Value": sku}, {"Type": "TERM_MATCH", "Field": "regionCode", "Value": s.Region}}}
			if token != "" {
				query["NextToken"] = token
			}
			body, _ := json.Marshal(query)
			req, e := http.NewRequestWithContext(objectContext(ctx, "GetProducts"), http.MethodPost, "https://api.pricing.us-east-1.amazonaws.com/", bytes.NewReader(body))
			if e != nil {
				return nil, e
			}
			req.Header.Set("Content-Type", "application/x-amz-json-1.1")
			req.Header.Set("X-Amz-Target", "AWSPriceListService.GetProducts")
			credentials, e := cfg.Credentials.Retrieve(ctx)
			if e != nil {
				return nil, errors.New("S3_CATALOGUE_CREDENTIALS_UNAVAILABLE")
			}
			if e = v4.NewSigner().SignHTTP(ctx, credentials, req, objectstorage.BytesHash(body), "pricing", "us-east-1", time.Now().UTC()); e != nil {
				return nil, e
			}
			response, e := capture.Do(req)
			if e != nil {
				return nil, e
			}
			raw, e := io.ReadAll(response.Body)
			response.Body.Close()
			if e != nil || response.StatusCode != 200 {
				return nil, errors.New("S3_NATIVE_CATALOGUE_UNAVAILABLE")
			}
			var pageDoc struct {
				Products []string `json:"PriceList"`
				Next     string   `json:"NextToken"`
			}
			if rdsJSON(raw, &pageDoc) != nil || pageDoc.Products == nil {
				return nil, errors.New("S3_NATIVE_CATALOGUE_INVALID")
			}
			for _, encoded := range pageDoc.Products {
				var product struct {
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
				if rdsJSON([]byte(encoded), &product) != nil || product.Product.SKU != sku || product.Product.Attributes["regionCode"] != s.Region || product.Product.Attributes["servicecode"] != "" && product.Product.Attributes["servicecode"] != "AmazonS3" {
					return nil, errors.New("S3_CATALOGUE_SCOPE_MISMATCH")
				}
				found = true
				for _, term := range product.Terms["OnDemand"] {
					for key, d := range term.Dimensions {
						begin, ok := new(big.Rat).SetString(d.Begin)
						if !ok || begin.Sign() < 0 || d.Unit == "" || d.RateCode != key {
							return nil, errors.New("S3_CATALOGUE_DIMENSION_INVALID")
						}
						if d.End != "Inf" {
							end, ok := new(big.Rat).SetString(d.End)
							if !ok || end.Cmp(begin) <= 0 {
								return nil, errors.New("S3_CATALOGUE_DIMENSION_INVALID")
							}
						}
						dimensions = append(dimensions, model.Document{"sku": sku, "rate_code": d.RateCode, "begin_range": d.Begin, "end_range": d.End, "unit": d.Unit, "applies_to": d.Applies, "term_type": "OnDemand", "effective_date": term.Effective, "publication_date": product.Publication, "attributes": product.Product.Attributes, "basis": "NATIVE_CATALOGUE_DIMENSIONS_ONLY_NOT_CUSTOMER_PRICE"})
						if len(dimensions) > 4096 {
							return nil, errors.New("S3_CATALOGUE_DIMENSION_LIMIT")
						}
					}
				}
			}
			if pageDoc.Next == "" {
				complete = true
				break
			}
			if seenToken[pageDoc.Next] {
				return nil, errors.New("S3_CATALOGUE_PAGINATION_CYCLE")
			}
			seenToken[pageDoc.Next] = true
			token = pageDoc.Next
		}
		if !complete || !found {
			return nil, errors.New("S3_CATALOGUE_SKU_UNRESOLVED")
		}
	}
	sort.Slice(dimensions, func(i, j int) bool {
		return strings.Compare(model.String(dimensions[i], "rate_code"), model.String(dimensions[j], "rate_code")) < 0
	})
	raw, _ := json.Marshal(model.Document{"scope": s, "frames": capture.frames})
	return model.Document{"schema_version": "1", "scope": s, "dimensions": dimensions, "collected_at": time.Now().UTC(), "raw": raw, "raw_sha256": objectstorage.BytesHash(raw), "basis": "NATIVE_PRICING_RANGES_WITHOUT_LIST_PRICE_SUBSTITUTION"}, nil
}
