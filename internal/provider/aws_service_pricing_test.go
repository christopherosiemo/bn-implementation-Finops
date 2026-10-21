package provider

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/awsservice"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
)

func TestAWSServiceNativePricingPinsDimensionsWithoutPublicRate(t *testing.T) {
	for _, scenario := range []string{"valid", "foreign region", "missing sku", "partial page"} {
		t.Run(scenario, func(t *testing.T) {
			transport := &serviceTestTransport{handle: func(req *http.Request, p model.Document, _ url.Values) (string, int) {
				if req.URL.Host != "api.pricing.us-east-1.amazonaws.com" || p["ServiceCode"] != "AmazonECS" {
					t.Fatal("unexpected pricing scope")
				}
				region := "eu-west-1"
				if scenario == "foreign region" {
					region = "us-east-1"
				}
				product := model.Document{"product": model.Document{"sku": "FARGATE_CPU_SKU", "attributes": model.Document{"servicecode": "AmazonECS", "regionCode": region, "usagetype": "EU-Fargate-vCPU-Hours", "operation": "FargateTask", "cpuArchitecture": "x86", "operatingSystem": "Linux"}}, "terms": model.Document{"OnDemand": model.Document{"term": model.Document{"effectiveDate": "2026-01-01T00:00:00Z", "priceDimensions": model.Document{"FARGATE_CPU_SKU.RATE": model.Document{"rateCode": "FARGATE_CPU_SKU.RATE", "unit": "vCPU-Hours", "beginRange": "0", "endRange": "Inf", "pricePerUnit": model.Document{"USD": "999.99"}}}}}}}
				encoded, _ := json.Marshal(product)
				rows := []string{string(encoded)}
				if scenario == "missing sku" {
					rows = []string{}
				}
				out := model.Document{"PriceList": rows}
				if scenario == "partial page" {
					out["NextToken"] = "repeated"
				}
				return serviceTestJSON(out)
			}}
			scope := awsservice.Scope{TenantID: "tenant-a", AccountID: "111122223333", Region: "eu-west-1"}
			out, e := serviceTestAWS(transport).AWSServicePriceDimensions(context.Background(), scope, []string{"FARGATE_CPU_SKU"})
			if scenario != "valid" {
				if e == nil {
					t.Fatal("unresolved native dimension accepted")
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			raw, _ := json.Marshal(out["dimensions"])
			if strings.Contains(string(raw), "999.99") || strings.Contains(string(raw), "pricePerUnit") {
				t.Fatal("public rate became customer economics")
			}
		})
	}
}
