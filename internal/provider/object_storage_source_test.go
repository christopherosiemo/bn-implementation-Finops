package provider

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/objectstorage"
)

func objectReportPolicy(r objectstorage.Registration) string {
	resource := "arn:aws:s3:::" + r.ReportBucket + "/" + r.Prefix + "*"
	statements := []model.Document{{"Effect": "Allow", "Principal": model.Document{"Service": "s3.amazonaws.com"}, "Action": "s3:PutObject", "Resource": resource, "Condition": model.Document{"StringEquals": model.Document{"aws:SourceAccount": r.AccountID}, "ArnLike": model.Document{"aws:SourceArn": "arn:aws:s3:::" + r.Bucket}}}}
	for k, v := range map[string]string{"aws:PrincipalServiceName": "s3.amazonaws.com", "aws:SourceArn": "arn:aws:s3:::" + r.Bucket, "aws:SourceAccount": r.AccountID} {
		statements = append(statements, model.Document{"Effect": "Deny", "Principal": "*", "Action": []string{"s3:PutObject", "s3:DeleteObject", "s3:DeleteObjectVersion"}, "Resource": resource, "Condition": model.Document{"StringNotEqualsIfExists": model.Document{k: v}}})
	}
	raw, _ := json.Marshal(model.Document{"Version": "2012-10-17", "Statement": statements})
	return string(raw)
}

func TestS3NativeReportConfigurationAndWriterFences(t *testing.T) {
	r := objectstorage.Registration{ID: "native-s3", TenantID: "tenant-s3", Kind: objectstorage.InventoryKind, AccountID: "111122223333", Region: "eu-west-1", Bucket: "data-bucket", ReportBucket: "report-bucket", ReportOwner: "111122223333", Prefix: "reports/", InventoryID: "native-config", ReadRoleBindingID: "read"}
	for _, name := range []string{"valid", "unversioned", "writer", "destination", "owner", "region"} {
		t.Run(name, func(t *testing.T) {
			a := s3TestAWS(func(req *http.Request) (string, int) {
				if strings.HasPrefix(req.URL.Host, "sts.") {
					return rdsTestIdentity(), 200
				}
				if req.Header.Get("x-amz-expected-bucket-owner") != r.AccountID {
					t.Fatal("exact owner omitted")
				}
				q := req.URL.Query()
				switch {
				case q.Has("location"):
					if name == "region" {
						return `<LocationConstraint>us-east-1</LocationConstraint>`, 200
					}
					return `<LocationConstraint>eu-west-1</LocationConstraint>`, 200
				case q.Has("versioning"):
					if name == "unversioned" {
						return `<VersioningConfiguration/>`, 200
					}
					return `<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>`, 200
				case q.Has("policy"):
					policy := objectReportPolicy(r)
					if name == "writer" {
						policy = strings.ReplaceAll(policy, "s3.amazonaws.com", "ec2.amazonaws.com")
					}
					return policy, 200
				case q.Has("inventory"):
					bucket, owner := "report-bucket", r.AccountID
					if name == "destination" {
						bucket = "other-report"
					}
					if name == "owner" {
						owner = "999900001111"
					}
					return `<InventoryConfiguration><Id>native-config</Id><IsEnabled>true</IsEnabled><IncludedObjectVersions>All</IncludedObjectVersions><Destination><S3BucketDestination><AccountId>` + owner + `</AccountId><Bucket>arn:aws:s3:::` + bucket + `</Bucket><Format>CSV</Format><Prefix>reports</Prefix></S3BucketDestination></Destination></InventoryConfiguration>`, 200
				case q.Has("tagging"):
					return `<Tagging><TagSet/></Tagging>`, 200
				}
				return `<Error><Code>AccessDenied</Code></Error>`, 403
			})
			boundary, e := a.ReportBoundary(context.Background(), r)
			if name == "valid" {
				if e != nil || model.String(boundary, "versioning") != "Enabled" || len(model.String(boundary, "writer_policy_hash")) != 64 {
					t.Fatal("native boundary rejected", e)
				}
			} else if e == nil {
				t.Fatal("untrusted report boundary accepted")
			}
		})
	}
}

func TestS3NativePricingDimensionsPreserveRangesNotPublicAmounts(t *testing.T) {
	const sku = "NATIVES3SKU"
	const rate = "NATIVES3SKU.TERM.RATE"
	product := model.Document{"product": model.Document{"sku": sku, "attributes": model.Document{"regionCode": "eu-west-1", "servicecode": "AmazonS3", "storageClass": "Standard"}}, "publicationDate": "2026-10-01T00:00:00Z", "terms": model.Document{"OnDemand": model.Document{"native-term": model.Document{"effectiveDate": "2026-10-01T00:00:00Z", "priceDimensions": model.Document{rate: model.Document{"rateCode": rate, "beginRange": "0", "endRange": "51200", "unit": "GB-Mo", "appliesTo": []string{}, "pricePerUnit": model.Document{"USD": "0.023"}}}}}}}
	for _, name := range []string{"valid", "region", "bounds", "pagination"} {
		t.Run(name, func(t *testing.T) {
			a := s3TestAWS(func(req *http.Request) (string, int) {
				if strings.HasPrefix(req.URL.Host, "sts.") {
					return rdsTestIdentity(), 200
				}
				if req.URL.Host != "api.pricing.us-east-1.amazonaws.com" || req.Header.Get("X-Amz-Target") != "AWSPriceListService.GetProducts" {
					t.Fatal("unapproved pricing endpoint")
				}
				body, _ := io.ReadAll(req.Body)
				if !strings.Contains(string(body), sku) {
					t.Fatal("pricing SKU not bounded")
				}
				raw, _ := json.Marshal(product)
				encoded := string(raw)
				if name == "region" {
					encoded = strings.ReplaceAll(encoded, "eu-west-1", "us-east-1")
				}
				if name == "bounds" {
					encoded = strings.ReplaceAll(encoded, `"beginRange":"0"`, `"beginRange":"70000"`)
				}
				page := model.Document{"PriceList": []string{encoded}}
				if name == "pagination" {
					page["NextToken"] = "same"
				}
				out, _ := json.Marshal(page)
				return string(out), 200
			})
			result, e := a.S3PriceDimensions(context.Background(), objectstorage.Scope{TenantID: "tenant-s3", AccountID: "111122223333", Region: "eu-west-1"}, []string{sku})
			if name != "valid" {
				if e == nil {
					t.Fatal("invalid native dimension accepted")
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			dimensions := objectstorage.Rows(result["dimensions"])
			if len(dimensions) != 1 || dimensions[0]["rate_code"] != rate || dimensions[0]["end_range"] != "51200" {
				t.Fatal("native dimensions lost")
			}
			interpreted, _ := json.Marshal(dimensions)
			if strings.Contains(string(interpreted), "0.023") || strings.Contains(string(interpreted), "pricePerUnit") {
				t.Fatal("catalogue amount became customer price")
			}
		})
	}
}
