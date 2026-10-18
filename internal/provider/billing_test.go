package provider

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
)

func billingTestAWS(handler func(*http.Request) (*http.Response, error)) *BillingAWS {
	client := &http.Client{Transport: roundTrip(handler)}
	cfg := aws.Config{Region: "eu-west-1", Credentials: aws.NewCredentialsCache(credentials.NewStaticCredentialsProvider("fixture", "fixture-secret", "fixture-session")), HTTPClient: client}
	return &BillingAWS{AWS: &AWS{cfg: cfg, client: client}, ExpectedOwner: "111122223333"}
}
func billingResponse(body string) *http.Response {
	return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: http.Header{"Content-Type": []string{"application/x-amz-json-1.1"}}}
}

func TestNativeInvoicesPaginatePreserveMoneyAndNormalizeIssuedDate(t *testing.T) {
	calls := 0
	a := billingTestAWS(func(r *http.Request) (*http.Response, error) {
		calls++
		if !strings.Contains(r.Header.Get("Authorization"), "/us-east-1/invoicing/aws4_request") || r.Header.Get("X-Amz-Target") != "Invoicing.ListInvoiceSummaries" {
			t.Errorf("unsigned or wrong native API: %s", r.Header.Get("X-Amz-Target"))
		}
		var body model.Document
		if e := json.NewDecoder(r.Body).Decode(&body); e != nil {
			t.Fatal(e)
		}
		if model.String(modelObject(body["Selector"]), "Value") != "111122223333" {
			t.Fatal("payer selector missing")
		}
		period := modelObject(modelObject(body["Filter"])["BillingPeriod"])
		if model.Number(period, "Month") != 9 || model.Number(period, "Year") != 2026 {
			t.Fatal("native billing period missing")
		}
		if calls == 1 {
			return billingResponse(`{"InvoiceSummaries":[{"AccountId":"111122223333","InvoiceId":"invoice","InvoiceType":"INVOICE","IssuedDate":1790856000,"TaxAuthorityStatus":"ISSUED","BillingPeriod":{"Year":2026,"Month":9},"Entity":{"InvoicingEntity":"AWS EMEA"},"BaseCurrencyAmount":{"CurrencyCode":"GBP","TotalAmount":"340.440000000001"}}],"NextToken":"next"}`), nil
		}
		if model.String(body, "NextToken") != "next" {
			t.Fatal("invoice pagination omitted")
		}
		return billingResponse(`{"InvoiceSummaries":[]}`), nil
	})
	rows, e := a.BillingInvoices(context.Background(), "111122223333", 2026, 9)
	if e != nil {
		t.Fatal(e)
	}
	if calls != 2 || len(rows) != 1 {
		t.Fatal("invoice pagination incomplete")
	}
	if model.String(modelObject(rows[0]["BaseCurrencyAmount"]), "TotalAmount") != "340.440000000001" {
		t.Fatal("native exact money changed")
	}
	if _, e = time.Parse(time.RFC3339, model.String(rows[0], "IssuedDate")); e != nil {
		t.Fatalf("native timestamp was not normalized: %v", e)
	}
}
func modelObject(v any) model.Document {
	b, _ := json.Marshal(v)
	d := model.Document{}
	_ = json.Unmarshal(b, &d)
	return d
}

func TestNativeS3RequiresOwnerAndVersion(t *testing.T) {
	calls := 0
	a := billingTestAWS(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != "GET" || r.Header.Get("X-Amz-Expected-Bucket-Owner") != "111122223333" || r.URL.Query().Get("versionId") != "immutable-version" || !strings.Contains(r.Header.Get("Authorization"), "/eu-west-1/s3/aws4_request") {
			t.Error("S3 object read not pinned to owner/version/signing region")
		}
		out := billingResponse("exact provider bytes")
		out.Header.Set("Last-Modified", "Thu, 01 Oct 2026 00:00:00 GMT")
		if calls == 1 {
			out.Header.Set("X-Amz-Version-Id", "immutable-version")
		}
		return out, nil
	})
	o, e := a.BillingObject(context.Background(), "billing-bucket", "cur/data.csv.gz", "immutable-version")
	if e != nil {
		t.Fatal(e)
	}
	if string(o.Data) != "exact provider bytes" || o.VersionID != "immutable-version" || o.LastModified.IsZero() {
		t.Fatal("raw evidence identity lost")
	}
	if _, e = a.BillingObject(context.Background(), "billing-bucket", "cur/data.csv.gz", "immutable-version"); e == nil {
		t.Fatal("unversioned provider response accepted")
	}
}

func TestOrganizationAccessDeniedCannotMasqueradeAsStandalone(t *testing.T) {
	a := billingTestAWS(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host == "sts.eu-west-1.amazonaws.com" {
			return billingResponse(`<GetCallerIdentityResponse><GetCallerIdentityResult><Account>111122223333</Account></GetCallerIdentityResult></GetCallerIdentityResponse>`), nil
		}
		if strings.Contains(r.Header.Get("X-Amz-Target"), "DescribeOrganization") {
			out := billingResponse(`{"__type":"AccessDeniedException","Message":"not allowed"}`)
			out.StatusCode = 400
			return out, nil
		}
		t.Fatalf("account-scoped evidence queried after unknown organization scope: %s", r.URL.Host)
		return nil, nil
	})
	proof, e := a.BillingCommitments(context.Background(), "111122223333")
	if e != nil {
		t.Fatal(e)
	}
	if model.Bool(proof, "complete") {
		t.Fatal("access denied turned into complete standalone proof")
	}
}
