package multicloud

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func nativeGCPRow() Document {
	return Document{"billing_account_id": "ABCDEF-123456-ABC123", "cost": json.Number("0.10000000000000001"), "currency": "GBP", "cost_type": "regular", "project": Document{"id": "usage-project"}, "resource": Document{"global_name": "//compute.googleapis.com/projects/usage-project/zones/europe-west1-b/instances/123"}, "location": Document{"region": "europe-west1"}, "usage_start_time": "2026-10-01T00:00:00Z", "usage_end_time": "2026-10-01T01:00:00Z", "invoice": Document{"month": "202610"}, "credits": []any{Document{"id": "credit-1", "amount": json.Number("-0.005"), "type": "COMMITTED_USAGE_DISCOUNT"}}}
}
func TestGCPNativeCostsCreditsAndCorrections(t *testing.T) {
	r := gcpRegistration(GCPDetailed)
	native := nativeGCPRow()
	rows, e := ParseGCPRow(r, native, "job#0", "GBP")
	if e != nil {
		t.Fatal(e)
	}
	if len(rows) != 2 || *rows[0].BilledCost != "0.10000000000000001" || *rows[1].BilledCost != "-0.005" || rows[0].EffectiveCost != nil || rows[1].ChargeCategory != "Credit" || rows[1].ID == rows[0].ID {
		t.Fatalf("native money/credits changed: %+v", rows)
	}
	if !hasReason(rows[0].MappingGaps, "PROVIDER_FLOAT64_MONEY_PRECISION") {
		t.Fatal("native floating precision hidden")
	}
	native["cost"] = json.Number("-0.1")
	native["adjustment_info"] = Document{"id": "correction-1", "mode": "PARTIAL_CORRECTION"}
	rows, e = ParseGCPRow(r, native, "job#1", "GBP")
	if e != nil || rows[0].ChargeClass != "Correction" || *rows[0].BilledCost != "-0.1" {
		t.Fatal(rows, e)
	}
	native["cost"] = nil
	rows, e = ParseGCPRow(r, native, "job#2", "GBP")
	if e != nil || rows[0].BilledCost != nil {
		t.Fatal("missing cost became zero")
	}
	_, e = ParseGCPRow(r, native, "job", "USD")
	wantError(t, e, "CURRENCY_MISMATCH")
	native["billing_account_id"] = "OTHER1-OTHER2-OTHER3"
	_, e = ParseGCPRow(r, native, "job", "GBP")
	wantError(t, e, "BILLING_ACCOUNT_MISMATCH")
}
func TestGCPPricingAndCUDMetadataCannotSubstituteMoney(t *testing.T) {
	for _, kind := range []Kind{GCPPricing, GCPCommitments} {
		t.Run(string(kind), func(t *testing.T) {
			r := gcpRegistration(kind)
			native := Document{"billing_account_id": r.GCP.BillingAccountID, "account_currency_code": "GBP", "list_price": Document{"tiered_rates": []any{Document{"usd_amount": "10"}}}, "currency_conversion_rate": "0.73", "billing_account_price": nil, "entitlement_schedule": []any{Document{"start_time": "2026-10-01T00:00:00", "end_time": "2027-10-01T00:00:00", "commitment_amount": "2"}}, "commitment_amount": []any{Document{"unit": "$/hr", "value": "2"}}}
			rows, e := ParseGCPRow(r, native, "row", "GBP")
			if e != nil {
				t.Fatal(e)
			}
			row := rows[0]
			if row.BilledCost != nil || row.EffectiveCost != nil || row.ListCost != nil {
				t.Fatal("auxiliary metadata manufactured resource cost")
			}
			if Hash(row.Native) != Hash(native) {
				t.Fatal("native calendar/commitment/pricing fields lost")
			}
		})
	}
}
func TestGCPQueryIsBoundedParameterizedNativeRead(t *testing.T) {
	r := gcpRegistration(GCPDetailed)
	p := Period{testNow.Add(-14 * 24 * time.Hour), testNow.Add(-time.Hour)}
	q, e := Query(r, p, testNow)
	if e != nil {
		t.Fatal(e)
	}
	sql := str(q, "query")
	for _, fragment := range []string{"FOR SYSTEM_TIME AS OF @as_of", "billing_account_id = @billing", "invoice.month BETWEEN @first_invoice AND @last_invoice"} {
		if !strings.Contains(sql, fragment) {
			t.Fatal(sql)
		}
	}
	if boolean(q, "useLegacySql") || boolean(q, "useQueryCache") || str(q, "maximumBytesBilled") != "1000000000" || str(q, "jobCreationMode") != "JOB_CREATION_REQUIRED" {
		t.Fatal(q)
	}
	r.GCP.TableID += "` UNION SELECT secret"
	if _, e = Query(r, p, testNow); e == nil {
		t.Fatal("accepted caller SQL injection")
	}
}

type gcpDouble struct {
	t           *testing.T
	r           Registration
	mutation    string
	request     Document
	calls       int
	pages       int
	tokenScopes []string
}

func (g *gcpDouble) transport(req *http.Request) (*http.Response, error) {
	g.calls++
	if req.Header.Get("Authorization") != "Bearer test-machine-token" {
		g.t.Fatal("identity missing")
	}
	s := g.r.GCP
	if req.URL.Host == "cloudbilling.googleapis.com" {
		currency := "GBP"
		if g.mutation == "currency" {
			currency = "USD"
		}
		return response(200, wire(g.t, Document{"name": "billingAccounts/" + s.BillingAccountID, "currencyCode": currency}), nil), nil
	}
	if req.URL.Host != "bigquery.googleapis.com" {
		g.t.Fatal("unexpected endpoint")
	}
	tableRef := Document{"projectId": s.DatasetProjectID, "datasetId": s.DatasetID, "tableId": s.TableID}
	if strings.Contains(req.URL.Path, "/datasets/") {
		if strings.Contains(req.URL.Path, "/tables/") {
			fields := []any{Document{"name": "billing_account_id", "type": "STRING"}, Document{"name": "cost", "type": "FLOAT"}, Document{"name": "currency", "type": "STRING"}, Document{"name": "usage_start_time", "type": "TIMESTAMP"}, Document{"name": "usage_end_time", "type": "TIMESTAMP"}, Document{"name": "invoice", "type": "RECORD"}}
			if g.r.Kind == GCPPricing {
				fields = []any{Document{"name": "billing_account_id", "type": "STRING"}, Document{"name": "account_currency_code", "type": "STRING"}, Document{"name": "pricing_as_of_time", "type": "TIMESTAMP"}}
			}
			if g.r.Kind == GCPCommitments {
				fields = []any{Document{"name": "billing_account_id", "type": "STRING"}, Document{"name": "state", "type": "STRING"}, Document{"name": "start_time", "type": "TIMESTAMP"}, Document{"name": "end_time", "type": "TIMESTAMP"}}
			}
			kind := "TABLE"
			if g.mutation == "view" {
				kind = "VIEW"
			}
			return response(200, wire(g.t, Document{"tableReference": tableRef, "type": kind, "etag": "table-version-1", "location": s.Location, "schema": Document{"fields": fields}}), nil), nil
		}
		return response(200, wire(g.t, Document{"datasetReference": Document{"projectId": s.DatasetProjectID, "datasetId": s.DatasetID}, "etag": "dataset-version", "location": s.Location}), nil), nil
	}
	job := Document{"projectId": s.QueryProjectID, "location": s.Location, "jobId": "job-native-1"}
	if req.Method == http.MethodPost {
		raw, _ := io.ReadAll(req.Body)
		g.request, _ = decode(raw)
		if str(g.request, "query") == "" {
			g.t.Fatal("query missing")
		}
		return response(200, wire(g.t, Document{"jobReference": job, "jobComplete": false}), nil), nil
	}
	if strings.Contains(req.URL.Path, "/queries/") {
		g.pages++
		native := nativeGCPRow()
		if g.r.Kind != GCPDetailed {
			native = Document{"billing_account_id": s.BillingAccountID, "account_currency_code": "GBP", "pricing_as_of_time": "2026-10-17T00:00:00Z", "list_price": Document{"tiered_rates": []any{Document{"usd_amount": "0.1"}}}, "state": "Active", "start_time": "2026-09-01T00:00:00Z", "end_time": "2027-09-01T00:00:00Z", "entitlement_schedule": []any{Document{"start_time": "2026-09-01T00:00:00", "end_time": "2027-09-01T00:00:00", "commitment_amount": "2"}}}
		}
		d := Document{"jobReference": job, "jobComplete": true, "totalRows": "2", "schema": Document{"fields": []any{Document{"name": "native_row", "type": "STRING"}}}}
		if req.URL.Query().Get("pageToken") == "" {
			d["pageToken"] = "native-page-two"
		} else {
			native["cost"] = json.Number("-0.02")
			delete(native, "credits")
			native["adjustment_info"] = Document{"id": "correction-1"}
			if g.mutation == "cycle" {
				d["pageToken"] = "native-page-two"
			}
			if g.mutation == "total" {
				d["totalRows"] = "3"
			}
		}
		if g.mutation == "job" {
			d["jobReference"] = Document{"projectId": "other-project", "location": s.Location, "jobId": "job-native-1"}
		}
		if g.mutation == "warning" {
			d["errors"] = []any{Document{"reason": "partialResult"}}
		}
		d["rows"] = []any{Document{"f": []any{Document{"v": string(wire(g.t, native))}}}}
		return response(200, wire(g.t, d), nil), nil
	}
	if strings.Contains(req.URL.Path, "/jobs/") {
		q := g.request
		if g.mutation == "definition" {
			q = Document{}
			for k, v := range g.request {
				q[k] = v
			}
			q["query"] = "SELECT 1"
		}
		refs := []any{tableRef}
		if g.mutation == "table" {
			refs = []any{Document{"projectId": s.DatasetProjectID, "datasetId": s.DatasetID, "tableId": "other_table"}}
		}
		return response(200, wire(g.t, Document{"jobReference": job, "status": Document{"state": "DONE"}, "configuration": Document{"query": q}, "statistics": Document{"query": Document{"statementType": "SELECT", "cacheHit": false, "referencedTables": refs}}}), nil), nil
	}
	g.t.Fatalf("unexpected native request path %s", req.URL.Path)
	return nil, nil
}
func TestGCPNativeJourneyReadsCompleteQueryAndPreservesCredits(t *testing.T) {
	r := gcpRegistration(GCPDetailed)
	d := &gcpDouble{t: t, r: r}
	c := config(r, d.transport)
	c.Tokens = TokenFunc(func(_ context.Context, scope string) (string, error) {
		d.tokenScopes = append(d.tokenScopes, scope)
		return "test-machine-token", nil
	})
	s, e := (GCPReader{Config: c}).Collect(context.Background(), r, Period{testNow.Add(-14 * 24 * time.Hour), testNow.Add(-time.Hour)})
	if e != nil {
		t.Fatal(e)
	}
	if s.NativeRowCount != 2 || len(s.Records) != 3 || s.BilledTotals["GBP"] != "0.07500000000000001" || d.pages != 2 || s.ExecutionReady() || s.VerifiedSaving() != nil {
		t.Fatalf("bad complete query snapshot %+v", s)
	}
	if !hasReason(s.ReasonCodes, "GCP_INVOICE_MONTH_IS_NOT_ISSUED_INVOICE_FINALITY") {
		t.Fatal("invoice month granted finality")
	}
	for i, scope := range d.tokenScopes {
		want := bigQueryScope
		if i == 0 {
			want = cloudBillingScope
		}
		if scope != want {
			t.Fatal("overbroad OAuth scope")
		}
	}
	for _, o := range s.Objects {
		if o.SHA256 != BytesHash(o.Body) {
			t.Fatal("original raw bytes lost")
		}
	}
}
func TestGCPNativeJourneyFailsClosed(t *testing.T) {
	for mutation, code := range map[string]string{"currency": "CURRENCY_MISMATCH", "view": "TABLE_BINDING_INVALID", "cycle": "PAGINATION_INVALID", "total": "TOTAL_ROWS_CHANGED", "job": "JOB_CHANGED", "warning": "PAGE_INVALID", "definition": "DEFINITION_CHANGED", "table": "TABLE_SCOPE_CHANGED"} {
		t.Run(mutation, func(t *testing.T) {
			r := gcpRegistration(GCPDetailed)
			d := &gcpDouble{t: t, r: r, mutation: mutation}
			_, e := (GCPReader{Config: config(r, d.transport)}).Collect(context.Background(), r, Period{testNow.Add(-14 * 24 * time.Hour), testNow.Add(-time.Hour)})
			wantError(t, e, code)
		})
	}
}
func TestGCPNativeAuxiliaryJourneysNeverBecomeBilledCost(t *testing.T) {
	for _, kind := range []Kind{GCPPricing, GCPCommitments} {
		t.Run(string(kind), func(t *testing.T) {
			r := gcpRegistration(kind)
			d := &gcpDouble{t: t, r: r}
			s, e := (GCPReader{Config: config(r, d.transport)}).Collect(context.Background(), r, Period{testNow.Add(-14 * 24 * time.Hour), testNow.Add(-time.Hour)})
			if e != nil {
				t.Fatal(e)
			}
			if s.Kind != kind || len(s.Records) != 2 || len(s.BilledTotals) != 0 || s.ExecutionReady() || s.VerifiedSaving() != nil {
				t.Fatal("auxiliary data manufactured authority", s)
			}
			if kind == GCPCommitments && !hasReason(s.ReasonCodes, "GCP_RESOURCE_BASED_COMMITMENT_INVENTORY_UNPROVEN") {
				t.Fatal("partial commitment inventory hidden")
			}
		})
	}
}
