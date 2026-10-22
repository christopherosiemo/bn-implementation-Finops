package multicloud

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

var testNow = time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)

const subscription = "11111111-1111-1111-1111-111111111111"
const directory = "22222222-2222-2222-2222-222222222222"
const runID = "33333333-3333-3333-3333-333333333333"

func azureRegistration(kind Kind) Registration {
	return Registration{SchemaVersion: "1", ID: "azure-source", Version: 1, TenantID: "tenant-a", ReadBindingID: "azure-reader", Kind: kind, Azure: &AzureScope{
		DirectoryTenantID: directory, ExportResourceID: "/subscriptions/" + subscription + "/providers/Microsoft.CostManagement/exports/finops", BillingAccountID: "billing-a", SubscriptionIDs: []string{subscription},
		StorageAccountResourceID: "/subscriptions/" + subscription + "/resourceGroups/finops/providers/Microsoft.Storage/storageAccounts/finopsbilling", StorageAccountName: "finopsbilling", Container: "billing", Prefix: "exports/", DataVersion: "2023-05-01",
	}}
}
func gcpRegistration(kind Kind) Registration {
	table := "gcp_billing_export_resource_v1_ABCDEF_123456_ABC123"
	if kind == GCPPricing {
		table = "cloud_pricing_export"
	}
	if kind == GCPCommitments {
		table = "cud_subscriptions_export"
	}
	return Registration{SchemaVersion: "1", ID: "gcp-source", Version: 1, TenantID: "tenant-a", ReadBindingID: "gcp-reader", Kind: kind, GCP: &GCPScope{BillingAccountID: "ABCDEF-123456-ABC123", QueryProjectID: "query-project", DatasetProjectID: "source-project", DatasetID: "billing", TableID: table, Location: "EU", UsageProjectIDs: []string{"usage-project"}, MaximumBytesBilled: "1000000000"}}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func response(status int, raw []byte, headers map[string]string) *http.Response {
	h := http.Header{}
	for k, v := range headers {
		h.Set(k, v)
	}
	return &http.Response{StatusCode: status, Header: h, Body: io.NopCloser(bytes.NewReader(raw))}
}
func wire(t *testing.T, v any) []byte {
	t.Helper()
	b, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func config(r Registration, transport roundTripFunc) Config {
	b := ReadBinding{ID: r.ReadBindingID, TenantID: r.TenantID, ScopeHash: ScopeHash(r)}
	if r.Azure != nil {
		b.Provider = "AZURE"
		b.DirectoryTenantID = r.Azure.DirectoryTenantID
	} else {
		b.Provider = "GCP"
		b.BillingAccountID = r.GCP.BillingAccountID
		b.DatasetProjectID = r.GCP.DatasetProjectID
	}
	return Config{HTTP: &http.Client{Transport: transport}, Binding: b, Now: func() time.Time { return testNow }, Tokens: TokenFunc(func(_ context.Context, scope string) (string, error) { return "test-machine-token", nil })}
}
func wantError(t *testing.T, err error, code string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), code) {
		t.Fatalf("expected %s, got %v", code, err)
	}
}
func hasReason(reasons []string, reason string) bool {
	for _, r := range reasons {
		if r == reason {
			return true
		}
	}
	return false
}

func TestServerBindingCannotRetargetNativeCredential(t *testing.T) {
	for _, kind := range []Kind{AzureActual, GCPDetailed} {
		t.Run(string(kind), func(t *testing.T) {
			r := gcpRegistration(kind)
			if kind == AzureActual {
				r = azureRegistration(kind)
			}
			calls := 0
			c := config(r, func(*http.Request) (*http.Response, error) { calls++; return nil, nil })
			mutated := r
			if r.Azure != nil {
				a := *r.Azure
				a.Prefix = "other/"
				mutated.Azure = &a
			} else {
				g := *r.GCP
				g.QueryProjectID = "other-query-project"
				mutated.GCP = &g
			}
			wantError(t, c.validate(mutated, c.Binding.Provider), "READ_BINDING_MISMATCH")
			if calls != 0 {
				t.Fatal("retargeted request dispatched")
			}
			if ScopeHash(r) == ScopeHash(mutated) {
				t.Fatal("scope hash did not bind retargeted destination")
			}
		})
	}
}
func TestHTTPRejectsRedirectAndUnapprovedTarget(t *testing.T) {
	r := azureRegistration(AzureActual)
	calls := 0
	c := config(r, func(req *http.Request) (*http.Response, error) {
		calls++
		if req.URL.Host != "management.azure.com" {
			t.Fatal("credential forwarded")
		}
		return response(302, nil, map[string]string{"Location": "http://169.254.169.254/latest/meta-data"}), nil
	})
	_, _, err := c.request(context.Background(), http.MethodGet, "https://management.azure.com/test", armScope, nil, nil)
	wantError(t, err, "PROVIDER_REJECTED")
	if calls != 1 {
		t.Fatal("redirect followed")
	}
	for _, address := range []string{"http://management.azure.com/test", "https://169.254.169.254/", "https://management.azure.com:443/test", "https://management.azure.com.evil.test/", "https://name:secret@management.azure.com/test"} {
		_, _, err = c.request(context.Background(), http.MethodGet, address, armScope, nil, nil)
		wantError(t, err, "ENDPOINT_NOT_APPROVED")
	}
	if calls != 1 {
		t.Fatal("unapproved request dispatched")
	}
}
func TestExactMoneyLimitsAndUnknownValues(t *testing.T) {
	for in, want := range map[string]string{"0.10000000000000000001": "0.10000000000000000001", "-0.0050": "-0.005", "1.25e-3": "0.00125", "-0": "0"} {
		got, e := decimal(json.Number(in))
		if e != nil || got != want {
			t.Fatalf("%s => %s %v", in, got, e)
		}
	}
	for _, v := range []any{1.25, "NaN", "1e999999999999", "1e-61", "01", ""} {
		if _, e := decimal(v); e == nil {
			t.Fatalf("accepted unsafe decimal %v", v)
		}
	}
	if p, e := moneyPtr(nil); e != nil || p != nil {
		t.Fatal("unknown became zero")
	}
	totals := map[string]string{}
	for _, v := range []string{"0.10000000000000000001", "-0.005"} {
		p, _ := moneyPtr(v)
		addTotal(totals, "GBP", p)
	}
	if totals["GBP"] != "0.09500000000000000001" {
		t.Fatal(totals)
	}
}
func TestSnapshotCorrectionAndImportsNeverGrantAuthority(t *testing.T) {
	r := azureRegistration(AzureActual)
	a := CustomerImport(r, []Record{{ID: "row", Native: Document{"cost": "1"}}}, testNow)
	b := CustomerImport(r, []Record{{ID: "row", Native: Document{"cost": "2"}}}, testNow.Add(time.Minute))
	again := CustomerImport(r, a.Records, testNow.Add(time.Minute))
	if a.Revision == b.Revision || a.Revision != again.Revision {
		t.Fatal("revision must bind content, not polling time")
	}
	for _, s := range []Snapshot{a, b} {
		if s.ExecutionReady() || s.VerifiedSaving() != nil || s.Status != "PROVISIONAL" || !hasReason(s.ReasonCodes, "TRUSTED_PROVIDER_SOURCE_REQUIRED") {
			t.Fatal("untrusted upload gained authority")
		}
	}
}
