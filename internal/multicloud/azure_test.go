package multicloud

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestAzureCostKindsAndScopePrecision(t *testing.T) {
	actual := "BillingAccountId,SubscriptionId,ResourceId,BillingCurrencyCode,CostInBillingCurrency,Date,ChargeType\nbilling-a," + subscription + ",/subscriptions/" + subscription + "/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm,GBP,0.10000000000000000001,2026-10-01,Usage\n"
	for _, kind := range []Kind{AzureActual, AzureAmortized} {
		r := azureRegistration(kind)
		rows, e := ParseAzureCSV(r, []byte(actual), "None", "part.csv")
		if e != nil {
			t.Fatal(e)
		}
		row := rows[0]
		if row.ChargeStart != nil || row.ChargeEnd != nil || row.ListCost != nil {
			t.Fatal("inferred boundaries or list cost")
		}
		if kind == AzureActual {
			if row.BilledCost == nil || *row.BilledCost != "0.10000000000000000001" || row.EffectiveCost != nil {
				t.Fatal(row)
			}
		} else if row.BilledCost != nil || row.EffectiveCost == nil {
			t.Fatal("amortized substituted for invoice bill")
		}
	}
	focus := "BillingCurrency,BilledCost,EffectiveCost,ListCost,BillingAccountId,SubAccountId,ChargePeriodStart,ChargePeriodEnd,ChargeClass\nGBP,-0.0100,0.008,0.02,billing-a," + subscription + ",2026-10-01T00:00:00Z,2026-10-01T01:00:00Z,Correction\n"
	rows, e := ParseAzureCSV(azureRegistration(AzureFOCUS), []byte(focus), "None", "part.csv")
	if e != nil || *rows[0].BilledCost != "-0.01" || rows[0].ChargeClass != "Correction" {
		t.Fatalf("focus %v %v", rows, e)
	}
	_, e = ParseAzureCSV(azureRegistration(AzureActual), []byte(strings.ReplaceAll(actual, subscription, directory)), "None", "part.csv")
	wantError(t, e, "ROW_SUBSCRIPTION_MISMATCH")
	_, e = ParseAzureCSV(azureRegistration(AzureActual), []byte("BillingCurrencyCode,billingcurrencycode,CostInBillingCurrency\nGBP,GBP,1\n"), "None", "part.csv")
	wantError(t, e, "HEADER_AMBIGUOUS")
	unknown := strings.Replace(actual, "GBP,0.10000000000000000001", ",0.10000000000000000001", 1)
	rows, e = ParseAzureCSV(azureRegistration(AzureActual), []byte(unknown), "None", "part.csv")
	if e != nil || rows[0].BilledCost != nil || !hasReason(rows[0].MappingGaps, "BILLING_CURRENCY_MISSING") {
		t.Fatal("missing currency fabricated money")
	}
}
func TestAzureGzipAndPartitionLimits(t *testing.T) {
	var compressed bytes.Buffer
	gz := gzip.NewWriter(&compressed)
	_, _ = gz.Write([]byte("BillingCurrencyCode,CostInBillingCurrency\nGBP,1.25\n"))
	_ = gz.Close()
	rows, e := ParseAzureCSV(azureRegistration(AzureActual), compressed.Bytes(), "Gzip", "part.csv.gz")
	if e != nil || len(rows) != 1 || *rows[0].BilledCost != "1.25" {
		t.Fatal(rows, e)
	}
	_, e = ParseAzureCSV(azureRegistration(AzureActual), []byte("not gzip"), "Gzip", "part")
	wantError(t, e, "GZIP_INVALID")
	_, e = ParseAzureCSV(azureRegistration(AzureActual), []byte("BillingCurrencyCode,CostInBillingCurrency,extra\nGBP,1,"+strings.Repeat("x", 65537)+"\n"), "None", "part")
	wantError(t, e, "FIELD_LIMIT")
	compressed.Reset()
	gz = gzip.NewWriter(&compressed)
	_, _ = io.Copy(gz, io.LimitReader(zeroReader{}, MaxBodyBytes+1))
	_ = gz.Close()
	_, e = ParseAzureCSV(azureRegistration(AzureActual), compressed.Bytes(), "Gzip", "bomb.csv.gz")
	wantError(t, e, "DECODED_PARTITION_LIMIT")
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) { clear(p); return len(p), nil }

type azureDouble struct {
	t         *testing.T
	r         Registration
	mutation  string
	calls     int
	blobCalls int
}

func (a *azureDouble) transport(req *http.Request) (*http.Response, error) {
	a.calls++
	if req.Header.Get("Authorization") != "Bearer test-machine-token" {
		a.t.Fatal("machine identity missing")
	}
	scope := a.r.Azure
	settings := Document{"format": "Csv", "compressionMode": "None", "partitionData": true, "definition": Document{"type": azureType(a.r.Kind), "dataSet": Document{"configuration": Document{"dataVersion": scope.DataVersion}}}, "deliveryInfo": Document{"destination": Document{"resourceId": scope.StorageAccountResourceID, "container": scope.Container, "rootFolderPath": scope.Prefix}}}
	if req.URL.Host == "management.azure.com" {
		if req.URL.Path == scope.ExportResourceID {
			return response(200, wire(a.t, Document{"id": scope.ExportResourceID, "properties": settings}), nil), nil
		}
		if strings.HasSuffix(req.URL.Path, "/runHistory") {
			if req.URL.Query().Get("page") == "" {
				next := "https://management.azure.com" + scope.ExportResourceID + "/runHistory?page=2"
				if a.mutation == "next" {
					next = "https://evil.test/runHistory"
				}
				return response(200, wire(a.t, Document{"value": []any{}, "nextLink": next}), nil), nil
			}
			if a.mutation == "history" {
				delete(settings, "definition")
			}
			run := Document{"id": scope.ExportResourceID + "/Run/" + runID, "properties": Document{"status": "Completed", "submittedTime": "2026-10-18T10:00:00Z", "processingEndTime": "2026-10-18T10:01:00Z", "startDate": "2026-10-01T00:00:00Z", "endDate": "2026-10-17T00:00:00Z", "manifestFile": "exports/manifest.json", "runSettings": settings}}
			return response(200, wire(a.t, Document{"value": []any{run}}), nil), nil
		}
	}
	if req.URL.Host != "finopsbilling.blob.core.windows.net" {
		a.t.Fatalf("unexpected host %s", req.URL.Host)
	}
	a.blobCalls++
	part := []byte("BillingAccountId,SubscriptionId,BillingCurrencyCode,CostInBillingCurrency\nbilling-a," + subscription + ",GBP,1.2500\nbilling-a," + subscription + ",GBP,-0.005\n")
	if a.r.Kind == AzureFOCUS {
		part = []byte("BillingAccountId,SubAccountId,BillingCurrency,BilledCost,EffectiveCost\nbilling-a," + subscription + ",GBP,1.2500,1.1\nbilling-a," + subscription + ",GBP,-0.005,-0.005\n")
	}
	body := part
	if strings.HasSuffix(req.URL.Path, "manifest.json") {
		name := "exports/part.csv"
		count := 2
		if a.mutation == "path" {
			name = "../private.csv"
		}
		if a.mutation == "count" {
			count = 3
		}
		start := "2026-10-01T00:00:00Z"
		if a.mutation == "period" {
			start = "2026-10-02T00:00:00Z"
		}
		body = wire(a.t, Document{"manifestVersion": "2024-04-01", "blobCount": 1, "dataRowCount": count, "byteCount": len(part), "exportConfig": Document{"resourceId": scope.ExportResourceID, "dataVersion": scope.DataVersion, "type": azureType(a.r.Kind)}, "deliveryConfig": Document{"containerUri": scope.StorageAccountResourceID, "rootFolderPath": scope.Prefix, "fileFormat": "Csv", "compressionMode": "None"}, "runInfo": Document{"runId": runID, "submittedTime": "2026-10-18T10:00:00Z", "startDate": start, "endDate": "2026-10-17T00:00:00Z"}, "blobs": []any{Document{"blobName": name, "byteCount": len(part), "dataRowCount": count}}})
	}
	headers := map[string]string{"x-ms-version-id": "2026-10-18T10:00:30Z", "ETag": "\"version-etag\"", "Last-Modified": time.Date(2026, 10, 18, 10, 0, 30, 0, time.UTC).Format(http.TimeFormat)}
	if req.URL.Query().Get("versionid") != "" {
		if req.Header.Get("If-Match") != "\"version-etag\"" {
			a.t.Fatal("version re-read missing fence")
		}
		if a.mutation == "race" {
			headers["ETag"] = "\"changed\""
		}
	}
	if a.mutation == "version" {
		delete(headers, "x-ms-version-id")
	}
	return response(200, body, headers), nil
}
func TestAzureNativeJourneyPinsAllPartitionsAndCorrections(t *testing.T) {
	r := azureRegistration(AzureActual)
	d := &azureDouble{t: t, r: r}
	s, e := (AzureReader{Config: config(r, d.transport)}).Collect(context.Background(), r, AzureRequest{})
	if e != nil {
		t.Fatal(e)
	}
	if s.NativeRowCount != 2 || len(s.Records) != 2 || s.BilledTotals["GBP"] != "1.245" || len(s.Objects) != 5 || d.blobCalls != 4 || s.ExecutionReady() || s.VerifiedSaving() != nil {
		t.Fatalf("unexpected snapshot %+v calls %d", s, d.blobCalls)
	}
	for _, o := range s.Objects {
		if o.SHA256 != BytesHash(o.Body) {
			t.Fatal("original wire hash lost")
		}
		if o.Kind == "AZURE_COST_PARTITION" && !strings.Contains(o.Resource, "versionid=") {
			t.Fatal("partition not pinned")
		}
	}
}
func TestAzureNativeJourneyFailsClosed(t *testing.T) {
	for mutation, code := range map[string]string{"next": "NEXT_LINK_INVALID", "history": "EXPORT_CONFIGURATION_MISMATCH", "path": "PARTITION_INVALID", "count": "ROW_COUNT_MISMATCH", "period": "PERIOD_MISMATCH", "race": "CHANGED_DURING_READ", "version": "VERSIONED_BLOB_REQUIRED"} {
		t.Run(mutation, func(t *testing.T) {
			r := azureRegistration(AzureActual)
			d := &azureDouble{t: t, r: r, mutation: mutation}
			_, e := (AzureReader{Config: config(r, d.transport)}).Collect(context.Background(), r, AzureRequest{})
			wantError(t, e, code)
		})
	}
}
func TestAzureNativeAuxiliaryCostKindsStayDistinct(t *testing.T) {
	for _, kind := range []Kind{AzureAmortized, AzureFOCUS} {
		t.Run(string(kind), func(t *testing.T) {
			r := azureRegistration(kind)
			d := &azureDouble{t: t, r: r}
			s, e := (AzureReader{Config: config(r, d.transport)}).Collect(context.Background(), r, AzureRequest{})
			if e != nil {
				t.Fatal(e)
			}
			if s.Kind != kind || s.NativeRowCount != 2 || s.ExecutionReady() || s.VerifiedSaving() != nil {
				t.Fatal("native kind or permanent gate lost")
			}
			if kind == AzureAmortized {
				if len(s.BilledTotals) != 0 || s.AmortizedTotals["GBP"] != "1.245" {
					t.Fatal("amortized treated as billed", s)
				}
			} else if s.BilledTotals["GBP"] != "1.245" || *s.Records[0].EffectiveCost != "1.1" {
				t.Fatal("focus cost distinctions lost")
			}
		})
	}
}
