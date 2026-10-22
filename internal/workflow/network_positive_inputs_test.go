package workflow

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/native"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/service"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/source"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
)

// The customer-rate witness enters through the existing provider-shaped CUR
// reader and Python normalization, never through a canonical projection insert.
// This is deterministic synthetic evidence, not customer AWS acceptance.
func networkPositiveBilling(t *testing.T, ctx context.Context, apiDB, ingester *store.Store, archive *native.Storage, tenant, natID string, start, end time.Time) {
	t.Helper()
	byMonth := map[string][]model.Document{}
	for at := start; at.Before(end); at = at.Add(time.Hour) {
		for _, part := range []struct{ sku, usage, unit, quantity, cost string }{
			{"NETWORKHOUR", "EU-NatGateway-Hours", "Hrs", "1", "0.045"},
			{"NETWORKDATA", "EU-NatGateway-Bytes", "GB", "2", "0.09"},
		} {
			key := at.Format("2006-01")
			byMonth[key] = append(byMonth[key], model.Document{
				"identity_line_item_id":      "native-network-" + part.sku + "-" + at.Format("2006010215"),
				"line_item_usage_account_id": "111122223333", "line_item_resource_id": natID,
				"line_item_currency_code": "GBP", "line_item_line_item_type": "Usage",
				"line_item_usage_start_date": at.Format(time.RFC3339), "line_item_usage_end_date": at.Add(time.Hour).Format(time.RFC3339),
				"line_item_unblended_cost": part.cost, "line_item_net_unblended_cost": part.cost,
				"line_item_unblended_rate": "0.045", "line_item_net_unblended_rate": "0.045",
				"line_item_usage_amount": part.quantity, "line_item_usage_type": part.usage,
				"line_item_operation": "NatGateway", "product_servicecode": "AmazonEC2",
				"product_product_family": "NAT Gateway", "product_region_code": "eu-west-1",
				"product_sku": part.sku, "pricing_term": "OnDemand", "pricing_unit": part.unit,
				"pricing_rate_code": part.sku + ".native", "bill_invoice_id": "",
			})
		}
	}
	for month, rows := range byMonth {
		id := "network-native-cur-" + month + "-" + model.ID()
		d := source.FixtureRegistration(tenant, id)
		if err := apiDB.Do(ctx, tenant, func(tx *store.Tx) error { _, err := tx.SourceCreate(ctx, d); return err }); err != nil {
			t.Fatal(err)
		}
		registration, err := source.ParseRegistration(d)
		if err != nil {
			t.Fatal(err)
		}
		period, err := time.Parse("2006-01", month)
		if err != nil {
			t.Fatal(err)
		}
		reader, err := source.NewFixtureReaderForBillingPeriod(registration, rows, period)
		if err != nil {
			t.Fatal(err)
		}
		now := time.Now().UTC()
		reader.Execution["ExecutionStatus"] = model.Document{"StatusCode": "DELIVERY_SUCCESS", "CreatedAt": now.Add(-time.Second).Format(time.RFC3339Nano)}
		reader.Invoices = []model.Document{}
		for key, object := range reader.Objects {
			object.LastModified = now.Add(-time.Second)
			reader.Objects[key] = object
		}
		normalizer := &service.API{Config: service.Config{EconomicsURL: os.Getenv("ECONOMICS_TEST_URL"), EconomicsToken: os.Getenv("ECONOMICS_TEST_TOKEN")}}
		pipeline := source.Pipeline{Store: ingester, ProviderFactory: func(context.Context, source.Registration) (source.Reader, error) { return reader, nil }, Normalize: normalizer.NormalizeTrustedSource, Persist: service.PersistEvidence, ArchiveObject: func(c context.Context, tenant, _, key string, raw []byte) error {
			ref, err := archive.Archive(c, tenant, "wire", "network-billing-"+source.BytesHash([]byte(key)), raw)
			if err != nil {
				return err
			}
			back, err := archive.Read(c, tenant, ref)
			if err != nil || !bytes.Equal(back, raw) {
				return errors.New("native network billing archive readback differs")
			}
			return nil
		}}
		if err = pipeline.Sync(ctx, tenant, id); err != nil {
			t.Fatal("actual native-shaped network CUR pipeline", err)
		}
		if err = ingester.Do(ctx, tenant, func(tx *store.Tx) error {
			registered, err := tx.SourceGet(ctx, id)
			if err != nil {
				return err
			}
			if registered["status"] != "HEALTHY" {
				return errors.New("native network billing source incomplete")
			}
			receipt, err := tx.SourceReceiptGet(ctx, model.String(registered, "latest_receipt_id"))
			if err != nil {
				return err
			}
			job, err := tx.Get(ctx, "ingestion_jobs", model.String(receipt, "ingestion_job_id"))
			if err != nil {
				return err
			}
			if len(networkRows(networkDoc(job["canonical"])["records"])) != len(rows) {
				return errors.New("actual Python changed native network CUR population")
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		endpoint, err := url.Parse(archive.AnalyticsURL)
		if err != nil {
			t.Fatal(err)
		}
		q := endpoint.Query()
		q.Set("database", archive.Database)
		q.Set("query", "SELECT uniqExact(tuple(source_version,source_record_id)) FROM billing_facts WHERE tenant_id={tenant:String} AND source_id={source:String} FORMAT TabSeparated")
		q.Set("param_tenant", tenant)
		q.Set("param_source", id)
		endpoint.RawQuery = q.Encode()
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("X-ClickHouse-User", archive.AnalyticsUser)
		request.Header.Set("X-ClickHouse-Key", archive.AnalyticsSecret)
		response, err := archive.Client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(io.LimitReader(response.Body, 1024))
		_ = response.Body.Close()
		if err != nil || response.StatusCode != 200 || strings.TrimSpace(string(body)) != strconv.Itoa(len(rows)) {
			t.Fatal("native network CUR analytical population differs")
		}
	}
}

// Only dimensional catalogue metadata is authoritative. The deliberately
// different public amount is ignored by the native reader and cannot price a
// recommendation; its rate comes from the customer CUR witnesses above.
func networkPositivePriceReply(body []byte, start time.Time) (model.Document, error) {
	var request struct {
		ServiceCode string                          `json:"ServiceCode"`
		Filters     []struct{ Field, Value string } `json:"Filters"`
	}
	if json.Unmarshal(body, &request) != nil {
		return nil, errors.New("network native pricing request invalid")
	}
	sku := ""
	for _, filter := range request.Filters {
		if filter.Field == "sku" {
			if sku != "" {
				return nil, errors.New("network native pricing SKU ambiguous")
			}
			sku = filter.Value
		}
	}
	if sku != "NETWORKHOUR" && sku != "NETWORKDATA" {
		return nil, errors.New("network native pricing SKU unregistered")
	}
	if request.ServiceCode != "AmazonEC2" {
		return model.Document{"PriceList": []string{}}, nil
	}
	unit, usage := "Hrs", "EU-NatGateway-Hours"
	if sku == "NETWORKDATA" {
		unit, usage = "GB", "EU-NatGateway-Bytes"
	}
	product := model.Document{
		"product":         model.Document{"sku": sku, "productFamily": "NAT Gateway", "attributes": model.Document{"servicecode": "AmazonEC2", "regionCode": "eu-west-1", "usagetype": usage, "operation": "NatGateway"}},
		"publicationDate": start.Add(-time.Hour).Format(time.RFC3339),
		"terms":           model.Document{"OnDemand": model.Document{sku + ".OnDemand": model.Document{"effectiveDate": start.Add(-time.Hour).Format(time.RFC3339), "priceDimensions": model.Document{sku + ".native": model.Document{"rateCode": sku + ".native", "beginRange": "0", "endRange": "Inf", "unit": unit, "appliesTo": []string{}, "pricePerUnit": model.Document{"USD": "9999"}}}}}},
	}
	encoded, err := json.Marshal(product)
	if err != nil {
		return nil, err
	}
	return model.Document{"PriceList": []string{string(encoded)}}, nil
}
