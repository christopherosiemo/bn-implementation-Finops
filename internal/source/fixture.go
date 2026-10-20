package source

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strings"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/provider"
)

// FixtureReader is an explicit test adapter. Production AWSFactory never
// constructs it. Its native-shaped delivery passes the ordinary pipeline's
// policy, execution, manifest, gzip, version and row validation unchanged.
type FixtureReader struct {
	Registration Registration
	Execution    model.Document
	Executions   []model.Document
	Objects      map[string]provider.BillingObject
	ManifestKeys []string
	Invoices     []model.Document
	Commitments  model.Document
}

func FixtureRegistration(tenant, id string) model.Document {
	return model.Document{"id": id, "tenant_id": tenant, "version": 1, "kind": "AWS_CUR2", "payer_account_id": "111122223333", "usage_account_ids": []string{"111122223333"}, "region": "eu-west-1", "export_arn": "arn:aws:bcm-data-exports:us-east-1:111122223333:export/fixture-export", "bucket": "finops-fixture-cur2", "bucket_owner": "111122223333", "prefix": "cur/", "read_role_binding_id": "fixture-payer", "enabled": true}
}

// NewFixtureReader accepts caller-selected native records for integration tests.
// Nil records produce a complete September bill with one 10h45m owned stop.
// Rows are never accepted by the live factory or trusted merely by this shape.
func NewFixtureReader(r Registration, records []model.Document) (*FixtureReader, error) {
	return fixtureReaderForPeriod(r, records, time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC))
}

// NewFixtureReaderForBillingPeriod uses the same explicitly synthetic provider
// transport for a selected month. This is not a live ingestion entry point and
// does not change receipt, row, manifest or completeness validation.
func NewFixtureReaderForBillingPeriod(r Registration, records []model.Document, start time.Time) (*FixtureReader, error) {
	if start.Location() != time.UTC || start.Day() != 1 || start.Hour() != 0 || start.Minute() != 0 || start.Second() != 0 || start.Nanosecond() != 0 {
		return nil, errors.New("SOURCE_FIXTURE_BILLING_MONTH_REQUIRED")
	}
	return fixtureReaderForPeriod(r, records, start)
}

func fixtureReaderForPeriod(r Registration, records []model.Document, start time.Time) (*FixtureReader, error) {
	if len(r.UsageAccountIDs) == 0 {
		return nil, errors.New("SOURCE_USAGE_SCOPE_REQUIRED")
	}
	end := start.AddDate(0, 1, 0)
	if records == nil {
		records = FixtureBillingRows(r, "i-0123456789abcdef0")
	}
	name, execution := "fixture-cur2", "fixture-delivery"
	root := r.Prefix + name
	partition := start.Format("2006-01")
	deliveryTime := end.Format("20060102T150405Z")
	invoiceID := "fixture-invoice-" + partition
	manifestKey := root + "/metadata/BILLING_PERIOD=" + partition + "/" + deliveryTime + "-" + execution + "/Manifest.json"
	f := &FixtureReader{Registration: r, Objects: map[string]provider.BillingObject{}, ManifestKeys: []string{manifestKey}, Commitments: model.Document{"payer_account_id": r.PayerAccountID, "usage_account_ids": r.UsageAccountIDs, "scope": "PAYER_ALL_LINKED_ACCOUNTS_ALL_REGIONS", "complete": true, "reserved_instance_count": 0, "savings_plan_count": 0, "native_snapshots": []model.Document{{"account_id": r.PayerAccountID, "reserved_instances": []model.Document{}, "savings_plans": []model.Document{}, "regions": []string{r.Region}}}}}
	f.Execution = model.Document{"ExecutionId": execution, "ExecutionStatus": model.Document{"StatusCode": "DELIVERY_SUCCESS", "CreatedAt": end.Add(-time.Minute).Format(time.RFC3339)}, "Export": model.Document{"ExportArn": r.ExportARN, "Name": name, "DataQuery": model.Document{"QueryStatement": "SELECT * FROM COST_AND_USAGE_REPORT", "TableConfigurations": model.Document{"COST_AND_USAGE_REPORT": model.Document{"TIME_GRANULARITY": "HOURLY", "INCLUDE_RESOURCES": "TRUE"}}}, "DestinationConfigurations": model.Document{"S3Destination": model.Document{"S3Bucket": r.Bucket, "S3BucketOwner": r.BucketOwner, "S3Prefix": r.Prefix, "S3Region": r.Region, "S3OutputConfigurations": model.Document{"Format": "TEXT_OR_CSV", "Compression": "GZIP", "Overwrite": "CREATE_NEW_REPORT"}}}}}
	keys := []string{}
	for first := 0; first < len(records); first += 400 {
		last := first + 400
		if last > len(records) {
			last = len(records)
		}
		key := fmt.Sprintf("%s/data/BILLING_PERIOD=%s/%s-%s/part-%03d.csv.gz", root, partition, deliveryTime, execution, len(keys))
		var plain bytes.Buffer
		zip := gzip.NewWriter(&plain)
		writer := csv.NewWriter(zip)
		columns := append([]string{}, requiredColumns...)
		extra := map[string]bool{}
		for _, row := range records[first:last] {
			for k := range row {
				if !contains(columns, k) {
					extra[k] = true
				}
			}
		}
		extras := []string{}
		for k := range extra {
			extras = append(extras, k)
		}
		sort.Strings(extras)
		columns = append(columns, extras...)
		if err := writer.Write(columns); err != nil {
			return nil, err
		}
		for _, original := range records[first:last] {
			row := model.Clone(original)
			row["bill_payer_account_id"] = r.PayerAccountID
			row["bill_billing_period_start_date"] = start.Format(time.RFC3339)
			row["bill_billing_period_end_date"] = end.Format(time.RFC3339)
			if _, ok := row["bill_invoicing_entity"]; !ok {
				row["bill_invoicing_entity"] = "Amazon Web Services EMEA SARL"
			}
			if _, ok := row["bill_invoice_id"]; !ok {
				row["bill_invoice_id"] = invoiceID
			}
			values := make([]string, len(columns))
			for i, k := range columns {
				values[i] = model.String(row, k)
			}
			if err := writer.Write(values); err != nil {
				return nil, err
			}
		}
		writer.Flush()
		if err := writer.Error(); err != nil {
			return nil, err
		}
		if err := zip.Close(); err != nil {
			return nil, err
		}
		data := plain.Bytes()
		f.Objects[key] = provider.BillingObject{Key: key, VersionID: "v1-" + BytesHash(data), ETag: BytesHash(data), LastModified: end, Data: data}
		keys = append(keys, key)
	}
	manifest, _ := json.Marshal(model.Document{"reportKeys": keys, "columns": requiredColumns, "billingPeriod": model.Document{"start": start.Format(time.RFC3339), "end": end.Format(time.RFC3339)}})
	f.Objects[manifestKey] = provider.BillingObject{Key: manifestKey, VersionID: "v1-" + BytesHash(manifest), ETag: BytesHash(manifest), LastModified: end.Add(time.Minute), Data: manifest}
	total := new(big.Rat)
	for _, row := range records {
		amount, ok := new(big.Rat).SetString(model.String(row, "line_item_unblended_cost"))
		if !ok {
			return nil, errors.New("fixture cost invalid")
		}
		total.Add(total, amount)
	}
	f.Invoices = []model.Document{{"AccountId": r.PayerAccountID, "InvoiceId": invoiceID, "InvoiceType": "INVOICE", "IssuedDate": end.Add(12 * time.Hour).Format(time.RFC3339), "TaxAuthorityStatus": "ISSUED", "BillingPeriod": model.Document{"Year": start.Year(), "Month": int(start.Month())}, "Entity": model.Document{"InvoicingEntity": "Amazon Web Services EMEA SARL"}, "BaseCurrencyAmount": model.Document{"CurrencyCode": "GBP", "TotalAmount": total.FloatString(12)}}}
	return f, nil
}

func FixtureBillingRows(r Registration, resource string) []model.Document {
	start := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	end := start.AddDate(0, 1, 0)
	rows := []model.Document{}
	stop := time.Date(2026, 9, 16, 20, 0, 0, 0, time.UTC)
	running := time.Date(2026, 9, 17, 6, 45, 0, 0, time.UTC)
	for at := start; at.Before(end); at = at.Add(time.Hour) {
		next := at.Add(time.Hour)
		from := at
		cost := "0.48"
		if !at.Before(stop) && !next.After(running) {
			continue
		}
		if at.Before(running) && next.After(running) {
			from = running
			cost = "0.12"
		}
		rows = append(rows, model.Document{"identity_line_item_id": "fixture-" + at.Format("20060102T150405"), "line_item_usage_account_id": r.UsageAccountIDs[0], "line_item_resource_id": resource, "line_item_currency_code": "GBP", "line_item_line_item_type": "Usage", "line_item_usage_start_date": from.Format(time.RFC3339), "line_item_usage_end_date": next.Format(time.RFC3339), "line_item_unblended_cost": cost, "pricing_term": "OnDemand", "line_item_operation": "RunInstances", "product_servicecode": "AmazonEC2", "product_region_code": r.Region})
	}
	return rows
}
func (f *FixtureReader) ListBillingExecutions(context.Context, string) ([]model.Document, error) {
	if len(f.Executions) > 0 {
		return Rows(f.Executions), nil
	}
	return []model.Document{model.Clone(f.Execution)}, nil
}
func (f *FixtureReader) BillingExecution(_ context.Context, arn, id string) (model.Document, error) {
	if arn == f.Registration.ExportARN {
		for _, x := range f.Executions {
			if model.String(x, "ExecutionId") == id {
				return model.Clone(x), nil
			}
		}
	}
	if arn != f.Registration.ExportARN || id != model.String(f.Execution, "ExecutionId") {
		return nil, errors.New("fixture execution missing")
	}
	return model.Clone(f.Execution), nil
}
func (f *FixtureReader) BillingManifestKeys(_ context.Context, bucket, prefix, execution string) ([]string, error) {
	keys := []string{}
	for _, k := range f.ManifestKeys {
		if strings.HasPrefix(k, prefix) && strings.Contains(k, "-"+execution+"/") {
			keys = append(keys, k)
		}
	}
	return keys, nil
}
func (f *FixtureReader) BillingObject(_ context.Context, bucket, key, version string) (provider.BillingObject, error) {
	o, ok := f.Objects[key]
	if !ok || bucket != f.Registration.Bucket || (version != "" && version != o.VersionID) {
		return o, errors.New("fixture version unavailable")
	}
	o.Data = append([]byte{}, o.Data...)
	return o, nil
}
func (f *FixtureReader) BillingBucket(context.Context, string) (model.Document, error) {
	return FixtureBucketPolicy(f.Registration), nil
}
func (f *FixtureReader) BillingInvoices(context.Context, string, int, int) ([]model.Document, error) {
	return Rows(f.Invoices), nil
}
func (f *FixtureReader) BillingCommitments(context.Context, string) (model.Document, error) {
	return model.Clone(f.Commitments), nil
}

func FixtureBucketPolicy(r Registration) model.Document {
	resource := "arn:aws:s3:::" + r.Bucket + "/" + r.Prefix + "*"
	actions := []string{"s3:PutObject", "s3:DeleteObject", "s3:DeleteObjectVersion"}
	statements := []model.Document{{"Effect": "Allow", "Principal": model.Document{"Service": "bcm-data-exports.amazonaws.com"}, "Action": "s3:PutObject", "Resource": resource, "Condition": model.Document{"StringEquals": model.Document{"aws:SourceAccount": r.PayerAccountID, "aws:SourceArn": r.ExportARN}}}}
	for _, condition := range []struct{ key, value string }{{"aws:PrincipalServiceName", "bcm-data-exports.amazonaws.com"}, {"aws:SourceArn", r.ExportARN}, {"aws:SourceAccount", r.PayerAccountID}} {
		statements = append(statements, model.Document{"Effect": "Deny", "Principal": "*", "Action": actions, "Resource": resource, "Condition": model.Document{"StringNotEqualsIfExists": model.Document{condition.key: condition.value}}})
	}
	return model.Document{"versioning": "Enabled", "region": r.Region, "bucket_owner": r.BucketOwner, "policy": model.Document{"Version": "2012-10-17", "Statement": statements}}
}
