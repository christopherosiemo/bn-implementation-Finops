package source

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"io"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"
)

func Hash(v any) string         { b, _ := json.Marshal(v); return BytesHash(b) }
func BytesHash(b []byte) string { x := sha256.Sum256(b); return hex.EncodeToString(x[:]) }
func ConfigurationHash(d model.Document) string {
	copy := model.Document{}
	for _, k := range []string{"kind", "payer_account_id", "usage_account_ids", "region", "export_arn", "bucket", "bucket_owner", "prefix", "read_role_binding_id"} {
		copy[k] = d[k]
	}
	ids := append([]string{}, model.Strings(d, "usage_account_ids")...)
	sort.Strings(ids)
	copy["usage_account_ids"] = ids
	return Hash(copy)
}
func stringValues(v any) []string {
	if s, ok := v.(string); ok {
		return []string{s}
	}
	var out []string
	b, _ := json.Marshal(v)
	_ = json.Unmarshal(b, &out)
	return out
}
func contains(v []string, s string) bool {
	for _, x := range v {
		if x == s {
			return true
		}
	}
	return false
}
func actionCovers(v any, action string) bool {
	for _, a := range stringValues(v) {
		if strings.EqualFold(a, action) || a == "s3:*" || a == "*" {
			return true
		}
	}
	return false
}

// ValidateWriterPolicy accepts a deliberately narrow, auditable policy shape:
// exact Data Exports source ARN/account allow, plus separate explicit denies
// for every other service, source ARN and source account on the full prefix.
// An Allow alone, or a deny that exempts every Data Export, is not proof.
func ValidateWriterPolicy(r Registration, bucket model.Document) error {
	if model.String(bucket, "versioning") != "Enabled" || model.String(bucket, "region") != r.Region || model.String(bucket, "bucket_owner") != r.BucketOwner {
		return errors.New("SOURCE_BUCKET_BOUNDARY_INVALID")
	}
	resource := "arn:aws:s3:::" + r.Bucket + "/" + r.Prefix + "*"
	allow, deny, denyARN, denyAccount := false, false, false, false
	for _, s := range Rows(Object(bucket["policy"])["Statement"]) {
		if !contains(stringValues(s["Resource"]), resource) {
			continue
		}
		condition := Object(s["Condition"])
		if model.String(s, "Effect") == "Allow" && contains(stringValues(Object(s["Principal"])["Service"]), "bcm-data-exports.amazonaws.com") && actionCovers(s["Action"], "s3:PutObject") {
			eq := Object(condition["StringEquals"])
			arn := model.String(eq, "aws:SourceArn")
			if arn == "" {
				arn = model.String(Object(condition["ArnEquals"]), "aws:SourceArn")
			}
			if arn == r.ExportARN && model.String(eq, "aws:SourceAccount") == r.PayerAccountID {
				allow = true
			}
		}
		if model.String(s, "Effect") == "Deny" && s["Principal"] == "*" && actionCovers(s["Action"], "s3:PutObject") && actionCovers(s["Action"], "s3:DeleteObject") && actionCovers(s["Action"], "s3:DeleteObjectVersion") {
			notEq := Object(condition["StringNotEqualsIfExists"])
			if model.String(notEq, "aws:PrincipalServiceName") == "bcm-data-exports.amazonaws.com" && len(condition) == 1 && len(notEq) == 1 {
				deny = true
			}
			if model.String(notEq, "aws:SourceArn") == r.ExportARN && len(condition) == 1 && len(notEq) == 1 {
				denyARN = true
			}
			if model.String(notEq, "aws:SourceAccount") == r.PayerAccountID && len(condition) == 1 && len(notEq) == 1 {
				denyAccount = true
			}
		}
	}
	if !allow || !deny || !denyARN || !denyAccount {
		return errors.New("SOURCE_WRITER_POLICY_REQUIRED")
	}
	return nil
}
func ValidateExecution(r Registration, d model.Document) (string, error) {
	if model.String(Object(d["ExecutionStatus"]), "StatusCode") != "DELIVERY_SUCCESS" {
		return "", errors.New("SOURCE_DELIVERY_NOT_COMPLETE")
	}
	if _, e := time.Parse(time.RFC3339Nano, model.String(Object(d["ExecutionStatus"]), "CreatedAt")); e != nil {
		return "", errors.New("SOURCE_EXECUTION_TIME_REQUIRED")
	}
	export := Object(d["Export"])
	if model.String(export, "ExportArn") != r.ExportARN {
		return "", errors.New("SOURCE_EXPORT_BINDING_INVALID")
	}
	query := Object(export["DataQuery"])
	sql := strings.Join(strings.Fields(strings.TrimSuffix(strings.TrimSpace(model.String(query, "QueryStatement")), ";")), " ")
	if strings.ToUpper(sql) != "SELECT * FROM COST_AND_USAGE_REPORT" {
		return "", errors.New("SOURCE_UNFILTERED_QUERY_REQUIRED")
	}
	config := Object(Object(query["TableConfigurations"])["COST_AND_USAGE_REPORT"])
	if model.String(config, "TIME_GRANULARITY") != "HOURLY" || model.String(config, "INCLUDE_RESOURCES") != "TRUE" {
		return "", errors.New("SOURCE_HOURLY_RESOURCES_REQUIRED")
	}
	destination := Object(Object(export["DestinationConfigurations"])["S3Destination"])
	if model.String(destination, "S3Bucket") != r.Bucket || model.String(destination, "S3BucketOwner") != r.BucketOwner || strings.TrimSuffix(model.String(destination, "S3Prefix"), "/")+"/" != r.Prefix || model.String(destination, "S3Region") != r.Region {
		return "", errors.New("SOURCE_DESTINATION_MISMATCH")
	}
	format := Object(destination["S3OutputConfigurations"])
	if model.String(format, "Format") != "TEXT_OR_CSV" || model.String(format, "Compression") != "GZIP" || model.String(format, "Overwrite") != "CREATE_NEW_REPORT" {
		return "", errors.New("SOURCE_FORMAT_UNSUPPORTED")
	}
	name := model.String(export, "Name")
	if name == "" || strings.ContainsAny(name, "/\\\x00") || name == ".." {
		return "", errors.New("SOURCE_EXPORT_NAME_INVALID")
	}
	return name, nil
}

func ValidateExecutionTime(d model.Document, now time.Time) error {
	status := Object(d["ExecutionStatus"])
	for _, key := range []string{"CreatedAt", "CompletedAt", "LastUpdatedAt"} {
		value := model.String(status, key)
		if value == "" && key != "CreatedAt" {
			continue
		}
		observed, e := time.Parse(time.RFC3339Nano, value)
		if e != nil || observed.After(now.Add(30*time.Second)) {
			return errors.New("SOURCE_EXECUTION_TIME_INVALID")
		}
	}
	return nil
}

type Manifest struct {
	Keys       []string
	Start, End time.Time
	Raw        model.Document
}

var partitionPattern = regexp.MustCompile(`(?:^|/)BILLING_PERIOD=([0-9]{4}-[0-9]{2})/`)
var currencyPattern = regexp.MustCompile(`^[A-Z]{3}$`)

func ParseManifest(r Registration, exportName, execution, key string, b []byte) (Manifest, error) {
	var m Manifest
	if len(b) > 2<<20 {
		return m, errors.New("SOURCE_MANIFEST_LIMIT")
	}
	if !strings.HasPrefix(key, r.Prefix+exportName+"/metadata/") || !strings.Contains(key, "-"+execution+"/") {
		return m, errors.New("SOURCE_MANIFEST_PATH_INVALID")
	}
	match := partitionPattern.FindStringSubmatch(key)
	if len(match) != 2 {
		return m, errors.New("SOURCE_PARTITION_REQUIRED")
	}
	start, e := time.Parse("2006-01", match[1])
	if e != nil {
		return m, e
	}
	m.Start, m.End = start, start.AddDate(0, 1, 0)
	if e = json.Unmarshal(b, &m.Raw); e != nil {
		return m, errors.New("SOURCE_MANIFEST_INVALID")
	}
	m.Keys = stringValues(m.Raw["reportKeys"])
	if len(m.Keys) == 0 || len(m.Keys) > 256 {
		return m, errors.New("SOURCE_MANIFEST_FILES_REQUIRED")
	}
	seen := map[string]bool{}
	for _, object := range m.Keys {
		if !strings.HasPrefix(object, r.Prefix+exportName+"/data/BILLING_PERIOD="+match[1]+"/") || !strings.Contains(object, "-"+execution+"/") || path.Clean(object) != object || strings.ContainsAny(object, "\\\x00") || !strings.HasSuffix(object, ".csv.gz") || seen[object] {
			return m, errors.New("SOURCE_MANIFEST_OBJECT_INVALID")
		}
		seen[object] = true
	}
	for _, k := range []string{"exportArn", "exportARN"} {
		if v := model.String(m.Raw, k); v != "" && v != r.ExportARN {
			return m, errors.New("SOURCE_MANIFEST_EXPORT_MISMATCH")
		}
	}
	sort.Strings(m.Keys)
	return m, nil
}

var requiredColumns = []string{"identity_line_item_id", "line_item_usage_account_id", "line_item_resource_id", "line_item_currency_code", "line_item_line_item_type", "line_item_usage_start_date", "line_item_usage_end_date", "line_item_unblended_cost", "bill_payer_account_id", "bill_invoice_id", "bill_invoicing_entity", "bill_billing_period_start_date", "bill_billing_period_end_date", "pricing_term", "line_item_operation", "product_servicecode", "product_region_code"}

func ParseGzipCSV(b []byte) ([]model.Document, error) {
	if len(b) > 64<<20 {
		return nil, errors.New("SOURCE_OBJECT_LIMIT")
	}
	g, e := gzip.NewReader(bytes.NewReader(b))
	if e != nil {
		return nil, errors.New("SOURCE_COMPRESSION_INVALID")
	}
	defer g.Close()
	limited := &io.LimitedReader{R: g, N: (256 << 20) + 1}
	c := csv.NewReader(limited)
	c.ReuseRecord = false
	header, e := c.Read()
	if e != nil {
		return nil, errors.New("SOURCE_CSV_HEADER_INVALID")
	}
	seen := map[string]bool{}
	for n, h := range header {
		h = strings.TrimPrefix(h, "\ufeff")
		header[n] = h
		if h == "" || seen[h] {
			return nil, errors.New("SOURCE_CSV_HEADER_INVALID")
		}
		seen[h] = true
	}
	for _, name := range requiredColumns {
		if !seen[name] {
			return nil, errors.New("SOURCE_SCHEMA_COLUMN_MISSING:" + name)
		}
	}
	rows := []model.Document{}
	for {
		record, e := c.Read()
		if e == io.EOF {
			break
		}
		if e != nil {
			return nil, errors.New("SOURCE_CSV_INVALID")
		}
		if len(rows) >= 100000 {
			return nil, errors.New("SOURCE_ROW_LIMIT")
		}
		row := model.Document{}
		for n, value := range record {
			row[header[n]] = value
		}
		rows = append(rows, row)
	}
	if limited.N <= 0 {
		return nil, errors.New("SOURCE_DECOMPRESSED_LIMIT")
	}
	return rows, nil
}

func ValidateRows(r Registration, m Manifest, rows []model.Document) error {
	seen := map[string]bool{}
	for _, row := range rows {
		if model.String(row, "bill_payer_account_id") != r.PayerAccountID {
			return errors.New("SOURCE_PAYER_MISMATCH")
		}
		id := model.String(row, "identity_line_item_id")
		if id == "" || seen[id] {
			return errors.New("SOURCE_DUPLICATE_RECORD")
		}
		seen[id] = true
		start, e1 := time.Parse(time.RFC3339Nano, model.String(row, "line_item_usage_start_date"))
		end, e2 := time.Parse(time.RFC3339Nano, model.String(row, "line_item_usage_end_date"))
		if e1 != nil || e2 != nil || !start.Before(end) || start.Before(m.Start) || end.After(m.End) {
			return errors.New("SOURCE_USAGE_PERIOD_INVALID")
		}
		billStart, e1 := time.Parse(time.RFC3339Nano, model.String(row, "bill_billing_period_start_date"))
		billEnd, e2 := time.Parse(time.RFC3339Nano, model.String(row, "bill_billing_period_end_date"))
		if e1 != nil || e2 != nil || !billStart.Equal(m.Start) || !billEnd.Equal(m.End) {
			return errors.New("SOURCE_BILLING_PERIOD_MISMATCH")
		}
		account := model.String(row, "line_item_usage_account_id")
		if !accountPattern.MatchString(account) {
			return errors.New("SOURCE_USAGE_ACCOUNT_INVALID")
		}
		if !currencyPattern.MatchString(model.String(row, "line_item_currency_code")) {
			return errors.New("SOURCE_CURRENCY_INVALID")
		}
	}
	return nil
}
