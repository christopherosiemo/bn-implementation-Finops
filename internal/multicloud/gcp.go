package multicloud

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const bigQueryScope = "https://www.googleapis.com/auth/bigquery.readonly"
const cloudBillingScope = "https://www.googleapis.com/auth/cloud-billing.readonly"
const bigQueryAPI = "https://bigquery.googleapis.com/bigquery/v2"

type GCPReader struct{ Config Config }

// Query is server-built, parameterized and limited to a single registered table.
// Calling Collect in a future live deployment creates a potentially billable
// read-only query job; maximumBytesBilled and IAM job/data-read scopes are required.
// Tests use HTTP doubles exclusively. No free-form SQL or mutating job is accepted.
func Query(r Registration, p Period, asOf time.Time) (Document, error) {
	if err := Validate(r); err != nil {
		return nil, err
	}
	if r.GCP == nil || !periodValid(p, asOf.Add(5*time.Second)) {
		return nil, errors.New("GCP_QUERY_PERIOD_INVALID")
	}
	g := r.GCP
	params := []any{parameter("billing", "STRING", g.BillingAccountID), parameter("as_of", "TIMESTAMP", asOf.Format(time.RFC3339Nano))}
	filter := "billing_account_id = @billing"
	if r.Kind == GCPDetailed {
		filter += " AND ((usage_start_time < @period_end AND usage_end_time > @period_start) OR invoice.month BETWEEN @first_invoice AND @last_invoice)"
		params = append(params, parameter("period_start", "TIMESTAMP", p.Start.Format(time.RFC3339Nano)), parameter("period_end", "TIMESTAMP", p.End.Format(time.RFC3339Nano)), parameter("first_invoice", "STRING", p.Start.UTC().Format("200601")), parameter("last_invoice", "STRING", p.End.Add(-time.Nanosecond).UTC().Format("200601")))
	}
	if r.Kind == GCPPricing {
		filter += " AND pricing_as_of_time >= @period_start AND pricing_as_of_time < @period_end"
		params = append(params, parameter("period_start", "TIMESTAMP", p.Start.Format(time.RFC3339Nano)), parameter("period_end", "TIMESTAMP", p.End.Format(time.RFC3339Nano)))
	}
	sql := "SELECT TO_JSON_STRING(t) AS native_row FROM `" + g.DatasetProjectID + "." + g.DatasetID + "." + g.TableID + "` FOR SYSTEM_TIME AS OF @as_of AS t WHERE " + filter
	request := Document{"query": sql, "useLegacySql": false, "useQueryCache": false, "parameterMode": "NAMED", "queryParameters": params, "maximumBytesBilled": g.MaximumBytesBilled, "location": g.Location, "maxResults": 1000, "timeoutMs": 5000, "jobTimeoutMs": "60000", "jobCreationMode": "JOB_CREATION_REQUIRED"}
	request["requestId"] = Hash(Document{"config": Hash(r), "period": p, "as_of": asOf})[:32]
	return request, nil
}
func parameter(name, kind, value string) Document {
	return Document{"name": name, "parameterType": Document{"type": kind}, "parameterValue": Document{"value": value}}
}

func (g GCPReader) Collect(ctx context.Context, r Registration, p Period) (Snapshot, error) {
	c := g.Config
	if err := c.validate(r, "GCP"); err != nil {
		return Snapshot{}, err
	}
	s := base(r, c.now())
	if !periodValid(p, c.now()) {
		return s, errors.New("GCP_QUERY_PERIOD_INVALID")
	}
	s.Period = p
	scope := r.GCP
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	read := func(kind, address string) (Document, error) {
		o, d, e := c.request(ctx, http.MethodGet, address, bigQueryScope, nil, nil)
		if e == nil {
			o.Kind = kind
			e = appendObject(&s, o)
		}
		return d, e
	}
	o, account, e := c.request(ctx, http.MethodGet, "https://cloudbilling.googleapis.com/v1/billingAccounts/"+scope.BillingAccountID, cloudBillingScope, nil, nil)
	if e != nil {
		return s, e
	}
	o.Kind = "GCP_BILLING_ACCOUNT"
	if e = appendObject(&s, o); e != nil {
		return s, e
	}
	if str(account, "name") != "billingAccounts/"+scope.BillingAccountID {
		return s, errors.New("GCP_BILLING_ACCOUNT_MISMATCH")
	}
	accountCurrency := str(account, "currencyCode")
	if accountCurrency != "" && !currencyPattern.MatchString(accountCurrency) {
		return s, errors.New("GCP_ACCOUNT_CURRENCY_INVALID")
	}
	if accountCurrency == "" {
		s.ReasonCodes = append(s.ReasonCodes, "GCP_INDEPENDENT_ACCOUNT_CURRENCY_UNAVAILABLE")
	}
	datasetAddress := bigQueryAPI + "/projects/" + scope.DatasetProjectID + "/datasets/" + scope.DatasetID
	dataset, e := read("GCP_DATASET_METADATA", datasetAddress)
	if e != nil {
		return s, e
	}
	ref := obj(dataset["datasetReference"])
	if str(ref, "projectId") != scope.DatasetProjectID || str(ref, "datasetId") != scope.DatasetID || str(dataset, "location") != scope.Location || str(dataset, "etag") == "" {
		return s, errors.New("GCP_DATASET_BINDING_INVALID")
	}
	table, e := read("GCP_TABLE_METADATA", datasetAddress+"/tables/"+scope.TableID)
	if e != nil {
		return s, e
	}
	ref = obj(table["tableReference"])
	if str(ref, "projectId") != scope.DatasetProjectID || str(ref, "datasetId") != scope.DatasetID || str(ref, "tableId") != scope.TableID || str(table, "type") != "TABLE" || str(table, "etag") == "" || str(table, "location") != scope.Location || len(obj(table["externalDataConfiguration"])) > 0 || len(obj(table["view"])) > 0 {
		return s, errors.New("GCP_TABLE_BINDING_INVALID")
	}
	if len(obj(table["streamingBuffer"])) > 0 {
		s.ReasonCodes = append(s.ReasonCodes, "GCP_STREAMING_BUFFER_COMPLETENESS_UNPROVEN")
	}
	if e = tableSchema(r, obj(table["schema"])); e != nil {
		return s, e
	}
	asOf := c.now().Add(-5 * time.Second)
	request, e := Query(r, p, asOf)
	if e != nil {
		return s, e
	}
	o, first, e := c.request(ctx, http.MethodPost, bigQueryAPI+"/projects/"+scope.QueryProjectID+"/queries", bigQueryScope, request, nil)
	if e != nil {
		return s, e
	}
	o.Kind = "GCP_QUERY_RESPONSE"
	if e = appendObject(&s, o); e != nil {
		return s, e
	}
	job := obj(first["jobReference"])
	jobID := str(job, "jobId")
	if !regexp.MustCompile(`^[A-Za-z0-9_-]+$`).MatchString(jobID) || len(jobID) > 1024 || str(job, "projectId") != scope.QueryProjectID || str(job, "location") != scope.Location {
		return s, errors.New("GCP_QUERY_JOB_BINDING_INVALID")
	}
	s.NativeReference = "projects/" + scope.QueryProjectID + "/jobs/" + jobID + "?location=" + scope.Location
	queryAddress := bigQueryAPI + "/projects/" + scope.QueryProjectID + "/queries/" + url.PathEscape(jobID)
	current := first
	for poll := 0; !boolean(current, "jobComplete"); poll++ {
		if poll >= 12 {
			return s, errors.New("GCP_QUERY_NOT_COMPLETE")
		}
		if len(list(current["errors"])) > 0 {
			return s, errors.New("GCP_QUERY_ERRORS_OR_WARNINGS")
		}
		current, e = read("GCP_QUERY_POLL", queryAddress+"?location="+url.QueryEscape(scope.Location)+"&timeoutMs=5000")
		if e != nil {
			return s, e
		}
		if !sameJob(obj(current["jobReference"]), job) {
			return s, errors.New("GCP_QUERY_JOB_CHANGED")
		}
	}
	total, e := strconv.ParseUint(str(current, "totalRows"), 10, 64)
	if e != nil || total > MaxRows {
		return s, errors.New("GCP_QUERY_ROW_LIMIT")
	}
	rows := []Document{}
	tokens := map[string]bool{}
	var canonicalBytes int
	for page := 0; ; page++ {
		if page >= 1000 || !boolean(current, "jobComplete") || !sameJob(obj(current["jobReference"]), job) || len(list(current["errors"])) > 0 {
			return s, errors.New("GCP_QUERY_PAGE_INVALID")
		}
		if value := str(current, "totalRows"); value != "" && value != strconv.FormatUint(total, 10) {
			return s, errors.New("GCP_QUERY_TOTAL_ROWS_CHANGED")
		}
		fields := list(obj(current["schema"])["fields"])
		if page == 0 || len(fields) > 0 {
			if len(fields) != 1 || str(obj(fields[0]), "name") != "native_row" || str(obj(fields[0]), "type") != "STRING" {
				return s, errors.New("GCP_QUERY_RESULT_SCHEMA_INVALID")
			}
		}
		for _, x := range list(current["rows"]) {
			f := list(obj(x)["f"])
			if len(f) != 1 {
				return s, errors.New("GCP_QUERY_NATIVE_ROW_INVALID")
			}
			raw := str(obj(f[0]), "v")
			canonicalBytes += len(raw)
			if len(rows) >= MaxRows || canonicalBytes > MaxCollectionBytes {
				return s, errors.New("MULTICLOUD_ROW_LIMIT")
			}
			d, e := decode([]byte(raw))
			if e != nil {
				return s, e
			}
			rows = append(rows, d)
		}
		token := str(current, "pageToken")
		if token == "" {
			break
		}
		if len(token) > 4096 || tokens[token] {
			return s, errors.New("GCP_QUERY_PAGINATION_INVALID")
		}
		tokens[token] = true
		current, e = read("GCP_QUERY_RESULT_PAGE", queryAddress+"?location="+url.QueryEscape(scope.Location)+"&maxResults=1000&pageToken="+url.QueryEscape(token))
		if e != nil {
			return s, e
		}
	}
	if uint64(len(rows)) != total {
		return s, errors.New("GCP_QUERY_ROW_COUNT_MISMATCH")
	}
	nativeJob, e := read("GCP_QUERY_JOB_METADATA", bigQueryAPI+"/projects/"+scope.QueryProjectID+"/jobs/"+url.PathEscape(jobID)+"?location="+url.QueryEscape(scope.Location))
	if e != nil {
		return s, e
	}
	if e = validateJob(nativeJob, job, request, r); e != nil {
		return s, e
	}
	canonicalBytes = 0
	for index, row := range rows {
		records, e := ParseGCPRow(r, row, s.NativeReference+"#"+strconv.Itoa(index), accountCurrency)
		if e != nil {
			return s, e
		}
		encoded, _ := json.Marshal(records)
		canonicalBytes += len(encoded)
		if len(s.Records)+len(records) > MaxRows*2 || canonicalBytes > MaxCollectionBytes {
			return s, errors.New("MULTICLOUD_COLLECTION_LIMIT")
		}
		s.Records = append(s.Records, records...)
		for _, record := range records {
			addTotal(s.BilledTotals, record.Currency, record.BilledCost)
		}
	}
	s.NativeRowCount = int64(len(rows))
	s.ReasonCodes = append(s.ReasonCodes, "GCP_SNAPSHOT_QUERY_IS_NOT_PROVIDER_PERIOD_COMPLETENESS", "GCP_INVOICE_MONTH_IS_NOT_ISSUED_INVOICE_FINALITY")
	if r.Kind == GCPCommitments {
		s.ReasonCodes = append(s.ReasonCodes, "GCP_CUD_EXPORT_PREVIEW_SPEND_BASED_ONLY", "GCP_RESOURCE_BASED_COMMITMENT_INVENTORY_UNPROVEN")
	}
	return seal(s), nil
}
func sameJob(a, b Document) bool {
	return str(a, "projectId") == str(b, "projectId") && str(a, "jobId") == str(b, "jobId") && str(a, "location") == str(b, "location")
}
func tableSchema(r Registration, schema Document) error {
	fields := map[string]string{}
	for _, x := range list(schema["fields"]) {
		v := obj(x)
		if _, ok := fields[str(v, "name")]; ok {
			return errors.New("GCP_TABLE_SCHEMA_AMBIGUOUS")
		}
		fields[str(v, "name")] = str(v, "type")
	}
	required := map[string]string{"billing_account_id": "STRING"}
	switch r.Kind {
	case GCPDetailed:
		required["cost"] = "FLOAT"
		required["currency"] = "STRING"
		required["usage_start_time"] = "TIMESTAMP"
		required["usage_end_time"] = "TIMESTAMP"
		required["invoice"] = "RECORD"
	case GCPPricing:
		required["account_currency_code"] = "STRING"
		required["pricing_as_of_time"] = "TIMESTAMP"
	case GCPCommitments:
		required["state"] = "STRING"
		required["start_time"] = "TIMESTAMP"
		required["end_time"] = "TIMESTAMP"
	}
	for k, v := range required {
		actual := fields[k]
		if k == "cost" && actual == "FLOAT64" {
			continue
		}
		if actual != v {
			return errors.New("GCP_NATIVE_TABLE_SCHEMA_UNSUPPORTED")
		}
	}
	return nil
}
func parameters(p any) (Document, error) {
	out := Document{}
	for _, x := range list(p) {
		v := obj(x)
		name := str(v, "name")
		if name == "" || out[name] != nil {
			return nil, errors.New("GCP_QUERY_PARAMETER_INVALID")
		}
		out[name] = Document{"type": str(obj(v["parameterType"]), "type"), "value": str(obj(v["parameterValue"]), "value")}
	}
	return out, nil
}
func validateJob(d, expected, request Document, r Registration) error {
	if !sameJob(obj(d["jobReference"]), expected) || str(obj(d["status"]), "state") != "DONE" || len(obj(obj(d["status"])["errorResult"])) > 0 || len(list(obj(d["status"])["errors"])) > 0 {
		return errors.New("GCP_JOB_NOT_SUCCESSFUL")
	}
	q := obj(obj(d["configuration"])["query"])
	if str(q, "query") != str(request, "query") || boolean(q, "useLegacySql") || boolean(q, "useQueryCache") || str(q, "maximumBytesBilled") != r.GCP.MaximumBytesBilled || str(q, "parameterMode") != "NAMED" {
		return errors.New("GCP_QUERY_DEFINITION_CHANGED")
	}
	a, e := parameters(q["queryParameters"])
	if e != nil {
		return e
	}
	b, e := parameters(request["queryParameters"])
	if e != nil || Hash(a) != Hash(b) {
		return errors.New("GCP_QUERY_PARAMETERS_CHANGED")
	}
	stats := obj(obj(d["statistics"])["query"])
	if str(stats, "statementType") != "SELECT" || boolean(stats, "cacheHit") {
		return errors.New("GCP_NON_NATIVE_READ_QUERY")
	}
	refs := list(stats["referencedTables"])
	if len(refs) != 1 {
		return errors.New("GCP_QUERY_TABLE_SCOPE_CHANGED")
	}
	ref := obj(refs[0])
	if str(ref, "projectId") != r.GCP.DatasetProjectID || str(ref, "datasetId") != r.GCP.DatasetID || str(ref, "tableId") != r.GCP.TableID {
		return errors.New("GCP_QUERY_TABLE_SCOPE_CHANGED")
	}
	return nil
}

// ParseGCPRow keeps correction and credit rows. Billing amounts are never
// replaced with public list prices, blended currencies or amortization guesses.
func ParseGCPRow(r Registration, native Document, id, accountCurrency string) ([]Record, error) {
	if err := Validate(r); err != nil {
		return nil, err
	}
	if r.GCP == nil {
		return nil, errors.New("GCP_SCOPE_REQUIRED")
	}
	if str(native, "billing_account_id") != r.GCP.BillingAccountID {
		return nil, errors.New("GCP_NATIVE_BILLING_ACCOUNT_MISMATCH")
	}
	record := Record{ID: id, Kind: r.Kind, BillingAccountID: r.GCP.BillingAccountID, Native: native, MappingGaps: []string{}, Precision: "NATIVE_AUXILIARY_METADATA_NO_BILLED_COST"}
	if r.Kind != GCPDetailed {
		record.Currency = str(native, "account_currency_code")
		if r.Kind == GCPCommitments {
			record.Currency = accountCurrency
			record.MappingGaps = append(record.MappingGaps, "CUD_SPEND_BASED_PREVIEW_IS_NOT_COMPLETE_COMMITMENT_INVENTORY", "CUD_LOCAL_ENTITLEMENT_SCHEDULE_NOT_REINTERPRETED_AS_UTC")
		}
		if accountCurrency != "" && record.Currency != "" && accountCurrency != record.Currency {
			return nil, errors.New("GCP_NATIVE_CURRENCY_MISMATCH")
		}
		if record.Currency != "" && !currencyPattern.MatchString(record.Currency) {
			return nil, errors.New("GCP_NATIVE_CURRENCY_INVALID")
		}
		if r.Kind == GCPPricing {
			record.MappingGaps = append(record.MappingGaps, "PRICING_IS_NOT_RESOURCE_BILLED_OR_EFFECTIVE_COST", "USD_LIST_PRICE_NOT_CONVERTED_TO_BILLING_CURRENCY")
		}
		return []Record{record}, nil
	}
	record.Currency = str(native, "currency")
	if !currencyPattern.MatchString(record.Currency) {
		return nil, errors.New("GCP_NATIVE_CURRENCY_INVALID")
	}
	if accountCurrency != "" && record.Currency != accountCurrency {
		return nil, errors.New("GCP_NATIVE_CURRENCY_MISMATCH")
	}
	record.UsageAccountID = str(obj(native["project"]), "id")
	record.ResourceID = str(obj(native["resource"]), "global_name")
	record.Region = str(obj(native["location"]), "region")
	record.InvoiceMonth = str(obj(native["invoice"]), "month")
	if _, err := time.Parse("200601", record.InvoiceMonth); err != nil {
		record.MappingGaps = append(record.MappingGaps, "INVOICE_MONTH_MISSING_OR_UNKNOWN")
	}
	cost, e := moneyPtr(native["cost"])
	if e != nil {
		return nil, e
	}
	record.BilledCost = cost
	record.Precision = "PROVIDER_FLOAT64_NATIVE_LEXICAL_VALUE"
	record.MappingGaps = append(record.MappingGaps, "PROVIDER_FLOAT64_MONEY_PRECISION", "COMMITMENT_EFFECTIVE_COST_SOURCE_REQUIRED")
	record.ChargeCategory = str(native, "cost_type")
	if len(obj(native["adjustment_info"])) > 0 {
		record.ChargeClass = "Correction"
	}
	record.ChargeStart = optionalTime(str(native, "usage_start_time"))
	record.ChargeEnd = optionalTime(str(native, "usage_end_time"))
	if record.ChargeStart == nil || record.ChargeEnd == nil {
		record.MappingGaps = append(record.MappingGaps, "CHARGE_INTERVAL_MISSING")
	}
	if record.ResourceID == "" {
		record.MappingGaps = append(record.MappingGaps, "RESOURCE_ALLOCATION_MISSING")
	}
	if cost == nil {
		record.MappingGaps = append(record.MappingGaps, "BILLED_COST_MISSING")
	}
	record.MappingGaps = unique(record.MappingGaps)
	result := []Record{record}
	credits := list(native["credits"])
	if len(credits) > 64 {
		return nil, errors.New("GCP_CREDIT_ROW_LIMIT")
	}
	for i, x := range credits {
		credit := obj(x)
		amount, e := moneyPtr(credit["amount"])
		if e != nil || amount == nil {
			return nil, errors.New("GCP_CREDIT_AMOUNT_INVALID")
		}
		copy := record
		copy.ID = fmt.Sprintf("%s#credit-%d", id, i)
		copy.BilledCost = amount
		copy.ChargeCategory = "Credit"
		// The base row already retains every original field. Reference it rather
		// than duplicating its full credits array for every derived credit record.
		copy.Native = Document{"parent_row_id": id, "native_credit": credit}
		copy.MappingGaps = append(append([]string{}, record.MappingGaps...), "NATIVE_CREDIT_IS_NOT_MARGINAL_COMPUTE_SAVING")
		if strings.HasPrefix(*amount, "-") == false && *amount != "0" {
			copy.MappingGaps = append(copy.MappingGaps, "POSITIVE_CREDIT_REQUIRES_SOURCE_REVIEW")
		}
		result = append(result, copy)
	}
	return result, nil
}
