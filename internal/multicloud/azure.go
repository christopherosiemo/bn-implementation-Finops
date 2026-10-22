package multicloud

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"
)

const azureAPI = "2025-03-01"
const armScope = "https://management.azure.com/.default"
const blobScope = "https://storage.azure.com/.default"

type AzureReader struct{ Config Config }
type AzureRequest struct {
	RunID string
	// Optional immutable pins are selected from previously persisted receipts by
	// a server, not interpreted as caller assertions of authenticity.
	ManifestVersion string
	BlobVersions    map[string]string
}

func azureType(k Kind) string {
	switch k {
	case AzureActual:
		return "ActualCost"
	case AzureAmortized:
		return "AmortizedCost"
	case AzureFOCUS:
		return "FocusCost"
	}
	return ""
}
func appendObject(s *Snapshot, o Object) error {
	var size int64
	for _, p := range s.Objects {
		size += p.Bytes
	}
	if len(s.Objects) >= 1100 || size+o.Bytes > MaxCollectionBytes {
		return errors.New("MULTICLOUD_COLLECTION_LIMIT")
	}
	s.Objects = append(s.Objects, o)
	return nil
}

// Collect follows a native ARM execution's historical runSettings and manifest,
// then reads every version-pinned blob. Delivery success is not invoice finality,
// exclusive producer policy, complete-period evidence or execution authority.
func (a AzureReader) Collect(ctx context.Context, r Registration, in AzureRequest) (Snapshot, error) {
	c := a.Config
	if err := c.validate(r, "AZURE"); err != nil {
		return Snapshot{}, err
	}
	s := base(r, c.now())
	scope := r.Azure
	o, definition, e := c.request(ctx, http.MethodGet, "https://management.azure.com"+scope.ExportResourceID+"?api-version="+azureAPI, armScope, nil, nil)
	if e != nil {
		return s, e
	}
	o.Kind = "AZURE_EXPORT_DEFINITION"
	if e = appendObject(&s, o); e != nil {
		return s, e
	}
	if !strings.EqualFold(str(definition, "id"), scope.ExportResourceID) {
		return s, errors.New("AZURE_EXPORT_BINDING_INVALID")
	}
	if e = azureSettings(obj(definition["properties"]), r); e != nil {
		return s, e
	}
	address := "https://management.azure.com" + scope.ExportResourceID + "/runHistory?api-version=" + azureAPI
	seen := map[string]bool{}
	var selected Document
	var latest time.Time
	found := false
	for page := 0; address != ""; page++ {
		if page >= 1000 || seen[address] {
			return s, errors.New("AZURE_HISTORY_PAGINATION_INVALID")
		}
		seen[address] = true
		o, d, e := c.request(ctx, http.MethodGet, address, armScope, nil, nil)
		if e != nil {
			return s, e
		}
		o.Kind = "AZURE_EXPORT_RUN_HISTORY"
		if e = appendObject(&s, o); e != nil {
			return s, e
		}
		for _, x := range list(d["value"]) {
			run := obj(x)
			p := obj(run["properties"])
			id := str(run, "id")
			prefix := scope.ExportResourceID + "/Run/"
			if !strings.HasPrefix(strings.ToLower(id), strings.ToLower(prefix)) {
				return s, errors.New("AZURE_RUN_SCOPE_INVALID")
			}
			runID := id[len(prefix):]
			if !guid.MatchString(runID) {
				return s, errors.New("AZURE_RUN_ID_INVALID")
			}
			submitted, err := instant(str(p, "submittedTime"))
			if err != nil || submitted.After(c.now().Add(5*time.Second)) {
				return s, errors.New("AZURE_RUN_TIME_INVALID")
			}
			if in.RunID != "" && !strings.EqualFold(in.RunID, runID) {
				continue
			}
			if str(p, "status") != "Completed" {
				if in.RunID != "" {
					return s, errors.New("AZURE_RUN_NOT_COMPLETED")
				}
				continue
			}
			if !found || submitted.After(latest) {
				selected = run
				latest = submitted
				found = true
			}
		}
		next := str(d, "nextLink")
		if next != "" {
			u, err := url.Parse(next)
			if err != nil || u.Scheme != "https" || u.Host != "management.azure.com" || u.User != nil || !strings.EqualFold(u.Path, scope.ExportResourceID+"/runHistory") || u.Fragment != "" {
				return s, errors.New("AZURE_HISTORY_NEXT_LINK_INVALID")
			}
		}
		address = next
	}
	if !found {
		return s, errors.New("AZURE_COMPLETED_RUN_REQUIRED")
	}
	p := obj(selected["properties"])
	s.NativeReference = str(selected, "id")
	runID := path.Base(s.NativeReference)
	settings := obj(p["runSettings"])
	if len(settings) == 0 {
		return s, errors.New("AZURE_HISTORICAL_DEFINITION_REQUIRED")
	}
	if e = azureSettings(settings, r); e != nil {
		return s, e
	}
	start, e1 := instant(str(p, "startDate"))
	end, e2 := instant(str(p, "endDate"))
	finished, e3 := instant(str(p, "processingEndTime"))
	if e1 != nil || e2 != nil || e3 != nil || !end.After(start) || finished.Before(latest) || finished.After(c.now().Add(5*time.Second)) {
		return s, errors.New("AZURE_RUN_TIME_INVALID")
	}
	s.Period = Period{start, end}
	manifestName := str(p, "manifestFile")
	if !safePath(manifestName) || !strings.HasPrefix(manifestName, scope.Prefix) {
		return s, errors.New("AZURE_MANIFEST_PATH_INVALID")
	}
	manifestObject, e := a.blob(ctx, r, manifestName, in.ManifestVersion, latest, finished)
	if e != nil {
		return s, e
	}
	manifestObject.Kind = "AZURE_EXPORT_MANIFEST"
	if e = appendObject(&s, manifestObject); e != nil {
		return s, e
	}
	manifest, e := decode(manifestObject.Body)
	if e != nil {
		return s, e
	}
	if str(manifest, "manifestVersion") != "2024-04-01" {
		return s, errors.New("AZURE_MANIFEST_VERSION_UNSUPPORTED")
	}
	config, delivery, runInfo := obj(manifest["exportConfig"]), obj(manifest["deliveryConfig"]), obj(manifest["runInfo"])
	if !strings.EqualFold(str(config, "resourceId"), scope.ExportResourceID) || str(config, "dataVersion") != scope.DataVersion || str(config, "type") != azureType(r.Kind) || !strings.EqualFold(str(delivery, "containerUri"), scope.StorageAccountResourceID) || strings.Trim(str(delivery, "rootFolderPath"), "/")+"/" != scope.Prefix || !strings.EqualFold(str(delivery, "fileFormat"), "Csv") || !strings.EqualFold(str(runInfo, "runId"), runID) {
		return s, errors.New("AZURE_MANIFEST_BINDING_INVALID")
	}
	manifestSubmitted, err := instant(str(runInfo, "submittedTime"))
	if err != nil || !manifestSubmitted.Equal(latest) {
		return s, errors.New("AZURE_MANIFEST_RUN_TIME_INVALID")
	}
	// A date without a timezone cannot silently become UTC. Preserve it visibly,
	// while the native ARM run range remains the authoritative raw boundary.
	for _, key := range []string{"startDate", "endDate"} {
		value, err := instant(str(runInfo, key))
		if err != nil {
			s.ReasonCodes = append(s.ReasonCodes, "AZURE_MANIFEST_DATE_TIMEZONE_UNPROVEN")
		} else {
			expected := start
			if key == "endDate" {
				expected = end
			}
			if !value.Equal(expected) {
				return s, errors.New("AZURE_MANIFEST_PERIOD_MISMATCH")
			}
		}
	}
	compression := str(delivery, "compressionMode")
	if !strings.EqualFold(compression, str(settings, "compressionMode")) {
		return s, errors.New("AZURE_COMPRESSION_BINDING_INVALID")
	}
	if !strings.EqualFold(compression, "None") && !strings.EqualFold(compression, "Gzip") {
		return s, errors.New("AZURE_COMPRESSION_UNSUPPORTED")
	}
	blobs := list(manifest["blobs"])
	blobCount, ok := num(manifest, "blobCount")
	rows, okRows := num(manifest, "dataRowCount")
	byteCount, okBytes := num(manifest, "byteCount")
	if !ok || !okRows || !okBytes || blobCount < 1 || blobCount > 1024 || blobCount != int64(len(blobs)) || rows < 0 || rows > MaxRows || byteCount < 0 {
		return s, errors.New("AZURE_MANIFEST_COUNTS_INVALID")
	}
	seenBlobs := map[string]bool{}
	var actualRows, actualBytes, canonicalBytes int64
	for _, x := range blobs {
		part := obj(x)
		name := str(part, "blobName")
		count, countOK := num(part, "dataRowCount")
		size, sizeOK := num(part, "byteCount")
		if !safePath(name) || !strings.HasPrefix(name, scope.Prefix) || seenBlobs[name] || !countOK || !sizeOK || count < 0 || size < 0 {
			return s, errors.New("AZURE_PARTITION_INVALID")
		}
		seenBlobs[name] = true
		o, e := a.blob(ctx, r, name, in.BlobVersions[name], latest, finished)
		if e != nil {
			return s, e
		}
		o.Kind = "AZURE_COST_PARTITION"
		if o.Bytes != size {
			return s, errors.New("AZURE_PARTITION_BYTE_COUNT_MISMATCH")
		}
		if e = appendObject(&s, o); e != nil {
			return s, e
		}
		parsed, e := ParseAzureCSV(r, o.Body, compression, name)
		if e != nil {
			return s, e
		}
		if int64(len(parsed)) != count {
			return s, errors.New("AZURE_PARTITION_ROW_COUNT_MISMATCH")
		}
		actualRows += count
		actualBytes += size
		encoded, _ := json.Marshal(parsed)
		canonicalBytes += int64(len(encoded))
		if actualRows > MaxRows || actualBytes > MaxCollectionBytes || canonicalBytes > MaxCollectionBytes {
			return s, errors.New("MULTICLOUD_COLLECTION_LIMIT")
		}
		for _, record := range parsed {
			s.Records = append(s.Records, record)
			addTotal(s.BilledTotals, record.Currency, record.BilledCost)
			if r.Kind == AzureAmortized {
				addTotal(s.AmortizedTotals, record.Currency, record.EffectiveCost)
			}
		}
	}
	if actualRows != rows || actualBytes != byteCount {
		return s, errors.New("AZURE_MANIFEST_TOTAL_MISMATCH")
	}
	s.NativeRowCount = actualRows
	s.ReasonCodes = append(s.ReasonCodes, "AZURE_NATIVE_RUN_RANGE_BOUNDARY_SEMANTICS_UNPROVEN")
	return seal(s), nil
}
func azureSettings(p Document, r Registration) error {
	s := r.Azure
	d := obj(p["definition"])
	destination := obj(obj(p["deliveryInfo"])["destination"])
	if str(d, "type") != azureType(r.Kind) || str(obj(obj(d["dataSet"])["configuration"]), "dataVersion") != s.DataVersion || !strings.EqualFold(str(p, "format"), "Csv") || !boolean(p, "partitionData") || !strings.EqualFold(str(destination, "resourceId"), s.StorageAccountResourceID) || str(destination, "container") != s.Container || strings.Trim(str(destination, "rootFolderPath"), "/")+"/" != s.Prefix {
		return errors.New("AZURE_EXPORT_CONFIGURATION_MISMATCH")
	}
	return nil
}
func (a AzureReader) blob(ctx context.Context, r Registration, name, version string, submitted, finished time.Time) (Object, error) {
	escaped := []string{}
	for _, segment := range strings.Split(name, "/") {
		escaped = append(escaped, url.PathEscape(segment))
	}
	address := "https://" + r.Azure.StorageAccountName + ".blob.core.windows.net/" + url.PathEscape(r.Azure.Container) + "/" + strings.Join(escaped, "/")
	if version != "" {
		address += "?versionid=" + url.QueryEscape(version)
	}
	o, _, e := a.Config.request(ctx, http.MethodGet, address, blobScope, nil, map[string]string{"x-ms-version": "2023-11-03"})
	if e != nil {
		return o, e
	}
	if o.Version == "" || o.ETag == "" || o.LastModified.IsZero() {
		return o, errors.New("AZURE_VERSIONED_BLOB_REQUIRED")
	}
	vt, e := instant(o.Version)
	if e != nil || vt.Before(submitted.Add(-5*time.Second)) || vt.After(finished.Add(5*time.Minute)) || vt.After(a.Config.now().Add(5*time.Second)) || o.LastModified.After(a.Config.now().Add(5*time.Second)) || o.LastModified.Before(vt.Truncate(time.Second)) || o.LastModified.After(vt.Add(time.Second)) {
		return o, errors.New("AZURE_BLOB_VERSION_OUTSIDE_RUN")
	}
	if version != "" {
		if o.Version != version {
			return o, errors.New("AZURE_BLOB_VERSION_MISMATCH")
		}
		return o, nil
	}
	// Pin and re-read the actual provider version, with an exact ETag fence.
	pinned := address + "?versionid=" + url.QueryEscape(o.Version)
	again, _, e := a.Config.request(ctx, http.MethodGet, pinned, blobScope, nil, map[string]string{"x-ms-version": "2023-11-03", "If-Match": o.ETag})
	if e != nil {
		return o, e
	}
	if again.Version != o.Version || again.ETag != o.ETag || again.SHA256 != o.SHA256 || !again.LastModified.Equal(o.LastModified) {
		return o, errors.New("AZURE_BLOB_CHANGED_DURING_READ")
	}
	return again, nil
}

// ParseAzureCSV preserves all native columns and decimal precision. Actual and
// amortized exports remain distinct; one cannot manufacture the other's cost.
func ParseAzureCSV(r Registration, raw []byte, compression, source string) ([]Record, error) {
	if err := Validate(r); err != nil {
		return nil, err
	}
	if r.Azure == nil {
		return nil, errors.New("AZURE_SCOPE_REQUIRED")
	}
	var reader io.Reader = bytes.NewReader(raw)
	if strings.EqualFold(compression, "Gzip") {
		gz, e := gzip.NewReader(reader)
		if e != nil {
			return nil, errors.New("AZURE_GZIP_INVALID")
		}
		defer gz.Close()
		decoded, e := io.ReadAll(io.LimitReader(gz, MaxBodyBytes+1))
		if e != nil || len(decoded) > MaxBodyBytes {
			return nil, errors.New("AZURE_DECODED_PARTITION_LIMIT")
		}
		reader = bytes.NewReader(decoded)
	} else if !strings.EqualFold(compression, "None") {
		return nil, errors.New("AZURE_COMPRESSION_UNSUPPORTED")
	}
	parser := csv.NewReader(reader)
	header, e := parser.Read()
	if e != nil || len(header) > 256 {
		return nil, errors.New("AZURE_CSV_HEADER_REQUIRED")
	}
	seen := map[string]bool{}
	for i, key := range header {
		key = strings.TrimPrefix(key, "\ufeff")
		header[i] = key
		lower := strings.ToLower(key)
		if key == "" || len(key) > 256 || seen[lower] {
			return nil, errors.New("AZURE_CSV_HEADER_AMBIGUOUS")
		}
		seen[lower] = true
	}
	if r.Kind == AzureFOCUS {
		if !seen["billingcurrency"] || !seen["billedcost"] {
			return nil, errors.New("AZURE_FOCUS_SCHEMA_REQUIRED")
		}
	} else if !seen["costinbillingcurrency"] || !(seen["billingcurrencycode"] || seen["billingcurrency"]) {
		return nil, errors.New("AZURE_COST_SCHEMA_REQUIRED")
	}
	result := []Record{}
	for rowIndex := 0; ; rowIndex++ {
		fields, e := parser.Read()
		if e == io.EOF {
			break
		}
		if e != nil {
			return nil, errors.New("AZURE_CSV_INVALID")
		}
		if rowIndex >= MaxRows {
			return nil, errors.New("MULTICLOUD_ROW_LIMIT")
		}
		native := Document{}
		lower := Document{}
		for i, key := range header {
			if len(fields[i]) > 65536 {
				return nil, errors.New("AZURE_CSV_FIELD_LIMIT")
			}
			native[key] = fields[i]
			lower[strings.ToLower(key)] = fields[i]
		}
		record := Record{ID: source + "#" + strconv.Itoa(rowIndex), Kind: r.Kind, Native: native, Precision: "PROVIDER_DECIMAL_TEXT", MappingGaps: []string{}}
		if r.Kind == AzureFOCUS {
			record.Currency = str(lower, "billingcurrency")
			record.BillingAccountID = str(lower, "billingaccountid")
			record.UsageAccountID = str(lower, "subaccountid")
			record.ResourceID = str(lower, "resourceid")
			record.Region = str(lower, "regionid")
			record.BilledCost, e = moneyPtr(lower["billedcost"])
			if e != nil {
				return nil, e
			}
			record.EffectiveCost, e = moneyPtr(lower["effectivecost"])
			if e != nil {
				return nil, e
			}
			record.ListCost, e = moneyPtr(lower["listcost"])
			if e != nil {
				return nil, e
			}
			record.ChargeCategory = str(lower, "chargecategory")
			record.ChargeClass = str(lower, "chargeclass")
			record.ChargeStart = optionalTime(str(lower, "chargeperiodstart"))
			record.ChargeEnd = optionalTime(str(lower, "chargeperiodend"))
		} else {
			record.Currency = str(lower, "billingcurrencycode")
			if record.Currency == "" {
				record.Currency = str(lower, "billingcurrency")
			}
			record.BillingAccountID = str(lower, "billingaccountid")
			record.UsageAccountID = str(lower, "subscriptionid")
			record.ResourceID = str(lower, "resourceid")
			record.Region = str(lower, "resourcelocation")
			cost, err := moneyPtr(lower["costinbillingcurrency"])
			if err != nil {
				return nil, err
			}
			if r.Kind == AzureAmortized {
				record.EffectiveCost = cost
				record.MappingGaps = append(record.MappingGaps, "NATIVE_AMORTIZED_COST_IS_NOT_INVOICE_BILLED_COST")
			} else {
				record.BilledCost = cost
				record.MappingGaps = append(record.MappingGaps, "EFFECTIVE_COST_SOURCE_REQUIRED")
			}
			record.ChargeCategory = str(lower, "chargetype")
			record.MappingGaps = append(record.MappingGaps, "NATIVE_DAILY_DATE_BOUNDARIES_NOT_INFERRED")
		}
		if record.Currency == "" {
			record.MappingGaps = append(record.MappingGaps, "BILLING_CURRENCY_MISSING")
			record.BilledCost = nil
			record.EffectiveCost = nil
			record.ListCost = nil
		} else if !currencyPattern.MatchString(record.Currency) {
			return nil, errors.New("AZURE_BILLING_CURRENCY_INVALID")
		}
		if r.Azure.BillingAccountID != "" && record.BillingAccountID != "" && record.BillingAccountID != r.Azure.BillingAccountID {
			return nil, errors.New("AZURE_BILLING_ACCOUNT_MISMATCH")
		}
		subscription := strings.TrimPrefix(strings.ToLower(record.UsageAccountID), "/subscriptions/")
		if subscription != "" {
			allowed := false
			for _, id := range r.Azure.SubscriptionIDs {
				if strings.EqualFold(subscription, id) {
					allowed = true
				}
			}
			if !allowed {
				return nil, errors.New("AZURE_ROW_SUBSCRIPTION_MISMATCH")
			}
		}
		if record.ResourceID != "" {
			parts := strings.Split(strings.ToLower(record.ResourceID), "/")
			if len(parts) >= 3 && parts[1] == "subscriptions" {
				if subscription != "" && subscription != parts[2] {
					return nil, errors.New("AZURE_RESOURCE_SUBSCRIPTION_MISMATCH")
				}
				allowed := false
				for _, id := range r.Azure.SubscriptionIDs {
					if strings.EqualFold(id, parts[2]) {
						allowed = true
					}
				}
				if !allowed {
					return nil, errors.New("AZURE_RESOURCE_SCOPE_MISMATCH")
				}
			}
		}
		if record.BilledCost == nil && r.Kind != AzureAmortized {
			record.MappingGaps = append(record.MappingGaps, "BILLED_COST_MISSING")
		}
		if record.ResourceID == "" {
			record.MappingGaps = append(record.MappingGaps, "RESOURCE_ALLOCATION_MISSING")
		}
		if record.ChargeStart == nil || record.ChargeEnd == nil {
			record.MappingGaps = append(record.MappingGaps, "CHARGE_INTERVAL_MISSING")
		}
		record.MappingGaps = unique(record.MappingGaps)
		result = append(result, record)
	}
	return result, nil
}
func optionalTime(s string) *time.Time {
	t, e := instant(s)
	if e != nil {
		return nil
	}
	return &t
}

// NativeDocument is useful for preserving native auxiliary pricing/commitment
// fields without inferring exchange rates, application identity or finality.
func NativeDocument(raw []byte) (Document, error) { return decode(raw) }
