package multicloud

import (
	"encoding/json"
	"errors"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var publicationSHA = regexp.MustCompile(`^[a-f0-9]{64}$`)

func validatePrivateRegistration(s RegistrationSnapshot) error {
	b := s.ReadBinding
	expected, e := PrivateRegistration(s.Registration, ReadBinding{ID: b.ID, TenantID: b.TenantID, Provider: b.Provider, DirectoryTenantID: b.DirectoryTenantID, BillingAccountID: b.BillingAccountID, DatasetProjectID: b.DatasetProjectID, ScopeHash: b.ScopeHash})
	if e != nil || Hash(expected) != Hash(s) {
		return errors.New("MULTICLOUD_PRIVATE_REGISTRATION_CHANGED")
	}
	return nil
}

type canonicalObservation struct {
	SchemaVersion       string       `json:"schema_version"`
	Registration        Registration `json:"registration"`
	ScopeHash           string       `json:"scope_hash"`
	NativeRevision      string       `json:"native_revision"`
	Period              Period       `json:"period"`
	Objects             []Object     `json:"objects"`
	Records             []Record     `json:"records"`
	EconomicHash        string       `json:"economic_hash"`
	Status              string       `json:"status"`
	ReasonCodes         []string     `json:"reason_codes"`
	ExecutionAuthorized bool         `json:"execution_authorized"`
	VerifiedSaving      *string      `json:"verified_saving"`
}

// PublicationContent re-derives every native value. It does not interpret a
// caller's billed/final/trusted flags as evidence or accept customer imports.
func PublicationContent(reg RegistrationSnapshot, s Snapshot) (PublicationManifest, []byte, FactPopulation, error) {
	var empty PublicationManifest
	var facts FactPopulation
	if e := validatePrivateRegistration(reg); e != nil {
		return empty, nil, facts, e
	}
	r := reg.Registration
	if s.SchemaVersion != "multicloud-billing-1" || s.TenantID != r.TenantID || s.RegistrationID != r.ID || s.RegistrationVersion != r.Version || s.ConfigHash != reg.ConfigHash || s.Kind != r.Kind || s.Status != "PROVISIONAL" || s.SourceClass != "AUTHENTICATED_PROVIDER_READ_PROVISIONAL" || s.Revision != seal(s).Revision || len(s.Objects) == 0 || len(s.Objects) > 1100 {
		return empty, nil, facts, errors.New("MULTICLOUD_SNAPSHOT_BINDING_INVALID")
	}
	var bytes int64
	objects := make([]Object, len(s.Objects))
	for i, o := range s.Objects {
		if o.Bytes != int64(len(o.Body)) || o.Bytes <= 0 || o.Bytes > MaxBodyBytes || !publicationSHA.MatchString(o.SHA256) || o.SHA256 != BytesHash(o.Body) {
			return empty, nil, facts, errors.New("MULTICLOUD_NATIVE_OBJECT_CHANGED")
		}
		bytes += o.Bytes
		if bytes > MaxCollectionBytes {
			return empty, nil, facts, errors.New("MULTICLOUD_COLLECTION_LIMIT")
		}
		objects[i] = o
		objects[i].Body = nil
	}
	var records []Record
	var rows int64
	var e error
	if r.Azure != nil {
		records, rows, e = deriveAzurePublication(r, s)
	} else {
		records, rows, e = deriveGCPPublication(r, s)
	}
	if e != nil {
		return empty, nil, facts, e
	}
	if rows != s.NativeRowCount || Hash(records) != Hash(s.Records) {
		return empty, nil, facts, errors.New("MULTICLOUD_CANONICAL_NATIVE_VALUES_CHANGED")
	}
	nativeAt, e := publicationNativeTime(r, s)
	if e != nil {
		return empty, nil, facts, e
	}
	billed, amortized := map[string]string{}, map[string]string{}
	for _, row := range records {
		addTotal(billed, row.Currency, row.BilledCost)
		if r.Kind == AzureAmortized {
			addTotal(amortized, row.Currency, row.EffectiveCost)
		}
	}
	if Hash(billed) != Hash(s.BilledTotals) || Hash(amortized) != Hash(s.AmortizedTotals) {
		return empty, nil, facts, errors.New("MULTICLOUD_NATIVE_TOTALS_CHANGED")
	}
	facts = economicPopulation(reg, s.Period, records)
	reasons := unique(append(append([]string{}, s.ReasonCodes...), "EXCLUSIVE_PRODUCER_POLICY_UNPROVEN", "REPORTING_PERIOD_COMPLETENESS_UNPROVEN", "INVOICE_FINALITY_UNPROVEN", "VM_INCARNATION_ALLOCATION_UNPROVEN", "NO_EXECUTION_AUTHORITY"))
	for _, reason := range reasons {
		if !regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,99}$`).MatchString(reason) {
			return empty, nil, facts, errors.New("MULTICLOUD_REASON_CODE_INVALID")
		}
	}
	canonical := canonicalObservation{SchemaVersion: "multicloud-canonical-1", Registration: r, ScopeHash: reg.ScopeHash, NativeRevision: s.Revision, Period: s.Period, Objects: objects, Records: records, EconomicHash: facts.EconomicHash, Status: "PROVISIONAL", ReasonCodes: reasons}
	raw, e := json.Marshal(canonical)
	if e != nil || len(raw) > MaxCollectionBytes {
		return empty, nil, facts, errors.New("MULTICLOUD_CANONICAL_LIMIT")
	}
	factRaw, _ := json.Marshal(facts)
	if len(factRaw) > MaxCollectionBytes {
		return empty, nil, facts, errors.New("MULTICLOUD_FACT_LIMIT")
	}
	factHash := BytesHash(factRaw)
	m := PublicationManifest{SchemaVersion: "1", TenantID: r.TenantID, RegistrationID: r.ID, RegistrationVersion: r.Version, ConfigHash: reg.ConfigHash, ScopeHash: reg.ScopeHash, BindingHash: reg.BindingHash, Kind: r.Kind, Period: s.Period, NativeRevision: s.Revision, NativeReference: s.NativeReference, NativeObservedAt: nativeAt, SourceReasonCodes: append([]string{}, s.ReasonCodes...), RawObjects: objects, RawManifestHash: Hash(objects), CanonicalSHA256: BytesHash(raw), FactHash: factHash, PopulationID: "mc-pop-" + factHash, EconomicHash: facts.EconomicHash, NativeRowCount: rows, RecordCount: int64(len(records)), DistinctRows: int64(len(facts.Rows)), Status: "PROVISIONAL", ReasonCodes: reasons}
	encoded, _ := json.Marshal(m)
	if len(encoded) > 1<<20 {
		return empty, nil, facts, errors.New("MULTICLOUD_MANIFEST_LIMIT")
	}
	return m, raw, facts, nil
}
func economicPopulation(reg RegistrationSnapshot, period Period, records []Record) FactPopulation {
	byHash := map[string]*EconomicRow{}
	for _, original := range records {
		row := original
		row.ID = ""
		row.MappingGaps = unique(append([]string{}, original.MappingGaps...))
		row.Native = Document{}
		for k, v := range original.Native {
			if k != "parent_row_id" {
				row.Native[k] = v
			}
		}
		key := Hash(row)
		if old := byHash[key]; old != nil {
			old.Multiplicity++
			continue
		}
		b, bg := WarehouseDecimal(row.BilledCost)
		eff, eg := WarehouseDecimal(row.EffectiveCost)
		list, lg := WarehouseDecimal(row.ListCost)
		gaps := []string{}
		for field, codes := range map[string][]string{"BILLED": bg, "EFFECTIVE": eg, "LIST": lg} {
			for _, code := range codes {
				gaps = append(gaps, field+"_"+code)
			}
		}
		byHash[key] = &EconomicRow{Hash: key, Multiplicity: 1, Native: row, BilledDecimal: b, EffectiveDecimal: eff, ListDecimal: list, ProjectionGaps: unique(gaps)}
	}
	keys := []string{}
	for key := range byHash {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	rows := []EconomicRow{}
	multiset := []Document{}
	for _, key := range keys {
		row := *byHash[key]
		rows = append(rows, row)
		multiset = append(multiset, Document{"hash": key, "count": row.Multiplicity})
	}
	economic := Hash(Document{"kind": reg.Registration.Kind, "period": period, "rows": multiset})
	return FactPopulation{SchemaVersion: "multicloud-facts-1", TenantID: reg.Registration.TenantID, RegistrationID: reg.Registration.ID, ScopeHash: reg.ScopeHash, Kind: reg.Registration.Kind, Period: period, EconomicHash: economic, Rows: rows, RecordCount: int64(len(records))}
}

func deriveAzurePublication(r Registration, s Snapshot) ([]Record, int64, error) {
	var manifest Document
	var manifestObject Object
	var definition bool
	var run Document
	parts := map[string]Object{}
	for _, o := range s.Objects {
		switch o.Kind {
		case "AZURE_EXPORT_DEFINITION":
			if definition {
				return nil, 0, errors.New("MULTICLOUD_AZURE_DEFINITION_AMBIGUOUS")
			}
			d, e := decode(o.Body)
			if e != nil || !strings.EqualFold(str(d, "id"), r.Azure.ExportResourceID) || azureSettings(obj(d["properties"]), r) != nil {
				return nil, 0, errors.New("MULTICLOUD_AZURE_DEFINITION_CHANGED")
			}
			definition = true
		case "AZURE_EXPORT_RUN_HISTORY":
			d, e := decode(o.Body)
			if e != nil {
				return nil, 0, e
			}
			for _, x := range list(d["value"]) {
				candidate := obj(x)
				if str(candidate, "id") == s.NativeReference {
					if run != nil {
						return nil, 0, errors.New("MULTICLOUD_AZURE_RUN_AMBIGUOUS")
					}
					run = candidate
				}
			}
		case "AZURE_EXPORT_MANIFEST":
			if manifest != nil {
				return nil, 0, errors.New("MULTICLOUD_AZURE_MANIFEST_AMBIGUOUS")
			}
			var e error
			manifest, e = decode(o.Body)
			if e != nil {
				return nil, 0, e
			}
			if o.Version == "" || o.ETag == "" {
				return nil, 0, errors.New("MULTICLOUD_AZURE_VERSION_REQUIRED")
			}
			manifestObject = o
		case "AZURE_COST_PARTITION":
			u, e := url.Parse(o.Resource)
			if e != nil || u.Scheme != "https" || u.Host != r.Azure.StorageAccountName+".blob.core.windows.net" || u.User != nil || u.Port() != "" || u.Fragment != "" || u.Query().Get("versionid") != o.Version || o.Version == "" || o.ETag == "" || !strings.HasPrefix(u.Path, "/"+r.Azure.Container+"/") {
				return nil, 0, errors.New("MULTICLOUD_AZURE_PARTITION_BINDING_INVALID")
			}
			name := strings.TrimPrefix(u.Path, "/"+r.Azure.Container+"/")
			if !safePath(name) || !strings.HasPrefix(name, r.Azure.Prefix) || parts[name].Body != nil {
				return nil, 0, errors.New("MULTICLOUD_AZURE_PARTITION_DUPLICATE")
			}
			parts[name] = o
		default:
			return nil, 0, errors.New("MULTICLOUD_NATIVE_OBJECT_KIND_INVALID")
		}
	}
	p := obj(run["properties"])
	manifestURL, eURL := url.Parse(manifestObject.Resource)
	manifestName := str(p, "manifestFile")
	if eURL != nil || !safePath(manifestName) || !strings.HasPrefix(manifestName, r.Azure.Prefix) || manifestURL.Scheme != "https" || manifestURL.Host != r.Azure.StorageAccountName+".blob.core.windows.net" || manifestURL.User != nil || manifestURL.Fragment != "" || manifestURL.Path != "/"+r.Azure.Container+"/"+manifestName || manifestURL.Query().Get("versionid") != manifestObject.Version || len(manifestURL.Query()) != 1 {
		return nil, 0, errors.New("MULTICLOUD_AZURE_MANIFEST_PATH_CHANGED")
	}
	cfg, delivery, info := obj(manifest["exportConfig"]), obj(manifest["deliveryConfig"]), obj(manifest["runInfo"])
	start, e := instant(str(p, "startDate"))
	end, e2 := instant(str(p, "endDate"))
	if !definition || run == nil || manifest == nil || str(p, "status") != "Completed" || azureSettings(obj(p["runSettings"]), r) != nil || e != nil || e2 != nil || !start.Equal(s.Period.Start) || !end.Equal(s.Period.End) || !strings.HasPrefix(strings.ToLower(s.NativeReference), strings.ToLower(r.Azure.ExportResourceID+"/Run/")) || str(manifest, "manifestVersion") != "2024-04-01" || !strings.EqualFold(str(cfg, "resourceId"), r.Azure.ExportResourceID) || str(cfg, "type") != azureType(r.Kind) || str(cfg, "dataVersion") != r.Azure.DataVersion || !strings.EqualFold(str(delivery, "containerUri"), r.Azure.StorageAccountResourceID) || strings.Trim(str(delivery, "rootFolderPath"), "/")+"/" != r.Azure.Prefix || str(info, "runId") != path.Base(s.NativeReference) || str(info, "submittedTime") != str(p, "submittedTime") {
		return nil, 0, errors.New("MULTICLOUD_AZURE_MANIFEST_NATIVE_BINDING_INVALID")
	}
	for _, key := range []string{"startDate", "endDate"} {
		if value, err := instant(str(info, key)); err == nil {
			expected := start
			if key == "endDate" {
				expected = end
			}
			if !value.Equal(expected) {
				return nil, 0, errors.New("MULTICLOUD_AZURE_MANIFEST_PERIOD_CHANGED")
			}
		}
	}
	compression := str(delivery, "compressionMode")
	if !strings.EqualFold(compression, str(obj(p["runSettings"]), "compressionMode")) || !strings.EqualFold(str(delivery, "fileFormat"), "Csv") {
		return nil, 0, errors.New("MULTICLOUD_AZURE_COMPRESSION_CHANGED")
	}
	blobs := list(manifest["blobs"])
	count, ok := num(manifest, "blobCount")
	wantRows, okRows := num(manifest, "dataRowCount")
	wantBytes, okBytes := num(manifest, "byteCount")
	if !ok || !okRows || !okBytes || count != int64(len(parts)) || count != int64(len(blobs)) {
		return nil, 0, errors.New("MULTICLOUD_AZURE_MANIFEST_COUNTS_CHANGED")
	}
	records := []Record{}
	var rows, size int64
	seen := map[string]bool{}
	for _, x := range blobs {
		part := obj(x)
		name := str(part, "blobName")
		o, exists := parts[name]
		partRows, rowOK := num(part, "dataRowCount")
		partBytes, bytesOK := num(part, "byteCount")
		if !exists || seen[name] || !rowOK || !bytesOK || partBytes != o.Bytes {
			return nil, 0, errors.New("MULTICLOUD_AZURE_PARTITION_COUNTS_CHANGED")
		}
		seen[name] = true
		parsed, e := ParseAzureCSV(r, o.Body, compression, name)
		if e != nil || int64(len(parsed)) != partRows {
			return nil, 0, errors.New("MULTICLOUD_AZURE_PARTITION_ROWS_CHANGED")
		}
		records = append(records, parsed...)
		rows += partRows
		size += partBytes
	}
	if rows != wantRows || size != wantBytes {
		return nil, 0, errors.New("MULTICLOUD_AZURE_TOTALS_CHANGED")
	}
	return records, rows, nil
}
func deriveGCPPublication(r Registration, s Snapshot) ([]Record, int64, error) {
	var nativeJob, account, dataset, table Document
	queryObjects := []Object{}
	pages := []Document{}
	for _, o := range s.Objects {
		d, e := decode(o.Body)
		if e != nil {
			return nil, 0, e
		}
		switch o.Kind {
		case "GCP_BILLING_ACCOUNT":
			if account != nil {
				return nil, 0, errors.New("MULTICLOUD_GCP_ACCOUNT_AMBIGUOUS")
			}
			account = d
		case "GCP_QUERY_JOB_METADATA":
			if nativeJob != nil {
				return nil, 0, errors.New("MULTICLOUD_GCP_JOB_AMBIGUOUS")
			}
			nativeJob = d
		case "GCP_QUERY_RESPONSE", "GCP_QUERY_POLL", "GCP_QUERY_RESULT_PAGE":
			queryObjects = append(queryObjects, o)
			if boolean(d, "jobComplete") {
				pages = append(pages, d)
			}
		case "GCP_DATASET_METADATA":
			if dataset != nil {
				return nil, 0, errors.New("MULTICLOUD_GCP_DATASET_AMBIGUOUS")
			}
			dataset = d
		case "GCP_TABLE_METADATA":
			if table != nil {
				return nil, 0, errors.New("MULTICLOUD_GCP_TABLE_AMBIGUOUS")
			}
			table = d
		default:
			return nil, 0, errors.New("MULTICLOUD_NATIVE_OBJECT_KIND_INVALID")
		}
	}
	ref := obj(dataset["datasetReference"])
	tableRef := obj(table["tableReference"])
	if dataset == nil || str(ref, "projectId") != r.GCP.DatasetProjectID || str(ref, "datasetId") != r.GCP.DatasetID || str(dataset, "location") != r.GCP.Location || str(dataset, "etag") == "" || table == nil || str(tableRef, "projectId") != r.GCP.DatasetProjectID || str(tableRef, "datasetId") != r.GCP.DatasetID || str(tableRef, "tableId") != r.GCP.TableID || str(table, "type") != "TABLE" || str(table, "location") != r.GCP.Location || str(table, "etag") == "" || len(obj(table["externalDataConfiguration"])) > 0 || len(obj(table["view"])) > 0 || tableSchema(r, obj(table["schema"])) != nil {
		return nil, 0, errors.New("MULTICLOUD_GCP_SOURCE_METADATA_CHANGED")
	}
	if account == nil || str(account, "name") != "billingAccounts/"+r.GCP.BillingAccountID || nativeJob == nil || len(pages) == 0 {
		return nil, 0, errors.New("MULTICLOUD_GCP_NATIVE_SCOPE_REQUIRED")
	}
	query := obj(obj(nativeJob["configuration"])["query"])
	parameters, e := parameters(query["queryParameters"])
	if e != nil {
		return nil, 0, e
	}
	asOf, e := instant(str(obj(parameters["as_of"]), "value"))
	if e != nil {
		return nil, 0, errors.New("MULTICLOUD_GCP_QUERY_TIME_INVALID")
	}
	request, e := Query(r, s.Period, asOf)
	if e != nil {
		return nil, 0, e
	}
	job := obj(nativeJob["jobReference"])
	if e = validateJob(nativeJob, job, request, r); e != nil {
		return nil, 0, e
	}
	if str(job, "projectId") != r.GCP.QueryProjectID || str(job, "location") != r.GCP.Location || s.NativeReference != "projects/"+r.GCP.QueryProjectID+"/jobs/"+str(job, "jobId")+"?location="+r.GCP.Location {
		return nil, 0, errors.New("MULTICLOUD_GCP_JOB_SCOPE_CHANGED")
	}
	complete := false
	first := false
	nextToken := ""
	tokens := map[string]bool{}
	for _, o := range queryObjects {
		page, err := decode(o.Body)
		if err != nil {
			return nil, 0, err
		}
		u, err := url.Parse(o.Resource)
		if err != nil || u.Scheme != "https" || u.Host != "bigquery.googleapis.com" || u.User != nil || u.Fragment != "" || !sameJob(obj(page["jobReference"]), job) || len(list(page["errors"])) > 0 {
			return nil, 0, errors.New("MULTICLOUD_GCP_QUERY_OBJECT_CHANGED")
		}
		if o.Kind == "GCP_QUERY_RESPONSE" {
			if first || u.Path != "/bigquery/v2/projects/"+r.GCP.QueryProjectID+"/queries" || u.RawQuery != "" {
				return nil, 0, errors.New("MULTICLOUD_GCP_QUERY_SEQUENCE_CHANGED")
			}
			first = true
		} else {
			if !first || u.Path != "/bigquery/v2/projects/"+r.GCP.QueryProjectID+"/queries/"+str(job, "jobId") || u.Query().Get("location") != r.GCP.Location {
				return nil, 0, errors.New("MULTICLOUD_GCP_PAGE_SCOPE_CHANGED")
			}
			if o.Kind == "GCP_QUERY_POLL" {
				if complete || u.Query().Get("pageToken") != "" {
					return nil, 0, errors.New("MULTICLOUD_GCP_QUERY_SEQUENCE_CHANGED")
				}
			} else {
				if !complete || nextToken == "" || u.Query().Get("pageToken") != nextToken || tokens[nextToken] {
					return nil, 0, errors.New("MULTICLOUD_GCP_PAGE_SEQUENCE_CHANGED")
				}
				tokens[nextToken] = true
			}
		}
		if boolean(page, "jobComplete") {
			complete = true
			fields := list(obj(page["schema"])["fields"])
			if len(fields) != 1 || str(obj(fields[0]), "name") != "native_row" || str(obj(fields[0]), "type") != "STRING" {
				return nil, 0, errors.New("MULTICLOUD_GCP_ROW_SCHEMA_CHANGED")
			}
			nextToken = str(page, "pageToken")
		} else if o.Kind == "GCP_QUERY_RESULT_PAGE" {
			return nil, 0, errors.New("MULTICLOUD_GCP_PAGE_INCOMPLETE")
		}
	}
	if !first || !complete || nextToken != "" {
		return nil, 0, errors.New("MULTICLOUD_GCP_QUERY_PAGES_INCOMPLETE")
	}
	records := []Record{}
	var rows int64
	total := ""
	for _, page := range pages {
		if !sameJob(obj(page["jobReference"]), job) || len(list(page["errors"])) > 0 {
			return nil, 0, errors.New("MULTICLOUD_GCP_PAGE_CHANGED")
		}
		if value := str(page, "totalRows"); value != "" {
			if total != "" && total != value {
				return nil, 0, errors.New("MULTICLOUD_GCP_TOTAL_CHANGED")
			}
			total = value
		}
		for _, x := range list(page["rows"]) {
			fields := list(obj(x)["f"])
			if len(fields) != 1 {
				return nil, 0, errors.New("MULTICLOUD_GCP_ROW_SCHEMA_CHANGED")
			}
			native, e := decode([]byte(str(obj(fields[0]), "v")))
			if e != nil {
				return nil, 0, e
			}
			parsed, e := ParseGCPRow(r, native, s.NativeReference+"#"+strconv.FormatInt(rows, 10), str(account, "currencyCode"))
			if e != nil {
				return nil, 0, e
			}
			records = append(records, parsed...)
			rows++
			if rows > MaxRows || len(records) > MaxRows*2 {
				return nil, 0, errors.New("MULTICLOUD_ROW_LIMIT")
			}
		}
	}
	want, e := strconv.ParseInt(total, 10, 64)
	if e != nil || want != rows {
		return nil, 0, errors.New("MULTICLOUD_GCP_ROWS_INCOMPLETE")
	}
	return records, rows, nil
}
