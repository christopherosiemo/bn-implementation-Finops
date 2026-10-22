package objectstorage

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"io"
	"math/big"
	"sort"
	"strconv"
	"strings"
	"time"
)

type lensManifest struct {
	Account     string `json:"sourceAccountId"`
	Config      string `json:"configId"`
	Destination string `json:"destinationBucket"`
	Version     string `json:"reportVersion"`
	Date        string `json:"reportDate"`
	Format      string `json:"reportFormat"`
	Schema      string `json:"reportSchema"`
	Files       []struct {
		Key  string `json:"key"`
		Size int64  `json:"size"`
		MD5  string `json:"md5Checksum"`
	} `json:"reportFiles"`
}

// IngestAnalysis preserves native export scope/units and actual daily records.
// It never equates a report's presence with universal complete access logs.
func (p *InventoryPipeline) IngestAnalysis(ctx context.Context, r Registration, key string) (Generation, error) {
	out := Generation{Scope: Scope{r.TenantID, r.AccountID, r.Region}, SourceID: r.ID, Bucket: r.Bucket, Cohorts: []model.Document{}, SourceRefs: []model.Document{}, Access: model.Document{"state": "ACCESS_UNKNOWN", "complete": false}}
	if ValidateRegistration(Doc(r)) != nil || r.Kind != AccessKind || p.Reader == nil || p.Archive == nil {
		return out, errors.New("S3_ANALYTICS_PIPELINE_INVALID")
	}
	boundary, e := p.Reader.ReportBoundary(ctx, r)
	if e != nil {
		return out, e
	}
	rawBoundary, _ := json.Marshal(boundary)
	boundaryRef, e := p.archive(ctx, r, "s3-analysis-boundary-"+BytesHash(rawBoundary), rawBoundary)
	if e != nil {
		return out, e
	}
	out.SourceRefs = append(out.SourceRefs, sourceReference("AWS_S3_ANALYTICS_BOUNDARY", boundaryRef))
	if r.ReportType == "APP_ACCESS" {
		return p.ingestApplication(ctx, r, key, boundary, out)
	}
	observations := []model.Document{}
	refs := []model.Document{}
	configuration := Doc(boundary["configuration"])
	filter := configuration["Filter"]
	if r.ReportType == "S3_STORAGE_LENS" {
		expected := r.Prefix + "StorageLens/" + r.AccountID + "/" + r.InventoryID + "/V_1/manifests/"
		if !strings.HasPrefix(key, expected) || !strings.HasSuffix(key, "/manifest.json") {
			return out, errors.New("S3_LENS_MANIFEST_SCOPE_MISMATCH")
		}
		raw, obj, e := p.readSmall(ctx, r, key, "", 4<<20)
		if e != nil {
			return out, e
		}
		var manifest lensManifest
		if json.Unmarshal(raw, &manifest) != nil || manifest.Account != r.AccountID || manifest.Config != r.InventoryID || manifest.Destination != "arn:aws:s3:::"+r.ReportBucket || manifest.Version != "V_1" || manifest.Format != "CSV" || len(manifest.Files) > 10000 {
			return out, errors.New("S3_LENS_MANIFEST_INVALID")
		}
		day, e := time.Parse("2006-01-02", manifest.Date)
		if e != nil || !day.Before(p.now().UTC().Truncate(24*time.Hour)) {
			return out, errors.New("S3_LENS_REPORT_PERIOD_INVALID")
		}
		ref, e := p.archive(ctx, r, "s3-lens-manifest-"+BytesHash(raw), raw)
		if e != nil {
			return out, e
		}
		refs = append(refs, sourceReference("AWS_S3_STORAGE_LENS_MANIFEST", ref))
		sort.Slice(manifest.Files, func(i, j int) bool { return manifest.Files[i].Key < manifest.Files[j].Key })
		seenFiles := map[string]bool{}
		for _, f := range manifest.Files {
			if seenFiles[f.Key] || !strings.HasPrefix(f.Key, r.Prefix+"StorageLens/"+r.AccountID+"/"+r.InventoryID+"/V_1/reports/dt="+manifest.Date+"/") || f.Size < 0 || len(f.MD5) != 32 {
				return out, errors.New("S3_LENS_FILE_SCOPE_INVALID")
			}
			seenFiles[f.Key] = true
			rows, ref, e := p.analysisFile(ctx, r, f.Key, manifest.Schema, &day, f.Size, f.MD5)
			if e != nil {
				return out, e
			}
			observations = append(observations, rows...)
			refs = append(refs, ref)
			if len(observations) > 100000 {
				return out, errors.New("S3_ANALYTICS_OBSERVATION_LIMIT")
			}
		}
		again, _, e := p.readSmall(ctx, r, key, obj.VersionID, 4<<20)
		if e != nil || !bytes.Equal(raw, again) {
			return out, errors.New("S3_LENS_MANIFEST_CHANGED")
		}
		out.ObservedAt = day
	} else {
		if !strings.HasPrefix(key, r.Prefix) || !strings.HasSuffix(key, ".csv") {
			return out, errors.New("S3_ANALYTICS_OBJECT_SCOPE_INVALID")
		}
		rows, ref, e := p.analysisFile(ctx, r, key, "", nil, -1, "")
		if e != nil {
			return out, e
		}
		observations = rows
		refs = append(refs, ref)
		out.ObservedAt = p.now()
	}
	after, e := p.Reader.ReportBoundary(ctx, r)
	if e != nil || after["writer_policy_hash"] != boundary["writer_policy_hash"] || after["configuration_hash"] != boundary["configuration_hash"] {
		return out, errors.New("S3_ANALYTICS_AUTHORITY_CHANGED")
	}
	version := Hash(model.Document{"registration": r, "refs": refs, "configuration_hash": boundary["configuration_hash"], "writer_policy_hash": boundary["writer_policy_hash"]})
	out.ID = "s3-access-" + version
	out.SourceVersion = version
	out.SourceRefs = append(out.SourceRefs, refs...)
	days := map[string]bool{}
	for _, row := range observations {
		days[model.String(row, "date")] = true
	}
	dates := []string{}
	for day := range days {
		dates = append(dates, day)
	}
	sort.Strings(dates)
	contiguous := len(dates) > 0
	for i := 1; i < len(dates); i++ {
		before, _ := time.Parse("2006-01-02", dates[i-1])
		if dates[i] != before.Add(24*time.Hour).Format("2006-01-02") {
			contiguous = false
		}
	}
	out.Access = model.Document{"state": "ACCESS_PATTERN_OBSERVED", "source_type": r.ReportType, "complete": false, "period_observations_contiguous": contiguous, "observed_days": len(days), "observed_dates": dates, "request_accounting_complete": false, "filter": filter, "observations": observations, "source_ref": out.SourceRefs[len(out.SourceRefs)-1], "unknown_periods": "UNKNOWN_NOT_ZERO", "eligible_cold_bytes_fraction": nil, "it_tier_fractions": nil, "reason_codes": []string{"NATIVE_OBSERVATION_SUBSET_NOT_COMPLETE_ACCOUNTING", "MISSING_PERIODS_REMAIN_UNKNOWN"}}
	if len(dates) > 0 {
		start, _ := time.Parse("2006-01-02", dates[0])
		end, _ := time.Parse("2006-01-02", dates[len(dates)-1])
		out.Access["start"] = start
		out.Access["end"] = end.Add(24 * time.Hour)
	}
	out.Inventory = model.Document{"complete": false, "status": "ANALYTICS_IS_NOT_OBJECT_INVENTORY", "row_count": nil}
	out.Complete = true
	return out, nil
}
func (p *InventoryPipeline) ingestApplication(ctx context.Context, r Registration, key string, boundary model.Document, out Generation) (Generation, error) {
	if !strings.HasPrefix(key, r.Prefix) || !strings.HasSuffix(key, ".jsonl") {
		return out, errors.New("S3_APP_REPORT_SCOPE_INVALID")
	}
	definition := model.String(Doc(boundary["configuration"]), "metric_definition_id")
	if definition == "" {
		return out, errors.New("S3_APP_METRIC_DEFINITION_UNREGISTERED")
	}
	o, e := p.Reader.OpenObject(ctx, r, key, "")
	if e != nil {
		return out, e
	}
	defer o.Body.Close()
	if o.Length < 0 {
		return out, errors.New("S3_APP_REPORT_SIZE_UNKNOWN")
	}
	writer := &archiveChunkWriter{ctx: ctx, p: p, r: r, fileID: r.ID + ":" + key + ":" + o.VersionID, buffer: make([]byte, 0, RawChunkBytes), refs: []model.Document{}}
	sha := sha256.New()
	counter := &countReader{Reader: io.TeeReader(io.LimitReader(o.Body, o.Length+1), io.MultiWriter(writer, sha))}
	access, e := ParseAppAccess(counter, r, p.now(), definition, model.String(Doc(boundary["configuration"]), "metric_definition_version"))
	if e != nil {
		return out, e
	}
	if _, e = io.Copy(io.Discard, counter); e != nil || counter.Count != o.Length {
		return out, errors.New("S3_APP_REPORT_BODY_INCOMPLETE")
	}
	if e = writer.flush(); e != nil {
		return out, e
	}
	after, e := p.Reader.ReportBoundary(ctx, r)
	if e != nil || after["writer_policy_hash"] != boundary["writer_policy_hash"] || after["configuration_hash"] != boundary["configuration_hash"] {
		return out, errors.New("S3_APP_REPORT_AUTHORITY_CHANGED")
	}
	index := model.Document{"bucket": r.ReportBucket, "key": key, "version_id": o.VersionID, "sha256": hex.EncodeToString(sha.Sum(nil)), "length": strconv.FormatInt(o.Length, 10), "raw_chunks": writer.refs, "metric_definition_id": definition}
	raw, _ := json.Marshal(index)
	ref, e := p.archive(ctx, r, "s3-app-file-"+BytesHash(raw), raw)
	if e != nil {
		return out, e
	}
	sourceRef := sourceReference("AWS_S3_APPROVED_APPLICATION_ACCESS_HISTORY", ref)
	out.SourceRefs = append(out.SourceRefs, sourceRef)
	version := Hash(model.Document{"registration": r, "file": index, "configuration_hash": boundary["configuration_hash"], "writer_policy_hash": boundary["writer_policy_hash"]})
	out.ID = "s3-access-" + version
	out.SourceVersion = version
	out.Access = access
	out.Access["source_ref"] = sourceRef
	out.Access["provenance"] = "REGISTERED_COLLECTOR_S3_WRITER_AND_IMMUTABLE_VERSION"
	if at, ok := access["end"].(time.Time); ok {
		out.ObservedAt = at
	} else {
		out.ObservedAt, _ = time.Parse(time.RFC3339Nano, model.String(access, "end"))
	}
	out.Complete = true
	out.Inventory = model.Document{"complete": false, "status": "ACCESS_HISTORY_REQUIRES_INDEPENDENT_INVENTORY"}
	return out, nil
}
func (p *InventoryPipeline) analysisFile(ctx context.Context, r Registration, key, schema string, reportDay *time.Time, size int64, md5Expected string) ([]model.Document, model.Document, error) {
	rows := []model.Document{}
	o, e := p.Reader.OpenObject(ctx, r, key, "")
	if e != nil {
		return nil, nil, e
	}
	defer o.Body.Close()
	if size >= 0 && o.Length != size {
		return nil, nil, errors.New("S3_ANALYTICS_SIZE_MISMATCH")
	}
	if o.Length < 0 {
		return nil, nil, errors.New("S3_ANALYTICS_SIZE_UNKNOWN")
	}
	writer := &archiveChunkWriter{ctx: ctx, p: p, r: r, fileID: r.ID + ":" + key + ":" + o.VersionID, buffer: make([]byte, 0, RawChunkBytes), refs: []model.Document{}}
	md5Hash, sha := md5.New(), sha256.New()
	counted := &countReader{Reader: io.TeeReader(io.LimitReader(o.Body, o.Length+1), io.MultiWriter(writer, md5Hash, sha))}
	reader := csv.NewReader(&boundedLineReader{Reader: counted, limit: 256 << 10})
	reader.ReuseRecord = true
	reader.FieldsPerRecord = -1
	headers := []string{}
	if schema != "" {
		for _, h := range strings.Split(schema, ",") {
			headers = append(headers, strings.TrimSpace(h))
		}
	}
	seen := map[string]bool{}
	first := true
	for {
		record, e := reader.Read()
		if e == io.EOF {
			break
		}
		if e != nil {
			return nil, nil, errors.New("S3_ANALYTICS_CSV_INVALID")
		}
		if len(record) > 128 {
			return nil, nil, errors.New("S3_ANALYTICS_SCHEMA_LIMIT")
		}
		if first {
			first = false
			if len(headers) == 0 {
				headers = append([]string{}, record...)
				continue
			}
			if len(record) > 0 && record[0] == headers[0] {
				continue
			}
		}
		if len(record) != len(headers) {
			return nil, nil, errors.New("S3_ANALYTICS_SCHEMA_MISMATCH")
		}
		f := map[string]string{}
		for i, k := range headers {
			if len(record[i]) > 16384 {
				return nil, nil, errors.New("S3_ANALYTICS_FIELD_LIMIT")
			}
			if _, exists := f[k]; exists {
				return nil, nil, errors.New("S3_ANALYTICS_DUPLICATE_HEADER")
			}
			f[k] = record[i]
		}
		row := model.Document{}
		if r.ReportType == "S3_STORAGE_LENS" {
			if f["configuration_id"] != r.InventoryID || f["aws_account_number"] != r.AccountID {
				return nil, nil, errors.New("S3_LENS_ACCOUNT_OR_CONFIGURATION_MISMATCH")
			}
			if f["aws_region"] != r.Region || f["bucket_name"] != r.Bucket {
				continue
			}
			if f["record_type"] != "BUCKET" && f["record_type"] != "PREFIX" {
				continue
			}
			if reportDay == nil || f["report_date"] != reportDay.Format("2006-01-02") {
				return nil, nil, errors.New("S3_LENS_ROW_PERIOD_MISMATCH")
			}
			value, ok := new(big.Rat).SetString(f["metric_value"])
			if !ok || value.Sign() < 0 || !value.IsInt() {
				return nil, nil, errors.New("S3_LENS_METRIC_VALUE_INVALID")
			}
			row = model.Document{"date": f["report_date"], "storage_class": f["storage_class"], "record_type": f["record_type"], "record_value": f["record_value"], "metric": f["metric_name"], "value": f["metric_value"], "unit": "NATIVE_METRIC_DEFINITION_REQUIRED", "bucket": r.Bucket}
			if strings.Contains(f["metric_name"], "Bytes") {
				row["unit"] = "Bytes"
			} else if strings.Contains(f["metric_name"], "Count") || strings.HasSuffix(f["metric_name"], "Requests") {
				row["unit"] = "Count"
			}
		} else {
			if f["ConfigId"] != r.InventoryID {
				return nil, nil, errors.New("S3_ANALYTICS_CONFIGURATION_MISMATCH")
			}
			date, e := time.Parse("01-02-2006", f["Date"])
			if e != nil || !date.Before(p.now().UTC().Truncate(24*time.Hour)) {
				return nil, nil, errors.New("S3_ANALYTICS_DATE_INVALID")
			}
			if date.Before(p.now().Add(-366 * 24 * time.Hour)) {
				continue
			}
			row = model.Document{"date": date.Format("2006-01-02"), "storage_class": f["StorageClass"], "object_age_group": f["ObjectAge"], "native_values": f, "request_semantics": "GetRequestCount_INCLUDES_GET_AND_PUT_SUCCESS_SUBSET", "native_data_unit": "MB", "canonical_retrieved_bytes": nil, "eligible_cold_bytes_fraction": nil}
			for _, metric := range []string{"Storage_MB", "DataRetrieved_MB", "GetRequestCount"} {
				v, ok := new(big.Rat).SetString(f[metric])
				if !ok || v.Sign() < 0 {
					return nil, nil, errors.New("S3_ANALYTICS_REQUIRED_METRIC_UNKNOWN")
				}
			}
		}
		identity := Hash(row)
		if seen[identity] {
			return nil, nil, errors.New("S3_ANALYTICS_DUPLICATE_ROW")
		}
		seen[identity] = true
		rows = append(rows, row)
		if len(rows) > 100000 {
			return nil, nil, errors.New("S3_ANALYTICS_OBSERVATION_LIMIT")
		}
	}
	if counted.Count != o.Length {
		return nil, nil, errors.New("S3_ANALYTICS_BODY_INCOMPLETE")
	}
	digest := hex.EncodeToString(md5Hash.Sum(nil))
	if md5Expected != "" && !strings.EqualFold(md5Expected, digest) {
		return nil, nil, errors.New("S3_LENS_FILE_CHECKSUM_DIFFERS")
	}
	if e = writer.flush(); e != nil {
		return nil, nil, e
	}
	index := model.Document{"key": key, "version_id": o.VersionID, "sha256": hex.EncodeToString(sha.Sum(nil)), "md5": digest, "length": strconv.FormatInt(o.Length, 10), "raw_chunks": writer.refs, "observation_count": len(rows)}
	encoded, _ := json.Marshal(index)
	ref, e := p.archive(ctx, r, "s3-access-file-"+BytesHash(encoded), encoded)
	if e != nil {
		return nil, nil, e
	}
	return rows, sourceReference("AWS_S3_NATIVE_ACCESS_EXPORT", ref), nil
}
