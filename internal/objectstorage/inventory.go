package objectstorage

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"hash"
	"io"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

type InventoryFile struct {
	Key  string `json:"key"`
	Size int64  `json:"size"`
	MD5  string `json:"MD5checksum"`
}
type InventoryManifest struct {
	SourceBucket      string          `json:"sourceBucket"`
	DestinationBucket string          `json:"destinationBucket"`
	Version           string          `json:"version"`
	CreationTimestamp string          `json:"creationTimestamp"`
	FileFormat        string          `json:"fileFormat"`
	FileSchema        string          `json:"fileSchema"`
	Files             []InventoryFile `json:"files"`
}
type InventoryPipeline struct {
	Reader             ObjectReader
	Archive            Archive
	Facts              Facts
	LoadCheckpoint     func(context.Context, string) (model.Document, error)
	SaveCheckpoint     func(context.Context, string, model.Document) error
	Now                func() time.Time
	IdentityKey        []byte
	IdentityKeyVersion string
}
type objectBand struct {
	Count      int64 `json:"count"`
	TotalBytes int64 `json:"total_bytes"`
	MinBytes   int64 `json:"min_bytes"`
	MaxBytes   int64 `json:"max_bytes"`
}
type objectCohort struct {
	ID               string       `json:"id"`
	DatasetID        string       `json:"dataset_id"`
	Label            string       `json:"label"`
	Prefix           string       `json:"prefix"`
	SourceClass      string       `json:"source_class"`
	AccessTier       string       `json:"access_tier"`
	State            string       `json:"state"`
	ObjectCount      int64        `json:"object_count"`
	TotalBytes       int64        `json:"total_bytes"`
	SizeBands        []objectBand `json:"size_bands"`
	AgeMin           int64        `json:"age_days_min"`
	AgeMax           int64        `json:"age_days_max"`
	UnknownAge       bool         `json:"unknown_age"`
	LockedCount      int64        `json:"locked_count"`
	RetentionUnknown int64        `json:"retention_unknown_count"`
	ReplicatedCount  int64        `json:"replicated_count"`
	NoncurrentCount  int64        `json:"noncurrent_count"`
	PopulationHash   string       `json:"population_hash"`
}
type fileSummary struct {
	Cohorts       []objectCohort   `json:"cohorts"`
	RowCount      int64            `json:"row_count"`
	DeleteMarkers int64            `json:"delete_markers"`
	RawChunks     []model.Document `json:"raw_chunks"`
	File          model.Document   `json:"file"`
	Batches       []model.Document `json:"batches"`
	BatchCount    int              `json:"batch_count"`
	BatchHash     string           `json:"batch_hash"`
}

func (p *InventoryPipeline) now() time.Time {
	if p.Now != nil {
		return p.Now().UTC()
	}
	return time.Now().UTC()
}
func (p *InventoryPipeline) archive(ctx context.Context, r Registration, id string, raw []byte) (model.Document, error) {
	cache := "archive:" + Hash(model.Document{"id": id, "sha256": BytesHash(raw)})
	if p.LoadCheckpoint != nil {
		saved, e := p.LoadCheckpoint(ctx, cache)
		if e != nil {
			return nil, e
		}
		if ref := Doc(saved["archive"]); model.String(ref, "version_id") != "" {
			again, e := p.Archive.Read(ctx, r.TenantID, ref)
			if e != nil || !bytes.Equal(raw, again) || model.String(ref, "body_sha256") != BytesHash(raw) {
				return nil, errors.New("S3_ARCHIVE_CHECKPOINT_CHANGED")
			}
			return ref, nil
		}
	}
	ref, e := p.Archive.Archive(ctx, r.TenantID, "wire", id, raw)
	if e != nil {
		return nil, e
	}
	if model.String(ref, "body_sha256") != BytesHash(raw) || model.String(ref, "version_id") == "" || model.String(ref, "version_id") == "null" {
		return nil, errors.New("S3_IMMUTABLE_ARCHIVE_REQUIRED")
	}
	again, e := p.Archive.Read(ctx, r.TenantID, ref)
	if e != nil || !bytes.Equal(raw, again) {
		return nil, errors.New("S3_ARCHIVE_READBACK_DIFFERS")
	}
	if p.SaveCheckpoint != nil {
		if e = p.SaveCheckpoint(ctx, cache, model.Document{"archive": ref}); e != nil {
			return nil, e
		}
	}
	return ref, nil
}
func sourceReference(kind string, ref model.Document) model.Document {
	return model.Document{"kind": kind, "id": model.String(ref, "key"), "version": model.String(ref, "version_id"), "sha256": model.String(ref, "body_sha256"), "archive": ref}
}
func (p *InventoryPipeline) readSmall(ctx context.Context, r Registration, key, version string, max int64) ([]byte, Object, error) {
	o, e := p.Reader.OpenObject(ctx, r, key, version)
	if e != nil {
		return nil, o, e
	}
	defer o.Body.Close()
	if o.Length < 0 || o.Length > max {
		return nil, o, errors.New("S3_MANIFEST_SIZE_LIMIT")
	}
	b, e := io.ReadAll(io.LimitReader(o.Body, max+1))
	if e != nil || int64(len(b)) > max || int64(len(b)) != o.Length {
		return nil, o, errors.New("S3_MANIFEST_BODY_INCOMPLETE")
	}
	return b, o, nil
}
func (p *InventoryPipeline) Ingest(ctx context.Context, r Registration, manifestKey string) (Generation, error) {
	out := Generation{Scope: Scope{r.TenantID, r.AccountID, r.Region}, Bucket: r.Bucket, SourceID: r.ID, Cohorts: []model.Document{}, SourceRefs: []model.Document{}, Access: model.Document{"status": "ACCESS_UNKNOWN", "state": "ACCESS_UNKNOWN", "basis": "AGE_IS_NOT_ACCESS", "complete": false}}
	rd := Doc(r)
	if ValidateRegistration(rd) != nil || r.Kind != InventoryKind || p.Reader == nil || p.Archive == nil || p.Facts == nil || p.LoadCheckpoint == nil || p.SaveCheckpoint == nil || len(p.IdentityKey) < 32 || !safe.MatchString(p.IdentityKeyVersion) {
		return out, errors.New("S3_INVENTORY_PIPELINE_INVALID")
	}
	expected := r.Prefix + r.Bucket + "/" + r.InventoryID + "/"
	if !strings.HasPrefix(manifestKey, expected) || !strings.HasSuffix(manifestKey, "/manifest.json") {
		return out, errors.New("S3_MANIFEST_SCOPE_MISMATCH")
	}
	boundary, e := p.Reader.ReportBoundary(ctx, r)
	if e != nil {
		return out, e
	}
	boundaryRaw, _ := json.Marshal(boundary)
	boundaryRef, e := p.archive(ctx, r, "s3-boundary-"+BytesHash(boundaryRaw), boundaryRaw)
	if e != nil {
		return out, e
	}
	state, e := p.LoadCheckpoint(ctx, "manifest:"+BytesHash([]byte(manifestKey)))
	if e != nil {
		return out, e
	}
	raw, object, e := p.readSmall(ctx, r, manifestKey, model.String(state, "version_id"), 4<<20)
	if e != nil {
		return out, e
	}
	checkKey := strings.TrimSuffix(manifestKey, "manifest.json") + "manifest.checksum"
	checksum, checkObject, e := p.readSmall(ctx, r, checkKey, model.String(state, "checksum_version_id"), 1024)
	if e != nil {
		return out, e
	}
	digest := md5.Sum(raw)
	if !strings.EqualFold(strings.TrimSpace(string(checksum)), hex.EncodeToString(digest[:])) {
		return out, errors.New("S3_MANIFEST_CHECKSUM_DIFFERS")
	}
	manifest := InventoryManifest{}
	d := json.NewDecoder(bytes.NewReader(raw))
	if d.Decode(&manifest) != nil || d.Decode(new(any)) != io.EOF {
		return out, errors.New("S3_MANIFEST_INVALID")
	}
	at, e := strconv.ParseInt(manifest.CreationTimestamp, 10, 64)
	if e != nil {
		return out, errors.New("S3_GENERATION_TIME_INVALID")
	}
	observed := time.UnixMilli(at).UTC()
	if manifest.SourceBucket != r.Bucket || manifest.DestinationBucket != "arn:aws:s3:::"+r.ReportBucket || manifest.FileFormat != "CSV" || manifest.Version != "2016-11-30" || observed.After(p.now().Add(time.Minute)) || observed.IsZero() || len(manifest.Files) > 10000 {
		return out, errors.New("S3_MANIFEST_BINDING_OR_FORMAT_INVALID")
	}
	headers := strings.Split(manifest.FileSchema, ",")
	seenHeaders := map[string]bool{}
	for i := range headers {
		headers[i] = strings.TrimSpace(headers[i])
		if seenHeaders[headers[i]] {
			return out, errors.New("S3_INVENTORY_SCHEMA_AMBIGUOUS")
		}
		seenHeaders[headers[i]] = true
	}
	for _, k := range []string{"Bucket", "Key", "Size", "LastModifiedDate", "StorageClass"} {
		if !seenHeaders[k] {
			return out, errors.New("S3_INVENTORY_REQUIRED_FIELD_UNAVAILABLE")
		}
	}
	configuration := Doc(boundary["configuration"])
	r.NativeBucketTags = map[string]string{}
	tagState := Doc(configuration["source_bucket_tags"])
	if model.String(tagState, "status") == "OBSERVED" {
		for _, tag := range Rows(Doc(tagState["value"])["TagSet"]) {
			r.NativeBucketTags[model.String(tag, "Key")] = model.String(tag, "Value")
		}
	}
	allVersions := model.String(configuration, "IncludedObjectVersions") == "All"
	if allVersions && (!seenHeaders["VersionId"] || !seenHeaders["IsLatest"] || !seenHeaders["IsDeleteMarker"]) {
		return out, errors.New("S3_VERSION_POPULATION_INCOMPLETE")
	}
	if prior := model.String(state, "sha256"); prior != "" && prior != BytesHash(raw) {
		return out, errors.New("S3_MANIFEST_VERSION_CHANGED")
	}
	if e = p.SaveCheckpoint(ctx, "manifest:"+BytesHash([]byte(manifestKey)), model.Document{"version_id": object.VersionID, "checksum_version_id": checkObject.VersionID, "sha256": BytesHash(raw), "status": "READING"}); e != nil {
		return out, e
	}
	manifestRef, e := p.archive(ctx, r, "s3-manifest-"+BytesHash(raw), raw)
	if e != nil {
		return out, e
	}
	checksumRef, e := p.archive(ctx, r, "s3-checksum-"+BytesHash(checksum), checksum)
	if e != nil {
		return out, e
	}
	generation := Hash(model.Document{"source_id": r.ID, "registration": r, "identity_key_version": p.IdentityKeyVersion, "manifest_sha256": BytesHash(raw), "manifest_version": object.VersionID, "configuration_hash": boundary["configuration_hash"], "writer_policy_hash": boundary["writer_policy_hash"]})
	out.ID = "s3-generation-" + generation
	out.SourceVersion = generation
	out.ObservedAt = observed
	sort.Slice(manifest.Files, func(i, j int) bool { return manifest.Files[i].Key < manifest.Files[j].Key })
	files := []model.Document{}
	cohorts := map[string]*objectCohort{}
	population := map[string]hash.Hash{}
	seenFiles := map[string]bool{}
	rowCount, markers := int64(0), int64(0)
	for _, file := range manifest.Files {
		if seenFiles[file.Key] || !strings.HasPrefix(file.Key, expected+"data/") || !strings.HasSuffix(file.Key, ".csv.gz") || file.Size < 0 || len(file.MD5) != 32 {
			return out, errors.New("S3_INVENTORY_FILE_SCOPE_INVALID")
		}
		seenFiles[file.Key] = true
		summary, e := p.ingestFile(ctx, r, generation, file, headers, observed, allVersions)
		if e != nil {
			return out, e
		}
		files = append(files, summary.File)
		rowCount += summary.RowCount
		markers += summary.DeleteMarkers
		for _, part := range summary.Cohorts {
			current := cohorts[part.ID]
			if current == nil {
				x := part
				x.ObjectCount = 0
				x.TotalBytes = 0
				x.SizeBands = nil
				x.LockedCount = 0
				x.RetentionUnknown = 0
				x.ReplicatedCount = 0
				x.NoncurrentCount = 0
				x.AgeMin = part.AgeMin
				cohorts[part.ID] = &x
				current = &x
				population[part.ID] = sha256.New()
			}
			if e = mergeCohort(current, part); e != nil {
				return out, e
			}
			_, _ = io.WriteString(population[part.ID], file.Key+"\x00"+part.PopulationHash+"\n")
		}
	}
	if validator, ok := p.Facts.(interface {
		ValidateObjectGeneration(context.Context, Scope, string, int64) error
	}); ok {
		if e = validator.ValidateObjectGeneration(ctx, out.Scope, generation, rowCount); e != nil {
			return out, e
		}
	} else {
		return out, errors.New("S3_GENERATION_READBACK_REQUIRED")
	}
	// Repeat native authority after the last data file. A policy/config change
	// cannot borrow the initial healthy boundary.
	after, e := p.Reader.ReportBoundary(ctx, r)
	if e != nil || after["writer_policy_hash"] != boundary["writer_policy_hash"] || after["configuration_hash"] != boundary["configuration_hash"] {
		return out, errors.New("S3_REPORT_AUTHORITY_CHANGED")
	}
	verify, _, e := p.readSmall(ctx, r, manifestKey, object.VersionID, 4<<20)
	if e != nil || !bytes.Equal(raw, verify) {
		return out, errors.New("S3_MANIFEST_VERSION_CHANGED")
	}
	fileIndex, _ := json.Marshal(files)
	indexRef, e := p.archive(ctx, r, "s3-index-"+BytesHash(fileIndex), fileIndex)
	if e != nil {
		return out, e
	}
	keys := []string{}
	for key := range cohorts {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	sourceRef := sourceReference("AWS_S3_INVENTORY_MANIFEST", manifestRef)
	for _, key := range keys {
		c := cohorts[key]
		c.PopulationHash = hex.EncodeToString(population[key].Sum(nil))
		doc := Doc(c)
		for _, selector := range r.Datasets {
			if selector.ID == c.DatasetID {
				doc["dataset_version"] = selector.DatasetVersion
				doc["dataset_hash"] = selector.DatasetHash
			}
		}
		doc["object_count"] = strconv.FormatInt(c.ObjectCount, 10)
		doc["total_bytes"] = strconv.FormatInt(c.TotalBytes, 10)
		bands := []model.Document{}
		for _, b := range c.SizeBands {
			if b.Count > 0 {
				bands = append(bands, model.Document{"count": strconv.FormatInt(b.Count, 10), "total_bytes": strconv.FormatInt(b.TotalBytes, 10), "min_bytes": strconv.FormatInt(b.MinBytes, 10), "max_bytes": strconv.FormatInt(b.MaxBytes, 10)})
			}
		}
		doc["size_bands"] = bands
		doc["inventory_complete"] = true
		doc["population_hash"] = c.PopulationHash
		doc["source_ref"] = sourceRef
		doc["minimum_duration_remaining_days"] = nil
		doc["access"] = model.Document{"state": "ACCESS_UNKNOWN", "start": nil, "end": nil, "complete": false, "requests": nil, "retrieved_bytes": nil, "eligible_cold_bytes_fraction": nil, "it_tier_fractions": nil, "source_ref": nil}
		doc["age_days_min"] = nil
		doc["age_days_max"] = nil
		if !c.UnknownAge {
			doc["age_days_min"] = strconv.FormatInt(c.AgeMin, 10)
			doc["age_days_max"] = strconv.FormatInt(c.AgeMax, 10)
		}
		out.Cohorts = append(out.Cohorts, doc)
	}
	out.Inventory = model.Document{"identity_key_version": p.IdentityKeyVersion, "generation_id": out.ID, "complete": true, "row_count": strconv.FormatInt(rowCount, 10), "delete_marker_count": strconv.FormatInt(markers, 10), "source_schema": manifest.FileSchema, "current_versions_only": !allVersions, "file_count": len(files), "file_index": indexRef, "observation_basis": "NATIVE_INVENTORY_SCAN_NOT_ATOMIC_STATE", "raw_manifest_ref": manifestRef, "source_version": generation}
	out.SourceRefs = []model.Document{sourceRef, sourceReference("AWS_S3_INVENTORY_CHECKSUM", checksumRef), sourceReference("AWS_S3_INVENTORY_FILE_INDEX", indexRef), sourceReference("AWS_S3_REPORT_BOUNDARY", boundaryRef)}
	out.Complete = true
	return out, nil
}

func mergeCohort(a *objectCohort, b objectCohort) error {
	max := int64(^uint64(0) >> 1)
	if a.ObjectCount > max-b.ObjectCount || a.TotalBytes > max-b.TotalBytes {
		return errors.New("S3_POPULATION_OVERFLOW")
	}
	a.ObjectCount += b.ObjectCount
	a.TotalBytes += b.TotalBytes
	a.LockedCount += b.LockedCount
	a.RetentionUnknown += b.RetentionUnknown
	a.ReplicatedCount += b.ReplicatedCount
	a.NoncurrentCount += b.NoncurrentCount
	a.UnknownAge = a.UnknownAge || b.UnknownAge
	if b.AgeMin < a.AgeMin {
		a.AgeMin = b.AgeMin
	}
	if b.AgeMax > a.AgeMax {
		a.AgeMax = b.AgeMax
	}
	if a.SizeBands == nil {
		a.SizeBands = make([]objectBand, len(b.SizeBands))
	}
	for i, v := range b.SizeBands {
		if v.Count == 0 {
			continue
		}
		d := &a.SizeBands[i]
		if d.Count > max-v.Count || d.TotalBytes > max-v.TotalBytes {
			return errors.New("S3_POPULATION_OVERFLOW")
		}
		if d.Count == 0 || v.MinBytes < d.MinBytes {
			d.MinBytes = v.MinBytes
		}
		if v.MaxBytes > d.MaxBytes {
			d.MaxBytes = v.MaxBytes
		}
		d.Count += v.Count
		d.TotalBytes += v.TotalBytes
	}
	return nil
}

type archiveChunkWriter struct {
	ctx    context.Context
	p      *InventoryPipeline
	r      Registration
	fileID string
	index  int
	buffer []byte
	refs   []model.Document
}

func (w *archiveChunkWriter) Write(b []byte) (int, error) {
	total := len(b)
	for len(b) > 0 {
		n := min(len(b), RawChunkBytes-len(w.buffer))
		w.buffer = append(w.buffer, b[:n]...)
		b = b[n:]
		if len(w.buffer) == RawChunkBytes {
			if e := w.flush(); e != nil {
				return 0, e
			}
		}
	}
	return total, nil
}
func (w *archiveChunkWriter) flush() error {
	if len(w.buffer) == 0 {
		return nil
	}
	ref, e := w.p.archive(w.ctx, w.r, "s3-chunk-"+Hash(model.Document{"file": w.fileID, "ordinal": w.index, "sha256": BytesHash(w.buffer)}), w.buffer)
	if e != nil {
		return e
	}
	ref["ordinal"] = w.index
	w.refs = append(w.refs, ref)
	w.index++
	w.buffer = w.buffer[:0]
	return nil
}
func (p *InventoryPipeline) ingestFile(ctx context.Context, r Registration, generation string, file InventoryFile, headers []string, observed time.Time, allVersions bool) (fileSummary, error) {
	summary := fileSummary{Cohorts: []objectCohort{}, RawChunks: []model.Document{}, Batches: []model.Document{}}
	checkpointKey := "file:" + generation + ":" + BytesHash([]byte(file.Key))
	state, e := p.LoadCheckpoint(ctx, checkpointKey)
	if e != nil {
		return summary, e
	}
	if ref := Doc(state["summary_ref"]); model.String(ref, "version_id") != "" {
		raw, e := p.Archive.Read(ctx, r.TenantID, ref)
		if e != nil || BytesHash(raw) != model.String(ref, "body_sha256") || json.Unmarshal(raw, &summary) != nil {
			return summary, errors.New("S3_FILE_CHECKPOINT_INVALID")
		}
		summary.File = compactFileSummary(summary, ref)
		return summary, nil
	}
	object, e := p.Reader.OpenObject(ctx, r, file.Key, model.String(state, "version_id"))
	if e != nil {
		return summary, e
	}
	defer object.Body.Close()
	if object.Length != file.Size || object.VersionID == "" || object.VersionID == "null" {
		return summary, errors.New("S3_FILE_VERSION_OR_SIZE_MISMATCH")
	}
	if e = p.SaveCheckpoint(ctx, checkpointKey, model.Document{"version_id": object.VersionID, "status": "READING"}); e != nil {
		return summary, e
	}
	writer := &archiveChunkWriter{ctx: ctx, p: p, r: r, fileID: generation + ":" + file.Key, buffer: make([]byte, 0, RawChunkBytes), refs: []model.Document{}}
	md5Hash, sha := md5.New(), sha256.New()
	counted := &countReader{Reader: io.TeeReader(io.LimitReader(object.Body, file.Size+1), io.MultiWriter(writer, md5Hash, sha))}
	gz, e := gzip.NewReader(counted)
	if e != nil {
		return summary, errors.New("S3_INVENTORY_GZIP_INVALID")
	}
	defer gz.Close()
	csvReader := csv.NewReader(&boundedLineReader{Reader: gz, limit: 256 << 10})
	csvReader.FieldsPerRecord = len(headers)
	csvReader.ReuseRecord = true
	cohorts := map[string]*objectCohort{}
	hashes := map[string]hash.Hash{}
	batch := []InventoryRow{}
	batchOrdinal := 0
	batchHash := sha256.New()
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		batchID := Hash(model.Document{"generation": generation, "file": file.Key, "ordinal": batchOrdinal})
		ack, e := p.Facts.WriteObjectRows(ctx, Scope{r.TenantID, r.AccountID, r.Region}, generation, batchID, batch)
		if e != nil || model.String(ack, "canonical_hash") != Hash(batch) || model.Number(ack, "row_count") != int64(len(batch)) {
			return errors.New("S3_INVENTORY_ANALYTICS_ACK_INVALID")
		}
		_, _ = io.WriteString(batchHash, Hash(ack)+"\n")
		batch = batch[:0]
		batchOrdinal++
		return nil
	}
	for {
		record, e := csvReader.Read()
		if e == io.EOF {
			break
		}
		if e != nil {
			return summary, errors.New("S3_INVENTORY_CSV_INVALID")
		}
		if ctx.Err() != nil {
			return summary, ctx.Err()
		}
		fields := map[string]string{}
		for i, key := range headers {
			if len(record[i]) > 16384 {
				return summary, errors.New("S3_INVENTORY_FIELD_LIMIT")
			}
			fields[key] = record[i]
		}
		row, c, e := parseInventoryRow(r, generation, file.Key, summary.RowCount, fields, observed, allVersions, p.IdentityKey)
		if e != nil {
			return summary, e
		}
		summary.RowCount++
		batch = append(batch, row)
		if row.IsDeleteMarker != nil && *row.IsDeleteMarker {
			summary.DeleteMarkers++
		} else {
			if len(cohorts) >= 4096 && cohorts[c.ID] == nil {
				return summary, errors.New("S3_COHORT_LIMIT")
			}
			current := cohorts[c.ID]
			if current == nil {
				x := c
				x.ObjectCount = 0
				x.TotalBytes = 0
				x.SizeBands = nil
				x.LockedCount = 0
				x.RetentionUnknown = 0
				x.ReplicatedCount = 0
				x.NoncurrentCount = 0
				cohorts[c.ID] = &x
				current = &x
				hashes[c.ID] = sha256.New()
			}
			if e = mergeCohort(current, c); e != nil {
				return summary, e
			}
			_, _ = io.WriteString(hashes[c.ID], Hash(row)+"\n")
		}
		if len(batch) == InventoryBatchRows {
			if e = flush(); e != nil {
				return summary, e
			}
		}
	}
	if e = flush(); e != nil {
		return summary, e
	}
	if _, e = io.Copy(io.Discard, counted); e != nil {
		return summary, errors.New("S3_FILE_READ_INCOMPLETE")
	}
	if counted.Count != file.Size || !strings.EqualFold(hex.EncodeToString(md5Hash.Sum(nil)), file.MD5) {
		return summary, errors.New("S3_FILE_CHECKSUM_DIFFERS")
	}
	if e = writer.flush(); e != nil {
		return summary, e
	}
	summary.RawChunks = writer.refs
	summary.BatchCount = batchOrdinal
	summary.BatchHash = hex.EncodeToString(batchHash.Sum(nil))
	summary.File = model.Document{"key": file.Key, "version_id": object.VersionID, "length": file.Size, "sha256": hex.EncodeToString(sha.Sum(nil)), "md5": hex.EncodeToString(md5Hash.Sum(nil)), "raw_chunks": writer.refs, "row_count": summary.RowCount, "batch_count": summary.BatchCount, "batch_hash": summary.BatchHash}
	keys := []string{}
	for key := range cohorts {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		c := cohorts[key]
		c.PopulationHash = hex.EncodeToString(hashes[key].Sum(nil))
		summary.Cohorts = append(summary.Cohorts, *c)
	}
	raw, _ := json.Marshal(summary)
	if len(raw) > RawChunkBytes {
		return summary, errors.New("S3_FILE_SUMMARY_LIMIT")
	}
	ref, e := p.archive(ctx, r, "s3-file-summary-"+BytesHash(raw), raw)
	if e != nil {
		return summary, e
	}
	if e = p.SaveCheckpoint(ctx, checkpointKey, model.Document{"version_id": object.VersionID, "status": "PERSISTED", "summary_ref": ref}); e != nil {
		return summary, e
	}
	summary.File = compactFileSummary(summary, ref)
	return summary, nil
}
func compactFileSummary(summary fileSummary, ref model.Document) model.Document {
	return model.Document{"key": summary.File["key"], "version_id": summary.File["version_id"], "length": summary.File["length"], "sha256": summary.File["sha256"], "md5": summary.File["md5"], "row_count": summary.RowCount, "batch_count": summary.BatchCount, "batch_hash": summary.BatchHash, "summary_ref": ref}
}

type boundedLineReader struct {
	io.Reader
	limit int
	line  int
}

func (r *boundedLineReader) Read(b []byte) (int, error) {
	n, e := r.Reader.Read(b)
	for _, v := range b[:n] {
		if v == '\n' {
			r.line = 0
		} else {
			r.line++
			if r.line > r.limit {
				return 0, errors.New("S3_CSV_RECORD_BYTE_LIMIT")
			}
		}
	}
	return n, e
}

type countReader struct {
	io.Reader
	Count int64
}

func (r *countReader) Read(b []byte) (int, error) {
	n, e := r.Reader.Read(b)
	r.Count += int64(n)
	return n, e
}
func parseInventoryRow(r Registration, generation, file string, index int64, f map[string]string, observed time.Time, allVersions bool, identityKey []byte) (InventoryRow, objectCohort, error) {
	row := InventoryRow{}
	c := objectCohort{}
	if f["Bucket"] != r.Bucket {
		return row, c, errors.New("S3_OBJECT_BUCKET_MISMATCH")
	}
	key, e := url.PathUnescape(f["Key"])
	if e != nil || key == "" || len(key) > 1024 {
		return row, c, errors.New("S3_OBJECT_KEY_INVALID")
	}
	version := f["VersionId"]
	tenantMAC := hmac.New(sha256.New, identityKey)
	_, _ = io.WriteString(tenantMAC, "s3-object-identity\x00"+r.TenantID)
	mac := hmac.New(sha256.New, tenantMAC.Sum(nil))
	identityRaw, _ := json.Marshal(model.Document{"bucket": r.Bucket, "key": key, "version": version})
	_, _ = mac.Write(identityRaw)
	identity := hex.EncodeToString(mac.Sum(nil))
	row = InventoryRow{ID: Hash(model.Document{"generation": generation, "file": file, "index": index}), Bucket: r.Bucket, ObjectIdentity: identity, Fields: map[string]string{}}
	if version != "" {
		row.VersionID = &version
	}
	latest := true
	if allVersions {
		v, e := strconv.ParseBool(f["IsLatest"])
		if e != nil {
			return row, c, errors.New("S3_OBJECT_VERSION_STATE_UNKNOWN")
		}
		latest = v
	}
	row.IsLatest = &latest
	marker := false
	if f["IsDeleteMarker"] != "" {
		v, e := strconv.ParseBool(f["IsDeleteMarker"])
		if e != nil {
			return row, c, errors.New("S3_DELETE_MARKER_INVALID")
		}
		marker = v
	}
	row.IsDeleteMarker = &marker
	for k, v := range f {
		if k != "Key" {
			row.Fields[k] = v
		}
	}
	selector := DatasetSelector{Kind: "BUCKET"}
	for _, s := range r.Datasets {
		if len(s.Tags) > 0 {
			// An object tag is not a bucket label. Inventory cannot establish
			// membership of an object-tag filter from GetBucketTagging.
			continue
		}
		if len(s.StorageClasses) > 0 {
			matched := false
			for _, class := range s.StorageClasses {
				if class == f["StorageClass"] {
					matched = true
				}
			}
			if !matched {
				continue
			}
		}
		if strings.HasPrefix(key, s.Prefix) && (len(s.Prefix) > len(selector.Prefix) || len(s.Prefix) == len(selector.Prefix) && (selector.ID == "" || s.ID < selector.ID)) {
			selector = s
		}
	}
	if selector.ID == "" {
		selector.ID = "bucket"
	}
	state := "CURRENT"
	if !latest {
		state = "NONCURRENT"
	}
	class, tier := f["StorageClass"], f["IntelligentTieringAccessTier"]
	cohortID := selector.ID + ":" + Hash(model.Document{"prefix": selector.Prefix, "class": class, "tier": tier, "state": state})[:24]
	row.CohortID = cohortID
	if marker {
		return row, c, nil
	}
	size, e := strconv.ParseInt(f["Size"], 10, 64)
	if e != nil || size < 0 {
		return row, c, errors.New("S3_OBJECT_SIZE_UNKNOWN")
	}
	if class == "" {
		return row, c, errors.New("S3_OBJECT_CLASS_UNKNOWN")
	}
	row.Size = &size
	row.StorageClass = &class
	c = objectCohort{ID: cohortID, DatasetID: selector.ID, Label: r.Bucket + "/" + selector.Prefix, Prefix: selector.Prefix, SourceClass: class, AccessTier: tier, State: state, ObjectCount: 1, TotalBytes: size, SizeBands: make([]objectBand, 8)}
	bounds := []int64{1024, 8192, 65536, 131072, 1048576, 16777216, 1073741824}
	band := 0
	for band < len(bounds) && size >= bounds[band] {
		band++
	}
	c.SizeBands[band] = objectBand{Count: 1, TotalBytes: size, MinBytes: size, MaxBytes: size}
	at, e := time.Parse(time.RFC3339, f["LastModifiedDate"])
	if e != nil || at.After(observed) {
		c.UnknownAge = true
	} else {
		row.LastModified = &at
		age := int64(observed.Sub(at) / (24 * time.Hour))
		c.AgeMin = age
		c.AgeMax = age
	}
	if f["ObjectLockRetainUntilDate"] == "" || f["ObjectLockMode"] == "" || f["ObjectLockLegalHoldStatus"] == "" {
		c.RetentionUnknown = 1
	}
	if strings.EqualFold(f["ObjectLockLegalHoldStatus"], "ON") {
		c.LockedCount = 1
	}
	if t, e := time.Parse(time.RFC3339, f["ObjectLockRetainUntilDate"]); e == nil && t.After(observed) {
		c.LockedCount = 1
	}
	if f["ReplicationStatus"] != "" {
		c.ReplicatedCount = 1
	}
	if !latest {
		c.NoncurrentCount = 1
	}
	return row, c, nil
}
