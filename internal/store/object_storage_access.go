package store

// S3 application access is a distinct, current minute contract. Registered
// application scope is a customer declaration, never independent proof that
// every S3 access path was instrumented or an invented historical receipt.
import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"strconv"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/jackc/pgx/v5"
)

var ErrObjectStorageAccessSource = errors.New("object storage access source not authorized")
var ErrObjectStorageAccessConflict = errors.New("object storage access replay or interval conflicts")
var objectStorageAccessCount = regexp.MustCompile(`^(0|[1-9][0-9]{0,25})$`)

const ObjectStorageAccessUnit = "s3-get-requests-and-bytes"

type ObjectStorageAccessSource struct {
	ID                       string         `json:"id"`
	ResourceID               string         `json:"resource_id"`
	DatasetID                string         `json:"dataset_id"`
	DatasetVersion           int64          `json:"dataset_version"`
	ProviderResourceID       string         `json:"provider_resource_id"`
	AccountID                string         `json:"account_id"`
	Region                   string         `json:"region"`
	Issuer                   string         `json:"issuer"`
	Subject                  string         `json:"subject"`
	MetricDefinition         ActivityMetric `json:"metric_definition"`
	AuthoritativeAccessScope bool           `json:"authoritative_access_scope"`
	Enabled                  bool           `json:"enabled"`
	Version                  int64          `json:"version"`
	CreatedAt                time.Time      `json:"created_at"`
}

type ObjectStorageAccessInterval struct {
	SchemaVersion    string         `json:"schema_version"`
	SourceID         string         `json:"source_id"`
	ResourceID       string         `json:"resource_id"`
	DatasetID        string         `json:"dataset_id"`
	DatasetVersion   int64          `json:"dataset_version"`
	Sequence         int64          `json:"sequence"`
	IntervalStart    time.Time      `json:"interval_start"`
	IntervalEnd      time.Time      `json:"interval_end"`
	MetricDefinition ActivityMetric `json:"metric_definition"`
	GetRequests      string         `json:"get_requests"`
	RetrievedBytes   string         `json:"retrieved_bytes"`
	Heartbeat        bool           `json:"heartbeat"`
}

type ObjectStorageAccessReceipt struct {
	ObjectStorageAccessInterval
	ID             string         `json:"id"`
	TenantID       string         `json:"tenant_id"`
	Issuer         string         `json:"issuer"`
	Subject        string         `json:"subject"`
	ReceivedAt     time.Time      `json:"received_at"`
	BodySHA256     string         `json:"body_sha256"`
	IdempotencyKey string         `json:"idempotency_key"`
	Binding        model.Document `json:"binding"`
}

type ObjectStorageAccessSubmission struct {
	Interval                        ObjectStorageAccessInterval
	RawBody                         []byte
	Issuer, Subject, IdempotencyKey string
}

func ValidateObjectStorageAccessInterval(in ObjectStorageAccessInterval) error {
	if in.SchemaVersion != "1" || in.SourceID == "" || in.ResourceID == "" || in.DatasetID == "" || in.DatasetVersion < 1 || in.Sequence < 1 || in.MetricDefinition.ID == "" || in.MetricDefinition.Version == "" || in.MetricDefinition.Unit != ObjectStorageAccessUnit || !objectStorageAccessCount.MatchString(in.GetRequests) || !objectStorageAccessCount.MatchString(in.RetrievedBytes) {
		return ErrObjectStorageAccessSource
	}
	if in.IntervalEnd.Sub(in.IntervalStart) != time.Minute || in.IntervalStart.Second() != 0 || in.IntervalStart.Nanosecond() != 0 {
		return ErrObjectStorageAccessSource
	}
	if in.GetRequests == "0" && in.RetrievedBytes != "0" {
		return ErrObjectStorageAccessSource
	}
	_, left := in.IntervalStart.Zone()
	_, right := in.IntervalEnd.Zone()
	if left != 0 || right != 0 {
		return ErrObjectStorageAccessSource
	}
	return nil
}

func (t *Tx) ObjectStorageAccessSourceGet(ctx context.Context, id string) (ObjectStorageAccessSource, error) {
	var out ObjectStorageAccessSource
	var raw []byte
	err := t.QueryRow(ctx, `SELECT s.document||jsonb_build_object('enabled',r.source_id IS NULL,'version',CASE WHEN r.source_id IS NULL THEN 1 ELSE 2 END) FROM object_storage_access_sources s LEFT JOIN object_storage_access_revocations r ON r.tenant_id=s.tenant_id AND r.source_id=s.id WHERE s.tenant_id=$1 AND s.id=$2`, t.Tenant, id).Scan(&raw)
	if err == nil {
		err = json.Unmarshal(raw, &out)
	}
	return out, err
}

func (t *Tx) ObjectStorageAccessSourcePage(ctx context.Context, after, resource string, limit int) ([]model.Document, error) {
	if limit < 1 || limit > 101 {
		return nil, ErrConflict
	}
	return t.sourceRows(ctx, `SELECT s.document||jsonb_build_object('enabled',r.source_id IS NULL,'version',CASE WHEN r.source_id IS NULL THEN 1 ELSE 2 END) FROM object_storage_access_sources s LEFT JOIN object_storage_access_revocations r ON r.tenant_id=s.tenant_id AND r.source_id=s.id WHERE s.tenant_id=$1 AND s.id>$2 AND ($3='' OR s.resource_id=$3) ORDER BY s.id LIMIT $4`, t.Tenant, after, resource, limit)
}

func (t *Tx) ObjectStorageAccessRegister(ctx context.Context, in ObjectStorageAccessSource) (ObjectStorageAccessSource, error) {
	if in.ID == "" {
		in.ID = model.ID()
	}
	if in.ResourceID == "" || in.DatasetID == "" || in.DatasetVersion < 1 || !regexp.MustCompile(`^[0-9]{12}$`).MatchString(in.AccountID) || in.ProviderResourceID == "" || in.Region == "" || in.Issuer == "" || in.Subject == "" || len(in.Subject) > 2048 || in.MetricDefinition.ID == "" || in.MetricDefinition.Version == "" || in.MetricDefinition.Unit != ObjectStorageAccessUnit {
		return in, ErrObjectStorageAccessSource
	}
	in.Enabled, in.Version = true, 1
	raw, err := json.Marshal(in)
	if err != nil {
		return in, err
	}
	_, err = t.Exec(ctx, `INSERT INTO object_storage_access_sources(tenant_id,id,resource_id,dataset_id,dataset_version,issuer,subject,document) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, t.Tenant, in.ID, in.ResourceID, in.DatasetID, in.DatasetVersion, in.Issuer, in.Subject, raw)
	if err != nil {
		return in, err
	}
	return t.ObjectStorageAccessSourceGet(ctx, in.ID)
}

func (t *Tx) ObjectStorageAccessRevoke(ctx context.Context, id, actor string) (ObjectStorageAccessSource, error) {
	if actor == "" {
		return ObjectStorageAccessSource{}, ErrObjectStorageAccessSource
	}
	if _, err := t.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, t.Tenant+":object-access:"+id); err != nil {
		return ObjectStorageAccessSource{}, err
	}
	if _, err := t.Exec(ctx, `INSERT INTO object_storage_access_revocations(tenant_id,source_id,actor) VALUES($1,$2,$3) ON CONFLICT(tenant_id,source_id) DO NOTHING`, t.Tenant, id, actor); err != nil {
		return ObjectStorageAccessSource{}, err
	}
	return t.ObjectStorageAccessSourceGet(ctx, id)
}

func (t *Tx) ObjectStorageAccessAppend(ctx context.Context, submission ObjectStorageAccessSubmission) (ObjectStorageAccessReceipt, bool, error) {
	var receipt ObjectStorageAccessReceipt
	in := submission.Interval
	if err := ValidateObjectStorageAccessInterval(in); err != nil {
		return receipt, false, err
	}
	var decoded ObjectStorageAccessInterval
	if len(submission.RawBody) > 16<<10 || json.Unmarshal(submission.RawBody, &decoded) != nil {
		return receipt, false, ErrObjectStorageAccessSource
	}
	left, _ := json.Marshal(decoded)
	right, _ := json.Marshal(in)
	if !bytes.Equal(left, right) || submission.IdempotencyKey == "" || len(submission.IdempotencyKey) > 200 {
		return receipt, false, ErrObjectStorageAccessConflict
	}
	if _, err := t.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, t.Tenant+":object-access:"+in.SourceID); err != nil {
		return receipt, false, err
	}
	source, err := t.ObjectStorageAccessSourceGet(ctx, in.SourceID)
	if err != nil {
		return receipt, false, err
	}
	if !source.Enabled || source.Subject != submission.Subject || source.Issuer != submission.Issuer || source.ResourceID != in.ResourceID || source.DatasetID != in.DatasetID || source.DatasetVersion != in.DatasetVersion || source.MetricDefinition != in.MetricDefinition {
		return receipt, false, ErrObjectStorageAccessSource
	}
	var currentVersion int64
	if err = t.QueryRow(ctx, `SELECT max(version) FROM object_storage_datasets WHERE tenant_id=$1 AND id=$2 AND resource_id=$3`, t.Tenant, source.DatasetID, source.ResourceID).Scan(&currentVersion); err != nil || currentVersion != source.DatasetVersion {
		return receipt, false, ErrObjectStorageAccessSource
	}
	digest := sha256.Sum256(submission.RawBody)
	hash := hex.EncodeToString(digest[:])
	var raw []byte
	err = t.QueryRow(ctx, `SELECT document FROM object_storage_access_receipts WHERE tenant_id=$1 AND source_id=$2 AND (sequence=$3 OR interval_start=$4 OR idempotency_key=$5) ORDER BY sequence DESC LIMIT 1`, t.Tenant, in.SourceID, in.Sequence, in.IntervalStart, submission.IdempotencyKey).Scan(&raw)
	if err == nil {
		if err = json.Unmarshal(raw, &receipt); err != nil {
			return receipt, false, err
		}
		if receipt.BodySHA256 != hash || receipt.Sequence != in.Sequence || receipt.IdempotencyKey != submission.IdempotencyKey {
			return receipt, false, ErrObjectStorageAccessConflict
		}
		return receipt, true, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return receipt, false, err
	}
	var received time.Time
	if err = t.QueryRow(ctx, "SELECT activity_receive_time()").Scan(&received); err != nil {
		return receipt, false, err
	}
	if in.IntervalEnd.After(received.Add(5*time.Second)) || received.Sub(in.IntervalEnd) > 5*time.Minute {
		return receipt, false, ErrObjectStorageAccessConflict
	}
	var priorEnd time.Time
	var priorSequence int64
	err = t.QueryRow(ctx, `SELECT interval_end,sequence FROM object_storage_access_receipts WHERE tenant_id=$1 AND source_id=$2 ORDER BY sequence DESC LIMIT 1`, t.Tenant, in.SourceID).Scan(&priorEnd, &priorSequence)
	if err == nil && (in.Sequence <= priorSequence || in.IntervalStart.Before(priorEnd)) {
		return receipt, false, ErrObjectStorageAccessConflict
	}
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return receipt, false, err
	}
	receipt = ObjectStorageAccessReceipt{ObjectStorageAccessInterval: in, ID: model.ID(), TenantID: t.Tenant, Issuer: submission.Issuer, Subject: submission.Subject, ReceivedAt: received, BodySHA256: hash, IdempotencyKey: submission.IdempotencyKey,
		Binding: model.Document{"tenant_id": t.Tenant, "resource_id": source.ResourceID, "dataset_id": source.DatasetID, "dataset_version": source.DatasetVersion, "provider_resource_id": source.ProviderResourceID, "account_id": source.AccountID, "region": source.Region}}
	data, err := json.Marshal(receipt)
	if err != nil {
		return receipt, false, err
	}
	err = t.QueryRow(ctx, `INSERT INTO object_storage_access_receipts(tenant_id,id,source_id,resource_id,dataset_id,dataset_version,sequence,interval_start,interval_end,received_at,body_sha256,idempotency_key,document,raw_body) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) RETURNING document`, t.Tenant, receipt.ID, in.SourceID, in.ResourceID, in.DatasetID, in.DatasetVersion, in.Sequence, in.IntervalStart, in.IntervalEnd, received, hash, submission.IdempotencyKey, data, submission.RawBody).Scan(&raw)
	if err == nil {
		err = json.Unmarshal(raw, &receipt)
	}
	return receipt, false, err
}

// ObjectStorageAccessSummary streams at most366days of actual minute receipts.
// It never outputs a cold fraction or asserts instrumented scope independently.
func (t *Tx) ObjectStorageAccessSummary(ctx context.Context, sourceID, resourceID, datasetID string, datasetVersion int64, start, end time.Time) (model.Document, error) {
	if !end.After(start) || end.Sub(start) > 366*24*time.Hour || start.Second() != 0 || start.Nanosecond() != 0 || end.Second() != 0 || end.Nanosecond() != 0 {
		return nil, ErrObjectStorageAccessSource
	}
	source, err := t.ObjectStorageAccessSourceGet(ctx, sourceID)
	if err != nil {
		return nil, err
	}
	if source.ResourceID != resourceID || source.DatasetID != datasetID || source.DatasetVersion != datasetVersion {
		return nil, ErrObjectStorageAccessSource
	}
	rows, err := t.Query(ctx, `SELECT id,document,body_sha256 FROM object_storage_access_receipts WHERE tenant_id=$1 AND source_id=$2 AND resource_id=$3 AND dataset_id=$4 AND dataset_version=$5 AND interval_start >= $6 AND interval_end <= $7 ORDER BY interval_start`, t.Tenant, sourceID, resourceID, datasetID, datasetVersion, start, end)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	cursor, previousSequence := start, int64(0)
	count, complete := int64(0), source.Enabled && source.AuthoritativeAccessScope
	requests, retrieved := new(big.Int), new(big.Int)
	hasher := sha256.New()
	for rows.Next() {
		var id, hash string
		var raw []byte
		var receipt ObjectStorageAccessReceipt
		if err = rows.Scan(&id, &raw, &hash); err != nil {
			return nil, err
		}
		if err = json.Unmarshal(raw, &receipt); err != nil {
			return nil, err
		}
		if err = ValidateObjectStorageAccessInterval(receipt.ObjectStorageAccessInterval); err != nil {
			return nil, err
		}
		if !receipt.IntervalStart.Equal(cursor) || previousSequence != 0 && receipt.Sequence != previousSequence+1 || !receipt.Heartbeat || receipt.Subject != source.Subject || receipt.Issuer != source.Issuer || receipt.MetricDefinition != source.MetricDefinition {
			complete = false
		}
		q, _ := new(big.Int).SetString(receipt.GetRequests, 10)
		b, _ := new(big.Int).SetString(receipt.RetrievedBytes, 10)
		requests.Add(requests, q)
		retrieved.Add(retrieved, b)
		fmt.Fprintf(hasher, "%d:%s:%d:%s\n", len(id), id, len(hash), hash)
		cursor, previousSequence = receipt.IntervalEnd, receipt.Sequence
		count++
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	expected := int64(end.Sub(start) / time.Minute)
	complete = complete && cursor.Equal(end) && count == expected
	var totalRequests, totalBytes any
	if complete {
		totalRequests, totalBytes = requests.String(), retrieved.String()
	}
	out := model.Document{"source_id": sourceID, "resource_id": resourceID, "dataset_id": datasetID, "dataset_version": datasetVersion, "metric_definition": source.MetricDefinition,
		"start": start.UTC().Format(time.RFC3339), "end": end.UTC().Format(time.RFC3339), "expected_intervals": expected, "observed_intervals": count,
		"observed_get_requests": requests.String(), "observed_retrieved_bytes": retrieved.String(), "get_requests": totalRequests, "retrieved_bytes": totalBytes,
		"contiguous_scoped_window": complete, "authoritative_access_scope_declared": source.AuthoritativeAccessScope, "all_access_paths_independently_proven": false,
		"coverage_state": "INCOMPLETE_SCOPED_APPLICATION_WINDOW", "population_sha256": hex.EncodeToString(hasher.Sum(nil)), "eligible_cold_bytes_fraction": nil, "it_tier_fractions": nil,
		"source_ref": model.Document{"kind": "AUTHENTICATED_APPLICATION_S3_ACCESS", "id": sourceID + ":" + start.UTC().Format(time.RFC3339) + ":" + end.UTC().Format(time.RFC3339), "version": strconv.FormatInt(source.Version, 10), "sha256": hex.EncodeToString(hasher.Sum(nil))}}
	if complete {
		out["coverage_state"] = "COMPLETE_SCOPED_APPLICATION_WINDOW"
	}
	return out, nil
}
