package native

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/telemetry"
)

var safeKey = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)

type Storage struct {
	S3                                                             *s3.Client
	Bucket, Database, AnalyticsURL, AnalyticsUser, AnalyticsSecret string
	Client                                                         *http.Client
}

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
func StorageFromEnvironment(ctx context.Context, fixture bool) (*Storage, error) {
	region := env("OBJECT_REGION", "eu-west-1")
	if region != "eu-west-1" {
		return nil, errors.New("TELEMETRY_EU_STORAGE_REQUIRED")
	}
	opts := []func(*awsconfig.LoadOptions) error{awsconfig.WithRegion(region)}
	if key, secret := os.Getenv("OBJECT_ACCESS_KEY"), os.Getenv("OBJECT_SECRET_KEY"); key != "" || secret != "" {
		if key == "" || secret == "" {
			return nil, errors.New("TELEMETRY_STORAGE_IDENTITY_INCOMPLETE")
		}
		opts = append(opts, awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(key, secret, "")))
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, errors.New("TELEMETRY_STORAGE_IDENTITY_UNAVAILABLE")
	}
	endpoint := env("OBJECT_ENDPOINT", "https://s3.eu-west-1.amazonaws.com")
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || (u.Scheme != "https" && !(fixture && u.Scheme == "http")) {
		return nil, errors.New("TELEMETRY_STORAGE_ENDPOINT_INVALID")
	}
	client := &http.Client{Timeout: 35 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect refused") }}
	cfg.HTTPClient = client
	object := s3.NewFromConfig(cfg, func(o *s3.Options) { o.BaseEndpoint = aws.String(endpoint); o.UsePathStyle = true })
	bucket := os.Getenv("OBJECT_BUCKET_RAW")
	if !safeKey.MatchString(bucket) {
		return nil, errors.New("TELEMETRY_EVIDENCE_BUCKET_REQUIRED")
	}
	return &Storage{S3: object, Bucket: bucket, Database: env("CLICKHOUSE_DATABASE", "finops"), AnalyticsURL: os.Getenv("CLICKHOUSE_URL"), AnalyticsUser: env("CLICKHOUSE_USER", "finops"), AnalyticsSecret: os.Getenv("CLICKHOUSE_PASSWORD"), Client: client}, nil
}
func (s *Storage) Archive(ctx context.Context, tenant, kind, id string, raw []byte) (model.Document, error) {
	if !safeKey.MatchString(tenant) || !safeKey.MatchString(id) || (kind != "wire" && kind != "canonical") {
		return nil, errors.New("TELEMETRY_OBJECT_BINDING_INVALID")
	}
	digest := telemetry.BytesHash(raw)
	checksum := sha256.Sum256(raw)
	// The checksum is a transport integrity check; the immutable reference retains
	// the hex digest and exact S3 version separately from its content-addressed key.
	key := "tenant/" + tenant + "/native/" + id + "/" + kind + "/" + digest + ".bin"
	out, e := s.S3.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(s.Bucket), Key: aws.String(key), Body: bytes.NewReader(raw), ContentType: aws.String("application/octet-stream"), ChecksumSHA256: aws.String(base64.StdEncoding.EncodeToString(checksum[:]))})
	if e != nil {
		return nil, errors.New("TELEMETRY_OBJECT_WRITE_FAILED")
	}
	version := aws.ToString(out.VersionId)
	if version == "" || version == "null" {
		return nil, errors.New("TELEMETRY_VERSIONED_STORAGE_REQUIRED")
	}
	return model.Document{"bucket": s.Bucket, "key": key, "version_id": version, "body_sha256": digest}, nil
}
func (s *Storage) Read(ctx context.Context, tenant string, ref model.Document) ([]byte, error) {
	key := model.String(ref, "key")
	if !safeKey.MatchString(tenant) || model.String(ref, "bucket") != s.Bucket || !strings.HasPrefix(key, "tenant/"+tenant+"/native/") || strings.Contains(key, "..") || model.String(ref, "version_id") == "" {
		return nil, errors.New("TELEMETRY_OBJECT_SCOPE_DENIED")
	}
	out, err := s.S3.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(s.Bucket), Key: aws.String(key), VersionId: aws.String(model.String(ref, "version_id"))})
	if err != nil {
		return nil, errors.New("TELEMETRY_OBJECT_READ_FAILED")
	}
	defer out.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(out.Body, 128<<20+1))
	if err != nil || len(raw) > 128<<20 || telemetry.BytesHash(raw) != model.String(ref, "body_sha256") {
		return nil, errors.New("TELEMETRY_OBJECT_HASH_MISMATCH")
	}
	return raw, nil
}
func (s *Storage) WriteFacts(ctx context.Context, tenant, batchID string, b telemetry.Batch) (model.Document, error) {
	if tenant != b.Binding.TenantID || !safeKey.MatchString(s.Database) || !safeKey.MatchString(batchID) {
		return nil, errors.New("TELEMETRY_ANALYTICS_SCOPE_INVALID")
	}
	u, err := url.Parse(s.AnalyticsURL)
	if err != nil || u.Host == "" || u.User != nil {
		return nil, errors.New("TELEMETRY_ANALYTICS_ENDPOINT_REQUIRED")
	}
	q := u.Query()
	q.Set("database", s.Database)
	q.Set("query", "INSERT INTO native_metric_samples FORMAT JSONEachRow")
	q.Set("date_time_input_format", "best_effort")
	q.Set("insert_deduplicate", "1")
	q.Set("insert_deduplication_token", tenant+":"+batchID+":"+telemetry.CanonicalHash(b))
	u.RawQuery = q.Encode()
	canonicalHash := telemetry.CanonicalHash(b)
	var body bytes.Buffer
	enc := json.NewEncoder(&body)
	for _, sample := range b.Samples {
		payload, e := json.Marshal(sample)
		if e != nil {
			return nil, e
		}
		row := model.Document{"tenant_id": tenant, "batch_id": batchID, "connection_id": b.ConnectionID, "config_hash": b.ConfigHash, "canonical_hash": canonicalHash, "sample_id": sample.ID, "definition_id": sample.DefinitionID, "stream_id": sample.StreamID, "resource_id": b.Binding.ResourceID, "workload_id": b.Binding.WorkloadID, "provider": b.Binding.Provider, "account_id": b.Binding.AccountID, "region": b.Binding.Region, "metric": sample.Metric, "unit": sample.Unit, "statistic": sample.Statistic, "source_time": sample.Time, "raw_sha256": b.RawSHA256, "payload": string(payload)}
		if e = enc.Encode(row); e != nil {
			return nil, e
		}
	}
	if len(b.Samples) > 0 {
		req, e := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), &body)
		if e != nil {
			return nil, e
		}
		req.Header.Set("X-ClickHouse-User", s.AnalyticsUser)
		req.Header.Set("X-ClickHouse-Key", s.AnalyticsSecret)
		req.Header.Set("Content-Type", "application/x-ndjson")
		response, e := s.Client.Do(req)
		if e != nil {
			return nil, errors.New("TELEMETRY_ANALYTICS_WRITE_FAILED")
		}
		io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		response.Body.Close()
		if response.StatusCode != 200 {
			return nil, errors.New("TELEMETRY_ANALYTICS_WRITE_REJECTED")
		}
	}
	q.Set("query", "INSERT INTO native_metric_batches FORMAT JSONEachRow")
	q.Set("insert_deduplication_token", tenant+":"+batchID+":batch:"+canonicalHash)
	u.RawQuery = q.Encode()
	batchBody, _ := json.Marshal(model.Document{"tenant_id": tenant, "batch_id": batchID, "connection_id": b.ConnectionID, "config_hash": b.ConfigHash, "canonical_hash": canonicalHash, "sample_count": len(b.Samples), "raw_sha256": b.RawSHA256})
	req, e := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(batchBody))
	if e != nil {
		return nil, e
	}
	req.Header.Set("X-ClickHouse-User", s.AnalyticsUser)
	req.Header.Set("X-ClickHouse-Key", s.AnalyticsSecret)
	req.Header.Set("Content-Type", "application/x-ndjson")
	res, e := s.Client.Do(req)
	if e != nil {
		return nil, errors.New("TELEMETRY_ANALYTICS_MANIFEST_FAILED")
	}
	io.Copy(io.Discard, io.LimitReader(res.Body, 4096))
	res.Body.Close()
	if res.StatusCode != 200 {
		return nil, errors.New("TELEMETRY_ANALYTICS_MANIFEST_REJECTED")
	}
	return model.Document{"database": s.Database, "table": "native_metric_samples", "write_id": batchID, "canonical_hash": canonicalHash, "sample_count": len(b.Samples)}, nil
}
