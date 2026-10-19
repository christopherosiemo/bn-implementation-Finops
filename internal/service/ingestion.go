package service

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
)

var tenantKey = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)

func evidenceHash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

// ArchiveSourceObject preserves exact native bytes before authenticated receipt
// publication. Product evidence keys and storage remain in the Ireland cell.
func ArchiveSourceObject(ctx context.Context, tenant, source, key string, b []byte) error {
	return putEvidence(ctx, tenant, "raw", source+":"+key, b)
}

func (a *API) NormalizeTrustedSource(ctx context.Context, raw model.Document) (model.Document, error) {
	return a.economics(ctx, "v3/normalize", raw)
}

// putEvidence uses a content-addressed, tenant-qualified key. The raw/audit bucket
// policies and Object Lock, not application DELETE conventions, protect history.
func putEvidence(ctx context.Context, tenant, kind, id string, b []byte) error {
	if !tenantKey.MatchString(tenant) {
		return errors.New("invalid tenant storage identity")
	}
	region := env("OBJECT_REGION", env("AWS_REGION", "eu-west-1"))
	bucket := os.Getenv("OBJECT_BUCKET_RAW")
	access, secret := os.Getenv("OBJECT_ACCESS_KEY"), os.Getenv("OBJECT_SECRET_KEY")
	if kind == "audit" {
		bucket = os.Getenv("OBJECT_BUCKET_AUDIT")
		access, secret = os.Getenv("AUDIT_ACCESS_KEY"), os.Getenv("AUDIT_SECRET_KEY")
	}
	if bucket == "" {
		return errors.New("evidence bucket is required")
	}
	endpoint := env("OBJECT_ENDPOINT", "https://s3."+region+".amazonaws.com")
	parsed, e := url.Parse(endpoint)
	if e != nil || parsed.Host == "" || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.User != nil {
		return errors.New("invalid object endpoint")
	}
	key := "tenant/" + tenant + "/" + kind + "/" + evidenceHash([]byte(id)) + "/" + evidenceHash(b) + ".json"
	parsed.Path = strings.TrimSuffix(parsed.Path, "/") + "/" + bucket + "/" + key
	req, e := http.NewRequestWithContext(ctx, http.MethodPut, parsed.String(), bytes.NewReader(b))
	if e != nil {
		return e
	}
	req.Header.Set("Content-Type", "application/json")
	// S3 Object Lock requires a payload checksum. MD5 is used only as the
	// transport integrity checksum; authentication remains SigV4 SHA-256.
	checksum := md5.Sum(b)
	req.Header.Set("Content-MD5", base64.StdEncoding.EncodeToString(checksum[:]))
	req.Header.Set("X-Amz-Content-Sha256", evidenceHash(b))
	var creds aws.Credentials
	if access != "" && secret != "" {
		creds = aws.Credentials{AccessKeyID: access, SecretAccessKey: secret, Source: "scoped-evidence"}
	} else {
		cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
		if err != nil {
			return errors.New("evidence workload identity unavailable")
		}
		creds, e = cfg.Credentials.Retrieve(ctx)
		if e != nil {
			return errors.New("evidence workload identity unavailable")
		}
	}
	if e = v4.NewSigner().SignHTTP(ctx, creds, req, evidenceHash(b), "s3", region, time.Now().UTC()); e != nil {
		return errors.New("cannot sign evidence request")
	}
	resp, e := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if e != nil {
		return errors.New("object evidence storage unavailable")
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("object evidence storage rejected request (%d)", resp.StatusCode)
	}
	return nil
}

func clickhouseRows(ctx context.Context, table string, rows []model.Document) error {
	if len(rows) == 0 {
		return nil
	}
	endpoint := os.Getenv("CLICKHOUSE_URL")
	if endpoint == "" {
		return errors.New("analytics endpoint required")
	}
	parsed, e := url.Parse(endpoint)
	if e != nil || parsed.Host == "" || parsed.User != nil {
		return errors.New("invalid analytics endpoint")
	}
	query := parsed.Query()
	query.Set("database", env("CLICKHOUSE_DATABASE", "finops"))
	query.Set("query", "INSERT INTO "+table+" FORMAT JSONEachRow")
	query.Set("date_time_input_format", "best_effort")
	parsed.RawQuery = query.Encode()
	var body bytes.Buffer
	encoder := json.NewEncoder(&body)
	for _, row := range rows {
		if e = encoder.Encode(row); e != nil {
			return e
		}
	}
	query.Set("insert_deduplicate", "1")
	query.Set("insert_deduplication_token", evidenceHash(body.Bytes()))
	parsed.RawQuery = query.Encode()
	req, e := http.NewRequestWithContext(ctx, http.MethodPost, parsed.String(), &body)
	if e != nil {
		return e
	}
	req.Header.Set("X-ClickHouse-User", env("CLICKHOUSE_USER", "finops"))
	req.Header.Set("X-ClickHouse-Key", os.Getenv("CLICKHOUSE_PASSWORD"))
	req.Header.Set("Content-Type", "application/x-ndjson")
	resp, e := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if e != nil {
		return errors.New("analytics storage unavailable")
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != 200 {
		return fmt.Errorf("analytics storage rejected facts (%d)", resp.StatusCode)
	}
	return nil
}

func documentList(value any) []model.Document {
	var result []model.Document
	switch rows := value.(type) {
	case []model.Document:
		return rows
	case []any:
		for _, v := range rows {
			switch d := v.(type) {
			case map[string]any:
				result = append(result, model.Document(d))
			case model.Document:
				result = append(result, d)
			}
		}
	}
	return result
}

// PersistEvidence persists raw source bytes before canonical facts. A failure is
// retried by the durable ingestion/outbox activity; it must never mark a source
// fully processed until both writes succeed.
func PersistEvidence(ctx context.Context, tenant, source string, raw, canonical model.Document) error {
	if !tenantKey.MatchString(tenant) || source == "" {
		return errors.New("tenant and source identity required")
	}
	body, e := json.Marshal(raw)
	if e != nil {
		return e
	}
	if e = putEvidence(ctx, tenant, "raw", source, body); e != nil {
		return e
	}
	if e = persistBillingFacts(ctx, tenant, source, canonical); e != nil {
		return e
	}
	metrics := []model.Document{}
	for _, r := range documentList(canonical["metric_facts"]) {
		value, ok := new(big.Rat).SetString(model.String(r, "value"))
		if !ok {
			return errors.New("invalid exact metric value")
		}
		at := model.String(r, "source_time")
		if _, e = time.Parse(time.RFC3339Nano, at); e != nil {
			return errors.New("invalid metric timestamp")
		}
		metrics = append(metrics, model.Document{"tenant_id": tenant, "resource_id": model.String(r, "resource_id"), "metric_name": model.String(r, "metric_name"), "source_time": at, "value": value.FloatString(12)})
	}
	return clickhouseRows(ctx, "metric_facts", metrics)
}

// ArchiveAudit cannot update the transactional append-only log. It adds a WORM
// object copy, using the dedicated audit writer identity.
func ArchiveAudit(ctx context.Context, tenant string, events []model.Document) error {
	for _, event := range events {
		if model.String(event, "id") == "" {
			return errors.New("audit event identity missing")
		}
		b, e := json.Marshal(event)
		if e != nil {
			return e
		}
		if e = putEvidence(ctx, tenant, "audit", model.String(event, "id"), b); e != nil {
			return e
		}
	}
	return nil
}
