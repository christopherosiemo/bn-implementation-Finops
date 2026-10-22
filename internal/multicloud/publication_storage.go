package multicloud

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

var warehouseIdentifier = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,62}$`)
var publicationReason = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,99}$`)

type PublicationS3 interface {
	PutObject(context.Context, *s3.PutObjectInput, ...func(*s3.Options)) (*s3.PutObjectOutput, error)
	GetObject(context.Context, *s3.GetObjectInput, ...func(*s3.Options)) (*s3.GetObjectOutput, error)
}

// S3PublicationArchive requires bucket versioning. The caller supplies the
// private, scoped SDK client; there is no environment credential fallback here.
type S3PublicationArchive struct {
	Client PublicationS3
	Bucket string
}

func (a *S3PublicationArchive) Put(ctx context.Context, tenant, job, kind string, raw []byte) (ArchiveRef, error) {
	if a.Client == nil || !safeID.MatchString(a.Bucket) || !safeID.MatchString(tenant) || !safeID.MatchString(job) || !safeID.MatchString(kind) || len(raw) == 0 || len(raw) > MaxCollectionBytes {
		return ArchiveRef{}, errors.New("MULTICLOUD_ARCHIVE_INPUT_INVALID")
	}
	hash := BytesHash(raw)
	digest, _ := hex.DecodeString(hash)
	key := "tenant/" + tenant + "/multicloud/" + job + "/" + kind + "/" + hash + ".bin"
	out, e := a.Client.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(a.Bucket), Key: aws.String(key), Body: bytes.NewReader(raw), ContentLength: aws.Int64(int64(len(raw))), ContentType: aws.String("application/octet-stream"), ChecksumAlgorithm: types.ChecksumAlgorithmSha256, ChecksumSHA256: aws.String(base64.StdEncoding.EncodeToString(digest))})
	if e != nil {
		return ArchiveRef{}, errors.New("MULTICLOUD_ARCHIVE_WRITE_FAILED")
	}
	if out == nil || aws.ToString(out.VersionId) == "" || aws.ToString(out.VersionId) == "null" {
		return ArchiveRef{}, errors.New("MULTICLOUD_ARCHIVE_VERSION_REQUIRED")
	}
	return ArchiveRef{Bucket: a.Bucket, Key: key, VersionID: aws.ToString(out.VersionId), SHA256: hash, Bytes: int64(len(raw))}, nil
}
func (a *S3PublicationArchive) Read(ctx context.Context, tenant string, ref ArchiveRef) ([]byte, error) {
	if a.Client == nil || ref.Bucket != a.Bucket || !safeID.MatchString(tenant) || !strings.HasPrefix(ref.Key, "tenant/"+tenant+"/multicloud/") || strings.Contains(ref.Key, "..") || strings.ContainsAny(ref.Key, "\\\x00\r\n") || ref.VersionID == "" || ref.VersionID == "null" || !publicationSHA.MatchString(ref.SHA256) || ref.Bytes < 1 || ref.Bytes > MaxCollectionBytes {
		return nil, errors.New("MULTICLOUD_ARCHIVE_REFERENCE_INVALID")
	}
	out, e := a.Client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(a.Bucket), Key: aws.String(ref.Key), VersionId: aws.String(ref.VersionID)})
	if e != nil || out == nil || out.Body == nil {
		return nil, errors.New("MULTICLOUD_ARCHIVE_READ_FAILED")
	}
	defer out.Body.Close()
	if aws.ToString(out.VersionId) != ref.VersionID || aws.ToInt64(out.ContentLength) != ref.Bytes {
		return nil, errors.New("MULTICLOUD_ARCHIVE_VERSION_CHANGED")
	}
	raw, e := io.ReadAll(io.LimitReader(out.Body, ref.Bytes+1))
	if e != nil || int64(len(raw)) != ref.Bytes || BytesHash(raw) != ref.SHA256 {
		return nil, errors.New("MULTICLOUD_ARCHIVE_READBACK_CHANGED")
	}
	return raw, nil
}

// ClickHousePublicationFacts stores a content-addressed population, rather than
// appending every repeated poll as extra spend. FINAL selects one population
// head under concurrent retries. The table is observational and has no joins to
// the application's savings ledger. Native money remains exact JSON text.
type ClickHousePublicationFacts struct {
	HTTP                                      *http.Client
	Endpoint, Database, Table, User, Password string
	Fixture                                   bool
}

func (f *ClickHousePublicationFacts) request(ctx context.Context, query string, body []byte) ([]byte, error) {
	u, e := url.Parse(f.Endpoint)
	if e != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Hostname() == "" || u.Path != "" && u.Path != "/" || (!f.Fixture && u.Scheme != "https") || f.Fixture && u.Scheme != "http" && u.Scheme != "https" || !warehouseIdentifier.MatchString(f.Database) || !warehouseIdentifier.MatchString(f.Table) {
		return nil, errors.New("MULTICLOUD_ANALYTICS_CONFIGURATION_INVALID")
	}
	q := url.Values{"query": {query}, "wait_end_of_query": {"1"}, "max_execution_time": {"30"}, "max_result_bytes": {"134217728"}}
	u.RawQuery = q.Encode()
	req, e := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(body))
	if e != nil {
		return nil, e
	}
	req.Header.Set("X-ClickHouse-User", f.User)
	req.Header.Set("X-ClickHouse-Key", f.Password)
	req.Header.Set("Content-Type", "application/octet-stream")
	client := http.Client{Timeout: 45 * time.Second}
	if f.HTTP != nil {
		client = *f.HTTP
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, e := client.Do(req)
	if e != nil {
		return nil, errors.New("MULTICLOUD_ANALYTICS_TRANSPORT_FAILED")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, errors.New("MULTICLOUD_ANALYTICS_REQUEST_FAILED")
	}
	raw, e := io.ReadAll(io.LimitReader(resp.Body, MaxCollectionBytes+1))
	if e != nil || len(raw) > MaxCollectionBytes {
		return nil, errors.New("MULTICLOUD_ANALYTICS_READ_LIMIT")
	}
	return raw, nil
}
func factsAck(facts FactPopulation, database, table string) FactAck {
	hash := Hash(facts)
	return FactAck{TenantID: facts.TenantID, PopulationID: "mc-pop-" + hash, FactHash: hash, EconomicHash: facts.EconomicHash, DistinctRows: int64(len(facts.Rows)), RecordCount: facts.RecordCount, Database: database, Table: table}
}
func (f *ClickHousePublicationFacts) population(ctx context.Context, ack FactAck) (FactPopulation, bool, error) {
	if !safeID.MatchString(ack.TenantID) || !publicationSHA.MatchString(ack.FactHash) || ack.PopulationID != "mc-pop-"+ack.FactHash || ack.Database != f.Database || ack.Table != f.Table {
		return FactPopulation{}, false, errors.New("MULTICLOUD_ANALYTICS_REFERENCE_INVALID")
	}
	// PopulationID is a fixed prefix and validated hex, never arbitrary SQL.
	raw, e := f.request(ctx, fmt.Sprintf("SELECT tenant_id,population_id,fact_hash,economic_hash,distinct_rows,record_count,payload FROM %s.%s FINAL WHERE tenant_id='%s' AND population_id='%s' FORMAT JSONEachRow", f.Database, f.Table, ack.TenantID, ack.PopulationID), nil)
	if e != nil {
		return FactPopulation{}, false, e
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return FactPopulation{}, false, nil
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	var row struct {
		TenantID     string      `json:"tenant_id"`
		PopulationID string      `json:"population_id"`
		FactHash     string      `json:"fact_hash"`
		EconomicHash string      `json:"economic_hash"`
		DistinctRows json.Number `json:"distinct_rows"`
		RecordCount  json.Number `json:"record_count"`
		Payload      string      `json:"payload"`
	}
	if e = decoder.Decode(&row); e != nil {
		return FactPopulation{}, false, errors.New("MULTICLOUD_ANALYTICS_READBACK_INVALID")
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return FactPopulation{}, false, errors.New("MULTICLOUD_ANALYTICS_POPULATION_AMBIGUOUS")
	}
	if BytesHash([]byte(row.Payload)) != ack.FactHash {
		return FactPopulation{}, false, errors.New("MULTICLOUD_ANALYTICS_READBACK_CHANGED")
	}
	distinct, eDistinct := row.DistinctRows.Int64()
	records, eRecords := row.RecordCount.Int64()
	if row.TenantID != ack.TenantID || row.PopulationID != ack.PopulationID || row.FactHash != ack.FactHash || row.EconomicHash != ack.EconomicHash || eDistinct != nil || eRecords != nil || distinct != ack.DistinctRows || records != ack.RecordCount {
		return FactPopulation{}, false, errors.New("MULTICLOUD_ANALYTICS_SCOPE_CHANGED")
	}
	var facts FactPopulation
	// Native provider numeric lexemes are evidence. Decoding a dynamic native
	// field through float64 would change e.g. 0.10000000000000001 to 0.1.
	content := json.NewDecoder(strings.NewReader(row.Payload))
	content.UseNumber()
	if e = content.Decode(&facts); e != nil || facts.TenantID != ack.TenantID || Hash(facts) != ack.FactHash || facts.EconomicHash != ack.EconomicHash || facts.RecordCount != ack.RecordCount || int64(len(facts.Rows)) != ack.DistinctRows {
		return FactPopulation{}, false, errors.New("MULTICLOUD_ANALYTICS_READBACK_CHANGED")
	}
	return facts, true, nil
}
func (f *ClickHousePublicationFacts) Write(ctx context.Context, facts FactPopulation) (FactAck, error) {
	ack := factsAck(facts, f.Database, f.Table)
	if _, exists, e := f.population(ctx, ack); e != nil {
		return FactAck{}, e
	} else if exists {
		return ack, nil
	}
	payload, e := json.Marshal(facts)
	if e != nil || len(payload) > MaxCollectionBytes {
		return FactAck{}, errors.New("MULTICLOUD_FACT_LIMIT")
	}
	row, e := json.Marshal(Document{"tenant_id": facts.TenantID, "population_id": ack.PopulationID, "fact_hash": ack.FactHash, "economic_hash": ack.EconomicHash, "distinct_rows": ack.DistinctRows, "record_count": ack.RecordCount, "payload": string(payload)})
	if e != nil {
		return FactAck{}, e
	}
	_, e = f.request(ctx, fmt.Sprintf("INSERT INTO %s.%s SETTINGS insert_deduplication_token='%s' FORMAT JSONEachRow", f.Database, f.Table, ack.FactHash), append(row, '\n'))
	if e != nil {
		return FactAck{}, e
	}
	return ack, nil
}
func (f *ClickHousePublicationFacts) Readback(ctx context.Context, ack FactAck) (FactAck, error) {
	_, exists, e := f.population(ctx, ack)
	if e != nil {
		return FactAck{}, e
	}
	if !exists {
		return FactAck{}, errors.New("MULTICLOUD_ANALYTICS_NOT_PERSISTED")
	}
	return ack, nil
}
