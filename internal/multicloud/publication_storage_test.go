package multicloud

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/google/uuid"
)

func TestPublicationAnalyticsRedirectsAndChangedReadbackAreRejected(t *testing.T) {
	var leaked bool
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = true; w.WriteHeader(200) }))
	defer receiver.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, receiver.URL, http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()
	f := ClickHousePublicationFacts{Endpoint: redirect.URL, Database: "fixture", Table: "population", Fixture: true}
	reg, s := publicationFixture(t, GCPDetailed)
	_, _, facts, e := PublicationContent(reg, s)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.Write(context.Background(), facts); e == nil || leaked {
		t.Fatal("analytics redirected private payload/credentials")
	}
	f.Fixture = false
	if _, e = f.Write(context.Background(), facts); e == nil {
		t.Fatal("live analytics accepted HTTP")
	}
	f.Fixture = true
	f.Endpoint = receiver.URL
	f.Table = "population; DROP TABLE billing"
	if _, e = f.Write(context.Background(), facts); e == nil {
		t.Fatal("analytics SQL identifier injection")
	}
}

func TestPublicationRealPostgresVersionedMinIOAndClickHouse(t *testing.T) {
	if os.Getenv("TEST_MULTICLOUD_STORAGE") != "true" {
		t.Skip("explicit local storage acceptance only")
	}
	ctx := context.Background()
	pg := publicationPostgres(t)
	endpoint := os.Getenv("TEST_MULTICLOUD_S3_ENDPOINT")
	chEndpoint := os.Getenv("TEST_MULTICLOUD_CH_ENDPOINT")
	// This test never accepts cloud endpoints/credentials by accident. Its only
	// operations target the explicitly named local Compose fixture services.
	if endpoint != "http://minio:9000" || chEndpoint != "http://clickhouse:8123" {
		t.Fatal("storage acceptance requires exact isolated local Compose endpoints")
	}
	id := strings.ReplaceAll(uuid.NewString(), "-", "")
	bucket := "mc-publication-" + id
	table := "mc_publication_" + id
	owner := "acceptance-" + id
	t.Logf("Owned temporary storage bucket=%s table=finops.%s ownership=%s", bucket, table, owner)
	client := s3.NewFromConfig(aws.Config{Region: "eu-west-1", Credentials: credentials.NewStaticCredentialsProvider(os.Getenv("TEST_MULTICLOUD_S3_ACCESS_KEY"), os.Getenv("TEST_MULTICLOUD_S3_SECRET_KEY"), "")}, func(o *s3.Options) { o.BaseEndpoint = aws.String(endpoint); o.UsePathStyle = true })
	if _, e := client.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(bucket)}); e != nil {
		t.Fatal("owned local versioned fixture bucket creation failed")
	}
	tagged := false
	t.Cleanup(func() {
		tags, e := client.GetBucketTagging(ctx, &s3.GetBucketTaggingInput{Bucket: aws.String(bucket)})
		if e != nil || !tagged {
			t.Error("owned bucket cleanup stopped: ownership not established")
			return
		}
		owned := false
		for _, tag := range tags.TagSet {
			if aws.ToString(tag.Key) == "finops-local-acceptance-owner" && aws.ToString(tag.Value) == owner {
				owned = true
			}
		}
		if !owned {
			t.Error("owned bucket cleanup stopped: label mismatch")
			return
		}
		// Only this test-created, exact-label bucket is enumerated/deleted. Neither
		// shared raw/audit buckets nor unrelated object prefixes are touched.
		pages := s3.NewListObjectVersionsPaginator(client, &s3.ListObjectVersionsInput{Bucket: aws.String(bucket)})
		for pages.HasMorePages() {
			page, e := pages.NextPage(ctx)
			if e != nil {
				t.Error("owned bucket version cleanup failed")
				return
			}
			objects := []types.ObjectIdentifier{}
			for _, v := range page.Versions {
				objects = append(objects, types.ObjectIdentifier{Key: v.Key, VersionId: v.VersionId})
			}
			for _, v := range page.DeleteMarkers {
				objects = append(objects, types.ObjectIdentifier{Key: v.Key, VersionId: v.VersionId})
			}
			if len(objects) > 0 {
				out, e := client.DeleteObjects(ctx, &s3.DeleteObjectsInput{Bucket: aws.String(bucket), Delete: &types.Delete{Objects: objects, Quiet: aws.Bool(true)}})
				if e != nil || len(out.Errors) > 0 {
					t.Error("owned object cleanup failed")
					return
				}
			}
		}
		if _, e = client.DeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: aws.String(bucket)}); e != nil {
			t.Error("owned fixture bucket cleanup failed")
		}
	})
	if _, e := client.PutBucketTagging(ctx, &s3.PutBucketTaggingInput{Bucket: aws.String(bucket), Tagging: &types.Tagging{TagSet: []types.Tag{{Key: aws.String("finops-local-acceptance-owner"), Value: aws.String(owner)}}}}); e != nil {
		t.Fatal("owned local fixture bucket tagging failed")
	}
	tagged = true
	if _, e := client.PutBucketVersioning(ctx, &s3.PutBucketVersioningInput{Bucket: aws.String(bucket), VersioningConfiguration: &types.VersioningConfiguration{Status: types.BucketVersioningStatusEnabled}}); e != nil {
		t.Fatal("owned fixture versioning failed")
	}
	facts := &ClickHousePublicationFacts{Endpoint: chEndpoint, Database: "finops", Table: table, User: os.Getenv("TEST_MULTICLOUD_CH_USER"), Password: os.Getenv("TEST_MULTICLOUD_CH_PASSWORD"), Fixture: true}
	ddl := "CREATE TABLE finops." + table + " (tenant_id String,population_id String,fact_hash String,economic_hash String,distinct_rows UInt64,record_count UInt64,payload String) ENGINE=ReplacingMergeTree ORDER BY (tenant_id,population_id) COMMENT '" + owner + "'"
	if _, e := facts.request(ctx, ddl, nil); e != nil {
		t.Fatal("owned local analytics table creation failed")
	}
	t.Cleanup(func() {
		raw, e := facts.request(ctx, "SELECT comment FROM system.tables WHERE database='finops' AND name='"+table+"' FORMAT JSONEachRow", nil)
		var metadata struct {
			Comment string `json:"comment"`
		}
		if e != nil || json.Unmarshal(bytes.TrimSpace(raw), &metadata) != nil || metadata.Comment != owner {
			t.Error("owned table cleanup stopped: ownership mismatch")
			return
		}
		if _, e = facts.request(ctx, "DROP TABLE finops."+table+" SYNC", nil); e != nil {
			t.Error("owned analytics fixture cleanup failed")
		}
	})
	reg, s := publicationFixture(t, GCPDetailed)
	if e := pg.repo.Register(ctx, reg); e != nil {
		t.Fatal(e)
	}
	archive := &S3PublicationArchive{Client: client, Bucket: bucket}
	pipeline := PublicationPipeline{Repository: pg.repo, Archive: archive, Facts: facts}
	receipt, replay, e := pipeline.Publish(ctx, reg, s, "provider-query-observation-1")
	if e != nil {
		t.Fatal(e)
	}
	if replay || receipt.ExecutionAuthorized || receipt.VerifiedSaving != nil || !receipt.IsCurrent || receipt.Manifest.Status != "PROVISIONAL" {
		t.Fatal("invalid real publication receipt")
	}
	stages, e := pg.repo.Checkpoints(ctx, reg.Registration.TenantID, receipt.JobID)
	if e != nil || len(stages) != 3 {
		t.Fatal("real publication missing ordered checkpoints", e)
	}
	var rawStage PublicationCheckpoint
	for _, stage := range stages {
		if stage.Stage == "RAW_ARCHIVED" {
			rawStage = stage
		}
	}
	if len(rawStage.Raw) != len(s.Objects) {
		t.Fatal("not all exact raw provider objects archived")
	}
	for i, ref := range rawStage.Raw {
		body, e := archive.Read(ctx, reg.Registration.TenantID, ref)
		if e != nil || !bytes.Equal(body, s.Objects[i].Body) {
			t.Fatal("exact provider body/version readback failed", e)
		}
	}
	if _, e = archive.Read(ctx, "tenant-other", rawStage.Raw[0]); e == nil {
		t.Fatal("cross-tenant raw read accepted")
	}
	// Overwriting a key creates a new version; replay MUST pin the original.
	ref := rawStage.Raw[0]
	if _, e = client.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(bucket), Key: aws.String(ref.Key), Body: strings.NewReader("unrelated latest version")}); e != nil {
		t.Fatal("owned version test write failed")
	}
	if _, _, e = pipeline.Publish(ctx, reg, s, "provider-query-observation-1"); e != nil {
		t.Fatal("replay read latest instead of pinned version", e)
	}
	second, _, e := pipeline.Publish(ctx, reg, s, "provider-query-observation-2")
	if e != nil {
		t.Fatal(e)
	}
	if second.Manifest.EconomicHash != receipt.Manifest.EconomicHash || second.Manifest.PopulationID != receipt.Manifest.PopulationID {
		t.Fatal("repeat query changed economic multiset")
	}
	raw, e := facts.request(ctx, "SELECT count() AS populations FROM finops."+table+" FINAL FORMAT JSONEachRow", nil)
	populationCount, decodeErr := decode(bytes.TrimSpace(raw))
	if e != nil || decodeErr != nil || fmt.Sprint(populationCount["populations"]) != "1" {
		t.Fatal("repeated native query appended extra current spend", e)
	}
	history, e := pg.repo.Receipts(ctx, reg.Registration.TenantID, reg.Registration.ID)
	if e != nil || len(history) != 2 || history[0].IsCurrent || !history[1].IsCurrent {
		t.Fatal("real current observation projection invalid", e)
	}
	// A changed warehouse body cannot be disguised as successful persistence.
	_, e = facts.request(ctx, "ALTER TABLE finops."+table+" UPDATE payload='{}' WHERE population_id='"+receipt.Manifest.PopulationID+"' SETTINGS mutations_sync=2", nil)
	if e != nil {
		t.Fatal("owned analytics tamper fixture failed")
	}
	_, _, e = pipeline.Publish(ctx, reg, s, "provider-query-observation-2")
	if e == nil {
		t.Fatal("replayed changed analytics payload")
	}
	history, e = pg.repo.Receipts(ctx, reg.Registration.TenantID, reg.Registration.ID)
	if e != nil || len(history) != 2 {
		t.Fatal("tamper rewrote immutable receipt history", e)
	}
	t.Log("Actual local acceptance: restricted PostgreSQL role + exact versioned MinIO readback + ClickHouse population + replay + current-head projection + tamper failure; no cloud calls or financial/execution authority.")
}

// Keep HTTP failure messages generic: service response bodies can contain
// native billing rows or endpoint credentials and are never returned in errors.
func TestPublicationAnalyticsErrorsNeverReturnResponseBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
		io.WriteString(w, "private-native-billing-secret")
	}))
	defer server.Close()
	f := ClickHousePublicationFacts{Endpoint: server.URL, Database: "fixture", Table: "population", Fixture: true}
	_, e := f.request(context.Background(), "SELECT 1", nil)
	if e == nil || strings.Contains(e.Error(), "private-native-billing-secret") {
		t.Fatal("private analytics error body escaped")
	}
}
