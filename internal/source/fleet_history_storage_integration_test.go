package source

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// This acceptance uses actual isolated PostgreSQL and versioned MinIO. The AWS
// DescribeAutoScalingGroups transport remains an explicitly labelled double;
// no cloud call, historical ownership, encryption or financial claim is made.
func TestFleetHistoryActualPostgresVersionedMinIOReplayAndRevocation(t *testing.T) {
	adminURL := os.Getenv("TEST_FLEET_HISTORY_ADMIN_URL")
	if adminURL == "" {
		t.Skip("explicit owned local PostgreSQL/MinIO acceptance required")
	}
	u, err := url.Parse(adminURL)
	if err != nil || u.Scheme != "postgres" || u.Host != "postgres:5432" || u.Path != "/postgres" || u.Query().Get("sslmode") != "disable" || os.Getenv("TEST_FLEET_HISTORY_S3_ENDPOINT") != "http://minio:9000" {
		t.Fatal("only the dedicated local fixture endpoints are accepted")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	master, err := pgxpool.New(ctx, adminURL)
	if err != nil {
		t.Fatal("owned PostgreSQL unavailable")
	}
	suffix := strings.ReplaceAll(model.ID(), "-", "")
	database, login := "history_storage_"+suffix, "history_writer_"+suffix
	owner := "finops-fleet-history-storage:" + suffix
	if _, err = master.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{database}.Sanitize()); err != nil {
		master.Close()
		t.Fatal("owned database creation failed")
	}
	var admin *store.Store
	var writers []*store.Store
	loginCreated := false
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		for _, writer := range writers {
			writer.Pool.Close()
		}
		if admin != nil {
			admin.Pool.Close()
		}
		var actual string
		if err := master.QueryRow(cleanup, "SELECT coalesce(shobj_description(oid,'pg_database'),'') FROM pg_database WHERE datname=$1", database).Scan(&actual); err != nil || actual != owner {
			t.Error("owned history database cleanup refused")
		} else if _, err = master.Exec(cleanup, "DROP DATABASE "+pgx.Identifier{database}.Sanitize()); err != nil {
			t.Error("owned history database cleanup failed")
		}
		if loginCreated {
			if err := master.QueryRow(cleanup, "SELECT coalesce(shobj_description(oid,'pg_authid'),'') FROM pg_roles WHERE rolname=$1", login).Scan(&actual); err != nil || actual != owner {
				t.Error("owned history login cleanup refused")
			} else if _, err = master.Exec(cleanup, "DROP ROLE "+pgx.Identifier{login}.Sanitize()); err != nil {
				t.Error("owned history login cleanup failed")
			}
		}
		master.Close()
	})
	if _, err = master.Exec(ctx, "COMMENT ON DATABASE "+pgx.Identifier{database}.Sanitize()+" IS '"+owner+"'"); err != nil {
		t.Fatal("owned database marker failed")
	}
	u.Path = "/" + database
	admin, err = store.Open(ctx, u.String())
	if err != nil {
		t.Fatal("owned database open failed")
	}
	if err = admin.Migrate(ctx, "../../migrations"); err != nil {
		t.Fatal("snapshot migration failed", err)
	}
	secret := make([]byte, 32)
	if _, err = rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	password := hex.EncodeToString(secret)
	if _, err = master.Exec(ctx, "CREATE ROLE "+pgx.Identifier{login}.Sanitize()+" LOGIN PASSWORD '"+password+"' IN ROLE finops_ingester"); err != nil {
		t.Fatal("owned restricted login creation failed")
	}
	loginCreated = true
	if _, err = master.Exec(ctx, "COMMENT ON ROLE "+pgx.Identifier{login}.Sanitize()+" IS '"+owner+"'"); err != nil {
		t.Fatal("owned login marker failed")
	}
	u.User = url.UserPassword(login, password)
	openWriter := func() *store.Store {
		t.Helper()
		cfg, err := pgxpool.ParseConfig(u.String())
		if err != nil {
			t.Fatal("restricted writer configuration failed")
		}
		cfg.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
			_, err := conn.Exec(ctx, "SET ROLE finops_ingester")
			return err
		}
		pool, err := pgxpool.NewWithConfig(ctx, cfg)
		if err != nil {
			t.Fatal("restricted writer connection failed")
		}
		var current, session string
		var super bool
		if err = pool.QueryRow(ctx, "SELECT current_user,session_user,(SELECT rolsuper FROM pg_roles WHERE rolname=session_user)").Scan(&current, &session, &super); err != nil || current != "finops_ingester" || session != login || super {
			pool.Close()
			t.Fatal("actual restricted process identity changed")
		}
		writer := &store.Store{Pool: pool}
		writers = append(writers, writer)
		return writer
	}
	writer := openWriter()
	client := s3.NewFromConfig(aws.Config{Region: "eu-west-1", Credentials: credentials.NewStaticCredentialsProvider(os.Getenv("TEST_FLEET_HISTORY_S3_ACCESS_KEY"), os.Getenv("TEST_FLEET_HISTORY_S3_SECRET_KEY"), "")}, func(o *s3.Options) {
		o.BaseEndpoint = aws.String("http://minio:9000")
		o.UsePathStyle = true
	})
	bucket := "history-acceptance-" + suffix
	if _, err = client.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(bucket)}); err != nil {
		t.Fatal("owned MinIO bucket creation failed")
	}
	tagged := false
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		tags, err := client.GetBucketTagging(cleanup, &s3.GetBucketTaggingInput{Bucket: aws.String(bucket)})
		owned := false
		if err == nil && tagged {
			for _, tag := range tags.TagSet {
				owned = owned || aws.ToString(tag.Key) == "finops-history-owner" && aws.ToString(tag.Value) == owner
			}
		}
		if !owned {
			t.Error("owned history bucket cleanup refused")
			return
		}
		pages := s3.NewListObjectVersionsPaginator(client, &s3.ListObjectVersionsInput{Bucket: aws.String(bucket)})
		for pages.HasMorePages() {
			page, err := pages.NextPage(cleanup)
			if err != nil || len(page.Versions)+len(page.DeleteMarkers) > 1000 {
				t.Error("owned history version enumeration failed")
				return
			}
			objects := []types.ObjectIdentifier{}
			for _, version := range page.Versions {
				objects = append(objects, types.ObjectIdentifier{Key: version.Key, VersionId: version.VersionId})
			}
			for _, version := range page.DeleteMarkers {
				objects = append(objects, types.ObjectIdentifier{Key: version.Key, VersionId: version.VersionId})
			}
			if len(objects) > 0 {
				out, err := client.DeleteObjects(cleanup, &s3.DeleteObjectsInput{Bucket: aws.String(bucket), Delete: &types.Delete{Objects: objects, Quiet: aws.Bool(true)}})
				if err != nil || len(out.Errors) != 0 {
					t.Error("owned history version cleanup failed")
					return
				}
			}
		}
		if _, err = client.DeleteBucket(cleanup, &s3.DeleteBucketInput{Bucket: aws.String(bucket)}); err != nil {
			t.Error("owned history bucket cleanup failed")
		}
	})
	if _, err = client.PutBucketTagging(ctx, &s3.PutBucketTaggingInput{Bucket: aws.String(bucket), Tagging: &types.Tagging{TagSet: []types.Tag{{Key: aws.String("finops-history-owner"), Value: aws.String(owner)}}}}); err != nil {
		t.Fatal("owned MinIO bucket marker failed")
	}
	tagged = true
	if _, err = client.PutBucketVersioning(ctx, &s3.PutBucketVersioningInput{Bucket: aws.String(bucket), VersioningConfiguration: &types.VersioningConfiguration{Status: types.BucketVersioningStatusEnabled}}); err != nil {
		t.Fatal("owned MinIO versioning failed")
	}
	versioning, err := client.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{Bucket: aws.String(bucket)})
	if err != nil || versioning.Status != types.BucketVersioningStatusEnabled {
		t.Fatal("actual MinIO versioning was not enabled")
	}
	for _, mode := range []string{"success and process replay", "readback unavailable", "wrong returned version", "process loss before publication", "source revoked after archive"} {
		t.Run(mode, func(t *testing.T) {
			tenant := "history-storage-" + model.ID()
			registration, native := historyNativeFixture(t, time.Now().UTC())
			registration.Binding.TenantID = tenant
			src := FixtureRegistration(tenant, registration.SourceID)
			registration.SourceConfigHash = ConfigurationHash(src)
			if err := admin.Do(ctx, tenant, func(tx *store.Tx) error {
				if _, err := tx.Exec(ctx, "SET LOCAL ROLE finops_api"); err != nil {
					return err
				}
				if _, err := tx.Create(ctx, "workloads", model.Document{"id": registration.Binding.WorkloadID, "name": "Native transport double / real archive acceptance"}); err != nil {
					return err
				}
				if _, err := tx.SourceCreate(ctx, src); err != nil {
					return err
				}
				_, err := tx.FleetHistoryRegistrationAppend(ctx, 0, registration)
				return err
			}); err != nil {
				t.Fatal("private fixture registration failed", err)
			}
			sdk := &historyStorageS3{Client: client, Mode: mode}
			archive := &FleetS3Archive{Client: sdk, Bucket: bucket}
			var pinned model.Document
			pipeline := FleetHistoryPipeline{Store: writer, ReaderFactory: func(_ context.Context, approved Registration, account string) (FleetReader, error) {
				if approved.TenantID != tenant || approved.ID != registration.SourceID || account != registration.Binding.AccountID {
					return nil, errors.New("private credential binding changed")
				}
				return &historyFixtureReader{native}, nil
			}, Archive: func(ctx context.Context, actualTenant, target string, raw []byte) (model.Document, error) {
				ref, err := archive.Archive(ctx, actualTenant, target, raw)
				if err != nil {
					return nil, err
				}
				pinned = ref
				if mode == "process loss before publication" {
					return nil, errors.New("simulated process loss after real durable archive")
				}
				if mode == "source revoked after archive" {
					err = admin.Do(ctx, tenant, func(tx *store.Tx) error {
						if _, err := tx.Exec(ctx, "SET LOCAL ROLE finops_api"); err != nil {
							return err
						}
						current, err := tx.SourceGet(ctx, registration.SourceID)
						if err != nil {
							return err
						}
						current["revoked"] = true
						_, err = tx.SourceUpdate(ctx, registration.SourceID, model.Number(current, "version"), current)
						return err
					})
				}
				return ref, err
			}}
			result, captureErr := pipeline.Capture(ctx, tenant, registration.ID)
			if sdk.PutCalls != 1 || sdk.GetCalls != 1 || sdk.RequestedVersion == "" || sdk.RequestedVersion == "null" {
				t.Fatal("real versioned Put/Get protocol was not exercised")
			}
			if mode != "success and process replay" {
				if captureErr == nil {
					t.Fatal("unreadable, uncertain or revoked archive published history")
				}
				if err := writer.Do(ctx, tenant, func(tx *store.Tx) error {
					receipts, err := tx.SourceReceiptList(ctx, "AWS_FLEET_MEMBERSHIP", registration.SourceID)
					if err != nil {
						return err
					}
					points, err := tx.FleetHistoryObservationPage(ctx, registration.ID, "", 100)
					if err == nil && (len(receipts) != 0 || len(points) != 0) {
						return errors.New("failed capture left published authority")
					}
					return err
				}); err != nil {
					t.Fatal(err)
				}
				if mode == "process loss before publication" {
					writer.Pool.Close()
					writer = openWriter()
					pipeline.Store = writer
					pipeline.Archive = archive.Archive
					if recovered, err := pipeline.Capture(ctx, tenant, registration.ID); err != nil || model.String(recovered, "id") == "" {
						t.Fatal("reopened process could not recover unpublished archive", err)
					}
				}
				return
			}
			if captureErr != nil {
				t.Fatal("actual archive publication failed", captureErr)
			}
			observation, err := store.FleetHistoryObservationDocument(registration, result)
			if err != nil || !observation.ObservedAt.Equal(native.CollectedAt) || observation.Source.Archive == nil || observation.Source.Archive.VersionID != model.String(pinned, "version_id") || len(observation.Members) != 2 || observation.Members[0].LaunchTime != nil || observation.Members[0].Hardware != nil {
				t.Fatal("issued point lost pinned provenance or invented incarnation", err)
			}
			originalVersion := observation.Source.Archive.VersionID
			writer.Pool.Close()
			writer = openWriter()
			pipeline.Store = writer
			replay, err := pipeline.Capture(ctx, tenant, registration.ID)
			if err != nil || model.String(replay, "id") != model.String(result, "id") || model.String(replay, "hash") != model.String(result, "hash") {
				t.Fatal("new process changed immutable replay", err)
			}
			key := observation.Source.Archive.Key
			if _, err := client.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(bucket), Key: aws.String(key), Body: strings.NewReader("deliberately different latest local fixture version")}); err != nil {
				t.Fatal("local latest-version overwrite setup failed")
			}
			get, err := client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String(key), VersionId: aws.String(originalVersion)})
			if err != nil {
				t.Fatal("pinned historical object became unavailable")
			}
			actual, readErr := io.ReadAll(io.LimitReader(get.Body, 32<<20+1))
			get.Body.Close()
			if readErr != nil || aws.ToString(get.VersionId) != originalVersion || !bytes.Equal(actual, native.Raw) {
				t.Fatal("latest overwrite changed pinned raw evidence")
			}
			if err := writer.Do(ctx, tenant, func(tx *store.Tx) error {
				receipts, err := tx.SourceReceiptList(ctx, "AWS_FLEET_MEMBERSHIP", registration.SourceID)
				if err != nil || len(receipts) != 1 || model.String(receipts[0], "writer_role") != "finops_ingester" {
					return errors.New("receipt replay or process authority changed")
				}
				_, err = tx.FleetHistorySourceReference(ctx, observation.Source.ReceiptID, "AWS_FLEET_MEMBERSHIP", registration.ASGARN)
				return err
			}); err != nil {
				t.Fatal("restricted process could not resolve original issued reference", err)
			}
			if err := writer.Do(ctx, "foreign-"+tenant, func(tx *store.Tx) error {
				points, err := tx.FleetHistoryObservationPage(ctx, registration.ID, "", 100)
				if err == nil && len(points) != 0 {
					return errors.New("foreign tenant read published native history")
				}
				return err
			}); err != nil {
				t.Fatal(err)
			}
			for _, table := range []string{"fleet_plans", "savings_ledger", "signed_plans"} {
				var allowed bool
				if err := writer.Pool.QueryRow(ctx, "SELECT has_table_privilege(current_user,$1,'INSERT')", table).Scan(&allowed); err != nil || allowed {
					t.Fatal("history process acquired execution, approval or financial write privilege")
				}
			}
			if err := writer.Do(ctx, tenant, func(tx *store.Tx) error {
				_, err := tx.Create(ctx, "approvals", model.Document{"id": "forbidden-history-approval", "approved_by": "human"})
				return err
			}); err == nil || !strings.Contains(err.Error(), "ingestion identity cannot write control or approval state") {
				t.Fatal("history process was not denied by the approval writer boundary")
			}
		})
	}
	t.Log("actual restricted PostgreSQL + versioned MinIO + process replay; AWS transport double; no encryption or financial authority claim")
}

type historyStorageS3 struct {
	Client           *s3.Client
	Mode             string
	PutCalls         int
	GetCalls         int
	RequestedVersion string
}

func (s *historyStorageS3) PutObject(ctx context.Context, in *s3.PutObjectInput, options ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	s.PutCalls++
	return s.Client.PutObject(ctx, in, options...)
}
func (s *historyStorageS3) GetObject(ctx context.Context, in *s3.GetObjectInput, options ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	s.GetCalls++
	s.RequestedVersion = aws.ToString(in.VersionId)
	if s.Mode == "readback unavailable" {
		request := *in
		request.VersionId = aws.String("00000000-0000-0000-0000-000000000000")
		return s.Client.GetObject(ctx, &request, options...)
	}
	out, err := s.Client.GetObject(ctx, in, options...)
	if err == nil && s.Mode == "wrong returned version" {
		out.VersionId = aws.String("different-from-the-written-version")
	}
	return out, err
}
