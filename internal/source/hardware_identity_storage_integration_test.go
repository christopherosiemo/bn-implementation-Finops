package source

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
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
	"github.com/christopherosiemo/bn-implementation-Finops/internal/provider"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
)

// Actual storage/role/restart acceptance, not AWS source authenticity. The
// existing provider-shaped XML fixture is augmented with explicit native fields;
// no customer cloud call or historical identity/ownership claim is made.
func TestHardwareIdentityActualPostgresVersionedMinIOReadbackAndReplay(t *testing.T) {
	if os.Getenv("TEST_HARDWARE_IDENTITY_STORAGE") != "owned-local" {
		t.Skip("explicit new local PostgreSQL/MinIO lab required")
	}
	u, err := url.Parse(os.Getenv("TEST_DATABASE_URL"))
	if err != nil || u.Scheme != "postgres" || u.Host != "postgres:5432" || u.Path != "/postgres" || u.Query().Get("sslmode") != "disable" || os.Getenv("TEST_HARDWARE_IDENTITY_S3_ENDPOINT") != "http://minio:9000" {
		t.Fatal("only dedicated local fixture endpoints are accepted")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	admin, ingester := historyFactoryDatabase(t)
	dsn := ingester.Pool.Config().ConnConfig.ConnString()
	reopen := func() {
		t.Helper()
		ingester.Pool.Close()
		ingester, err = store.OpenRuntime(ctx, dsn, "fleet-history-reader")
		if err != nil {
			t.Fatal("actual restricted process reopen failed")
		}
		t.Cleanup(ingester.Pool.Close)
	}
	var current, session string
	var privileged bool
	if err = ingester.Pool.QueryRow(ctx, "SELECT current_user,session_user,(SELECT rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb FROM pg_roles WHERE rolname=session_user)").Scan(&current, &session, &privileged); err != nil || current != "finops_ingester" || current == session || privileged {
		t.Fatal("actual dedicated ingestion identity changed")
	}
	client := s3.NewFromConfig(aws.Config{Region: "eu-west-1", Credentials: credentials.NewStaticCredentialsProvider(os.Getenv("TEST_HARDWARE_IDENTITY_S3_ACCESS_KEY"), os.Getenv("TEST_HARDWARE_IDENTITY_S3_SECRET_KEY"), "")}, func(o *s3.Options) {
		o.BaseEndpoint = aws.String("http://minio:9000")
		o.UsePathStyle = true
	})
	bucket := "identity-acceptance-" + strings.ReplaceAll(model.ID(), "-", "")
	owner := "finops-hardware-identity:" + model.ID()
	if _, err = client.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(bucket)}); err != nil {
		t.Fatal("owned MinIO bucket creation failed")
	}
	marked := false
	t.Cleanup(func() { identityStorageCleanupBucket(t, client, bucket, owner, marked) })
	if _, err = client.PutBucketTagging(ctx, &s3.PutBucketTaggingInput{Bucket: aws.String(bucket), Tagging: &types.Tagging{TagSet: []types.Tag{{Key: aws.String("finops-identity-owner"), Value: aws.String(owner)}}}}); err != nil {
		t.Fatal("owned MinIO bucket marker failed")
	}
	marked = true
	if _, err = client.PutBucketVersioning(ctx, &s3.PutBucketVersioningInput{Bucket: aws.String(bucket), VersioningConfiguration: &types.VersioningConfiguration{Status: types.BucketVersioningStatusEnabled}}); err != nil {
		t.Fatal("owned MinIO versioning failed")
	}
	for _, mode := range []string{"success and reopen", "missing native identity", "readback unavailable", "wrong returned version", "source revoked during read", "process loss before publication"} {
		t.Run(mode, func(t *testing.T) {
			tenant := "identity-storage-" + model.ID()
			target := hardwareSourceFixture(t, admin, tenant)
			now := time.Now().UTC()
			raw := identityStorageNativeFixture(t, now, mode == "missing native identity")
			archive := &HardwareS3Archive{Client: client, Bucket: bucket}
			capture := HardwarePipeline{Store: ingester, Targets: map[string]HardwareTarget{tenant + ":" + target.Binding.ResourceID: target}, ReaderFactory: func(_ context.Context, approved Registration, account string) (HardwareReader, error) {
				if approved.TenantID != tenant || approved.ID != target.SourceID || account != target.Binding.AccountID {
					return nil, errors.New("private native fixture binding changed")
				}
				return hardwareFixtureReader{raw: raw, now: now}, nil
			}, Archive: archive.Archive}
			parent, err := capture.Capture(ctx, tenant, target.Binding.ResourceID)
			if err != nil {
				t.Fatal("actual parent hardware archive/publication failed", err)
			}
			parentHash := Hash(parent)
			parentNative := Object(parent["native"])
			if parentNative["schema_version"] != "1" || Object(parentNative["instance"])["last_start_time"] != nil || Object(parentNative["instance"])["primary_eni"] != nil {
				t.Fatal("v1 canonical projection was silently enriched")
			}
			ref := Object(parent["raw_object"])
			originalVersion := model.String(ref, "version_id")
			if originalVersion == "" || originalVersion == "null" {
				t.Fatal("real versioned parent archive required")
			}
			// Latest-object reads would now fail. Only the issued pinned version
			// contains the original XML and can satisfy the derivation.
			if _, err := client.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(bucket), Key: aws.String(model.String(ref, "key")), Body: strings.NewReader("different latest fixture version")}); err != nil {
				t.Fatal("latest version overwrite fixture failed")
			}
			sdk := &historyStorageS3{Client: client, Mode: mode}
			reader := &HardwareIdentityS3Reader{Client: sdk, Bucket: bucket}
			pipeline := HardwareIdentityPipeline{Store: ingester, ReadObject: func(ctx context.Context, actualTenant string, actualRef model.Document) ([]byte, error) {
				if actualTenant != tenant || Hash(actualRef) != Hash(ref) {
					return nil, errors.New("pinned native parent scope changed")
				}
				body, err := reader.Read(ctx, actualTenant, actualRef)
				if err != nil {
					return nil, err
				}
				if mode == "source revoked during read" {
					err = admin.Do(ctx, tenant, func(tx *store.Tx) error {
						if _, err := tx.Exec(ctx, "SET LOCAL ROLE finops_api"); err != nil {
							return err
						}
						source, err := tx.SourceGet(ctx, target.SourceID)
						if err != nil {
							return err
						}
						source["enabled"], source["revoked"] = false, true
						_, err = tx.SourceUpdate(ctx, target.SourceID, model.Number(source, "version"), source)
						return err
					})
				}
				if mode == "process loss before publication" {
					return nil, errors.New("simulated process loss after actual pinned readback")
				}
				return body, err
			}}
			derived, deriveErr := pipeline.Derive(ctx, tenant, model.String(parent, "id"))
			if sdk.PutCalls != 0 || sdk.GetCalls != 1 || sdk.RequestedVersion != originalVersion {
				t.Fatal("derivation did not perform one read of the issued original version")
			}
			failed := mode != "success and reopen" && mode != "missing native identity"
			if failed {
				if deriveErr == nil {
					t.Fatal("failed or revoked native readback published derivation")
				}
				if err = ingester.Do(ctx, tenant, func(tx *store.Tx) error {
					var count int
					if err := tx.QueryRow(ctx, "SELECT count(*) FROM hardware_identity_derivations WHERE tenant_id=$1", tenant).Scan(&count); err != nil {
						return err
					}
					if count != 0 {
						return errors.New("unpublished derivation left a visible row")
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
				if mode != "process loss before publication" {
					return
				}
				reopen()
				pipeline.Store, pipeline.ReadObject = ingester, reader.Read
				derived, deriveErr = pipeline.Derive(ctx, tenant, model.String(parent, "id"))
			}
			if deriveErr != nil {
				t.Fatal("actual identity derivation publication failed", deriveErr)
			}
			identity := Object(derived["identity"])
			if model.String(derived, "status") != "OBSERVED_ONLY" || model.String(derived, "incarnation_status") != "UNKNOWN" || model.String(derived, "interval_ownership") != "UNPROVEN" || model.Bool(derived, "execution_authorized") || derived["verified_saving"] != nil || derived["parent_collected_at"] != parent["collected_at"] || derived["parent_received_at"] != parent["created_at"] || Hash(derived["raw_object"]) != Hash(ref) || model.String(identity, "raw_sha256") != BytesHash(raw) {
				t.Fatal("derived observation changed original evidence or acquired authority")
			}
			if mode == "missing native identity" {
				if identity["last_start_time"] != nil || identity["primary_eni"] != nil {
					t.Fatal("missing native identity became zero or invented facts")
				}
			} else {
				last, err := time.Parse(time.RFC3339Nano, model.String(identity, "last_start_time"))
				if err != nil || !last.Equal(now.Add(-time.Hour)) {
					t.Fatal("latest native start was not preserved")
				}
				primary := Object(identity["primary_eni"])
				attach, err := time.Parse(time.RFC3339Nano, model.String(primary, "attach_time"))
				if err != nil || !attach.Equal(now.Add(-24*time.Hour)) || !attach.Before(last) || model.String(primary, "network_interface_id") != "eni-0123456789abcdef0" || model.Number(primary, "device_index") != 0 {
					t.Fatal("native primary attachment and latest start were conflated")
				}
			}
			reopen()
			pipeline.Store, pipeline.ReadObject = ingester, reader.Read
			replay, err := pipeline.Derive(ctx, tenant, model.String(parent, "id"))
			if err != nil || Hash(replay) != Hash(derived) {
				t.Fatal("reopened restricted process changed immutable replay", err)
			}
			if err = ingester.Do(ctx, tenant, func(tx *store.Tx) error {
				unchanged, err := tx.SourceReceiptGet(ctx, model.String(parent, "id"))
				if err != nil || Hash(unchanged) != parentHash {
					return errors.New("v2 derivation rewrote v1 receipt, hash or time")
				}
				var count int
				if err = tx.QueryRow(ctx, "SELECT count(*) FROM hardware_identity_derivations WHERE tenant_id=$1", tenant).Scan(&count); err != nil || count != 1 {
					return errors.New("replay duplicated derivation")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if err = ingester.Do(ctx, "foreign-"+tenant, func(tx *store.Tx) error {
				var count int
				if err := tx.QueryRow(ctx, "SELECT count(*) FROM hardware_identity_derivations WHERE id=$1", derived["id"]).Scan(&count); err != nil || count != 0 {
					return errors.New("foreign tenant could read identity derivation")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
	for _, table := range []string{"signed_plans", "fleet_plans", "savings_ledger"} {
		var allowed bool
		if err = ingester.Pool.QueryRow(ctx, "SELECT has_table_privilege(current_user,$1,'INSERT')", table).Scan(&allowed); err != nil || allowed {
			t.Fatal("identity reader acquired signing, execution or financial privilege")
		}
	}
	for _, role := range []string{"finops_api", "finops_worker", "finops_signer", "finops_executor", "finops_activity", "finops_telemetry_ingress", "finops_telemetry_reader"} {
		var insert bool
		if err = admin.Pool.QueryRow(ctx, "SELECT has_table_privilege($1,'hardware_identity_derivations','INSERT')", role).Scan(&insert); err != nil || insert {
			t.Fatal("non-ingestion role acquired identity publication privilege")
		}
	}
	t.Log("actual restricted PostgreSQL + pinned hardware MinIO readback + identity replay; provider-shaped XML double; original v1 preserved; no incarnation, interval or financial authority")
}

func identityStorageNativeFixture(t *testing.T, now time.Time, absent bool) []byte {
	t.Helper()
	raw, err := os.ReadFile("../provider/testdata/hardware_capture.bin")
	if err != nil {
		t.Fatal("public native fixture unavailable")
	}
	if absent {
		return raw
	}
	r := bytes.NewReader(raw)
	var selectorSize uint32
	if binary.Read(r, binary.BigEndian, &selectorSize) != nil || int(selectorSize) > r.Len() {
		t.Fatal("fixture selector framing invalid")
	}
	selector := make([]byte, selectorSize)
	_, _ = io.ReadFull(r, selector)
	var size uint64
	if binary.Read(r, binary.BigEndian, &size) != nil || size > uint64(r.Len()) {
		t.Fatal("fixture body framing invalid")
	}
	body := make([]byte, int(size))
	_, _ = io.ReadFull(r, body)
	fields := fmt.Sprintf("<launchTime>%s</launchTime><networkInterfaceSet><item><networkInterfaceId>eni-0123456789abcdef0</networkInterfaceId><ownerId>111122223333</ownerId><attachment><attachmentId>eni-attach-0123456789abcdef0</attachmentId><deviceIndex>0</deviceIndex><networkCardIndex>0</networkCardIndex><attachTime>%s</attachTime><status>attached</status></attachment></item></networkInterfaceSet>", now.Add(-time.Hour).Format(time.RFC3339Nano), now.Add(-24*time.Hour).Format(time.RFC3339Nano))
	needle := "</instanceId>"
	if bytes.Count(body, []byte(needle)) != 1 {
		t.Fatal("fixture must contain exactly one instance")
	}
	body = bytes.Replace(body, []byte(needle), []byte(needle+fields), 1)
	var out bytes.Buffer
	_ = binary.Write(&out, binary.BigEndian, selectorSize)
	out.Write(selector)
	_ = binary.Write(&out, binary.BigEndian, uint64(len(body)))
	out.Write(body)
	out.Write(raw[len(raw)-r.Len():])
	if _, err := provider.ParseHardwareEvidence(out.Bytes(), "111122223333", "eu-west-1", "i-0123456789abcdef0", []string{"m6i.large"}, now); err != nil {
		t.Fatal("native-shaped augmentation changed v1 hardware projection", err)
	}
	return out.Bytes()
}

func identityStorageCleanupBucket(t *testing.T, client *s3.Client, bucket, owner string, marked bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	tags, err := client.GetBucketTagging(ctx, &s3.GetBucketTaggingInput{Bucket: aws.String(bucket)})
	owned := false
	if err == nil && marked {
		for _, tag := range tags.TagSet {
			owned = owned || aws.ToString(tag.Key) == "finops-identity-owner" && aws.ToString(tag.Value) == owner
		}
	}
	if !owned {
		t.Error("owned identity bucket cleanup refused")
		return
	}
	pages := s3.NewListObjectVersionsPaginator(client, &s3.ListObjectVersionsInput{Bucket: aws.String(bucket)})
	for pages.HasMorePages() {
		page, err := pages.NextPage(ctx)
		if err != nil {
			t.Error("owned identity bucket version enumeration failed")
			return
		}
		objects := []types.ObjectIdentifier{}
		for _, version := range page.Versions {
			objects = append(objects, types.ObjectIdentifier{Key: version.Key, VersionId: version.VersionId})
		}
		for _, marker := range page.DeleteMarkers {
			objects = append(objects, types.ObjectIdentifier{Key: marker.Key, VersionId: marker.VersionId})
		}
		if len(objects) > 0 {
			out, err := client.DeleteObjects(ctx, &s3.DeleteObjectsInput{Bucket: aws.String(bucket), Delete: &types.Delete{Objects: objects, Quiet: aws.Bool(true)}})
			if err != nil || len(out.Errors) > 0 {
				t.Error("owned identity bucket version cleanup failed")
				return
			}
		}
	}
	if _, err = client.DeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: aws.String(bucket)}); err != nil {
		t.Error("owned identity bucket cleanup failed")
	}
}
