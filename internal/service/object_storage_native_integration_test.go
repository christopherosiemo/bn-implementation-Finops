package service

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/auth"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/configuration"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/native"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/objectstorage"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/provider"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/source"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/jackc/pgx/v5"
)

// COMPONENT evidence only: deterministic native AWS transport, real SDK,
// Inventory and authenticated historical-access parsers, immutable versioned
// archive, ClickHouse readback, ordinary OIDC API, separate PostgreSQL analyst
// and actual Python. No live AWS, object mutation or verified-saving claim.
func TestObjectStorageNativeBillingPersistedAssessmentThroughActualPython(t *testing.T) {
	if os.Getenv("S3_TEST_STORAGE_ENABLED") != "true" {
		t.Skip("existing owned PostgreSQL/object/analytics components required")
	}
	if os.Getenv("ECONOMICS_TEST_URL") == "" || os.Getenv("ECONOMICS_TEST_TOKEN") == "" {
		t.Fatal("actual private Python endpoint required")
	}
	f := newMutationReplayFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	if os.Getenv("FINOPS_OBJECT_STORAGE_BROWSER") == "true" {
		f.tenant = "tenant-demo"
		if e := f.roles["api"].Do(ctx, f.tenant, func(tx *store.Tx) error { return tx.Seed(ctx, true) }); e != nil {
			t.Fatal(e)
		}
	}
	admin := databaseAssessmentTestAdmin(t, ctx, f)
	analyst := databaseAssessmentTestRuntime(t, ctx, admin, "object-storage-assessor", "finops_object_storage_analyst")
	archive, e := native.StorageFromEnvironment(ctx, true)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now().UTC()
	end := now.Truncate(24 * time.Hour)
	token := f.token(f.tenant, "s3-component-requester", "PLATFORM_ADMIN")
	type scenario struct {
		name, want        string
		bucket            objectstorage.Bucket
		resource, dataset model.Document
		inventory         objectstorage.Registration
		generation        objectstorage.Generation
		canonical         model.Document
	}
	cases := []scenario{{name: "cold-positive", want: "RECOMMENDED"}, {name: "missing-access", want: "BLOCKED"}, {name: "retention-review", want: "OBSERVATION_ONLY"}}
	for j := range cases {
		c := &cases[j]
		name := "synthetic-s3-" + c.name + "-" + strings.ReplaceAll(model.ID(), "-", "")[:12]
		c.bucket = objectstorage.Bucket{Name: name, ARN: "arn:aws:s3:::" + name, AccountID: "111122223333", Region: "eu-west-1", CreatedAt: end.AddDate(-2, 0, 0), ObservedAt: now, Tags: map[string]string{"evidence_basis": "SYNTHETIC_COMPONENT_NO_LIVE_CUSTOMER_CLAIM"}, Configurations: map[string]objectstorage.Observation{
			"versioning":          {Status: "OBSERVED", Value: model.Document{"Status": "Enabled"}},
			"lifecycle":           {Status: "ABSENT", ReasonCode: "NoSuchLifecycleConfiguration", Value: nil},
			"replication":         {Status: "ABSENT", ReasonCode: "ReplicationConfigurationNotFoundError", Value: nil},
			"object_lock":         {Status: "ABSENT", ReasonCode: "ObjectLockConfigurationNotFoundError", Value: nil},
			"encryption":          {Status: "OBSERVED", Value: model.Document{"ServerSideEncryptionConfiguration": model.Document{"Rules": []model.Document{{"ApplyServerSideEncryptionByDefault": model.Document{"SSEAlgorithm": "aws:kms"}}}}}},
			"multipart_uploads":   {Status: "OBSERVED", Value: model.Document{"complete": true, "uploads": []model.Document{}}},
			"intelligent_tiering": {Status: "OBSERVED", Value: model.Document{"Configurations": []model.Document{}, "complete": true}},
		}}
		if j == 2 {
			c.bucket.Configurations["multipart_uploads"] = objectstorage.Observation{Status: "OBSERVED", Value: model.Document{"complete": true, "uploads": []model.Document{{"upload_id": "synthetic-incomplete", "storage_class": "STANDARD", "size_bytes": "1073741824", "initiated": end.AddDate(0, 0, -45).Format(time.RFC3339)}}}}
		}
		if e = f.roles["api"].Do(ctx, f.tenant, func(tx *store.Tx) error {
			wid := "object-storage-workload-" + c.name
			if _, e := tx.Create(ctx, "workloads", model.Document{"id": wid, "name": "Synthetic S3 " + c.name, "owner_subject": "s3-component-owner", "environment": "NON_PRODUCTION"}); e != nil {
				return e
			}
			var e error
			c.resource, e = tx.Create(ctx, "resources", model.Document{"name": "Synthetic provider-shaped S3 " + c.name, "resource_type": "S3_BUCKET", "provider": "AWS", "provider_resource_id": c.bucket.ARN, "account_id": c.bucket.AccountID, "region": c.bucket.Region, "workload_id": wid, "owner": "s3-component-owner", "environment": "NON_PRODUCTION", "configuration_authority": "TERRAFORM", "object_storage_configuration": c.bucket, "tags": c.bucket.Tags})
			if e != nil {
				return e
			}
			d := configuration.Declaration{SchemaVersion: "1", Authority: "TERRAFORM", Repository: configuration.Repository{URL: "https://github.com/example/synthetic-component-infrastructure.git", Ref: "main", Directory: "object-storage"}, Pipeline: configuration.Pipeline{System: "GITHUB_ACTIONS", Identity: configuration.PipelineIdentity{Issuer: "https://token.actions.githubusercontent.com", Audience: configuration.ObserverAudience, Subject: "repo:example/synthetic-component-infrastructure:ref:refs/heads/main", PipelineID: ".github/workflows/deploy.yml"}}, Terraform: configuration.Terraform{Workspace: "component-eu-" + c.name, StateLineage: model.ID(), Addresses: []string{"aws_s3_bucket.fixture"}}}
			_, e = tx.ConfigurationAuthorityAppend(ctx, model.String(c.resource, "id"), 0, "s3-component-owner", d)
			return e
		}); e != nil {
			t.Fatal(e)
		}
		policy := model.Document{"criticality": "NON_PRODUCTION", "high_seasonality": false, "remaining_lifetime_days": "365", "rto_seconds": "86400", "retention_known": true, "compliance_clear": true, "recovery_known": true, "allow_onezone": false, "dependencies_reviewed": true}
		code, dataset, _ := f.request("object-storage-datasets", `"0"`, "s3-native-dataset-"+c.name, token, model.Document{"resource_id": c.resource["id"], "name": "Synthetic " + c.name + " bucket dataset", "selector": model.Document{"kind": "BUCKET"}, "policy": policy})
		if code != 201 {
			t.Fatal("ordinary dataset declaration", code, dataset)
		}
		c.dataset = dataset
		body := model.Document{"kind": objectstorage.InventoryKind, "account_id": c.bucket.AccountID, "region": c.bucket.Region, "bucket": name, "report_bucket": "synthetic-s3-reports", "report_owner": c.bucket.AccountID, "prefix": "inventory/", "inventory_id": "native-config", "read_role_binding_id": "synthetic-s3-read", "dataset_ids": []string{model.String(dataset, "id")}}
		code, registered, _ := f.request("source-connections", `"0"`, "s3-native-source-"+c.name, token, body)
		if code != 201 {
			t.Fatal("ordinary source registration", code, registered)
		}
		c.inventory, e = objectstorage.ParseRegistration(registered)
		if e != nil {
			t.Fatal(e)
		}
	}
	// Existing native CUR delivery/normalization pipeline. Non-target peer
	// buckets witness actual customer rate dimensions; no public price is used.
	rows := objectStorageNativeCUR(cases[0].bucket.ARN, cases[1].bucket.ARN, cases[2].bucket.ARN, end.Add(-24*time.Hour), end)
	normalizer := &API{Config: Config{Fixture: true, EconomicsURL: os.Getenv("ECONOMICS_TEST_URL"), EconomicsToken: os.Getenv("ECONOMICS_TEST_TOKEN")}, Client: &http.Client{Timeout: HTTPTimeout}}
	billingID := "s3-native-billing-" + model.ID()
	versions := map[string]provider.BillingObject{}
	executions := map[string]*source.FixtureReader{}
	databaseAssessmentTestBilling(t, ctx, f, archive, normalizer, billingID, rows, now, versions, executions)
	reader, objects := objectStorageNativeTestReader(t, ctx, f.tenant)
	objectStorageNativeCatalogue(t, objects, rows, end.AddDate(0, -1, 0))
	for j := range cases {
		c := &cases[j]
		objects["fixture/source_bucket"] = []byte(c.bucket.Name)
		key := objectStorageNativeInventory(t, objects, c.inventory, now, j == 2)
		p := objectStorageNativePipeline(t, ctx, f, archive, reader, c.inventory.ID)
		c.generation, e = p.Ingest(ctx, c.inventory, key)
		if e != nil {
			t.Fatal("actual native inventory pipeline", c.name, e)
		}
		if !c.generation.Complete || len(c.generation.Cohorts) != 1 {
			t.Fatal("actual inventory population incomplete", c.name)
		}
		wire, _ := json.Marshal(model.Document{"evidence_basis": "SYNTHETIC_COMPONENT_NO_LIVE_CUSTOMER_CLAIM", "native_bucket_projection": c.bucket})
		bucketArchive := databaseAssessmentTestArchive(t, ctx, archive, f.tenant, "wire", "s3-bucket-"+model.ID(), wire)
		bucketRef := model.Document{"kind": "AWS_S3_BUCKET_DISCOVERY", "id": bucketArchive["key"], "version": bucketArchive["version_id"], "sha256": bucketArchive["body_sha256"], "archive": bucketArchive}
		c.canonical = objectstorage.CanonicalSnapshot(model.String(c.resource, "id"), c.bucket, c.inventory, c.generation, bucketRef)
		// Native Price List contributes unit/range metadata only, independently
		// joined to the actual customer CUR rateCode and SKU.
		var skus []string
		if e = f.roles["ingester"].Do(ctx, f.tenant, func(tx *store.Tx) error {
			var e error
			skus, e = CurrentObjectStorageSKUs(ctx, tx, c.bucket.AccountID, c.bucket.Region)
			return e
		}); e != nil {
			t.Fatal(e)
		}
		dimensions, e := reader.S3PriceDimensions(ctx, objectstorage.Scope{TenantID: f.tenant, AccountID: c.bucket.AccountID, Region: c.bucket.Region}, skus)
		if e != nil {
			t.Fatal("actual native catalogue", e)
		}
		raw, ok := dimensions["raw"].([]byte)
		if !ok {
			t.Fatal("native catalogue raw unavailable")
		}
		ref := databaseAssessmentTestArchive(t, ctx, archive, f.tenant, "wire", "s3-native-pricing-"+model.ID(), raw)
		delete(dimensions, "raw")
		dimensions["status"] = "OBSERVED"
		dimensions["source_ref"] = model.Document{"kind": "AWS_S3_NATIVE_PRICE_DIMENSIONS", "id": ref["key"], "version": ref["version_id"], "sha256": ref["body_sha256"], "archive": ref}
		c.canonical["pricing_dimensions"] = dimensions
		objectStorageNativePublish(t, ctx, f, archive, c.resource, c.inventory, c.generation, c.canonical)
		if j == 0 {
			body := model.Document{"kind": objectstorage.AccessKind, "account_id": c.bucket.AccountID, "region": c.bucket.Region, "bucket": c.bucket.Name, "report_bucket": "synthetic-s3-reports", "report_owner": c.bucket.AccountID, "prefix": "access/", "inventory_id": "native-config", "report_type": "APP_ACCESS", "read_role_binding_id": "synthetic-s3-read", "dataset_ids": []string{model.String(c.dataset, "id")}}
			code, registered, _ := f.request("source-connections", `"0"`, "s3-native-access-source", token, body)
			if code != 201 {
				t.Fatal("registered historical access", code, registered)
			}
			r, e := objectstorage.ParseRegistration(registered)
			if e != nil {
				t.Fatal(e)
			}
			key := "access/" + c.bucket.Name + "/observed.jsonl"
			objects[r.ReportBucket+"/"+key] = objectStorageNativeAccess(t, r, c.generation.Cohorts[0], end)
			accessPipeline := objectStorageNativePipeline(t, ctx, f, archive, reader, r.ID)
			g, e := accessPipeline.IngestAnalysis(ctx, r, key)
			if e != nil {
				t.Fatal("actual historical application access", e)
			}
			if g.Access["complete"] != true || g.Access["requests"] != "0" || g.Access["eligible_cold_bytes_fraction"] != "1" {
				t.Fatal("observed explicit zero lost", g.Access)
			}
			if e = archive.WriteObjectAccess(ctx, g.Scope, g.SourceVersion, objectstorage.Rows(g.Access["observations"])); e != nil {
				t.Fatal(e)
			}
			accessCanonical := objectstorage.CanonicalSnapshot(model.String(c.resource, "id"), c.bucket, r, g, bucketRef)
			for _, field := range []string{"inventory", "cohorts", "dataset_bindings", "pricing_dimensions"} {
				accessCanonical[field] = c.canonical[field]
			}
			accessCanonical["source_refs"] = append(objectstorage.Rows(c.canonical["source_refs"]), g.SourceRefs...)
			accessCanonical["source_bindings"] = append(objectstorage.Rows(c.canonical["source_bindings"]), objectstorage.Rows(accessCanonical["source_bindings"])...)
			objectStorageNativePublish(t, ctx, f, archive, c.resource, r, g, accessCanonical)
			c.canonical = accessCanonical
		}
	}
	workerCtx, stopWorker := context.WithCancel(ctx)
	workerDone := make(chan error, 1)
	stopped := false
	go func() {
		workerDone <- RunObjectStorageAssessor(workerCtx, Config{Fixture: true, EconomicsURL: os.Getenv("ECONOMICS_TEST_URL"), EconomicsToken: os.Getenv("ECONOMICS_TEST_TOKEN")}, analyst)
	}()
	t.Cleanup(func() {
		if stopped {
			return
		}
		stopWorker()
		select {
		case e := <-workerDone:
			if e != nil {
				t.Error(e)
			}
		case <-time.After(5 * time.Second):
			t.Error("S3 analyst did not stop")
		}
	})
	issued := map[string]string{}
	hashes := map[string]string{}
	for _, c := range cases {
		code, d, _ := f.request("object-storage-assessments", `"0"`, "s3-native-assessment-"+c.name, token, model.Document{"resource_id": c.resource["id"], "dataset_id": c.dataset["id"]})
		if code != 202 {
			t.Fatal("IDs-only assessment", code, d)
		}
		issued[c.name] = model.String(d, "id")
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			record := objectStorageNativeWait(t, ctx, f, issued[c.name], token)
			assessment := storageObject(record["assessment"])
			if model.String(assessment, "status") != c.want {
				t.Fatalf("persisted status=%s want=%s blockers=%v server=%v", model.String(assessment, "status"), c.want, assessment["blockers"], assessment["server_evidence_blockers"])
			}
			if model.String(assessment, "model_assessment_hash") == "" || model.String(assessment, "model_version") != "object-storage-v1" {
				t.Fatal("actual Python missing")
			}
			if p := storageObject(assessment["proposal"]); p["risk_class"] != "R3" || p["executable"] != false || p["execution_authorized"] != false || assessment["verified_saving"] != nil {
				t.Fatal("read-only boundary lost")
			}
			if c.want == "RECOMMENDED" {
				found := map[string]bool{}
				for _, candidate := range storageRows(assessment["candidates"]) {
					if model.String(candidate, "status") == "RECOMMENDED" {
						money := storageObject(candidate["economics"])
						saving, ok := databaseDecimal(money["estimated_monthly_saving"])
						if !ok || saving.Sign() <= 0 || money["basis"] != "AWS_CUR_NET_USAGE" {
							t.Fatal("native economics unavailable", money)
						}
						found[model.String(candidate, "candidate_storage_class")] = true
					}
				}
				for _, class := range []string{"STANDARD_IA", "INTELLIGENT_TIERING", "GLACIER_INSTANT_RETRIEVAL", "GLACIER_FLEXIBLE_RETRIEVAL", "DEEP_ARCHIVE"} {
					if !found[class] {
						t.Fatal("connected positive family unavailable", class, assessment["candidates"])
					}
				}
			}
			if c.want == "OBSERVATION_ONLY" {
				families := map[string]bool{}
				for _, candidate := range storageRows(assessment["candidates"]) {
					families[model.String(candidate, "recommendation_kind")] = true
				}
				if !families["S3_NONCURRENT_VERSION_REVIEW"] || !families["S3_MULTIPART_UPLOAD_REVIEW"] {
					t.Fatal("native retention populations lost", families)
				}
			}
			hashes[c.name] = source.Hash(assessment)
			if code, again := fleetNativeHTTPGet(t, f, "object-storage-assessments/"+issued[c.name], token); code != 200 || source.Hash(again["assessment"]) != hashes[c.name] {
				t.Fatal("immutable reload changed")
			}
			if code, _ := fleetNativeHTTPGet(t, f, "object-storage-assessments/"+issued[c.name], f.token("foreign-"+f.tenant, "s3-other", "FINOPS_ADMIN")); code != 404 {
				t.Fatal("cross-tenant S3 result", code)
			}
			if code, pub := fleetNativeHTTPGet(t, f, "recommendations/object-storage-"+issued[c.name], token); code != 200 || pub["execution_authorized"] != false {
				t.Fatal("ordinary recommendation publication", code)
			}
		})
	}
	if t.Failed() {
		return
	}
	if code, _, _ := f.request("object-storage-assessments", `"0"`, "s3-reject-authoritative-money", token, model.Document{"resource_id": cases[0].resource["id"], "estimated_monthly_saving": "1000"}); code != 422 {
		t.Fatal("caller money accepted", code)
	}
	if code, coverage := fleetNativeHTTPGet(t, f, "coverage", token); code != 200 || len(storageRows(coverage["object_storage_groups"])) != 1 || len(storageRows(coverage["groups"])) != 1 {
		t.Fatal("ordinary coverage missing", code)
	}
	// Independent native billing correction invalidates prior advice without
	// changing immutable assessment history. Browser commissions new current IDs.
	corrected := storageRows(rows)
	corrected[0]["line_item_net_unblended_rate"] = "0.024"
	corrected[0]["line_item_unblended_rate"] = "0.024"
	q, _ := databaseDecimal(corrected[0]["line_item_usage_amount"])
	corrected[0]["line_item_net_unblended_cost"] = databaseInputMoney(new(big.Rat).Mul(q, big.NewRat(24, 1000)))
	corrected[0]["line_item_unblended_cost"] = corrected[0]["line_item_net_unblended_cost"]
	// Preserve a coherent rate across every target witness in this correction.
	for j, row := range corrected {
		if row["product_sku"] == corrected[0]["product_sku"] {
			row["line_item_net_unblended_rate"] = "0.024"
			row["line_item_unblended_rate"] = "0.024"
			q, _ := databaseDecimal(row["line_item_usage_amount"])
			row["line_item_net_unblended_cost"] = databaseInputMoney(new(big.Rat).Mul(q, big.NewRat(24, 1000)))
			row["line_item_unblended_cost"] = row["line_item_net_unblended_cost"]
			corrected[j] = row
		}
	}
	databaseAssessmentTestBilling(t, ctx, f, archive, normalizer, billingID, corrected, time.Now().UTC(), versions, executions)
	for _, c := range cases {
		code, old := fleetNativeHTTPGet(t, f, "object-storage-assessments/"+issued[c.name], token)
		if code != 200 || model.Bool(old, "current") || source.Hash(old["assessment"]) != hashes[c.name] {
			t.Fatal("billing correction rewrote or retained current advice", c.name)
		}
	}
	if os.Getenv("FINOPS_OBJECT_STORAGE_BROWSER") == "true" {
		stopWorker()
		select {
		case e := <-workerDone:
			stopped = true
			if e != nil {
				t.Fatal(e)
			}
		case <-ctx.Done():
			t.Fatal("component analyst shutdown deadline")
		}
		resources, datasets := []model.Document{}, []model.Document{}
		for _, c := range cases {
			resources = append(resources, c.resource)
			datasets = append(datasets, c.dataset)
		}
		objectStorageNativeBrowser(t, ctx, f, analyst, resources, datasets, issued)
	}
}

func objectStorageNativePipeline(t *testing.T, ctx context.Context, f *mutationReplayFixture, archive *native.Storage, reader *provider.ObjectStorageAWS, sourceID string) *objectstorage.InventoryPipeline {
	t.Helper()
	key, e := hex.DecodeString(os.Getenv("S3_OBJECT_IDENTITY_KEY_HEX"))
	if e != nil || len(key) < 32 || os.Getenv("S3_OBJECT_IDENTITY_KEY_VERSION") == "" {
		t.Fatal("dedicated synthetic object identity key required")
	}
	return &objectstorage.InventoryPipeline{Reader: reader, Archive: archive, Facts: archive, IdentityKey: key, IdentityKeyVersion: os.Getenv("S3_OBJECT_IDENTITY_KEY_VERSION"), LoadCheckpoint: func(ctx context.Context, key string) (model.Document, error) {
		var out model.Document
		e := f.roles["ingester"].Do(ctx, f.tenant, func(tx *store.Tx) error {
			var e error
			out, e = tx.SourceCheckpointGet(ctx, sourceID, key)
			if errors.Is(e, pgx.ErrNoRows) {
				return nil
			}
			return e
		})
		return out, e
	}, SaveCheckpoint: func(ctx context.Context, key string, d model.Document) error {
		return f.roles["ingester"].Do(ctx, f.tenant, func(tx *store.Tx) error { return tx.SourceCheckpointSet(ctx, sourceID, key, d) })
	}}
}

func objectStorageNativeInventory(t *testing.T, objects map[string][]byte, r objectstorage.Registration, now time.Time, noncurrent bool) string {
	t.Helper()
	var csv bytes.Buffer
	for n := 0; n < 1000; n++ {
		fmt.Fprintf(&csv, "%s,logs/observed-%04d,version-1,%t,false,1073741824,%s,STANDARD\n", r.Bucket, n, !noncurrent, now.AddDate(0, 0, -180).UTC().Format(time.RFC3339))
	}
	var compressed bytes.Buffer
	gz := gzip.NewWriter(&compressed)
	if _, e := io.Copy(gz, &csv); e != nil {
		t.Fatal(e)
	}
	if e := gz.Close(); e != nil {
		t.Fatal(e)
	}
	file := r.Prefix + r.Bucket + "/" + r.InventoryID + "/data/part.csv.gz"
	sum := md5.Sum(compressed.Bytes())
	manifest := objectstorage.InventoryManifest{SourceBucket: r.Bucket, DestinationBucket: "arn:aws:s3:::" + r.ReportBucket, Version: "2016-11-30", CreationTimestamp: strconv.FormatInt(now.UnixMilli(), 10), FileFormat: "CSV", FileSchema: "Bucket, Key, VersionId, IsLatest, IsDeleteMarker, Size, LastModifiedDate, StorageClass", Files: []objectstorage.InventoryFile{{Key: file, Size: int64(compressed.Len()), MD5: hex.EncodeToString(sum[:])}}}
	raw, e := json.Marshal(manifest)
	if e != nil {
		t.Fatal(e)
	}
	key := r.Prefix + r.Bucket + "/" + r.InventoryID + "/" + now.Format("2006-01-02T15-04Z") + "/manifest.json"
	checksum := md5.Sum(raw)
	objects[r.ReportBucket+"/"+key] = raw
	objects[r.ReportBucket+"/"+strings.TrimSuffix(key, "manifest.json")+"manifest.checksum"] = []byte(hex.EncodeToString(checksum[:]))
	objects[r.ReportBucket+"/"+file] = compressed.Bytes()
	return key
}

func objectStorageNativeAccess(t *testing.T, r objectstorage.Registration, cohort model.Document, end time.Time) []byte {
	t.Helper()
	start := end.AddDate(0, 0, -90)
	var raw bytes.Buffer
	enc := json.NewEncoder(&raw)
	header := model.Document{"schema_version": "1", "kind": "S3_APPLICATION_ACCESS_HISTORY", "account_id": r.AccountID, "region": r.Region, "bucket": r.Bucket, "dataset_id": r.Datasets[0].ID, "dataset_version": r.Datasets[0].DatasetVersion, "metric_definition": model.Document{"id": "synthetic-approved-access", "version": "1", "unit": objectstorage.AppAccessReportUnit}, "population_sha256": cohort["population_hash"], "interval_start": start, "interval_end": end, "authoritative_access_scope": true}
	if e := enc.Encode(header); e != nil {
		t.Fatal(e)
	}
	for minute := 0; minute < 90*1440; minute++ {
		if e := enc.Encode(model.Document{"sequence": minute + 1, "interval_start": start.Add(time.Duration(minute) * time.Minute), "interval_end": start.Add(time.Duration(minute+1) * time.Minute), "get_requests": "0", "retrieved_bytes": "0", "heartbeat": true}); e != nil {
			t.Fatal(e)
		}
	}
	return raw.Bytes()
}

func objectStorageNativePublish(t *testing.T, ctx context.Context, f *mutationReplayFixture, archive *native.Storage, resource model.Document, r objectstorage.Registration, g objectstorage.Generation, canonical model.Document) {
	t.Helper()
	raw, e := json.Marshal(canonical)
	if e != nil {
		t.Fatal(e)
	}
	ref := databaseAssessmentTestArchive(t, ctx, archive, f.tenant, "canonical", "s3-evaluation-"+source.BytesHash(raw), raw)
	if e = f.roles["ingester"].Do(ctx, f.tenant, func(tx *store.Tx) error {
		current, e := tx.SourceGet(ctx, r.ID)
		if e != nil {
			return e
		}
		parsed, e := objectstorage.ParseRegistration(current)
		if e != nil || objectstorage.Hash(parsed) != objectstorage.Hash(r) {
			return errors.New("registered S3 source changed")
		}
		revisionID, receiptID := "revision-"+g.SourceVersion, "receipt-"+g.SourceVersion
		if _, e = tx.SourceRevisionCreate(ctx, model.Document{"id": revisionID, "source_id": r.ID, "revision_hash": g.SourceVersion, "kind": r.Kind, "config_hash": objectstorage.Hash(r), "source_version": g.SourceVersion, "source_refs": g.SourceRefs, "generation_id": g.ID}); e != nil {
			return e
		}
		if _, e = tx.SourceReceiptCreate(ctx, model.Document{"id": receiptID, "source_id": r.ID, "revision_id": revisionID, "kind": r.Kind, "config_hash": objectstorage.Hash(r), "registration_version": r.Version, "generation_id": g.ID, "source_version": g.SourceVersion, "complete": g.Complete, "observed_at": g.ObservedAt, "source_refs": g.SourceRefs, "canonical_hash": ref["body_sha256"], "snapshot_archive": ref}); e != nil {
			return e
		}
		if _, e = tx.ObjectStorageEvidenceCreate(ctx, model.String(resource, "id"), r.ID, canonical, ref); e != nil {
			return e
		}
		return tx.SourceCheckpointSet(ctx, r.ID, "status", model.Document{"status": "HEALTHY", "reason_code": "SYNTHETIC_NATIVE_S3_GENERATION_PERSISTED", "last_sync_version": r.Version, "config_hash": objectstorage.Hash(r), "last_sync_at": model.Now(), "latest_revision_id": revisionID, "latest_receipt_id": receiptID})
	}); e != nil {
		t.Fatal("persist native S3 generation", e)
	}
}

func objectStorageNativeWait(t *testing.T, ctx context.Context, f *mutationReplayFixture, id, token string) model.Document {
	t.Helper()
	for {
		code, d := fleetNativeHTTPGet(t, f, "object-storage-assessments/"+id, token)
		if code != 200 {
			t.Fatal("persisted S3 read", code)
		}
		switch model.String(d, "status") {
		case "ASSESSED", "BLOCKED":
			return d
		case "FAILED":
			t.Fatal("S3 analyst terminal failure")
		}
		select {
		case <-ctx.Done():
			t.Fatal("S3 assessment deadline", id)
			return nil
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func objectStorageNativeCUR(positive, blocked, review string, start, end time.Time) []model.Document {
	type component struct{ class, usage, operation, unit, rate string }
	parts := []component{
		{"Standard", "TimedStorage-ByteHrs", "StandardStorage", "GB-Mo", "0.023"},
		{"Standard - Infrequent Access", "TimedStorage-SIA-ByteHrs", "StandardIAStorage", "GB-Mo", "0.0125"},
		{"One Zone - Infrequent Access", "TimedStorage-ZIA-ByteHrs", "OneZoneIAStorage", "GB-Mo", "0.01"},
		{"Glacier Instant Retrieval", "TimedStorage-GIR-ByteHrs", "GlacierInstantRetrievalStorage", "GB-Mo", "0.004"},
		{"Glacier", "TimedStorage-GlacierByteHrs", "GlacierStorage", "GB-Mo", "0.0036"},
		{"Glacier Deep Archive", "TimedStorage-GDA-ByteHrs", "DeepArchiveStorage", "GB-Mo", "0.00099"},
		{"Intelligent-Tiering", "TimedStorage-INT-FA-ByteHrs", "IntelligentTieringFAStorage", "GB-Mo", "0.023"},
		{"Intelligent-Tiering", "TimedStorage-INT-IA-ByteHrs", "IntelligentTieringIAStorage", "GB-Mo", "0.0125"},
		{"Intelligent-Tiering", "TimedStorage-INT-AIA-ByteHrs", "IntelligentTieringAIAStorage", "GB-Mo", "0.004"},
		{"Intelligent-Tiering", "TimedStorage-INT-AA-ByteHrs", "IntelligentTieringAAStorage", "GB-Mo", "0.0036"},
		{"Intelligent-Tiering", "TimedStorage-INT-DAA-ByteHrs", "IntelligentTieringDAAStorage", "GB-Mo", "0.00099"},
	}
	for _, class := range []string{"Standard - Infrequent Access", "One Zone - Infrequent Access", "Intelligent-Tiering", "Glacier Instant Retrieval", "Glacier", "Glacier Deep Archive"} {
		parts = append(parts, component{class, "LifecycleTransition", "LifecycleTransition", "Requests", "0.00001"})
	}
	parts = append(parts, component{"Intelligent-Tiering", "Monitoring-Automation-INT", "IntelligentTieringMonitoring", "Objects", "0.0000025"})
	rows := []model.Document{}
	add := func(arn string, index int, part component, at time.Time, units int64) {
		quantity := "1"
		if part.unit == "GB-Mo" {
			quantity = new(big.Rat).SetFrac64(units, 730).FloatString(12)
		}
		q, _ := new(big.Rat).SetString(quantity)
		rate, _ := new(big.Rat).SetString(part.rate)
		amount := databaseInputMoney(new(big.Rat).Mul(q, rate))
		sku := fmt.Sprintf("SYNTHETICS3%02d", index)
		rows = append(rows, model.Document{"identity_line_item_id": fmt.Sprintf("synthetic-s3-%s-%02d-%d", strings.TrimPrefix(arn, "arn:aws:s3:::"), index, at.Unix()), "line_item_usage_account_id": "111122223333", "line_item_resource_id": arn, "line_item_currency_code": "USD", "line_item_line_item_type": "Usage", "line_item_usage_start_date": at.Format(time.RFC3339), "line_item_usage_end_date": at.Add(time.Hour).Format(time.RFC3339), "line_item_unblended_cost": amount, "line_item_net_unblended_cost": amount, "line_item_unblended_rate": part.rate, "line_item_net_unblended_rate": part.rate, "line_item_usage_amount": quantity, "line_item_usage_type": "EU-" + part.usage, "line_item_operation": part.operation, "product_servicecode": "AmazonS3", "product_product_family": "Storage", "product_storage_class": part.class, "product_region_code": "eu-west-1", "product_sku": sku, "pricing_term": "OnDemand", "pricing_unit": part.unit, "pricing_rate_code": sku + ".SYNTHETIC.0"})
	}
	for at := start; at.Before(end); at = at.Add(time.Hour) {
		for _, arn := range []string{positive, blocked, review} {
			add(arn, 0, parts[0], at, 1000)
		}
		for index, part := range parts {
			if index == 0 {
				continue
			}
			add("arn:aws:s3:::synthetic-customer-rate-witness", index, part, at, 1)
		}
	}
	for _, charge := range []struct{ id, service, kind, resource, cost string }{{"unsupported", "AmazonDynamoDB", "Usage", "arn:aws:dynamodb:eu-west-1:111122223333:table/unassessed", "7"}, {"unowned-s3", "AmazonS3", "Usage", "arn:aws:s3:::synthetic-unowned-native-bucket", "4"}, {"credit", "AWSSupport", "Credit", "", "-2"}, {"resource-less", "AWSSupport", "Fee", "", "3"}} {
		rows = append(rows, model.Document{"identity_line_item_id": "synthetic-s3-coverage-" + charge.id, "line_item_usage_account_id": "111122223333", "line_item_resource_id": charge.resource, "line_item_currency_code": "USD", "line_item_line_item_type": charge.kind, "line_item_usage_start_date": start.Format(time.RFC3339), "line_item_usage_end_date": end.Format(time.RFC3339), "line_item_unblended_cost": charge.cost, "line_item_net_unblended_cost": charge.cost, "line_item_operation": "SyntheticComponentCharge", "product_servicecode": charge.service, "product_region_code": "eu-west-1", "pricing_term": "OnDemand"})
	}
	return rows
}

func objectStorageNativeCatalogue(t *testing.T, objects map[string][]byte, rows []model.Document, effective time.Time) {
	t.Helper()
	for _, row := range rows {
		sku := model.String(row, "product_sku")
		if sku == "" {
			continue
		}
		key := "pricing/" + sku
		if _, ok := objects[key]; ok {
			continue
		}
		rateCode := model.String(row, "pricing_rate_code")
		product := model.Document{"product": model.Document{"sku": sku, "attributes": model.Document{"regionCode": "eu-west-1", "servicecode": "AmazonS3", "operation": row["line_item_operation"], "usagetype": row["line_item_usage_type"]}}, "publicationDate": effective.Format(time.RFC3339), "terms": model.Document{"OnDemand": model.Document{"synthetic-native-term": model.Document{"effectiveDate": effective.Format(time.RFC3339), "priceDimensions": model.Document{rateCode: model.Document{"rateCode": rateCode, "beginRange": "0", "endRange": "Inf", "unit": row["pricing_unit"], "appliesTo": []string{}, "pricePerUnit": model.Document{"USD": "999999.00"}}}}}}}
		encoded, e := json.Marshal(product)
		if e != nil {
			t.Fatal(e)
		}
		raw, e := json.Marshal(model.Document{"PriceList": []string{string(encoded)}})
		if e != nil {
			t.Fatal(e)
		}
		objects[key] = raw
	}
}

func objectStorageNativeBrowser(t *testing.T, ctx context.Context, f *mutationReplayFixture, analyst *store.Store, resources, datasets []model.Document, componentIDs map[string]string) {
	t.Helper()
	const binary = "/tmp/s3-finops"
	if os.Getenv("FINOPS_OBJECT_STORAGE_ASSESSOR_BINARY") != binary {
		t.Fatal("actual compiled storage analyst required")
	}
	info, err := os.Lstat(binary)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode()&0111 == 0 {
		t.Fatal("actual storage analyst executable unavailable")
	}
	log, err := os.OpenFile("/results/object-storage-analyst.log", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal("private analyst log unavailable")
	}
	defer log.Close()
	cmd := exec.CommandContext(ctx, binary, "--mode", "object-storage-assessor")
	cmd.Env = []string{"FIXTURE_MODE=true", "PORT=8098", "DATABASE_URL=" + analyst.Pool.Config().ConnConfig.ConnString(), "ECONOMICS_URL=" + os.Getenv("ECONOMICS_TEST_URL"), "ECONOMICS_TOKEN=" + os.Getenv("ECONOMICS_TEST_TOKEN")}
	for _, key := range []string{"OBJECT_REGION", "OBJECT_ENDPOINT", "OBJECT_BUCKET_RAW"} {
		value := os.Getenv(key)
		if value == "" {
			t.Fatal("fixture analyst object binding incomplete")
		}
		cmd.Env = append(cmd.Env, key+"="+value)
	}
	for _, pair := range [][2]string{{"OBJECT_ACCESS_KEY", "FINOPS_OBJECT_STORAGE_READER_ACCESS_KEY"}, {"OBJECT_SECRET_KEY", "FINOPS_OBJECT_STORAGE_READER_SECRET_KEY"}} {
		value := os.Getenv(pair[1])
		if value == "" {
			t.Fatal("version-only assessment object reader required")
		}
		cmd.Env = append(cmd.Env, pair[0]+"="+value)
	}
	cmd.Stdout, cmd.Stderr = log, log
	if err = cmd.Start(); err != nil {
		t.Fatal("actual storage analyst process failed to start")
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	processStopped := false
	defer func() {
		if !processStopped {
			_ = cmd.Process.Signal(syscall.SIGTERM)
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				_ = cmd.Process.Kill()
				<-done
			}
		}
	}()
	validator, err := auth.New(ctx, "http://localhost:8081/realms/finops", "finops", "http://keycloak:8080/realms/finops/protocol/openid-connect/certs")
	if err != nil {
		t.Fatal("normal OIDC validator unavailable")
	}
	listener, err := net.Listen("tcp", ":8097")
	if err != nil {
		t.Fatal("private normal API listener unavailable")
	}
	server := &http.Server{Handler: &API{Store: f.roles["api"], Auth: validator, Config: Config{Fixture: true}}, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 40 * time.Second, WriteTimeout: 40 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	apiDone := make(chan error, 1)
	go func() { apiDone <- server.Serve(listener) }()
	defer func() {
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
		if e := <-apiDone; e != nil && !errors.Is(e, http.ErrServerClosed) {
			t.Error("normal OIDC API stopped unexpectedly")
		}
	}()
	ids, datasetIDs := []string{}, []string{}
	for index, resource := range resources {
		ids = append(ids, model.String(resource, "id"))
		datasetIDs = append(datasetIDs, model.String(datasets[index], "id"))
	}
	ready, err := fleetCapacityBrowserWrite("/results/object-storage-native-ready.json", model.Document{"schema_version": "1", "tenant_id": f.tenant, "resource_ids": ids, "dataset_ids": datasetIDs})
	if err != nil {
		t.Fatal("native browser READY publication failed")
	}
	var proof struct {
		SchemaVersion string   `json:"schema_version"`
		TenantID      string   `json:"tenant_id"`
		ReadySHA256   string   `json:"ready_sha256"`
		AssessmentIDs []string `json:"assessment_ids"`
	}
	if err = fleetCapacityBrowserWait(ctx, "object-storage-native-browser-done.json", &proof); err != nil {
		t.Fatal("normal storage browser deadline")
	}
	if proof.SchemaVersion != "1" || proof.TenantID != f.tenant || proof.ReadySHA256 != source.BytesHash(ready) || len(proof.AssessmentIDs) != len(resources) {
		t.Fatal("normal storage browser result binding differs")
	}
	seen := map[string]bool{}
	for index, id := range proof.AssessmentIDs {
		if id == "" || seen[id] {
			t.Fatal("browser assessment IDs repeated")
		}
		seen[id] = true
		for _, old := range componentIDs {
			if old == id {
				t.Fatal("browser reused component assessment")
			}
		}
		code, record := fleetNativeHTTPGet(t, f, "object-storage-assessments/"+id, f.token(f.tenant, "s3-independent-verifier", "FINOPS_ADMIN"))
		assessment := databaseInputObject(record["assessment"])
		want := []string{"RECOMMENDED", "BLOCKED", "OBSERVATION_ONLY"}[index]
		if code != 200 || model.String(record, "resource_id") != ids[index] || model.String(record, "dataset_id") != datasetIDs[index] || model.String(assessment, "status") != want || model.String(assessment, "model_assessment_hash") == "" || index != 1 && !model.Bool(record, "current") {
			t.Fatal("actual browser publication differs from stored native result")
		}
		var actor string
		if err = f.roles["api"].Do(ctx, f.tenant, func(tx *store.Tx) error {
			return tx.QueryRow(ctx, "SELECT created_by FROM object_storage_assessments WHERE tenant_id=$1 AND id=$2", f.tenant, id).Scan(&actor)
		}); err != nil || actor == "" || actor == "s3-component-requester" {
			t.Fatal("normal OIDC browser requester was not independently persisted")
		}
	}
	if err = cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal("actual analyst shutdown signal failed")
	}
	select {
	case err = <-done:
		processStopped = true
		if err != nil {
			t.Fatal("actual analyst process did not stop cleanly")
		}
	case <-ctx.Done():
		t.Fatal("actual analyst shutdown deadline")
	}
}
