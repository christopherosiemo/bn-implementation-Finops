package workflow

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/native"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/objectstorage"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/provider"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/service"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/source"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/jackc/pgx/v5"
	"os"
	"sort"
	"strings"
	"time"
)

func objectStorageArchive(ctx context.Context, archive objectstorage.Archive, tenant, id string, document any) (model.Document, error) {
	raw, e := json.Marshal(document)
	if e != nil || len(raw) > objectstorage.RawChunkBytes {
		return nil, errors.New("S3_EVALUATION_SNAPSHOT_LIMIT")
	}
	ref, e := archive.Archive(ctx, tenant, "canonical", id, raw)
	if e != nil {
		return nil, e
	}
	read, e := archive.Read(ctx, tenant, ref)
	if e != nil || objectstorage.BytesHash(read) != objectstorage.BytesHash(raw) {
		return nil, errors.New("S3_EVIDENCE_ARCHIVE_DIFFERS")
	}
	return ref, nil
}
func objectStorageResource(ctx context.Context, tx *store.Tx, b objectstorage.Bucket, accountID any, discoveryRef model.Document) (model.Document, error) {
	var id string
	e := tx.QueryRow(ctx, "SELECT id FROM entities WHERE tenant_id=$1 AND kind='resources' AND document->>'provider'='AWS' AND document->>'provider_resource_id'=$2 AND document->>'account_id'=$3 AND document->>'region'=$4", tx.Tenant, b.ARN, b.AccountID, b.Region).Scan(&id)
	resource := model.Document{"provider": "AWS", "resource_type": "S3_BUCKET", "provider_resource_id": b.ARN, "account_id": b.AccountID, "region": b.Region, "configuration_authority": "UNKNOWN", "environment": "UNKNOWN", "eligibility": "OBSERVE_ONLY"}
	if e == nil {
		resource, e = tx.Get(ctx, "resources", id)
		if e != nil {
			return nil, e
		}
	} else if e != pgx.ErrNoRows {
		return nil, e
	}
	resource["name"] = b.Name
	resource["cloud_account_id"] = accountID
	resource["object_storage_configuration"] = b
	resource["object_storage_discovery_ref"] = discoveryRef
	resource["last_seen_at"] = b.ObservedAt
	resource["state"] = "OBSERVED"
	if id == "" {
		return tx.Create(ctx, "resources", resource)
	}
	return tx.Update(ctx, "resources", id, model.Number(resource, "version"), resource)
}
func collectObjectStorageDiscovery(ctx context.Context, a *Activities, tenant string, archive *native.Storage) error {
	if os.Getenv("S3_READONLY_ENABLED") != "true" || a.Config.Fixture {
		return nil
	}
	var accounts []model.Document
	if e := a.Store.Do(ctx, tenant, func(tx *store.Tx) error { var e error; accounts, e = tx.List(ctx, "cloud_accounts"); return e }); e != nil {
		return e
	}
	for _, account := range accounts {
		last, _ := time.Parse(time.RFC3339Nano, model.String(account, "s3_last_discovered_at"))
		if !last.IsZero() && time.Since(last) < 10*time.Minute {
			continue
		}
		id, region := model.String(account, "account_id"), model.String(account, "region")
		if !strings.Contains(a.Config.AWSReadRole, ":"+id+":") {
			continue
		}
		scope := objectstorage.Scope{TenantID: tenant, AccountID: id, Region: region}
		if objectstorage.ValidateScope(scope) != nil {
			continue
		}
		reader, e := provider.NewAWS(ctx, region, a.Config.AWSReadRole, a.Config.AWSExternalID)
		if e != nil {
			return e
		}
		readCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
		discovery, e := reader.S3Discover(readCtx, scope)
		cancel()
		if e != nil {
			return e
		}
		if !discovery.Complete || discovery.Scope != scope || discovery.RawSHA256 != objectstorage.BytesHash(discovery.Raw) {
			return errors.New("S3_NATIVE_DISCOVERY_INVALID")
		}
		rawRef, e := archive.Archive(ctx, tenant, "wire", "s3-discovery-"+discovery.RawSHA256, discovery.Raw)
		if e != nil {
			return e
		}
		read, e := archive.Read(ctx, tenant, rawRef)
		if e != nil || objectstorage.BytesHash(read) != discovery.RawSHA256 {
			return errors.New("S3_NATIVE_ARCHIVE_DIFFERS")
		}
		for _, bucket := range discovery.Buckets {
			if bucket.AccountID != id || bucket.Region != region {
				return errors.New("S3_BUCKET_PUBLISH_SCOPE_MISMATCH")
			}
			access := model.Document{"state": "ACCESS_UNKNOWN", "complete": false}
			accessRefs := []model.Document{}
			if b := objectstorage.Doc(bucket.Configurations["metrics"].Value); len(objectstorage.Rows(b["Configurations"])) > 0 {
				end := time.Now().UTC().Truncate(24 * time.Hour)
				metricCtx, stop := context.WithTimeout(ctx, 2*time.Minute)
				observed, metricError := reader.S3AccessMetrics(metricCtx, scope, bucket, end.Add(-30*24*time.Hour), end)
				stop()
				if metricError == nil {
					if raw, ok := observed["raw"].([]byte); ok {
						ref, e := archive.Archive(ctx, tenant, "wire", "s3-request-metrics-"+objectstorage.BytesHash(raw), raw)
						if e != nil {
							return e
						}
						again, e := archive.Read(ctx, tenant, ref)
						if e != nil || objectstorage.BytesHash(again) != objectstorage.BytesHash(raw) {
							return errors.New("S3_METRICS_ARCHIVE_DIFFERS")
						}
						delete(observed, "raw")
						access = observed
						accessRefs = append(accessRefs, model.Document{"kind": "AWS_S3_CONFIGURED_REQUEST_METRICS", "id": ref["key"], "version": ref["version_id"], "sha256": ref["body_sha256"], "archive": ref})
						flat := []model.Document{}
						for _, series := range objectstorage.Rows(observed["series"]) {
							for _, point := range objectstorage.Rows(series["points"]) {
								flat = append(flat, model.Document{"bucket": bucket.Name, "metric": series["metric"], "configuration_id": series["configuration_id"], "filter": series["filter"], "unit": series["unit"], "statistic": series["statistic"], "period_seconds": 3600, "point": point, "source_ref": accessRefs[0]})
							}
						}
						if e = archive.WriteObjectAccess(ctx, scope, objectstorage.Hash(observed), flat); e != nil {
							return e
						}
					}
				} else {
					access["reason_code"] = "NATIVE_S3_REQUEST_METRICS_UNAVAILABLE"
				}
			}
			if e = a.Store.Do(ctx, tenant, func(tx *store.Tx) error {
				bucketRef := model.Document{"kind": "AWS_S3_BUCKET_DISCOVERY", "id": rawRef["key"], "version": rawRef["version_id"], "sha256": rawRef["body_sha256"], "archive": rawRef}
				resource, e := objectStorageResource(ctx, tx, bucket, account["id"], bucketRef)
				if e != nil {
					return e
				}
				canonical := model.Document{"schema_version": "1", "resource_id": resource["id"], "account_id": id, "region": region, "config_hash": objectstorage.ConfigurationHash(bucket), "source_id": "", "source_version": discovery.RawSHA256, "observed_at": bucket.ObservedAt, "configuration": bucket, "inventory": model.Document{"complete": false, "status": "OBJECT_INVENTORY_NOT_COMMISSIONED", "row_count": nil}, "cohorts": objectstorage.MultipartCohorts(bucket, bucket.ObservedAt, bucketRef), "access": model.Document{"state": "ACCESS_UNKNOWN", "complete": false}, "source_refs": []model.Document{bucketRef}}
				canonical["access"] = access
				canonical["source_refs"] = append(objectstorage.Rows(canonical["source_refs"]), accessRefs...)
				ref, e := objectStorageArchive(ctx, archive, tenant, "s3-evaluation-"+objectstorage.Hash(canonical), canonical)
				if e != nil {
					return e
				}
				_, e = tx.ObjectStorageEvidenceCreate(ctx, model.String(resource, "id"), "", canonical, ref)
				return e
			}); e != nil {
				return e
			}
		}
		if e = a.Store.Do(ctx, tenant, func(tx *store.Tx) error {
			current, e := tx.Get(ctx, "cloud_accounts", model.String(account, "id"))
			if e != nil {
				return e
			}
			current["s3_last_discovered_at"] = model.Now()
			_, e = tx.Update(ctx, "cloud_accounts", model.String(current, "id"), model.Number(current, "version"), current)
			return e
		}); e != nil {
			return e
		}
	}
	return nil
}
func objectStorageTick(ctx context.Context, a *Activities, tenant string) error {
	if a.Config.Fixture {
		return nil
	}
	var registrations []model.Document
	if e := a.Store.Do(ctx, tenant, func(tx *store.Tx) error { var e error; registrations, e = tx.SourceList(ctx); return e }); e != nil {
		return e
	}
	enabled := os.Getenv("S3_READONLY_ENABLED") == "true"
	for _, d := range registrations {
		if strings.HasPrefix(model.String(d, "kind"), "AWS_S3_") && model.Bool(d, "enabled") {
			enabled = true
		}
	}
	if !enabled {
		return nil
	}
	archive, e := native.StorageFromEnvironment(ctx, false)
	if e != nil {
		return e
	}
	if e = collectObjectStorageDiscovery(ctx, a, tenant, archive); e != nil {
		return e
	}
	encoded := os.Getenv("AWS_OBJECT_STORAGE_READ_BINDINGS_JSON")
	if encoded == "" {
		encoded = os.Getenv("AWS_SOURCE_READ_BINDINGS_JSON")
	}
	factory, e := source.ObjectStorageAWSFactory(encoded)
	if e != nil {
		return e
	}
	var first error
	for _, d := range registrations {
		if !strings.HasPrefix(model.String(d, "kind"), "AWS_S3_") || !model.Bool(d, "enabled") || model.Bool(d, "revoked") {
			continue
		}
		last, _ := time.Parse(time.RFC3339Nano, model.String(d, "last_sync_at"))
		if !last.IsZero() && time.Since(last) < time.Minute {
			continue
		}
		r, e := objectstorage.ParseRegistration(d)
		if e == nil {
			e = syncObjectStorageSource(ctx, a, r, factory, archive)
		}
		if e != nil && first == nil {
			first = e
		}
	}
	return first
}
func syncObjectStorageSource(ctx context.Context, a *Activities, r objectstorage.Registration, factory func(context.Context, objectstorage.Registration) (*provider.ObjectStorageAWS, error), archive *native.Storage) (err error) {
	conn, e := a.Store.Pool.Acquire(ctx)
	if e != nil {
		return e
	}
	defer conn.Release()
	lock := "s3-source:" + r.TenantID + ":" + r.ID
	var held bool
	if e = conn.QueryRow(ctx, "SELECT pg_try_advisory_lock(hashtextextended($1,0))", lock).Scan(&held); e != nil || !held {
		return e
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_, _ = conn.Exec(cleanup, "SELECT pg_advisory_unlock(hashtextextended($1,0))", lock)
	}()
	status := model.Document{"status": "SYNCING", "reason_code": "S3_SOURCE_SYNC_IN_PROGRESS", "last_sync_version": r.Version, "config_hash": objectstorage.Hash(r), "last_sync_at": model.Now()}
	save := func(key string, document model.Document) error {
		return a.Store.Do(ctx, r.TenantID, func(tx *store.Tx) error { return tx.SourceCheckpointSet(ctx, r.ID, key, document) })
	}
	if e = save("status", status); e != nil {
		return e
	}
	defer func() {
		if err != nil {
			status["status"] = "BLOCKED"
			status["reason_code"] = "S3_SOURCE_EVIDENCE_UNAVAILABLE"
		}
		status["last_sync_at"] = model.Now()
		if e := save("status", status); err == nil {
			err = e
		}
	}()
	reader, e := factory(ctx, r)
	if e != nil {
		return e
	}
	readCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	keys, e := reader.S3ManifestKeys(readCtx, r)
	if e != nil {
		return e
	}
	sort.Sort(sort.Reverse(sort.StringSlice(keys)))
	if len(keys) == 0 {
		return errors.New("S3_INVENTORY_DELIVERY_NOT_OBSERVED")
	}
	identityKey, _ := hex.DecodeString(os.Getenv("S3_OBJECT_IDENTITY_KEY_HEX"))
	pipeline := objectstorage.InventoryPipeline{Reader: reader, Archive: archive, Facts: archive, IdentityKey: identityKey, IdentityKeyVersion: os.Getenv("S3_OBJECT_IDENTITY_KEY_VERSION"), LoadCheckpoint: func(ctx context.Context, key string) (model.Document, error) {
		var out model.Document
		e := a.Store.Do(ctx, r.TenantID, func(tx *store.Tx) error {
			var e error
			out, e = tx.SourceCheckpointGet(ctx, r.ID, key)
			if e == pgx.ErrNoRows {
				return nil
			}
			return e
		})
		return out, e
	}, SaveCheckpoint: func(ctx context.Context, key string, d model.Document) error { return save(key, d) }}
	var generation objectstorage.Generation
	if r.Kind == objectstorage.InventoryKind {
		generation, e = pipeline.Ingest(readCtx, r, keys[0])
	} else {
		generation, e = pipeline.IngestAnalysis(readCtx, r, keys[0])
	}
	if e != nil {
		return e
	}
	if r.Kind == objectstorage.AccessKind {
		if e = archive.WriteObjectAccess(readCtx, generation.Scope, generation.SourceVersion, objectstorage.Rows(generation.Access["observations"])); e != nil {
			return e
		}
	}
	// Re-observing the same authenticated provider generation must preserve an
	// independently joined access snapshot and its immutable issued receipt.
	var issued bool
	if e = a.Store.Do(ctx, r.TenantID, func(tx *store.Tx) error {
		current, e := tx.SourceGet(ctx, r.ID)
		if e != nil {
			return e
		}
		parsed, e := objectstorage.ParseRegistration(current)
		if e != nil || !parsed.Enabled || model.Bool(current, "revoked") || objectstorage.Hash(parsed) != objectstorage.Hash(r) {
			return errors.New("S3_SOURCE_REGISTRATION_CHANGED")
		}
		_, e = tx.SourceReceiptGet(ctx, "receipt-"+generation.SourceVersion)
		if e == pgx.ErrNoRows {
			return nil
		}
		if e == nil {
			issued = true
		}
		return e
	}); e != nil {
		return e
	}
	if issued {
		status["status"] = "HEALTHY"
		status["reason_code"] = "NATIVE_S3_GENERATION_ALREADY_PERSISTED"
		status["latest_revision_id"] = "revision-" + generation.SourceVersion
		status["latest_receipt_id"] = "receipt-" + generation.SourceVersion
		return nil
	}
	var resource model.Document
	e = a.Store.Do(ctx, r.TenantID, func(tx *store.Tx) error {
		var id string
		e := tx.QueryRow(ctx, "SELECT id FROM entities WHERE tenant_id=$1 AND kind='resources' AND document->>'resource_type'='S3_BUCKET' AND document->>'provider_resource_id'=$2 AND document->>'account_id'=$3 AND document->>'region'=$4", r.TenantID, "arn:aws:s3:::"+r.Bucket, r.AccountID, r.Region).Scan(&id)
		if e != nil {
			return e
		}
		resource, e = tx.Get(ctx, "resources", id)
		return e
	})
	if e == pgx.ErrNoRows {
		discovery, readError := reader.S3DescribeBucket(readCtx, objectstorage.Scope{TenantID: r.TenantID, AccountID: r.AccountID, Region: r.Region}, r.Bucket)
		if readError != nil {
			return readError
		}
		if !discovery.Complete || len(discovery.Buckets) != 1 || discovery.RawSHA256 != objectstorage.BytesHash(discovery.Raw) {
			return errors.New("S3_REGISTERED_BUCKET_DISCOVERY_INVALID")
		}
		ref, archiveError := archive.Archive(ctx, r.TenantID, "wire", "s3-discovery-"+discovery.RawSHA256, discovery.Raw)
		if archiveError != nil {
			return archiveError
		}
		again, archiveError := archive.Read(ctx, r.TenantID, ref)
		if archiveError != nil || objectstorage.BytesHash(again) != discovery.RawSHA256 {
			return errors.New("S3_NATIVE_ARCHIVE_DIFFERS")
		}
		sourceRef := model.Document{"kind": "AWS_S3_BUCKET_DISCOVERY", "id": ref["key"], "version": ref["version_id"], "sha256": ref["body_sha256"], "archive": ref}
		e = a.Store.Do(ctx, r.TenantID, func(tx *store.Tx) error {
			var e error
			resource, e = objectStorageResource(ctx, tx, discovery.Buckets[0], nil, sourceRef)
			return e
		})
	}
	if e != nil {
		return e
	}
	configuration := objectstorage.Bucket{}
	raw, _ := json.Marshal(resource["object_storage_configuration"])
	if json.Unmarshal(raw, &configuration) != nil {
		return errors.New("S3_BUCKET_CONFIGURATION_UNAVAILABLE")
	}
	canonical := objectstorage.CanonicalSnapshot(model.String(resource, "id"), configuration, r, generation, objectstorage.Doc(resource["object_storage_discovery_ref"]))
	if r.Kind == objectstorage.InventoryKind {
		var skus []string
		catalogueError := a.Store.Do(ctx, r.TenantID, func(tx *store.Tx) error {
			var e error
			skus, e = service.CurrentObjectStorageSKUs(ctx, tx, r.AccountID, r.Region)
			return e
		})
		dimensions := model.Document{"status": "UNAVAILABLE", "reason_code": "AUTHENTICATED_CUR_SKU_OR_NATIVE_DIMENSIONS_UNAVAILABLE", "dimensions": []model.Document{}}
		if catalogueError == nil && len(skus) > 0 {
			nativeDimensions, readError := reader.S3PriceDimensions(readCtx, objectstorage.Scope{TenantID: r.TenantID, AccountID: r.AccountID, Region: r.Region}, skus)
			if readError == nil {
				if raw, ok := nativeDimensions["raw"].([]byte); ok {
					ref, e := archive.Archive(ctx, r.TenantID, "wire", "s3-price-dimensions-"+objectstorage.BytesHash(raw), raw)
					if e != nil {
						return e
					}
					again, e := archive.Read(ctx, r.TenantID, ref)
					if e != nil || objectstorage.BytesHash(again) != objectstorage.BytesHash(raw) {
						return errors.New("S3_PRICE_DIMENSION_ARCHIVE_DIFFERS")
					}
					delete(nativeDimensions, "raw")
					nativeDimensions["status"] = "OBSERVED"
					sourceRef := model.Document{"kind": "AWS_S3_NATIVE_PRICE_DIMENSIONS", "id": ref["key"], "version": ref["version_id"], "sha256": ref["body_sha256"], "archive": ref}
					nativeDimensions["source_ref"] = sourceRef
					dimensions = nativeDimensions
					canonical["source_refs"] = append(objectstorage.Rows(canonical["source_refs"]), sourceRef)
				}
			}
		}
		canonical["pricing_dimensions"] = dimensions
	}
	if r.Kind == objectstorage.AccessKind {
		var previous model.Document
		e = a.Store.Do(ctx, r.TenantID, func(tx *store.Tx) error {
			var e error
			previous, e = tx.ObjectStorageEvidenceLatest(ctx, model.String(resource, "id"))
			if e == pgx.ErrNoRows {
				return nil
			}
			return e
		})
		if e != nil {
			return e
		}
		if previous != nil {
			priorRaw, e := archive.Read(ctx, r.TenantID, objectstorage.Doc(previous["archive"]))
			if e != nil {
				return e
			}
			prior := model.Document{}
			if json.Unmarshal(priorRaw, &prior) != nil || prior["config_hash"] != canonical["config_hash"] || prior["account_id"] != r.AccountID || prior["region"] != r.Region {
				return errors.New("S3_ANALYTICS_POPULATION_BINDING_MISMATCH")
			}
			canonical["inventory"] = prior["inventory"]
			canonical["cohorts"] = prior["cohorts"]
			canonical["dataset_bindings"] = prior["dataset_bindings"]
			canonical["pricing_dimensions"] = prior["pricing_dimensions"]
			refs := []model.Document{}
			for _, ref := range objectstorage.Rows(prior["source_refs"]) {
				if strings.HasPrefix(model.String(ref, "kind"), "AWS_S3_INVENTORY") || model.String(ref, "kind") == "AWS_S3_REPORT_BOUNDARY" || strings.Contains(model.String(ref, "kind"), "PRIC") || model.String(ref, "kind") == "AWS_S3_BUCKET_DISCOVERY" {
					refs = append(refs, ref)
				}
			}
			canonical["source_refs"] = append(refs, generation.SourceRefs...)
			bindings := []model.Document{}
			for _, b := range objectstorage.Rows(prior["source_bindings"]) {
				if model.String(b, "source_id") != r.ID {
					bindings = append(bindings, b)
				}
			}
			canonical["source_bindings"] = append(bindings, objectstorage.Rows(canonical["source_bindings"])...)
		}
	}
	ref, e := objectStorageArchive(ctx, archive, r.TenantID, "s3-evaluation-"+objectstorage.Hash(canonical), canonical)
	if e != nil {
		return e
	}
	e = a.Store.Do(ctx, r.TenantID, func(tx *store.Tx) error {
		current, e := tx.SourceGet(ctx, r.ID)
		if e != nil {
			return e
		}
		parsed, e := objectstorage.ParseRegistration(current)
		if e != nil || !parsed.Enabled || model.Bool(current, "revoked") || objectstorage.Hash(parsed) != objectstorage.Hash(r) {
			return errors.New("S3_SOURCE_REGISTRATION_CHANGED")
		}
		receiptID := "receipt-" + generation.SourceVersion
		revisionID := "revision-" + generation.SourceVersion
		if _, e = tx.SourceRevisionGet(ctx, revisionID); e == pgx.ErrNoRows {
			_, e = tx.SourceRevisionCreate(ctx, model.Document{"id": revisionID, "source_id": r.ID, "revision_hash": generation.SourceVersion, "kind": r.Kind, "config_hash": objectstorage.Hash(r), "source_version": generation.SourceVersion, "source_refs": generation.SourceRefs, "generation_id": generation.ID})
		}
		if e != nil {
			return e
		}
		if _, e = tx.SourceReceiptGet(ctx, receiptID); e == pgx.ErrNoRows {
			_, e = tx.SourceReceiptCreate(ctx, model.Document{"id": receiptID, "source_id": r.ID, "revision_id": revisionID, "kind": r.Kind, "config_hash": objectstorage.Hash(r), "registration_version": r.Version, "generation_id": generation.ID, "source_version": generation.SourceVersion, "complete": true, "observed_at": generation.ObservedAt, "source_refs": generation.SourceRefs, "canonical_hash": ref["body_sha256"], "snapshot_archive": ref})
		}
		if e != nil {
			return e
		}
		_, e = tx.ObjectStorageEvidenceCreate(ctx, model.String(resource, "id"), r.ID, canonical, ref)
		if e != nil {
			return e
		}
		if e = tx.Audit(ctx, "object-storage-ingester", "object_storage.evidence.published", generation.ID, model.Document{"source_id": r.ID, "resource_id": resource["id"], "row_count": generation.Inventory["row_count"], "execution_authorized": false}); e != nil {
			return e
		}
		return tx.Event(ctx, "object_storage.evidence.published", model.Document{"source_id": r.ID, "generation_id": generation.ID, "resource_id": resource["id"]})
	})
	if e != nil {
		return e
	}
	status["status"] = "HEALTHY"
	status["reason_code"] = "NATIVE_S3_INVENTORY_PERSISTED"
	status["latest_revision_id"] = "revision-" + generation.SourceVersion
	status["latest_receipt_id"] = "receipt-" + generation.SourceVersion
	return nil
}
