package workflow

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/awsservice"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/native"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/provider"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/source"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/telemetry"
	"github.com/jackc/pgx/v5"
	"os"
	"time"
)

type AWSServiceReader interface {
	ServiceInventory(context.Context, awsservice.Registration, string, string) (awsservice.Collection, error)
}

func awsServiceRegistrationCurrent(ctx context.Context, tx *store.Tx, r awsservice.Registration) error {
	current, e := tx.SourceGet(ctx, r.ID)
	if e != nil {
		return e
	}
	parsed, e := awsservice.ParseRegistration(current)
	if e != nil || !parsed.Enabled || model.Bool(current, "revoked") || awsservice.Hash(parsed) != awsservice.Hash(r) {
		return errors.New("AWS_SERVICE_SOURCE_CHANGED_OR_REVOKED")
	}
	return nil
}
func awsServiceArchive(ctx context.Context, s *native.Storage, tenant, kind string, raw []byte) (model.Document, error) {
	if len(raw) == 0 || len(raw) > awsservice.MaxCaptureBytes {
		return nil, awsservice.ErrEvidence
	}
	ref, e := s.Archive(ctx, tenant, kind, "aws-service-"+awsservice.BytesHash(raw), raw)
	if e != nil {
		return nil, e
	}
	read, e := s.Read(ctx, tenant, ref)
	if e != nil || awsservice.BytesHash(read) != awsservice.BytesHash(raw) {
		return nil, errors.New("AWS_SERVICE_ARCHIVE_READBACK_DIFFERS")
	}
	return ref, nil
}

// PublishAWSServiceCollection archives before publishing authority, then uses
// short tenant transactions for each canonical resource and immutable snapshot.
// Existing ownership/configuration authority and Network LB metadata survive.
func PublishAWSServiceCollection(ctx context.Context, db *store.Store, s *native.Storage, r awsservice.Registration, generation string, c awsservice.Collection) ([]model.Document, error) {
	if awsservice.ValidateRegistration(r) != nil || !r.Enabled || c.Scope != (awsservice.Scope{TenantID: r.TenantID, AccountID: r.AccountID, Region: r.Region}) || !awsservice.Contains(r.ServiceFamilies, c.Family) || len(c.Resources) > awsservice.MaxRows || len(c.Raw) == 0 || len(c.Raw) > awsservice.MaxCaptureBytes || c.RawSHA256 != awsservice.BytesHash(c.Raw) || generation == "" {
		return nil, awsservice.ErrEvidence
	}
	rawRefs := []model.Document{}
	for first := 0; first < len(c.Raw); first += awsservice.MaxPageBytes {
		last := min(first+awsservice.MaxPageBytes, len(c.Raw))
		ref, e := awsServiceArchive(ctx, s, r.TenantID, "wire", c.Raw[first:last])
		if e != nil {
			return nil, e
		}
		rawRefs = append(rawRefs, ref)
	}
	// Keep immutable delivery references even when the page has no resources.
	// Delivery is not inventory publication or historical/financial absence.
	if e := db.Do(ctx, r.TenantID, func(tx *store.Tx) error {
		if e := awsServiceRegistrationCurrent(ctx, tx, r); e != nil {
			return e
		}
		revisionHash := awsservice.Hash(model.Document{"registration": r, "generation": generation, "family": c.Family, "raw": c.RawSHA256, "next_cursor": c.NextCursor, "reason_codes": c.Reasons})
		revisionID, receiptID := "aws-service-revision-"+revisionHash, "aws-service-receipt-"+revisionHash
		if _, e := tx.SourceReceiptGet(ctx, receiptID); e == nil {
			return nil
		} else if !errors.Is(e, pgx.ErrNoRows) {
			return e
		}
		if _, e := tx.SourceRevisionCreate(ctx, model.Document{"id": revisionID, "source_id": r.ID, "kind": awsservice.NativeKind, "revision_hash": revisionHash, "registration_version": r.Version, "config_hash": awsservice.Hash(r), "family": c.Family, "generation_id": generation, "raw_sha256": c.RawSHA256, "raw_refs": rawRefs}); e != nil {
			return e
		}
		_, e := tx.SourceReceiptCreate(ctx, model.Document{"id": receiptID, "source_id": r.ID, "revision_id": revisionID, "kind": awsservice.NativeKind, "registration_version": r.Version, "family": c.Family, "generation_id": generation, "raw_sha256": c.RawSHA256, "raw_refs": rawRefs, "collected_at": c.CollectedAt, "collection_complete": c.Complete, "next_cursor": c.NextCursor, "reason_codes": c.Reasons, "publication_status": "DELIVERY_ONLY", "observation_basis": "BOUNDED_NON_ATOMIC_SANITIZED_AWS_SERVICE_POINT_READ", "execution_authorized": false, "verified_saving": nil})
		return e
	}); e != nil {
		return nil, e
	}
	published := []model.Document{}
	for _, row := range c.Resources {
		if row["provider"] != "AWS" || row["account_id"] != r.AccountID || row["region"] != r.Region || row["service_family"] != c.Family || !awsservice.Contains(awsservice.ResourceTypes, model.String(row, "resource_type")) || !awsservice.BoundARN(c.Scope, model.String(row, "provider_resource_id")) {
			return nil, awsservice.ErrEvidence
		}
		var resource model.Document
		e := db.Do(ctx, r.TenantID, func(tx *store.Tx) error {
			if e := awsServiceRegistrationCurrent(ctx, tx, r); e != nil {
				return e
			}
			if _, e := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", tx.Tenant+":dependency-graph"); e != nil {
				return e
			}
			var id string
			err := tx.QueryRow(ctx, `SELECT id FROM entities WHERE tenant_id=$1 AND kind='resources' AND document->>'provider'='AWS' AND document->>'account_id'=$2 AND document->>'region'=$3 AND document->>'provider_resource_id'=$4`, tx.Tenant, r.AccountID, r.Region, row["provider_resource_id"]).Scan(&id)
			d := model.Document{"owner": nil, "workload_id": nil, "configuration_authority": "UNKNOWN", "environment": "UNKNOWN"}
			version := int64(0)
			if err == nil {
				d, err = tx.Get(ctx, "resources", id)
				if err != nil {
					return err
				}
				version = model.Number(d, "version")
			} else if err != pgx.ErrNoRows {
				return err
			}
			for _, key := range []string{"provider", "resource_type", "provider_resource_id", "account_id", "region", "name", "state", "service_family", "aws_service_configuration"} {
				if value, ok := row[key]; ok {
					d[key] = value
				}
			}
			relationships := []model.Document{}
			for _, old := range awsservice.Rows(d["provider_relationships"]) {
				if model.String(old, "basis") != "NATIVE_AWS_SERVICE_POINT_RELATIONSHIP" {
					relationships = append(relationships, old)
				}
			}
			relationships = append(relationships, awsservice.Rows(row["provider_relationships"])...)
			d["provider_relationships"], d["last_seen_at"], d["eligibility"] = relationships, c.CollectedAt, "OBSERVE_ONLY"
			if _, ok := d["cost_status"]; !ok {
				d["cost_status"] = "UNAVAILABLE"
			}
			if _, ok := d["spend_coverage"]; !ok {
				d["spend_coverage"] = "OBSERVATION_ONLY"
			}
			if _, ok := d["estimated_monthly_cost"]; !ok {
				d["estimated_monthly_cost"] = nil
			}
			d["verified_saving"], d["execution_authorized"], d["pre_execution_ready"] = nil, false, false
			d["aws_service_source_id"], d["aws_service_registration_version"], d["aws_service_generation_id"] = r.ID, r.Version, generation
			if version == 0 {
				resource, err = tx.Create(ctx, "resources", d)
			} else {
				resource, err = tx.Update(ctx, "resources", id, version, d)
			}
			if err == nil {
				err = retainAWSServiceManagement(ctx, tx, r, generation, row)
			}
			return err
		})
		if e != nil {
			return nil, e
		}
		configHash := awsservice.ConfigurationHash(resource)
		canonical := model.Document{"schema_version": "1", "kind": "AWS_SERVICE_NATIVE_SNAPSHOT_V1", "tenant_id": r.TenantID, "resource_id": resource["id"], "source_id": r.ID, "registration_version": r.Version, "generation_id": generation, "family": c.Family, "account_id": r.AccountID, "region": r.Region, "config_hash": configHash, "observed_at": c.CollectedAt, "collection_complete": c.Complete, "collection_reason_codes": c.Reasons, "resource": resource, "raw_refs": rawRefs, "read_only": true, "execution_authorized": false, "verified_saving": nil}
		raw, e := json.Marshal(canonical)
		if e != nil {
			return nil, e
		}
		archive, e := awsServiceArchive(ctx, s, r.TenantID, "canonical", raw)
		if e != nil {
			return nil, e
		}
		// One bounded inventory fact per canonical resource; no task-observation or
		// invocation rows are inserted into PostgreSQL.
		at := c.CollectedAt
		if at.IsZero() {
			return nil, awsservice.ErrEvidence
		}
		binding := telemetry.Binding{TenantID: r.TenantID, Provider: "AWS", ResourceID: model.String(resource, "id"), ProviderResourceID: model.String(resource, "provider_resource_id"), AccountID: r.AccountID, Region: r.Region, WorkloadID: model.String(resource, "workload_id")}
		sample := telemetry.Sample{ID: awsservice.Hash(model.Document{"registration": r, "generation": generation, "resource": resource["id"], "config_hash": configHash}), DefinitionID: "AWS_SERVICE_INVENTORY_V1", StreamID: r.ID, Metric: "AWS_SERVICE_CONFIGURATION", Type: "OBSERVATION", Unit: "native", Statistic: "SOURCE_RECORD", Temporality: "OBSERVED_NATIVE_RECORD", StartTime: at, Time: at, RawSHA256: c.RawSHA256, OriginalAttributes: model.Document{"family": c.Family, "resource_type": resource["resource_type"], "config_hash": configHash, "generation_id": generation, "collection_complete": c.Complete, "missing_is_zero": false}}
		ack, e := s.WriteFacts(ctx, r.TenantID, "aws-service-"+sample.ID, telemetry.Batch{SchemaVersion: "1", ConnectionID: r.ID, ConfigHash: configHash, Binding: binding, SourceKind: awsservice.NativeKind, RawSHA256: c.RawSHA256, Samples: []telemetry.Sample{sample}, Start: at, End: at})
		if e != nil || model.Number(ack, "sample_count") != 1 {
			return nil, errors.New("AWS_SERVICE_ANALYTICS_ACK_DIFFERS")
		}
		summary := model.Document{"schema_version": "1", "kind": "AWS_SERVICE_NATIVE_SNAPSHOT_V1", "resource_id": resource["id"], "source_id": r.ID, "registration_version": r.Version, "generation_id": generation, "family": c.Family, "account_id": r.AccountID, "region": r.Region, "config_hash": configHash, "content_hash": archive["body_sha256"], "archive": archive, "raw_refs": rawRefs, "analytics": ack, "observed_at": c.CollectedAt, "collection_complete": c.Complete, "collection_reason_codes": c.Reasons, "relationships": relationshipsForSnapshot(resource), "execution_authorized": false, "verified_saving": nil}
		e = db.Do(ctx, r.TenantID, func(tx *store.Tx) error {
			if e := awsServiceRegistrationCurrent(ctx, tx, r); e != nil {
				return e
			}
			current, e := tx.Get(ctx, "resources", model.String(resource, "id"))
			if e != nil {
				return e
			}
			if awsservice.ConfigurationHash(current) != configHash {
				return errors.New("AWS_SERVICE_CONFIGURATION_CHANGED_DURING_PUBLICATION")
			}
			_, e = tx.AWSServiceEvidenceAppend(ctx, summary)
			if errors.Is(e, pgx.ErrNoRows) {
				return nil
			}
			return e
		})
		if e != nil {
			return nil, e
		}
		published = append(published, resource)
	}
	return published, nil
}
func relationshipsForSnapshot(r model.Document) []model.Document {
	out := []model.Document{}
	for _, rel := range awsservice.Rows(r["provider_relationships"]) {
		if model.String(rel, "basis") == "NATIVE_AWS_SERVICE_POINT_RELATIONSHIP" {
			out = append(out, rel)
		}
	}
	return out
}

// SyncAWSServiceSource advances one bounded family page. Registration revisions
// reset cursors; interrupted/nested-partial collections cannot become complete.
func SyncAWSServiceSource(ctx context.Context, a *Activities, s *native.Storage, reader AWSServiceReader, r awsservice.Registration) error {
	if awsservice.ValidateRegistration(r) != nil || !r.Enabled {
		return awsservice.ErrEvidence
	}
	// Refresh completed point inventories without treating a previous census as
	// continuously current. Cursor resets are private checkpoints, not source edits.
	if e := a.Store.Do(ctx, r.TenantID, func(tx *store.Tx) error {
		if e := awsServiceRegistrationCurrent(ctx, tx, r); e != nil {
			return e
		}
		current, e := tx.SourceGet(ctx, r.ID)
		if e != nil {
			return e
		}
		last, _ := time.Parse(time.RFC3339Nano, model.String(current, "last_sync_at"))
		if model.Number(current, "last_sync_version") == r.Version && !last.IsZero() && time.Since(last) >= 10*time.Minute {
			for _, family := range r.ServiceFamilies {
				if e = tx.SourceCheckpointSet(ctx, r.ID, "aws-service-"+family, model.Document{"registration_version": r.Version, "generation_id": model.ID(), "complete": false}); e != nil {
					return e
				}
			}
			return tx.SourceCheckpointSet(ctx, r.ID, "status", model.Document{"status": "SYNCING", "reason_code": "AWS_SERVICE_NATIVE_POINT_INVENTORY_REFRESH", "last_sync_version": r.Version, "config_hash": awsservice.Hash(r)})
		}
		return nil
	}); e != nil {
		return e
	}
	for _, family := range r.ServiceFamilies {
		checkpoint := model.Document{}
		e := a.Store.Do(ctx, r.TenantID, func(tx *store.Tx) error {
			if e := awsServiceRegistrationCurrent(ctx, tx, r); e != nil {
				return e
			}
			d, e := tx.SourceCheckpointGet(ctx, r.ID, "aws-service-"+family)
			if errors.Is(e, pgx.ErrNoRows) {
				return nil
			}
			if e != nil {
				return e
			}
			if model.Number(d, "registration_version") == r.Version {
				checkpoint = d
			}
			return nil
		})
		if e != nil {
			return e
		}
		if model.Bool(checkpoint, "complete") {
			continue
		}
		generation := model.String(checkpoint, "generation_id")
		if generation == "" {
			generation = model.ID()
		}
		collection, e := reader.ServiceInventory(ctx, r, family, model.String(checkpoint, "next_cursor"))
		if e != nil {
			return e
		}
		// Completeness belongs to the entire generation, not merely its last
		// page. A denied optional read on an earlier page remains a visible gap.
		collection = awsServiceGenerationCollection(checkpoint, collection)
		published, e := PublishAWSServiceCollection(ctx, a.Store, s, r, generation, collection)
		if e != nil {
			return e
		}
		e = a.Store.Do(ctx, r.TenantID, func(tx *store.Tx) error {
			if e := awsServiceRegistrationCurrent(ctx, tx, r); e != nil {
				return e
			}
			return tx.SourceCheckpointSet(ctx, r.ID, "aws-service-"+family, model.Document{"registration_version": r.Version, "generation_id": generation, "next_cursor": collection.NextCursor, "complete": collection.Complete, "page_exhausted": collection.NextCursor == "", "published_resources": len(published), "reason_codes": collection.Reasons, "observed_at": collection.CollectedAt})
		})
		if e != nil {
			return e
		}
	}
	return a.Store.Do(ctx, r.TenantID, func(tx *store.Tx) error {
		if e := awsServiceRegistrationCurrent(ctx, tx, r); e != nil {
			return e
		}
		allComplete, pagesExhausted := true, true
		for _, family := range r.ServiceFamilies {
			d, e := tx.SourceCheckpointGet(ctx, r.ID, "aws-service-"+family)
			if e != nil {
				return e
			}
			allComplete = allComplete && model.Bool(d, "complete")
			pagesExhausted = pagesExhausted && model.Bool(d, "page_exhausted")
		}
		status, reason := "SYNCING", "AWS_SERVICE_NATIVE_COLLECTION_IN_PROGRESS"
		if pagesExhausted {
			status, reason = "PARTIAL", "AWS_SERVICE_NATIVE_OPTIONAL_READS_INCOMPLETE"
		}
		if allComplete {
			status, reason = "HEALTHY", "AWS_SERVICE_NATIVE_INVENTORY_PERSISTED"
		}
		d := model.Document{"status": status, "reason_code": reason, "last_sync_version": r.Version, "config_hash": awsservice.Hash(r)}
		if pagesExhausted {
			d["last_sync_at"] = model.Now()
		}
		return tx.SourceCheckpointSet(ctx, r.ID, "status", d)
	})
}
func awsServiceTick(ctx context.Context, a *Activities, tenant string) error {
	if a.Config.Fixture {
		return nil
	}
	var registrations []model.Document
	e := a.Store.Do(ctx, tenant, func(tx *store.Tx) error { var e error; registrations, e = tx.SourceList(ctx); return e })
	if e != nil {
		return e
	}
	pending := []awsservice.Registration{}
	for _, d := range registrations {
		if d["kind"] != awsservice.NativeKind || !model.Bool(d, "enabled") || model.Bool(d, "revoked") {
			continue
		}
		r, e := awsservice.ParseRegistration(d)
		if e != nil {
			continue
		}
		last, _ := time.Parse(time.RFC3339Nano, model.String(d, "last_sync_at"))
		if model.Number(d, "last_sync_version") == r.Version && !last.IsZero() && time.Since(last) < 10*time.Minute {
			continue
		}
		if !model.Bool(d, "sync_requested") {
			continue
		}
		pending = append(pending, r)
	}
	if len(pending) == 0 {
		return nil
	}
	storage, e := native.StorageFromEnvironment(ctx, false)
	if e != nil {
		return e
	}
	encoded := os.Getenv("AWS_SERVICE_READ_BINDINGS_JSON")
	if encoded == "" {
		encoded = os.Getenv("AWS_SOURCE_READ_BINDINGS_JSON")
	}
	factory, e := source.AWSServiceFactory(encoded)
	if e != nil {
		return e
	}
	var first error
	for _, r := range pending {
		reader, e := factory(ctx, r)
		if e == nil {
			readCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
			e = SyncAWSServiceSource(readCtx, a, storage, reader, r)
			cancel()
		}
		if e != nil {
			_ = a.Store.Do(ctx, tenant, func(tx *store.Tx) error {
				return tx.SourceCheckpointSet(ctx, r.ID, "status", model.Document{"status": "BLOCKED", "reason_code": "AWS_SERVICE_NATIVE_READ_UNAVAILABLE", "last_sync_version": r.Version})
			})
			if first == nil {
				first = e
			}
		}
	}
	return first
}

var _ AWSServiceReader = (*provider.AWS)(nil)

func awsServiceReasons(values []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, v := range values {
		if v != "" && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

func awsServiceGenerationCollection(previous model.Document, current awsservice.Collection) awsservice.Collection {
	current.Reasons = awsServiceReasons(append(model.Strings(previous, "reason_codes"), current.Reasons...))
	if len(current.Reasons) > 0 {
		current.Complete = false
	}
	return current
}
