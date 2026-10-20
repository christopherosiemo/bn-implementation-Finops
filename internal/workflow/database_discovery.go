package workflow

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/native"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/provider"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/service"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/telemetry"
	"github.com/jackc/pgx/v5"
	"os"
	"sort"
	"strings"
	"time"
)

type databaseAWSReader interface {
	RDSDiscover(context.Context, provider.RDSScope) (provider.RDSDiscoveryEvidence, error)
	RDSCatalog(context.Context, provider.RDSScope, string) (provider.RDSCatalogEvidence, error)
	RDSParameters(context.Context, provider.RDSScope, string) (provider.RDSParameterEvidence, error)
	RDSMetrics(context.Context, provider.RDSScope, provider.RDSMetricSelection) (provider.RDSMetricEvidence, error)
	RDSDatabaseSavingsPlans(context.Context, provider.RDSScope) (provider.RDSCommitmentExposure, error)
	RDSComputeOptimizer(context.Context, provider.RDSScope, string) (provider.RDSOptimizerEvidence, error)
}
type databaseArchive interface {
	Archive(context.Context, string, string, string, []byte) (model.Document, error)
	Read(context.Context, string, model.Document) ([]byte, error)
	WriteFacts(context.Context, string, string, telemetry.Batch) (model.Document, error)
}

func databaseDocument(v any) (model.Document, error) {
	raw, e := json.Marshal(v)
	if e != nil {
		return nil, e
	}
	var out model.Document
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	e = d.Decode(&out)
	return out, e
}
func databasePeriod(profile model.Document, now time.Time) (time.Time, time.Time, []string) {
	days := 30
	reasons := []string{}
	if model.Bool(profile, "high_seasonality") {
		days = 90
	} else if model.String(profile, "criticality") == "NON_PRODUCTION" {
		days = 14
	} else if criticality := model.String(profile, "criticality"); criticality != "TIER_0" && criticality != "TIER_1" && criticality != "TIER_2" && criticality != "TIER_3" {
		reasons = append(reasons, "UNKNOWN_PROFILE_OBSERVE_ONLY_30_DAY_COLLECTION")
	}
	utc := now.UTC()
	end := time.Date(utc.Year(), utc.Month(), utc.Day(), 0, 0, 0, 0, time.UTC)
	return end.Add(-time.Duration(days) * 24 * time.Hour), end, reasons
}
func databaseArchiveReadback(ctx context.Context, storage databaseArchive, tenant, kind, id string, raw []byte) (model.Document, error) {
	if len(raw) == 0 || len(raw) > 128<<20 {
		return nil, errors.New("RDS_ARCHIVE_BUDGET")
	}
	ref, e := storage.Archive(ctx, tenant, kind, id, raw)
	if e != nil {
		return nil, e
	}
	if model.String(ref, "version_id") == "" || model.String(ref, "version_id") == "null" || model.String(ref, "body_sha256") != telemetry.BytesHash(raw) {
		return nil, errors.New("RDS_IMMUTABLE_ARCHIVE_REQUIRED")
	}
	read, e := storage.Read(ctx, tenant, ref)
	if e != nil || !bytes.Equal(raw, read) {
		return nil, errors.New("RDS_ARCHIVE_READBACK_DIFFERS")
	}
	return ref, nil
}
func databaseRaw(ctx context.Context, storage databaseArchive, tenant string, evidence provider.RDSReadEvidence) (model.Document, error) {
	if evidence.Scope.TenantID != tenant || evidence.RawSHA256 != telemetry.BytesHash(evidence.Raw) {
		return nil, errors.New("RDS_RAW_SCOPE_OR_HASH_DIFFERS")
	}
	if _, e := provider.RDSCaptureFrames(evidence.Raw); e != nil {
		return nil, e
	}
	return databaseArchiveReadback(ctx, storage, tenant, "wire", "rds-"+evidence.RawSHA256, evidence.Raw)
}
func databaseMetricBatches(resource model.Document, metrics provider.RDSMetricEvidence) ([]telemetry.Batch, error) {
	if len(metrics.Metrics) > telemetry.MaxSamples {
		return nil, errors.New("RDS_FULL_SAMPLE_BUDGET")
	}
	binding := telemetry.Binding{TenantID: metrics.Scope.TenantID, ResourceID: model.String(resource, "id"), WorkloadID: model.String(resource, "workload_id"), Provider: "AWS", ProviderResourceID: metrics.Selection.ResourceARN, AccountID: metrics.Scope.AccountID, Region: metrics.Scope.Region}
	if binding.ResourceID == "" || model.String(resource, "account_id") != binding.AccountID || model.String(resource, "region") != binding.Region {
		return nil, errors.New("RDS_FACT_BINDING_DIFFERS")
	}
	samples := make([]telemetry.Sample, 0, len(metrics.Metrics))
	for _, row := range metrics.Metrics {
		if model.String(row, "unknown_reason") != "" {
			continue
		}
		at, e := time.Parse(time.RFC3339Nano, model.String(row, "source_time"))
		if e != nil || at.Before(metrics.Selection.Start) || !at.Before(metrics.Selection.End) || model.String(row, "provider_resource_id") != binding.ProviderResourceID || model.Number(row, "period_seconds") != int64(metrics.Selection.PeriodSeconds) {
			return nil, errors.New("RDS_FACT_SOURCE_DIFFERS")
		}
		id := telemetry.Hash(model.Document{"arn": binding.ProviderResourceID, "metric": row["metric"], "time": row["source_time"], "statistic": row["statistic"], "raw_sha256": metrics.RawSHA256})
		samples = append(samples, telemetry.Sample{ID: id, DefinitionID: "AWS/RDS:" + model.String(row, "metric"), StreamID: binding.ProviderResourceID, Metric: model.String(row, "metric"), Type: "gauge", Unit: model.String(row, "unit"), Statistic: model.String(row, "statistic"), Temporality: "OBSERVED_PERIOD_STATISTIC", StartTime: at, Time: at, Attributes: map[string]string{}, ResourceAttributes: map[string]string{"provider_resource_id": binding.ProviderResourceID}, ScopeAttributes: map[string]string{"namespace": "AWS/RDS"}, OriginalAttributes: model.Clone(row), Value: model.String(row, "value"), RawSHA256: metrics.RawSHA256, SourceHashes: []string{model.String(row, "raw_page_sha256")}, ReasonCodes: []string{}})
	}
	batches := []telemetry.Batch{}
	for first := 0; first < len(samples); first += 5000 {
		last := min(first+5000, len(samples))
		batches = append(batches, telemetry.Batch{SchemaVersion: "1", ConnectionID: "rds-cloudwatch-" + binding.ResourceID, ConfigHash: service.DatabaseConfigurationHash(resource), Binding: binding, SourceKind: "RDS_CLOUDWATCH", RawSHA256: metrics.RawSHA256, CollectedAt: metrics.CollectedAt, Start: metrics.Selection.Start, End: metrics.Selection.End, Samples: samples[first:last], Rejections: []telemetry.Rejection{}, Warnings: []string{}})
	}
	return batches, nil
}
func databaseUpsert(ctx context.Context, t *store.Tx, row model.Document, cloudID any) (model.Document, error) {
	var id string
	e := t.QueryRow(ctx, "SELECT id FROM entities WHERE tenant_id=$1 AND kind='resources' AND document->>'provider'='AWS' AND document->>'account_id'=$2 AND document->>'region'=$3 AND document->>'provider_resource_id'=$4", t.Tenant, row["account_id"], row["region"], row["arn"]).Scan(&id)
	out := model.Document{}
	version := int64(0)
	if e == nil {
		old, e := t.Get(ctx, "resources", id)
		if e != nil {
			return nil, e
		}
		out = model.Clone(old)
		version = model.Number(old, "version")
	} else if e == pgx.ErrNoRows {
		id = model.ID()
		out = model.Document{"id": id, "configuration_authority": "UNKNOWN", "eligibility": "OBSERVE_ONLY"}
	} else {
		return nil, e
	}
	out["id"] = id
	out["provider"] = "AWS"
	out["resource_type"] = row["resource_type"]
	out["provider_resource_id"] = row["arn"]
	out["account_id"] = row["account_id"]
	out["region"] = row["region"]
	out["cloud_account_id"] = cloudID
	out["database_configuration"] = model.Clone(row)
	out["state"] = row["status"]
	out["last_seen_at"] = model.Now()
	if model.String(out, "name") == "" {
		out["name"] = row["identifier"]
	}
	if version == 0 {
		return t.Create(ctx, "resources", out)
	}
	return t.Update(ctx, "resources", id, version, out)
}
func databaseRelationships(row model.Document, byARN map[string]model.Document) []model.Document {
	out := []model.Document{}
	put := func(kind, arn string, writer any) {
		if arn == "" {
			return
		}
		var id any
		if r := byARN[arn]; r != nil {
			id = r["id"]
		}
		if id != nil {
			out = append(out, model.Document{"type": kind, "target_provider_resource_id": arn, "target_resource_id": id, "basis": "NATIVE_RDS_POINT_RELATIONSHIP"})
		}
	}
	nativeRow, _ := databaseDocument(row["database_configuration"])
	prefix := "arn:aws:rds:" + model.String(row, "region") + ":" + model.String(row, "account_id") + ":"
	if id := model.String(nativeRow, "cluster_identifier"); id != "" {
		put("MEMBER_OF", prefix+"cluster:"+id, nil)
	}
	if id := model.String(nativeRow, "read_replica_source_identifier"); id != "" {
		if !strings.HasPrefix(id, "arn:") {
			id = prefix + "db:" + id
		}
		put("DEPENDS_ON", id, nil)
	}
	// Cluster-native member records remain in database_configuration. No inverse
	// hard MEMBER_OF edges are created, avoiding a synthetic graph cycle.
	return out
}
func databaseQuality(ctx context.Context, t *store.Tx, id, status, reason string) error {
	d, e := t.Get(ctx, "data_quality", id)
	if e == nil {
		d["status"] = status
		d["reason_codes"] = []string{reason}
		d["observed_at"] = model.Now()
		_, e = t.Update(ctx, "data_quality", id, model.Number(d, "version"), d)
		return e
	}
	if e != pgx.ErrNoRows {
		return e
	}
	_, e = t.Create(ctx, "data_quality", model.Document{"id": id, "name": "Native RDS/Aurora evidence", "status": status, "reason_codes": []string{reason}, "message": "Read-only native database evidence; missing sources remain unavailable.", "observed_at": model.Now()})
	return e
}

// discoverRDSAccount is optional within the ordinary ingestion identity. A
// failed database read/archive cannot undo existing EC2 discoveries.
func discoverRDSAccount(ctx context.Context, a *Activities, t *store.Tx, client databaseAWSReader, account model.Document) error {
	scope := provider.RDSScope{TenantID: t.Tenant, AccountID: model.String(account, "account_id"), Region: model.String(account, "region")}
	if service.ValidateAWSTenant(t.Tenant) != nil {
		return nil
	}
	discovery, e := client.RDSDiscover(ctx, scope)
	qualityID := "quality-rds-" + scope.AccountID + "-" + scope.Region
	if e != nil {
		return databaseQuality(ctx, t, qualityID, "DEGRADED", "NATIVE_RDS_DISCOVERY_UNAVAILABLE")
	}
	rows := append(append([]model.Document{}, discovery.Instances...), discovery.Clusters...)
	byARN := map[string]model.Document{}
	for _, row := range rows {
		current, e := databaseUpsert(ctx, t, row, account["id"])
		if e != nil {
			return e
		}
		byARN[model.String(row, "arn")] = current
	}
	for arn, row := range byARN {
		row["provider_relationships"] = databaseRelationships(row, byARN)
		updated, e := t.Update(ctx, "resources", model.String(row, "id"), model.Number(row, "version"), row)
		if e != nil {
			return e
		}
		byARN[arn] = updated
	}
	if len(rows) == 0 {
		return databaseQuality(ctx, t, qualityID, "HEALTHY", "NATIVE_RDS_EMPTY_ACCOUNT_REGION_OBSERVED")
	}
	storage, e := native.StorageFromEnvironment(ctx, a.Config.Fixture)
	if e != nil {
		return databaseQuality(ctx, t, qualityID, "DEGRADED", "RDS_IMMUTABLE_STORAGE_UNAVAILABLE")
	}
	rawRef, e := databaseRaw(ctx, storage, t.Tenant, discovery.RDSReadEvidence)
	if e != nil {
		return databaseQuality(ctx, t, qualityID, "DEGRADED", "RDS_DISCOVERY_ARCHIVE_UNAVAILABLE")
	}
	exposure := model.Document{"status": "UNKNOWN_NOT_COMMISSIONED", "plans": nil, "raw_ref": nil}
	if os.Getenv("RDS_DATABASE_SAVINGS_PLAN_INVENTORY_ENABLED") == "true" {
		v, err := client.RDSDatabaseSavingsPlans(ctx, scope)
		if err != nil {
			exposure["status"] = "UNAVAILABLE"
		} else {
			ref, err := databaseRaw(ctx, storage, t.Tenant, v.RDSReadEvidence)
			if err != nil {
				return databaseQuality(ctx, t, qualityID, "DEGRADED", "RDS_DATABASE_PLAN_ARCHIVE_UNAVAILABLE")
			}
			exposure = model.Document{"status": "OBSERVED_ACCOUNT_ONLY_NOT_COMPLETE_PAYER_PORTFOLIO", "plans": v.Plans, "raw_ref": ref}
		}
	}
	failures := 0
	arns := []string{}
	for arn := range byARN {
		arns = append(arns, arn)
	}
	sort.Strings(arns)
	for _, arn := range arns {
		row := byARN[arn]
		latest, err := t.DatabaseEvidenceLatest(ctx, model.String(row, "id"))
		if err != nil && err != pgx.ErrNoRows {
			return err
		}
		if latest != nil && model.String(latest, "config_hash") == service.DatabaseConfigurationHash(row) {
			observed, _ := time.Parse(time.RFC3339Nano, model.String(latest, "observed_at"))
			if observed.After(time.Now().UTC().Add(-10 * time.Minute)) {
				continue
			}
		}
		if _, err = t.Exec(ctx, "SAVEPOINT rds_resource_capture"); err != nil {
			return err
		}
		err = collectDatabaseResource(ctx, t, client, storage, row, byARN, discovery, rawRef, exposure)
		if err != nil {
			failures++
			if _, err = t.Exec(ctx, "ROLLBACK TO SAVEPOINT rds_resource_capture"); err != nil {
				return err
			}
		}
		if _, err = t.Exec(ctx, "RELEASE SAVEPOINT rds_resource_capture"); err != nil {
			return err
		}
	}
	if failures > 0 {
		return databaseQuality(ctx, t, qualityID, "DEGRADED", "NATIVE_RDS_RESOURCE_EVIDENCE_UNAVAILABLE")
	}
	return databaseQuality(ctx, t, qualityID, "HEALTHY", "NATIVE_RDS_CAPTURED_NO_EXECUTION_AUTHORITY")
}
func collectDatabaseResource(ctx context.Context, t *store.Tx, client databaseAWSReader, storage databaseArchive, resource model.Document, byARN map[string]model.Document, discovery provider.RDSDiscoveryEvidence, discoveryRef, exposure model.Document) error {
	profile := model.Document{}
	if workload := model.String(resource, "workload_id"); workload != "" {
		p, e := t.WorkloadSafetyLatest(ctx, workload)
		if e != nil && e != pgx.ErrNoRows {
			return e
		}
		if p != nil {
			profile = p
		}
	}
	start, end, reasons := databasePeriod(profile, time.Now().UTC())
	scope := discovery.Scope
	arn := model.String(resource, "provider_resource_id")
	object := model.Document{"schema_version": "1", "resource": resource, "discovery": model.Document{"instances": discovery.Instances, "clusters": discovery.Clusters, "reserved_instances": discovery.ReservedInstances, "scope": scope, "raw_ref": discoveryRef}, "catalogs": model.Document{}, "parameters": model.Document{}, "metrics": []model.Document{}, "commitments": model.Document{"reserved_instances": discovery.ReservedInstances, "scope_basis": "ACCOUNT_REGION_NATIVE_RDS_RESERVATION_INVENTORY"}, "database_savings_plans": exposure, "collection_reason_codes": reasons, "period": model.Document{"start": start, "end": end}}
	observedAt := discovery.CollectedAt
	refs := []model.Document{discoveryRef}
	if ref, ok := exposure["raw_ref"].(model.Document); ok {
		refs = append(refs, ref)
	}
	targets := []string{arn}
	if model.String(resource, "resource_type") == "RDS_CLUSTER" {
		targets = []string{}
		nativeRow, _ := databaseDocument(resource["database_configuration"])
		members, _ := nativeRow["members"].([]any)
		for _, v := range members {
			m, _ := databaseDocument(v)
			memberARN := "arn:aws:rds:" + scope.Region + ":" + scope.AccountID + ":db:" + model.String(m, "identifier")
			if byARN[memberARN] == nil {
				return errors.New("RDS_COMPLETE_CLUSTER_MEMBER_BINDING_REQUIRED")
			}
			targets = append(targets, memberARN)
		}
		if len(targets) == 0 {
			return errors.New("RDS_EMPTY_CLUSTER_MEMBER_SCOPE")
		}
	}
	if len(targets) > 64 {
		return errors.New("RDS_MEMBER_CAPTURE_BOUND")
	}
	sort.Strings(targets)
	metricsObjects := []model.Document{}
	sampleTotal := 0
	metricTargets := append([]string{}, targets...)
	if model.String(resource, "resource_type") == "RDS_CLUSTER" {
		metricTargets = append(metricTargets, arn)
	}
	asset := provider.RDSDocumentedIOBaselineAsset()
	assetRef, e := databaseArchiveReadback(ctx, storage, t.Tenant, "wire", "rds-ebs-baseline-"+telemetry.BytesHash(asset), asset)
	if e != nil {
		return e
	}
	refs = append(refs, assetRef)
	for _, target := range targets {
		catalog, e := client.RDSCatalog(ctx, scope, target)
		if e != nil {
			return e
		}
		if catalog.CollectedAt.After(observedAt) {
			observedAt = catalog.CollectedAt
		}
		ref, e := databaseRaw(ctx, storage, t.Tenant, catalog.RDSReadEvidence)
		if e != nil {
			return e
		}
		refs = append(refs, ref)
		d, e := databaseDocument(catalog)
		if e != nil {
			return e
		}
		d["raw_ref"] = ref
		d["ebs_baseline_asset_ref"] = assetRef
		object["catalogs"].(model.Document)[target] = d
		parameters, e := client.RDSParameters(ctx, scope, target)
		if e != nil {
			return e
		}
		if parameters.CollectedAt.After(observedAt) {
			observedAt = parameters.CollectedAt
		}
		ref, e = databaseRaw(ctx, storage, t.Tenant, parameters.RDSReadEvidence)
		if e != nil {
			return e
		}
		refs = append(refs, ref)
		d, e = databaseDocument(parameters)
		if e != nil {
			return e
		}
		d["raw_ref"] = ref
		object["parameters"].(model.Document)[target] = d
	}
	for _, target := range metricTargets {
		metrics, e := client.RDSMetrics(ctx, scope, provider.RDSMetricSelection{ResourceARN: target, Start: start, End: end, PeriodSeconds: 3600})
		if e != nil {
			return e
		}
		if metrics.CollectedAt.After(observedAt) {
			observedAt = metrics.CollectedAt
		}
		sampleTotal += len(metrics.Metrics)
		if sampleTotal > telemetry.MaxSamples {
			return errors.New("RDS_FULL_SAMPLE_BUDGET")
		}
		ref, e := databaseRaw(ctx, storage, t.Tenant, metrics.RDSReadEvidence)
		if e != nil {
			return e
		}
		refs = append(refs, ref)
		d, e := databaseDocument(metrics)
		if e != nil {
			return e
		}
		d["raw_ref"] = ref
		metricsObjects = append(metricsObjects, d)
		factResource := resource
		if member := byARN[target]; member != nil {
			factResource = member
		}
		batches, e := databaseMetricBatches(factResource, metrics)
		if e != nil {
			return e
		}
		for i, batch := range batches {
			id := "rds-" + telemetry.Hash(model.Document{"resource": resource["id"], "arn": target, "raw_sha256": metrics.RawSHA256, "chunk": i})
			ack, e := storage.WriteFacts(ctx, t.Tenant, id, batch)
			if e != nil {
				return e
			}
			if model.Number(ack, "sample_count") != int64(len(batch.Samples)) || model.String(ack, "canonical_hash") != telemetry.CanonicalHash(batch) {
				return errors.New("RDS_FACT_ACK_DIFFERS")
			}
		}
	}
	object["metrics"] = metricsObjects
	object["compute_optimizer"] = model.Document{"status": "UNKNOWN_NOT_COMMISSIONED"}
	if os.Getenv("RDS_COMPUTE_OPTIMIZER_ENABLED") == "true" {
		v, e := client.RDSComputeOptimizer(ctx, scope, arn)
		if e != nil {
			object["compute_optimizer"] = model.Document{"status": "UNAVAILABLE"}
		} else {
			if v.CollectedAt.After(observedAt) {
				observedAt = v.CollectedAt
			}
			ref, e := databaseRaw(ctx, storage, t.Tenant, v.RDSReadEvidence)
			if e != nil {
				return e
			}
			refs = append(refs, ref)
			object["compute_optimizer"] = model.Document{"status": "OPTIONAL_PROVIDER_ADVICE_NOT_CUSTOMER_PRICE", "recommendations": v.Recommendations, "raw_ref": ref}
		}
	}
	if len(refs) > 256 {
		return errors.New("RDS_SOURCE_REFERENCE_BOUND")
	}
	if observedAt.IsZero() || observedAt.After(time.Now().UTC()) {
		return errors.New("RDS_NATIVE_COLLECTION_TIME_INVALID")
	}
	object["observed_at"] = observedAt
	raw, e := json.Marshal(object)
	if e != nil || len(raw) > 128<<20 {
		return errors.New("RDS_CANONICAL_BUDGET")
	}
	ref, e := databaseArchiveReadback(ctx, storage, t.Tenant, "canonical", "rds-"+telemetry.BytesHash(raw), raw)
	if e != nil {
		return e
	}
	_, e = t.DatabaseEvidenceAppend(ctx, model.Document{"id": model.ID(), "schema_version": "1", "resource_id": resource["id"], "account_id": scope.AccountID, "region": scope.Region, "config_hash": service.DatabaseConfigurationHash(resource), "content_hash": ref["body_sha256"], "archive": ref, "source_refs": refs, "observed_at": observedAt, "period": model.Document{"start": start, "end": end}})
	return e
}
