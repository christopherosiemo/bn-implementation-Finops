package workflow

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/lambdacost"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/native"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/provider"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/service"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/source"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/telemetry"
	"github.com/jackc/pgx/v5"
	"os"
	"sort"
	"strings"
	"time"
)

type LambdaNativeReader interface {
	LambdaMetrics(context.Context, lambdacost.Scope, lambdacost.MetricSelection) (lambdacost.Metrics, error)
	LambdaReports(context.Context, lambdacost.Scope, lambdacost.Registration, string, time.Time, time.Time, string) (lambdacost.Reports, error)
	LambdaComputeOptimizer(context.Context, lambdacost.Scope, string) (model.Document, lambdacost.Evidence, error)
	LambdaPriceDimensions(context.Context, lambdacost.Scope, []string) (model.Document, error)
}
type LambdaCollectionOptions struct {
	ComputeOptimizer   bool
	ReportReader       func(context.Context, lambdacost.Registration) (LambdaNativeReader, error)
	NativeRegistration *lambdacost.Registration
}

func lambdaArchive(ctx context.Context, storage *native.Storage, tenant, kind string, v any) (model.Document, error) {
	raw, e := json.Marshal(v)
	if e != nil || len(raw) > 96<<20 {
		return nil, errors.New("LAMBDA_SNAPSHOT_BOUND_EXCEEDED")
	}
	ref, e := storage.Archive(ctx, tenant, "canonical", "lambda-"+kind+"-"+lambdacost.BytesHash(raw), raw)
	if e != nil {
		return nil, e
	}
	read, e := storage.Read(ctx, tenant, ref)
	if e != nil || lambdacost.BytesHash(read) != lambdacost.BytesHash(raw) {
		return nil, errors.New("LAMBDA_ARCHIVE_READBACK_DIFFERS")
	}
	return ref, nil
}
func lambdaWire(ctx context.Context, storage *native.Storage, evidence lambdacost.Evidence) (model.Document, error) {
	if lambdacost.ValidateScope(evidence.Scope) != nil || len(evidence.Raw) == 0 || len(evidence.Raw) > lambdacost.MaxCaptureBytes*2 || evidence.RawSHA256 != lambdacost.BytesHash(evidence.Raw) {
		return nil, lambdacost.ErrEvidence
	}
	ref, e := storage.Archive(ctx, evidence.Scope.TenantID, "wire", "lambda-"+evidence.RawSHA256, evidence.Raw)
	if e != nil {
		return nil, e
	}
	read, e := storage.Read(ctx, evidence.Scope.TenantID, ref)
	if e != nil || lambdacost.BytesHash(read) != evidence.RawSHA256 {
		return nil, errors.New("LAMBDA_NATIVE_ARCHIVE_DIFFERS")
	}
	ref["observation_basis"] = evidence.ObservationBasis
	ref["kind"], ref["id"], ref["version"], ref["sha256"] = "AWS_LAMBDA_NATIVE_CAPTURE", ref["key"], ref["version_id"], ref["body_sha256"]
	ref["binding"] = lambdacost.Document(evidence.Scope)
	return ref, nil
}
func lambdaResource(ctx context.Context, db *store.Store, scope lambdacost.Scope, row model.Document, cloudID string) (model.Document, error) {
	var result model.Document
	e := db.Do(ctx, scope.TenantID, func(tx *store.Tx) error {
		var id string
		err := tx.QueryRow(ctx, "SELECT id FROM entities WHERE tenant_id=$1 AND kind='resources' AND document->>'provider'='AWS' AND document->>'account_id'=$2 AND document->>'region'=$3 AND document->>'provider_resource_id'=$4", tx.Tenant, scope.AccountID, scope.Region, row["provider_resource_id"]).Scan(&id)
		d := model.Document{"configuration_authority": "UNKNOWN", "owner": nil, "workload_id": nil, "environment": "UNKNOWN"}
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
		for _, key := range []string{"provider", "resource_type", "provider_resource_id", "account_id", "region", "name", "state", "lambda_configuration"} {
			d[key] = row[key]
		}
		d["last_seen_at"], d["eligibility"] = model.Now(), "OBSERVE_ONLY"
		if cloudID != "" {
			d["cloud_account_id"] = cloudID
		}
		relations := []model.Document{}
		config := lambdacost.Document(row["lambda_configuration"])
		for _, mapping := range lambdacost.Rows(config["event_source_mappings"]) {
			if source := model.String(mapping, "EventSourceArn"); source != "" {
				relations = append(relations, model.Document{"type": "INVOKED_BY", "target_provider_resource_id": source, "basis": "NATIVE_EVENT_SOURCE_MAPPING", "analytical": true, "mapping_uuid": mapping["UUID"]})
			}
		}
		for _, async := range lambdacost.Rows(config["async_configurations"]) {
			destination := lambdacost.Document(async["DestinationConfig"])
			for _, key := range []string{"OnSuccess", "OnFailure"} {
				if arn := model.String(lambdacost.Document(destination[key]), "Destination"); arn != "" {
					relations = append(relations, model.Document{"type": "DELIVERS_TO", "target_provider_resource_id": arn, "basis": "NATIVE_ASYNC_DESTINATION", "analytical": true})
				}
			}
		}
		d["provider_relationships"] = relations
		if version == 0 {
			result, err = tx.Create(ctx, "resources", d)
		} else {
			result, err = tx.Update(ctx, "resources", id, version, d)
		}
		return err
	})
	return result, e
}
func lambdaPeriod(profile model.Document) (time.Time, time.Time, int) {
	days := 30
	if model.Bool(profile, "high_seasonality") {
		days = 90
	} else if model.String(profile, "criticality") == "NON_PRODUCTION" {
		days = 14
	}
	end := time.Now().UTC().Truncate(24 * time.Hour)
	period := 300
	if days > 63 {
		period = 3600
	}
	return end.Add(-time.Duration(days) * 24 * time.Hour), end, period
}
func lambdaServing(config model.Document) []model.Document {
	versions := map[string]model.Document{}
	for _, v := range lambdacost.Rows(config["versions"]) {
		versions[model.String(v, "version")] = v
	}
	out := []model.Document{}
	if latest := versions["$LATEST"]; latest != nil {
		out = append(out, lambdacost.Document(latest))
	}
	used := map[string]bool{"$LATEST": true}
	for _, alias := range lambdacost.Rows(config["aliases"]) {
		v := versions[model.String(alias, "function_version")]
		if v == nil {
			continue
		}
		target := lambdacost.Document(v)
		target["qualifier"], target["qualified_arn"] = alias["name"], alias["alias_arn"]
		target["alias_revision_id"], target["routing_weights"] = alias["revision_id"], alias["routing_weights"]
		if len(lambdacost.Document(alias["routing_weights"])) > 0 {
			target["multiple_serving_versions"] = true
		}
		out = append(out, target)
	}
	for _, pc := range lambdacost.Rows(config["provisioned_concurrency"]) {
		arn := model.String(pc, "FunctionArn")
		parts := strings.Split(arn, ":")
		q := parts[len(parts)-1]
		if v := versions[q]; v != nil && !used[q] {
			out = append(out, lambdacost.Document(v))
			used[q] = true
		}
	}
	if len(out) > 32 {
		out = out[:32]
	}
	return out
}
func lambdaWriteMetrics(ctx context.Context, storage *native.Storage, resource model.Document, m lambdacost.Metrics) (model.Document, error) {
	ref, e := lambdaWire(ctx, storage, m.Evidence)
	if e != nil {
		return nil, e
	}
	binding := telemetry.Binding{TenantID: m.Scope.TenantID, ResourceID: model.String(resource, "id"), WorkloadID: model.String(resource, "workload_id"), Provider: "AWS", ProviderResourceID: m.Selection.QualifiedARN, AccountID: m.Scope.AccountID, Region: m.Scope.Region}
	for first := 0; first < len(m.Rows); first += 2000 {
		samples := []telemetry.Sample{}
		for _, row := range m.Rows[first:min(first+2000, len(m.Rows))] {
			at, e := time.Parse(time.RFC3339Nano, model.String(row, "source_time"))
			if e != nil {
				return nil, e
			}
			samples = append(samples, telemetry.Sample{ID: lambdacost.Hash(row), DefinitionID: "AWS/Lambda:" + model.String(row, "metric") + ":" + model.String(row, "statistic"), StreamID: m.Selection.QualifiedARN + ":" + m.Selection.Version, Metric: model.String(row, "metric"), Type: "gauge", Unit: model.String(row, "unit"), Statistic: model.String(row, "statistic"), Temporality: "OBSERVED_PERIOD_STATISTIC", StartTime: at, Time: at, Value: model.String(row, "value"), OriginalAttributes: row, RawSHA256: m.RawSHA256})
		}
		batch := telemetry.Batch{SchemaVersion: "1", ConnectionID: "lambda-cloudwatch-" + binding.ResourceID, ConfigHash: lambdacost.ConfigurationHash(lambdacost.Document(resource["lambda_configuration"])), Binding: binding, SourceKind: "AWS_LAMBDA_CLOUDWATCH", RawSHA256: m.RawSHA256, Samples: samples, Start: m.Selection.Start, End: m.Selection.End}
		ack, e := storage.WriteFacts(ctx, m.Scope.TenantID, "lambda-"+lambdacost.Hash(model.Document{"source": m.RawSHA256, "chunk": first}), batch)
		if e != nil || model.Number(ack, "sample_count") != int64(len(samples)) {
			return nil, errors.New("LAMBDA_METRIC_ACK_DIFFERS")
		}
	}
	return ref, nil
}
func lambdaReportCohorts(rows []model.Document) ([]model.Document, bool) {
	cohorts := map[string]model.Document{}
	for _, row := range rows {
		d := model.Document{}
		for _, key := range []string{"duration_ms", "billed_duration_ms", "memory_size_mb", "max_memory_used_mb", "init_duration_ms", "restore_duration_ms", "version", "qualified_arn", "memory_semantics", "source_kind", "status"} {
			if v, ok := row[key]; ok {
				d[key] = v
			}
		}
		key := lambdacost.Hash(d)
		if old := cohorts[key]; old != nil {
			old["count"] = model.Number(old, "count") + 1
			at, _ := time.Parse(time.RFC3339Nano, model.String(row, "event_time"))
			first, _ := time.Parse(time.RFC3339Nano, model.String(old, "first_event_time"))
			last, _ := time.Parse(time.RFC3339Nano, model.String(old, "last_event_time"))
			if at.Before(first) {
				old["first_event_time"] = row["event_time"]
			}
			if at.After(last) {
				old["last_event_time"] = row["event_time"]
			}
		} else {
			d["count"] = 1
			d["cohort_id"] = key
			d["first_event_time"], d["last_event_time"] = row["event_time"], row["event_time"]
			cohorts[key] = d
		}
	}
	keys := []string{}
	for key := range cohorts {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	truncated := len(keys) > 128
	if truncated {
		keys = keys[:128]
	}
	out := []model.Document{}
	for _, key := range keys {
		out = append(out, cohorts[key])
	}
	return out, truncated
}

// CollectAndPublishLambda retains the native collector's exact sanitized
// observations through the same archived snapshot consumed by assessments.
// PostgreSQL stores resource/snapshot references, never invocation records.
func CollectAndPublishLambda(ctx context.Context, db *store.Store, storage *native.Storage, reader LambdaNativeReader, d lambdacost.Discovery, cloudID string, registrations []lambdacost.Registration, options LambdaCollectionOptions) ([]model.Document, error) {
	if lambdacost.ValidateScope(d.Scope) != nil {
		return nil, lambdacost.ErrEvidence
	}
	discoveryRef, e := lambdaWire(ctx, storage, d.Evidence)
	if e != nil {
		return nil, e
	}
	published := []model.Document{}
	for _, row := range d.Functions {
		if row["account_id"] != d.Scope.AccountID || row["region"] != d.Scope.Region {
			return nil, lambdacost.ErrEvidence
		}
		if reg := options.NativeRegistration; reg != nil {
			if lambdacost.ValidateRegistration(*reg) != nil || reg.Kind != lambdacost.NativeKind || !reg.Enabled || reg.TenantID != d.Scope.TenantID || reg.AccountID != d.Scope.AccountID || reg.Region != d.Scope.Region || row["provider_resource_id"] != reg.FunctionARN {
				return nil, lambdacost.ErrEvidence
			}
		}
		resource, e := lambdaResource(ctx, db, d.Scope, row, cloudID)
		if e != nil {
			return nil, e
		}
		configuration := lambdacost.Document(resource["lambda_configuration"])
		profile := model.Document{}
		if workload := model.String(resource, "workload_id"); workload != "" {
			e = db.Do(ctx, d.Scope.TenantID, func(tx *store.Tx) error {
				p, err := tx.WorkloadSafetyLatest(ctx, workload)
				if err == nil {
					profile = p
				} else if err != pgx.ErrNoRows {
					return err
				}
				return nil
			})
			if e != nil {
				return nil, e
			}
		}
		start, end, period := lambdaPeriod(profile)
		base := model.String(resource, "provider_resource_id")
		functionMetrics := model.Document{"rows": []model.Document{}, "coverage": []model.Document{}, "period": model.Document{"start": start, "end": end}, "status": "UNAVAILABLE"}
		aggregate, e := reader.LambdaMetrics(ctx, d.Scope, lambdacost.MetricSelection{QualifiedARN: base, Version: "ALL", Start: start, End: end, PeriodSeconds: period})
		if e == nil {
			ref, err := lambdaWriteMetrics(ctx, storage, resource, aggregate)
			if err != nil {
				return nil, err
			}
			functionMetrics = model.Document{"rows": aggregate.Rows, "coverage": aggregate.Coverage, "period": model.Document{"start": start, "end": end}, "source_ref": ref}
		}
		providerAdvice := model.Document{"status": "NOT_COMMISSIONED", "rows": []model.Document{}}
		if options.ComputeOptimizer {
			advice, evidence, err := reader.LambdaComputeOptimizer(ctx, d.Scope, base)
			if err == nil {
				ref, err := lambdaWire(ctx, storage, evidence)
				if err != nil {
					return nil, err
				}
				providerAdvice = advice
				providerAdvice["source_ref"] = ref
			} else {
				providerAdvice["status"] = "UNAVAILABLE"
			}
		}
		prices := model.Document{"dimensions": []model.Document{}, "status": "UNAVAILABLE"}
		var skus []string
		err := db.Do(ctx, d.Scope.TenantID, func(tx *store.Tx) error {
			var err error
			skus, err = service.CurrentLambdaSKUs(ctx, tx, d.Scope.AccountID, d.Scope.Region)
			return err
		})
		if err == nil && len(skus) > 0 {
			p, err := reader.LambdaPriceDimensions(ctx, d.Scope, skus)
			if err == nil {
				raw, _ := p["raw"].([]byte)
				evidence := lambdacost.Evidence{Scope: d.Scope, Raw: raw, RawSHA256: lambdacost.BytesHash(raw), ObservationBasis: "NATIVE_CATALOGUE_DIMENSIONS_ONLY_NOT_CUSTOMER_PRICE"}
				ref, err := lambdaWire(ctx, storage, evidence)
				if err != nil {
					return nil, err
				}
				delete(p, "raw")
				p["source_ref"] = ref
				prices = p
			}
		}
		targets := lambdaServing(configuration)
		if reg := options.NativeRegistration; reg != nil {
			found := false
			for _, target := range targets {
				if model.String(target, "qualifier") == reg.Qualifier {
					found = true
				}
			}
			if !found {
				for _, version := range lambdacost.Rows(configuration["versions"]) {
					if model.String(version, "version") == reg.Qualifier {
						targets = append(targets, lambdacost.Document(version))
						break
					}
				}
			}
		}
		for _, target := range targets {
			q, version := model.String(target, "qualifier"), model.String(target, "version")
			if reg := options.NativeRegistration; reg != nil && reg.Qualifier != q {
				continue
			}
			refs := []model.Document{discoveryRef}
			for _, observation := range []model.Document{functionMetrics, providerAdvice, prices} {
				if ref := lambdacost.Document(observation["source_ref"]); len(ref) > 0 {
					refs = append(refs, ref)
				}
			}
			metrics := model.Document{"rows": []model.Document{}, "coverage": []model.Document{}, "period": model.Document{"start": start, "end": end}, "status": "UNAVAILABLE"}
			if model.String(target, "model") == "EVENT_DEFAULT" {
				m, err := reader.LambdaMetrics(ctx, d.Scope, lambdacost.MetricSelection{QualifiedARN: model.String(target, "qualified_arn"), Version: version, Start: start, End: end, PeriodSeconds: period})
				if err == nil {
					ref, err := lambdaWriteMetrics(ctx, storage, resource, m)
					if err != nil {
						return nil, err
					}
					refs = append(refs, ref)
					metrics = model.Document{"rows": m.Rows, "coverage": m.Coverage, "period": model.Document{"start": start, "end": end}, "source_ref": ref}
				}
			}
			reports := model.Document{"rows": []model.Document{}, "coverage": model.Document{"status": "NOT_COMMISSIONED", "missing_is_zero": false}}
			sourceID := ""
			var sourceVersion any
			sourceBindings := []model.Document{}
			for _, reg := range registrations {
				if reg.Kind != lambdacost.ReportsKind || !reg.Enabled || reg.FunctionARN != base || reg.Qualifier != q || options.ReportReader == nil {
					continue
				}
				rr, err := options.ReportReader(ctx, reg)
				if err != nil {
					reports["coverage"] = model.Document{"status": "SOURCE_BINDING_UNAVAILABLE", "missing_is_zero": false}
					continue
				}
				observed, err := rr.LambdaReports(ctx, d.Scope, reg, version, start, end, "")
				if err != nil {
					reports["coverage"] = model.Document{"status": "REPORT_READ_UNAVAILABLE", "missing_is_zero": false}
					continue
				}
				ref, err := lambdaWire(ctx, storage, observed.Evidence)
				if err != nil {
					return nil, err
				}
				refs = append(refs, ref)
				if len(observed.Rows) > 0 {
					analytical := []model.Document{}
					for _, r := range observed.Rows {
						x := lambdacost.Document(r)
						x["resource_id"], x["workload_id"], x["account_id"], x["region"] = resource["id"], resource["workload_id"], d.Scope.AccountID, d.Scope.Region
						analytical = append(analytical, x)
					}
					if _, err = storage.WriteLambdaReports(ctx, d.Scope.TenantID, reg.ID, "reports-"+observed.RawSHA256, analytical); err != nil {
						return nil, err
					}
				}
				cohorts, truncated := lambdaReportCohorts(observed.Rows)
				coverage := lambdacost.Document(observed.Coverage)
				coverage["cohort_rows_truncated"] = truncated
				coverage["query_scope"] = "FUNCTION_ALL_VERSIONS"
				if model.Bool(coverage, "query_complete") && model.Number(coverage, "rejected_records") == 0 && !truncated {
					coverage["status"] = "COMPLETE_OBSERVED"
				}
				reports = model.Document{"rows": cohorts, "coverage": coverage, "source_ref": ref, "row_semantics": "EXACT_EQUIVALENT_REPORT_COHORT_COUNTS_NOT_RAW_EVENT_PERCENTILES"}
				sourceID, sourceVersion = reg.ID, reg.Version
				sourceBindings = append(sourceBindings, model.Document{"source_id": reg.ID, "version": reg.Version})
				break
			}
			if reg := options.NativeRegistration; reg != nil {
				sourceID, sourceVersion = reg.ID, reg.Version
				sourceBindings = append(sourceBindings, model.Document{"source_id": reg.ID, "version": reg.Version})
			}
			target["reserved_concurrency"] = configuration["reserved_concurrency"]
			target["provisioned_concurrency"] = configuration["provisioned_concurrency"]
			target["account_concurrency"] = configuration["account_concurrency"]
			target["account_concurrency_limit"] = lambdacost.Document(lambdacost.Document(configuration["account_concurrency"])["AccountLimit"])["ConcurrentExecutions"]
			target["event_source_mappings"] = configuration["event_source_mappings"]
			target["configuration_authority"] = resource["configuration_authority"]
			canonical := model.Document{"schema_version": "LAMBDA_NATIVE_V1", "resource_id": resource["id"], "account_id": d.Scope.AccountID, "region": d.Scope.Region, "qualifier": q, "serving_target": target["qualified_arn"], "config_hash": lambdacost.ConfigurationHash(configuration), "source_id": sourceID, "source_version": d.RawSHA256, "source_registration_version": sourceVersion, "observed_at": d.CollectedAt, "period": model.Document{"start": start, "end": end}, "configuration": target, "aliases": configuration["aliases"], "metrics": metrics, "function_metrics": functionMetrics, "reports": reports, "performance_curves": []model.Document{}, "provider_recommendations": providerAdvice, "price_dimensions": prices["dimensions"], "pricing_status": prices["status"], "price_source_ref": prices["source_ref"], "source_refs": refs, "inventory_coverage": d.Coverage}
			canonical["source_bindings"] = sourceBindings
			ref, err := lambdaArchive(ctx, storage, d.Scope.TenantID, "snapshot", canonical)
			if err != nil {
				return nil, err
			}
			var snapshot model.Document
			err = db.Do(ctx, d.Scope.TenantID, func(tx *store.Tx) error {
				current, err := tx.Get(ctx, "resources", model.String(resource, "id"))
				if err != nil {
					return err
				}
				if lambdacost.ConfigurationHash(lambdacost.Document(current["lambda_configuration"])) != canonical["config_hash"] {
					return errors.New("LAMBDA_CONFIGURATION_CHANGED_DURING_PUBLICATION")
				}
				for _, binding := range sourceBindings {
					registered, err := tx.SourceGet(ctx, model.String(binding, "source_id"))
					if err != nil || !model.Bool(registered, "enabled") || model.Bool(registered, "revoked") || model.Number(registered, "version") != model.Number(binding, "version") || model.String(registered, "function_arn") != base || model.String(registered, "qualifier") != q || model.String(registered, "account_id") != d.Scope.AccountID || model.String(registered, "region") != d.Scope.Region {
						return errors.New("LAMBDA_SOURCE_CHANGED_DURING_PUBLICATION")
					}
				}
				snapshot, err = tx.LambdaEvidenceCreate(ctx, model.String(resource, "id"), sourceID, canonical, ref)
				return err
			})
			if err != nil {
				return nil, err
			}
			published = append(published, model.Document{"resource": resource, "evidence": snapshot, "canonical": canonical})
		}
	}
	return published, nil
}

func lambdaTick(ctx context.Context, a *Activities, tenant string) error {
	if a.Config.Fixture {
		return nil
	}
	var accounts, registered []model.Document
	e := a.Store.Do(ctx, tenant, func(tx *store.Tx) error {
		var err error
		accounts, err = tx.List(ctx, "cloud_accounts")
		if err != nil {
			return err
		}
		registered, err = tx.SourceList(ctx)
		return err
	})
	if e != nil {
		return e
	}
	regs := []lambdacost.Registration{}
	nativeRegistrations := []model.Document{}
	for _, d := range registered {
		if d["kind"] == lambdacost.ReportsKind && model.Bool(d, "enabled") && !model.Bool(d, "revoked") {
			r, e := lambdacost.ParseRegistration(d)
			if e == nil {
				regs = append(regs, r)
			}
		}
		if d["kind"] == lambdacost.NativeKind && model.Bool(d, "enabled") && !model.Bool(d, "revoked") {
			nativeRegistrations = append(nativeRegistrations, d)
		}
	}
	staticEnabled := os.Getenv("LAMBDA_READONLY_ENABLED") == "true" && service.ValidateAWSTenant(tenant) == nil
	if !staticEnabled && len(nativeRegistrations) == 0 {
		return nil
	}
	storage, e := native.StorageFromEnvironment(ctx, false)
	if e != nil {
		return e
	}
	encoded := os.Getenv("AWS_LAMBDA_READ_BINDINGS_JSON")
	if encoded == "" {
		encoded = os.Getenv("AWS_SOURCE_READ_BINDINGS_JSON")
	}
	factory, e := source.LambdaAWSFactory(encoded)
	if e != nil {
		return e
	}
	options := LambdaCollectionOptions{ComputeOptimizer: os.Getenv("LAMBDA_COMPUTE_OPTIMIZER_ENABLED") == "true", ReportReader: func(ctx context.Context, r lambdacost.Registration) (LambdaNativeReader, error) {
		return factory(ctx, r)
	}}
	var first error
	for _, d := range nativeRegistrations {
		r, err := lambdacost.ParseRegistration(d)
		if err != nil {
			if first == nil {
				first = err
			}
			continue
		}
		last, _ := time.Parse(time.RFC3339Nano, model.String(d, "last_sync_at"))
		if model.Number(d, "last_sync_version") == r.Version && !last.IsZero() && time.Since(last) < 10*time.Minute {
			continue
		}
		if !model.Bool(d, "sync_requested") && model.Number(d, "last_sync_version") != r.Version {
			continue
		}
		reader, err := factory(ctx, r)
		if err == nil {
			readCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
			err = SyncLambdaNativeSource(readCtx, a, storage, reader, r, regs, options)
			cancel()
		}
		if err != nil {
			_ = a.Store.Do(ctx, tenant, func(tx *store.Tx) error {
				return tx.SourceCheckpointSet(ctx, r.ID, "status", model.Document{"status": "BLOCKED", "reason_code": "LAMBDA_REGISTERED_NATIVE_SOURCE_UNAVAILABLE", "last_sync_at": model.Now(), "last_sync_version": r.Version})
			})
			if first == nil {
				first = err
			}
		}
	}
	for _, account := range accounts {
		if !staticEnabled {
			break
		}
		last, _ := time.Parse(time.RFC3339Nano, model.String(account, "lambda_last_discovered_at"))
		marker := model.String(account, "lambda_discovery_marker")
		if marker == "" && !last.IsZero() && time.Since(last) < 10*time.Minute {
			continue
		}
		id, region := model.String(account, "account_id"), model.String(account, "region")
		if !strings.Contains(a.Config.AWSReadRole, ":"+id+":") {
			continue
		}
		scope := lambdacost.Scope{TenantID: tenant, AccountID: id, Region: region}
		reader, e := provider.NewAWS(ctx, region, a.Config.AWSReadRole, a.Config.AWSExternalID)
		if e != nil {
			if first == nil {
				first = e
			}
			continue
		}
		readCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
		d, e := reader.LambdaDiscover(readCtx, scope, lambdacost.DiscoverySelection{Marker: marker, MaxFunctions: 5})
		if e == nil {
			_, e = CollectAndPublishLambda(readCtx, a.Store, storage, reader, d, model.String(account, "id"), regs, options)
		}
		cancel()
		if e != nil {
			if first == nil {
				first = e
			}
			continue
		}
		e = a.Store.Do(ctx, tenant, func(tx *store.Tx) error {
			current, e := tx.Get(ctx, "cloud_accounts", model.String(account, "id"))
			if e != nil {
				return e
			}
			current["lambda_discovery_marker"] = d.NextMarker
			current["lambda_inventory_scope"] = "EVENT_FUNCTIONS_ONLY"
			if d.Complete {
				current["lambda_last_discovered_at"] = model.Now()
			}
			_, e = tx.Update(ctx, "cloud_accounts", model.String(current, "id"), model.Number(current, "version"), current)
			return e
		})
		if e != nil && first == nil {
			first = e
		}
	}
	return first
}
