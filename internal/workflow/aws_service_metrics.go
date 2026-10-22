package workflow

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/awsservice"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/native"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/telemetry"
)

type awsServiceMetricReader interface {
	ServiceMetrics(context.Context, awsservice.Registration, model.Document, time.Time, time.Time) (awsservice.Metrics, error)
}

// EnrichAWSServiceCollection reads existing commissioned native metrics only.
// Large evaluation histories stay in versioned objects, never entity documents.
func EnrichAWSServiceCollection(ctx context.Context, reader AWSServiceReader, reg awsservice.Registration, c awsservice.Collection, storage *native.Storage) (awsservice.Collection, error) {
	metricsReader, ok := reader.(awsServiceMetricReader)
	if !ok {
		return c, nil
	}
	definitions := map[string]model.Document{}
	for _, r := range c.Resources {
		if r["resource_type"] == "ECS_TASK_DEFINITION" {
			definitions[model.String(r, "provider_resource_id")] = awsservice.Document(r["aws_service_configuration"])
		}
	}
	end := time.Now().UTC().Truncate(24 * time.Hour)
	start := end.Add(-90 * 24 * time.Hour)
	for _, resource := range c.Resources {
		if !awsservice.Contains([]string{"ECS_SERVICE", "DYNAMODB_TABLE", "DYNAMODB_GSI", "ELASTICACHE_CLUSTER", "ELASTICACHE_REPLICATION_GROUP", "LOAD_BALANCER"}, model.String(resource, "resource_type")) {
			continue
		}
		m, e := metricsReader.ServiceMetrics(ctx, reg, resource, start, end)
		if e != nil {
			resource["aws_service_assessment_evidence"] = model.Document{"status": "UNAVAILABLE", "reason_codes": []string{"AWS_SERVICE_NATIVE_METRIC_COLLECTION_UNAVAILABLE"}}
			continue
		}
		if m.Scope != (awsservice.Scope{TenantID: reg.TenantID, AccountID: reg.AccountID, Region: reg.Region}) || m.ProviderResourceID != model.String(resource, "provider_resource_id") || m.RawSHA256 != awsservice.BytesHash(m.Raw) {
			return c, awsservice.ErrEvidence
		}
		rawRefs := []model.Document{}
		for first := 0; first < len(m.Raw); first += awsservice.MaxPageBytes {
			last := min(first+awsservice.MaxPageBytes, len(m.Raw))
			ref, e := awsServiceArchive(ctx, storage, reg.TenantID, "wire", m.Raw[first:last])
			if e != nil {
				return c, e
			}
			rawRefs = append(rawRefs, ref)
		}
		cfg := awsservice.Document(resource["aws_service_configuration"])
		capabilities := model.Document{"candidates": []model.Document{}, "source_refs": []model.Document{}}
		if resource["resource_type"] == "ECS_SERVICE" {
			if def := definitions[model.String(cfg, "taskDefinition")]; def != nil {
				cfg["task_definition"] = def
				cfg["fargate_cohort"] = awsservice.FargateCohort(c.Resources, resource, c.CollectedAt)
				if cfg["launchType"] == "FARGATE" {
					capabilities = fargateServiceCapabilities(cfg, def)
				}
			}
		}
		data := model.Document{"schema_version": "1", "configuration": cfg, "observations": model.Document{"start": m.Start.UTC().Format(time.RFC3339Nano), "end": m.End.UTC().Format(time.RFC3339Nano), "metrics": m.Rows, "expected_series": m.ExpectedSeries, "activity": []model.Document{}, "reason_codes": m.ReasonCodes}, "capabilities": capabilities, "raw_refs": rawRefs}
		raw, e := json.Marshal(data)
		if e != nil || len(raw) > awsservice.MaxCaptureBytes {
			return c, awsservice.ErrEvidence
		}
		archive, e := awsServiceArchive(ctx, storage, reg.TenantID, "canonical", raw)
		if e != nil {
			return c, e
		}
		resource["aws_service_assessment_evidence"] = model.Document{"status": "OBSERVED_NATIVE_METRICS", "archive": archive, "raw_refs": rawRefs, "start": m.Start, "end": m.End, "metric_count": len(m.Rows), "reason_codes": m.ReasonCodes, "source_registration_version": reg.Version, "source_id": reg.ID, "missing_is_zero": false}
	}
	return c, nil
}

// AWS documents these ordinary Fargate task sizes independently of customer
// rates. This reviewed subset is a capability constraint, not price authority.
func fargateServiceCapabilities(config, definition model.Document) model.Document {
	shapes := []model.Document{}
	runtime := awsservice.Document(definition["runtimePlatform"])
	// This accepted subset is ordinary Linux/x86 Fargate. Other models remain
	// visible without invented capability or licensing equivalence.
	if runtime["operatingSystemFamily"] != "LINUX" || runtime["cpuArchitecture"] != "X86_64" || definition["networkMode"] != "awsvpc" || !awsservice.Contains(model.Strings(definition, "requiresCompatibilities"), "FARGATE") {
		return model.Document{"version": "AWS_FARGATE_TASK_CAPABILITY_V1", "candidates": shapes, "reason_codes": []string{"ECS_SUPPORTED_NATIVE_RUNTIME_CAPABILITY_REQUIRED"}}
	}
	for _, shape := range []struct{ cpu, min, max, step int }{{256, 512, 2048, 512}, {512, 1024, 4096, 1024}, {1024, 2048, 8192, 1024}, {2048, 4096, 16384, 1024}, {4096, 8192, 30720, 1024}} {
		for mem := shape.min; mem <= shape.max; mem += shape.step {
			if shape.cpu == 256 && mem == 1536 {
				continue
			}
			shapes = append(shapes, model.Document{"id": "cpu-" + strconv.Itoa(shape.cpu) + "-memory-" + strconv.Itoa(mem), "cpu_units": strconv.Itoa(shape.cpu), "memory_mib": strconv.Itoa(mem), "architecture": awsservice.Document(definition["runtimePlatform"])["cpuArchitecture"], "operating_system_family": awsservice.Document(definition["runtimePlatform"])["operatingSystemFamily"], "basis": "VERSIONED_AWS_DOCUMENTED_FARGATE_SHAPES", "source_ref": model.Document{"kind": "AWS_FARGATE_TASK_CAPABILITY", "id": "ordinary-fargate-reviewed-subset-" + strconv.Itoa(shape.cpu), "version": "1", "sha256": awsservice.Hash(model.Document{"cpu": shape.cpu, "min": shape.min, "max": shape.max, "step": shape.step})}})
		}
	}
	return model.Document{"version": "AWS_FARGATE_TASK_CAPABILITY_V1", "reference_url": "https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-cpu-memory-error.html", "candidates": shapes, "source_refs": []model.Document{}}
}

// PersistAWSServiceAssessmentMetrics joins already archived actual samples to
// the canonical resource UUID after upsert; it grants no ingestion authority.
func PersistAWSServiceAssessmentMetrics(ctx context.Context, storage *native.Storage, resource model.Document) error {
	e := awsservice.Document(resource["aws_service_assessment_evidence"])
	if e["status"] != "OBSERVED_NATIVE_METRICS" {
		return nil
	}
	archive := awsservice.Document(e["archive"])
	raw, err := storage.Read(ctx, model.String(resource, "tenant_id"), archive)
	if err != nil {
		return err
	}
	if awsservice.BytesHash(raw) != model.String(archive, "body_sha256") {
		return errors.New("AWS_SERVICE_METRIC_ARCHIVE_DIFFERS")
	}
	var data model.Document
	if json.Unmarshal(raw, &data) != nil {
		return awsservice.ErrEvidence
	}
	o := awsservice.Document(data["observations"])
	start, e1 := time.Parse(time.RFC3339Nano, model.String(o, "start"))
	end, e2 := time.Parse(time.RFC3339Nano, model.String(o, "end"))
	if e1 != nil || e2 != nil {
		return awsservice.ErrEvidence
	}
	binding := telemetry.Binding{TenantID: model.String(resource, "tenant_id"), ResourceID: model.String(resource, "id"), Provider: "AWS", ProviderResourceID: model.String(resource, "provider_resource_id"), AccountID: model.String(resource, "account_id"), Region: model.String(resource, "region"), WorkloadID: model.String(resource, "workload_id")}
	rows := awsservice.Rows(o["metrics"])
	for first := 0; first < len(rows); first += 2000 {
		samples := []telemetry.Sample{}
		for _, row := range rows[first:min(first+2000, len(rows))] {
			at, err := time.Parse(time.RFC3339Nano, model.String(row, "source_time"))
			if err != nil || row["provider_resource_id"] != binding.ProviderResourceID {
				return awsservice.ErrEvidence
			}
			samples = append(samples, telemetry.Sample{ID: awsservice.Hash(row), DefinitionID: model.String(row, "namespace") + ":" + model.String(row, "metric") + ":" + model.String(row, "statistic"), StreamID: binding.ProviderResourceID, Metric: model.String(row, "metric"), Type: "gauge", Unit: model.String(row, "unit"), Statistic: model.String(row, "statistic"), Temporality: "OBSERVED_PERIOD_STATISTIC", StartTime: at, Time: at, Value: model.String(row, "value"), OriginalAttributes: row, RawSHA256: awsservice.BytesHash(raw)})
		}
		ack, err := storage.WriteFacts(ctx, binding.TenantID, "aws-service-metrics-"+awsservice.Hash(model.Document{"resource": binding.ResourceID, "content": archive["body_sha256"], "first": first}), telemetry.Batch{SchemaVersion: "1", ConnectionID: model.String(e, "source_id"), ConfigHash: awsservice.ConfigurationHash(resource), Binding: binding, SourceKind: "AWS_SERVICE_CLOUDWATCH", RawSHA256: awsservice.BytesHash(raw), Start: start, End: end, Samples: samples})
		if err != nil || model.Number(ack, "sample_count") != int64(len(samples)) {
			return errors.New("AWS_SERVICE_METRIC_ANALYTICS_ACK_DIFFERS")
		}
	}
	return nil
}
