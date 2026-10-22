package native

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/lambdacost"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/telemetry"
	"strconv"
	"time"
)

func (s *Storage) WriteLambdaPerformance(ctx context.Context, tenant, sourceID, batchID string, rows []model.Document) (model.Document, error) {
	projected := make([]model.Document, 0, len(rows))
	for _, point := range rows {
		d := lambdacost.Document(point)
		binding := lambdacost.Document(d["binding"])
		if model.String(binding, "tenant_id") != tenant {
			return nil, errors.New("LAMBDA_PERFORMANCE_TENANT_DIFFERS")
		}
		for _, key := range []string{"resource_id", "workload_id", "account_id", "region"} {
			d[key] = binding[key]
		}
		base := model.String(binding, "provider_resource_id")
		scope := lambdacost.Scope{TenantID: tenant, AccountID: model.String(binding, "account_id"), Region: model.String(binding, "region")}
		qualified := base + ":" + model.String(d, "qualifier")
		if _, _, err := lambdacost.FunctionARN(scope, qualified); err != nil {
			return nil, errors.New("LAMBDA_PERFORMANCE_TARGET_DIFFERS")
		}
		d["qualified_arn"] = qualified
		d["observed_at"] = d["measurement_end"]
		d["time_semantics"] = "BENCHMARK_MEASUREMENT_END"
		projected = append(projected, d)
	}
	return s.writeLambdaRows(ctx, tenant, sourceID, batchID, "LAMBDA_PERFORMANCE_POINT", projected)
}
func (s *Storage) WriteLambdaReports(ctx context.Context, tenant, sourceID, batchID string, rows []model.Document) (model.Document, error) {
	return s.writeLambdaRows(ctx, tenant, sourceID, batchID, "LAMBDA_PLATFORM_REPORT", rows)
}
func (s *Storage) writeLambdaRows(ctx context.Context, tenant, sourceID, batchID, kind string, rows []model.Document) (model.Document, error) {
	if !safeKey.MatchString(tenant) || !safeKey.MatchString(sourceID) || !safeKey.MatchString(batchID) || len(rows) < 1 || len(rows) > 10000 {
		return nil, errors.New("LAMBDA_ANALYTICS_BOUND_INVALID")
	}
	digest := lambdacost.Hash(rows)
	expected := map[string]bool{}
	for first := 0; first < len(rows); first += 1000 {
		last := min(first+1000, len(rows))
		samples := []telemetry.Sample{}
		binding := telemetry.Binding{TenantID: tenant, Provider: "AWS"}
		for _, row := range rows[first:last] {
			account, region, resource := model.String(row, "account_id"), model.String(row, "region"), model.String(row, "resource_id")
			scope := lambdacost.Scope{TenantID: tenant, AccountID: account, Region: region}
			if lambdacost.ValidateScope(scope) != nil || resource == "" {
				return nil, errors.New("LAMBDA_ANALYTICS_BINDING_INVALID")
			}
			if binding.ResourceID != "" && (binding.ResourceID != resource || binding.AccountID != account || binding.Region != region) {
				return nil, errors.New("LAMBDA_ANALYTICS_MIXED_SCOPE")
			}
			binding.ResourceID, binding.AccountID, binding.Region = resource, account, region
			binding.WorkloadID = model.String(row, "workload_id")
			binding.ProviderResourceID = model.String(row, "qualified_arn")
			at, err := time.Parse(time.RFC3339Nano, model.String(row, "event_time"))
			if err != nil {
				at, err = time.Parse(time.RFC3339Nano, model.String(row, "observed_at"))
			}
			if err != nil {
				return nil, errors.New("LAMBDA_ANALYTICS_OBSERVATION_TIME_INVALID")
			}
			id := lambdacost.Hash(model.Document{"source_id": sourceID, "batch_id": batchID, "row": row})
			if expected[id] {
				return nil, errors.New("LAMBDA_ANALYTICS_DUPLICATE_ROW")
			}
			expected[id] = true
			samples = append(samples, telemetry.Sample{ID: id, DefinitionID: kind + "_V1", StreamID: sourceID, Metric: kind, Type: "OBSERVATION", Unit: "native", Statistic: "SOURCE_RECORD", Temporality: "OBSERVED_NATIVE_RECORD", Time: at, StartTime: at, RawSHA256: digest, OriginalAttributes: lambdacost.Document(row)})
		}
		batch := telemetry.Batch{SchemaVersion: "1", ConnectionID: sourceID, ConfigHash: digest, Binding: binding, SourceKind: kind, RawSHA256: digest, Samples: samples}
		ack, e := s.WriteFacts(ctx, tenant, batchID+"-"+strconv.Itoa(first), batch)
		if e != nil || model.Number(ack, "sample_count") != int64(len(samples)) {
			return nil, errors.New("LAMBDA_ANALYTICS_ACK_DIFFERS")
		}
	}
	query := "SELECT toString(uniqExact(sample_id)) AS rows,toString(uniqExact(tuple(sample_id,payload))) AS variants FROM native_metric_samples WHERE tenant_id='" + tenant + "' AND connection_id='" + sourceID + "' AND startsWith(batch_id,'" + batchID + "-') AND raw_sha256='" + digest + "' FORMAT JSONEachRow"
	raw, e := s.objectQuery(ctx, query, nil)
	if e != nil {
		return nil, e
	}
	var got struct {
		Rows     string `json:"rows"`
		Variants string `json:"variants"`
	}
	if json.Unmarshal(bytes.TrimSpace(raw), &got) != nil || got.Rows != strconv.Itoa(len(rows)) || got.Variants != got.Rows {
		return nil, errors.New("LAMBDA_ANALYTICS_READBACK_DIFFERS")
	}
	return model.Document{"table": "native_metric_samples", "source_id": sourceID, "batch_id": batchID, "row_count": len(rows), "row_digest": digest, "kind": kind}, nil
}
