package activity

import (
	"encoding/json"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"strings"
	"testing"
	"time"
)

func lambdaBenchmarkBody() model.Document {
	now := time.Now().UTC()
	return model.Document{"schema_version": "1", "source_id": "source", "source_version": 1, "sequence": "1", "point": model.Document{"binding": model.Document{"tenant_id": "tenant", "resource_id": "function", "workload_id": "workload", "provider": "AWS", "provider_resource_id": "arn:aws:lambda:eu-west-1:111122223333:function:app", "account_id": "111122223333", "region": "eu-west-1"}, "qualifier": "live", "executed_version": "3", "code_sha256": strings.Repeat("a", 64), "comparison_fingerprint": strings.Repeat("b", 64), "workload_definition_id": "successful-messages", "workload_definition_version": "1", "workload_mix_hash": strings.Repeat("c", 64), "load_profile_hash": strings.Repeat("d", 64), "architecture": "x86_64", "memory_size_mb": "1024", "invocations": "10", "successful_work": "100", "errors": "0", "throttles": "0", "p95_duration_ms": "120", "p99_duration_ms": "150", "max_memory_used_mb": "450", "peak_concurrent_executions": "2", "total_duration_ms": "1050.5", "total_billed_duration_ms": "1060", "measurement_start": now.Add(-2 * time.Hour).Format(time.RFC3339Nano), "measurement_end": now.Add(-time.Hour).Format(time.RFC3339Nano)}}
}
func TestLambdaPerformanceKeepsBusinessWorkAndRejectsAuthorityConfusion(t *testing.T) {
	d := lambdaBenchmarkBody()
	raw, _ := json.Marshal(d)
	if _, e := decodeLambdaPerformance(raw); e != nil {
		t.Fatal(e)
	}
	for name, alter := range map[string]func(model.Document){
		"money":                      func(d model.Document) { d["monthly_saving"] = "100" },
		"caller-provenance":          func(d model.Document) { d["trusted"] = true },
		"candidate-authority":        func(d model.Document) { d["point"].(map[string]any)["execution_authorized"] = true },
		"float-duration":             func(d model.Document) { d["point"].(map[string]any)["total_duration_ms"] = 1.2 },
		"missing-measurement":        func(d model.Document) { delete(d["point"].(map[string]any), "total_billed_duration_ms") },
		"impossible-billed-duration": func(d model.Document) { d["point"].(map[string]any)["total_billed_duration_ms"] = "1" },
		"future": func(d model.Document) {
			d["point"].(map[string]any)["measurement_end"] = time.Now().Add(time.Hour).Format(time.RFC3339Nano)
		},
		"arbitrary-old-backfill": func(d model.Document) {
			d["point"].(map[string]any)["measurement_start"] = time.Now().Add(-400 * 24 * time.Hour).Format(time.RFC3339Nano)
		},
		"invalid-code":       func(d model.Document) { d["point"].(map[string]any)["code_sha256"] = "fiction" },
		"unsupported-memory": func(d model.Document) { d["point"].(map[string]any)["memory_size_mb"] = "32768" },
	} {
		t.Run(name, func(t *testing.T) {
			x := model.Clone(d)
			alter(x)
			r, _ := json.Marshal(x)
			if _, e := decodeLambdaPerformance(r); e == nil {
				t.Fatal("untrusted/invalid benchmark accepted")
			}
		})
	}
	duplicated := strings.Replace(string(raw), `"sequence":"1"`, `"sequence":"1","sequence":"2"`, 1)
	if _, e := decodeLambdaPerformance([]byte(duplicated)); e == nil {
		t.Fatal("duplicate field accepted")
	}
	if _, e := decodeLambdaPerformance(append(raw, []byte(` {}`)...)); e == nil {
		t.Fatal("trailing object accepted")
	}
}
