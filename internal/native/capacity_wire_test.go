package native

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/telemetry"
)

func capacityWireProofFixture(missingMemory bool) CapacityPopulation {
	in, start, end := capacityHistoryProofFixture(missingMemory)
	segments, evaluation := capacityHistoryEvidence(in, start, end)
	return CapacityPopulation{SchemaVersion: "1", Binding: telemetry.Binding{TenantID: "tenant", WorkloadID: "workload", ResourceID: "resource", Provider: "AWS", ProviderResourceID: "i-0123456789abcdef0", AccountID: "111122223333", Region: "eu-west-1"}, ConnectionID: "native", ConnectionVersion: 1, ConfigHash: "config", SafetyProfileID: "profile", SafetyProfileVersion: 1, SafetyProfileHash: "profile-hash", AsOf: in.Now, Start: start, End: end, HistoryDays: 14, Timezone: "UTC", Environment: "NON_PRODUCTION", Definitions: in.Definitions, Segments: segments, ReceiptIDs: []string{"original-receipt"}, SourceRefs: []CapacityReceiptRef{{ReceiptID: "original-receipt", BatchID: "original-batch", ConfigHash: "config", RawSHA256: "raw", CanonicalHash: "canonical"}}, ReasonCodes: []string{}, Evaluation: evaluation}
}

func legacyCapacityPopulationWire(population CapacityPopulation) ([]byte, error) {
	population.PopulationHash = CapacityPopulationHash(population)
	var out bytes.Buffer
	err := json.NewEncoder(&out).Encode(population)
	return out.Bytes(), err
}

func TestCapacityPopulationWireReusesExactlyTheHashedJSON(t *testing.T) {
	for _, missing := range []bool{false, true} {
		t.Run(strconv.FormatBool(missing), func(t *testing.T) {
			population := capacityWireProofFixture(missing)
			before, _ := json.Marshal(population)
			want, err := legacyCapacityPopulationWire(population)
			if err != nil {
				t.Fatal(err)
			}
			got, err := capacityPopulationWire(population)
			if err != nil || !bytes.Equal(got, want) {
				t.Fatal("request-local serialization changed the complete population HTTP bytes or hash", err)
			}
			after, _ := json.Marshal(population)
			if !bytes.Equal(before, after) {
				t.Fatal("serialization changed the caller's proof")
			}
			var restored CapacityPopulation
			if json.Unmarshal(got, &restored) != nil || restored.PopulationHash != CapacityPopulationHash(restored) {
				t.Fatal("wire population did not independently verify")
			}
			if missing && (restored.Evaluation.Status != "BLOCKED" || restored.Evaluation.Metrics[1].Maximum != nil) {
				t.Fatal("missing memory became observed demand")
			}
			// Existing fixed pre-optimization JSON and population hash goldens.
			hashes := [2]string{"d39b39704e4682bae496bb6e4cc37f4598adfdf1ca14f73381f2aef7aaa7d6e8", "c8478c9e7dbd758ad947aa9c35847584dfa2fab4a696544d08d0868f2fa995d0"}
			if missing {
				hashes = [2]string{"8d53e071968daa0e030dcc99207c56ad8f100220d18a9f261fe7a9c2ea828f91", "69e2320ac306d55db3811273419067401e352425e86d30d4a9a044f899381614"}
			}
			if telemetry.BytesHash(bytes.TrimSuffix(got, []byte{'\n'})) != hashes[0] || restored.PopulationHash != hashes[1] {
				t.Fatal("pre-optimization provenance golden changed")
			}
		})
	}
}

func TestCapacityPopulationWirePreservesNullsEscapesIntegersAndTime(t *testing.T) {
	at := time.Date(2026, 10, 25, 1, 30, 0, 123456789, time.FixedZone("observed", 3600))
	population := CapacityPopulation{SchemaVersion: "1", ConnectionVersion: 9007199254740993, ConfigHash: "<>&\u2028\u2029", AsOf: at,
		Segments: []telemetry.Segment{{ID: "counter-reset", Type: "SUM", Status: "RESET", Value: "", Start: at, End: at.Add(time.Minute), ReasonCodes: []string{"TELEMETRY_COUNTER_RESET"}},
			{ID: "histogram", Type: "HISTOGRAM", Status: "OBSERVED", Histogram: &telemetry.Histogram{Count: 9007199254740993, Bounds: []string{"100"}, BucketCounts: []uint64{9007199254740992, 1}}, SampleIDs: []string{}, RawHashes: []string{"raw"}}},
		Evaluation: telemetry.Evaluation{Status: "BLOCKED", Metrics: []telemetry.MetricResult{{Status: "BLOCKED", Maximum: nil, ReasonCodes: []string{"TELEMETRY_UNKNOWN_INTERVAL"}, SegmentIDs: []string{}}}}, PopulationHash: "supplied-old-hash"}
	want, err := legacyCapacityPopulationWire(population)
	if err != nil {
		t.Fatal(err)
	}
	got, err := capacityPopulationWire(population)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatal("JSON scalar/null/collection semantics changed", err)
	}
	if bytes.Contains(got, []byte("supplied-old-hash")) {
		t.Fatal("stale caller hash was reused")
	}
	population.AsOf = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)
	if raw, err := capacityPopulationWire(population); err == nil || raw != nil {
		t.Fatal("failed encoding emitted a partial proof")
	}
}

func TestNativeAnalyticsUsesOneIdenticalBatchHashForRowsAndDedupe(t *testing.T) {
	batch := telemetry.Batch{SchemaVersion: "1", Binding: telemetry.Binding{TenantID: "tenant-a"}, ConnectionID: "native", Samples: []telemetry.Sample{{ID: "observed", Metric: "cpu", Time: time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC), Value: "0.25"}}}
	expected := telemetry.CanonicalHash(batch)
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		query := r.URL.Query()
		var row model.Document
		if json.NewDecoder(r.Body).Decode(&row) != nil || model.String(row, "canonical_hash") != expected {
			t.Error("analytics row canonical hash changed")
		}
		token := "tenant-a:batch-a:" + expected
		if strings.Contains(query.Get("query"), "native_metric_batches") {
			token = "tenant-a:batch-a:batch:" + expected
		}
		if query.Get("insert_deduplication_token") != token {
			t.Error("analytics idempotency hash changed")
		}
		if r.Method != http.MethodPost {
			t.Error("analytics method changed")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	storage := &Storage{Database: "finops", AnalyticsURL: server.URL, Client: server.Client()}
	ref, err := storage.WriteFacts(context.Background(), "tenant-a", "batch-a", batch)
	if err != nil || calls != 2 || model.String(ref, "canonical_hash") != expected || model.Number(ref, "sample_count") != 1 {
		t.Fatal("analytics publication changed", err)
	}
}

func BenchmarkCapacityPopulationWire(b *testing.B) {
	population := capacityWireProofFixture(false)
	// Same actual 14-day, five-minute population in both paths; no observations omitted.
	for _, optimized := range []bool{false, true} {
		name := "legacy_hash_then_encode"
		if optimized {
			name = "request_local_single_encoding"
		}
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				var raw []byte
				var err error
				if optimized {
					raw, err = capacityPopulationWire(population)
				} else {
					raw, err = legacyCapacityPopulationWire(population)
				}
				if err != nil {
					b.Fatal(err)
				}
				if len(raw) == 0 {
					b.Fatal(io.ErrUnexpectedEOF)
				}
			}
		})
	}
}
