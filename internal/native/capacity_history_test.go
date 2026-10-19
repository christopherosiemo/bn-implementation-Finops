package native

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/telemetry"
)

func capacityHistoryProofFixture(missingMemory bool) (telemetry.HistoryInput, time.Time, time.Time) {
	end := time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC)
	start := end.AddDate(0, 0, -14)
	cpu := telemetry.Definition{ID: "cpu", Version: "1", Metric: "cpu_utilization", Type: "GAUGE", Unit: "ratio", CadenceSeconds: 300, MaxGapSeconds: 600}
	memory := cpu
	memory.ID, memory.Metric = "memory", "memory_utilization"
	in := telemetry.HistoryInput{Now: end.Add(12 * time.Hour), Definitions: []telemetry.Definition{cpu, memory}, Days: 14, Timezone: "UTC"}
	for _, d := range in.Definitions {
		if missingMemory && d.ID == "memory" {
			continue
		}
		for at := start.Add(-5 * time.Minute); !at.After(end); at = at.Add(5 * time.Minute) {
			in.Samples = append(in.Samples, telemetry.Sample{DefinitionID: d.ID, StreamID: d.ID + "-stream", Metric: d.Metric, Type: d.Type, Unit: d.Unit, Time: at, Value: "0.25", Temporality: "INSTANT", Statistic: "SAMPLED_VALUE", RawSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ReasonCodes: []string{}})
		}
	}
	return in, start, end
}

func TestCapacityHistoryDerivationPreservesPopulationWireAndHash(t *testing.T) {
	// Entire population JSON and the embedded PopulationHash were captured
	// before replacing the native selector's two independent derivations.
	want := map[string][2]string{
		"complete":       {"d39b39704e4682bae496bb6e4cc37f4598adfdf1ca14f73381f2aef7aaa7d6e8", "c8478c9e7dbd758ad947aa9c35847584dfa2fab4a696544d08d0868f2fa995d0"},
		"missing_memory": {"8d53e071968daa0e030dcc99207c56ad8f100220d18a9f261fe7a9c2ea828f91", "69e2320ac306d55db3811273419067401e352425e86d30d4a9a044f899381614"},
	}
	for _, missing := range []bool{false, true} {
		name := "complete"
		if missing {
			name = "missing_memory"
		}
		t.Run(name, func(t *testing.T) {
			in, start, end := capacityHistoryProofFixture(missing)
			segments, evaluation := capacityHistoryEvidence(in, start, end)
			population := CapacityPopulation{SchemaVersion: "1", Binding: telemetry.Binding{TenantID: "tenant", WorkloadID: "workload", ResourceID: "resource", Provider: "AWS", ProviderResourceID: "i-0123456789abcdef0", AccountID: "111122223333", Region: "eu-west-1"}, ConnectionID: "native", ConnectionVersion: 1, ConfigHash: "config", SafetyProfileID: "profile", SafetyProfileVersion: 1, SafetyProfileHash: "profile-hash", AsOf: in.Now, Start: start, End: end, HistoryDays: 14, Timezone: "UTC", Environment: "NON_PRODUCTION", Definitions: in.Definitions, Segments: segments, ReceiptIDs: []string{"original-receipt"}, SourceRefs: []CapacityReceiptRef{{ReceiptID: "original-receipt", BatchID: "original-batch", ConfigHash: "config", RawSHA256: "raw", CanonicalHash: "canonical"}}, ReasonCodes: []string{}, Evaluation: evaluation}
			population.PopulationHash = CapacityPopulationHash(population)
			raw, err := json.Marshal(population)
			if err != nil {
				t.Fatal(err)
			}
			if telemetry.BytesHash(raw) != want[name][0] || population.PopulationHash != want[name][1] {
				t.Fatal("native history optimization changed population bytes or its signed-source consistency hash")
			}
			if missing && (evaluation.Status != "BLOCKED" || evaluation.Metrics[1].Maximum != nil) {
				t.Fatal("missing physical evidence became an observed zero")
			}
		})
	}
}

func TestCapacityHistoryDoesNotAcceptDerivedProofsFromCaller(t *testing.T) {
	s := &Server{ReaderToken: "private-reader"}
	for _, field := range []string{"segments", "evaluation", "population_hash"} {
		in := model.Document{"tenant_id": "tenant", "connection_id": "connection", "config_hash": "config", "safety_profile_id": "profile", "safety_profile_version": 1, field: []any{}}
		if response := capacityRequest(s, in, "private-reader"); response.Code != http.StatusBadRequest {
			t.Fatalf("caller-provided %s reached evidence resolution: %d", field, response.Code)
		}
	}
}
