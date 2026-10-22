package telemetry

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func historyDerivationFixture(name string) HistoryInput {
	now := time.Date(2026, 10, 18, 12, 30, 0, 123456789, time.UTC)
	end := time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC)
	start := end.AddDate(0, 0, -14)
	d := Definition{ID: "cpu-v1", Version: "1", Metric: "cpu_utilization", Type: "GAUGE", Unit: "ratio", CadenceSeconds: 300, MaxGapSeconds: 600}
	in := HistoryInput{Now: now, Definitions: []Definition{d}, Days: 14, Timezone: "UTC"}
	point := func(at time.Time, value string) Sample {
		s := nativeSample(d, at, value)
		s.SourceHashes = []string{strings.Repeat("b", 64), strings.Repeat("a", 64)}
		return s
	}
	for at := start.Add(-5 * time.Minute); !at.After(end); at = at.Add(5 * time.Minute) {
		in.Samples = append(in.Samples, point(at, "0.25"))
	}
	switch name {
	case "ready":
	case "observed_zero":
		for i := range in.Samples {
			in.Samples[i].Value = "0"
		}
	case "gap":
		in.Samples = append(in.Samples[:100], in.Samples[103:]...)
	case "conflict":
		other := in.Samples[100]
		other.Value = "0.75"
		in.Samples = append(in.Samples, other)
	case "missing_memory":
		memory := d
		memory.ID, memory.Metric = "memory-v1", "memory_utilization"
		in.Definitions = append(in.Definitions, memory)
	case "counter_reset":
		d.ID, d.Metric, d.Type, d.Unit = "requests-v1", "request_count", "SUM", "count"
		in.Definitions, in.Samples = []Definition{d}, nil
		for i, value := range []string{"100", "130", "1", "7", "10"} {
			s := point(start.Add(time.Duration(i)*5*time.Minute), value)
			s.Temporality, s.Epoch = "CUMULATIVE", "old"
			if i >= 2 {
				s.Epoch = "new"
			}
			in.Samples = append(in.Samples, s)
		}
	case "histogram":
		d.ID, d.Metric, d.Type, d.Unit = "latency-v1", "latency", "HISTOGRAM", "milliseconds"
		in.Definitions, in.Samples = []Definition{d}, nil
		for i := 0; i < 4; i++ {
			s := point(start.Add(time.Duration(i+1)*5*time.Minute), "")
			s.StartTime, s.Temporality = s.Time.Add(-5*time.Minute), "DELTA"
			s.Histogram = &Histogram{Count: 9007199254740993, Bounds: []string{"100", "1000"}, BucketCounts: []uint64{9007199254740992, 1, 0}}
			in.Samples = append(in.Samples, s)
		}
	case "dst":
		in.Now = time.Date(2026, 4, 5, 12, 0, 0, 0, time.UTC)
		in.Timezone = "Europe/London"
	case "invalid":
		in.Timezone = "not/a/timezone"
	default:
		panic("unknown history proof fixture")
	}
	return in
}

// Golden values are captured from the unchanged two-derivation implementation.
// They bind the entire JSON values, including provenance IDs, missing values,
// original interval boundaries, histogram integer text and evaluation hashes.
func TestHistoryDerivationPreservesLegacyProofs(t *testing.T) {
	want := map[string][2]string{
		"ready":          {"7dc661efc6c0d3ab9c7fcf83789cca2668732910150fcab4bd1e06b6c4dc928c", "b71813d59b9ec95d024c29bf53d4a264a43e40119606b7d26d79fab25e472b20"},
		"observed_zero":  {"62e2245435afe84df243253ad410f731e5480b70cec53e0eab793fef1479f777", "d58a8d2ff043791c5747e7b508d891e7f28225470be2869d3416116b4f459cf7"},
		"gap":            {"f11f2b3a8064c9edf0dbed67f53c2614f97ea768cb860f13a9e907ce6db5bc83", "9a92634aed71fd69a243045ea833d0076f17fbb8684ca9b443a757fcd0bde865"},
		"conflict":       {"bfdbb78bd1051949e9d705867e1db4582578209ae5b9fcfa5254247311d9bab8", "ce8a1c34f6dcd7ffa8a30b5a92de6b830114088b4a6309d5226c636aaf2dafe0"},
		"missing_memory": {"d6f319466a4dc73f0df2f203a5459e9552fb79d420d4c04b1923ab7dca5dfae3", "b71813d59b9ec95d024c29bf53d4a264a43e40119606b7d26d79fab25e472b20"},
		"counter_reset":  {"71830b353171141d1f74a76d61c67bf203a8c5e09d2a59d47ec4860f0474c476", "4d09e1243df5a509d0760084f231b1cafb3ba51008a7d69d2c3f85a87212d352"},
		"histogram":      {"22b370883447b86a9bc23838f982e865d7e0f8b9399c46a2f49094904634e632", "2ea6d35817a11ce9f1fe63072d1fec3252454ea472fa3d0b0ffc03af6040bf03"},
		"dst":            {"1b2b456edceadf7997db66993922eef0b6fdcb1df1e4e0ea0e2386a898ce8cbf", "b71813d59b9ec95d024c29bf53d4a264a43e40119606b7d26d79fab25e472b20"},
		"invalid":        {"c8984ee5806a02ec8801ea56fc7e795b2cbcca1fd4c0b497493aa1bbcaa59cf4", "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b"},
	}
	for _, name := range []string{"ready", "observed_zero", "gap", "conflict", "missing_memory", "counter_reset", "histogram", "dst", "invalid"} {
		t.Run(name, func(t *testing.T) {
			in := historyDerivationFixture(name)
			before := Hash(in)
			evaluation, segments := EvaluateHistoryWithSegments(in)
			if Hash(evaluation) != want[name][0] || Hash(segments) != want[name][1] {
				t.Fatal("combined derivation changed the original history JSON or segment proof")
			}
			if Hash(EvaluateHistory(in)) != want[name][0] {
				t.Fatal("existing history API changed its evaluation proof")
			}
			if name != "invalid" && Hash(Segments(in.Samples, in.Definitions)) != want[name][1] {
				t.Fatal("returned intervals differ from direct native derivation")
			}
			if Hash(in) != before {
				t.Fatal("history derivation mutated original observations")
			}
			if name == "ready" && (evaluation.Status != "READY" || evaluation.Metrics[0].CoveragePPM != 1000000) {
				t.Fatal("complete native fixture did not establish coverage")
			}
			if name == "missing_memory" && (evaluation.Status != "BLOCKED" || len(evaluation.Metrics) != 2 || evaluation.Metrics[1].Maximum != nil) {
				t.Fatal("missing memory became an observed value")
			}
			if name == "counter_reset" && (segments[2].Status != "RESET" || segments[2].Value != "") {
				t.Fatal("counter reset invented a delta")
			}
			wire, err := json.Marshal(evaluation)
			if err != nil {
				t.Fatal(err)
			}
			if len(segments) > 0 {
				segments[0].Value = "tampered caller copy"
				segments[0].ReasonCodes = append(segments[0].ReasonCodes, "CALLER_MUTATION")
				for i := range segments {
					if segments[i].Histogram != nil {
						segments[i].Histogram.BucketCounts[0]++
						break
					}
				}
			}
			currentWire, _ := json.Marshal(evaluation)
			if string(wire) != string(currentWire) || Hash(in) != before || Hash(EvaluateHistory(in)) != want[name][0] {
				t.Fatal("returned segments alias original observations, sealed evaluation, or later requests")
			}
		})
	}
}

func BenchmarkHistoryDerivation(b *testing.B) {
	in := historyDerivationFixture("ready")
	for _, combined := range []bool{false, true} {
		name := "legacy_two_derivations"
		if combined {
			name = "combined_request_local"
		}
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if combined {
					EvaluateHistoryWithSegments(in)
				} else {
					Segments(in.Samples, in.Definitions)
					EvaluateHistory(in)
				}
			}
		})
	}
}
