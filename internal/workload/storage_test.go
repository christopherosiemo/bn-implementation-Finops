package workload

import (
	"encoding/json"
	"testing"
)

func TestStoragePolicyPreservesUnknownRequirementsAndBounds(t *testing.T) {
	p := testProfile()
	p.Statefulness = "STATEFUL"
	p.Storage = &StorageLimits{IOPSMaxFraction: "0.8", ThroughputMaxFraction: "0.7", MaxReadLatencySeconds: "0.02", MaxWriteLatencySeconds: "0.02", MaxDiskQueueDepth: "2", MinBurstBalancePercent: "20", SnapshotRetentionDays: 30, QuarantineDays: 14}
	raw, _ := json.Marshal(p)
	got, e := Decode(raw)
	if e != nil || got.Storage.BackupRequired != nil || got.Storage.AllowDurabilityReduction != nil {
		t.Fatal("unknown storage requirements were defaulted", e)
	}
	p.Storage.IOPSMaxFraction = "1.01"
	if Validate(p) == nil {
		t.Fatal("impossible IOPS fraction accepted")
	}
	p.Storage.IOPSMaxFraction = "0.8"
	p.Storage.MaxReadLatencySeconds = "-0.01"
	if Validate(p) == nil {
		t.Fatal("negative latency accepted")
	}
}
