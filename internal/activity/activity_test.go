package activity

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
)

func observation() store.ActivityInterval {
	return store.ActivityInterval{SchemaVersion: "1", SourceID: "gateway", ResourceID: "resource-dev", WorkloadID: "workload-dev", Sequence: 2, IntervalStart: time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC), IntervalEnd: time.Date(2026, 10, 18, 12, 1, 0, 0, time.UTC), MetricDefinition: store.ActivityMetric{ID: "orders", Version: "1", Unit: "order"}, Heartbeat: true, Incident: "CLEAR", Deployment: "CLEAR", Job: "CLEAR"}
}
func TestObservationRequiresExplicitCountsAndOperationalStates(t *testing.T) {
	valid := observation()
	raw, _ := json.Marshal(valid)
	if _, err := Decode(raw); err != nil {
		t.Fatal(err)
	}
	var object map[string]any
	_ = json.Unmarshal(raw, &object)
	for _, field := range []string{"accepted", "completed", "rejected", "backlog", "inflight", "heartbeat", "incident", "deployment", "job"} {
		t.Run(field, func(t *testing.T) {
			copy := map[string]any{}
			for k, v := range object {
				copy[k] = v
			}
			delete(copy, field)
			b, _ := json.Marshal(copy)
			if _, err := Decode(b); err == nil {
				t.Fatal("missing observation silently became zero/clear")
			}
		})
	}
	for name, mutate := range map[string]func(*store.ActivityInterval){"negative": func(v *store.ActivityInterval) { v.Rejected = -1 }, "partial minute": func(v *store.ActivityInterval) { v.IntervalEnd = v.IntervalEnd.Add(time.Second) }, "non-minute alignment": func(v *store.ActivityInterval) {
		v.IntervalStart = v.IntervalStart.Add(time.Second)
		v.IntervalEnd = v.IntervalEnd.Add(time.Second)
	}, "unknown state": func(v *store.ActivityInterval) { v.Incident = "" }, "no metric version": func(v *store.ActivityInterval) { v.MetricDefinition.Version = "" }, "sequence": func(v *store.ActivityInterval) { v.Sequence = 0 }} {
		t.Run(name, func(t *testing.T) {
			v := valid
			mutate(&v)
			if Validate(v) == nil {
				t.Fatal("invalid interval accepted")
			}
		})
	}
}
func TestFreshActivityFailsClosedAndRequestsRecoveryOnWork(t *testing.T) {
	now := time.Date(2026, 10, 18, 12, 1, 20, 0, time.UTC)
	previous := observation().IntervalStart
	receipt := store.ActivityReceipt{ActivityInterval: observation(), ID: "receipt", ReceivedAt: now.Add(-10 * time.Second), PreviousIntervalEnd: &previous, PreviousSequence: 1, PreviousIdle: true}
	if result := FreshActivity(now, receipt, 2*time.Minute); result.Status != "CLEAR" {
		t.Fatalf("complete idle observation:%+v", result)
	}
	for name, change := range map[string]func(*store.ActivityReceipt){"accepted": func(r *store.ActivityReceipt) { r.Accepted = 1 }, "completed": func(r *store.ActivityReceipt) { r.Completed = 1 }, "rejected": func(r *store.ActivityReceipt) { r.Rejected = 1 }, "backlog": func(r *store.ActivityReceipt) { r.Backlog = 1 }, "inflight": func(r *store.ActivityReceipt) { r.Inflight = 1 }, "incident": func(r *store.ActivityReceipt) { r.Incident = "ACTIVE" }, "deployment": func(r *store.ActivityReceipt) { r.Deployment = "ACTIVE" }, "job": func(r *store.ActivityReceipt) { r.Job = "ACTIVE" }} {
		t.Run(name, func(t *testing.T) {
			r := receipt
			change(&r)
			if FreshActivity(now, r, 2*time.Minute).Status != "ACTIVE" {
				t.Fatal("work did not signal early restoration")
			}
		})
	}
	for name, change := range map[string]func(*store.ActivityReceipt){"missing": func(r *store.ActivityReceipt) { r.ID = "" }, "stale interval": func(r *store.ActivityReceipt) { r.IntervalEnd = now.Add(-3 * time.Minute) }, "stale receipt": func(r *store.ActivityReceipt) { r.ReceivedAt = now.Add(-3 * time.Minute) }, "heartbeat": func(r *store.ActivityReceipt) { r.Heartbeat = false }, "unknown incident": func(r *store.ActivityReceipt) { r.Incident = "UNKNOWN" }, "gap": func(r *store.ActivityReceipt) { r.PreviousIntervalEnd = nil }, "sequence gap": func(r *store.ActivityReceipt) { r.PreviousSequence = 0 }, "prior demand": func(r *store.ActivityReceipt) { r.PreviousIdle = false }} {
		t.Run(name, func(t *testing.T) {
			r := receipt
			change(&r)
			if FreshActivity(now, r, 2*time.Minute).Status != "UNKNOWN" {
				t.Fatal("missing evidence became idle")
			}
		})
	}
}
