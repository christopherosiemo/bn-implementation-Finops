package workload

import (
	"encoding/json"
	"testing"
	"time"
)

func testProfile() Profile {
	return Profile{SchemaVersion: "1", Criticality: "NON_PRODUCTION", Statefulness: "STATELESS", Timezone: "Europe/London", MinReplicas: 6, MinZones: 3, Headroom: Headroom{300000, 250000, 300000}, Saturation: Saturation{850000, 900000}, RTOSeconds: 900, MaxSimultaneousChangePPM: 100000, VMCooldownSeconds: 604800, Maintenance: []WeeklyWindow{{[]int{0}, "00:00", "04:00"}}}
}
func at(s string) time.Time { v, _ := time.Parse(time.RFC3339, s); return v }
func TestHeadroomAndUnavailableRPO(t *testing.T) {
	p := testProfile()
	if Validate(p) != nil || p.RPOSeconds != nil {
		t.Fatal("requirements should not invent RPO")
	}
	raw, _ := json.Marshal(p)
	if _, e := Decode(raw); e != nil {
		t.Fatal(e)
	}
	if _, e := Decode(append(raw[:len(raw)-1], []byte(`,"evidence_complete":true}`)...)); e == nil {
		t.Fatal("caller evidence accepted")
	}
	p.MinZones = 7
	if Validate(p) == nil {
		t.Fatal("impossible topology accepted")
	}
}
func TestWholeMaintenanceAndBlackouts(t *testing.T) {
	p := testProfile()
	start, end := at("2026-10-18T00:00:00Z"), at("2026-10-18T01:00:00Z")
	if r := EvaluateWindow(p, start, end); r.Status != "CLEAR" {
		t.Fatal(r)
	}
	p.Blackouts = []Blackout{{"payroll", "declared event", start.Add(35 * time.Second), start.Add(40 * time.Second)}}
	if r := EvaluateWindow(p, start, end); r.Status != "BLOCKED" {
		t.Fatal("subminute blackout escaped")
	}
	p.Blackouts = nil
	p.RecurringBlackouts = []WeeklyWindow{{[]int{0}, "01:30", "01:31"}}
	if r := EvaluateWindow(p, start, end); r.Status != "BLOCKED" {
		t.Fatal("interior blackout escaped")
	}
}
func TestDSTBothRepeatedHoursAndNoInventedGap(t *testing.T) {
	p := testProfile()
	p.Maintenance = []WeeklyWindow{{[]int{0}, "01:00", "02:00"}}
	for _, s := range []string{"2026-10-25T00:10:00Z", "2026-10-25T01:10:00Z"} {
		start := at(s)
		if r := EvaluateWindow(p, start, start.Add(10*time.Minute)); r.Status != "CLEAR" {
			t.Fatal(r)
		}
	}
	p.Maintenance = []WeeklyWindow{{[]int{0}, "01:10", "01:50"}}
	start := at("2026-03-29T00:59:00Z")
	if r := EvaluateWindow(p, start, start.Add(2*time.Minute)); r.Status != "BLOCKED" {
		t.Fatal("nonexistent maintenance invented")
	}
}
func TestOvernightWindowAndConcurrentBudget(t *testing.T) {
	p := testProfile()
	p.Maintenance = []WeeklyWindow{{[]int{6}, "23:00", "02:00"}}
	start := at("2026-10-18T00:00:00Z")
	if r := EvaluateWindow(p, start, start.Add(10*time.Minute)); r.Status != "CLEAR" {
		t.Fatal(r)
	}
	if r := EvaluateTopology(p, 20, 3, 20, 0, 2); r.Status != "CLEAR" || r.SimultaneousBudget != 2 {
		t.Fatal(r)
	}
	if r := EvaluateTopology(p, 20, 3, 20, 1, 2); r.Status != "BLOCKED" {
		t.Fatal("parallel rollout escaped budget")
	}
	if r := EvaluateTopology(p, 20, 2, 20, 0, 1); r.Status != "BLOCKED" {
		t.Fatal("zone minimum ignored")
	}
	if r := EvaluateTopology(p, 1, 1, 1, 0, 1); r.Status != "BLOCKED" {
		t.Fatal("tiny fleet rounded to100%")
	}
}

func TestExplicitFullDayEnd(t *testing.T) {
	p := testProfile()
	p.Maintenance = []WeeklyWindow{{[]int{0}, "00:00", "24:00"}}
	start := at("2026-10-18T22:59:00Z")
	if r := EvaluateWindow(p, start, start.Add(time.Minute)); r.Status != "CLEAR" {
		t.Fatal(r)
	}
	p.Maintenance[0].StartTime = "24:00"
	if Validate(p) == nil {
		t.Fatal("24:00 must only be a window end")
	}
}
