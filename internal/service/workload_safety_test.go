package service

import (
	"encoding/json"
	"testing"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
)

func TestSafetyRequirementsDoNotDefaultUnknownValues(t *testing.T) {
	const body = `{"schema_version":"1","criticality":"NON_PRODUCTION","statefulness":"STATELESS","high_seasonality":false,"timezone":"Europe/London","min_replicas":20,"min_zones":3,"headroom":{"cpu_free_ppm":300000,"memory_free_ppm":250000,"reserve_above_forecast_ppm":300000},"saturation":{"cpu_p99_ppm":850000,"memory_p99_ppm":900000},"rto_seconds":900,"rpo_seconds":null,"maintenance":[{"days":[0,1,2,3,4,5,6],"start_time":"00:00","end_time":"24:00"}],"recurring_blackouts":[],"blackouts":[],"demand_events":[],"max_simultaneous_change_ppm":100000,"vm_cooldown_seconds":604800}`
	var d model.Document
	if json.Unmarshal([]byte(body), &d) != nil {
		t.Fatal("fixture invalid")
	}
	if p, err := safetyProfileRequest(d); err != nil || p.RPOSeconds != nil {
		t.Fatalf("explicit unknown RPO must remain unavailable: %v", err)
	}
	for _, field := range []string{"high_seasonality", "maintenance", "vm_cooldown_seconds"} {
		changed := model.Clone(d)
		changed[field] = nil
		if _, err := safetyProfileRequest(changed); err == nil {
			t.Fatalf("null %s silently defaulted", field)
		}
	}
	changed := model.Clone(d)
	changed["history_complete"] = true
	if _, err := safetyProfileRequest(changed); err == nil {
		t.Fatal("declaration accepted caller evidence")
	}
}
