package native

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/telemetry"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/workload"
)

func TestCapacityHistoryUsesCompleteLocalCalendarAndCriticality(t *testing.T) {
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	profile := workload.Profile{Criticality: "NON_PRODUCTION", Timezone: "Europe/London"}
	start, end, days, err := capacityHistory(now, profile)
	if err != nil || days != 14 || end.Sub(start) != 337*time.Hour || start.Format(time.RFC3339) != "2026-10-11T23:00:00Z" || end.Format(time.RFC3339) != "2026-10-26T00:00:00Z" {
		t.Fatalf("DST history collapsed to fixed UTC days: %s %s %d %v", start, end, days, err)
	}
	profile.Criticality = "TIER_2"
	if _, _, days, err = capacityHistory(now, profile); err != nil || days != 30 {
		t.Fatal("production history did not require 30 complete local days")
	}
	profile.HighSeasonality = true
	if _, _, days, err = capacityHistory(now, profile); err != nil || days != 90 {
		t.Fatal("seasonality did not override production history to 90 days")
	}
	profile.Timezone = "not/a/timezone"
	if _, _, _, err = capacityHistory(now, profile); err == nil {
		t.Fatal("invalid timezone accepted")
	}
}

func capacityRequest(s *Server, body any, token string) *httptest.ResponseRecorder {
	raw, _ := json.Marshal(body)
	r := httptest.NewRequest(http.MethodPost, "/capacity-input", bytes.NewReader(raw))
	r.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}

func TestCapacitySelectorRejectsPublicAuthorityAndClosedInput(t *testing.T) {
	s := &Server{ReaderToken: "private-reader"}
	if response := capacityRequest(s, model.Document{}, "console-token"); response.Code != 401 {
		t.Fatalf("console token accepted: %d", response.Code)
	}
	for _, input := range []model.Document{
		{"tenant_id": "t", "connection_id": "c"},
		{"tenant_id": "t", "connection_id": "c", "config_hash": "h", "safety_profile_id": "p", "safety_profile_version": 1, "metrics": []any{}},
		{"tenant_id": "t", "connection_id": "c", "config_hash": "h", "safety_profile_id": "p", "safety_profile_version": 1, "prices": []any{}},
		{"tenant_id": "t", "connection_id": "c", "config_hash": "h", "safety_profile_id": "p", "safety_profile_version": 1, "start": "2000-01-01T00:00:00Z"},
	} {
		if response := capacityRequest(s, input, "private-reader"); response.Code != 400 {
			t.Fatalf("caller selected history or evidence: %d %s", response.Code, response.Body.String())
		}
	}
}

func capacityFixtureProfile(t *testing.T, f *runtimeFixture) model.Document {
	t.Helper()
	p := workload.Profile{SchemaVersion: "1", Criticality: "NON_PRODUCTION", Statefulness: "UNKNOWN", Timezone: "UTC", MinReplicas: 1, MinZones: 1, Headroom: workload.Headroom{CPUFreePPM: 300000, MemoryFreePPM: 250000, ReserveAboveForecastPPM: 300000}, Saturation: workload.Saturation{CPUP99PPM: 850000, MemoryP99PPM: 900000}, RTOSeconds: 300, MaxSimultaneousChangePPM: 250000, VMCooldownSeconds: 86400}
	var result model.Document
	if err := f.api.Do(f.ctx, f.tenant, func(tx *store.Tx) error {
		resource, err := tx.Get(f.ctx, "resources", f.c.Binding.ResourceID)
		if err != nil {
			return err
		}
		resource["environment"] = "NON_PRODUCTION"
		if _, err = tx.Update(f.ctx, "resources", f.c.Binding.ResourceID, model.Number(resource, "version"), resource); err != nil {
			return err
		}
		result, err = tx.WorkloadSafetyAppend(f.ctx, f.c.Binding.WorkloadID, 0, p)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestCapacitySelectorReadsPinnedNativePopulationAndRechecksCurrentBindings(t *testing.T) {
	f := newRuntimeFixture(t, "PROMETHEUS")
	profile := capacityFixtureProfile(t, f)
	now := time.Now().UTC()
	end := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	start := end.AddDate(0, 0, -14)
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.URL.Path == "/api/v1/metadata" {
			_ = json.NewEncoder(w).Encode(model.Document{"status": "success", "data": model.Document{"cpu_utilization": []any{model.Document{"type": "gauge", "unit": "ratio"}}}})
			return
		}
		at, err := time.Parse(time.RFC3339Nano, r.Form.Get("time"))
		if err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		query := r.Form.Get("query")
		seconds, err := strconv.Atoi(strings.TrimSuffix(query[strings.LastIndex(query, "[")+1:], "s]"))
		if err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		points := [][]any{}
		for atPoint := at.Add(-time.Duration(seconds) * time.Second).Truncate(5 * time.Minute).Add(5 * time.Minute); !atPoint.After(at); atPoint = atPoint.Add(5 * time.Minute) {
			points = append(points, []any{atPoint.Unix(), "0.35"})
		}
		_ = json.NewEncoder(w).Encode(model.Document{"status": "success", "data": model.Document{"resultType": "matrix", "result": []any{model.Document{"metric": model.Document{"__name__": "cpu_utilization", "host_id": f.c.Binding.ProviderResourceID}, "values": points}}}})
	}))
	defer remote.Close()
	binding := ReadBinding{Binding: f.c.Binding, Endpoint: remote.URL, RequiredLabels: map[string]string{"host_id": f.c.Binding.ProviderResourceID}, AllowedCIDRs: []string{"127.0.0.1/32"}}
	s := &Server{Store: f.transport, Pipeline: f.p, Fixture: true, ReaderToken: "private-reader", Bindings: map[string]ReadBinding{"approved": binding}, Now: func() time.Time { return now }}
	if _, err := s.collect(f.ctx, f.c, "capacity-full-history", start, end); err != nil {
		t.Fatal(err)
	}
	input := CapacityInputRequest{TenantID: f.tenant, ConnectionID: f.c.ID, ConfigHash: telemetry.ConfigHash(f.c), SafetyProfileID: model.String(profile, "id"), SafetyProfileVersion: model.Number(profile, "version")}
	response := capacityRequest(s, input, "private-reader")
	if response.Code != 200 {
		t.Fatalf("native population unavailable: %d %s", response.Code, response.Body.String())
	}
	var population CapacityPopulation
	if err := json.Unmarshal(response.Body.Bytes(), &population); err != nil {
		t.Fatal(err)
	}
	if population.HistoryDays != 14 || len(population.Segments) != 14*24*12 || len(population.SourceRefs) != 1 || population.PopulationHash != CapacityPopulationHash(population) || population.SafetyProfileHash != model.String(profile, "hash") {
		t.Fatalf("history/proof binding lost: days=%d segments=%d sources=%d", population.HistoryDays, len(population.Segments), len(population.SourceRefs))
	}
	for _, segment := range population.Segments {
		if segment.Status != "OBSERVED" || segment.Unit != "ratio" || segment.Value != "0.35" || segment.Statistic != "OBSERVED_SAMPLE_DISTRIBUTION" || segment.End.Sub(segment.Start) != 5*time.Minute || len(segment.RawHashes) == 0 {
			t.Fatalf("native interval rewritten as physical demand: %+v", segment)
		}
	}
	if strings.Contains(response.Body.String(), "pricing") || strings.Contains(response.Body.String(), "denominator") {
		t.Fatal("missing provider catalogue was invented by native selector")
	}
	changed := input
	changed.ConfigHash = strings.Repeat("a", 64)
	if response = capacityRequest(s, changed, "private-reader"); response.Code != 409 {
		t.Fatal("changed configuration accepted")
	}
	changed = input
	changed.SafetyProfileVersion++
	if response = capacityRequest(s, changed, "private-reader"); response.Code != 409 {
		t.Fatal("changed safety requirements accepted")
	}
	changed = input
	changed.TenantID = "unrelated-tenant"
	if response = capacityRequest(s, changed, "private-reader"); response.Code != 409 || strings.Contains(response.Body.String(), "0.35") {
		t.Fatal("cross-tenant population escaped")
	}
	if err := f.api.Do(f.ctx, f.tenant, func(tx *store.Tx) error {
		resource, err := tx.Get(f.ctx, "resources", f.c.Binding.ResourceID)
		if err != nil {
			return err
		}
		resource["environment"] = "PRODUCTION"
		_, err = tx.Update(f.ctx, "resources", f.c.Binding.ResourceID, model.Number(resource, "version"), resource)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if response = capacityRequest(s, input, "private-reader"); response.Code != 200 {
		t.Fatal("production evidence could not be inspected")
	}
	var production CapacityPopulation
	if err := json.Unmarshal(response.Body.Bytes(), &production); err != nil || production.HistoryDays != 30 || production.Environment != "PRODUCTION" || !containsRuntime(production.ReasonCodes, "CAPACITY_ENVIRONMENT_CLASSIFICATION_CONFLICT") || production.Evaluation.Status != "BLOCKED" {
		t.Fatal("nonproduction declaration waived actual production history")
	}
	f.mu.Lock()
	for key := range f.objects {
		if strings.Contains(key, "/canonical/") {
			f.objects[key] = []byte("tampered archive")
		}
	}
	f.mu.Unlock()
	if response = capacityRequest(s, input, "private-reader"); response.Code != 503 || strings.Contains(response.Body.String(), "0.35") {
		t.Fatal("tampered canonical evidence became a population")
	}
}

func TestCapacityAssessmentMetadataIsScopedImmutableAndCannotGrantAuthority(t *testing.T) {
	f := newRuntimeFixture(t, "PROMETHEUS")
	profile := capacityFixtureProfile(t, f)
	var conn model.Document
	if err := f.api.Do(f.ctx, f.tenant, func(tx *store.Tx) error { var err error; conn, err = tx.TelemetryConnection(f.ctx, f.c.ID); return err }); err != nil {
		t.Fatal(err)
	}
	metadata := model.Document{"schema_version": "1", "status": "BLOCKED", "execution_authorized": false, "estimated_saving": nil, "verified_saving": nil, "workload_id": f.c.Binding.WorkloadID, "resource_id": f.c.Binding.ResourceID, "connection_id": f.c.ID, "revision_id": conn["revision_id"], "config_hash": conn["config_hash"], "safety_profile_id": profile["id"], "safety_profile_version": profile["version"], "safety_profile_hash": profile["hash"], "population_hash": strings.Repeat("a", 64), "receipt_ids": []string{}, "reason_codes": []string{"NATIVE_CAPACITY_CATALOG_REQUIRED", "NATIVE_PRICE_UNAVAILABLE"}}
	var record model.Document
	if err := f.api.Do(f.ctx, f.tenant, func(tx *store.Tx) error {
		var err error
		record, err = tx.CapacityAssessmentCreate(f.ctx, metadata)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if model.String(record, "writer_role") != "finops_api" || model.String(record, "hash") == "" {
		t.Fatal("analytical metadata lacks server stamp")
	}
	for _, change := range []func(model.Document){
		func(d model.Document) { d["execution_authorized"] = true },
		func(d model.Document) { d["estimated_saving"] = "1.00" },
		func(d model.Document) { d["status"] = "VALIDATED" },
		func(d model.Document) { d["safety_profile_version"] = 2 },
		func(d model.Document) { d["nested"] = model.Document{"points": []any{1}} },
		func(d model.Document) { d["receipt_ids"] = []string{"unrelated-receipt"} },
	} {
		changed := model.Clone(metadata)
		change(changed)
		if err := f.api.Do(f.ctx, f.tenant, func(tx *store.Tx) error { _, err := tx.CapacityAssessmentCreate(f.ctx, changed); return err }); err == nil {
			t.Fatal("unbound capacity authority or point payload accepted")
		}
	}
	if err := f.transport.Do(f.ctx, f.tenant, func(tx *store.Tx) error { _, err := tx.CapacityAssessmentCreate(f.ctx, metadata); return err }); err == nil {
		t.Fatal("transport manufactured API capacity assessment")
	}
	if err := f.admin.Do(f.ctx, f.tenant, func(tx *store.Tx) error {
		_, err := tx.Exec(f.ctx, "UPDATE capacity_assessments SET document='{}' WHERE tenant_id=$1 AND id=$2", f.tenant, model.String(record, "id"))
		return err
	}); err == nil {
		t.Fatal("owner rewrote immutable assessment")
	}
	if err := f.api.Do(f.ctx, "other-"+f.tenant, func(tx *store.Tx) error {
		_, err := tx.CapacityAssessmentGet(f.ctx, model.String(record, "id"))
		return err
	}); err == nil {
		t.Fatal("cross tenant assessment readable")
	}
	if err := f.api.Do(f.ctx, f.tenant, func(tx *store.Tx) error {
		_, _, err := tx.TelemetryRevocationAppend(f.ctx, model.String(conn, "revision_id"), "revoked after assessment")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.api.Do(f.ctx, f.tenant, func(tx *store.Tx) error { _, err := tx.CapacityAssessmentCreate(f.ctx, metadata); return err }); err == nil {
		t.Fatal("revoked source generated another assessment")
	}
	if err := f.api.Do(f.ctx, f.tenant, func(tx *store.Tx) error {
		_, err := tx.CapacityAssessmentGet(f.ctx, model.String(record, "id"))
		return err
	}); err != nil {
		t.Fatal("revocation destroyed immutable history")
	}
}
