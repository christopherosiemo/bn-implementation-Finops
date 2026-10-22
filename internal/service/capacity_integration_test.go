package service

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/auth"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/native"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/telemetry"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/workload"
)

func TestCapacityBrokerSelectsServerEvidenceAndPersistsOnlyBlockedMetadata(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("disposable PostgreSQL required")
	}
	ctx := context.Background()
	db, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Pool.Close()
	if err = db.Migrate(ctx, "../../migrations"); err != nil {
		t.Fatal(err)
	}
	tenant := "capacity-broker-" + model.ID()
	var profile model.Document
	var connection telemetry.Connection
	if err = db.Do(ctx, tenant, func(tx *store.Tx) error {
		if _, e := tx.Exec(ctx, "SET LOCAL ROLE finops_api"); e != nil {
			return e
		}
		if e := tx.Seed(ctx, true); e != nil {
			return e
		}
		p := workload.Profile{SchemaVersion: "1", Criticality: "NON_PRODUCTION", Statefulness: "UNKNOWN", Timezone: "UTC", MinReplicas: 1, MinZones: 1, Headroom: workload.Headroom{CPUFreePPM: 300000, MemoryFreePPM: 250000}, Saturation: workload.Saturation{CPUP99PPM: 850000, MemoryP99PPM: 900000}, RTOSeconds: 300, MaxSimultaneousChangePPM: 250000, VMCooldownSeconds: 86400}
		var e error
		profile, e = tx.WorkloadSafetyAppend(ctx, "workload-dev", 0, p)
		if e != nil {
			return e
		}
		r, e := tx.Get(ctx, "resources", "resource-dev-api")
		if e != nil {
			return e
		}
		connection = telemetry.Connection{SchemaVersion: "1", ID: "capacity-connection", Version: 1, Kind: "PROMETHEUS", ReadBindingID: "approved", Enabled: true, Binding: telemetry.Binding{TenantID: tenant, WorkloadID: "workload-dev", ResourceID: "resource-dev-api", Provider: model.String(r, "provider"), ProviderResourceID: model.String(r, "provider_resource_id"), AccountID: model.String(r, "account_id"), Region: model.String(r, "region")}, Definitions: []telemetry.Definition{{ID: "cpu", Version: "1", Metric: "cpu_utilization", Name: "cpu_utilization", Unit: "ratio", Type: "GAUGE", CadenceSeconds: 60, MaxGapSeconds: 120, Attributes: map[string]string{}, ResourceAttributes: map[string]string{}}}}
		_, e = tx.TelemetryConnectionAppend(ctx, connection.ID, 0, telemetry.Document(connection))
		return e
	}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	end := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	population := native.CapacityPopulation{SchemaVersion: "1", Binding: connection.Binding, ConnectionID: connection.ID, ConnectionVersion: 1, ConfigHash: telemetry.ConfigHash(connection), SafetyProfileID: model.String(profile, "id"), SafetyProfileVersion: 1, SafetyProfileHash: model.String(profile, "hash"), AsOf: now, Start: end.AddDate(0, 0, -14), End: end, HistoryDays: 14, Timezone: "UTC", Environment: "NON_PRODUCTION", Definitions: connection.Definitions, Segments: []telemetry.Segment{}, ReceiptIDs: []string{}, SourceRefs: []native.CapacityReceiptRef{}, ReasonCodes: []string{}, Evaluation: telemetry.Evaluation{SchemaVersion: "1", Status: "BLOCKED", ReasonCodes: []string{"TELEMETRY_HISTORY_INCOMPLETE"}, Metrics: []telemetry.MetricResult{}}}
	population.PopulationHash = native.CapacityPopulationHash(population)
	var calls atomic.Int32
	var corrupt atomic.Bool
	reader := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path != "/capacity-input" || r.Header.Get("Authorization") != "Bearer private-capacity" {
			t.Error("reader identity or route not selected by API")
			w.WriteHeader(401)
			return
		}
		var input native.CapacityInputRequest
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if decoder.Decode(&input) != nil || input.TenantID != tenant || input.ConfigHash != population.ConfigHash || input.SafetyProfileID != population.SafetyProfileID || input.SafetyProfileVersion != 1 {
			t.Error("API did not select immutable profile/source binding")
			w.WriteHeader(400)
			return
		}
		out := population
		if corrupt.Load() {
			out.Binding.AccountID = "000000000000"
			out.PopulationHash = native.CapacityPopulationHash(out)
		}
		_ = json.NewEncoder(w).Encode(out)
	}))
	defer reader.Close()
	t.Setenv("TELEMETRY_READER_TOKEN", "private-capacity")
	t.Setenv("TELEMETRY_READER_URL", reader.URL)
	api := &API{Store: db, Client: reader.Client(), Clock: func() time.Time { return now }}
	identity := auth.Identity{Tenant: tenant, Subject: "operator", Roles: map[string]bool{"PLATFORM_ADMIN": true}}
	invoke := func(body model.Document, version string, who auth.Identity) (model.Document, error) {
		r := httptest.NewRequest(http.MethodPost, "/v1/workloads/workload-dev/capacity-assessments", strings.NewReader("{}"))
		r.Header.Set("If-Match", version)
		var result model.Document
		e := db.Do(ctx, who.Tenant, func(tx *store.Tx) error {
			if _, e := tx.Exec(ctx, "SET LOCAL ROLE finops_api"); e != nil {
				return e
			}
			var e error
			var handled bool
			var status int
			result, status, handled, e = api.capacityMutate(ctx, tx, who, r, body, []string{"workloads", "workload-dev", "capacity-assessments"})
			if e == nil && (!handled || status != 201) {
				t.Fatal("capacity route not handled")
			}
			return e
		})
		return result, e
	}
	for _, body := range []model.Document{{"connection_id": connection.ID, "metrics": []any{}}, {"connection_id": connection.ID, "prices": []any{}}, {"connection_id": connection.ID, "history_days": 14}} {
		if _, e := invoke(body, `"1"`, identity); e == nil {
			t.Fatal("caller capacity evidence accepted")
		}
	}
	if _, e := invoke(model.Document{"connection_id": connection.ID}, `"0"`, identity); e == nil {
		t.Fatal("stale safety version accepted")
	}
	viewer := identity
	viewer.Roles = map[string]bool{"VIEWER": true}
	if _, e := invoke(model.Document{"connection_id": connection.ID}, `"1"`, viewer); e == nil {
		t.Fatal("viewer created assessment")
	}
	if calls.Load() != 0 {
		t.Fatal("unauthorized request reached private evidence selector")
	}
	corrupt.Store(true)
	if _, e := invoke(model.Document{"connection_id": connection.ID}, `"1"`, identity); e == nil {
		t.Fatal("cross-account private population accepted")
	}
	corrupt.Store(false)
	result, err := invoke(model.Document{"connection_id": connection.ID}, `"1"`, identity)
	if err != nil {
		t.Fatal(err)
	}
	if model.String(result, "status") != "BLOCKED" || model.Bool(result, "execution_authorized") || result["estimated_saving"] != nil || result["verified_saving"] != nil || model.String(result, "population_hash") != population.PopulationHash || model.String(result, "hardware_catalog_status") != "UNAVAILABLE" {
		t.Fatalf("catalogue absence became authority or zero cost: %+v", result)
	}
	if !strings.Contains(model.String(result, "reason_codes"), "BLOCKED_NATIVE_CAPACITY_CATALOG_REQUIRED") {
		raw, _ := json.Marshal(result["reason_codes"])
		if !strings.Contains(string(raw), "BLOCKED_NATIVE_CAPACITY_CATALOG_REQUIRED") {
			t.Fatal("missing catalogue not explained")
		}
	}
	if err = db.Do(ctx, tenant, func(tx *store.Tx) error {
		if _, e := tx.Exec(ctx, "SET LOCAL ROLE finops_api"); e != nil {
			return e
		}
		rows, e := tx.CapacityAssessmentPage(ctx, "workload-dev", "", 20)
		if e == nil && len(rows) != 1 {
			t.Fatal("failed attempts appended an assessment")
		}
		return e
	}); err != nil {
		t.Fatal(err)
	}
}
