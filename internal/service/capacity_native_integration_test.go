package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/auth"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/native"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/provider"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/source"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/telemetry"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/workload"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type nativeHardwareFixtureReader struct {
	raw []byte
	now time.Time
}

func (f nativeHardwareFixtureReader) HardwareInventory(_ context.Context, region, account, instance string, candidates []string) (provider.HardwareEvidence, error) {
	return provider.ParseHardwareEvidence(f.raw, account, region, instance, candidates, f.now)
}

func nativeHardwareDB(t *testing.T) (*store.Store, func(string) *store.Store) {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("disposable PostgreSQL required")
	}
	ctx := context.Background()
	db, e := store.Open(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(db.Pool.Close)
	dir := t.TempDir()
	files, e := os.ReadDir("../../migrations")
	if e != nil {
		t.Fatal(e)
	}
	for _, f := range files {
		if !strings.HasSuffix(f.Name(), ".sql") || f.Name()[:3] > "017" {
			continue
		}
		raw, e := os.ReadFile(filepath.Join("../../migrations", f.Name()))
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join(dir, f.Name()), raw, 0600); e != nil {
			t.Fatal(e)
		}
	}
	if e = db.Migrate(ctx, dir); e != nil {
		t.Fatal(e)
	}
	return db, func(role string) *store.Store {
		c, e := pgxpool.ParseConfig(dsn)
		if e != nil {
			t.Fatal(e)
		}
		c.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
			_, e := conn.Exec(ctx, "SET ROLE "+pgx.Identifier{role}.Sanitize())
			return e
		}
		p, e := pgxpool.NewWithConfig(ctx, c)
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(p.Close)
		return &store.Store{Pool: p}
	}
}

// This acceptance uses native object/checkpoint publication and the private
// selector under their real PostgreSQL roles, then the actual Python worker.
// In-memory versioned objects and acknowledged analytics are dependency fixtures;
// no public point, capacity, candidate or price arrays enter the broker.
func TestNativeHardwareCapacityBrokerRealWorkerAndPostgresBoundaries(t *testing.T) {
	workerURL := os.Getenv("ECONOMICS_TEST_URL")
	if workerURL == "" {
		t.Skip("real Python capacity worker required")
	}
	ctx := context.Background()
	admin, role := nativeHardwareDB(t)
	apiStore := role("finops_api")
	ingester := role("finops_ingester")
	reader := role("finops_telemetry_reader")
	tenant := "hardware-model-" + model.ID()
	now := time.Now().UTC()
	end := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	start := end.AddDate(0, 0, -14)
	c := telemetry.Connection{SchemaVersion: "1", ID: "capacity-native", Version: 1, Kind: "PROMETHEUS", ReadBindingID: "approved", Enabled: true, Binding: telemetry.Binding{TenantID: tenant, ResourceID: "resource-dev-api", WorkloadID: "workload-dev", Provider: "AWS", ProviderResourceID: "i-0123456789abcdef0", AccountID: "111122223333", Region: "eu-west-1"}}
	metrics := []string{"cpu_utilization", "memory_utilization", "cpu_capacity", "memory_capacity", "network_in", "network_out", "disk_read_operations", "disk_write_operations", "disk_read_bytes", "disk_write_bytes", "request_count"}
	for _, metric := range metrics {
		kind, unit := "SUM", "bytes"
		if strings.HasSuffix(metric, "operations") || metric == "request_count" {
			unit = "count"
		}
		if metric == "cpu_utilization" || metric == "memory_utilization" {
			kind, unit = "GAUGE", "ratio"
		}
		if metric == "cpu_capacity" {
			kind, unit = "GAUGE", "vCPU"
		}
		if metric == "memory_capacity" {
			kind, unit = "GAUGE", "bytes"
		}
		d := telemetry.Definition{ID: metric, Version: "1", Metric: metric, Name: metric, Type: kind, Unit: unit, Monotonic: kind == "SUM", CadenceSeconds: 300, MaxGapSeconds: 600, Attributes: map[string]string{}, ResourceAttributes: map[string]string{}}
		if kind == "SUM" {
			d.EpochMetric = "process_start_time_seconds"
		}
		c.Definitions = append(c.Definitions, d)
	}
	profile := workload.Profile{SchemaVersion: "1", Criticality: "NON_PRODUCTION", Statefulness: "UNKNOWN", Timezone: "UTC", MinReplicas: 1, MinZones: 1, Headroom: workload.Headroom{CPUFreePPM: 300000, MemoryFreePPM: 250000, ReserveAboveForecastPPM: 300000}, Saturation: workload.Saturation{CPUP99PPM: 850000, MemoryP99PPM: 900000}, RTOSeconds: 300, MaxSimultaneousChangePPM: 250000, VMCooldownSeconds: 86400}
	var profileDoc model.Document
	if e := apiStore.Do(ctx, tenant, func(tx *store.Tx) error {
		if e := tx.Seed(ctx, true); e != nil {
			return e
		}
		r, e := tx.Get(ctx, "resources", c.Binding.ResourceID)
		if e != nil {
			return e
		}
		r["instance_type"] = "m6i.xlarge"
		if _, e = tx.Update(ctx, "resources", c.Binding.ResourceID, model.Number(r, "version"), r); e != nil {
			return e
		}
		if _, e = tx.SourceCreate(ctx, source.FixtureRegistration(tenant, "hardware-source")); e != nil {
			return e
		}
		if _, e = tx.TelemetryConnectionAppend(ctx, c.ID, 0, telemetry.Document(c)); e != nil {
			return e
		}
		profileDoc, e = tx.WorkloadSafetyAppend(ctx, c.Binding.WorkloadID, 0, profile)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	profile.ID = model.String(profileDoc, "id")
	profile.Version = model.Number(profileDoc, "version")
	profile.WorkloadID = c.Binding.WorkloadID
	objects := map[string][]byte{}
	pipeline := &native.Pipeline{Store: reader, Archive: func(_ context.Context, tenant, lane, id string, raw []byte) (model.Document, error) {
		hash := telemetry.BytesHash(raw)
		key := "tenant/" + tenant + "/native/" + lane + "/" + id
		objects[key+"/"+hash] = append([]byte{}, raw...)
		return model.Document{"bucket": "native-fixture", "key": key, "version_id": hash, "body_sha256": hash}, nil
	}, ReadObject: func(_ context.Context, _ string, ref model.Document) ([]byte, error) {
		raw := objects[model.String(ref, "key")+"/"+model.String(ref, "version_id")]
		if telemetry.BytesHash(raw) != model.String(ref, "body_sha256") {
			return nil, errors.New("pinned object changed")
		}
		return raw, nil
	}, WriteFacts: func(_ context.Context, _ string, id string, b telemetry.Batch) (model.Document, error) {
		return model.Document{"database": "finops", "table": "native_telemetry", "write_id": id, "canonical_hash": telemetry.CanonicalHash(b), "sample_count": len(b.Samples)}, nil
	}}
	batch := telemetry.Batch{SchemaVersion: "1", ConnectionID: c.ID, ConfigHash: telemetry.ConfigHash(c), Binding: c.Binding, SourceKind: c.Kind, CollectedAt: now, Start: start.Add(-5 * time.Minute), End: end, Samples: []telemetry.Sample{}, Rejections: []telemetry.Rejection{}, Warnings: []string{}}
	// A source fixture with actual five-minute observations and cumulative
	// counter epochs. Samples are archived before PostgreSQL publishes a receipt.
	for _, d := range c.Definitions {
		for at, i := batch.Start, 0; !at.After(end); at, i = at.Add(5*time.Minute), i+1 {
			value := "0.2"
			switch d.Metric {
			case "cpu_capacity":
				value = "2"
			case "memory_capacity":
				value = "17179869184"
			default:
				if d.Type == "SUM" {
					value = strconv.Itoa(i * 3000)
				}
			}
			sample := telemetry.Sample{DefinitionID: d.ID, StreamID: d.ID, Metric: d.Metric, Type: d.Type, Unit: d.Unit, Statistic: "SAMPLED_VALUE", Time: at, StartTime: batch.Start, Value: value, Attributes: map[string]string{}, ResourceAttributes: map[string]string{}, ScopeAttributes: map[string]string{}, ReasonCodes: []string{}}
			if d.Type == "SUM" {
				sample.Temporality = "CUMULATIVE"
				sample.Epoch = "stable-native-process-epoch"
				sample.Statistic = "MONOTONIC_COUNTER"
			}
			sample.ID = telemetry.Hash(sample)
			batch.Samples = append(batch.Samples, sample)
		}
	}
	batch.Raw, _ = json.Marshal(model.Document{"provider_shaped_fixture": "prometheus cumulative and gauge populations", "samples": batch.Samples})
	batch.RawSHA256 = telemetry.BytesHash(batch.Raw)
	for i := range batch.Samples {
		batch.Samples[i].RawSHA256 = batch.RawSHA256
	}
	if _, _, e := pipeline.Publish(ctx, c, batch, "capacity-full-history", batch.Start, end); e != nil {
		t.Fatal("native publication", e)
	}
	selector := &native.Server{Store: reader, Pipeline: pipeline, ReaderToken: "private-selector", Fixture: true, Now: func() time.Time { return now }, Bindings: map[string]native.ReadBinding{"approved": {Binding: c.Binding, Endpoint: "http://127.0.0.1:1", AllowedCIDRs: []string{"127.0.0.1/32"}, RequiredLabels: map[string]string{}}}}
	input := native.CapacityInputRequest{TenantID: tenant, ConnectionID: c.ID, ConfigHash: telemetry.ConfigHash(c), SafetyProfileID: profile.ID, SafetyProfileVersion: profile.Version}
	raw, _ := json.Marshal(input)
	request := httptest.NewRequest(http.MethodPost, "/capacity-input", bytes.NewReader(raw))
	request.Header.Set("Authorization", "Bearer private-selector")
	response := httptest.NewRecorder()
	selector.Handler().ServeHTTP(response, request)
	if response.Code != 200 {
		t.Fatalf("private native selection: %d %s", response.Code, response.Body.String())
	}
	var population native.CapacityPopulation
	if e := json.Unmarshal(response.Body.Bytes(), &population); e != nil {
		t.Fatal(e)
	}
	fixtureRaw, e := os.ReadFile("../provider/testdata/hardware_capture.bin")
	if e != nil {
		t.Fatal(e)
	}
	target := source.HardwareTarget{Binding: c.Binding, SourceID: "hardware-source", CandidateTypes: []string{"m6i.large"}}
	hp := source.HardwarePipeline{Store: ingester, Targets: map[string]source.HardwareTarget{tenant + ":" + c.Binding.ResourceID: target}, Now: func() time.Time { return now }, ReaderFactory: func(context.Context, source.Registration, string) (source.HardwareReader, error) {
		return nativeHardwareFixtureReader{fixtureRaw, now}, nil
	}, Archive: func(_ context.Context, tenant, resource string, raw []byte) (model.Document, error) {
		hash := telemetry.BytesHash(raw)
		return model.Document{"bucket": "native-fixture", "key": "tenant/" + tenant + "/hardware/" + resource + "/" + hash, "version_id": hash, "body_sha256": hash}, nil
	}}
	hardware, e := hp.Capture(ctx, tenant, c.Binding.ResourceID)
	if e != nil {
		t.Fatal("native hardware publication", e)
	}
	a := &API{Config: Config{EconomicsURL: workerURL, EconomicsToken: os.Getenv("ECONOMICS_TEST_TOKEN")}, Clock: func() time.Time { return now }}
	var saved model.Document
	if e = apiStore.Do(ctx, tenant, func(tx *store.Tx) error {
		var e error
		saved, e = a.capacityWithNativeHardware(ctx, tx, population, profile)
		return e
	}); e != nil {
		t.Fatal("capacity broker", e)
	}
	if !model.Bool(saved, "model_evaluated") {
		t.Fatalf("actual Python model was not accepted: %v", saved["reason_codes"])
	}
	evaluation := telemetry.Document(saved["model_evaluation"])
	if model.String(evaluation, "schema_version") != "4" || model.String(saved, "status") != "BLOCKED" || model.Bool(saved, "execution_authorized") || saved["estimated_saving"] != nil || saved["verified_saving"] != nil || saved["change_plan_id"] != nil || model.String(saved, "hardware_receipt_id") != model.String(hardware, "id") {
		t.Fatal("native model gained price or execution authority", saved)
	}
	fleetAvoidabilityUnproven := false
	for _, reason := range model.Strings(saved, "reason_codes") {
		if reason == capacityFleetAvoidabilityUnproven {
			fleetAvoidabilityUnproven = true
		}
	}
	if !fleetAvoidabilityUnproven {
		t.Fatal("single-resource physical fit was presented without the unresolved fleet-cost gate", saved["reason_codes"])
	}
	mapping, e := native.BuildCapacityModelInput(population, profile, hardware)
	if e != nil || mapping.Request == nil {
		t.Fatal("trusted input was not reproducible", e)
	}
	for _, claim := range []string{"invented price", "invented calibrated probability", "wrong assessment hash"} {
		t.Run("worker response "+claim, func(t *testing.T) {
			forged := model.Clone(evaluation)
			candidates := forged["candidates"].([]any)
			candidate := telemetry.Document(candidates[0])
			if claim == "invented price" {
				economics := telemetry.Document(candidate["economics"])
				economics["estimated_saving"] = "1.00"
				candidate["economics"] = economics
			}
			if claim == "invented calibrated probability" {
				risk := telemetry.Document(candidate["future_risk"])
				risk["future_breach_probability_upper_ppm"] = 1
				candidate["future_risk"] = risk
			}
			candidates[0] = candidate
			forged["candidates"] = candidates
			raw, _ := json.Marshal(forged)
			hash, e := native.CapacityModelBodyHash(raw)
			if e != nil {
				t.Fatal(e)
			}
			forged["assessment_hash"] = hash
			if claim == "wrong assessment hash" {
				forged["assessment_hash"] = strings.Repeat("f", 64)
			}
			raw, _ = json.Marshal(forged)
			if _, e = native.DecodeCapacityModelResult(raw, *mapping.Request); e == nil {
				t.Fatal("private worker claim without native evidence accepted")
			}
		})
	}
	serialized, _ := json.Marshal(saved)
	if bytes.Contains(serialized, []byte(`"points"`)) || bytes.Contains(serialized, []byte(`"segments"`)) || bytes.Contains(serialized, []byte(`"samples"`)) {
		t.Fatal("raw native population persisted in transactional summary")
	}
	t.Logf("real Python result persisted: %s, native receipts=%d, observed segments=%d", model.String(saved, "id"), len(population.ReceiptIDs), len(population.Segments))
	selectorHTTP := httptest.NewServer(selector.Handler())
	defer selectorHTTP.Close()
	t.Setenv("TELEMETRY_READER_TOKEN", "private-selector")
	t.Setenv("TELEMETRY_READER_URL", selectorHTTP.URL)
	identity := auth.Identity{Tenant: tenant, Subject: "capacity-operator", Roles: map[string]bool{"FINOPS_ADMIN": true}}
	if e := apiStore.Do(ctx, tenant, func(tx *store.Tx) error {
		r := httptest.NewRequest(http.MethodPost, "/v1/workloads/workload-dev/capacity-assessments", nil)
		r.Header.Set("If-Match", fmt.Sprintf("\"%d\"", profile.Version))
		out, status, handled, e := a.capacityMutate(ctx, tx, identity, r, model.Document{"connection_id": c.ID}, []string{"workloads", c.Binding.WorkloadID, "capacity-assessments"})
		if e == nil && (!handled || status != 201 || !model.Bool(out, "model_evaluated")) {
			return errors.New("public selector did not call real native model")
		}
		return e
	}); e != nil {
		t.Fatal("public connection-only broker", e)
	}
	if e := apiStore.Do(ctx, tenant, func(tx *store.Tx) error { _, e := tx.CapacityAssessmentGet(ctx, model.String(saved, "id")); return e }); e == nil {
		t.Fatal("native model result became legacy configuration proposal authority")
	}
	if e := apiStore.Do(ctx, tenant, func(tx *store.Tx) error {
		r := httptest.NewRequest(http.MethodGet, "/v1/workloads/workload-dev/native-capacity-results?limit=1", nil)
		out, handled, e := a.capacityGet(ctx, tx, identity, r)
		if e != nil {
			return e
		}
		raw, _ := json.Marshal(out)
		var page struct {
			Items []model.Document `json:"items"`
			Next  *string          `json:"next_cursor"`
		}
		if json.Unmarshal(raw, &page) != nil || !handled || len(page.Items) != 1 || page.Next == nil {
			return errors.New("scoped native result cursor page missing")
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	if e := apiStore.Do(ctx, tenant, func(tx *store.Tx) error {
		r := httptest.NewRequest(http.MethodGet, "/v1/workloads/workload-dev/native-capacity-results", nil)
		_, _, e := a.capacityGet(ctx, tx, auth.Identity{Tenant: tenant, Subject: "unassigned-owner", Roles: map[string]bool{"APPLICATION_OWNER": true}}, r)
		return e
	}); e == nil {
		t.Fatal("unassigned application owner read native model history")
	}
	if e := apiStore.Do(ctx, tenant, func(tx *store.Tx) error {
		r := httptest.NewRequest(http.MethodPost, "/v1/workloads/workload-dev/capacity-assessments", nil)
		r.Header.Set("If-Match", fmt.Sprintf("\"%d\"", profile.Version))
		_, _, _, e := a.capacityMutate(ctx, tx, identity, r, model.Document{"connection_id": c.ID, "prices": []any{}}, []string{"workloads", c.Binding.WorkloadID, "capacity-assessments"})
		return e
	}); e == nil {
		t.Fatal("public candidate price array accepted")
	}
	for name, mutate := range map[string]func(model.Document){
		"execution grant":           func(d model.Document) { d["execution_authorized"] = true },
		"invented savings":          func(d model.Document) { d["estimated_saving"] = "1.00" },
		"raw samples":               func(d model.Document) { d["samples"] = []any{} },
		"foreign telemetry receipt": func(d model.Document) { d["receipt_ids"] = []string{"foreign-receipt"} },
		"changed profile":           func(d model.Document) { d["safety_profile_version"] = profile.Version + 1 },
		"invented future probability": func(d model.Document) {
			m := telemetry.Document(d["model_evaluation"])
			rows := m["candidates"].([]any)
			candidate := telemetry.Document(rows[0])
			risk := telemetry.Document(candidate["future_risk"])
			risk["future_breach_probability_upper_ppm"] = 1
			candidate["future_risk"] = risk
			rows[0] = candidate
			m["candidates"] = rows
			d["model_evaluation"] = m
		},
	} {
		t.Run(name, func(t *testing.T) {
			d := model.Clone(saved)
			for _, key := range []string{"id", "tenant_id", "hash", "created_at", "writer_role"} {
				delete(d, key)
			}
			mutate(d)
			encoded, _ := json.Marshal(d)
			e := apiStore.Do(ctx, tenant, func(tx *store.Tx) error {
				_, e := tx.Exec(ctx, "INSERT INTO native_capacity_results(tenant_id,id,workload_id,resource_id,connection_id,revision_id,safety_profile_id,hardware_receipt_id,input_hash,content_hash,document) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)", tenant, model.ID(), d["workload_id"], d["resource_id"], d["connection_id"], d["revision_id"], d["safety_profile_id"], d["hardware_receipt_id"], d["input_hash"], telemetry.Hash(d), encoded)
				return e
			})
			if e == nil {
				t.Fatal("SQL accepted forged native capacity result")
			}
		})
	}
	for _, table := range []string{"native_capacity_results", "source_receipts"} {
		if e = admin.Do(ctx, tenant, func(tx *store.Tx) error {
			_, e := tx.Exec(ctx, fmt.Sprintf("UPDATE %s SET document=document||'{\"tampered\":true}'::jsonb WHERE tenant_id=$1", table), tenant)
			return e
		}); e == nil {
			t.Fatal("immutable evidence update accepted", table)
		}
	}
	var foreignCount int
	if e = apiStore.Do(ctx, "unrelated-tenant", func(tx *store.Tx) error {
		return tx.QueryRow(ctx, "SELECT count(*) FROM native_capacity_results WHERE id=$1", saved["id"]).Scan(&foreignCount)
	}); e != nil || foreignCount != 0 {
		t.Fatal(e)
	}
	for _, mutate := range []string{"foreign receipt", "hash tamper", "source revoked"} {
		t.Run(mutate, func(t *testing.T) {
			changed := population
			changed.SourceRefs = append([]native.CapacityReceiptRef{}, population.SourceRefs...)
			if mutate == "foreign receipt" {
				changed.ReceiptIDs = []string{"other-tenant-receipt"}
			}
			if mutate == "hash tamper" {
				changed.SourceRefs[0].RawSHA256 = strings.Repeat("f", 64)
			}
			changed.PopulationHash = native.CapacityPopulationHash(changed)
			if mutate == "source revoked" {
				if e := apiStore.Do(ctx, tenant, func(tx *store.Tx) error {
					d, e := tx.SourceGet(ctx, "hardware-source")
					if e != nil {
						return e
					}
					d["enabled"] = false
					d["revoked"] = true
					_, e = tx.SourceUpdate(ctx, "hardware-source", model.Number(d, "version"), d)
					return e
				}); e != nil {
					t.Fatal(e)
				}
			}
			if e := apiStore.Do(ctx, tenant, func(tx *store.Tx) error { _, e := a.capacityWithNativeHardware(ctx, tx, changed, profile); return e }); e == nil {
				t.Fatal("changed or revoked evidence accepted")
			}
		})
	}
}
