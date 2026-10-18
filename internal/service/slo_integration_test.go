package service

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/slo"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
)

func sloTestObjective() model.Document {
	// Keep declared service hours inside the fixture's07:00–20:00 availability
	// and away from physical current time. No observation or clock is forged.
	hour := 10
	now := time.Now().UTC()
	if now.Hour() >= 9 && now.Hour() <= 11 {
		hour = 15
	}
	return model.Document{"schema_version": "1", "evaluation_minutes": 2, "limits": model.Document{"max_error_rate_ppm": 1000, "min_availability_ppm": 999000, "max_p95_latency_ms": 105, "max_p99_latency_ms": 200, "min_latency_samples": 1}, "availability": model.Document{"mode": "WINDOWS", "timezone": "UTC", "windows": []model.Document{{"days": []int{0, 1, 2, 3, 4, 5, 6}, "start_time": fmt.Sprintf("%02d:00", hour), "end_time": fmt.Sprintf("%02d:01", hour)}}}, "regression": model.Document{"enabled": false, "max_percent": 15}}
}

func seedSLOAuthority(t *testing.T, ctx context.Context, api *API, db *store.Store, tenant string) (model.Document, slo.Source) {
	t.Helper()
	local := *api
	local.Config.Issuer = "https://machine.example.test"
	obj, err := dependencyRequest(t, ctx, &local, db, tenant, "workloads/workload-dev/slo-objectives", 0, sloTestObjective(), false)
	if err != nil {
		t.Fatal(err)
	}
	src, err := dependencyRequest(t, ctx, &local, db, tenant, "slo-sources", 0, model.Document{"objective_id": obj["id"], "resource_id": "resource-dev-api", "subject": "independent-sli-gateway"}, false)
	if err != nil {
		t.Fatal(err)
	}
	var source slo.Source
	b, _ := json.Marshal(src)
	if err = json.Unmarshal(b, &source); err != nil {
		t.Fatal(err)
	}
	refreshSLOTestReceipts(t, ctx, tenant, source, false)
	return obj, source
}

func refreshSLOTestReceipts(t *testing.T, ctx context.Context, tenant string, source slo.Source, bad bool) {
	t.Helper()
	db := trustedRoleStore(t, os.Getenv("TEST_DATABASE_URL"), "finops_activity")
	// Collection at the minute boundary is real transport lag. Keep these short
	// integration checks away from the rollover; runtime still fails closed there.
	if remaining := time.Minute - time.Duration(time.Now().Second())*time.Second; remaining < 5*time.Second {
		time.Sleep(remaining + 100*time.Millisecond)
	}
	end := time.Now().UTC().Truncate(time.Minute)
	for n := 0; n < 2; n++ {
		right := end.Add(time.Duration(n-1) * time.Minute)
		requests, errorsCount := int64(0), int64(0)
		upper := int64(110)
		if bad && n == 1 {
			requests, errorsCount = 100, 10
		}
		in := slo.Interval{SchemaVersion: "1", SourceID: source.ID, ObjectiveID: source.ObjectiveID, WorkloadID: source.WorkloadID, ResourceID: source.ResourceID, Sequence: right.Unix() / 60, IntervalStart: right.Add(-time.Minute), IntervalEnd: right, RequestCount: requests, ErrorCount: errorsCount, AvailabilityGoodSeconds: 60, AvailabilityTotalSeconds: 60, Latency: slo.Histogram{Unit: "milliseconds", SampleCount: requests, Buckets: []slo.Bucket{{UpperBoundMS: &upper, Count: requests}, {UpperBoundMS: nil, Count: 0}}}}
		raw, _ := json.Marshal(in)
		err := db.Do(ctx, tenant, func(tx *store.Tx) error {
			_, _, e := tx.SLOAppend(ctx, store.SLOSubmission{Interval: in, RawBody: raw, Issuer: source.Issuer, Subject: source.Subject, IdempotencyKey: fmt.Sprintf("sli-%d", in.Sequence)})
			return e
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestSLOAPIRequiresExplicitObjectiveAndIndependentEvidence(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("disposable PostgreSQL required")
	}
	ctx := context.Background()
	admin, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Pool.Close()
	if err = admin.Migrate(ctx, "../../migrations"); err != nil {
		t.Fatal(err)
	}
	db := trustedRoleStore(t, dsn, "finops_api")
	tenant := "slo-api-" + model.ID()
	api := API{Store: db, Config: Config{Fixture: true}}
	if err = db.Do(ctx, tenant, func(tx *store.Tx) error { return tx.Seed(ctx, true) }); err != nil {
		t.Fatal(err)
	}
	omitted := sloTestObjective()
	delete(omitted["limits"].(model.Document), "max_error_rate_ppm")
	if _, err = dependencyRequest(t, ctx, &api, db, tenant, "workloads/workload-dev/slo-objectives", 0, omitted, false); err == nil {
		t.Fatal("omitted hard limit became an implicit zero")
	}
	if _, err = dependencyRequest(t, ctx, &api, db, tenant, "workloads/workload-dev/slo-objectives", 0, sloTestObjective(), true); err == nil {
		t.Fatal("viewer authorized an SLO objective")
	}
	obj, _ := seedSLOAuthority(t, ctx, &api, db, tenant)
	if err = db.Do(ctx, tenant, func(tx *store.Tx) error {
		res, e := tx.Get(ctx, "resources", "resource-dev-api")
		if e != nil {
			return e
		}
		state, e := currentSLO(ctx, tx, res, nil, true, time.Time{}, time.Time{})
		if e == nil && len(sloReasons(state)) > 0 {
			t.Fatalf("explicit independently observed closed zero demand rejected:%v", state)
		}
		return e
	}); err != nil {
		t.Fatal(err)
	}
	if _, err = dependencyRequest(t, ctx, &api, db, tenant, "workloads/workload-dev/slo-objectives", 0, sloTestObjective(), false); err == nil {
		t.Fatal("stale objective revision accepted")
	}
	if err = db.Do(ctx, tenant+"-other", func(tx *store.Tx) error {
		_, e := tx.SLOObjectiveGet(ctx, model.String(obj, "id"))
		if e == nil {
			t.Fatal("cross tenant SLO objective exposed")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
