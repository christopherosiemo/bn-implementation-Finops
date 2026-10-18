package service

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/telemetry"
)

func TestNativeEvaluationCannotRelabelConcurrentSourceRevision(t *testing.T) {
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
	tenant := "native-api-race-" + model.ID()
	if err = db.Do(ctx, tenant, func(tx *store.Tx) error { return tx.Seed(ctx, true) }); err != nil {
		t.Fatal(err)
	}
	c := telemetry.Connection{SchemaVersion: "1", ID: model.ID(), Version: 1, Kind: "OTLP", Issuer: "https://machine.invalid", Subject: "collector", Enabled: true,
		Binding:     telemetry.Binding{TenantID: tenant, ResourceID: "resource-dev-api", WorkloadID: "workload-dev", Provider: "AWS", ProviderResourceID: "i-0123456789abcdef0", AccountID: "111122223333", Region: "eu-west-1"},
		Definitions: []telemetry.Definition{{ID: "cpu", Version: "1", Metric: "cpu", Name: "cpu", Unit: "vCPU", Type: "GAUGE", CadenceSeconds: 60, MaxGapSeconds: 120}}}
	if err = db.Do(ctx, tenant, func(tx *store.Tx) error {
		_, err := tx.TelemetryConnectionAppend(ctx, c.ID, 0, telemetry.Document(c))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	var phase atomic.Int32
	reader := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if phase.Load() == 0 {
			JSON(w, 200, model.Document{"connection_id": c.ID, "config_hash": telemetry.ConfigHash(c), "receipt_ids": []string{}, "evaluation": model.Document{"schema_version": "1", "status": "BLOCKED"}})
			return
		}
		// The reader sees a newer revision than the API's initial optimistic read.
		c.Version = 2
		c.Definitions[0].Version = "2"
		if err := db.Do(ctx, tenant, func(tx *store.Tx) error {
			_, err := tx.TelemetryConnectionAppend(ctx, c.ID, 1, telemetry.Document(c))
			return err
		}); err != nil {
			t.Error(err)
			w.WriteHeader(500)
			return
		}
		JSON(w, 200, model.Document{"connection_id": c.ID, "config_hash": telemetry.ConfigHash(c), "receipt_ids": []string{}, "evaluation": model.Document{"status": "BLOCKED"}})
	}))
	defer reader.Close()
	t.Setenv("TELEMETRY_READER_TOKEN", "private-test-reader-token")
	t.Setenv("TELEMETRY_READER_URL", reader.URL)
	a := &API{Store: db, Client: reader.Client(), Config: Config{Fixture: true}}
	_, err = dependencyRequest(t, ctx, a, db, tenant, "telemetry-connections/"+c.ID+"/evaluate", 1, model.Document{"mode": "history"}, false)
	var missing *Problem
	if !errors.As(err, &missing) || missing.Status != 422 || missing.Code != "TELEMETRY_EVIDENCE_MISSING" {
		t.Fatalf("unpersisted evidence should be explicitly unavailable: %v", err)
	}
	phase.Store(1)
	_, err = dependencyRequest(t, ctx, a, db, tenant, "telemetry-connections/"+c.ID+"/evaluate", 1, model.Document{"mode": "history"}, false)
	var p *Problem
	if !errors.As(err, &p) || p.Status != 409 || p.Code != "TELEMETRY_CONFIG_CHANGED" {
		t.Fatalf("concurrent result relabelled instead of rejected: %v", err)
	}
	if err = db.Do(ctx, tenant, func(tx *store.Tx) error {
		rows, err := tx.TelemetryEvaluations(ctx, c.ID)
		if err == nil && len(rows) != 0 {
			t.Error("conflicting result persisted")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}
