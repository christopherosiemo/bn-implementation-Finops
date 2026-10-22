package store

import (
	"context"
	"os"
	"testing"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/workload"
)

func TestWorkloadSafetyProfileImmutableAuthority(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("disposable PostgreSQL required")
	}
	ctx := context.Background()
	db, err := Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Pool.Close()
	if err = db.Migrate(ctx, "../../migrations"); err != nil {
		t.Fatal(err)
	}
	tenant := "safety-profile-" + model.ID()
	var profileID string
	p := workload.Profile{SchemaVersion: "1", Criticality: "NON_PRODUCTION", Statefulness: "STATELESS", Timezone: "Europe/London", MinReplicas: 6, MinZones: 3, Headroom: workload.Headroom{CPUFreePPM: 300000, MemoryFreePPM: 250000, ReserveAboveForecastPPM: 300000}, Saturation: workload.Saturation{CPUP99PPM: 850000, MemoryP99PPM: 900000}, RTOSeconds: 900, MaxSimultaneousChangePPM: 100000, VMCooldownSeconds: 604800}
	if err = db.Do(ctx, tenant, func(tx *Tx) error {
		if _, e := tx.Exec(ctx, "SET LOCAL ROLE finops_api"); e != nil {
			return e
		}
		if e := tx.Seed(ctx, true); e != nil {
			return e
		}
		d, e := tx.WorkloadSafetyAppend(ctx, "workload-dev", 0, p)
		if e != nil {
			return e
		}
		profileID = model.String(d, "id")
		if model.String(d, "hash") == "" || model.String(d, "writer_role") != "finops_api" || model.Number(d, "version") != 1 {
			t.Fatal("missing server authority")
		}
		if _, e = tx.WorkloadSafetyAppend(ctx, "workload-dev", 0, p); e != ErrConflict {
			t.Fatal("stale profile accepted")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{"finops_worker", "finops_ingester", "finops_telemetry_reader", "finops_telemetry_ingress"} {
		err = db.Do(ctx, tenant, func(tx *Tx) error {
			if _, e := tx.Exec(ctx, "SET LOCAL ROLE "+role); e != nil {
				return e
			}
			_, e := tx.Exec(ctx, "INSERT INTO workload_safety_profiles(tenant_id,id,workload_id,version,content_hash,document) SELECT tenant_id,$2,workload_id,version+1,content_hash,document FROM workload_safety_profiles WHERE tenant_id=$1 AND id=$3", tenant, model.ID(), profileID)
			return e
		})
		if err == nil {
			t.Fatalf("%s manufactured policy", role)
		}
	}
	err = db.Do(ctx, tenant, func(tx *Tx) error {
		if _, e := tx.Exec(ctx, "SET LOCAL ROLE finops_api"); e != nil {
			return e
		}
		_, e := tx.Exec(ctx, "UPDATE workload_safety_profiles SET document='{}' WHERE tenant_id=$1 AND id=$2", tenant, profileID)
		return e
	})
	if err == nil {
		t.Fatal("profile was mutable")
	}
	if err = db.Do(ctx, "other-"+tenant, func(tx *Tx) error {
		if _, e := tx.Exec(ctx, "SET LOCAL ROLE finops_api"); e != nil {
			return e
		}
		var count int
		if e := tx.QueryRow(ctx, "SELECT count(*) FROM workload_safety_profiles WHERE id=$1", profileID).Scan(&count); e != nil {
			return e
		}
		if count != 0 {
			t.Fatal("cross tenant profile visible")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
