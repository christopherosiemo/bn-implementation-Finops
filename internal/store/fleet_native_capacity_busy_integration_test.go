package store

import (
	"context"
	"errors"
	"testing"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
)

func TestFleetCapacitySourceSyncBusyRetainsTypedRefusal(t *testing.T) {
	f, pair := newFleetCapacityDBTest(t)
	request := fleetCapacityRequest(t, f, pair)
	id := model.String(request, "id")
	var snapshot model.Document
	f.must("finops_group_capacity", func(tx *Tx) error {
		var e error
		snapshot, e = tx.FleetCapacityBatchResolve(f.ctx, id)
		return e
	})

	// Hold the actual exclusive source.Pipeline.Sync guard on a separate
	// PostgreSQL session. Native/provider inputs remain explicit fixture doubles;
	// this test proves the real restricted-role lock and typed refusal boundary.
	conn, e := f.admin.Pool.Acquire(f.ctx)
	if e != nil {
		t.Fatal(e)
	}
	key := f.tenant + ":trusted-source:" + f.registration.SourceID
	if _, e = conn.Exec(f.ctx, `SELECT pg_advisory_lock(hashtextextended($1,0))`, key); e != nil {
		conn.Release()
		t.Fatal(e)
	}
	held := true
	defer func() {
		if held {
			_, _ = conn.Exec(context.Background(), `SELECT pg_advisory_unlock(hashtextextended($1,0))`, key)
		}
		conn.Release()
	}()
	for name, operation := range map[string]func(*Tx) error{
		"initial resolution": func(tx *Tx) error {
			_, e := tx.FleetCapacityBatchResolve(f.ctx, id)
			return e
		},
		"publication recheck": func(tx *Tx) error {
			_, _, e := tx.FleetCapacityBatchScopeAppend(f.ctx, id, fleetNativeHash(snapshot), fleetCapacityUnknownScope(request))
			return e
		},
	} {
		e := f.roles["finops_group_capacity"].Do(f.ctx, f.tenant, operation)
		if !errors.Is(e, ErrFleetFixtureBusy) {
			t.Fatalf("%s lost specific source busy error: %v", name, e)
		}
	}
	var count int
	if e = f.admin.Pool.QueryRow(f.ctx, `SELECT count(*) FROM public.fleet_native_capacity_scopes WHERE tenant_id=$1 AND request_id=$2`, f.tenant, id).Scan(&count); e != nil || count != 0 {
		t.Fatal("busy refusal published a scope", count, e)
	}
	var released bool
	if e = conn.QueryRow(f.ctx, `SELECT pg_advisory_unlock(hashtextextended($1,0))`, key).Scan(&released); e != nil || !released {
		t.Fatal("source guard was not released", e)
	}
	held = false
	f.must("finops_group_capacity", func(tx *Tx) error {
		_, replay, e := tx.FleetCapacityBatchScopeAppend(f.ctx, id, fleetNativeHash(snapshot), fleetCapacityUnknownScope(request))
		if e == nil && replay {
			return errors.New("busy attempt fabricated an earlier publication")
		}
		return e
	})

	// A genuine current-source failure must remain a refusal, rather than being
	// relabelled as the transient lock case.
	other := fleetCapacityRequest(t, f, pair)
	f.must("finops_api", func(tx *Tx) error {
		_, e := tx.Exec(f.ctx, `UPDATE public.source_registrations SET document=document||'{"enabled":false,"revoked":true}' WHERE tenant_id=$1 AND id=$2`, f.tenant, f.registration.SourceID)
		return e
	})
	e = f.roles["finops_group_capacity"].Do(f.ctx, f.tenant, func(tx *Tx) error {
		_, e := tx.FleetCapacityBatchResolve(f.ctx, model.String(other, "id"))
		return e
	})
	if e == nil || errors.Is(e, ErrFleetFixtureBusy) {
		t.Fatal("disabled source was accepted or misclassified as busy", e)
	}
}
