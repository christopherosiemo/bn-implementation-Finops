package service

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/fleet"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestFleetForwardObservationRejectsLatePositiveAuthorityAndRetainsOwnership(t *testing.T) {
	f := newFleetCohortProtocolFixture(t)
	discovery := f.membership(nil, f.blue, []string{})
	var baseline model.Document
	f.must("finops_api", func(tx *store.Tx) error {
		var e error
		baseline, e = f.api.freezeFleetCohortBaseline(f.ctx, tx, f.binding, model.String(discovery, "id"))
		return e
	})
	pausedParent := f.parent(baseline)
	pausedExecution := f.execution(pausedParent)
	prepared := f.child(pausedParent, 0, 1, fleet.Transition{OldBefore: 20, OldAfter: 20})
	f.apply(pausedParent, prepared, pausedExecution, "NO_OP")
	canary := f.child(pausedParent, 1, 2, fleet.Transition{OldBefore: 20, OldAfter: 20, CandidateAfter: 2, InFlight: 2})
	paused := f.apply(pausedParent, canary, pausedExecution, "APPLIED")
	revokedParent := f.parent(baseline)
	revokedChild := f.child(revokedParent, 0, 1, fleet.Transition{OldBefore: 20, OldAfter: 20})
	revoked := f.apply(revokedParent, revokedChild, f.execution(revokedParent), "APPLIED")
	// This labelled synthetic legacy parent tests real expiry only. Its original
	// callback and every SLI/native receipt use the actual server/collector clock;
	// it is not a genuine historical pre-plan baseline or live-factory claim.
	expiredParent := f.parent(nil, true)
	expiredChild := f.child(expiredParent, 0, 1, fleet.Transition{OldBefore: 20, OldAfter: 20})
	expired := f.apply(expiredParent, expiredChild, f.execution(expiredParent), "APPLIED")
	end := time.Time{}
	for _, command := range []model.Document{paused, revoked, expired} {
		f.must("finops_api", func(tx *store.Tx) error {
			d, e := fleetHealthOne(f.ctx, tx, "SELECT document FROM fleet_callbacks WHERE tenant_id=$1 AND id=$2", f.tenant, command["owned_receipt_id"])
			var at time.Time
			if e == nil {
				e = fleetHealthDecode(d["received_at"], &at)
			}
			if candidate := fleetCeilMinute(at).Add(2 * time.Minute); candidate.After(end) {
				end = candidate
			}
			return e
		})
	}
	last := time.Time{}
	for {
		now := time.Now().UTC()
		minute := now.Truncate(time.Minute)
		if !minute.Equal(last) {
			f.observe(minute)
			f.membership(&canary, f.blue, f.green)
			f.membership(&revokedChild, f.blue, []string{})
			f.membership(&expiredChild, f.blue, []string{})
			last = minute
		}
		if now.After(end.Add(100 * time.Millisecond)) {
			break
		}
		delay := time.Until(minute.Add(time.Minute).Add(100 * time.Millisecond))
		if delay > 30*time.Second {
			delay = 30 * time.Second
		}
		time.Sleep(delay)
	}
	health := map[string]model.Document{}
	for _, command := range []model.Document{paused, revoked} {
		f.must("finops_api", func(tx *store.Tx) error {
			d, e := f.api.buildFleetCohortHealth(f.ctx, tx, model.String(command, "id"))
			if e == nil && model.String(d, "status") != "HEALTHY" {
				t.Fatal("truthful full-window positive fixture was not healthy", d["reason_codes"])
			}
			health[model.String(command, "id")] = d
			return e
		})
	}
	f.must("finops_api", func(tx *store.Tx) error {
		if _, e := tx.FleetControlAppend(f.ctx, pausedParent.Plan.ID, 0, "PAUSED", "late positive acceptance"); e != nil {
			return e
		}
		_, e := tx.FleetControlAppend(f.ctx, revokedParent.Plan.ID, 0, "REVOKED", "late positive acceptance")
		return e
	})
	if !time.Now().UTC().After(expiredParent.Plan.ExpiresAt) {
		t.Fatal("real-clock legacy expiry did not elapse")
	}
	for _, tc := range []struct {
		name    string
		command model.Document
		health  model.Document
	}{{"paused", paused, health[model.String(paused, "id")]}, {"revoked", revoked, health[model.String(revoked, "id")]}, {"expired", expired, health[model.String(revoked, "id")]}} {
		t.Run(tc.name, func(t *testing.T) {
			commandID := model.String(tc.command, "id")
			var window, proof model.Document
			f.must("finops_api", func(tx *store.Tx) error {
				var e error
				window, e = fleetHealthOne(f.ctx, tx, "SELECT document FROM fleet_cohort_windows WHERE tenant_id=$1 AND id=$2", f.tenant, tc.health["cohort_window_id"])
				if e == nil {
					proof, e = tx.FleetProof(f.ctx, model.String(tc.health, "cohort_proof_id"))
				}
				return e
			})
			deny := func(role string, fn func(*store.Tx) error) {
				t.Helper()
				e := f.run(role, fn)
				var pg *pgconn.PgError
				if !errors.As(e, &pg) || pg.Code != "P0001" || !strings.Contains(pg.Message, "fleet forward authority expired paused or revoked") {
					t.Fatalf("expected the explicit forward-authority refusal, got %v", e)
				}
			}
			// Clone existing truthful positive payloads with a distinct record key.
			// The current parent guard must run even when an earlier healthy record
			// or private cohort proof already exists. No release is performed first.
			deny("finops_api", func(tx *store.Tx) error {
				window["command_id"], window["guard_probe"] = commandID, model.ID()
				raw, _ := json.Marshal(window)
				_, e := tx.Exec(f.ctx, "INSERT INTO fleet_cohort_windows(tenant_id,id,command_id,baseline_id,mode,status,content_hash,document) VALUES($1,$2,$3,$4,'FORWARD','CLEAR',$5,$6)", f.tenant, model.ID(), commandID, baseline["id"], fleet.Digest(window), raw)
				return e
			})
			deny("finops_api", func(tx *store.Tx) error {
				proof["command_id"], proof["guard_probe"] = commandID, model.ID()
				raw, _ := json.Marshal(proof)
				_, e := tx.Exec(f.ctx, "INSERT INTO fleet_proof_sets(tenant_id,id,kind,version,content_hash,document) VALUES($1,$2,'COHORT_HEALTH','1',$3,$4)", f.tenant, model.ID(), fleet.Digest(proof), raw)
				return e
			})
			deny("finops_api", func(tx *store.Tx) error {
				d := model.Document{"status": "HEALTHY", "mode": "FORWARD", "cohort_proof_id": tc.health["cohort_proof_id"], "guard_probe": model.ID()}
				_, _, e := tx.FleetHealthEvidenceAppend(f.ctx, commandID, d)
				return e
			})
			deny("finops_worker", func(tx *store.Tx) error {
				_, _, e := tx.FleetReservationRelease(f.ctx, commandID, model.String(tc.health, "id"))
				return e
			})
			f.must("finops_api", func(tx *store.Tx) error {
				d, e := f.api.buildFleetCohortHealth(f.ctx, tx, commandID)
				if e == nil && (model.String(d, "status") != "BLOCKED" || !strings.Contains(strings.Join(model.Strings(d, "reason_codes"), ","), "COHORT_FORWARD_AUTHORITY_")) {
					return errors.New("lost forward authority was not durably blocked")
				}
				return e
			})
			f.must("finops_worker", func(tx *store.Tx) error {
				var latched, recovery bool
				if e := tx.QueryRow(f.ctx, "SELECT EXISTS(SELECT 1 FROM fleet_cohort_failures WHERE tenant_id=$1 AND execution_id=$2),recovery_only FROM fleet_executions WHERE tenant_id=$1 AND id=$2", f.tenant, tc.command["execution_id"]).Scan(&latched, &recovery); e != nil {
					return e
				}
				current, e := tx.FleetCommand(f.ctx, commandID)
				if e == nil && (!latched || !recovery || current["reservation_released_at"] != nil || model.String(current, "owned_receipt_id") != model.String(tc.command, "owned_receipt_id") || model.Bool(current, "restored")) {
					return errors.New("late positive check erased an owned recovery obligation")
				}
				return e
			})
		})
	}
}
