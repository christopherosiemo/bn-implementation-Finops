package service

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	ff "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetfixture"
	g "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetgroup"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/groupfixtureproducer"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
)

var errConnectedForwardDisqualified = errors.New("ISOLATED_HEALTH_INCIDENT_FORWARD_DISQUALIFIED")

// These diagnostics contain only fixed enums and elapsed time. Raw failure
// logs, bodies, credentials and artifact references stay private.
var connectedDriver struct {
	sync.Mutex
	started time.Time
	phase   string
	reasons []string
}

func connectedDriverStart(t *testing.T) {
	if os.Getenv("FLEET_CONNECTED_NATIVE_RUNTIME") != "1" {
		return
	}
	connectedDriver.Lock()
	connectedDriver.started = time.Now()
	connectedDriver.phase = "PREPARATION"
	connectedDriver.reasons = nil
	connectedDriver.Unlock()
	connectedDriverMark("PREPARATION", "")
	t.Cleanup(func() {
		if t.Failed() {
			connectedDriverMark("", "ASSERTION_FAILED")
		}
	})
}
func connectedDriverMark(phase, reason string) {
	connectedDriver.Lock()
	defer connectedDriver.Unlock()
	if connectedDriver.started.IsZero() {
		return
	}
	if phase != "" {
		connectedDriver.phase = phase
	}
	if reason != "" {
		exists := false
		for _, r := range connectedDriver.reasons {
			exists = exists || r == reason
		}
		if !exists && len(connectedDriver.reasons) < 8 {
			connectedDriver.reasons = append(connectedDriver.reasons, reason)
		}
	}
	reasons := append([]string{}, connectedDriver.reasons...)
	raw, _ := json.Marshal(model.Document{"schema_version": "1", "phase": connectedDriver.phase, "reason_codes": reasons, "elapsed_ms": time.Since(connectedDriver.started).Milliseconds()})
	tmp := filepath.Join("/results", "driver-phase.tmp")
	if os.WriteFile(tmp, raw, 0600) == nil {
		_ = os.Rename(tmp, filepath.Join("/results", "driver-phase.json"))
	}
}

func (h *connectedHealth) activate(t *testing.T, ctx context.Context, a *connectedStageArtifacts, command string) {
	t.Helper()
	a.h.refresh(t, ctx)
	refs := []groupfixtureproducer.HealthBaselineArtifact{}
	if err := a.h.ledger.Do(ctx, a.h.f.tenant, func(tx *store.Tx) error {
		v, keys, e := tx.FleetGroupJournalOriginal(ctx, a.h.bootstrap.ChainID)
		if e != nil {
			return e
		}
		for i, ref := range h.baselineRefs {
			d, e := tx.GroupArtifactGet(ctx, a.h.bootstrap.ChainID, command, "HEALTH_BASELINE", ref.ID)
			if e != nil {
				return e
			}
			raw, e := json.Marshal(d["artifact"])
			if e != nil {
				return e
			}
			var actual ff.ArtifactReference
			if json.Unmarshal(raw, &actual) != nil || actual != ref {
				return errors.New("issued baseline artifact differs")
			}
			at, ok := d["created_at"].(time.Time)
			if !ok || i >= len(h.baseline) {
				return errors.New("issued baseline time unavailable")
			}
			plain, e := a.archive.Read(ctx, a.selected, "HEALTH_BASELINE", ref)
			if e != nil {
				return e
			}
			expected, _ := json.Marshal(h.baseline[i])
			if g.BytesDigest(plain) != g.BytesDigest(expected) {
				return errors.New("issued baseline body differs")
			}
			refs = append(refs, groupfixtureproducer.HealthBaselineArtifact{Reference: ref, IssuedAt: at})
		}
		h.anchor, e = groupfixtureproducer.SignHealthBaselineAnchor(v, keys.Core(), v.Head.Head.Ref, h.binding, h.baseline, refs, a.h.ledgerKey, time.Now().UTC())
		return e
	}); err != nil {
		t.Fatal("immutable activated baseline", err)
	}
	h.anchorRef = a.put(t, ctx, command, "HEALTH_VERDICT", h.anchor)
}

// Private fixture repository policy. Every incident is immutable032 ciphertext
// referenced under the real issued command. It permanently disqualifies this
// program; a later healthy observation cannot clear it. This is NOT a deployed
// durable incident controller or an authorized external alert adapter.
func (a *connectedStageArtifacts) healthGuard(ctx context.Context, tx *store.Tx) error {
	rows, e := tx.Query(ctx, `SELECT command_id,id FROM public.fleet_group_artifacts WHERE tenant_id=$1 AND chain_id=$2 AND kind='HEALTH_VERDICT' ORDER BY command_id,id LIMIT 4097`, tx.Tenant, a.h.bootstrap.ChainID)
	if e != nil {
		return e
	}
	type selected struct{ command, id string }
	ids := []selected{}
	for rows.Next() {
		var s selected
		if e = rows.Scan(&s.command, &s.id); e != nil {
			rows.Close()
			return e
		}
		ids = append(ids, s)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	if len(ids) > 4096 {
		return errors.New("bounded fixture incident history unavailable")
	}
	for _, id := range ids {
		d, e := tx.GroupArtifactGet(ctx, a.h.bootstrap.ChainID, id.command, "HEALTH_VERDICT", id.id)
		if e != nil {
			return e
		}
		raw, _ := json.Marshal(d["artifact"])
		var ref ff.ArtifactReference
		if json.Unmarshal(raw, &ref) != nil {
			return errors.New("fixture incident ref unavailable")
		}
		plain, e := a.archive.Read(ctx, a.selected, "HEALTH_VERDICT", ref)
		if e != nil {
			return e
		}
		var body model.Document
		if json.Unmarshal(plain, &body) != nil {
			return errors.New("fixture verdict invalid")
		}
		if connectedIncidentDisqualifies(body, g.Digest(a.prepared.Program)) {
			return errConnectedForwardDisqualified
		}
	}
	return nil
}
func connectedIncidentDisqualifies(d model.Document, program string) bool {
	return model.String(d, "kind") == "ISOLATED_RECOVERY_HEALTH_INCIDENT" && model.String(d, "program_sha256") == program && d["forward_aborted"] == true && d["financial_disqualified_forever"] == true
}

func (a *connectedStageArtifacts) incident(t *testing.T, ctx context.Context, command g.JournalCommand, phase, attempt string, failed ff.ArtifactReference) ff.ArtifactReference {
	t.Helper()
	a.h.refresh(t, ctx)
	var proof model.Document
	if e := a.h.ledger.Do(ctx, a.h.f.tenant, func(tx *store.Tx) error {
		cursor, e := tx.FleetGroupJournalCursor(ctx, a.h.bootstrap.ChainID)
		if e != nil {
			return e
		}
		var workload string
		var released *time.Time
		var at time.Time
		if e = tx.QueryRow(ctx, `SELECT workload_id,released_at,clock_timestamp() FROM public.fleet_group_journal_reservations WHERE tenant_id=$1 AND chain_id=$2`, tx.Tenant, a.h.bootstrap.ChainID).Scan(&workload, &released, &at); e != nil {
			return e
		}
		if released != nil || workload != a.prepared.Program.Binding.Old.Target.WorkloadID {
			return errors.New("health failure lost held workload reservation")
		}
		proof = model.Document{"cursor": cursor, "workload_id": workload, "reservation_held_at": at, "released": false}
		return nil
	}); e != nil {
		t.Fatal("incident held-reservation proof", e)
	}
	ref := a.put(t, ctx, command.ID, "HEALTH_VERDICT", model.Document{"schema_version": "1", "kind": "ISOLATED_RECOVERY_HEALTH_INCIDENT", "program_sha256": g.Digest(a.prepared.Program), "phase": phase, "attempt_id": attempt, "failed_window_ref": failed, "command_id": command.ID, "operation_id": command.OperationID, "fence": command.Fence, "forward_aborted": true, "financial_disqualified_forever": true, "reservation_proof": proof, "alert_status": "RECOVERY_ALERT_PENDING", "alert_delivery": "UNAVAILABLE_NO_COMMISSIONED_ADAPTER", "production_durable_retry_accepted": false})
	// Reopen the actual DB pools and prove policy reloads ciphertext, rather
	// than borrowing an in-memory flag. No new event, command or native I/O.
	beforeCursor := a.h.cursor
	beforeNative, e := groupfixtureproducer.TerraformInvocations()
	if e != nil {
		t.Fatal(e)
	}
	a.h.reopen(t, ctx)
	if e := a.h.ledger.Do(ctx, a.h.f.tenant, func(tx *store.Tx) error { return a.healthGuard(ctx, tx) }); !errors.Is(e, errConnectedForwardDisqualified) {
		t.Fatal("persisted incident did not permanently block forward", e)
	}
	if e := a.h.ledger.Do(ctx, a.h.f.tenant, func(tx *store.Tx) error {
		cursor, e := tx.FleetGroupJournalCursor(ctx, a.h.bootstrap.ChainID)
		if e == nil && cursor != beforeCursor {
			return errors.New("incident policy check changed current journal")
		}
		return e
	}); e != nil {
		t.Fatal(e)
	}
	afterNative, e := groupfixtureproducer.TerraformInvocations()
	if e != nil || beforeNative.Total != afterNative.Total || beforeNative.SHA256 != afterNative.SHA256 {
		t.Fatal("incident policy check dispatched native command", e)
	}
	return ref
}

func TestConnectedRecoveryIncidentCannotBeClearedByHealthyRetry(t *testing.T) {
	d := model.Document{"kind": "ISOLATED_RECOVERY_HEALTH_INCIDENT", "program_sha256": "program", "forward_aborted": true, "financial_disqualified_forever": true}
	if !connectedIncidentDisqualifies(d, "program") {
		t.Fatal("incident ignored")
	}
	d["later_status"] = "OBSERVED"
	if !connectedIncidentDisqualifies(d, "program") {
		t.Fatal("healthy retry cleared permanent disqualification")
	}
	if connectedIncidentDisqualifies(d, "other") {
		t.Fatal("foreign incident borrowed")
	}
}
