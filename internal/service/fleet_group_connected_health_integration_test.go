package service

import (
	"context"
	"net/http/httptest"
	"sort"
	"sync/atomic"
	"testing"
	"time"

	ff "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetfixture"
	g "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetgroup"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/groupfixtureproducer"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
)

// Observer IDs identify this independently installed local instrumented work
// service. They are never relabelled as the deployment command. Each verdict
// separately pins the exact currently issued deployment command and manifest.
type connectedHealth struct {
	binding      groupfixtureproducer.HealthBinding
	url          string
	delay        atomic.Int64
	baseline     []groupfixtureproducer.HealthReceipt
	baselineRefs []ff.ArtifactReference
	limits       groupfixtureproducer.HealthLimits
	anchor       groupfixtureproducer.HealthBaselineAnchorEnvelope
	anchorRef    ff.ArtifactReference
}

func newConnectedHealth(t *testing.T, p g.GitProgram) *connectedHealth {
	t.Helper()
	h := &connectedHealth{binding: groupfixtureproducer.HealthBinding{Binding: p.Binding, Realm: p.Realm, ProgramSHA256: g.Digest(p), CommandID: model.ID(), OperationID: model.ID(), Fence: 1}, limits: groupfixtureproducer.HealthLimits{MinimumSamples: 30, MaxP95NS: int64(2 * time.Second), MaxP99NS: int64(3 * time.Second), MaxErrorRatePPM: 10000, MinAvailabilityPPM: 990000, MaxInFlight: 2, MaxBacklog: 0}}
	h.delay.Store(int64(time.Second))
	fixture, err := groupfixtureproducer.NewHTTPHealthFixture(h.binding, func(ctx context.Context) error {
		timer := time.NewTimer(time.Duration(h.delay.Load()))
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			return nil
		}
	}, 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(fixture)
	t.Cleanup(server.Close)
	h.url = server.URL
	return h
}

func (h *connectedHealth) collector(t *testing.T) *groupfixtureproducer.HealthCollector {
	t.Helper()
	c, err := groupfixtureproducer.NewHealthCollector(groupfixtureproducer.HealthInstallation{ID: model.ID(), Binding: h.binding, TargetURL: h.url})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func (h *connectedHealth) collect(t *testing.T, ctx context.Context, a *connectedStageArtifacts, command string, c *groupfixtureproducer.HealthCollector, kind string) (groupfixtureproducer.HealthReceipt, ff.ArtifactReference) {
	t.Helper()
	receipt, err := c.Collect(ctx, 40, 1)
	if err != nil {
		t.Fatal("actual instrumented HTTP receipt", err)
	}
	ref := a.put(t, ctx, command, kind, receipt)
	return receipt, ref
}

func (h *connectedHealth) calibrate(t *testing.T, ctx context.Context, a *connectedStageArtifacts, command string) {
	t.Helper()
	c := h.collector(t)
	for {
		r, ref := h.collect(t, ctx, a, command, c, "HEALTH_BASELINE")
		h.baseline = append(h.baseline, r)
		h.baselineRefs = append(h.baselineRefs, ref)
		if err := groupfixtureproducer.CheckHealthReceiptChain(h.binding, h.baseline); err != nil {
			t.Fatal("immutable baseline receipt quality", err)
		}
		var monotonic time.Duration
		for _, receipt := range h.baseline {
			if receipt.SchemaVersion != "2" || receipt.Clock == nil {
				t.Fatal("native baseline lacks versioned monotonic capture")
			}
			monotonic += time.Duration(receipt.Clock.ElapsedNS)
		}
		if r.After.CapturedAt.Sub(h.baseline[0].Before.CapturedAt) >= 2*time.Minute && monotonic >= 2*time.Minute {
			break
		}
	}
	latencies := []int64{}
	for _, r := range h.baseline {
		for _, o := range r.Observations {
			latencies = append(latencies, o.ElapsedNS)
		}
	}
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	if len(latencies) < 30 {
		t.Fatal("actual baseline sample population")
	}
	p95 := latencies[(len(latencies)*95+99)/100-1]
	// The eventual injected work delay derives from the actually observed
	// frozen baseline quantile. Nominal timer durations are not measurements.
	a.put(t, ctx, command, "HEALTH_VERDICT", model.Document{"schema_version": "1", "status": "BASELINE_CALIBRATED", "observer_binding": h.binding, "baseline_refs": h.baselineRefs, "actual_start": h.baseline[0].Before.CapturedAt, "actual_end": h.baseline[len(h.baseline)-1].After.CapturedAt, "actual_p95_ns": p95, "customer_work_preservation_authority": false})
}

func (h *connectedHealth) baselineP95() int64 {
	values := []int64{}
	for _, r := range h.baseline {
		for _, o := range r.Observations {
			values = append(values, o.ElapsedNS)
		}
	}
	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
	return values[(len(values)*95+99)/100-1]
}

func (h *connectedHealth) wrapper(command g.JournalCommand, entry *g.GitManifestEntry, window groupfixtureproducer.HealthWindow, refs []ff.ArtifactReference) model.Document {
	return model.Document{"schema_version": "2", "realm": "ISOLATED_FIXTURE", "observer_binding": h.binding, "deployment_command_id": command.ID, "deployment_operation_id": command.OperationID, "deployment_fence": command.Fence, "deployment_command_sha256": g.Digest(command), "manifest_entry": entry, "manifest_entry_sha256": g.Digest(entry), "baseline_refs": h.baselineRefs, "baseline_anchor_ref": h.anchorRef, "baseline_anchor_sha256": g.Digest(h.anchor), "current_receipt_refs": refs, "verdict": window, "customer_work_preservation_authority": false}
}

func (h *connectedHealth) observe(t *testing.T, ctx context.Context, a *connectedStageArtifacts, command g.JournalCommand, entry *g.GitManifestEntry, want string) (model.Document, groupfixtureproducer.HealthWindow, ff.ArtifactReference) {
	t.Helper()
	collector := h.collector(t)
	current := []groupfixtureproducer.HealthReceipt{}
	refs := []ff.ArtifactReference{}
	for {
		r, ref := h.collect(t, ctx, a, command.ID, collector, "HEALTH_RECEIPT")
		current = append(current, r)
		refs = append(refs, ref)
		a.h.refresh(t, ctx) // Renew only the identical current logical head, never intent/READY or baseline.
		kind := groupfixtureproducer.HealthManifestObservation
		if entry == nil {
			kind = groupfixtureproducer.HealthRestorationObservation
		}
		window := groupfixtureproducer.EvaluateActivatedHealthWindow(a.h.view, a.h.bootstrap.Keys.Core(), a.h.view.Head.Head.Ref, h.anchor, groupfixtureproducer.ActivatedHealthDeployment{CommandID: command.ID, OperationID: command.OperationID, Fence: command.Fence, Kind: kind}, h.binding, h.baseline, current, h.limits, time.Now().UTC())
		if window.Status == "BREACH" || window.Status == "OBSERVED" {
			wrapper := h.wrapper(command, entry, window, refs)
			ref := a.put(t, ctx, command.ID, "HEALTH_VERDICT", wrapper)
			if want != "" && window.Status != want {
				connectedDriverMark("", "HEALTH_BREACH")
				t.Fatal("actual health decision differed", window.Status, window.ReasonCodes)
			}
			return wrapper, window, ref
		}
		if connectedIrreparableHealth(window.ReasonCodes) {
			a.put(t, ctx, command.ID, "HEALTH_VERDICT", h.wrapper(command, entry, window, refs))
			connectedDriverMark("", "HEALTH_EVIDENCE_INVALID")
			t.Fatal("immutable health evidence cannot improve", window.ReasonCodes)
		}
	}
}

func connectedIrreparableHealth(reasons []string) bool {
	for _, reason := range reasons {
		switch reason {
		case "HEALTH_STAGE_INITIAL_COVERAGE_UNKNOWN", "HEALTH_CURRENT_JOURNAL_UNAVAILABLE", "HEALTH_ACTIVATION_ANCHOR_INVALID", "HEALTH_CURRENT_RECEIPTS_STALE", "HEALTH_STAGE_OWNERSHIP_UNAVAILABLE", "MANIFEST_ENTRY_HEALTH_BINDING_INVALID", "HEALTH_POLICY_INVALID", "HEALTH_RECEIPT_INVALID", "HEALTH_CLOCK_DISCONTINUITY", "HEALTH_COVERAGE_UNKNOWN", "HEALTH_PERIOD_INVALID", "HEALTH_MEASUREMENT_REVISION_MISMATCH", "BASELINE_OBSERVATION_WINDOW_INCOMPLETE", "BASELINE_MONOTONIC_OBSERVATION_WINDOW_INCOMPLETE", "BASELINE_OBSERVATION_STALE":
			return true
		}
	}
	return false
}

func TestConnectedHealthWaitsOnlyForRepairableWindowIncompleteness(t *testing.T) {
	for _, reason := range []string{"STAGE_OBSERVATION_WINDOW_INCOMPLETE", "MONOTONIC_OBSERVATION_WINDOW_INCOMPLETE", "HEALTH_SAMPLES_INSUFFICIENT"} {
		if connectedIrreparableHealth([]string{reason}) {
			t.Fatal("repairable current population rejected", reason)
		}
	}
	for _, reason := range []string{"HEALTH_COVERAGE_UNKNOWN", "HEALTH_CLOCK_DISCONTINUITY", "HEALTH_RECEIPT_INVALID", "BASELINE_OBSERVATION_STALE", "BASELINE_MONOTONIC_OBSERVATION_WINDOW_INCOMPLETE"} {
		if !connectedIrreparableHealth([]string{"STAGE_OBSERVATION_WINDOW_INCOMPLETE", reason}) {
			t.Fatal("irreparable frozen evidence would wait", reason)
		}
	}
}

func (h *connectedHealth) currentRecovery(t *testing.T, ctx context.Context, a *connectedStageArtifacts, command g.JournalCommand) model.Document {
	t.Helper()
	collector := h.collector(t)
	r, err := collector.Collect(ctx, 30, 1)
	if err != nil {
		t.Fatal("actual recovery observation", err)
	}
	ref := a.put(t, ctx, command.ID, "HEALTH_RECEIPT", r)
	// This is a fresh recovery observation, not a positive terminal window.
	// The final900s verdict is collected separately after every inverse.
	body := model.Document{"schema_version": "1", "status": "RECOVERY_OBSERVATION_ONLY", "observer_binding": h.binding, "deployment_command_id": command.ID, "deployment_operation_id": command.OperationID, "deployment_fence": command.Fence, "receipt_ref": ref, "receipt_sha256": r.SHA256, "baseline_refs": h.baselineRefs, "customer_work_preservation_authority": false}
	a.put(t, ctx, command.ID, "HEALTH_VERDICT", body)
	return body
}

func connectedNativeOperatingLoop(t *testing.T, ctx context.Context, h *connectedJournal, selected ff.Proposal, prepared ff.Preparation, archive *groupfixtureproducer.EncryptedArchive) (model.Document, []model.Document) {
	t.Helper()
	a := &connectedStageArtifacts{h: h, selected: selected, prepared: prepared, archive: archive}
	native, err := groupfixtureproducer.OpenNativeStage(ctx, selected, prepared, archive)
	if err != nil {
		t.Fatal("authenticated native stage open", err)
	}
	health := newConnectedHealth(t, prepared.Program)
	h.healthGuard = a.healthGuard
	connectedDriverMark("BASELINE", "")
	prepare := h.preparingForward(t, ctx, 1)
	health.calibrate(t, ctx, a, prepare.ID)
	baseline := model.Document{"status": "ACTUAL_BASELINE_CALIBRATED", "observer_binding": health.binding, "baseline_refs": health.baselineRefs, "native_deployment_observed": false}
	connectedDriverMark("PREPARE_APPLY", "")
	_, _ = a.execute(t, ctx, native, prepare, baseline, false)
	health.activate(t, ctx, a, prepare.ID)
	connectedDriverMark("CANDIDATE_APPLY", "")
	candidate := h.preparingForward(t, ctx, 2)
	candidate, _ = a.execute(t, ctx, native, candidate, baseline, true)
	// The pending apply really ran in a separate process, exited at its
	// fsynced terminal, and the original UNKNOWN was reconciled without CLI.
	warmEntry := prepared.Program.Manifest.Entries[1]
	connectedDriverMark("WARMUP", "")
	warmup, warmWindow, _ := health.observe(t, ctx, a, candidate, &warmEntry, "OBSERVED")
	if warmWindow.RequiredEnd.Sub(warmWindow.Start) != 120*time.Second || warmWindow.ObservedThrough.Before(warmWindow.RequiredEnd) {
		t.Fatal("unshortened actual candidate warmup missing")
	}
	connectedDriverMark("CANARY_APPLY", "")
	traffic := h.preparingForward(t, ctx, 3)
	traffic, _ = a.execute(t, ctx, native, traffic, warmup, false)
	actualBaselineP95 := health.baselineP95()
	injectedDelay := (actualBaselineP95*135 + 99) / 100
	health.delay.Store(injectedDelay)
	canaryEntry := prepared.Program.Manifest.Entries[2]
	connectedDriverMark("CANARY_OBSERVATION", "")
	breach, breachWindow, breachRef := health.observe(t, ctx, a, traffic, &canaryEntry, "BREACH")
	if breachWindow.RequiredEnd.Sub(breachWindow.Start) != time.Hour || !breachWindow.ObservedThrough.Before(breachWindow.RequiredEnd) || breachWindow.P95NS == nil || *breachWindow.P95NS*100 <= actualBaselineP95*115 {
		t.Fatal("genuine early latency abort did not preserve1h canary policy")
	}
	incidents := []ff.ArtifactReference{a.incident(t, ctx, traffic, "CANARY_OBSERVATION", model.ID(), breachRef)}
	// Failure stops forward delivery. Only the two retained exact LIFO effects
	// are restored; fresh recovery facts do not claim a completed canary.
	health.delay.Store(int64(time.Second))
	var last g.JournalCommand
	for i := 0; i < 2; i++ {
		connectedDriverMark("OWNED_INVERSE", "")
		last = h.preparingInverse(t, ctx, native)
		observation := health.currentRecovery(t, ctx, a, last)
		last, _ = a.execute(t, ctx, native, last, observation, false)
	}
	p := h.refresh(t, ctx)
	if len(p.Stack) != 0 || p.Pending != nil || p.Current.Model != prepared.JournalReview.Base.Model || p.LastForwardSequence != 3 || len(p.Consumed) != 2 {
		t.Fatal("exact owned LIFO restoration closure")
	}
	var terminal model.Document
	var terminalWindow groupfixtureproducer.HealthWindow
	failedWindows := []ff.ArtifactReference{}
	for attempt := 0; attempt < 2; attempt++ {
		connectedDriverMark("TERMINAL_OBSERVATION", "")
		var verdictRef ff.ArtifactReference
		terminal, terminalWindow, verdictRef = health.observe(t, ctx, a, last, nil, "")
		if terminalWindow.Status == "OBSERVED" {
			break
		}
		if terminalWindow.Status != "BREACH" {
			t.Fatal("terminal evidence unavailable; reservation remains held")
		}
		failedWindows = append(failedWindows, verdictRef)
		incidents = append(incidents, a.incident(t, ctx, last, "TERMINAL_OBSERVATION", model.ID(), verdictRef))
		connectedDriverMark("TERMINAL_OBSERVATION", "RECOVERY_WINDOW_RETRY")
		// A fresh full900s window follows an immutable failed-window incident.
		// The original baseline and permanent disqualification never change.
	}
	if terminalWindow.Status != "OBSERVED" {
		connectedDriverMark("TERMINAL_OBSERVATION", "HEALTH_BREACH")
		t.Fatal("bounded fixture recovery retries exhausted; reservation held, alert adapter unavailable")
	}
	if terminalWindow.RequiredEnd.Sub(terminalWindow.Start) != 15*time.Minute || terminalWindow.ObservedThrough.Before(terminalWindow.RequiredEnd) {
		t.Fatal("unshortened actual terminal observation missing")
	}
	// Release is only attempted after actual terminal health, never APPLIED.
	connectedDriverMark("RELEASE", "")
	h.refresh(t, ctx) // Logical ownership is unchanged; old intent/READY is not renewed.
	if err = h.ledger.Do(ctx, h.f.tenant, func(tx *store.Tx) error {
		cursor, e := tx.FleetGroupJournalCursor(ctx, h.bootstrap.ChainID)
		if e != nil {
			return e
		}
		return tx.FleetGroupJournalRelease(ctx, h.bootstrap.ChainID, cursor)
	}); err != nil {
		t.Fatal("resolved native fixture release", err)
	}
	counts, err := groupfixtureproducer.TerraformInvocations()
	if err != nil {
		t.Fatal(err)
	}
	if counts.Counts["apply"] != 6 {
		t.Fatal("native invocation audit must include exactly one bootstrap and five stage applies")
	}
	var baselineMonotonicNS int64
	for _, receipt := range health.baseline {
		baselineMonotonicNS += receipt.Clock.ElapsedNS
	}
	return model.Document{"status": "PASS", "fixture_only": true, "native_saved_plan_exact_applies": 5, "owned_effects": 2, "fresh_lifo_inverse_commits": 2, "actual_subprocess_terminal_exit_unknown_reconciled": true, "repeat_capture_and_apply_no_extra_terraform": true, "baseline_actual_duration_seconds": health.baseline[len(health.baseline)-1].After.CapturedAt.Sub(health.baseline[0].Before.CapturedAt).Seconds(), "baseline_measurement_revision": "GO_MONOTONIC_HTTP_V2", "baseline_monotonic_duration_ns": baselineMonotonicNS, "warmup": warmup, "canary_breach": breach, "injected_work_delay_ns": injectedDelay, "injection_basis": "CEIL_ACTUAL_FROZEN_BASELINE_P95_TIMES_1_35", "healthy_fixture_work_ns": int64(time.Second), "baseline_anchor_ref": health.anchorRef, "baseline_anchor_sha256": g.Digest(health.anchor), "baseline_activation_at": health.anchor.Anchor.ActivatedAt, "permanent_forward_disqualification": true, "financial_disqualified_forever": true, "health_incident_refs": incidents, "failed_recovery_window_refs": failedWindows, "recovery_alert_delivery": "UNAVAILABLE_NO_COMMISSIONED_ADAPTER", "production_durable_retry_accepted": false, "terminal": terminal, "terraform_invocations": counts, "customer_execution_authorized": false, "verified_saving": nil}, a.metadata
}
