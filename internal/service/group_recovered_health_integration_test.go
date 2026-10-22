package service

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	ff "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetfixture"
	g "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetgroup"
	native "github.com/christopherosiemo/bn-implementation-Finops/internal/groupfixtureproducer"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/jackc/pgx/v5"
)

type workspacePreparationHooks struct {
	Initialize       func(*testing.T, context.Context, *store.Store, workspaceRuntime, *connectedStageArtifacts, *connectedHealth)
	Calibrate        func(*testing.T, context.Context, *connectedStageArtifacts, *connectedHealth, string)
	FirstApplied     func(*testing.T, context.Context, *connectedStageArtifacts, *connectedHealth, string)
	ActivationSHA256 string
	PrivateSHA256    string
}
type recoveredHealthActivation struct {
	SchemaVersion       string                            `json:"schema_version"`
	RunID               string                            `json:"run_id"`
	TenantID            string                            `json:"tenant_id"`
	ChainID             string                            `json:"chain_id"`
	ProgramSHA256       string                            `json:"program_sha256"`
	OldWorkspace        native.NativeWorkspace            `json:"old_workspace"`
	Observer            store.GroupRecoveryHealthObserver `json:"observer"`
	Baseline            store.GroupRecoveryHealthBaseline `json:"baseline"`
	BaselineReceiptRefs []ff.ArtifactReference            `json:"baseline_receipt_refs"`
}

// Private fixture coordinator handoff, never an artifact uploaded to CI.
// The observer key grants no ledger, pipeline, signer or controller privilege.
type recoveredHealthPrivate struct {
	SchemaVersion    string                 `json:"schema_version"`
	RunID            string                 `json:"run_id"`
	ObserverDSN      string                 `json:"observer_dsn"`
	ObserverKey      ed25519.PrivateKey     `json:"observer_key"`
	Baseline         []native.HealthReceipt `json:"baseline"`
	ActivationSHA256 string                 `json:"activation_sha256"`
}
type recoveredHealthAttemptResult struct {
	Attempt               store.GroupRecoveryHealthAttempt `json:"attempt"`
	OutcomeCanonicalJSON  string                           `json:"outcome_canonical_json"`
	Algorithm             string                           `json:"algorithm"`
	Signature             string                           `json:"signature"`
	OutcomeReference      ff.ArtifactReference             `json:"outcome_reference"`
	ObservationReferences []ff.ArtifactReference           `json:"observation_references"`
}

// Opt-in034 extends the accepted033 pending result instead of changing it.
// Raw native/customer history remains BLOCKED, and this observed HTTP work
// fixture cannot establish customer execution or financial claim authority.
func TestFleetGroupWorkspaceRecoveryHealthPhases(t *testing.T) {
	switch os.Getenv("FLEET_GROUP_WORKSPACE_PHASE") {
	case "":
		t.Skip("requires owned recovery-health phase runner")
	case "PREPARE":
		workspacePrepareWithHook(t, newRecoveredHealthHooks())
	case "RECONSTRUCT":
		workspaceReconstruct(t)
		workspaceRecoveredHealth(t)
	case "CLEANUP":
		workspaceCleanup(t)
	default:
		t.Fatal("fixed recovery-health phase required")
	}
}

func newRecoveredHealthHooks() *workspacePreparationHooks {
	hooks := &workspacePreparationHooks{}
	var observer store.GroupRecoveryHealthObserver
	var private recoveredHealthPrivate
	var runtime workspaceRuntime
	var observations []store.GroupRecoveryHealthObservationEnvelope
	hooks.Initialize = func(t *testing.T, ctx context.Context, admin *store.Store, r workspaceRuntime, a *connectedStageArtifacts, health *connectedHealth) {
		runtime = r
		login := "connected_" + strings.ReplaceAll(model.ID(), "-", "")
		password := model.ID() + model.ID()
		if _, e := admin.Pool.Exec(ctx, "CREATE ROLE "+pgx.Identifier{login}.Sanitize()+" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '"+password+"' IN ROLE finops_group_health_observer"); e != nil {
			t.Fatal("independent recovery observer login unavailable")
		}
		public, key, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		observer = store.GroupRecoveryHealthObserver{ID: model.ID(), TenantID: a.h.f.tenant, ChainID: a.h.bootstrap.ChainID, DatabaseLogin: login, Identity: store.GroupRecoveryHealthIdentity{SourceID: "isolated-recovery-health-" + model.ID(), Issuer: "https://isolated-health.invalid", Subject: "owned-http-recovery-observer", Audience: "finops-group-health-observer"}, PublicKey: public, Limits: health.limits}
		private = recoveredHealthPrivate{SchemaVersion: "1", RunID: r.RunID, ObserverDSN: workspaceLoginDSN(admin.Pool.Config().ConnConfig, login, password), ObserverKey: key}
		limits, _ := json.Marshal(observer.Limits)
		if e = admin.Do(ctx, observer.TenantID, func(tx *store.Tx) error {
			_, err := tx.Exec(ctx, `INSERT INTO public.fleet_group_recovery_health_observers(tenant_id,chain_id,id,profile_id,profile_generation,image_sha256,database_login,source_id,issuer,subject,audience,public_key,limits) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13::jsonb)`, observer.TenantID, observer.ChainID, observer.ID, a.selected.Profile.ID, a.selected.Profile.Generation, r.Workspace.ImageSHA256, login, observer.Identity.SourceID, observer.Identity.Issuer, observer.Identity.Subject, observer.Identity.Audience, public, limits)
			return err
		}); e != nil {
			t.Fatal("operator-installed independent health observer failed", e)
		}
	}
	hooks.Calibrate = func(t *testing.T, ctx context.Context, a *connectedStageArtifacts, health *connectedHealth, command string) {
		measured := runRecoveredObserver(t, ctx, a, recoveredObserverConfig{SchemaVersion: "1", Mode: "BASELINE", DSN: private.ObserverDSN, Key: private.ObserverKey, Observer: observer, Workspace: runtime.Workspace, Binding: health.binding, TargetURL: health.url, CommandID: command}, false)
		observations = measured.Observations
		for _, o := range observations {
			health.baseline = append(health.baseline, o.Observation.Receipt)
			health.baselineRefs = append(health.baselineRefs, o.Observation.Reference)
		}
		if native.CheckHealthReceiptChain(health.binding, health.baseline) != nil {
			t.Fatal("independently observed baseline chain invalid")
		}
	}
	hooks.FirstApplied = func(t *testing.T, ctx context.Context, a *connectedStageArtifacts, health *connectedHealth, command string) {
		health.activate(t, ctx, a, command)
		ids := []string{}
		for _, o := range observations {
			ids = append(ids, o.Observation.ID)
		}
		baseline := store.GroupRecoveryHealthBaseline{SchemaVersion: "1", ID: model.ID(), TenantID: observer.TenantID, ChainID: observer.ChainID, Anchor: health.anchor, AnchorReference: health.anchorRef, ObservationIDs: ids}
		if e := a.h.ledger.Do(ctx, observer.TenantID, func(tx *store.Tx) error {
			_, _, err := tx.GroupRecoveryHealthBaselineBind(ctx, observer.ChainID, baseline.ID, baseline.Anchor, baseline.AnchorReference, ids)
			return err
		}); e != nil {
			t.Fatal("immutable original health baseline activation failed", e)
		}
		activation := recoveredHealthActivation{SchemaVersion: "1", RunID: runtime.RunID, TenantID: observer.TenantID, ChainID: observer.ChainID, ProgramSHA256: g.Digest(a.prepared.Program), OldWorkspace: runtime.Workspace, Observer: observer, Baseline: baseline, BaselineReceiptRefs: health.baselineRefs}
		var e error
		hooks.ActivationSHA256, e = workspaceWrite("/handoff/health-activation.json", activation)
		if e != nil {
			t.Fatal("immutable public health activation unavailable")
		}
		private.ActivationSHA256 = hooks.ActivationSHA256
		private.Baseline = health.baseline
		hooks.PrivateSHA256, e = workspaceWrite("/handoff/health-private.json", private)
		if e != nil {
			t.Fatal("immutable private observer handoff unavailable")
		}
	}
	return hooks
}

func recoveredAttemptResult(attempt store.GroupRecoveryHealthAttempt, run recoveredObserverRun, observations []store.GroupRecoveryHealthObservationEnvelope) recoveredHealthAttemptResult {
	raw, _ := json.Marshal(run.Envelope.Outcome)
	refs := []ff.ArtifactReference{}
	for _, o := range observations {
		refs = append(refs, o.Observation.Reference)
	}
	return recoveredHealthAttemptResult{attempt, string(raw), run.Envelope.Algorithm, run.Envelope.Signature, run.OutcomeReference, refs}
}

func workspaceRecoveredHealth(t *testing.T) {
	t.Helper()
	runtime := workspaceConfiguration(t)
	var b workspaceBundle
	if workspaceRead(workspaceBundlePath, 32<<20, &b) == nil || b.HealthActivationSHA256 == "" || b.HealthPrivateSHA256 == "" {
		t.Fatal("recovery health requires pre-loss activation")
	}
	var activation recoveredHealthActivation
	activationRaw := workspaceRead("/handoff/health-activation.json", 32<<10, &activation)
	var private recoveredHealthPrivate
	privateRaw := workspaceRead("/handoff/health-private.json", 256<<10, &private)
	if activationRaw == nil || privateRaw == nil || g.BytesDigest(activationRaw) != b.HealthActivationSHA256 || g.BytesDigest(privateRaw) != b.HealthPrivateSHA256 || private.ActivationSHA256 != b.HealthActivationSHA256 || activation.RunID != runtime.RunID || private.RunID != runtime.RunID || activation.ChainID != b.Bootstrap.ChainID || activation.TenantID != b.TenantID || activation.ProgramSHA256 != g.Digest(b.Prepared.Program) || activation.OldWorkspace != b.Runtime.Workspace || len(private.ObserverKey) != 64 || !private.ObserverKey.Public().(ed25519.PublicKey).Equal(activation.Observer.PublicKey) {
		t.Fatal("pre-loss observer or immutable baseline closure differs")
	}
	original, originalRaw := readRecoveredReconstruction("/results/workspace-reconstructed.json")
	if originalRaw == nil || !original.TerminalHealthPending || !original.ReservationHeld || original.RestoredStateSHA256 == "" {
		t.Fatal("original reconstruction pending evidence unavailable")
	}
	priorAudit, e := native.TerraformInvocations()
	if e != nil || priorAudit.Total != 3 || priorAudit.Counts["apply"] != 1 || g.Digest(priorAudit) != g.Digest(original.PostReconstructionRecoveryInvocations) {
		t.Fatal("exact original recovery invocation audit unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Minute)
	defer cancel()
	open := func(mode, dsn string) *store.Store {
		t.Helper()
		db, e := store.OpenRuntime(ctx, dsn, mode)
		if e != nil {
			t.Fatal("dedicated recovery runtime unavailable")
		}
		t.Cleanup(db.Pool.Close)
		return db
	}
	ledger := open("group-ledger", b.RoleDSNs["group-ledger"])
	pipeline := open("group-pipeline", b.RoleDSNs["group-pipeline"])
	h := &connectedJournal{f: &mutationReplayFixture{t: t, tenant: b.TenantID}, ledger: ledger, pipeline: pipeline, bootstrap: b.Bootstrap, signerKey: b.SignerKey, pipelineKey: b.PipelineKey, ledgerKey: b.LedgerKey}
	a := &connectedStageArtifacts{h: h, selected: b.Selected, prepared: b.Prepared, archive: workspaceArchive(t, b)}
	projection := h.refresh(t, ctx)
	if projection.Pending != nil || len(projection.Stack) != 0 || len(projection.Consumed) != 1 || projection.Current.StateSHA256 != original.RestoredStateSHA256 {
		t.Fatal("recovered native ownership is not exact restored head")
	}
	observer := activation.Observer
	observerDB := open("group-health-observer", private.ObserverDSN)
	var snapshot store.GroupRecoveryHealthSnapshot
	if e := observerDB.Do(ctx, b.TenantID, func(tx *store.Tx) error {
		var err error
		snapshot, err = tx.GroupRecoveryHealthSnapshot(ctx, b.Bootstrap.ChainID, observer.ID, runtime.Workspace.Generation)
		return err
	}); e != nil || snapshot.Baseline == nil || g.Digest(*snapshot.Baseline) != g.Digest(activation.Baseline) || snapshot.Workspace != runtime.Workspace || snapshot.Command.ID != original.FreshOwnedInverseCommandID {
		t.Fatal("server-resolved post-loss baseline/current inverse differs", e)
	}
	// An APPLIED native inverse is deliberately insufficient to release034.
	release := func() error {
		return ledger.Do(ctx, b.TenantID, func(tx *store.Tx) error {
			cursor, e := tx.FleetGroupJournalCursor(ctx, b.Bootstrap.ChainID)
			if e != nil {
				return e
			}
			return tx.FleetGroupJournalRelease(ctx, b.Bootstrap.ChainID, cursor)
		})
	}
	if e := release(); e == nil {
		t.Fatal("restoration released without full recovery health")
	}
	if len(private.Baseline) == 0 || len(private.Baseline) != len(activation.BaselineReceiptRefs) {
		t.Fatal("immutable baseline receipt population missing")
	}
	// The instrumented replacement must be constructed with the original
	// observer binding, not relabel a newly generated fixture after creation.
	health := workspaceRecoveredFixture(t, private.Baseline[0].Binding)
	base := recoveredObserverConfig{SchemaVersion: "1", Mode: "RESTORATION", DSN: private.ObserverDSN, Key: private.ObserverKey, Observer: observer, Workspace: runtime.Workspace, Binding: health.binding, TargetURL: health.url, CommandID: snapshot.Command.ID, AttemptID: model.ID()}
	partial := runRecoveredObserver(t, ctx, a, base, true)
	if partial.ExitCode != 73 || len(partial.Observations) != 1 {
		t.Fatal("actual partial observer restart not witnessed")
	}
	// Reopen actual authenticated pools before resolving the interrupted
	// attempt. No positive elapsed time or measurements cross attempt IDs.
	observerDB.Pool.Close()
	observerDB = open("group-health-observer", private.ObserverDSN)
	closeConfig := base
	closeConfig.Mode = "CLOSE"
	abandoned := runRecoveredObserver(t, ctx, a, closeConfig, false)
	if abandoned.Envelope.Outcome.Status != "ABANDONED" || len(abandoned.Envelope.Outcome.ObservationIDs) != 1 {
		t.Fatal("interrupted observer attempt not durably closed")
	}
	if e := release(); e == nil {
		t.Fatal("abandoned observation released ownership")
	}
	if e := ledger.Do(ctx, b.TenantID, func(tx *store.Tx) error {
		_, err := tx.GroupRecoveryHealthSelect(ctx, b.Bootstrap.ChainID, abandoned.Envelope.Outcome.ID)
		return err
	}); e == nil {
		t.Fatal("abandoned observation selected as healthy")
	}
	base.AttemptID = model.ID()
	base.PreviousOutcomeID = abandoned.Envelope.Outcome.ID
	completed := runRecoveredObserver(t, ctx, a, base, false)
	window := completed.Envelope.Outcome.Window
	if completed.Envelope.Outcome.Status != "OBSERVED" || completed.Attempt.PreviousOutcomeID != abandoned.Envelope.Outcome.ID || !completed.Attempt.StartedAt.After(partial.Attempt.StartedAt) || window.Start.Before(completed.Attempt.StartedAt) || window.RequiredEnd.Sub(window.Start) != 15*time.Minute || window.ObservedThrough.Before(window.RequiredEnd) || window.MonotonicDurationNS == nil || *window.MonotonicDurationNS < int64(15*time.Minute) {
		t.Fatal("fresh complete900-second recovery window absent")
	}
	h.refresh(t, ctx)
	if e := ledger.Do(ctx, b.TenantID, func(tx *store.Tx) error {
		_, err := tx.GroupRecoveryHealthSelect(ctx, b.Bootstrap.ChainID, completed.Envelope.Outcome.ID)
		return err
	}); e != nil {
		t.Fatal("current signed recovery outcome selection failed", e)
	}
	if e := release(); e != nil {
		t.Fatal("full recovery health did not release resolved obligation", e)
	}
	var released bool
	if e := ledger.Do(ctx, b.TenantID, func(tx *store.Tx) error {
		return tx.QueryRow(ctx, `SELECT released_at IS NOT NULL FROM public.fleet_group_journal_reservations WHERE tenant_id=$1 AND chain_id=$2`, tx.Tenant, b.Bootstrap.ChainID).Scan(&released)
	}); e != nil || !released {
		t.Fatal("durable recovery release missing")
	}
	var retained workspaceArtifactIndex
	indexRaw := workspaceRead("/results/reconstruction-artifact-index.json", 128<<10, &retained)
	if indexRaw == nil || g.BytesDigest(indexRaw) != original.ReconstructionArtifactIndexSHA256 {
		t.Fatal("original reconstruction ciphertext closure changed")
	}
	indexSHA := workspaceRetainIndex(t, "/results/recovery-health-artifact-index.json", runtime.RunID, append(append([]model.Document{}, retained.Artifacts...), a.metadata...))
	final := h.refresh(t, ctx)
	if final.Pending != nil || len(final.Stack) != 0 || len(final.Consumed) != 1 || final.Current.StateSHA256 != projection.Current.StateSHA256 {
		t.Fatal("health observation changed native ownership")
	}
	if finalAudit, err := native.TerraformInvocations(); err != nil || g.Digest(finalAudit) != g.Digest(priorAudit) {
		t.Fatal("health observation launched additional Terraform")
	}
	result := model.Document{"schema_version": "1", "status": "PASS", "run_id": runtime.RunID, "tenant_id": b.TenantID, "chain_id": b.Bootstrap.ChainID, "prepared_program_sha256": g.Digest(b.Prepared.Program), "original_reconstruction_sha256": g.BytesDigest(originalRaw), "health_activation_sha256": b.HealthActivationSHA256, "new_workspace": runtime.Workspace, "baseline_id": activation.Baseline.ID, "observer_id": observer.ID, "attempts": []recoveredHealthAttemptResult{recoveredAttemptResult(partial.Attempt, abandoned, partial.Observations), recoveredAttemptResult(completed.Attempt, completed, completed.Observations)}, "selected_outcome_id": completed.Envelope.Outcome.ID, "selected_outcome_sha256": g.Digest(completed.Envelope.Outcome), "final_head": h.view.Head.Head.Ref, "restored_state_sha256": final.Current.StateSHA256, "restored_owned_effects": 0, "consumed_owned_effects": 1, "pending": false, "reservation_released": true, "terminal_health_pending": false, "full_recovery_health_accepted": true, "financial_disqualified_forever": true, "recovery_health_artifact_index_sha256": indexSHA, "observer_restart_confirmed": true, "failed_attempt_elapsed_reused": false, "fixture": true, "customer_execution_authorized": false, "verified_saving": nil}
	raw, e := json.Marshal(result)
	if e != nil || len(raw) > 64<<10 {
		t.Fatal("bounded recovered health result exceeds contract")
	}
	if _, e = workspaceWrite("/results/workspace-recovered-health.json", result); e != nil {
		t.Fatal("recovered health result unavailable")
	}
}

func workspaceRecoveredFixture(t *testing.T, binding native.HealthBinding) *connectedHealth {
	t.Helper()
	h := &connectedHealth{binding: binding}
	fixture, e := native.NewHTTPHealthFixture(binding, func(ctx context.Context) error {
		timer := time.NewTimer(time.Second)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			return nil
		}
	}, 1, 0)
	if e != nil {
		t.Fatal(e)
	}
	server := httptest.NewServer(fixture)
	t.Cleanup(server.Close)
	h.url = server.URL
	return h
}
