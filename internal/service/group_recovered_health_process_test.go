package service

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	ff "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetfixture"
	g "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetgroup"
	native "github.com/christopherosiemo/bn-implementation-Finops/internal/groupfixtureproducer"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
)

// The observer's supplied configuration contains only its distinct commissioned
// login/key and a loopback HTTP installation. Environment filtering is tested.
// These processes still share one fixture container/UID and its private files;
// this rehearsal does not claim production OS-level credential isolation.
type recoveredObserverConfig struct {
	SchemaVersion     string                            `json:"schema_version"`
	Mode              string                            `json:"mode"`
	DSN               string                            `json:"dsn"`
	Key               ed25519.PrivateKey                `json:"key"`
	Observer          store.GroupRecoveryHealthObserver `json:"observer"`
	Workspace         native.NativeWorkspace            `json:"workspace"`
	Binding           native.HealthBinding              `json:"binding"`
	TargetURL         string                            `json:"target_url"`
	CommandID         string                            `json:"command_id"`
	AttemptID         string                            `json:"attempt_id"`
	PreviousOutcomeID string                            `json:"previous_outcome_id"`
}
type recoveredObserverDecision struct {
	Stop             bool                  `json:"stop"`
	Crash            bool                  `json:"crash"`
	OutcomeReference *ff.ArtifactReference `json:"outcome_reference"`
}
type recoveredObserverEvaluation struct {
	Envelope *store.GroupRecoveryHealthOutcomeEnvelope `json:"envelope"`
}
type recoveredObserverRun struct {
	Attempt          store.GroupRecoveryHealthAttempt
	Observations     []store.GroupRecoveryHealthObservationEnvelope
	Envelope         store.GroupRecoveryHealthOutcomeEnvelope
	OutcomeReference ff.ArtifactReference
	ExitCode         int
}

func recoveredObserverFile(directory, kind string, ordinal int) string {
	return filepath.Join(directory, fmt.Sprintf("%s-%03d.json", kind, ordinal))
}

func recoveredObserverEnvironment(file string) []string {
	return []string{"FLEET_GROUP_RECOVERY_OBSERVER_CONFIG=" + file, "GOMAXPROCS=1", "GOMEMLIMIT=192MiB", "HOME=/tmp", "TMPDIR=/tmp"}
}

// This is a fixed private subprocess entry, never a public health upload or
// sign-arbitrary-body interface. The child creates its own receipt and DB-time
// attempt. A supplied archive reference must match that exact measured body.
func TestGroupRecoveryHealthObserverProcess(t *testing.T) {
	file := os.Getenv("FLEET_GROUP_RECOVERY_OBSERVER_CONFIG")
	if file == "" {
		t.Skip("private observer subprocess only")
	}
	if os.Getuid() == 0 || filepath.Base(file) != "observer-config.json" || !strings.HasPrefix(filepath.Clean(filepath.Dir(file)), "/tmp/recovered-observer-") {
		t.Fatal("fixed private observer configuration required")
	}
	for _, key := range []string{"TEST_DATABASE_URL", "DATABASE_URL", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "DOCKER_HOST", "FLEET_CONNECTED_S3_SECRET"} {
		if os.Getenv(key) != "" {
			t.Fatal("observer inherited unrelated authority")
		}
	}
	var c recoveredObserverConfig
	if workspaceRead(file, 32<<10, &c) == nil || c.SchemaVersion != "1" || len(c.Key) != ed25519.PrivateKeySize || !ed25519.PublicKey(c.Key.Public().(ed25519.PublicKey)).Equal(c.Observer.PublicKey) || !workspaceUUID.MatchString(c.Observer.ID) || !strings.HasPrefix(c.Observer.ChainID, "connected-chain-") || !workspaceUUID.MatchString(strings.TrimPrefix(c.Observer.ChainID, "connected-chain-")) || !workspaceUUID.MatchString(c.Workspace.Generation) || c.CommandID == "" {
		t.Fatal("private observer configuration invalid")
	}
	if c.Mode != "BASELINE" && c.Mode != "RESTORATION" && c.Mode != "CLOSE" {
		t.Fatal("fixed observer mode required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Minute)
	defer cancel()
	db, e := store.OpenRuntime(ctx, c.DSN, "group-health-observer")
	if e != nil {
		t.Fatal("dedicated health observer identity unavailable")
	}
	defer db.Pool.Close()
	directory := filepath.Dir(file)
	write := func(kind string, n int, body any) {
		t.Helper()
		if _, e := workspaceWrite(recoveredObserverFile(directory, kind, n), body); e != nil {
			t.Fatal("durable observer handoff failed")
		}
	}
	wait := func(kind string, n int, out any) {
		t.Helper()
		for {
			if workspaceRead(recoveredObserverFile(directory, kind, n), 64<<10, out) != nil {
				return
			}
			select {
			case <-ctx.Done():
				t.Fatal("observer handoff deadline")
			case <-time.After(50 * time.Millisecond):
			}
		}
	}
	var attempt store.GroupRecoveryHealthAttempt
	if c.Mode == "RESTORATION" {
		if e = db.Do(ctx, c.Observer.TenantID, func(tx *store.Tx) error {
			var err error
			attempt, err = tx.GroupRecoveryHealthAttemptStart(ctx, c.Observer.ChainID, c.Observer.ID, c.Workspace.Generation, c.AttemptID, c.PreviousOutcomeID)
			return err
		}); e != nil {
			t.Fatal("actual observer attempt start failed", e)
		}
		if attempt.CommandID != c.CommandID || attempt.Workspace != c.Workspace {
			t.Fatal("observer attempt current binding differs")
		}
		write("attempt", 0, attempt)
	}
	finish := func(envelope store.GroupRecoveryHealthOutcomeEnvelope, n int) {
		write("evaluation", n, recoveredObserverEvaluation{&envelope})
		var decision recoveredObserverDecision
		wait("decision", n, &decision)
		if !decision.Stop || decision.Crash || decision.OutcomeReference == nil {
			t.Fatal("outcome archive decision invalid")
		}
		raw, _ := json.Marshal(envelope)
		ref := *decision.OutcomeReference
		if ref.SHA256 != g.BytesDigest(raw) || ref.SizeBytes != int64(len(raw)) {
			t.Fatal("outcome archive binding differs")
		}
		if e := db.Do(ctx, c.Observer.TenantID, func(tx *store.Tx) error {
			_, _, err := tx.GroupRecoveryHealthOutcomeAppend(ctx, c.Observer.Identity, envelope, ref)
			return err
		}); e != nil {
			t.Fatal("issued observer outcome failed", e)
		}
		write("done", 0, model.Document{"status": "PASS"})
	}
	if c.Mode == "CLOSE" {
		var body store.GroupRecoveryHealthOutcome
		if e = db.Do(ctx, c.Observer.TenantID, func(tx *store.Tx) error {
			var err error
			body, err = tx.GroupRecoveryHealthEvaluate(ctx, c.Observer.ChainID, c.AttemptID, model.ID(), "ABANDONED")
			return err
		}); e != nil {
			t.Fatal("abandoned observer attempt could not close", e)
		}
		envelope, e := store.SignGroupRecoveryHealthOutcome(body, c.Key)
		if e != nil {
			t.Fatal(e)
		}
		finish(envelope, 0)
		return
	}
	collector, e := native.NewHealthCollector(native.HealthInstallation{ID: model.ID(), Binding: c.Binding, TargetURL: c.TargetURL})
	if e != nil {
		t.Fatal("fixed loopback health installation invalid")
	}
	for n := 1; n <= 64; n++ {
		receipt, e := collector.Collect(ctx, 40, 1)
		if e != nil {
			t.Fatal("actual observer HTTP measurement failed")
		}
		write("receipt", n, receipt)
		var ref ff.ArtifactReference
		wait("reference", n, &ref)
		raw, _ := json.Marshal(receipt)
		if ref.SHA256 != g.BytesDigest(raw) || ref.SizeBytes != int64(len(raw)) {
			t.Fatal("receipt archive binding differs")
		}
		phase := "BASELINE"
		if c.Mode == "RESTORATION" {
			phase = "RESTORATION"
		}
		body := store.GroupRecoveryHealthObservation{SchemaVersion: "1", ID: model.ID(), TenantID: c.Observer.TenantID, ChainID: c.Observer.ChainID, ObserverID: c.Observer.ID, Workspace: c.Workspace, Phase: phase, AttemptID: c.AttemptID, CommandID: c.CommandID, Receipt: receipt, Reference: ref, SignedAt: time.Now().UTC()}
		envelope, e := store.SignGroupRecoveryHealthObservation(body, c.Key)
		if e != nil {
			t.Fatal(e)
		}
		if e = db.Do(ctx, c.Observer.TenantID, func(tx *store.Tx) error {
			_, _, err := tx.GroupRecoveryHealthObservationAppend(ctx, c.Observer.Identity, envelope)
			return err
		}); e != nil {
			t.Fatal("observer measured receipt rejected", e)
		}
		write("issued", n, envelope)
		var outcome *store.GroupRecoveryHealthOutcomeEnvelope
		if c.Mode == "RESTORATION" {
			var measured store.GroupRecoveryHealthOutcome
			e = db.Do(ctx, c.Observer.TenantID, func(tx *store.Tx) error {
				var err error
				measured, err = tx.GroupRecoveryHealthEvaluate(ctx, c.Observer.ChainID, c.AttemptID, model.ID(), "")
				return err
			})
			if e == nil {
				signed, err := store.SignGroupRecoveryHealthOutcome(measured, c.Key)
				if err != nil {
					t.Fatal(err)
				}
				outcome = &signed
			} else if !errors.Is(e, store.ErrGroupRecoveryHealth) {
				t.Fatal("observer outcome evaluation failed", e)
			}
		}
		write("evaluation", n, recoveredObserverEvaluation{outcome})
		var decision recoveredObserverDecision
		wait("decision", n, &decision)
		if decision.Crash {
			if !decision.Stop || c.Mode != "RESTORATION" || n != 1 || outcome != nil {
				t.Fatal("fixed observer crash boundary invalid")
			}
			os.Exit(73)
		}
		if decision.Stop {
			if outcome != nil {
				if decision.OutcomeReference == nil {
					t.Fatal("outcome archive unavailable")
				}
				raw, _ := json.Marshal(outcome)
				ref := *decision.OutcomeReference
				if ref.SHA256 != g.BytesDigest(raw) || ref.SizeBytes != int64(len(raw)) {
					t.Fatal("outcome archive differs")
				}
				if e = db.Do(ctx, c.Observer.TenantID, func(tx *store.Tx) error {
					_, _, err := tx.GroupRecoveryHealthOutcomeAppend(ctx, c.Observer.Identity, *outcome, ref)
					return err
				}); e != nil {
					t.Fatal("issued restoration outcome rejected", e)
				}
			} else if c.Mode != "BASELINE" {
				t.Fatal("restoration stopped without signed outcome")
			}
			write("done", 0, model.Document{"status": "PASS"})
			return
		}
		if outcome != nil {
			t.Fatal("terminal observer outcome discarded")
		}
	}
	t.Fatal("bounded observer receipt population exceeded")
}

// Coordinator archival is separate from the observer's measurement/signing.
// IPC and child diagnostics stay in private /tmp, outside hosted artifacts.
func runRecoveredObserver(t *testing.T, ctx context.Context, a *connectedStageArtifacts, c recoveredObserverConfig, partial bool) recoveredObserverRun {
	t.Helper()
	directory, e := os.MkdirTemp("/tmp", "recovered-observer-")
	if e != nil {
		t.Fatal(e)
	}
	if e = os.Chmod(directory, 0700); e != nil {
		t.Fatal(e)
	}
	if _, e = workspaceWrite(filepath.Join(directory, "observer-config.json"), c); e != nil {
		t.Fatal(e)
	}
	log, e := os.OpenFile(filepath.Join(directory, "child.log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		t.Fatal(e)
	}
	defer log.Close()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestGroupRecoveryHealthObserverProcess$", "-test.timeout=36m")
	command.Env = recoveredObserverEnvironment(filepath.Join(directory, "observer-config.json"))
	command.Stdout, command.Stderr = log, log
	if e = command.Start(); e != nil {
		t.Fatal("private observer process unavailable")
	}
	finished := make(chan error, 1)
	go func() { finished <- command.Wait() }()
	joined := false
	var processErr error
	t.Cleanup(func() {
		if !joined {
			_ = command.Process.Kill()
			<-finished
		}
		if t.Failed() {
			// Docker logs are retained privately by the fixed host runner. No
			// child output is copied into acceptance/failure receipts or CI.
			if f, err := os.Open(filepath.Join(directory, "child.log")); err == nil {
				defer f.Close()
				raw, err := io.ReadAll(io.LimitReader(f, 64<<10))
				if err == nil {
					t.Logf("private observer subprocess diagnostics:\n%s", raw)
				}
			}
		}
	})
	lastRefresh := time.Now()
	wait := func(kind string, n int, out any) {
		t.Helper()
		for {
			if workspaceRead(recoveredObserverFile(directory, kind, n), 64<<10, out) != nil {
				return
			}
			if joined {
				t.Fatalf("observer ended without private %s handoff: %v", kind, processErr)
			}
			select {
			case err := <-finished:
				joined = true
				processErr = err
				// The child can durably publish its final handoff and exit
				// between our file probe and select. Check the committed file
				// once after Wait before treating exit as missing evidence.
				if workspaceRead(recoveredObserverFile(directory, kind, n), 64<<10, out) != nil {
					return
				}
				t.Fatalf("observer exited before private %s handoff: %v", kind, err)
			case <-ctx.Done():
				t.Fatal("observer coordinator deadline")
			case <-time.After(100 * time.Millisecond):
			}
			if time.Since(lastRefresh) > 5*time.Second {
				a.h.refresh(t, ctx)
				lastRefresh = time.Now()
			}
		}
	}
	decision := func(n int, d recoveredObserverDecision) {
		t.Helper()
		if _, e := workspaceWrite(recoveredObserverFile(directory, "decision", n), d); e != nil {
			t.Fatal("private observer decision unavailable")
		}
	}
	var result recoveredObserverRun
	if c.Mode == "RESTORATION" {
		wait("attempt", 0, &result.Attempt)
	}
	if c.Mode == "CLOSE" {
		var evaluated recoveredObserverEvaluation
		wait("evaluation", 0, &evaluated)
		if evaluated.Envelope == nil || evaluated.Envelope.Outcome.Status != "ABANDONED" {
			t.Fatal("observer abandonment not authenticated")
		}
		result.Envelope = *evaluated.Envelope
		result.OutcomeReference = a.put(t, ctx, c.CommandID, "HEALTH_VERDICT", result.Envelope)
		decision(0, recoveredObserverDecision{Stop: true, OutcomeReference: &result.OutcomeReference})
	} else {
		for n := 1; n <= 64; n++ {
			var receipt native.HealthReceipt
			wait("receipt", n, &receipt)
			kind := "HEALTH_RECEIPT"
			if c.Mode == "BASELINE" {
				kind = "HEALTH_BASELINE"
			}
			ref := a.put(t, ctx, c.CommandID, kind, receipt)
			if _, e = workspaceWrite(recoveredObserverFile(directory, "reference", n), ref); e != nil {
				t.Fatal("private exact archive ref unavailable")
			}
			var observed store.GroupRecoveryHealthObservationEnvelope
			wait("issued", n, &observed)
			if observed.Observation.Receipt.SHA256 != receipt.SHA256 || observed.Observation.Reference != ref || observed.Observation.ObserverID != c.Observer.ID {
				t.Fatal("issued observer measured binding differs")
			}
			result.Observations = append(result.Observations, observed)
			var evaluated recoveredObserverEvaluation
			wait("evaluation", n, &evaluated)
			d := recoveredObserverDecision{}
			if partial {
				if n != 1 || evaluated.Envelope != nil {
					t.Fatal("fixed partial restart boundary differed")
				}
				d.Stop, d.Crash = true, true
			}
			if c.Mode == "BASELINE" {
				var mono int64
				for _, v := range result.Observations {
					if v.Observation.Receipt.Clock == nil {
						t.Fatal("baseline monotonic evidence absent")
					}
					mono += v.Observation.Receipt.Clock.ElapsedNS
				}
				d.Stop = receipt.After.CapturedAt.Sub(result.Observations[0].Observation.Receipt.Before.CapturedAt) >= 2*time.Minute && mono >= int64(2*time.Minute)
			} else if evaluated.Envelope != nil {
				result.Envelope = *evaluated.Envelope
				result.OutcomeReference = a.put(t, ctx, c.CommandID, "HEALTH_VERDICT", result.Envelope)
				d.Stop = true
				d.OutcomeReference = &result.OutcomeReference
			}
			decision(n, d)
			if d.Stop {
				break
			}
		}
	}
	if !partial {
		var done model.Document
		wait("done", 0, &done)
		if model.String(done, "status") != "PASS" {
			t.Fatal("observer completion missing")
		}
	}
	if !joined {
		processErr = <-finished
		joined = true
	}
	result.ExitCode = command.ProcessState.ExitCode()
	if partial {
		if processErr == nil || result.ExitCode != 73 {
			t.Fatal("observer process loss was not witnessed")
		}
	} else if processErr != nil {
		t.Fatal("observer process failed after issued facts", processErr)
	}
	return result
}
