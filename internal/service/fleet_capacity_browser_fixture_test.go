package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/auth"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/fleetbilling"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/coreos/go-oidc/v3/oidc"
)

const fleetCapacityBrowserSubject = "52a55d35-21b6-4a32-9dcb-fda96b34552e"

type fleetCapacityBrowserReady struct {
	SchemaVersion               string `json:"schema_version"`
	RunID                       string `json:"run_id"`
	TenantID                    string `json:"tenant_id"`
	WorkloadID                  string `json:"workload_id"`
	OperatorSubject             string `json:"operator_subject"`
	Username                    string `json:"username"`
	OldProposalID               string `json:"old_proposal_id"`
	CandidateProposalID         string `json:"candidate_proposal_id"`
	SafetyProfileVersion        int64  `json:"safety_profile_version"`
	FirstBatchID                string `json:"first_batch_id"`
	MemoryInstanceID            string `json:"memory_instance_id"`
	CandidateTemplateVersion    string `json:"candidate_template_version"`
	Fixture                     bool   `json:"fixture"`
	CustomerExecutionAuthorized bool   `json:"customer_execution_authorized"`
}
type fleetCapacityBrowserSignal struct {
	SchemaVersion string `json:"schema_version"`
	RunID         string `json:"run_id"`
	ReadySHA256   string `json:"ready_sha256"`
}
type fleetCapacityBrowserProof struct {
	SchemaVersion               string  `json:"schema_version"`
	Status                      string  `json:"status"`
	RunID                       string  `json:"run_id"`
	ReadySHA256                 string  `json:"ready_sha256"`
	TenantID                    string  `json:"tenant_id"`
	WorkloadID                  string  `json:"workload_id"`
	RequestID                   string  `json:"request_id"`
	MemberID                    string  `json:"member_id"`
	MemberSHA256                string  `json:"member_sha256"`
	ScopeSHA256                 string  `json:"scope_sha256"`
	CandidateTemplateVersion    string  `json:"candidate_template_version"`
	ModelVersion                string  `json:"model_version"`
	BrowserVersion              string  `json:"browser_version"`
	OIDCPKCE                    bool    `json:"oidc_pkce"`
	OIDCAuthorizationCode       bool    `json:"oidc_authorization_code"`
	UIIDsOnlyRequest            bool    `json:"ui_ids_only_request"`
	ActualWorkerResult          bool    `json:"actual_worker_result"`
	Memory95Rejected            bool    `json:"memory95_rejected"`
	LazyMemberDetail            bool    `json:"lazy_member_detail"`
	PersistedReload             bool    `json:"persisted_reload"`
	FixtureLabelsVisible        bool    `json:"fixture_labels_visible"`
	Fixture                     bool    `json:"fixture"`
	CustomerExecutionAuthorized bool    `json:"customer_execution_authorized"`
	VerifiedSaving              *string `json:"verified_saving"`
}

func fleetCapacityBrowserRead(path string, out any) error {
	info, e := os.Lstat(path)
	if e != nil {
		return e
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() < 1 || info.Size() > 8192 {
		return errors.New("browser fixture file shape differs")
	}
	f, e := os.Open(path)
	if e != nil {
		return e
	}
	defer f.Close()
	opened, e := f.Stat()
	if e != nil || !os.SameFile(info, opened) {
		return errors.New("browser fixture file identity differs")
	}
	raw, e := io.ReadAll(io.LimitReader(f, 8193))
	if e != nil || int64(len(raw)) != info.Size() {
		return errors.New("browser fixture file read differs")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil || d.Decode(new(any)) != io.EOF {
		return errors.New("browser fixture wire shape differs")
	}
	return nil
}

func TestFleetCapacityBrowserSignalBoundsAndStrictShape(t *testing.T) {
	dir := t.TempDir()
	signal := fleetCapacityBrowserSignal{SchemaVersion: "1", RunID: model.ID(), ReadySHA256: strings.Repeat("a", 64)}
	p := filepath.Join(dir, "valid.json")
	if _, e := fleetCapacityBrowserWrite(p, signal); e != nil {
		t.Fatal(e)
	}
	var read fleetCapacityBrowserSignal
	if e := fleetCapacityBrowserRead(p, &read); e != nil || read != signal {
		t.Fatal("exact private signal roundtrip", e)
	}
	if _, e := fleetCapacityBrowserWrite(p, signal); !errors.Is(e, os.ErrExist) {
		t.Fatal("fixture signal overwrite allowed", e)
	}
	for _, raw := range []string{`{"schema_version":"1","run_id":"r","ready_sha256":"h","authority":true}`, `{"schema_version":"1"} {"run_id":"r"}`, strings.Repeat(" ", 8193)} {
		name := filepath.Join(dir, model.ID()+".json")
		if e := os.WriteFile(name, []byte(raw), 0600); e != nil {
			t.Fatal(e)
		}
		if e := fleetCapacityBrowserRead(name, &read); e == nil {
			t.Fatal("malformed or unbounded private signal accepted")
		}
	}
	if e := fleetCapacityBrowserRead(dir, &read); e == nil {
		t.Fatal("directory accepted as fixture signal")
	}
}
func fleetCapacityBrowserWrite(path string, v any) ([]byte, error) {
	raw, e := json.Marshal(v)
	if e != nil || len(raw) > 8191 {
		return nil, errors.New("browser fixture output bound differs")
	}
	raw = append(raw, '\n')
	if _, e := os.Lstat(path); e == nil {
		return nil, os.ErrExist
	} else if !errors.Is(e, os.ErrNotExist) {
		return nil, e
	}
	// Each fixed signal has one private producer. Publish a completed file so
	// the host/browser cannot observe a partial JSON body during startup.
	f, e := os.CreateTemp(filepath.Dir(path), ".capacity-browser-*")
	if e != nil {
		return nil, e
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	_, e = f.Write(raw)
	if e == nil {
		e = f.Sync()
	}
	closed := f.Close()
	if e != nil {
		return nil, e
	}
	if closed != nil {
		return nil, closed
	}
	if _, e := os.Lstat(path); e == nil {
		return nil, os.ErrExist
	} else if !errors.Is(e, os.ErrNotExist) {
		return nil, e
	}
	if e = os.Rename(tmp, path); e != nil {
		return nil, e
	}
	return raw, nil
}
func fleetCapacityBrowserWait(ctx context.Context, name string, out any) error {
	tick := time.NewTicker(200 * time.Millisecond)
	defer tick.Stop()
	for {
		if e := ctx.Err(); e != nil {
			return e
		}
		e := fleetCapacityBrowserRead("/results/"+name, out)
		if e == nil {
			return nil
		}
		if !errors.Is(e, os.ErrNotExist) {
			return e
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		}
	}
}

func fleetCapacityBrowserJourneyContext(parent context.Context, started, expected fleetCapacityBrowserSignal) (context.Context, context.CancelFunc, error) {
	if parent.Err() != nil || started != expected || expected.SchemaVersion != "1" || !regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`).MatchString(expected.RunID) || !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(expected.ReadySHA256) {
		return nil, nil, errors.New("browser journey startup binding differs")
	}
	journeyCtx, cancelJourney := context.WithTimeout(parent, 180*time.Second)
	return journeyCtx, cancelJourney, nil
}

func TestFleetCapacityBrowserJourneyBudgetStartsAfterBoundStartup(t *testing.T) {
	parent, cancelParent := context.WithCancel(context.Background())
	defer cancelParent()
	// A nearly consumed setup deadline is represented without a real wait.
	setupCtx, cancelSetup := context.WithTimeout(parent, time.Second)
	signal := fleetCapacityBrowserSignal{SchemaVersion: "1", RunID: model.ID(), ReadySHA256: strings.Repeat("a", 64)}
	startedAt := time.Now()
	journeyCtx, cancelJourney, e := fleetCapacityBrowserJourneyContext(parent, signal, signal)
	if e != nil {
		t.Fatal(e)
	}
	defer cancelJourney()
	cancelSetup()
	deadline, bounded := journeyCtx.Deadline()
	if !errors.Is(setupCtx.Err(), context.Canceled) || !bounded || journeyCtx.Err() != nil || deadline.Before(startedAt.Add(180*time.Second)) || deadline.After(time.Now().Add(180*time.Second)) {
		t.Fatal("journey inherited consumed setup time or changed its fixed budget")
	}
	for _, changed := range []fleetCapacityBrowserSignal{
		{SchemaVersion: "1", RunID: model.ID(), ReadySHA256: signal.ReadySHA256},
		{SchemaVersion: "1", RunID: signal.RunID, ReadySHA256: strings.Repeat("b", 64)},
		{},
	} {
		if c, stop, e := fleetCapacityBrowserJourneyContext(parent, changed, signal); e == nil || c != nil || stop != nil {
			t.Fatal("unbound startup allocated a journey context")
		}
	}
	cancelParent()
	if c, stop, e := fleetCapacityBrowserJourneyContext(parent, signal, signal); e == nil || c != nil || stop != nil {
		t.Fatal("expired parent created a fresh journey budget")
	}
	if e := fleetCapacityBrowserWait(parent, "browser-start.json", new(fleetCapacityBrowserSignal)); !errors.Is(e, context.Canceled) {
		t.Fatal("expired phase accepted or waited for a fixture signal", e)
	}
}

// This optional phase is enabled only by the private lab, whose acceptance
// requires its browser receipt. It exposes the production API and App, never a
// presentation route or a trusted-evidence upload. No main database is opened.
func fleetCapacityPositiveBrowserPhase(t *testing.T, ctx context.Context, f *mutationReplayFixture, admin *store.Store, proposals []string, firstBatchID, memoryInstanceID string, refreshNative func(context.Context)) *fleetCapacityBrowserProof {
	t.Helper()
	mode := os.Getenv("FLEET_CAPACITY_BROWSER")
	if mode == "" {
		return nil
	}
	if mode != "ISOLATED_REAL_OIDC" || os.Getenv("FLEET_NATIVE_CAPACITY_LAB") != "ISOLATED_REAL_SERVICES_SYNTHETIC_HISTORY" || refreshNative == nil || len(proposals) != 2 || !f.api.Config.Fixture || !strings.HasPrefix(admin.Pool.Config().ConnConfig.Database, "fixture_http_") {
		t.Fatal("private browser fixture boundary differs")
	}
	runID := os.Getenv("FLEET_CAPACITY_BROWSER_RUN_ID")
	if !regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`).MatchString(runID) {
		t.Fatal("private browser run identity invalid")
	}
	// Setup includes real fresh identity-provider startup. Its budget ends at
	// the exact browser-start handshake; it is not the UI/model journey clock.
	setupCtx, cancelSetup := context.WithTimeout(ctx, 180*time.Second)
	defer cancelSetup()
	// The complete production dashboard uses readiness/dependency/SLO schemas.
	// Apply only the existing001..036 prefix to this owned child database.
	dir := t.TempDir()
	entries, e := os.ReadDir("../../migrations")
	if e != nil {
		t.Fatal(e)
	}
	count := 0
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !regexp.MustCompile(`^(00[1-9]|0[12][0-9]|03[0-6])_[a-z0-9_]+\.sql$`).MatchString(name) {
			continue
		}
		raw, e := os.ReadFile(filepath.Join("../../migrations", name))
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join(dir, name), raw, 0600); e != nil {
			t.Fatal(e)
		}
		count++
	}
	if count != 36 {
		t.Fatal("full browser schema prefix differs", count)
	}
	if e = admin.Migrate(setupCtx, dir); e != nil {
		t.Fatal("owned browser schema", e)
	}
	var first model.Document
	var profileVersion int64
	e = f.roles["api"].Do(setupCtx, f.tenant, func(tx *store.Tx) error {
		org, e := tx.Get(setupCtx, "org", f.tenant)
		if e != nil || !model.Bool(org, "fixture") {
			return errors.New("persisted browser fixture realm differs")
		}
		workload, e := tx.Get(setupCtx, "workloads", "fixture-workload")
		if e != nil || model.String(workload, "owner") != "assigned-owner" {
			return errors.New("browser fixture workload assignment differs")
		}
		workload["owner"] = fleetCapacityBrowserSubject
		if _, e = tx.Update(setupCtx, "workloads", "fixture-workload", model.Number(workload, "version"), workload); e != nil {
			return e
		}
		profile, e := tx.WorkloadSafetyLatest(setupCtx, "fixture-workload")
		if e != nil {
			return e
		}
		profileVersion = model.Number(profile, "version")
		first, e = tx.FleetCapacityBatchGet(setupCtx, firstBatchID)
		return e
	})
	if e != nil {
		t.Fatal(e)
	}
	scope := sourceDocument(first["scope"])
	candidate := sourceDocument(scope["candidate_template"])
	defer func() {
		c, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		e := f.roles["api"].Do(c, f.tenant, func(tx *store.Tx) error {
			w, e := tx.Get(c, "workloads", "fixture-workload")
			if e != nil {
				return e
			}
			if model.String(w, "owner") != fleetCapacityBrowserSubject {
				return errors.New("private browser fixture owner unexpectedly changed")
			}
			w["owner"] = "assigned-owner"
			_, e = tx.Update(c, "workloads", "fixture-workload", model.Number(w, "version"), w)
			return e
		})
		if e != nil {
			t.Error("private browser fixture owner cleanup", e)
		}
	}()
	ready := fleetCapacityBrowserReady{SchemaVersion: "1", RunID: runID, TenantID: f.tenant, WorkloadID: "fixture-workload", OperatorSubject: fleetCapacityBrowserSubject, Username: "capacity-owner", OldProposalID: proposals[0], CandidateProposalID: proposals[1], SafetyProfileVersion: profileVersion, FirstBatchID: firstBatchID, MemoryInstanceID: memoryInstanceID, CandidateTemplateVersion: model.String(candidate, "version"), Fixture: true}
	if ready.CandidateTemplateVersion == "" || model.String(first, "status") != "ASSESSED" {
		t.Fatal("calculated native baseline unavailable for browser")
	}
	// The remote-keyset lifetime follows the enclosing fixture, not setup's
	// expired clock. Each actual HTTP fetch still has an independent 30s cap.
	validatorCtx := oidc.ClientContext(ctx, &http.Client{Timeout: 30 * time.Second})
	validator, e := auth.New(validatorCtx, "http://localhost:8081/realms/finops", "finops", "http://browser-web:8081/realms/finops/protocol/openid-connect/certs")
	if e != nil {
		t.Fatal(e)
	}
	listener, e := net.Listen("tcp", "0.0.0.0:8097")
	if e != nil {
		t.Fatal("private browser API listener", e)
	}
	api := &API{Store: f.api.Store, Auth: validator, Config: Config{Fixture: true}}
	server := &http.Server{Handler: api, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	defer func() {
		c, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		_ = server.Shutdown(c)
		if e := <-done; e != nil && !errors.Is(e, http.ErrServerClosed) {
			t.Error("private browser API termination", e)
		}
	}()
	raw, e := fleetCapacityBrowserWrite("/results/browser-ready.json", ready)
	if e != nil {
		t.Fatal(e)
	}
	signal := fleetCapacityBrowserSignal{SchemaVersion: "1", RunID: runID, ReadySHA256: fleetbilling.BytesHash(raw)}
	var started fleetCapacityBrowserSignal
	if e = fleetCapacityBrowserWait(setupCtx, "browser-start.json", &started); e != nil || setupCtx.Err() != nil {
		t.Fatal("actual browser/identity startup handshake", e)
	}
	journeyCtx, cancelJourney, e := fleetCapacityBrowserJourneyContext(ctx, started, signal)
	if e != nil {
		t.Fatal("actual browser/identity startup handshake", e)
	}
	defer cancelJourney()
	// Start the unchanged 180s journey budget before real native recapture,
	// actual UI/model work, durable readback and final worker exclusion.
	refreshNative(journeyCtx)
	if e = journeyCtx.Err(); e != nil {
		t.Fatal("actual browser native refresh exceeded journey budget", e)
	}
	if _, e = fleetCapacityBrowserWrite("/results/browser-api-ready.json", signal); e != nil {
		t.Fatal(e)
	}
	var proof fleetCapacityBrowserProof
	if e = fleetCapacityBrowserWait(journeyCtx, "browser-result.json", &proof); e != nil {
		t.Fatal("actual browser outcome absent", e)
	}
	if proof.SchemaVersion != "1" || proof.Status != "PASS" || proof.RunID != runID || proof.ReadySHA256 != signal.ReadySHA256 || proof.TenantID != f.tenant || proof.WorkloadID != ready.WorkloadID || proof.RequestID == firstBatchID || !proof.OIDCPKCE || !proof.OIDCAuthorizationCode || !proof.UIIDsOnlyRequest || !proof.ActualWorkerResult || !proof.Memory95Rejected || !proof.LazyMemberDetail || !proof.PersistedReload || !proof.FixtureLabelsVisible || !proof.Fixture || proof.CustomerExecutionAuthorized || proof.VerifiedSaving != nil || proof.ModelVersion != "capacity-weekday-block-v2" || proof.CandidateTemplateVersion != ready.CandidateTemplateVersion {
		t.Fatal("actual browser proof binding differs")
	}
	// The signed-in browser cannot replace the issuer's durable evidence with
	// a success flag. Resolve its exact newly created immutable rows again.
	e = f.roles["api"].Do(journeyCtx, f.tenant, func(tx *store.Tx) error {
		request, e := tx.FleetCapacityBatchGet(journeyCtx, proof.RequestID)
		if e != nil {
			return e
		}
		if model.String(request, "creator_id") != fleetCapacityBrowserSubject || model.String(request, "status") != "ASSESSED" {
			return errors.New("browser did not create a scoped calculated request")
		}
		d, e := tx.FleetCapacityBatchMemberGet(journeyCtx, proof.MemberID)
		if e != nil {
			return e
		}
		member := sourceDocument(d["member"])
		reasons := model.Strings(member, "reason_codes")
		sort.Strings(reasons)
		at := sort.SearchStrings(reasons, "MEMORY_P95_PLANNING_LIMIT")
		if model.String(d, "request_id") != proof.RequestID || model.String(d, "sha256") != proof.MemberSHA256 || model.String(member, "instance_id") != memoryInstanceID || !model.Bool(member, "model_evaluated") || member["capacity_suitable"] != false || at == len(reasons) || reasons[at] != "MEMORY_P95_PLANNING_LIMIT" || model.String(sourceDocument(member["scope"]), "snapshot_sha256") != proof.ScopeSHA256 || model.Bool(member, "execution_authorized") || member["verified_saving"] != nil || member["estimated_saving"] != nil {
			return errors.New("browser outcome differs from actual native calculated row")
		}
		still, e := tx.FleetCapacityBatchGet(journeyCtx, firstBatchID)
		if e == nil && fleetbilling.Hash(still) != fleetbilling.Hash(first) {
			return errors.New("browser rewrote prior native evidence")
		}
		return e
	})
	if e != nil {
		t.Fatal(e)
	}
	// The host removes the separately owned browser worker before later fixture
	// requests may run. A browser PASS does not itself prove worker exclusion.
	var workerComplete fleetCapacityBrowserSignal
	if e = fleetCapacityBrowserWait(journeyCtx, "browser-worker-complete.json", &workerComplete); e != nil || workerComplete != signal {
		t.Fatal("browser worker exclusion before later fixture jobs is unproved", e)
	}
	return &proof
}
