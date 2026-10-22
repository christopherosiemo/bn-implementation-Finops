package groupfixtureproducer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	g "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetgroup"
)

func healthBinding() HealthBinding {
	p := archiveSelection()
	return HealthBinding{Binding: p.Binding, Realm: p.Realm, ProgramSHA256: g.BytesDigest([]byte("actual fixture program")), CommandID: "command-canary", OperationID: "operation-canary", Fence: 1}
}
func healthLimits() HealthLimits {
	return HealthLimits{MinimumSamples: 30, MaxP95NS: int64(time.Second), MaxP99NS: int64(time.Second), MaxErrorRatePPM: 0, MinAvailabilityPPM: 1000000, MaxInFlight: 4, MaxBacklog: 0}
}
func hasHealthReason(result HealthWindow, code string) bool {
	for _, c := range result.ReasonCodes {
		if c == code {
			return true
		}
	}
	return false
}

func TestHealthActualHTTPRegressionIsEarlyBreachNotFullWindow(t *testing.T) {
	binding := healthBinding()
	var delay atomic.Int64
	delay.Store(int64(30 * time.Millisecond))
	fixture, err := NewHTTPHealthFixture(binding, func(ctx context.Context) error {
		timer := time.NewTimer(time.Duration(delay.Load()))
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			return nil
		}
	}, 4, 0)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(fixture)
	defer server.Close()
	collector, err := NewHealthCollector(HealthInstallation{ID: "installed-health", Binding: binding, TargetURL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	baseline, err := collector.Collect(t.Context(), 40, 1)
	if err != nil {
		t.Fatal(err)
	}
	basePopulation, err := population([]HealthReceipt{baseline}, binding, true)
	if err != nil || !basePopulation.complete || len(basePopulation.latencies) != 40 {
		t.Fatalf("baseline coverage unavailable before fault: samples=%d beforeInflight=%d afterInflight=%d valid=%v complete=%v", len(basePopulation.latencies), baseline.Before.InFlight, baseline.After.InFlight, err == nil, basePopulation.complete)
	}
	measuredBaselineP95 := *healthQuantile(basePopulation.latencies, 95)
	// Freeze the measured native baseline, then inject an actual timer delay
	// at least35% above that observed p95. Scheduling and HTTP overhead remain
	// in both populations; no latency sample or decision threshold is replaced.
	faultDelay := (measuredBaselineP95*135 + 99) / 100
	delay.Store(faultDelay)
	current, err := collector.Collect(t.Context(), 40, 1)
	if err != nil {
		t.Fatal(err)
	}
	currentPopulation, err := population([]HealthReceipt{current}, binding, false)
	if err != nil || !currentPopulation.complete || len(currentPopulation.latencies) != 40 {
		t.Fatalf("current coverage unavailable: samples=%d beforeInflight=%d afterInflight=%d valid=%v complete=%v", len(currentPopulation.latencies), current.Before.InFlight, current.After.InFlight, err == nil, currentPopulation.complete)
	}
	result := EvaluateHealthWindow(binding, g.DefaultStages(20)[1], current.Before.CapturedAt, []HealthReceipt{baseline}, []HealthReceipt{current}, healthLimits(), time.Now().UTC())
	if result.Status != "BREACH" || !hasHealthReason(result, "LATENCY_REGRESSION_ABOVE_15_PERCENT") || !hasHealthReason(result, "STAGE_OBSERVATION_WINDOW_INCOMPLETE") || hasHealthReason(result, "HARD_LATENCY_BREACH") {
		t.Fatalf("unexpected native regression verdict: %+v", result)
	}
	if result.Completed == nil || *result.Completed != 40 || result.Accepted == nil || *result.Accepted != 40 || result.P95NS == nil || *result.P95NS < faultDelay || result.CustomerExecutionAuthorized || !result.RequiredEnd.Equal(current.Before.CapturedAt.Add(time.Hour)) {
		t.Fatalf("lost observed facts/window boundary: %+v", result)
	}
	if baseline.After.Completed != 40 || current.After.Completed != 80 || current.PreviousSHA256 != baseline.SHA256 || current.Sequence != 2 || current.Before != baseline.After {
		t.Fatal("server facts or append chain lost")
	}
	// A successful short HTTP batch does not earn a15minute terminal window.
	stable := EvaluateHealthWindow(binding, g.DefaultStages(20)[5], current.Before.CapturedAt, []HealthReceipt{current}, []HealthReceipt{current}, healthLimits(), time.Now().UTC())
	if stable.Status == "OBSERVED" {
		t.Fatal("short batch became complete health")
	}
}

func TestHealthActualFailureAndSaturationCounters(t *testing.T) {
	binding := healthBinding()
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	fixture, err := NewHTTPHealthFixture(binding, func(context.Context) error {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-release
		return errors.New("fixture work failed")
	}, 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(fixture)
	defer server.Close()
	done := make(chan *http.Response, 1)
	go func() { res, _ := http.Post(server.URL+"/work", "application/json", nil); done <- res }()
	<-entered
	res, err := http.Post(server.URL+"/work", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if res.StatusCode != 429 {
		t.Fatal("saturation not rejected")
	}
	close(release)
	first := <-done
	if first == nil || first.StatusCode != 503 {
		t.Fatal("failed work not503")
	}
	_ = first.Body.Close()
	s := fixture.snapshot()
	if s.Accepted != 1 || s.Completed != 0 || s.Rejected != 1 || s.Failed != 1 || s.Backlog != 0 || s.InFlight != 0 || s.PeakInFlight != 1 {
		t.Fatalf("incorrect actual work counters: %+v", s)
	}
}

func TestHealthActualIntervalPeaksResetAndUnexpectedReaderFailsClosed(t *testing.T) {
	b := healthBinding()
	f, _ := NewHTTPHealthFixture(b, func(context.Context) error { time.Sleep(2 * time.Millisecond); return nil }, 4, 0)
	server := httptest.NewServer(f)
	defer server.Close()
	c, _ := NewHealthCollector(HealthInstallation{ID: "installed-peak-test", Binding: b, TargetURL: server.URL})
	first, err := c.Collect(t.Context(), 40, 2)
	if err != nil {
		t.Fatal(err)
	}
	if first.After.PeakInFlight != 2 {
		t.Fatalf("actual concurrency peak absent: %d", first.After.PeakInFlight)
	}
	second, err := c.Collect(t.Context(), 40, 1)
	if err != nil {
		t.Fatal(err)
	}
	if second.After.PeakInFlight != 1 || second.After.PeakSinceSequence != second.Before.Sequence {
		t.Fatalf("lifetime peak poisoned later interval: %+v", second.After)
	}
	limits := healthLimits()
	limits.MaxInFlight = 1
	result := EvaluateHealthWindow(b, g.DefaultStages(20)[5], second.Before.CapturedAt, []HealthReceipt{first}, []HealthReceipt{second}, limits, time.Now().UTC())
	if hasHealthReason(result, "HARD_SATURATION_BREACH") {
		t.Fatal("fresh healthy interval inherited historical peak")
	}
	_ = f.snapshot() // A second reader cannot silently discard an interval peak.
	third, err := c.Collect(t.Context(), 40, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = population([]HealthReceipt{third}, b, false); err == nil {
		t.Fatal("unproven interval reset accepted")
	}
}

func TestHealthCollectorPinsTargetBindingAndNoRedirects(t *testing.T) {
	b := healthBinding()
	for _, target := range []string{"https://example.test", "http://127.0.0.1:80/path", "http://localhost:80", "http://169.254.169.254:80", "http://user:pass@127.0.0.1:80", "http://127.0.0.1:80?secret=x"} {
		if _, err := NewHealthCollector(HealthInstallation{ID: "installed", Binding: b, TargetURL: target}); err == nil {
			t.Fatalf("unsafe target accepted %s", target)
		}
	}
	var reached atomic.Bool
	destination := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached.Store(true) }))
	defer destination.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, destination.URL, http.StatusFound) }))
	defer redirect.Close()
	c, err := NewHealthCollector(HealthInstallation{ID: "installed", Binding: b, TargetURL: redirect.URL})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.Collect(t.Context(), 1, 1); err == nil || reached.Load() {
		t.Fatal("redirect followed or accepted")
	}
	wrong := b
	wrong.OperationID = "another-operation"
	f, _ := NewHTTPHealthFixture(wrong, func(context.Context) error { return nil }, 1, 0)
	server := httptest.NewServer(f)
	defer server.Close()
	c, _ = NewHealthCollector(HealthInstallation{ID: "installed", Binding: b, TargetURL: server.URL})
	if _, err = c.Collect(t.Context(), 1, 1); err == nil {
		t.Fatal("cross-operation heartbeat accepted")
	}
}

// Synthetic receipts below exercise evaluator algebra only; they do not
// constitute elapsed native-time, archive readback, or commissioned authority.
func syntheticHealthReceipt(b HealthBinding, start time.Time, duration time.Duration, latency time.Duration, sequence uint64, previous string, base uint64) HealthReceipt {
	end := start.Add(duration)
	before := HealthSnapshot{InstanceID: "fixture-instance", BindingSHA256: g.Digest(b), Definition: HealthCompletedOperation, CapturedAt: start, Sequence: sequence * 2, Accepted: base, Completed: base, Heartbeat: true}
	after := before
	after.CapturedAt = end
	after.Sequence++
	after.PeakSinceSequence = before.Sequence
	after.Accepted += 40
	after.Completed += 40
	after.PeakInFlight = 1
	observations := make([]HealthObservation, 40)
	for i := range observations {
		at := start.Add(time.Duration(i) * duration / 40)
		observations[i] = HealthObservation{StartedAt: at, FinishedAt: at.Add(latency), ElapsedNS: int64(latency), StatusCode: 200}
	}
	r := HealthReceipt{SchemaVersion: "1", InstallationID: "synthetic-unit-fixture", Binding: b, Sequence: sequence, PreviousSHA256: previous, Before: before, After: after, Observations: observations}
	r.SHA256 = HealthReceiptSHA256(r)
	return r
}

func TestHealthFullWindowCoverageHardLimitsAndUnknowns(t *testing.T) {
	b := healthBinding()
	start := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	baseline := []HealthReceipt{syntheticHealthReceipt(b, start.Add(-2*time.Minute), time.Minute, 10*time.Millisecond, 1, "", 0)}
	second := syntheticHealthReceipt(b, start.Add(-time.Minute), time.Minute, 10*time.Millisecond, 2, baseline[0].SHA256, 40)
	second.Before = baseline[0].After
	second.After.PeakSinceSequence = second.Before.Sequence
	second.SHA256 = HealthReceiptSHA256(second)
	baseline = append(baseline, second)
	current := []HealthReceipt{}
	for i := 0; i < 15; i++ {
		previous := ""
		if i > 0 {
			previous = current[i-1].SHA256
		}
		r := syntheticHealthReceipt(b, start.Add(time.Duration(i)*time.Minute), time.Minute, 10*time.Millisecond, uint64(i+1), previous, uint64(i*40))
		if i > 0 {
			r.Before = current[i-1].After
			r.After.PeakSinceSequence = r.Before.Sequence
			r.SHA256 = HealthReceiptSHA256(r)
		}
		current = append(current, r)
	}
	stage := g.DefaultStages(20)[5]
	now := start.Add(15 * time.Minute)
	evaluate := func(rows []HealthReceipt, limits HealthLimits) HealthWindow {
		return EvaluateHealthWindow(b, stage, start, baseline, rows, limits, now)
	}
	good := evaluate(current, healthLimits())
	if good.Status != "OBSERVED" || good.CustomerExecutionAuthorized || good.Completed == nil || *good.Completed != 600 || good.AvailabilityBasis != "OBSERVED_HTTP_REQUEST_SUCCESS" {
		t.Fatalf("full synthetic coverage failed %+v", good)
	}
	clone := func() []HealthReceipt {
		raw, _ := json.Marshal(current)
		var out []HealthReceipt
		_ = json.Unmarshal(raw, &out)
		return out
	}
	t.Run("missing minute unknown not zero", func(t *testing.T) {
		rows := append([]HealthReceipt{}, current[1:]...)
		r := evaluate(rows, healthLimits())
		if r.Status != "BLOCKED" || r.Completed == nil && r.ErrorRatePPM != nil || !hasHealthReason(r, "STAGE_OBSERVATION_WINDOW_INCOMPLETE") {
			t.Fatalf("gap accepted %+v", r)
		}
	})
	t.Run("tampered receipt", func(t *testing.T) {
		rows := clone()
		rows[2].After.Completed++
		if r := evaluate(rows, healthLimits()); r.Status != "BLOCKED" || !hasHealthReason(r, "HEALTH_RECEIPT_INVALID") {
			t.Fatal(r)
		}
	})
	t.Run("different realm", func(t *testing.T) {
		rows := clone()
		rows[0].Binding.Realm.Generation = "new-generation"
		rows[0].SHA256 = HealthReceiptSHA256(rows[0])
		if r := evaluate(rows, healthLimits()); r.Status != "BLOCKED" {
			t.Fatal(r)
		}
	})
	t.Run("unknown heartbeat", func(t *testing.T) {
		rows := clone()
		rows[0].Before.Heartbeat = false
		rows[0].SHA256 = HealthReceiptSHA256(rows[0])
		if r := evaluate(rows, healthLimits()); r.Status != "BLOCKED" || r.Completed != nil {
			t.Fatal(r)
		}
	})
	t.Run("independent hard limit", func(t *testing.T) {
		limits := healthLimits()
		limits.MaxP95NS = int64(5 * time.Millisecond)
		if r := evaluate(current, limits); r.Status != "BREACH" || !hasHealthReason(r, "HARD_LATENCY_BREACH") || hasHealthReason(r, "LATENCY_REGRESSION_ABOVE_15_PERCENT") {
			t.Fatal(r)
		}
	})
	t.Run("no shortened stage", func(t *testing.T) {
		s := stage
		s.MinimumObservationSeconds = 1
		r := EvaluateHealthWindow(b, s, start, baseline, current, healthLimits(), now)
		if r.Status != "BLOCKED" || !hasHealthReason(r, "HEALTH_POLICY_INVALID") {
			t.Fatal(r)
		}
	})
	t.Run("insufficient population", func(t *testing.T) {
		limits := healthLimits()
		limits.MinimumSamples = 1000
		if r := evaluate(current, limits); r.Status != "BLOCKED" || !hasHealthReason(r, "HEALTH_SAMPLES_INSUFFICIENT") {
			t.Fatal(r)
		}
	})
	t.Run("short or stale baseline cannot authorize positive health", func(t *testing.T) {
		r := EvaluateHealthWindow(b, stage, start, baseline[:1], current, healthLimits(), now)
		if r.Status != "BLOCKED" || !hasHealthReason(r, "BASELINE_OBSERVATION_WINDOW_INCOMPLETE") {
			t.Fatal(r)
		}
		old := syntheticHealthReceipt(b, start.Add(-10*time.Minute), time.Minute, 10*time.Millisecond, 1, "", 0)
		r = EvaluateHealthWindow(b, stage, start, []HealthReceipt{old}, current, healthLimits(), now)
		if r.Status != "BLOCKED" || !hasHealthReason(r, "BASELINE_OBSERVATION_STALE") {
			t.Fatal(r)
		}
	})
	t.Run("descriptor cannot decode as observation", func(t *testing.T) {
		var r HealthReceipt
		_ = json.Unmarshal([]byte(`{"kind":"FIXTURE_SLO","complete":true,"p95":0}`), &r)
		if result := evaluate([]HealthReceipt{r}, healthLimits()); result.Status != "BLOCKED" || result.P95NS != nil {
			t.Fatal(result)
		}
	})
	t.Run("overflow rejected", func(t *testing.T) {
		rows := clone()
		rows[0].Before.Accepted = 0
		rows[0].Before.Completed = ^uint64(0)
		rows[0].Before.Failed = 1
		rows[0].SHA256 = HealthReceiptSHA256(rows[0])
		if r := evaluate(rows, healthLimits()); r.Status != "BLOCKED" {
			t.Fatal(r)
		}
	})
	if strings.Join(good.ReasonCodes, ",") != "" {
		t.Fatal("observed carried blockers")
	}
}

func healthManifestProgram(t *testing.T, at time.Time) g.GitProgram {
	t.Helper()
	b := healthBinding()
	hash := strings.Repeat("a", 64)
	p := g.GitProgram{SchemaVersion: g.GitSchemaVersion, Kind: g.Kind, ID: "health-unit-program", Binding: b.Binding, Realm: b.Realm, CreatorID: "creator", Environment: "NON_PRODUCTION", Policy: g.Policy{ID: "health-policy", Version: 1, SHA256: hash, ApproverRole: g.ApproverRole},
		ArtifactContext: g.ArtifactContext{Kind: g.BuiltinFixtureArtifact, ProviderSource: g.BuiltinProvider, RepositoryID: "health-fixture", GitCommit: fmt.Sprintf("%040x", 1), GitTree: fmt.Sprintf("%040x", 100), ConfigurationSHA256: hash, ToolchainImageSHA256: hash, TerraformVersion: "1.16.0", PipelineID: "health-pipeline", Workspace: "default", StateLineage: "11111111-2222-3333-4444-555555555555", Mapping: g.ModelMapping{OldDeclaredASG: "aws_autoscaling_group.old", CandidateDeclaredASG: "aws_autoscaling_group.candidate", DeclaredListenerRule: "aws_lb_listener_rule.fixture", OldModel: "terraform_data.old", CandidateModel: "terraform_data.candidate", TrafficModel: "terraform_data.traffic"}},
		OldTemplate:     g.Template{ID: "lt-12345678", Version: 1, InstanceType: "m6i.large", SHA256: hash}, CandidateTemplate: g.Template{ID: "lt-87654321", Version: 1, InstanceType: "m6i.medium", SHA256: hash}, Budget: g.ModelBudget{CostBasis: g.FixtureModelCost, Currency: "USD", BaselineCount: 20, MaxInFlight: 2, MaxUnavailable: 0, MaxBlastRadiusPPM: 100000, MaxSurgeCount: 20, OldHourlyCost: "0.5", CandidateHourlyCost: "0.3", MaximumModelCost: "100", MaximumDurationSeconds: 6 * 3600}, Stages: g.DefaultStages(20), CreatedAt: at, ExpiresAt: at.Add(8 * time.Hour), Nonce: "health-parent-nonce"}
	for _, kind := range []string{"FIXTURE_HISTORY", "FIXTURE_DEMAND", "FIXTURE_CAPACITY", "FIXTURE_CONFIGURATION", "FIXTURE_DEPENDENCY", "FIXTURE_SLO", "FIXTURE_ECONOMICS"} {
		p.Evidence = append(p.Evidence, g.EvidenceRef{Kind: kind, ID: "unit-" + strings.ToLower(kind), SHA256: hash, BindingSHA256: g.Digest(p.Binding), RealmSHA256: g.Digest(p.Realm), ObservedAt: at, ValidUntil: p.ExpiresAt})
	}
	steps, err := g.GitStageSpecifications(p)
	if err != nil {
		t.Fatal(err)
	}
	source, err := g.GitFixtureConfiguration(p)
	if err != nil {
		t.Fatal(err)
	}
	p.ArtifactContext.ConfigurationSHA256 = g.BytesDigest(source)
	desired, _ := g.GitFixtureDesired(p, steps[0].Before)
	base := g.GitRevision{Commit: p.ArtifactContext.GitCommit, Tree: p.ArtifactContext.GitTree, ConfigurationSHA256: p.ArtifactContext.ConfigurationSHA256, DesiredSHA256: g.BytesDigest(desired)}
	p.Manifest = g.GitManifest{SchemaVersion: "1", Ref: "refs/heads/approved", Base: base}
	previous := base
	for i, s := range steps {
		s.PredecessorCommit = previous.Commit
		desired, _ = g.GitFixtureDesired(p, s.After)
		s.Revision = g.GitRevision{Commit: fmt.Sprintf("%040x", i+1), Tree: fmt.Sprintf("%040x", i+100), ConfigurationSHA256: base.ConfigurationSHA256, DesiredSHA256: g.BytesDigest(desired)}
		p.Manifest.Entries = append(p.Manifest.Entries, s)
		previous = s.Revision
	}
	p.ManifestSHA256 = g.Digest(p.Manifest)
	if err = g.ValidateGitProgram(p, g.Expected{Binding: p.Binding, Realm: p.Realm}, at); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestHealthExactManifestPreservesWarmupCanaryAndTerminalDurations(t *testing.T) {
	start := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	p := healthManifestProgram(t, start.Add(-3*time.Minute))
	binding := healthBinding()
	binding.ProgramSHA256 = g.Digest(p)
	for _, test := range []struct {
		index    int
		duration time.Duration
	}{{1, 120 * time.Second}, {2, time.Hour}, {25, 15 * time.Minute}} {
		entry := p.Manifest.Entries[test.index]
		r := EvaluateManifestHealthWindow(p, entry, binding, start, nil, nil, healthLimits(), start)
		if !r.RequiredEnd.Equal(start.Add(test.duration)) || r.Status != "BLOCKED" || hasHealthReason(r, "MANIFEST_ENTRY_HEALTH_BINDING_INVALID") {
			t.Fatalf("wrong approved duration: %d %+v", test.index, r)
		}
		entry.MinimumObservationSeconds = 1
		if bad := EvaluateManifestHealthWindow(p, entry, binding, start, nil, nil, healthLimits(), start); !hasHealthReason(bad, "MANIFEST_ENTRY_HEALTH_BINDING_INVALID") {
			t.Fatal("mutated duration accepted")
		}
	}
	badBinding := binding
	badBinding.ProgramSHA256 = strings.Repeat("b", 64)
	if bad := EvaluateManifestHealthWindow(p, p.Manifest.Entries[1], badBinding, start, nil, nil, healthLimits(), start); !hasHealthReason(bad, "MANIFEST_ENTRY_HEALTH_BINDING_INVALID") {
		t.Fatal("other program accepted")
	}
}
