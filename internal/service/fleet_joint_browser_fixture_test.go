package service

// Candidate-only real OIDC acceptance bridge. The host owns all container
// lifecycle operations; this Go fixture only commissions one analytical login,
// observes real committed requests and witnesses process replacement in PG.
import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/fleetbilling"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/jackc/pgx/v5"
)

const jointFinanceSubject = "15b833b1-3c50-4b20-921f-a8a72d88f1f2"

type jointBrowserRuntime struct {
	db       *store.Store
	login    string
	ready    fleetCapacityBrowserReady
	metadata jointBrowserWorkerReady
}
type jointBrowserWorkerReady struct {
	SchemaVersion       string `json:"schema_version"`
	RunID               string `json:"run_id"`
	TenantID            string `json:"tenant_id"`
	Purpose             string `json:"purpose"`
	DatabaseFileSHA256  string `json:"database_file_sha256"`
	DatabaseFileSize    int    `json:"database_file_size"`
	ConfigurationSHA256 string `json:"configuration_sha256"`
}
type jointBrowserRequest struct {
	SchemaVersion     string `json:"schema_version"`
	RunID             string `json:"run_id"`
	ReadySHA256       string `json:"ready_sha256"`
	CapacityRequestID string `json:"capacity_batch_request_id"`
}
type jointDecisionRequest struct {
	SchemaVersion string `json:"schema_version"`
	RunID         string `json:"run_id"`
	ReadySHA256   string `json:"ready_sha256"`
	RequestID     string `json:"request_id"`
}
type jointBrowserInputs struct {
	SchemaVersion               string `json:"schema_version"`
	RunID                       string `json:"run_id"`
	ReadySHA256                 string `json:"ready_sha256"`
	WorkloadID                  string `json:"workload_id"`
	AssessmentRequestID         string `json:"assessment_request_id"`
	CapacityRequestID           string `json:"capacity_batch_request_id"`
	InputRefs                   []any  `json:"input_refs"`
	ExpectedScenarioStatus      string `json:"expected_scenario_status"`
	Fixture                     bool   `json:"fixture"`
	CustomerExecutionAuthorized bool   `json:"customer_execution_authorized"`
}
type jointWorkerStarted struct {
	SchemaVersion string `json:"schema_version"`
	RunID         string `json:"run_id"`
	ReadySHA256   string `json:"ready_sha256"`
	RequestID     string `json:"request_id"`
	ContainerID   string `json:"container_id"`
}
type jointWorkerRestarted struct {
	SchemaVersion        string `json:"schema_version"`
	RunID                string `json:"run_id"`
	ReadySHA256          string `json:"ready_sha256"`
	RequestID            string `json:"request_id"`
	OldContainerID       string `json:"old_container_id"`
	NewContainerID       string `json:"new_container_id"`
	ImageID              string `json:"image_id"`
	CompiledBinarySHA256 string `json:"compiled_binary_sha256"`
	ConfigurationSHA256  string `json:"configuration_sha256"`
	FilesSHA256          string `json:"files_sha256"`
	OldAbsent            bool   `json:"old_absent"`
	DistinctProcess      bool   `json:"distinct_process"`
}
type jointWorkerComplete struct {
	SchemaVersion  string `json:"schema_version"`
	RunID          string `json:"run_id"`
	ReadySHA256    string `json:"ready_sha256"`
	OldContainerID string `json:"old_container_id"`
	NewContainerID string `json:"new_container_id"`
	OldAbsent      bool   `json:"old_absent"`
	NewAbsent      bool   `json:"new_absent"`
}

func jointBrowserEnabled() bool { return os.Getenv("FLEET_JOINT_BROWSER") == "ISOLATED_REAL_OIDC" }
func jointBrowserPrepare(t *testing.T, ctx context.Context, admin *store.Store, ready fleetCapacityBrowserReady) *jointBrowserRuntime {
	t.Helper()
	if !jointBrowserEnabled() {
		return nil
	}
	fleetJointMigrateCandidate(t, ctx, admin)
	db := jointRuntime(t, admin, "finops_group_decision", "group-decision-reader", ready.TenantID)
	cfg := db.Pool.Config().ConnConfig
	// This separate one-file volume never receives the capacity archive/model
	// files, administrator DSN, commissioning SQL, or signing credentials.
	dsn := url.URL{Scheme: "postgres", Host: net.JoinHostPort(cfg.Host, strconv.Itoa(int(cfg.Port))), Path: "/" + cfg.Database, User: url.UserPassword(cfg.User, cfg.Password), RawQuery: "sslmode=disable"}
	raw := []byte(dsn.String() + "\n")
	if len(raw) > 8192 {
		t.Fatal("joint private database file bound")
	}
	dir := "/decision-secrets"
	entries, e := os.ReadDir(dir)
	if e != nil || len(entries) != 0 {
		t.Fatal("joint secret volume is not fresh")
	}
	path := filepath.Join(dir, "group-decision-database")
	file, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0444)
	if e != nil {
		t.Fatal("joint secret staging", e)
	}
	if _, e = file.Write(raw); e == nil {
		e = file.Sync()
	}
	closed := file.Close()
	if e != nil || closed != nil {
		t.Fatal("joint secret staging failed")
	}
	if e = os.Chmod(path, 0444); e != nil {
		t.Fatal(e)
	}
	env := map[string]string{"FLEET_DECISION_ENABLED": "true", "FLEET_DECISION_TENANT_ID": ready.TenantID, "FLEET_DECISION_DATABASE_FILE": "/run/secrets/group-decision-database", "FLEET_DECISION_DATABASE_MODE": "LOCAL_PRIVATE"}
	metadata := jointBrowserWorkerReady{SchemaVersion: "1", RunID: ready.RunID, TenantID: ready.TenantID, Purpose: "group-decision-reader", DatabaseFileSHA256: fleetbilling.BytesHash(raw), DatabaseFileSize: len(raw), ConfigurationSHA256: fleetbilling.Hash(env)}
	if _, e = jointBrowserWrite("/results/joint-worker-ready.json", metadata); e != nil {
		t.Fatal(e)
	}
	return &jointBrowserRuntime{db: db, login: cfg.User, ready: ready, metadata: metadata}
}

func jointBrowserWaitPID(ctx context.Context, admin *store.Store, login string, guardPID, excludedPID int) (int, error) {
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		var pid int
		e := admin.Pool.QueryRow(ctx, `SELECT pid FROM pg_stat_activity WHERE datname=current_database() AND usename=$1 AND pid<>$2 AND wait_event_type='Lock' AND wait_event='advisory' AND $3=ANY(pg_blocking_pids(pid)) AND query LIKE '%fleet_joint_decision_inputs%' ORDER BY backend_start DESC LIMIT 1`, login, excludedPID, guardPID).Scan(&pid)
		if e == nil && pid > 0 {
			return pid, nil
		}
		if e != nil && !errors.Is(e, pgx.ErrNoRows) {
			return 0, e
		}
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-tick.C:
		}
	}
}

// Called synchronously instead of merely waiting for the old036 browser file.
// The parent journey retains its original180s bound. No worker exists before
// the actual POST202 request is committed and the fixture graph fence is held.
func jointBrowserCoordinate(t *testing.T, ctx context.Context, f *mutationReplayFixture, admin *store.Store, r *jointBrowserRuntime, signal fleetCapacityBrowserSignal, proposals []string, archive fleetbilling.PinnedReader, bucket string) error {
	t.Helper()
	if r == nil {
		return nil
	}
	var configured fleetCapacityBrowserSignal
	if e := fleetCapacityBrowserWait(ctx, "joint-worker-configured.json", &configured); e != nil || configured != signal {
		return errors.New("joint worker configuration handshake differs")
	}
	var requested jointBrowserRequest
	if e := fleetCapacityBrowserWait(ctx, "joint-input-request.json", &requested); e != nil {
		return e
	}
	if requested.SchemaVersion != "1" || requested.RunID != signal.RunID || requested.ReadySHA256 != signal.ReadySHA256 || !daemonFixtureUUID.MatchString(requested.CapacityRequestID) {
		return errors.New("joint native input request differs")
	}
	if e := f.roles["api"].Do(ctx, f.tenant, func(tx *store.Tx) error {
		d, e := tx.FleetCapacityBatchGet(ctx, requested.CapacityRequestID)
		if e != nil {
			return e
		}
		if model.String(d, "creator_id") != fleetCapacityBrowserSubject || model.String(d, "status") != "ASSESSED" {
			return errors.New("joint capacity input is not the actual owner-created result")
		}
		return nil
	}); e != nil {
		return e
	}
	assessment, e := fleetJointIssueNativeAssessment(t, ctx, f, admin, proposals, requested.CapacityRequestID, archive, bucket)
	if e != nil {
		return e
	}
	var in model.Document
	if e = r.db.Do(ctx, f.tenant, func(tx *store.Tx) error {
		var raw []byte
		if e := tx.QueryRow(ctx, `SELECT public.fleet_joint_decision_inputs($1,$2,$3)`, f.tenant, assessment, requested.CapacityRequestID).Scan(&raw); e != nil {
			return e
		}
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		return decoder.Decode(&in)
	}); e != nil {
		return e
	}
	scenario := sourceDocument(sourceDocument(in["assessment"])["scenario"])
	status := model.String(scenario, "status")
	if status != "OBSERVED_CONDITIONAL" {
		return errors.New("actual native conditional rates unavailable for joint browser")
	}
	inputs := jointBrowserInputs{SchemaVersion: "1", RunID: signal.RunID, ReadySHA256: signal.ReadySHA256, WorkloadID: r.ready.WorkloadID, AssessmentRequestID: assessment, CapacityRequestID: requested.CapacityRequestID, InputRefs: []any{in["assessment_ref"], in["scope_ref"], in["batch_ref"]}, ExpectedScenarioStatus: status, Fixture: true}
	inputRaw, e := jointBrowserWrite("/results/joint-inputs.json", inputs)
	if e != nil {
		return e
	}
	var posted jointDecisionRequest
	if e = fleetCapacityBrowserWait(ctx, "joint-decision-request.json", &posted); e != nil {
		return e
	}
	if posted.SchemaVersion != "1" || posted.RunID != signal.RunID || posted.ReadySHA256 != signal.ReadySHA256 || !daemonFixtureUUID.MatchString(posted.RequestID) {
		return errors.New("joint committed request signal differs")
	}
	guard, e := admin.Pool.Begin(ctx)
	if e != nil {
		return e
	}
	defer guard.Rollback(context.Background())
	var guardPID int
	if e = guard.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&guardPID); e != nil {
		return e
	}
	if _, e = guard.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, f.tenant+":dependency-graph"); e != nil {
		return e
	}
	if e = r.db.Do(ctx, f.tenant, func(tx *store.Tx) error {
		d, e := tx.FleetJointDecisionGet(ctx, posted.RequestID)
		if e != nil {
			return e
		}
		if model.String(d, "creator_id") != jointFinanceSubject || model.String(d, "status") != "QUEUED" || d["decision"] != nil || d["refusal"] != nil || model.String(d, "assessment_request_id") != assessment || model.String(d, "capacity_batch_request_id") != requested.CapacityRequestID || fleetbilling.Hash(d["input_refs"]) != fleetbilling.Hash(inputs.InputRefs) {
			return errors.New("actual committed finance request differs")
		}
		return nil
	}); e != nil {
		return e
	}
	cutpoint := model.Document{"schema_version": "1", "run_id": signal.RunID, "ready_sha256": signal.ReadySHA256, "request_id": posted.RequestID, "phase": "QUEUED_GRAPH_FENCE_HELD", "pending": true, "decision_exists": false}
	if _, e = jointBrowserWrite("/results/joint-worker-cutpoint.json", cutpoint); e != nil {
		return e
	}
	var started jointWorkerStarted
	if e = fleetCapacityBrowserWait(ctx, "joint-worker-started.json", &started); e != nil {
		return e
	}
	if started.SchemaVersion != "1" || started.RunID != signal.RunID || started.ReadySHA256 != signal.ReadySHA256 || started.RequestID != posted.RequestID || !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(started.ContainerID) {
		return errors.New("joint original worker binding differs")
	}
	oldPID, e := jointBrowserWaitPID(ctx, admin, r.login, guardPID, 0)
	if e != nil {
		return e
	}
	if _, e = jointBrowserWrite("/results/joint-worker-blocked.json", model.Document{"schema_version": "1", "run_id": signal.RunID, "ready_sha256": signal.ReadySHA256, "request_id": posted.RequestID, "original_waiting": true}); e != nil {
		return e
	}
	var restarted jointWorkerRestarted
	if e = fleetCapacityBrowserWait(ctx, "joint-worker-restarted.json", &restarted); e != nil {
		return e
	}
	sha := regexp.MustCompile(`^[a-f0-9]{64}$`)
	if restarted.SchemaVersion != "1" || restarted.RunID != signal.RunID || restarted.ReadySHA256 != signal.ReadySHA256 || restarted.RequestID != posted.RequestID || restarted.OldContainerID != started.ContainerID || !sha.MatchString(restarted.NewContainerID) || restarted.NewContainerID == started.ContainerID || !restarted.OldAbsent || !restarted.DistinctProcess || restarted.ConfigurationSHA256 != r.metadata.ConfigurationSHA256 || !regexp.MustCompile(`^sha256:[a-f0-9]{64}$`).MatchString(restarted.ImageID) || !sha.MatchString(restarted.CompiledBinarySHA256) || !sha.MatchString(restarted.FilesSHA256) {
		return errors.New("joint replacement worker proof differs")
	}
	var oldPresent bool
	if e = admin.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND usename=$1 AND pid=$2)`, r.login, oldPID).Scan(&oldPresent); e != nil || oldPresent {
		return errors.New("joint original database process remains")
	}
	if _, e = jointBrowserWaitPID(ctx, admin, r.login, guardPID, oldPID); e != nil {
		return e
	}
	if e = guard.Rollback(ctx); e != nil {
		return e
	}
	var proof model.Document
	if e = fleetCapacityBrowserWait(ctx, "joint-browser-result.json", &proof); e != nil {
		return e
	}
	if model.String(proof, "status") != "PASS" || model.String(proof, "run_id") != signal.RunID || model.String(proof, "ready_sha256") != signal.ReadySHA256 || model.String(proof, "joint_inputs_sha256") != fleetbilling.BytesHash(inputRaw) || model.String(proof, "request_id") != posted.RequestID || model.String(proof, "creator_id") != jointFinanceSubject {
		return errors.New("joint browser proof differs")
	}
	if e = r.db.Do(ctx, f.tenant, func(tx *store.Tx) error {
		d, e := tx.FleetJointDecisionGet(ctx, posted.RequestID)
		if e != nil {
			return e
		}
		decision := sourceDocument(d["decision"])
		members := jointBrowserDocs(decision["members"])
		if model.String(decision, "request_id") != posted.RequestID || model.String(d, "status") != "ASSESSED" || model.String(d, "creator_id") != jointFinanceSubject || fleetbilling.Hash(d["input_refs"]) != fleetbilling.Hash(inputs.InputRefs) || fleetbilling.Hash(decision) != model.String(proof, "decision_sha256") || model.String(decision, "physical_status") != "FAIL" || len(members) != 3 || model.String(sourceDocument(decision["scenario"]), "status") != "OBSERVED_CONDITIONAL" || decision["contracted_avoidable_cost"] != nil || decision["estimated_saving"] != nil || decision["verified_saving"] != nil || model.Bool(decision, "execution_authorized") || model.Bool(decision, "group_capacity_authorized") {
			return errors.New("joint browser result differs from actual native publication")
		}
		unknown := false
		for _, m := range members {
			if len(jointBrowserDocs(m["dimensions"])) != 5 {
				return errors.New("joint dimensions incomplete")
			}
			unknown = unknown || model.String(m, "status") == "UNKNOWN"
		}
		if !unknown {
			return errors.New("joint missing member was promoted")
		}
		return nil
	}); e != nil {
		return e
	}
	var complete jointWorkerComplete
	if e = fleetCapacityBrowserWait(ctx, "joint-worker-complete.json", &complete); e != nil {
		return e
	}
	if complete.SchemaVersion != "1" || complete.RunID != signal.RunID || complete.ReadySHA256 != signal.ReadySHA256 || complete.OldContainerID != restarted.OldContainerID || complete.NewContainerID != restarted.NewContainerID || !complete.OldAbsent || !complete.NewAbsent {
		return fmt.Errorf("joint worker exclusion is unproved")
	}
	return nil
}

func jointBrowserDocs(v any) []model.Document {
	var out []model.Document
	if rows, ok := v.([]any); ok {
		for _, row := range rows {
			out = append(out, sourceDocument(row))
		}
	}
	return out
}

func jointBrowserWrite(path string, value any) ([]byte, error) {
	raw, e := fleetCapacityDaemonJSON(value)
	if e != nil {
		return nil, e
	}
	if len(raw) > 8192 {
		return nil, errors.New("joint signal bound differs")
	}
	if e = fleetCapacityDaemonWriteBytes(path, raw, 0600); e != nil {
		return nil, e
	}
	return raw, nil
}
