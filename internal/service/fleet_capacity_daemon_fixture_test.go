package service

// This is an isolated acceptance coordinator. Only the host controller can
// create/remove worker containers. The workers themselves execute the real
// production binary with a dedicated evaluator and version-reader identity.
import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
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
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/native"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
)

var daemonFixtureUUID = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)
var daemonFixtureSHA = regexp.MustCompile(`^[a-f0-9]{64}$`)
var daemonFixtureSecrets = []string{"access-key", "database", "model-token", "reader-token", "secret-key"}

type fleetCapacityDaemonFile struct {
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}
type fleetCapacityDaemonReady struct {
	SchemaVersion       string                             `json:"schema_version"`
	RunID               string                             `json:"run_id"`
	TenantID            string                             `json:"tenant_id"`
	RequestID           string                             `json:"request_id"`
	ArchiveBucket       string                             `json:"archive_bucket"`
	ReaderEndpoint      string                             `json:"reader_endpoint"`
	ModelEndpoint       string                             `json:"model_endpoint"`
	ConfigurationSHA256 string                             `json:"configuration_sha256"`
	Files               map[string]fleetCapacityDaemonFile `json:"files"`
}
type fleetCapacityDaemonCutpoint struct {
	SchemaVersion        string `json:"schema_version"`
	RunID                string `json:"run_id"`
	RequestID            string `json:"request_id"`
	Phase                string `json:"phase"`
	FirstMemberID        string `json:"first_member_id"`
	FirstMemberSHA256    string `json:"first_member_sha256"`
	FirstMemberCreatedAt string `json:"first_member_created_at"`
	BlockedInstanceID    string `json:"blocked_instance_id"`
}
type fleetCapacityDaemonProof struct {
	SchemaVersion        string `json:"schema_version"`
	RunID                string `json:"run_id"`
	RequestID            string `json:"request_id"`
	OldContainerID       string `json:"old_container_id"`
	NewContainerID       string `json:"new_container_id"`
	ImageID              string `json:"image_id"`
	CompiledBinarySHA256 string `json:"compiled_binary_sha256"`
	ConfigurationSHA256  string `json:"configuration_sha256"`
	FilesSHA256          string `json:"files_sha256"`
	FirstMemberID        string `json:"first_member_id"`
	FirstMemberSHA256    string `json:"first_member_sha256"`
	FirstMemberCreatedAt string `json:"first_member_created_at"`
	BlockedInstanceID    string `json:"blocked_instance_id"`
	OldAbsenceConfirmed  bool   `json:"old_absence_confirmed"`
	DistinctProcess      bool   `json:"distinct_process"`
	ReadonlyWorker       bool   `json:"readonly_worker"`
	NoAWSOrExecution     bool   `json:"no_aws_signing_execution_credentials"`
}

func fleetCapacityDaemonHash(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
func fleetCapacityDaemonJSON(value any) ([]byte, error) {
	raw, e := json.Marshal(value)
	if e != nil {
		return nil, e
	}
	var d any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if decoder.Decode(&d) != nil {
		return nil, errors.New("capacity daemon canonical JSON refused")
	}
	return json.Marshal(d)
}
func fleetCapacityDaemonEnvironment(r fleetCapacityDaemonReady) map[string]string {
	return map[string]string{"FLEET_CAPACITY_ENABLED": "true", "FLEET_CAPACITY_TENANT_ID": r.TenantID, "FLEET_CAPACITY_DATABASE_FILE": "/run/secrets/group-capacity-database", "FLEET_CAPACITY_ARCHIVE_MODE": "LOCAL_VERSIONED_S3", "FLEET_CAPACITY_ARCHIVE_REGION": "eu-west-1", "FLEET_CAPACITY_ARCHIVE_ENDPOINT": "http://minio:9000", "FLEET_CAPACITY_ARCHIVE_BUCKET": r.ArchiveBucket, "FLEET_CAPACITY_ARCHIVE_ACCESS_KEY_FILE": "/run/secrets/group-capacity-access-key", "FLEET_CAPACITY_ARCHIVE_SECRET_KEY_FILE": "/run/secrets/group-capacity-secret-key", "FLEET_CAPACITY_SERVICE_MODE": "PRIVATE_SERVICES", "FLEET_CAPACITY_READER_URL": r.ReaderEndpoint, "FLEET_CAPACITY_READER_TOKEN_FILE": "/run/secrets/group-capacity-reader-token", "FLEET_CAPACITY_MODEL_URL": r.ModelEndpoint, "FLEET_CAPACITY_MODEL_TOKEN_FILE": "/run/secrets/group-capacity-model-token"}
}
func fleetCapacityDaemonWrite(path string, value any, mode os.FileMode) error {
	raw, e := fleetCapacityDaemonJSON(value)
	if e != nil || len(raw) > 8192 {
		return errors.New("capacity daemon marker refused")
	}
	return fleetCapacityDaemonWriteBytes(path, raw, mode)
}
func fleetCapacityDaemonWriteBytes(path string, raw []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	s, e := os.Lstat(dir)
	resolved, re := filepath.EvalSymlinks(dir)
	if e != nil || re != nil || !s.IsDir() || s.Mode()&os.ModeSymlink != 0 || resolved != dir {
		return errors.New("capacity daemon private directory refused")
	}
	f, e := os.CreateTemp(dir, ".capacity-daemon-publish-*")
	if e != nil {
		return errors.New("capacity daemon exclusive publication refused")
	}
	temporary := f.Name()
	defer os.Remove(temporary)
	if e = f.Chmod(mode); e == nil {
		_, e = f.Write(raw)
	}
	if e == nil {
		e = f.Sync()
	}
	closed := f.Close()
	if e != nil || closed != nil {
		return errors.New("capacity daemon durable publication refused")
	}
	// Link publishes a complete fsynced file atomically and refuses an existing
	// destination. Polling never observes a partial final-name marker.
	if e = os.Link(temporary, path); e != nil {
		return errors.New("capacity daemon exclusive publication refused")
	}
	if e = os.Remove(temporary); e != nil {
		return errors.New("capacity daemon publication cleanup refused")
	}
	d, e := os.Open(dir)
	if e != nil {
		return e
	}
	defer d.Close()
	return d.Sync()
}
func fleetCapacityDaemonRead(path string, out any) (bool, error) {
	s, e := os.Lstat(path)
	if os.IsNotExist(e) {
		return false, nil
	}
	if e != nil || !s.Mode().IsRegular() || s.Mode()&os.ModeSymlink != 0 || s.Size() < 1 || s.Size() > 8192 {
		return false, errors.New("capacity daemon marker metadata refused")
	}
	f, e := os.Open(path)
	if e != nil {
		return false, e
	}
	raw, e := io.ReadAll(io.LimitReader(f, 8193))
	_ = f.Close()
	if e != nil || len(raw) > 8192 {
		return false, errors.New("capacity daemon marker bound refused")
	}
	raw = bytes.TrimSuffix(raw, []byte("\n"))
	var generic any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if decoder.Decode(&generic) != nil || decoder.Decode(new(any)) != io.EOF {
		return false, errors.New("capacity daemon marker JSON refused")
	}
	canonical, e := json.Marshal(generic)
	if e != nil || !bytes.Equal(canonical, raw) {
		return false, errors.New("capacity daemon marker canonical framing refused")
	}
	decoder = json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(out) != nil || decoder.Decode(new(any)) != io.EOF {
		return false, errors.New("capacity daemon marker fields refused")
	}
	return true, nil
}

func fleetCapacityDaemonRows(ctx context.Context, db *store.Store, tenant, request string) (model.Document, []model.Document, error) {
	var requestDoc model.Document
	var rows []model.Document
	e := db.Do(ctx, tenant, func(tx *store.Tx) error {
		var e error
		requestDoc, e = tx.FleetCapacityBatchGet(ctx, request)
		if e != nil {
			return e
		}
		rows, e = tx.FleetCapacityBatchMemberPage(ctx, request, "", 101)
		return e
	})
	return requestDoc, rows, e
}

// fleetCapacityRunDaemonPhase blocks only an acceptance transport, never a
// production clock or source gate. It proves one committed member survives the
// destruction of the old daemon, and that a distinct daemon completes the same
// issued queue request. The host must remove the replacement before returning
// control, so it cannot race later independent fixture jobs.
func fleetCapacityRunDaemonPhase(t *testing.T, ctx context.Context, runID, tenant string, evaluator *store.Store, bucket, readerAccess, readerSecret, readerToken, modelToken string, nativeHandler http.Handler, requestID string) *fleetCapacityDaemonProof {
	t.Helper()
	if !daemonFixtureUUID.MatchString(runID) || !daemonFixtureUUID.MatchString(requestID) || tenant == "" || evaluator == nil || evaluator.Pool == nil || nativeHandler == nil || readerAccess == "" || readerSecret == "" || readerToken == "" || modelToken == "" || readerToken == modelToken || !regexp.MustCompile(`^native-capacity-[a-f0-9]{32}$`).MatchString(bucket) {
		t.Fatal("capacity daemon private installation refused")
	}
	for _, dir := range []string{"/daemon", "/daemon-secrets"} {
		s, e := os.Lstat(dir)
		if e != nil || !s.IsDir() || s.Mode()&os.ModeSymlink != 0 || dir == "/daemon-secrets" && s.Mode().Perm() != 0755 {
			t.Fatal("owned capacity daemon mount unavailable")
		}
	}
	entries, e := os.ReadDir("/daemon-secrets")
	if e != nil || len(entries) != 0 {
		t.Fatal("capacity daemon credential volume must start empty")
	}
	r := fleetCapacityDaemonReady{SchemaVersion: "1", RunID: runID, TenantID: tenant, RequestID: requestID, ArchiveBucket: bucket, ReaderEndpoint: "http://capacity-test:8098", ModelEndpoint: "http://economics:8000", Files: map[string]fleetCapacityDaemonFile{}}
	values := map[string]string{"database": evaluator.Pool.Config().ConnString(), "access-key": readerAccess, "secret-key": readerSecret, "reader-token": readerToken, "model-token": modelToken}
	for _, name := range daemonFixtureSecrets {
		raw := []byte(values[name] + "\n")
		limit := 256
		if name == "database" {
			limit = 8192
		} else if strings.HasSuffix(name, "token") {
			limit = 4096
		}
		if len(raw) < 2 || len(raw) > limit || strings.ContainsAny(values[name], "\x00\r\n") {
			t.Fatal("capacity daemon credential shape refused")
		}
		if e := fleetCapacityDaemonWriteBytes("/daemon-secrets/group-capacity-"+name, raw, 0444); e != nil {
			t.Fatal(e)
		}
		r.Files[name] = fleetCapacityDaemonFile{fleetCapacityDaemonHash(raw), int64(len(raw))}
	}
	envRaw, _ := json.Marshal(fleetCapacityDaemonEnvironment(r))
	r.ConfigurationSHA256 = fleetCapacityDaemonHash(envRaw)
	failures := make(chan error, 1)
	fail := func(e error) {
		select {
		case failures <- e:
		default:
		}
	}
	var calls atomic.Int32
	var cut fleetCapacityDaemonCutpoint
	var cutOnce sync.Once
	disconnected := make(chan struct{})
	cutPublished := make(chan struct{})
	handler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/capacity-input" || req.Method != http.MethodPost || req.Header.Get("Authorization") != "Bearer "+readerToken {
			nativeHandler.ServeHTTP(w, req)
			return
		}
		raw, e := io.ReadAll(io.LimitReader(req.Body, 8193))
		if e != nil || len(raw) > 8192 {
			fail(errors.New("capacity daemon reader input refused"))
			w.WriteHeader(503)
			return
		}
		_ = req.Body.Close()
		req.Body = io.NopCloser(bytes.NewReader(raw))
		var input native.CapacityInputRequest
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&input) != nil || decoder.Decode(new(any)) != io.EOF || input.TenantID != tenant {
			fail(errors.New("capacity daemon reader binding refused"))
			w.WriteHeader(503)
			return
		}
		if calls.Add(1) == 2 {
			d, rows, e := fleetCapacityDaemonRows(req.Context(), evaluator, tenant, requestID)
			scope := sourceObject(sourceObject(d["scope"])["scope"])
			ids := model.Strings(scope, "current_member_ids")
			sort.Strings(ids)
			if e != nil || len(rows) != 1 || len(ids) < 2 || rows[0]["instance_id"] != ids[0] || !model.Bool(rows[0], "model_evaluated") || d["batch"] != nil {
				fail(errors.New("capacity daemon first committed member unavailable"))
				w.WriteHeader(503)
				return
			}
			var inputs model.Document
			e = evaluator.Do(req.Context(), tenant, func(tx *store.Tx) error {
				var err error
				inputs, err = tx.FleetCapacityBatchMemberInputs(req.Context(), requestID, ids[1])
				return err
			})
			connection := sourceObject(inputs["connection"])
			if e != nil || !model.Bool(inputs, "current") || model.String(connection, "id") != input.ConnectionID || model.String(connection, "config_hash") != input.ConfigHash {
				fail(errors.New("capacity daemon held second-member selection differs"))
				w.WriteHeader(503)
				return
			}
			cut = fleetCapacityDaemonCutpoint{"1", runID, requestID, "SECOND_MEMBER_REQUEST_HELD", model.String(rows[0], "id"), model.String(rows[0], "sha256"), model.String(rows[0], "created_at"), ids[1]}
			if !daemonFixtureSHA.MatchString(cut.FirstMemberSHA256) || !strings.HasPrefix(cut.FirstMemberID, "fleet-capacity-member-") || cut.FirstMemberCreatedAt == "" {
				fail(errors.New("capacity daemon committed member seal invalid"))
				w.WriteHeader(503)
				return
			}
			if e = fleetCapacityDaemonWrite("/daemon/cutpoint.json", cut, 0600); e != nil {
				fail(e)
				w.WriteHeader(503)
				return
			}
			close(cutPublished)
			select {
			case <-req.Context().Done():
				cutOnce.Do(func() { close(disconnected) })
				return
			case <-ctx.Done():
				return
			}
		}
		nativeHandler.ServeHTTP(w, req)
	})
	listener, e := net.Listen("tcp4", "0.0.0.0:8098")
	if e != nil {
		t.Fatal("fixed capacity daemon native listener unavailable", e)
	}
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 3 * time.Second, IdleTimeout: 30 * time.Second}
	go func() {
		if e := server.Serve(listener); e != nil && !errors.Is(e, http.ErrServerClosed) {
			fail(errors.New("capacity daemon reader stopped"))
		}
	}()
	// Later browser acceptance reuses this registered reader with a separately
	// owned daemon episode. No daemon remains running between those episodes.
	t.Cleanup(func() {
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	})
	if e = fleetCapacityDaemonWrite("/daemon/ready.json", r, 0600); e != nil {
		t.Fatal(e)
	}
	wait := func(check func() (bool, error)) {
		t.Helper()
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			done, e := check()
			if e != nil {
				t.Fatal(e)
			}
			if done {
				return
			}
			select {
			case e := <-failures:
				t.Fatal(e)
			case <-ctx.Done():
				t.Fatal("capacity daemon host handshake expired")
			case <-ticker.C:
			}
		}
	}
	var proof fleetCapacityDaemonProof
	wait(func() (bool, error) { return fleetCapacityDaemonRead("/daemon/restarted.json", &proof) })
	// Host-observed removal and the server's cancellation callback are separate
	// scheduling events. Await the actual callback rather than inferring it or
	// rejecting a valid removal before the HTTP goroutine can observe it.
	for _, signal := range []<-chan struct{}{cutPublished, disconnected} {
		wait(func() (bool, error) {
			select {
			case <-signal:
				return true, nil
			default:
				return false, nil
			}
		})
	}
	filesRaw, _ := json.Marshal(r.Files)
	if proof.SchemaVersion != "1" || proof.RunID != runID || proof.RequestID != requestID || !daemonFixtureSHA.MatchString(proof.OldContainerID) || !daemonFixtureSHA.MatchString(proof.NewContainerID) || proof.OldContainerID == proof.NewContainerID || !regexp.MustCompile(`^sha256:[a-f0-9]{64}$`).MatchString(proof.ImageID) || !daemonFixtureSHA.MatchString(proof.CompiledBinarySHA256) || proof.ConfigurationSHA256 != r.ConfigurationSHA256 || proof.FilesSHA256 != fleetCapacityDaemonHash(filesRaw) || proof.FirstMemberID != cut.FirstMemberID || proof.FirstMemberSHA256 != cut.FirstMemberSHA256 || proof.FirstMemberCreatedAt != cut.FirstMemberCreatedAt || proof.BlockedInstanceID != cut.BlockedInstanceID || !proof.OldAbsenceConfirmed || !proof.DistinctProcess || !proof.ReadonlyWorker || !proof.NoAWSOrExecution {
		t.Fatal("host-observed daemon restart proof differs")
	}
	var finalRows []model.Document
	wait(func() (bool, error) {
		d, rows, e := fleetCapacityDaemonRows(ctx, evaluator, tenant, requestID)
		if e != nil {
			return false, e
		}
		if d["batch"] == nil {
			return false, nil
		}
		scope := sourceObject(sourceObject(d["scope"])["scope"])
		ids := model.Strings(scope, "current_member_ids")
		if len(rows) != len(ids) || model.String(d, "status") != "ASSESSED" {
			return false, errors.New("replacement daemon did not finish the complete point")
		}
		found := false
		for _, row := range rows {
			if model.String(row, "id") == cut.FirstMemberID {
				found = model.String(row, "sha256") == cut.FirstMemberSHA256 && model.String(row, "created_at") == cut.FirstMemberCreatedAt
			}
		}
		if !found {
			return false, errors.New("first committed capacity member changed across process loss")
		}
		finalRows = rows
		return true, nil
	})
	if calls.Load() != int32(len(finalRows)+1) {
		t.Fatal("daemon restart re-read a completed member or omitted held request", calls.Load())
	}
	proofRaw, _ := fleetCapacityDaemonJSON(proof)
	proofSHA := fleetCapacityDaemonHash(proofRaw)
	if e = fleetCapacityDaemonWrite("/daemon/finished.json", model.Document{"schema_version": "1", "run_id": runID, "request_id": requestID, "restart_proof_sha256": proofSHA, "member_count": len(finalRows), "first_member_id": cut.FirstMemberID, "first_member_sha256": cut.FirstMemberSHA256, "first_member_created_at": cut.FirstMemberCreatedAt}, 0600); e != nil {
		t.Fatal(e)
	}
	var complete struct {
		SchemaVersion      string `json:"schema_version"`
		RunID              string `json:"run_id"`
		RequestID          string `json:"request_id"`
		RestartProofSHA256 string `json:"restart_proof_sha256"`
		OldContainerID     string `json:"old_container_id"`
		NewContainerID     string `json:"new_container_id"`
		OldAbsent          bool   `json:"old_absent"`
		NewAbsent          bool   `json:"new_absent"`
	}
	wait(func() (bool, error) { return fleetCapacityDaemonRead("/daemon/complete.json", &complete) })
	if complete.SchemaVersion != "1" || complete.RunID != runID || complete.RequestID != requestID || complete.RestartProofSHA256 != proofSHA || complete.OldContainerID != proof.OldContainerID || complete.NewContainerID != proof.NewContainerID || !complete.OldAbsent || !complete.NewAbsent {
		t.Fatal("replacement daemon exclusion before later jobs is unproved")
	}
	return &proof
}

func TestFleetCapacityDaemonProtocolCanonicalAndExact(t *testing.T) {
	r := fleetCapacityDaemonReady{TenantID: "fixture-tenant", ArchiveBucket: "native-capacity-" + strings.Repeat("a", 32), ReaderEndpoint: "http://capacity-test:8098", ModelEndpoint: "http://economics:8000"}
	env := fleetCapacityDaemonEnvironment(r)
	if len(env) != 14 {
		t.Fatal("daemon env contract changed")
	}
	raw, e := fleetCapacityDaemonJSON(env)
	if e != nil || !bytes.Equal(raw, func() []byte { b, _ := json.Marshal(env); return b }()) {
		t.Fatal("daemon canonical environment differs")
	}
	path := filepath.Join(t.TempDir(), "marker.json")
	v := model.Document{"z": 1, "a": model.Document{"nanoseconds": "2026-10-19T12:00:00.123456789Z"}}
	if e := fleetCapacityDaemonWrite(path, v, 0600); e != nil {
		t.Fatal(e)
	}
	before, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	if e = fleetCapacityDaemonWrite(path, model.Document{"replacement": true}, 0600); e == nil {
		t.Fatal("published marker was overwritten")
	}
	after, e := os.ReadFile(path)
	if e != nil || !bytes.Equal(before, after) {
		t.Fatal("failed publication changed existing marker")
	}
	entries, e := os.ReadDir(filepath.Dir(path))
	if e != nil || len(entries) != 1 {
		t.Fatal("publication left temporary files")
	}
	var out model.Document
	if present, e := fleetCapacityDaemonRead(path, &out); e != nil || !present || model.String(sourceObject(out["a"]), "nanoseconds") != "2026-10-19T12:00:00.123456789Z" {
		t.Fatal("canonical marker interop refused", e)
	}
	for _, body := range []string{`{"a":1,"a":1}`, `{"a":1} {}`, ` {"a":1}`} {
		if e = os.WriteFile(path, []byte(body), 0600); e != nil {
			t.Fatal(e)
		}
		if _, e = fleetCapacityDaemonRead(path, &out); e == nil {
			t.Fatal("ambiguous marker accepted")
		}
	}
}
