package service

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/configuration"
	ff "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetfixture"
	g "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetgroup"
	native "github.com/christopherosiemo/bn-implementation-Finops/internal/groupfixtureproducer"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/jackc/pgx/v5"
)

const workspaceBundlePath = "/handoff/private-bundle.json"
const workspaceRuntimePath = "/handoff/runtime.json"
const workspaceRetirementPath = "/handoff/retirement.json"

var workspaceUUID = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)
var workspaceSHA = regexp.MustCompile(`^[a-f0-9]{64}$`)

type workspaceRuntime struct {
	SchemaVersion       string                 `json:"schema_version"`
	RunID               string                 `json:"run_id"`
	Workspace           native.NativeWorkspace `json:"workspace"`
	ControllerKeyID     string                 `json:"controller_key_id"`
	ControllerPublicKey ed25519.PublicKey      `json:"controller_public_key"`
}
type workspacePending struct {
	Command      g.JournalCommand                `json:"command"`
	Capture      g.GitTerraformArtifactCapture   `json:"capture"`
	Delivery     store.FleetGroupJournalDelivery `json:"delivery"`
	AttemptID    string                          `json:"attempt_id"`
	Permit       g.JournalDispatchPermit         `json:"permit"`
	Outcome      native.NativeOutcome            `json:"outcome"`
	SelectedRefs map[string]string               `json:"selected_refs"`
}

// Fixture-coordinator bundle only: these independent restricted logins/keys
// share one private acceptance harness. It is not a production worker design.
// The controller PRIVATE key is deliberately absent and remains host-only.
type workspaceBundle struct {
	SchemaVersion          string                           `json:"schema_version"`
	Runtime                workspaceRuntime                 `json:"runtime"`
	TenantID               string                           `json:"tenant_id"`
	DatabaseName           string                           `json:"database_name"`
	DatabaseMarker         string                           `json:"database_marker"`
	RoleDSNs               map[string]string                `json:"role_dsns"`
	RoleNames              []string                         `json:"role_names"`
	Selected               ff.Proposal                      `json:"selected"`
	Prepared               ff.Preparation                   `json:"prepared"`
	Bootstrap              store.FleetGroupJournalBootstrap `json:"bootstrap"`
	Pending                workspacePending                 `json:"pending"`
	References             native.NativeReconstructionRefs  `json:"references"`
	Terminal               native.NativeTerminalEnvelope    `json:"terminal"`
	TerminalRef            ff.ArtifactReference             `json:"terminal_ref"`
	SignerKey              ed25519.PrivateKey               `json:"signer_key"`
	PipelineKey            ed25519.PrivateKey               `json:"pipeline_key"`
	LedgerKey              ed25519.PrivateKey               `json:"ledger_key"`
	PriorNativeAudit       native.InvocationAudit           `json:"prior_native_audit"`
	MissingTerminalRefused bool                             `json:"missing_terminal_refused"`
	ArtifactIndexSHA256    string                           `json:"artifact_index_sha256"`
}

type workspaceArtifactIndex struct {
	SchemaVersion string           `json:"schema_version"`
	RunID         string           `json:"run_id"`
	Artifacts     []model.Document `json:"artifacts"`
}

func workspaceIndexBody(run string, artifacts []model.Document) (workspaceArtifactIndex, error) {
	body := workspaceArtifactIndex{"1", run, artifacts}
	invalid := errors.New("bounded retained artifact index invalid")
	if !workspaceUUID.MatchString(run) || len(artifacts) < 9 || len(artifacts) > 4096 {
		return body, invalid
	}
	seen := map[string]bool{}
	fields := map[string]bool{"id": true, "kind": true, "plain_sha256": true, "plain_size": true, "cipher_sha256": true, "cipher_size": true, "file": true, "version_id": true}
	for _, d := range artifacts {
		id := model.String(d, "id")
		if !workspaceUUID.MatchString(id) || seen[id] || len(d) != len(fields) || model.String(d, "file") != id+".ciphertext.json" || !workspaceSHA.MatchString(model.String(d, "plain_sha256")) || !workspaceSHA.MatchString(model.String(d, "cipher_sha256")) || model.Number(d, "plain_size") < 1 || model.Number(d, "plain_size") > 16<<20 || model.Number(d, "cipher_size") < 1 || model.Number(d, "cipher_size") > 24<<20 || model.String(d, "version_id") == "" || model.String(d, "version_id") == "null" {
			return body, invalid
		}
		for k := range d {
			if !fields[k] {
				return body, invalid
			}
		}
		seen[id] = true
	}
	raw, e := json.Marshal(body)
	if e != nil || len(raw) > 128<<10 {
		return body, invalid
	}
	return body, nil
}
func workspaceRetainIndex(t *testing.T, file, run string, artifacts []model.Document) string {
	t.Helper()
	body, e := workspaceIndexBody(run, artifacts)
	if e != nil {
		t.Fatal("bounded artifact index unavailable")
	}
	sha, e := workspaceWrite(file, body)
	if e != nil {
		t.Fatal("durable artifact index unavailable")
	}
	return sha
}

func workspaceRead(file string, limit int, out any) []byte {
	info, e := os.Lstat(file)
	if e != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > int64(limit) {
		return nil
	}
	raw, e := os.ReadFile(file)
	if e != nil || len(raw) != int(info.Size()) {
		return nil
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if decoder.Decode(out) != nil || decoder.Decode(new(any)) != io.EOF {
		return nil
	}
	canonical, e := json.Marshal(out)
	if e != nil || string(canonical) != string(raw) {
		return nil
	}
	return raw
}
func workspaceWrite(file string, body any) (string, error) {
	raw, e := json.Marshal(body)
	if e != nil {
		return "", e
	}
	if len(raw) > 32<<20 {
		return "", errors.New("bounded private phase body unavailable")
	}
	f, e := os.OpenFile(file, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return "", e
	}
	if _, e = f.Write(raw); e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e != nil {
		return "", e
	}
	if closeErr != nil {
		return "", closeErr
	}
	dir, e := os.Open(filepath.Dir(file))
	if e != nil {
		return "", e
	}
	defer dir.Close()
	if e = dir.Sync(); e != nil {
		return "", e
	}
	return g.BytesDigest(raw), nil
}
func workspaceConfiguration(t *testing.T) workspaceRuntime {
	t.Helper()
	var c workspaceRuntime
	if workspaceRead(workspaceRuntimePath, 4096, &c) == nil || c.SchemaVersion != "1" || !workspaceUUID.MatchString(c.RunID) || !workspaceUUID.MatchString(c.Workspace.Generation) || !workspaceSHA.MatchString(c.Workspace.RuntimeID) || c.Workspace.ImageSHA256 != os.Getenv("FLEET_CONNECTED_IMAGE_SHA256") || len(c.ControllerPublicKey) != ed25519.PublicKeySize || !workspaceUUID.MatchString(c.ControllerKeyID) {
		t.Fatal("fixed host-inspected workspace configuration invalid")
	}
	return c
}
func workspaceArchive(t *testing.T, b workspaceBundle) *native.EncryptedArchive {
	t.Helper()
	master, e := os.ReadFile("/secrets/archive.key")
	if e != nil || len(master) != 32 {
		t.Fatal("private archive key unavailable")
	}
	keys, e := configuration.NewArtifactFixtureKeys(master)
	if e != nil {
		t.Fatal("private archive key invalid")
	}
	client := s3.New(s3.Options{Region: "eu-west-1", Credentials: credentials.NewStaticCredentialsProvider(os.Getenv("FLEET_CONNECTED_S3_USER"), os.Getenv("FLEET_CONNECTED_S3_SECRET"), ""), BaseEndpoint: &[]string{"http://minio:9000"}[0], UsePathStyle: true})
	return &native.EncryptedArchive{Client: client, Bucket: b.Prepared.Artifacts[0].Bucket, Keys: keys}
}

func workspaceControllerLogin(t *testing.T, admin *store.Store) *store.Store {
	t.Helper()
	ctx := context.Background()
	login := "connected_" + strings.ReplaceAll(model.ID(), "-", "")
	password := model.ID() + model.ID()
	if _, e := admin.Pool.Exec(ctx, "CREATE ROLE "+pgx.Identifier{login}.Sanitize()+" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '"+password+"' IN ROLE finops_group_workspace_controller"); e != nil {
		t.Fatal("dedicated controller database identity unavailable")
	}
	dsn := workspaceLoginDSN(admin.Pool.Config().ConnConfig, login, password)
	s, e := store.OpenRuntime(ctx, dsn, "group-workspace-controller")
	if e != nil {
		t.Fatal("commissioned controller login invalid")
	}
	t.Cleanup(s.Pool.Close)
	return s
}

// ConnConfig.ConnString retains the originally parsed URI. Construct a fresh
// fixture-only URI so replacing a login cannot serialize the admin identity.
func workspaceLoginDSN(config *pgx.ConnConfig, login, password string) string {
	return (&url.URL{Scheme: "postgres", User: url.UserPassword(login, password), Host: net.JoinHostPort(config.Host, strconv.Itoa(int(config.Port))), Path: "/" + config.Database, RawQuery: "sslmode=disable"}).String()
}

func workspacePrepare(t *testing.T, ctx context.Context, f *mutationReplayFixture, selected ff.Proposal, prepared ff.Preparation, archive *native.EncryptedArchive, h *connectedJournal, preparedMetadata []model.Document) {
	t.Helper()
	runtime := workspaceConfiguration(t)
	admin := connectedJournalDatabase(t, f)
	controller := workspaceControllerLogin(t, admin)
	if err := admin.Do(ctx, f.tenant, func(tx *store.Tx) error {
		if _, e := tx.Exec(ctx, `INSERT INTO public.fleet_group_workspace_keys(tenant_id,chain_id,id,profile_id,profile_generation,image_sha256,public_key) VALUES($1,$2,$3,$4,$5,$6,$7)`, f.tenant, h.bootstrap.ChainID, runtime.ControllerKeyID, selected.Profile.ID, selected.Profile.Generation, runtime.Workspace.ImageSHA256, runtime.ControllerPublicKey); e != nil {
			return e
		}
		body := struct {
			SchemaVersion string                           `json:"schema_version"`
			Workspace     native.NativeWorkspace           `json:"workspace"`
			TerminalID    string                           `json:"terminal_id"`
			Retirement    *native.NativeRetirementEnvelope `json:"retirement"`
		}{"1", runtime.Workspace, "", nil}
		raw, _ := json.Marshal(body)
		_, e := tx.Exec(ctx, `INSERT INTO public.fleet_group_workspaces(tenant_id,chain_id,generation,ordinal,runtime_id,image_sha256,key_binding_id,previous_generation,document,raw_document,content_hash) VALUES($1,$2,$3,0,$4,$5,$6,NULL,convert_from($7::bytea,'UTF8')::jsonb,$7,$8)`, f.tenant, h.bootstrap.ChainID, runtime.Workspace.Generation, runtime.Workspace.RuntimeID, runtime.Workspace.ImageSHA256, runtime.ControllerKeyID, raw, g.BytesDigest(raw))
		return e
	}); err != nil {
		t.Fatal("operator-installed zero-head runtime", err)
	}
	worker, e := native.OpenNativeStage(ctx, selected, prepared, archive)
	if e != nil {
		t.Fatal(e)
	}
	a := &connectedStageArtifacts{h: h, selected: selected, prepared: prepared, archive: archive}
	health := newConnectedHealth(t, prepared.Program)
	var pending workspacePending
	var envelope native.NativeTerminalEnvelope
	var terminalRef ff.ArtifactReference
	var refs native.NativeReconstructionRefs
	for seq := uint64(1); seq <= 2; seq++ {
		command := h.preparingForward(t, ctx, seq)
		if seq == 1 {
			health.calibrate(t, ctx, a, command.ID)
		}
		observation := model.Document{"status": "ACTUAL_BASELINE_OBSERVATION_ONLY", "baseline_refs": health.baselineRefs, "observer_binding": health.binding, "health_window_accepted": false, "customer_work_preservation_authority": false}
		pending = a.workspacePendingEffect(t, ctx, worker, command, observation, seq == 2)
		refs = workspaceIssuedReferences(t, ctx, a, pending)
		request := store.GroupNativeReconstructionRequest{Mode: native.ReconstructionObservation, WorkspaceGeneration: runtime.Workspace.Generation, CommandID: pending.Command.ID, DeliveryID: pending.Delivery.ID, AttemptID: pending.AttemptID, CaptureID: refs.Capture.ID, AfterID: refs.After.ID}
		if seq == 2 {
			called := false
			err := h.ledger.Do(ctx, f.tenant, func(tx *store.Tx) error {
				missing := request
				missing.Mode = native.ReconstructionTerminal
				missing.CaptureID = ""
				missing.AfterID = ""
				return (store.GroupNativeReconstructionAuthority{Tx: tx, Prepared: prepared, Request: missing}).WithCurrentNativeFence(ctx, h.bootstrap.ChainID, func(native.NativeReconstructionSnapshot) error { called = true; return nil })
			})
			if err == nil || called {
				t.Fatal("missing terminal yielded reconstruction authority")
			}
			if p := h.refresh(t, ctx); p.Pending == nil || p.Pending.Phase != g.JournalUnknown || !p.Pending.ApplyIntent {
				t.Fatal("missing terminal erased UNKNOWN duty")
			}
		}
		if e = h.ledger.Do(ctx, f.tenant, func(tx *store.Tx) error {
			var err error
			envelope, err = worker.ObserveNativeTerminal(ctx, store.GroupNativeReconstructionAuthority{Tx: tx, Prepared: prepared, Request: request}, h.bootstrap.ChainID, h.pipelineKey)
			return err
		}); e != nil {
			t.Fatal("positive native terminal before retirement", e)
		}
		terminalRef = a.put(t, ctx, pending.Command.ID, "NATIVE_OPERATION_PROOF", envelope)
		if e = h.pipeline.Do(ctx, f.tenant, func(tx *store.Tx) error {
			_, _, err := tx.GroupNativeTerminalAppend(ctx, h.bootstrap.ChainID, store.FleetGroupPipelineIdentity{SourceID: "connected-machine", Issuer: "https://connected-machine.invalid", Subject: "connected-pipeline", Audience: "finops-group-pipeline"}, prepared, envelope, terminalRef)
			return err
		}); e != nil {
			t.Fatal("independent versioned signed terminal publication", e)
		}
		if e = h.ledger.Do(ctx, f.tenant, func(tx *store.Tx) error {
			_, err := tx.GroupNativeTerminalSelect(ctx, h.bootstrap.ChainID, pending.Command.ID, envelope.Terminal.ID, prepared)
			return err
		}); e != nil {
			t.Fatal("immutable positive terminal selection", e)
		}
		if seq == 1 {
			h.receipt(t, ctx, g.JournalApplied, pending.Command.Before, pending.Outcome.After)
		}
	}
	p := h.refresh(t, ctx)
	if p.Pending == nil || p.Pending.Phase != g.JournalUnknown || g.Digest(p.Pending.Command) != g.Digest(pending.Command) {
		t.Fatal("pre-retirement UNKNOWN lost")
	}
	b := workspaceBundle{SchemaVersion: "1", Runtime: runtime, TenantID: f.tenant, RoleDSNs: map[string]string{"group-ledger": h.ledger.Pool.Config().ConnString(), "group-pipeline": h.pipeline.Pool.Config().ConnString(), "group-workspace-controller": controller.Pool.Config().ConnString()}, Selected: selected, Prepared: prepared, Bootstrap: h.bootstrap, Pending: pending, References: refs, Terminal: envelope, TerminalRef: terminalRef, SignerKey: h.signerKey, PipelineKey: h.pipelineKey, LedgerKey: h.ledgerKey, MissingTerminalRefused: true}
	if e = admin.Pool.QueryRow(ctx, `SELECT current_database(),shobj_description(oid,'pg_database') FROM pg_database WHERE datname=current_database()`).Scan(&b.DatabaseName, &b.DatabaseMarker); e != nil || !strings.HasPrefix(b.DatabaseName, "fixture_http_") || !strings.HasPrefix(b.DatabaseMarker, "owned-fixture-http-") {
		t.Fatal("private owned database marker unavailable")
	}
	rows, e := admin.Pool.Query(ctx, `SELECT rolname FROM pg_roles WHERE rolname~'^(fixture_api_|fixture_http_|connected_)[a-f0-9]{32}$' AND rolcanlogin AND NOT rolsuper AND NOT rolcreatedb AND NOT rolcreaterole AND NOT rolbypassrls AND NOT rolreplication ORDER BY rolname`)
	if e != nil {
		t.Fatal(e)
	}
	for rows.Next() {
		var name string
		if e = rows.Scan(&name); e != nil {
			rows.Close()
			t.Fatal(e)
		}
		b.RoleNames = append(b.RoleNames, name)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		t.Fatal(e)
	}
	for _, name := range b.RoleNames {
		if _, e = admin.Pool.Exec(ctx, "COMMENT ON ROLE "+pgx.Identifier{name}.Sanitize()+" IS 'owned-workspace-"+runtime.RunID+"'"); e != nil {
			t.Fatal("owned runtime role marker unavailable")
		}
	}
	b.PriorNativeAudit, e = native.TerraformInvocations()
	if e != nil {
		t.Fatal(e)
	}
	b.ArtifactIndexSHA256 = workspaceRetainIndex(t, "/handoff/artifact-index.json", runtime.RunID, append(append([]model.Document{}, preparedMetadata...), a.metadata...))
	hash, e := workspaceWrite(workspaceBundlePath, b)
	if e != nil {
		t.Fatal("private durable phase bundle unavailable")
	}
	ready := struct {
		SchemaVersion               string                 `json:"schema_version"`
		Status                      string                 `json:"status"`
		RunID                       string                 `json:"run_id"`
		TenantID                    string                 `json:"tenant_id"`
		ChainID                     string                 `json:"chain_id"`
		CommandID                   string                 `json:"command_id"`
		TerminalID                  string                 `json:"terminal_id"`
		OldWorkspace                native.NativeWorkspace `json:"old_workspace"`
		TerminalSHA256              string                 `json:"terminal_sha256"`
		PreparedProgramSHA256       string                 `json:"prepared_program_sha256"`
		PrivateBundleSHA256         string                 `json:"private_bundle_sha256"`
		TerraformApplyAttempts      uint64                 `json:"terraform_apply_attempts"`
		Fixture                     bool                   `json:"fixture"`
		CustomerExecutionAuthorized bool                   `json:"customer_execution_authorized"`
	}{"1", "READY_TO_RETIRE", runtime.RunID, f.tenant, h.bootstrap.ChainID, pending.Command.ID, envelope.Terminal.ID, runtime.Workspace, g.Digest(envelope), g.Digest(prepared.Program), hash, b.PriorNativeAudit.Counts["apply"], true, false}
	if _, e = workspaceWrite("/results/workspace-ready.json", ready); e != nil {
		t.Fatal("durable bounded ready receipt unavailable")
	}
	// The host must destroy this exact owned container. Returning would run the
	// fixture test cleanups and erase the durable DB needed by the replacement.
	<-ctx.Done()
	t.Fatal("host did not retire ready workspace within bounded phase lifetime")
}
func workspaceIssuedReferences(t *testing.T, ctx context.Context, a *connectedStageArtifacts, p workspacePending) native.NativeReconstructionRefs {
	t.Helper()
	refs := native.NativeReconstructionRefs{After: p.Outcome.Artifact}
	if e := a.h.ledger.Do(ctx, a.h.f.tenant, func(tx *store.Tx) error {
		d, e := tx.GroupArtifactGet(ctx, a.h.bootstrap.ChainID, p.Command.ID, "NATIVE_ARTIFACT_REVIEW", connectedCommandArtifact(p.Command).Receipt.ID)
		if e != nil {
			return e
		}
		raw, _ := json.Marshal(d["artifact"])
		if json.Unmarshal(raw, &refs.Review) != nil {
			return errors.New("selected review ref invalid")
		}
		rows, e := tx.GroupArtifactPage(ctx, a.h.bootstrap.ChainID, p.Command.ID, "NATIVE_CAPTURE", "", 101)
		if e != nil {
			return e
		}
		if len(rows) == 101 {
			return errors.New("capture selection population unavailable")
		}
		n := 0
		for _, d := range rows {
			var r ff.ArtifactReference
			raw, _ := json.Marshal(d["artifact"])
			if json.Unmarshal(raw, &r) != nil {
				return errors.New("capture registry invalid")
			}
			if r.SHA256 == g.Digest(p.Capture) {
				refs.Capture = r
				n++
			}
		}
		if n != 1 {
			return errors.New("exact capture selection ambiguous")
		}
		return nil
	}); e != nil {
		t.Fatal("server selected exact immutable native refs", e)
	}
	return refs
}

func workspaceSelectObserved(t *testing.T, ctx context.Context, a *connectedStageArtifacts, worker *native.NativeStage, pending workspacePending, runtime workspaceRuntime) (native.NativeTerminalEnvelope, ff.ArtifactReference) {
	t.Helper()
	h := a.h
	refs := workspaceIssuedReferences(t, ctx, a, pending)
	request := store.GroupNativeReconstructionRequest{Mode: native.ReconstructionObservation, WorkspaceGeneration: runtime.Workspace.Generation, CommandID: pending.Command.ID, DeliveryID: pending.Delivery.ID, AttemptID: pending.AttemptID, CaptureID: refs.Capture.ID, AfterID: refs.After.ID}
	var envelope native.NativeTerminalEnvelope
	if e := h.ledger.Do(ctx, h.f.tenant, func(tx *store.Tx) error {
		var err error
		envelope, err = worker.ObserveNativeTerminal(ctx, store.GroupNativeReconstructionAuthority{Tx: tx, Prepared: a.prepared, Request: request}, h.bootstrap.ChainID, h.pipelineKey)
		return err
	}); e != nil {
		t.Fatal("fresh current-generation inverse terminal", e)
	}
	ref := a.put(t, ctx, pending.Command.ID, "NATIVE_OPERATION_PROOF", envelope)
	if e := h.pipeline.Do(ctx, h.f.tenant, func(tx *store.Tx) error {
		_, _, err := tx.GroupNativeTerminalAppend(ctx, h.bootstrap.ChainID, store.FleetGroupPipelineIdentity{SourceID: "connected-machine", Issuer: "https://connected-machine.invalid", Subject: "connected-pipeline", Audience: "finops-group-pipeline"}, a.prepared, envelope, ref)
		return err
	}); e != nil {
		t.Fatal("fresh inverse signed terminal publication", e)
	}
	if e := h.ledger.Do(ctx, h.f.tenant, func(tx *store.Tx) error {
		_, err := tx.GroupNativeTerminalSelect(ctx, h.bootstrap.ChainID, pending.Command.ID, envelope.Terminal.ID, a.prepared)
		return err
	}); e != nil {
		t.Fatal("inverse terminal selection beforeAPPLIED", e)
	}
	return envelope, ref
}

func workspaceReconstruct(t *testing.T) {
	t.Helper()
	if os.Getuid() == 0 || os.Getenv("FLEET_CONNECTED_FIXTURE") != "ISOLATED_FIXTURE" || os.Getenv("FLEET_CONNECTED_S3_ENDPOINT") != "http://minio:9000" {
		t.Fatal("fixed replacement boundary invalid")
	}
	runtime := workspaceConfiguration(t)
	var b workspaceBundle
	bundleRaw := workspaceRead(workspaceBundlePath, 32<<20, &b)
	if bundleRaw == nil || b.SchemaVersion != "1" || runtime.RunID != b.Runtime.RunID || runtime.ControllerKeyID != b.Runtime.ControllerKeyID || !bytes.Equal(runtime.ControllerPublicKey, b.Runtime.ControllerPublicKey) || runtime.Workspace == b.Runtime.Workspace || runtime.Workspace.ImageSHA256 != b.Runtime.Workspace.ImageSHA256 || !b.MissingTerminalRefused || len(b.SignerKey) != 64 || len(b.PipelineKey) != 64 || len(b.LedgerKey) != 64 || len(b.RoleDSNs) != 3 {
		t.Fatal("private immutable phase bundle invalid")
	}
	var retirement native.NativeRetirementEnvelope
	if workspaceRead(workspaceRetirementPath, 16<<10, &retirement) == nil || retirement.Retirement.Old != b.Runtime.Workspace || retirement.Retirement.New != runtime.Workspace || retirement.Retirement.ChainID != b.Bootstrap.ChainID || retirement.Retirement.TenantID != b.TenantID {
		t.Fatal("host observed exact retirement unavailable")
	}
	entries, e := os.ReadDir("/workspace")
	if e != nil || len(entries) != 0 {
		t.Fatal("replacement workspace must be empty")
	}
	auditAbsent := func() bool { _, e := os.Lstat("/workspace/private/native-invocations.jsonl"); return os.IsNotExist(e) }
	if !auditAbsent() {
		t.Fatal("fresh workspace already contains native dispatch audit")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	stores := map[string]*store.Store{}
	for _, mode := range []string{"group-ledger", "group-pipeline", "group-workspace-controller"} {
		s, e := store.OpenRuntime(ctx, b.RoleDSNs[mode], mode)
		if e != nil {
			t.Fatal("dedicated replacement database identity invalid")
		}
		stores[mode] = s
		t.Cleanup(s.Pool.Close)
	}
	f := &mutationReplayFixture{t: t, tenant: b.TenantID}
	h := &connectedJournal{f: f, ledger: stores["group-ledger"], pipeline: stores["group-pipeline"], bootstrap: b.Bootstrap, signerKey: b.SignerKey, pipelineKey: b.PipelineKey, ledgerKey: b.LedgerKey}
	h.refresh(t, ctx)
	if e = stores["group-workspace-controller"].Do(ctx, b.TenantID, func(tx *store.Tx) error {
		_, err := tx.GroupNativeWorkspaceActivate(ctx, b.Bootstrap.ChainID, runtime.ControllerKeyID, b.Terminal.Terminal.ID, b.Prepared, retirement)
		return err
	}); e != nil {
		t.Fatal("commissioned actual replacement generation activation", e)
	}
	request := store.GroupNativeReconstructionRequest{Mode: native.ReconstructionTerminal, WorkspaceGeneration: runtime.Workspace.Generation, CommandID: b.Pending.Command.ID, DeliveryID: b.Pending.Delivery.ID, AttemptID: b.Pending.AttemptID}
	oldCalled := false
	e = h.ledger.Do(ctx, b.TenantID, func(tx *store.Tx) error {
		old := request
		old.WorkspaceGeneration = b.Runtime.Workspace.Generation
		return (store.GroupNativeReconstructionAuthority{Tx: tx, Prepared: b.Prepared, Request: old}).WithCurrentNativeFence(ctx, b.Bootstrap.ChainID, func(native.NativeReconstructionSnapshot) error { oldCalled = true; return nil })
	})
	if e == nil || oldCalled {
		t.Fatal("retired workspace regained current authority")
	}
	archive := workspaceArchive(t, b)
	var worker *native.NativeStage
	if e = h.ledger.Do(ctx, b.TenantID, func(tx *store.Tx) error {
		var err error
		worker, err = native.ReconstructNativeWorkspace(ctx, store.GroupNativeReconstructionAuthority{Tx: tx, Prepared: b.Prepared, Request: request}, b.Bootstrap.ChainID, archive)
		return err
	}); e != nil {
		t.Fatal("authenticated empty-workspace reconstruction", e)
	}
	if worker == nil || !auditAbsent() {
		t.Fatal("reconstruction launched Terraform or lost materialization")
	}
	outcome, e := worker.Outcome(ctx, b.Pending.Command)
	if e != nil || outcome.After != b.Terminal.Terminal.After || outcome.Artifact != b.References.After {
		t.Fatal("reconstructed positive outcome unavailable", e)
	}
	inspected, e := worker.Inspect(ctx, outcome.After.Revision, outcome.After.Model)
	if e != nil || inspected != outcome.After {
		t.Fatal("reconstructed current native state differs", e)
	}
	// Retained old delivery permission cannot become a new apply. Historical
	// reconstruction grants observation only and UNKNOWN remains dispatched duty.
	refused := false
	if e = h.ledger.Do(ctx, b.TenantID, func(tx *store.Tx) error {
		return (store.GroupNativeReconstructionAuthority{Tx: tx, Prepared: b.Prepared, Request: request}).WithCurrentNativeFence(ctx, b.Bootstrap.ChainID, func(s native.NativeReconstructionSnapshot) error {
			_, err := worker.Apply(ctx, s.View, s.Keys, b.Pending.Permit, b.Pending.Capture)
			refused = err != nil
			if !refused {
				return errors.New("old apply permit redispatched")
			}
			return nil
		})
	}); e != nil || !refused || !auditAbsent() {
		t.Fatal("old apply permission revived after runtime loss", e)
	}
	reopened, e := native.OpenNativeStage(ctx, b.Selected, b.Prepared, archive)
	if e != nil {
		t.Fatal(e)
	}
	again, e := reopened.Outcome(ctx, b.Pending.Command)
	if e != nil || again != outcome || !auditAbsent() {
		t.Fatal("outcome reopen re-applied or changed facts", e)
	}
	// Positive033 selection was committed before destruction. Only now is the
	// previously UNKNOWN operation reconciled, with zero new Terraform command.
	h.receipt(t, ctx, g.JournalApplied, b.Pending.Command.Before, outcome.After)
	p := h.refresh(t, ctx)
	if p.Pending != nil || len(p.Stack) != 1 || p.Current != outcome.After || len(p.Consumed) != 0 {
		t.Fatal("reconciled owned effect was lost or consumed")
	}
	if e = h.pipeline.Do(ctx, b.TenantID, func(tx *store.Tx) error {
		_, replay, err := tx.GroupNativeTerminalAppend(ctx, b.Bootstrap.ChainID, store.FleetGroupPipelineIdentity{SourceID: "connected-machine", Issuer: "https://connected-machine.invalid", Subject: "connected-pipeline", Audience: "finops-group-pipeline"}, b.Prepared, b.Terminal, b.TerminalRef)
		if err == nil && !replay {
			return errors.New("terminal replay appended new fact")
		}
		return err
	}); e != nil {
		t.Fatal("immutable positive terminal replay", e)
	}
	if !auditAbsent() {
		t.Fatal("reconciliation launched Terraform")
	}
	// The reconstruction-only zero-invocation boundary ends here. The next
	// separately claimed recovery creates a NEW commit and saved plan; it is
	// neither a retry of the unknown apply nor a fabricated health completion.
	var retained workspaceArtifactIndex
	indexRaw := workspaceRead("/handoff/artifact-index.json", 128<<10, &retained)
	if indexRaw == nil || retained.SchemaVersion != "1" || retained.RunID != runtime.RunID || g.BytesDigest(indexRaw) != b.ArtifactIndexSHA256 {
		t.Fatal("retained pre-loss ciphertext index differs")
	}
	a := &connectedStageArtifacts{h: h, selected: b.Selected, prepared: b.Prepared, archive: archive}
	inverseCommand := h.preparingInverse(t, ctx, reopened)
	health := newConnectedHealth(t, b.Prepared.Program)
	observation := health.currentRecovery(t, ctx, a, inverseCommand)
	inverse := a.workspacePendingEffect(t, ctx, reopened, inverseCommand, observation, false)
	inverseTerminal, inverseRef := workspaceSelectObserved(t, ctx, a, reopened, inverse, runtime)
	h.receipt(t, ctx, g.JournalApplied, inverse.Command.Before, inverse.Outcome.After)
	restored := h.refresh(t, ctx)
	if restored.Pending != nil || len(restored.Stack) != 0 || len(restored.Consumed) != 1 || restored.Current.Model != b.Prepared.JournalReview.Base.Model || restored.Current.Revision.Commit == b.Pending.Command.Preparation.Revision.Commit {
		t.Fatal("fresh owned inverse did not restore exact model and consumeLIFO")
	}
	recoveryAudit, e := native.TerraformInvocations()
	if e != nil || recoveryAudit.Counts["apply"] != 1 || recoveryAudit.Counts["plan"] != 1 || recoveryAudit.Counts["show"] != 1 || recoveryAudit.Total != 3 {
		t.Fatal("replacement must execute only one newly authorized inverse", e)
	}
	indexSHA := workspaceRetainIndex(t, "/results/reconstruction-artifact-index.json", runtime.RunID, append(append([]model.Document{}, retained.Artifacts...), a.metadata...))
	var held bool
	if e = h.ledger.Do(ctx, b.TenantID, func(tx *store.Tx) error {
		return tx.QueryRow(ctx, `SELECT released_at IS NULL FROM public.fleet_group_journal_reservations WHERE tenant_id=$1 AND chain_id=$2`, tx.Tenant, b.Bootstrap.ChainID).Scan(&held)
	}); e != nil || !held {
		t.Fatal("owned restoration reservation was released", e)
	}
	result := model.Document{"schema_version": "1", "status": "PASS", "run_id": runtime.RunID, "tenant_id": b.TenantID, "chain_id": b.Bootstrap.ChainID, "command_id": b.Pending.Command.ID, "terminal_id": b.Terminal.Terminal.ID, "terminal_sha256": g.Digest(b.Terminal), "prepared_program_sha256": g.Digest(b.Prepared.Program), "private_bundle_sha256": g.BytesDigest(bundleRaw), "old_workspace": b.Runtime.Workspace, "new_workspace": runtime.Workspace, "reconstructed_state_sha256": outcome.After.StateSHA256, "reconstructed_outcome_sha256": g.Digest(outcome), "reconstructed_without_terraform": true, "reconstruction_terraform_invocation_delta": 0, "reconstruction_native_audit_absent": true, "old_generation_refused": true, "old_apply_permit_refused": true, "missing_terminal_remained_unknown": b.MissingTerminalRefused, "unknown_reconciled_from_selected_positive_terminal": true, "outcome_reopen_without_reapply": true, "reconciled_owned_effects": len(p.Stack), "fresh_owned_inverse_command_id": inverse.Command.ID, "inverse_terminal_id": inverseTerminal.Terminal.ID, "inverse_terminal_sha256": g.Digest(inverseTerminal), "inverse_terminal_ref": inverseRef, "restored_state_sha256": restored.Current.StateSHA256, "restored_owned_effects": len(restored.Stack), "consumed_owned_effects": len(restored.Consumed), "restored_original_model": true, "post_reconstruction_recovery_invocations": recoveryAudit, "reconstruction_artifact_index_sha256": indexSHA, "terminal_health_pending": true, "reservation_held": held, "fixture": true, "customer_execution_authorized": false, "verified_saving": nil, "repeated_replacement_without_new_terminal_supported": false, "full_recovery_health_accepted": false}
	if _, e = workspaceWrite("/results/workspace-reconstructed.json", result); e != nil {
		t.Fatal("bounded reconstruction acceptance write failed")
	}
}
func workspaceCleanup(t *testing.T) {
	t.Helper()
	if os.Getuid() == 0 || os.Getenv("FLEET_CONNECTED_FIXTURE") != "ISOLATED_FIXTURE" {
		t.Fatal("fixed isolated cleanup boundary required")
	}
	runtime := workspaceConfiguration(t)
	var b workspaceBundle
	if workspaceRead(workspaceBundlePath, 32<<20, &b) == nil || b.SchemaVersion != "1" || runtime.RunID != b.Runtime.RunID || !strings.HasPrefix(b.DatabaseName, "fixture_http_") || !strings.HasPrefix(b.DatabaseMarker, "owned-fixture-http-") || len(b.RoleNames) > 16 {
		t.Fatal("owned cleanup bundle invalid")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cfg, e := pgx.ParseConfig(os.Getenv("TEST_DATABASE_URL"))
	if e != nil || cfg.Host != "postgres" || cfg.Database != "postgres" || cfg.User != "postgres" || len(cfg.RuntimeParams) != 0 {
		t.Fatal("fixed isolated cleanup administrator required")
	}
	admin, e := pgx.ConnectConfig(ctx, cfg)
	if e != nil {
		t.Fatal("isolated cleanup unavailable")
	}
	defer admin.Close(context.Background())
	var marker string
	if e = admin.QueryRow(ctx, `SELECT shobj_description(oid,'pg_database') FROM pg_database WHERE datname=$1`, b.DatabaseName).Scan(&marker); e != nil || marker != b.DatabaseMarker {
		t.Fatal("cleanup database ownership mismatch")
	}
	if _, e = admin.Exec(ctx, `SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname=$1 AND pid<>pg_backend_pid()`, b.DatabaseName); e != nil {
		t.Fatal("owned database connections could not close")
	}
	if _, e = admin.Exec(ctx, "DROP DATABASE "+pgx.Identifier{b.DatabaseName}.Sanitize()); e != nil {
		t.Fatal("owned database cleanup failed")
	}
	rolePattern := regexp.MustCompile(`^(fixture_api_|fixture_http_|connected_)[a-f0-9]{32}$`)
	for _, name := range b.RoleNames {
		if !rolePattern.MatchString(name) {
			t.Fatal("cleanup role outside exact fixture namespace")
		}
		var note string
		var safe bool
		if e = admin.QueryRow(ctx, `SELECT coalesce(shobj_description(oid,'pg_authid'),''),NOT rolsuper AND NOT rolcreatedb AND NOT rolcreaterole AND NOT rolbypassrls AND NOT rolreplication FROM pg_roles WHERE rolname=$1`, name).Scan(&note, &safe); e != nil || !safe || note != "owned-workspace-"+runtime.RunID {
			t.Fatal("cleanup role ownership mismatch")
		}
		if _, e = admin.Exec(ctx, "DROP ROLE "+pgx.Identifier{name}.Sanitize()); e != nil {
			t.Fatal("owned role cleanup failed")
		}
	}
	if _, e = workspaceWrite("/results/workspace-cleanup.json", model.Document{"schema_version": "1", "status": "PASS", "run_id": runtime.RunID, "owned_database_dropped": true, "owned_roles_dropped": len(b.RoleNames), "fixture": true}); e != nil {
		t.Fatal("bounded cleanup receipt unavailable")
	}
}

// Keep the public-key transport canonical; no worker config accepts a private
// controller key, raw retirement authority flag, path or arbitrary command.
func TestWorkspaceRuntimePublicKeyEncodingAndUnknownFields(t *testing.T) {
	key := ed25519.NewKeyFromSeed(make([]byte, 32)).Public().(ed25519.PublicKey)
	raw, _ := json.Marshal(workspaceRuntime{SchemaVersion: "1", ControllerPublicKey: key})
	var d map[string]any
	_ = json.Unmarshal(raw, &d)
	if d["controller_public_key"] != base64.StdEncoding.EncodeToString(key) {
		t.Fatal("cross-language public key encoding changed")
	}
}

func TestWorkspaceLoginDSNUsesFreshRestrictedIdentity(t *testing.T) {
	admin, e := pgx.ParseConfig("postgres://postgres:original-admin@postgres:5544/fixture_http_123?sslmode=disable")
	if e != nil {
		t.Fatal(e)
	}
	admin.User = "changed-but-cached"
	admin.Password = "changed-but-cached"
	login, password := "connected_123", "private@password:/?"
	dsn := workspaceLoginDSN(admin, login, password)
	parsed, e := pgx.ParseConfig(dsn)
	if e != nil || parsed.User != login || parsed.Password != password || parsed.Host != admin.Host || parsed.Port != admin.Port || parsed.Database != admin.Database || parsed.ConnString() != dsn {
		t.Fatal("fresh restricted login did not survive URI serialization")
	}
	if strings.Contains(dsn, "original-admin") || strings.Contains(dsn, "changed-but-cached") {
		t.Fatal("original administrator identity leaked into restricted login")
	}
}

func TestWorkspacePhaseFilesRejectAmbiguityAndChangingDurableBody(t *testing.T) {
	directory := t.TempDir()
	file := filepath.Join(directory, "runtime.json")
	original := workspaceRuntime{SchemaVersion: "1", RunID: "11111111-2222-3333-4444-555555555555", Workspace: native.NativeWorkspace{Generation: "21111111-2222-3333-4444-555555555555", RuntimeID: strings.Repeat("a", 64), ImageSHA256: strings.Repeat("b", 64)}, ControllerKeyID: "31111111-2222-3333-4444-555555555555", ControllerPublicKey: ed25519.NewKeyFromSeed(make([]byte, 32)).Public().(ed25519.PublicKey)}
	hash, e := workspaceWrite(file, original)
	if e != nil {
		t.Fatal(e)
	}
	var decoded workspaceRuntime
	raw := workspaceRead(file, 4096, &decoded)
	if raw == nil || g.BytesDigest(raw) != hash || decoded.RunID != original.RunID || !bytes.Equal(decoded.ControllerPublicKey, original.ControllerPublicKey) {
		t.Fatal("durable private phase bytes changed")
	}
	if _, e = workspaceWrite(file, original); e == nil {
		t.Fatal("immutable handoff overwritten")
	}
	for _, invalid := range []string{`{"schema_version":"1","schema_version":"2"}`, `{"schema_version":"1","controller_private_key":"forbidden"}`, `{} {}`, strings.Repeat("x", 4097)} {
		if e = os.WriteFile(file, []byte(invalid), 0600); e != nil {
			t.Fatal(e)
		}
		var d workspaceRuntime
		if workspaceRead(file, 4096, &d) != nil {
			t.Fatal("ambiguous/private/oversize phase input accepted")
		}
	}
	target := filepath.Join(directory, "target")
	if e = os.WriteFile(target, []byte(`{}`), 0600); e != nil {
		t.Fatal(e)
	}
	link := filepath.Join(directory, "link")
	if e = os.Symlink(target, link); e == nil {
		var d workspaceRuntime
		if workspaceRead(link, 4096, &d) != nil {
			t.Fatal("symbolic link handoff accepted")
		}
	}
}

func TestWorkspaceArtifactRetentionRefusesDuplicatesAndNonMetadata(t *testing.T) {
	run := "11111111-2222-3333-4444-555555555555"
	artifacts := []model.Document{}
	for i := 0; i < 9; i++ {
		id := fmt.Sprintf("%08x-2222-3333-4444-555555555555", i)
		artifacts = append(artifacts, model.Document{"id": id, "kind": "FIXTURE_HISTORY", "plain_sha256": strings.Repeat("a", 64), "plain_size": 16, "cipher_sha256": strings.Repeat("b", 64), "cipher_size": 128, "file": id + ".ciphertext.json", "version_id": "pinned-version"})
	}
	if _, e := workspaceIndexBody(run, artifacts); e != nil {
		t.Fatal(e)
	}
	copied := append([]model.Document{}, artifacts...)
	copied = append(copied, artifacts[0])
	if _, e := workspaceIndexBody(run, copied); e == nil {
		t.Fatal("duplicate artifact ID silently discarded")
	}
	raw, _ := json.Marshal(artifacts)
	var unknown []model.Document
	_ = json.Unmarshal(raw, &unknown)
	unknown[0]["plaintext"] = "forbidden"
	if _, e := workspaceIndexBody(run, unknown); e == nil {
		t.Fatal("artifact index accepted nonmetadata body")
	}
}
