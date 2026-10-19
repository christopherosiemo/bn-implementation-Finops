package service

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/configuration"
	ff "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetfixture"
	g "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetgroup"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/groupfixtureproducer"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/source"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
)

// This test requires the dedicated native fixture runner. Native Git/Terraform,
// PostgreSQL, versioned S3, ciphertext and JWT validation are real. Registered
// AWS identities are explicit local dependency fixtures; their missing customer
// history remains BLOCKED and is never replaced by the installed fixture model.
func TestFleetGroupConnectedNativePreparationAndIndependentApproval(t *testing.T) {
	connectedDriverStart(t)
	if os.Getenv("FLEET_CONNECTED_FIXTURE") != "ISOLATED_FIXTURE" {
		t.Skip("requires the owned connected native fixture runner")
	}
	if os.Getuid() == 0 || os.Getenv("FLEET_CONNECTED_S3_ENDPOINT") != "http://minio:9000" || len(os.Getenv("FLEET_CONNECTED_IMAGE_SHA256")) != 64 {
		t.Fatal("fixed nonroot native fixture boundary required")
	}
	protocolBudget := 3 * time.Minute
	if os.Getenv("FLEET_CONNECTED_NATIVE_RUNTIME") == "1" {
		protocolBudget = 30 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), protocolBudget)
	defer cancel()
	defer func() {
		if ctx.Err() == context.DeadlineExceeded {
			connectedDriverMark("", "CONTEXT_EXPIRED")
		}
	}()
	ready := false
	for attempt := 0; attempt < 40; attempt++ {
		req, e := http.NewRequestWithContext(ctx, http.MethodGet, "http://minio:9000/minio/health/ready", nil)
		if e != nil {
			t.Fatal(e)
		}
		response, e := (&http.Client{Timeout: time.Second}).Do(req)
		if e == nil {
			_ = response.Body.Close()
			ready = response.StatusCode == http.StatusOK
		}
		if ready {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("owned MinIO readiness timed out")
		case <-time.After(500 * time.Millisecond):
		}
	}
	if !ready {
		t.Fatal("owned MinIO did not become ready")
	}
	f, producer := newFleetFixtureHTTPTest(t)
	platform := f.token(f.tenant, "connected-creator", "PLATFORM_ADMIN")
	approver := f.token(f.tenant, "connected-independent-approver", "APPROVER")
	get := func(path, token string) (int, model.Document) {
		t.Helper()
		r := httptest.NewRequest(http.MethodGet, "/v1/"+path, nil)
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		f.api.ServeHTTP(w, r)
		var out model.Document
		if json.Unmarshal(w.Body.Bytes(), &out) != nil {
			t.Fatal("invalid JSON response", w.Code)
		}
		return w.Code, out
	}
	var profile ff.Profile
	if err := producer.Do(ctx, f.tenant, func(tx *store.Tx) error {
		var err error
		profile, err = tx.FleetFixtureProfileInstall(ctx, ff.Installation{TemplateID: "builtin-group-fixture-v1", ToolchainImageSHA256: os.Getenv("FLEET_CONNECTED_IMAGE_SHA256"), TerraformVersion: "1.16.0", ReceiptID: "inspected-local-tooling-" + model.ID(), SourceSHA256: os.Getenv("FLEET_CONNECTED_SOURCE_SHA256")})
		return err
	}); err != nil {
		t.Fatal("private inspected installation", err)
	}
	activity := store.ActivitySource{ID: "connected-completed", WorkloadID: "fixture-workload", ResourceID: "connected-external-work", ProviderResourceID: "i-aaaaaaaaaaaaaaaaa", AccountID: "111122223333", Region: "eu-west-1", Issuer: "https://isolated-machine.invalid", Subject: "completed-work-collector", MetricDefinition: store.ActivityMetric{ID: "orders", Version: "1", Unit: "completed_orders"}, Enabled: true}
	src := source.FixtureRegistration(f.tenant, "connected-native")
	if err := f.roles["api"].Do(ctx, f.tenant, func(tx *store.Tx) error {
		if _, err := tx.Create(ctx, "resources", model.Document{"id": activity.ResourceID, "workload_id": activity.WorkloadID, "provider": "AWS", "provider_resource_id": activity.ProviderResourceID, "account_id": activity.AccountID, "region": activity.Region}); err != nil {
			return err
		}
		if _, err := tx.SourceCreate(ctx, src); err != nil {
			return err
		}
		_, err := tx.ActivityRegister(ctx, activity)
		return err
	}); err != nil {
		t.Fatal("guarded local source registration", err)
	}
	if err := f.roles["ingester"].Do(ctx, f.tenant, func(tx *store.Tx) error {
		return tx.SourceCheckpointSet(ctx, "connected-native", "status", model.Document{"status": "HEALTHY", "config_hash": source.ConfigurationHash(src), "last_sync_at": time.Now().UTC().Format(time.RFC3339Nano)})
	}); err != nil {
		t.Fatal(err)
	}
	configurationIDs := []string{}
	for index, name := range []string{"old", "candidate"} {
		code, reg, _ := f.request("fleet-history-registrations", `"0"`, "connected-registration-"+name, platform, model.Document{"workload_id": activity.WorkloadID, "fleet_id": "connected-" + name, "asg_arn": "arn:aws:autoscaling:eu-west-1:111122223333:autoScalingGroup:" + []string{"11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222"}[index] + ":autoScalingGroupName/connected-" + name, "source_connection_id": "connected-native", "cadence_seconds": 60, "max_gap_seconds": 120})
		if code != 201 {
			t.Fatal("registration", code, reg)
		}
		code, definition, _ := f.request("fleet-demand-definitions", `"0"`, "connected-definition-"+name, platform, model.Document{"registration_id": reg["id"], "activity_source_id": activity.ID, "business_operation": "declared completed orders", "semantic_contract_id": "orders-v1", "semantic_contract_hash": strings.Repeat("c", 64)})
		if code != 201 {
			t.Fatal("definition", code, definition)
		}
		code, scope, _ := f.request("fleet-history-scopes", `"1"`, "connected-scope-"+name, platform, model.Document{"registration_id": reg["id"], "definition_id": definition["id"], "definition_version": 1})
		if code != 201 || model.String(scope, "status") != "BLOCKED" {
			t.Fatal("missing native history must remain blocked", code, scope)
		}
		base := "fleet-history-registrations/" + model.String(reg, "id")
		metadata := model.Document{"schema_version": "1", "authority": "TERRAFORM", "repository": model.Document{"url": "https://git.example.invalid/connected.git", "ref": "refs/heads/declared", "directory": "infra"}, "pipeline": model.Document{"system": "GITHUB_ACTIONS", "identity": model.Document{"issuer": "https://token.actions.githubusercontent.com", "audience": "finops-deployment-observer", "subject": "repo:fixture/connected:ref:refs/heads/declared", "pipeline_id": "declared-customer-pipeline"}}, "terraform": model.Document{"workspace": "development", "state_lineage": "12345678-1234-1234-1234-123456789abc", "asg_address": "aws_autoscaling_group." + name, "launch_template_address": "aws_launch_template." + name, "traffic": model.Document{"listener_rule_address": "aws_lb_listener_rule.app", "target_group_addresses": []string{"aws_lb_target_group.old", "aws_lb_target_group.candidate"}}}}
		code, declaration, _ := f.request(base+"/configuration-authorities", `"0"`, "connected-declaration-"+name, platform, metadata)
		if code != 201 {
			t.Fatal("group declaration", code, declaration)
		}
		code, proposal, _ := f.request(base+"/configuration-proposals", `"1"`, "connected-configuration-"+name, platform, model.Document{"declaration_id": declaration["id"], "scope_id": scope["id"]})
		if code != 201 || model.String(proposal, "status") != "BLOCKED" || proposal["execution_authorized"] != false {
			t.Fatal("group proposal authority", code, proposal)
		}
		configurationIDs = append(configurationIDs, model.String(proposal, "id"))
	}
	selection := model.Document{"old_configuration_proposal_id": configurationIDs[0], "candidate_configuration_proposal_id": configurationIDs[1], "fixture_profile_id": profile.ID}
	code, selectedDoc, _ := f.request("fleet-fixture-proposals", `"0"`, "connected-select", platform, selection)
	if code != 201 || model.String(selectedDoc, "status") != "WAITING_FOR_PROGRAM" {
		t.Fatal("real ID-only selection", code, selectedDoc)
	}
	selected, err := store.FleetFixtureProposalDocument(selectedDoc)
	if err != nil {
		t.Fatal(err)
	}
	id := selected.ID
	if code, _, _ := f.request("fleet-fixture-proposals/"+id+"/approvals", `"1"`, "connected-unprepared-approval", approver, model.Document{}); code != 409 {
		t.Fatal("approved unprepared program", code)
	}
	var mapping g.ModelMapping
	if err = producer.Do(ctx, f.tenant, func(tx *store.Tx) error { var e error; mapping, e = tx.FleetFixtureMapping(ctx, id); return e }); err != nil {
		t.Fatal(err)
	}
	client := s3.New(s3.Options{Region: "eu-west-1", Credentials: credentials.NewStaticCredentialsProvider(os.Getenv("FLEET_CONNECTED_S3_USER"), os.Getenv("FLEET_CONNECTED_S3_SECRET"), ""), BaseEndpoint: aws.String("http://minio:9000"), UsePathStyle: true})
	bucket := "connected-" + strings.ReplaceAll(model.ID(), "-", "")
	if _, err = client.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(bucket)}); err != nil {
		t.Fatal("actual owned S3 bucket", err)
	}
	if _, err = client.PutBucketVersioning(ctx, &s3.PutBucketVersioningInput{Bucket: aws.String(bucket), VersioningConfiguration: &types.VersioningConfiguration{Status: types.BucketVersioningStatusEnabled}}); err != nil {
		t.Fatal(err)
	}
	master, err := os.ReadFile("/secrets/archive.key")
	if err != nil || len(master) != 32 {
		t.Fatal("private fixture archive key required")
	}
	keys, err := configuration.NewArtifactFixtureKeys(master)
	if err != nil {
		t.Fatal(err)
	}
	archive := &groupfixtureproducer.EncryptedArchive{Client: client, Bucket: bucket, Keys: keys}
	pipeline, pipelineKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ledger, ledgerKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := groupfixtureproducer.Prepare(ctx, selected, groupfixtureproducer.Installation{ImageSHA256: os.Getenv("FLEET_CONNECTED_IMAGE_SHA256"), Mapping: mapping, PipelineKey: pipeline, LedgerKey: ledger}, archive)
	if err != nil {
		t.Fatal("actual Git/Terraform preparation", err)
	}
	if len(prepared.GitProofs) != 26 || prepared.JournalReview.Base.StateSerial == 0 || prepared.JournalReview.Base.StateSHA256 == "" {
		t.Fatal("native base/manifest missing")
	}
	proofRaw, _ := ff.ProofBytes(prepared.GitProofs)
	artifactMetadata := []model.Document{}
	for _, ref := range prepared.Artifacts {
		kind := ""
		for _, e := range prepared.Program.Evidence {
			if e.ID == ref.ID {
				kind = e.Kind
			}
		}
		if ref.SHA256 == g.BytesDigest(proofRaw) {
			kind = "GIT_PROOF_SET"
		}
		if ref.SHA256 == prepared.JournalReview.Base.StateSHA256 {
			kind = "BASE_NATIVE_STATE"
		}
		if kind == "" {
			t.Fatal("unbound artifact")
		}
		plain, e := archive.Read(ctx, selected, kind, ref)
		if e != nil || g.BytesDigest(plain) != ref.SHA256 {
			t.Fatal("authenticated object readback", e)
		}
		object, e := client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String(ref.Key), VersionId: aws.String(ref.VersionID)})
		if e != nil {
			t.Fatal(e)
		}
		cipher, e := io.ReadAll(io.LimitReader(object.Body, 24<<20+1))
		_ = object.Body.Close()
		if e != nil || len(cipher) > 24<<20 || bytes.Contains(cipher, plain) {
			t.Fatal("plaintext escaped archive")
		}
		name := ref.ID + ".ciphertext.json"
		if e = os.WriteFile(filepath.Join("/results", name), cipher, 0600); e != nil {
			t.Fatal(e)
		}
		artifactMetadata = append(artifactMetadata, model.Document{"id": ref.ID, "kind": kind, "plain_sha256": ref.SHA256, "plain_size": ref.SizeBytes, "cipher_sha256": g.BytesDigest(cipher), "cipher_size": len(cipher), "file": name, "version_id": ref.VersionID})
		if kind == "BASE_NATIVE_STATE" {
			// A later object version cannot replace the already pinned native state.
			if _, e = client.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(bucket), Key: aws.String(ref.Key), Body: bytes.NewReader([]byte("corrupted latest fixture version"))}); e != nil {
				t.Fatal(e)
			}
			if pinned, e := archive.Read(ctx, selected, kind, ref); e != nil || !bytes.Equal(pinned, plain) {
				t.Fatal("latest overwrite replaced pinned bytes", e)
			}
			bad := ref
			bad.VersionID = "missing-version"
			if _, e = archive.Read(ctx, selected, kind, bad); e == nil {
				t.Fatal("missing object version accepted")
			}
			wrongKey, _ := configuration.NewArtifactFixtureKeys(bytes.Repeat([]byte{0x71}, 32))
			if _, e = (&groupfixtureproducer.EncryptedArchive{Client: client, Bucket: bucket, Keys: wrongKey}).Read(ctx, selected, kind, ref); e == nil {
				t.Fatal("wrong archive key accepted")
			}
		}
	}
	if len(artifactMetadata) != 9 {
		t.Fatal("all nine artifacts must be authenticated")
	}
	var preparedRow model.Document
	if err = producer.Do(ctx, f.tenant, func(tx *store.Tx) error {
		var e error
		preparedRow, e = tx.FleetFixturePreparedProgramAppend(ctx, id, prepared)
		return e
	}); err != nil {
		t.Fatal("private prepared publication", err)
	}
	if err = f.roles["api"].Do(ctx, f.tenant, func(tx *store.Tx) error { _, e := tx.FleetFixturePreparedProgramAppend(ctx, id, prepared); return e }); err == nil {
		t.Fatal("API acquired preparation write authority")
	}
	connectedDriverMark("APPROVAL", "")
	path := "fleet-fixture-proposals/" + id + "/approvals"
	if code, _, _ := f.request(path, `"2"`, "connected-self", f.token(f.tenant, "connected-creator", "APPROVER"), model.Document{}); code != 403 {
		t.Fatal("self approval", code)
	}
	if code, _, _ := f.request(path, `"1"`, "connected-stale", approver, model.Document{}); code != 409 {
		t.Fatal("stale approval", code)
	}
	code, approved, tag := f.request(path, `"2"`, "connected-approve", approver, model.Document{})
	if code != 201 || tag != `"3"` || model.String(approved, "status") != "APPROVED" {
		t.Fatal("independent exact program approval", code, approved)
	}
	approval := source.Object(approved["approval"])
	if model.String(approval, "program_hash") != g.Digest(prepared.Program) || model.String(approval, "manifest_hash") != prepared.Program.ManifestSHA256 || model.String(approval, "journal_review_hash") != g.Digest(prepared.JournalReview) {
		t.Fatal("approval changed exact reviewed bytes")
	}
	audit, outbox := f.counts()
	if code, again, _ := f.request(path, `"2"`, "connected-approve", approver, model.Document{}); code != 201 || model.String(again, "id") != id {
		t.Fatal("exact approval replay", code)
	}
	if a, b := f.counts(); a != audit || b != outbox {
		t.Fatal("approval replay repeated audit/outbox")
	}
	if code, _, _ := f.request(path, `"2"`, "connected-approve", f.token(f.tenant, "connected-independent-approver", "VIEWER"), model.Document{}); code != 403 {
		t.Fatal("cached approval borrowed prior role", code)
	}
	if code, _ := get("fleet-fixture-proposals/"+id, f.token(f.tenant+"-other", "viewer", "VIEWER")); code != 404 {
		t.Fatal("cross tenant proposal", code)
	}
	if code, review := get("fleet-fixture-proposals/"+id+"/prepared-program", platform); code != 200 || review["artifact_refs"] != nil || review["git_proofs"] != nil {
		t.Fatal("public raw artifact exposure", code)
	}
	if code, readiness := get("fleet-fixture-proposals/"+id+"/readiness", platform); code != 200 || readiness["customer_execution_authorized"] != false || readiness["verified_saving"] != nil {
		t.Fatal("fixture approval promoted customer authority", code)
	}
	connectedDriverMark("BOOTSTRAP", "")
	journal := connectedJournalBootstrap(t, ctx, f, selected, prepared, preparedRow, approved, pipelineKey, ledgerKey)
	if journal.cursor.RecordCount != 0 {
		t.Fatal("approval/bootstrap dispatched a command")
	}
	var runtimeEvidence model.Document
	if os.Getenv("FLEET_CONNECTED_NATIVE_RUNTIME") == "1" {
		var nativeArtifacts []model.Document
		runtimeEvidence, nativeArtifacts = connectedNativeOperatingLoop(t, ctx, journal, selected, prepared, archive)
		artifactMetadata = append(artifactMetadata, nativeArtifacts...)
	}
	if err = f.roles["api"].Do(ctx, f.tenant, func(tx *store.Tx) error {
		s, e := tx.SourceGet(ctx, "connected-native")
		if e != nil {
			return e
		}
		s["enabled"] = false
		_, e = tx.SourceUpdate(ctx, "connected-native", model.Number(s, "version"), s)
		return e
	}); err != nil {
		t.Fatal(err)
	}
	if err = producer.Do(ctx, f.tenant, func(tx *store.Tx) error { _, e := tx.FleetFixturePreparedProgramAppend(ctx, id, prepared); return e }); err == nil {
		t.Fatal("revocation permitted new prepared publication")
	}
	if code, old := get("fleet-fixture-proposals/"+id, platform); code != 200 || model.String(old, "status") != "APPROVED" {
		t.Fatal("revocation rewrote immutable approval", code)
	}
	result := model.Document{"schema_version": "1", "status": "PASS", "realm": "ISOLATED_FIXTURE", "actual_git_manifest_entries": 26, "terraform_version": "1.16.0", "native_base_state_serial": prepared.JournalReview.Base.StateSerial, "native_base_state_sha256": prepared.JournalReview.Base.StateSHA256, "program_sha256": g.Digest(prepared.Program), "manifest_sha256": prepared.Program.ManifestSHA256, "independent_jwt_approval_persisted": true, "independent_journal_and_continuation_http_approvals_persisted": true, "commissioned_distinct_key_registry": true, "durable_zero_command_bootstrap": true, "restricted_database_logins": true, "exact_replay_deduplicated": true, "revocation_blocks_new_publication": true, "pinned_version_survived_overwrite": true, "wrong_key_and_version_rejected": true, "customer_execution_authorized": false, "customer_history_status": "BLOCKED", "estimated_saving": nil, "verified_saving": nil, "native_journal_runtime_accepted": false, "artifacts": artifactMetadata}
	if runtimeEvidence != nil {
		result["native_journal_runtime_accepted"] = true
		result["native_operating_loop"] = runtimeEvidence
	}
	connectedDriverMark("RESULT_PUBLICATION", "")
	raw, _ := json.MarshalIndent(result, "", "  ")
	if err = os.WriteFile("/results/result.json", append(raw, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	t.Log("actual native Git/Terraform + restricted PostgreSQL + encrypted versioned MinIO + independent signed-JWT approval")
}
