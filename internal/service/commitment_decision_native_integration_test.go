//go:build commitment_decision_native_integration

package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	portfolio "github.com/christopherosiemo/bn-implementation-Finops/internal/commitmentportfolio"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/source"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

// Long ingestion is bounded fixture preparation, outside unchanged browser180.
// No operation is allowed until root explicitly schedules this tagged lab.
const decisionNativeSetupBudget = 15 * time.Minute
const decisionNativeOverallBudget = 20 * time.Minute

func TestCommitmentDecisionActualNativeProviderHistoryAndIndependentFinance(t *testing.T) {
	if os.Getenv("COMMITMENT_PORTFOLIO_NATIVE_LAB") != "ISOLATED_VERSIONED_MINIO_CLICKHOUSE" {
		t.Fatal("explicit decision native lab mode required")
	}
	if os.Getenv("TEST_FLEET_HISTORY_S3_ENDPOINT") != "http://minio:9000" || os.Getenv("FLEET_CAPACITY_CLICKHOUSE_URL") != "http://clickhouse:8123" {
		t.Fatal("portfolio isolated endpoint boundary differs")
	}
	modelToken := os.Getenv("TEST_COMMITMENT_PORTFOLIO_MODEL_TOKEN")
	access, secret := os.Getenv("TEST_FLEET_HISTORY_S3_ACCESS_KEY"), os.Getenv("TEST_FLEET_HISTORY_S3_SECRET_KEY")
	if len(modelToken) < 32 || access == "" || secret == "" || modelToken == secret {
		t.Fatal("portfolio private service credentials unavailable")
	}
	f, admin, _, _ := newFleetNativeHTTPTest(t)
	ctx, cancel := context.WithTimeout(context.Background(), decisionNativeOverallBudget)
	defer cancel()
	setupStarted := time.Now()
	setupCtx, stopSetup := context.WithTimeout(ctx, decisionNativeSetupBudget)
	defer stopSetup()
	if err := admin.Migrate(ctx, "../../migrations"); err != nil {
		t.Fatal("decision native schema unavailable", err)
	}
	analyst := commitmentPortfolioNativeRuntime(t, ctx, admin, f.tenant)
	commitmentPortfolioAssertSharedRoleMigration(t, ctx, admin)
	commitmentPortfolioCheckModelAuthentication(t, ctx)
	archive := s3.NewFromConfig(aws.Config{Region: "eu-west-1", Credentials: credentials.NewStaticCredentialsProvider(access, secret, "")}, func(o *s3.Options) { o.BaseEndpoint = aws.String("http://minio:9000"); o.UsePathStyle = true })
	bucket := "native-portfolio-" + strings.ReplaceAll(model.ID(), "-", "")
	owner := model.ID()
	if _, e := archive.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(bucket)}); e != nil {
		t.Fatal(e)
	}
	if _, e := archive.PutBucketTagging(ctx, &s3.PutBucketTaggingInput{Bucket: aws.String(bucket), Tagging: &s3types.Tagging{TagSet: []s3types.Tag{{Key: aws.String("finops-portfolio-owner"), Value: aws.String(owner)}}}}); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		c, stop := context.WithTimeout(context.Background(), 30*time.Second)
		defer stop()
		tags, e := archive.GetBucketTagging(c, &s3.GetBucketTaggingInput{Bucket: aws.String(bucket)})
		owned := false
		if e == nil {
			for _, tag := range tags.TagSet {
				owned = owned || aws.ToString(tag.Key) == "finops-portfolio-owner" && aws.ToString(tag.Value) == owner
			}
		}
		if !owned {
			t.Error("portfolio archive cleanup ownership differs")
			return
		}
		pages := s3.NewListObjectVersionsPaginator(archive, &s3.ListObjectVersionsInput{Bucket: aws.String(bucket)})
		for pages.HasMorePages() {
			page, e := pages.NextPage(c)
			if e != nil || len(page.Versions)+len(page.DeleteMarkers) > 1000 {
				t.Error("portfolio archive cleanup enumeration failed")
				return
			}
			objects := []s3types.ObjectIdentifier{}
			for _, v := range page.Versions {
				objects = append(objects, s3types.ObjectIdentifier{Key: v.Key, VersionId: v.VersionId})
			}
			for _, v := range page.DeleteMarkers {
				objects = append(objects, s3types.ObjectIdentifier{Key: v.Key, VersionId: v.VersionId})
			}
			if len(objects) > 0 {
				out, e := archive.DeleteObjects(c, &s3.DeleteObjectsInput{Bucket: aws.String(bucket), Delete: &s3types.Delete{Objects: objects, Quiet: aws.Bool(true)}})
				if e != nil || len(out.Errors) > 0 {
					t.Error("portfolio archive version cleanup failed")
					return
				}
			}
		}
		if _, e = archive.DeleteBucket(c, &s3.DeleteBucketInput{Bucket: aws.String(bucket)}); e != nil {
			t.Error("portfolio archive bucket cleanup failed")
		}
	})
	if _, e := archive.PutBucketVersioning(ctx, &s3.PutBucketVersioningInput{Bucket: aws.String(bucket), VersioningConfiguration: &s3types.VersioningConfiguration{Status: s3types.BucketVersioningStatusEnabled}}); e != nil {
		t.Fatal(e)
	}
	put := func(c context.Context, key string, raw []byte) (model.Document, error) {
		t.Helper()
		out, e := archive.PutObject(c, &s3.PutObjectInput{Bucket: aws.String(bucket), Key: aws.String(key), Body: bytes.NewReader(raw)})
		if e != nil || out.VersionId == nil || aws.ToString(out.VersionId) == "null" {
			return nil, errors.New("DECISION_NATIVE_APP_VERSION_WRITE_FAILED")
		}
		back, e := archive.GetObject(c, &s3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String(key), VersionId: out.VersionId})
		if e != nil {
			return nil, errors.New("DECISION_NATIVE_APP_VERSION_READ_FAILED")
		}
		body, e := io.ReadAll(io.LimitReader(back.Body, (32<<20)+1))
		_ = back.Body.Close()
		if e != nil || len(body) > 32<<20 || !bytes.Equal(body, raw) || aws.ToString(back.VersionId) != aws.ToString(out.VersionId) {
			return nil, errors.New("DECISION_NATIVE_APP_VERSION_BYTES_DIFFER")
		}
		return model.Document{"bucket": bucket, "key": key, "version_id": aws.ToString(out.VersionId), "body_sha256": source.BytesHash(raw)}, nil
	}
	oldPut := func(c context.Context, key string, raw []byte) model.Document {
		value, err := put(c, key, raw)
		if err != nil {
			t.Fatal("native218 versioned archive failed", err)
		}
		return value
	}
	var err error
	if err = commitmentDecisionNativeDeclarations(setupCtx, f); err != nil {
		t.Fatal("decision native declarations failed", err)
	}
	history, err := commitmentDecisionIssueNativeHistory(t, setupCtx, f, decisionNativeSource, decisionNativeID, put)
	if err != nil {
		t.Fatal("decision monthly native source/history issuance failed", err)
	}
	var refreshArtifact func(context.Context) error
	scope, err := commitmentDecisionNativeCurrentArtifact(t, setupCtx, f, admin, analyst, archive, put, &refreshArtifact)
	if err != nil {
		t.Fatal("decision actual current attestor/readback failed", err)
	}
	ownership, refreshArchive, err := commitmentDecisionNativeArchive(t, setupCtx, f, admin, scope, history.Training, archive, bucket)
	if err != nil {
		t.Fatal("decision actual original-version archive Pipeline failed", err)
	}
	if err = history.Refresh(setupCtx); err != nil {
		t.Fatal("decision current native financial refresh failed", err)
	}
	stages, err := commitmentDecisionIssueNativeStages(t, setupCtx, f, admin, decisionNativeSource, decisionNativeWorkload, decisionNativeResource, decisionNativeID, put, os.Getenv("TEST_COMMITMENT_PORTFOLIO_NORMALIZER_TOKEN"))
	if err != nil {
		t.Fatal("decision actual035/036/037 stage issuance failed", err)
	}
	if err = commitmentDecisionNativePolicy(setupCtx, f, admin, scope, stages); err != nil {
		t.Fatal("decision bounded customer constraint commissioning failed", err)
	}
	controllerTick, err := commitmentDecisionNativeControllers(t, setupCtx, f, stages.ASGARN, put)
	if err != nil {
		t.Fatal("decision controller raw reparse/source issuance failed", err)
	}
	offers, quoteTick, err := commitmentDecisionNativeQuotes(t, setupCtx, f, put)
	if err != nil || len(offers) != 2 {
		t.Fatal("decision two genuine issued offer receipts absent", err)
	}
	finance := f.token(f.tenant, jointFinanceSubject, "FINANCE")
	code, queued, _ := f.request("commitment-portfolio-analyses", `"0"`, "decision-native-financial-basis", finance, source.Object(history.Selection))
	if code != 202 {
		t.Fatal("decision actual039 IDs-only basis request failed", code)
	}
	calculator, err := portfolio.NewHTTPCalculator(setupCtx, portfolioNativeModel, "LOCAL_PRIVATE", modelToken)
	if err != nil {
		t.Fatal(err)
	}
	worker := portfolio.Worker{Pool: analyst.Pool, Tenant: f.tenant, Calculator: calculator}
	if replayed, err := worker.Process(setupCtx, model.String(queued, "id")); err != nil || replayed {
		t.Fatal("decision actual039 native/model basis failed", err)
	}
	record := commitmentPortfolioGet(t, f, finance, model.String(queued, "id"))
	if model.String(record, "status") != "ASSESSED" || portfolio.Hash(record["selection"]) != portfolio.Hash(history.Selection) {
		t.Fatal("decision actual039 basis differs")
	}
	nativeOffers := map[string]string{}
	for _, offer := range offers {
		nativeOffers[model.String(offer, "native_offering_id")] = model.String(offer, "id")
	}
	cases := []commitmentDecisionBrowserCase{{Case: "POSITIVE", PortfolioAnalysisRequestID: model.String(queued, "id"), OfferReceiptID: nativeOffers["aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa"]}, {Case: "DNP", PortfolioAnalysisRequestID: model.String(queued, "id"), OfferReceiptID: nativeOffers["bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb"]}}
	if cases[0].OfferReceiptID == "" || cases[1].OfferReceiptID == "" || cases[0].OfferReceiptID == cases[1].OfferReceiptID {
		t.Fatal("decision native offer identity join differs")
	}
	var initialSnapshot []byte
	var initialInputHash string
	if err = admin.Pool.QueryRow(setupCtx, "SELECT input_snapshot,input_hash FROM commitment_portfolio_requests WHERE tenant_id=$1 AND id=$2", f.tenant, queued["id"]).Scan(&initialSnapshot, &initialInputHash); err != nil || len(initialSnapshot) == 0 {
		t.Fatal("decision immutable original financial snapshot missing")
	}
	nativeEvidence := commitmentDecisionNativeEvidence{Cases: cases}
	nativeEvidence.Refresh = func(c context.Context) error {
		if err := history.Refresh(c); err != nil {
			return err
		}
		if err := refreshArtifact(c); err != nil {
			return err
		}
		if err := refreshArchive(c); err != nil {
			return err
		}
		if err := stages.Refresh(c); err != nil {
			return err
		}
		stages = stages.Snapshot()
		if err := commitmentDecisionNativePolicy(c, f, admin, scope, stages); err != nil {
			return err
		}
		if err := quoteTick(c); err != nil {
			return err
		}
		return controllerTick(c)
	}
	nativeEvidence.Tick = func(c context.Context) error {
		if err := quoteTick(c); err != nil {
			return err
		}
		return controllerTick(c)
	}
	nativeEvidence.RenewInventory = func(c context.Context) error {
		var before, after string
		if err := f.roles["ingester"].Do(c, f.tenant, func(tx *store.Tx) error {
			checkpoint, err := tx.SourceCheckpointGet(c, decisionNativeSource, "status")
			before = model.String(checkpoint, "commitment_receipt_id")
			return err
		}); err != nil {
			return err
		}
		if err := history.Refresh(c); err != nil {
			return err
		}
		if err := refreshArchive(c); err != nil {
			return err
		}
		if err := f.roles["ingester"].Do(c, f.tenant, func(tx *store.Tx) error {
			checkpoint, err := tx.SourceCheckpointGet(c, decisionNativeSource, "status")
			after = model.String(checkpoint, "commitment_receipt_id")
			if err == nil && model.String(checkpoint, "status") != "HEALTHY" {
				return errors.New("DECISION_ROUTINE_SOURCE_NOT_HEALTHY")
			}
			return err
		}); err != nil {
			return err
		}
		if before == "" || after == "" || before == after {
			return errors.New("DECISION_ROUTINE_NATIVE_RENEWAL_NOT_OBSERVED")
		}
		var snapshot []byte
		var hash string
		if err := admin.Pool.QueryRow(c, "SELECT input_snapshot,input_hash FROM commitment_portfolio_requests WHERE tenant_id=$1 AND id=$2", f.tenant, queued["id"]).Scan(&snapshot, &hash); err != nil {
			return err
		}
		if !bytes.Equal(initialSnapshot, snapshot) || initialInputHash != hash {
			return errors.New("DECISION_RENEWAL_REWROTE_ORIGINAL_SNAPSHOT")
		}
		return nil
	}
	oldCtx, stopOld := context.WithTimeout(setupCtx, 5*time.Minute)
	oldEvidence, err := commitmentPortfolioIssueNative(t, oldCtx, f, modelToken, oldPut)
	stopOld()
	if err != nil {
		t.Fatal("preserved218 native source issuance failed", err)
	}
	if setupCtx.Err() != nil {
		t.Fatal("decision bounded long fixture preparation expired")
	}
	if _, err = fleetCapacityBrowserWrite("/results/decision-native-fixture.json", model.Document{"schema_version": "1", "run_id": os.Getenv("COMMITMENT_PORTFOLIO_BROWSER_RUN_ID"), "fixture": true, "provider_history_and_source_transports": "SIMULATED_PROVIDER_SHAPED_FIXTURE", "historical_customer_or_live_provenance": false, "native_source_id": decisionNativeSource, "workload_id": decisionNativeWorkload, "initial_native_hourly_rows": history.NativeHourlyRows, "initial_clickhouse_readbacks": history.AnalyticsReadbacks, "initial_raw_version_readbacks": history.ArchiveReadbacks, "native_calendar_heads": len(history.CurrentMonthReceipts), "training_period": history.Training, "ownership_archive_id": ownership.ID, "ownership_basis": portfolio.DecisionOwnershipArchiveBasis, "original_provider_versions_simulated": true, "app_mirror_actual_versioned_minio": true, "analytical_sizing_basis": "CURRENT_BASELINE_WITH_UNKNOWN_037_MONEY", "setup_limit_seconds": 900, "overall_limit_seconds": 1200, "setup_elapsed_milliseconds": time.Since(setupStarted).Milliseconds(), "old218_limit_seconds": 300, "purchase_authorized": false, "execution_authorized": false, "verified_saving": nil}); err != nil {
		t.Fatal(err)
	}
	if commitmentDecisionPositiveBrowserPhase(t, ctx, f, admin, analyst, oldEvidence, modelToken, nativeEvidence) == nil {
		t.Fatal("actual native decision browser phase is required")
	}
	t.Log("Actual native decision: simulated provider-shaped full hourly history, actual source/CH/versioned app mirror and archive Pipeline; actual public PREPARE/model + positive/DNP + dedicated daemon + independent Finance PKCE/persisted replay; no live history, purchase, execution or verified savings claim")
}

// Focused diagnostic only. The public lab selects its original full test exactly;
// this separate entry never substitutes for original ownership/native acceptance.
func TestCommitmentDecisionNativeStagesDiagnostic(t *testing.T) {
	if os.Getenv("COMMITMENT_PORTFOLIO_NATIVE_LAB") != "ISOLATED_VERSIONED_MINIO_CLICKHOUSE" {
		t.Fatal("explicit decision native lab mode required")
	}
	if os.Getenv("TEST_FLEET_HISTORY_S3_ENDPOINT") != "http://minio:9000" || os.Getenv("FLEET_CAPACITY_CLICKHOUSE_URL") != "http://clickhouse:8123" {
		t.Fatal("portfolio isolated endpoint boundary differs")
	}
	modelToken := os.Getenv("TEST_COMMITMENT_PORTFOLIO_MODEL_TOKEN")
	access, secret := os.Getenv("TEST_FLEET_HISTORY_S3_ACCESS_KEY"), os.Getenv("TEST_FLEET_HISTORY_S3_SECRET_KEY")
	if len(modelToken) < 32 || access == "" || secret == "" || modelToken == secret {
		t.Fatal("portfolio private service credentials unavailable")
	}
	f, admin, _, _ := newFleetNativeHTTPTest(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	setupCtx := ctx
	if err := admin.Migrate(ctx, "../../migrations"); err != nil {
		t.Fatal("decision native schema unavailable", err)
	}
	analyst := commitmentPortfolioNativeRuntime(t, ctx, admin, f.tenant)
	commitmentPortfolioAssertSharedRoleMigration(t, ctx, admin)
	commitmentPortfolioCheckModelAuthentication(t, ctx)
	archive := s3.NewFromConfig(aws.Config{Region: "eu-west-1", Credentials: credentials.NewStaticCredentialsProvider(access, secret, "")}, func(o *s3.Options) { o.BaseEndpoint = aws.String("http://minio:9000"); o.UsePathStyle = true })
	bucket := "native-portfolio-" + strings.ReplaceAll(model.ID(), "-", "")
	owner := model.ID()
	if _, e := archive.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(bucket)}); e != nil {
		t.Fatal(e)
	}
	if _, e := archive.PutBucketTagging(ctx, &s3.PutBucketTaggingInput{Bucket: aws.String(bucket), Tagging: &s3types.Tagging{TagSet: []s3types.Tag{{Key: aws.String("finops-portfolio-owner"), Value: aws.String(owner)}}}}); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		c, stop := context.WithTimeout(context.Background(), 30*time.Second)
		defer stop()
		tags, e := archive.GetBucketTagging(c, &s3.GetBucketTaggingInput{Bucket: aws.String(bucket)})
		owned := false
		if e == nil {
			for _, tag := range tags.TagSet {
				owned = owned || aws.ToString(tag.Key) == "finops-portfolio-owner" && aws.ToString(tag.Value) == owner
			}
		}
		if !owned {
			t.Error("portfolio archive cleanup ownership differs")
			return
		}
		pages := s3.NewListObjectVersionsPaginator(archive, &s3.ListObjectVersionsInput{Bucket: aws.String(bucket)})
		for pages.HasMorePages() {
			page, e := pages.NextPage(c)
			if e != nil || len(page.Versions)+len(page.DeleteMarkers) > 1000 {
				t.Error("portfolio archive cleanup enumeration failed")
				return
			}
			objects := []s3types.ObjectIdentifier{}
			for _, v := range page.Versions {
				objects = append(objects, s3types.ObjectIdentifier{Key: v.Key, VersionId: v.VersionId})
			}
			for _, v := range page.DeleteMarkers {
				objects = append(objects, s3types.ObjectIdentifier{Key: v.Key, VersionId: v.VersionId})
			}
			if len(objects) > 0 {
				out, e := archive.DeleteObjects(c, &s3.DeleteObjectsInput{Bucket: aws.String(bucket), Delete: &s3types.Delete{Objects: objects, Quiet: aws.Bool(true)}})
				if e != nil || len(out.Errors) > 0 {
					t.Error("portfolio archive version cleanup failed")
					return
				}
			}
		}
		if _, e = archive.DeleteBucket(c, &s3.DeleteBucketInput{Bucket: aws.String(bucket)}); e != nil {
			t.Error("portfolio archive bucket cleanup failed")
		}
	})
	if _, e := archive.PutBucketVersioning(ctx, &s3.PutBucketVersioningInput{Bucket: aws.String(bucket), VersioningConfiguration: &s3types.VersioningConfiguration{Status: s3types.BucketVersioningStatusEnabled}}); e != nil {
		t.Fatal(e)
	}
	put := func(c context.Context, key string, raw []byte) (model.Document, error) {
		t.Helper()
		out, e := archive.PutObject(c, &s3.PutObjectInput{Bucket: aws.String(bucket), Key: aws.String(key), Body: bytes.NewReader(raw)})
		if e != nil || out.VersionId == nil || aws.ToString(out.VersionId) == "null" {
			return nil, errors.New("DECISION_NATIVE_APP_VERSION_WRITE_FAILED")
		}
		back, e := archive.GetObject(c, &s3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String(key), VersionId: out.VersionId})
		if e != nil {
			return nil, errors.New("DECISION_NATIVE_APP_VERSION_READ_FAILED")
		}
		body, e := io.ReadAll(io.LimitReader(back.Body, (32<<20)+1))
		_ = back.Body.Close()
		if e != nil || len(body) > 32<<20 || !bytes.Equal(body, raw) || aws.ToString(back.VersionId) != aws.ToString(out.VersionId) {
			return nil, errors.New("DECISION_NATIVE_APP_VERSION_BYTES_DIFFER")
		}
		return model.Document{"bucket": bucket, "key": key, "version_id": aws.ToString(out.VersionId), "body_sha256": source.BytesHash(raw)}, nil
	}
	t.Log("PRIVATE_STAGE_FACTORY_DIAGNOSTIC: actual native035/036/037 adapters; original ownership archive, financial advice and Finance journey are deliberately outside this component test")
	if err := commitmentDecisionNativeDeclarations(setupCtx, f); err != nil {
		t.Fatal("stage diagnostic native declarations failed", err)
	}
	history, err := commitmentDecisionIssueNativeHistory(t, setupCtx, f, decisionNativeSource, decisionNativeID, put)
	if err != nil {
		t.Fatal("stage diagnostic actual monthly native billing issuance failed", err)
	}
	if history.NativeHourlyRows < 23376 || history.AnalyticsReadbacks != history.NativeHourlyRows {
		t.Fatal("stage diagnostic complete native hourly source/readback differs")
	}
	var refreshArtifact func(context.Context) error
	scope, err := commitmentDecisionNativeCurrentArtifact(t, setupCtx, f, admin, analyst, archive, put, &refreshArtifact)
	if err != nil {
		t.Fatal("stage diagnostic actual current attestor/readback failed", err)
	}
	if len(scope.Resources) != 1 || scope.Resources[0].ProviderResourceID != decisionNativeID {
		t.Fatal("stage diagnostic actual bound artifact resource differs")
	}
	if err = history.Refresh(setupCtx); err != nil {
		t.Fatal("stage diagnostic current financial source refresh failed", err)
	}
	stages, err := commitmentDecisionIssueNativeStages(t, setupCtx, f, admin, decisionNativeSource, decisionNativeWorkload, decisionNativeResource, decisionNativeID, put, os.Getenv("TEST_COMMITMENT_PORTFOLIO_NORMALIZER_TOKEN"))
	if err != nil {
		t.Fatal("stage diagnostic actual035/036/037 issuance failed", err)
	}
	if stages.AssessmentRequestID == "" || stages.CapacityRequestID == "" || stages.JointRequestID == "" || stages.JointDecisionID == "" || len(stages.NativePins) != 1 {
		t.Fatal("stage diagnostic persisted actual stage references absent")
	}
	t.Log("PRIVATE_STAGE_FACTORY_DIAGNOSTIC_PASS: actual monthly native CUR/CH/versioned archive and bound current artifact,035/036/037 persisted current baseline with unknown money; no original historical ownership, advice, Finance or native acceptance claim")
}

func commitmentDecisionNativePolicy(ctx context.Context, f *mutationReplayFixture, admin *store.Store, scope portfolio.DecisionOwnershipScope, stages commitmentDecisionNativeStages) error {
	var revision int64
	if err := admin.Pool.QueryRow(ctx, "SELECT coalesce(max(revision),0)+1 FROM commitment_optimization_policies WHERE tenant_id=$1 AND workload_id=$2", f.tenant, decisionNativeWorkload).Scan(&revision); err != nil {
		return err
	}
	policy := portfolio.DecisionStagePolicy{SchemaVersion: "1", ID: "decision-native-customer-size-and-controller-policy", Revision: 1, Purpose: portfolio.DecisionStagePolicyPurpose, Basis: portfolio.DecisionStagePolicyBasis, TenantID: f.tenant, WorkloadID: decisionNativeWorkload, OwnershipScopeSHA256: portfolio.Hash(scope), ConfigurationSHA256: scope.ConfigurationSHA256, ResourceIDs: []string{decisionNativeID}, SourceID: decisionNativeSource, OldProposalID: stages.OldProposalID, ASGARN: stages.ASGARN, AccountID: nativeAssessmentAccount, Region: "eu-west-1", AllowedCandidates: []portfolio.DecisionStagePolicyCandidate{{InstanceType: "m6i.large", ProposalID: stages.CandidateProposalID, TemplateID: stages.LaunchTemplateID, TemplateVersion: stages.LaunchTemplateVersion, ImageID: stages.ImageID}}, SizeConstraintBasis: "BUSINESS_OR_LICENSE_RESTRICTION", ControllerScope: "CUSTOMER_REVIEWED_CONFIGURATION_ASG_ONLY", CustomerApprovalID: "explicit-synthetic-customer-license-review", CustomerApprovalIssuer: "https://fixture-customer-policy.invalid", CustomerApprovalSubject: "fixture-customer-reviewer", ValidUntil: time.Now().UTC().Add(time.Hour)}
	policy.Revision = revision
	raw, err := json.Marshal(policy)
	if err != nil {
		return err
	}
	_, err = admin.Pool.Exec(ctx, "INSERT INTO commitment_optimization_policies(tenant_id,id,revision,workload_id,document) VALUES($1,$2,$3,$4,$5)", f.tenant, policy.ID, revision, decisionNativeWorkload, raw)
	return err
}
