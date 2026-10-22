//go:build commitment_decision_native_integration

package service

import (
	"context"
	"errors"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/auth"
	portfolio "github.com/christopherosiemo/bn-implementation-Finops/internal/commitmentportfolio"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/fleetbilling"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/source"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/coreos/go-oidc/v3/oidc"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

type commitmentDecisionBrowserCase struct {
	Case                       string `json:"case"`
	PortfolioAnalysisRequestID string `json:"portfolio_analysis_request_id"`
	OfferReceiptID             string `json:"offer_receipt_id"`
}
type commitmentDecisionBrowserInputs struct {
	SchemaVersion string                          `json:"schema_version"`
	RunID         string                          `json:"run_id"`
	TenantID      string                          `json:"tenant_id"`
	ReadySHA256   string                          `json:"ready_sha256"`
	WorkloadID    string                          `json:"workload_id"`
	Cases         []commitmentDecisionBrowserCase `json:"cases"`
}
type commitmentDecisionFixtureSignal struct {
	SchemaVersion string `json:"schema_version"`
	RunID         string `json:"run_id"`
	ReadySHA256   string `json:"ready_sha256"`
	InputsSHA256  string `json:"inputs_sha256"`
}
type commitmentDecisionBrowserCaseProof struct {
	Case                 string `json:"case"`
	PreparationRequestID string `json:"preparation_request_id"`
	RequestID            string `json:"request_id"`
	DecisionID           string `json:"decision_id"`
	DecisionSHA256       string `json:"decision_sha256"`
	InputSHA256          string `json:"input_sha256"`
	Outcome              string `json:"outcome"`
}
type commitmentDecisionBrowserProof struct {
	SchemaVersion                     string                               `json:"schema_version"`
	Status                            string                               `json:"status"`
	RunID                             string                               `json:"run_id"`
	TenantID                          string                               `json:"tenant_id"`
	ReadySHA256                       string                               `json:"ready_sha256"`
	InputsSHA256                      string                               `json:"inputs_sha256"`
	WorkloadID                        string                               `json:"workload_id"`
	Cases                             []commitmentDecisionBrowserCaseProof `json:"cases"`
	ApprovalID                        string                               `json:"approval_id"`
	ReviewerID                        string                               `json:"reviewer_id"`
	RequesterID                       string                               `json:"requester_id"`
	OIDCPKCE                          bool                                 `json:"oidc_pkce"`
	OIDCAuthorizationCode             bool                                 `json:"oidc_authorization_code"`
	UIIDsOnlyRequests                 bool                                 `json:"ui_ids_only_requests"`
	ActualAnalyst                     bool                                 `json:"actual_analyst"`
	PersistedReload                   bool                                 `json:"persisted_reload"`
	IndependentFinance                bool                                 `json:"independent_finance"`
	ExactReviewVersion                bool                                 `json:"exact_review_version"`
	IdempotentReviewReplay            bool                                 `json:"idempotent_review_replay"`
	RoutineNativeRenewalBeforeFinance bool                                 `json:"routine_native_renewal_before_finance"`
	Fixture                           bool                                 `json:"fixture"`
	PurchaseAuthorized                bool                                 `json:"purchase_authorized"`
	ExecutionAuthorized               bool                                 `json:"execution_authorized"`
	VerifiedSaving                    *string                              `json:"verified_saving"`
}
type commitmentDecisionNativeEvidence struct {
	Cases          []commitmentDecisionBrowserCase
	Refresh        func(context.Context) error
	Tick           func(context.Context) error
	RenewInventory func(context.Context) error
}

// The timer uses real elapsed process time. Ordinary inventory Sync still runs
// through acquisition, immutable receipts and HEALTHY completion. No SQL clock,
// selected immutable snapshot or prior receipt timestamp is overwritten.
func commitmentDecisionNativeTicks(ctx context.Context, evidence commitmentDecisionNativeEvidence, signal commitmentDecisionFixtureSignal) error {
	if evidence.Tick == nil || evidence.RenewInventory == nil {
		return errors.New("DECISION_NATIVE_ROUTINE_DEPENDENCIES_REQUIRED")
	}
	started := time.Now()
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	renewed := false
	for {
		select {
		case <-ctx.Done():
			if errors.Is(ctx.Err(), context.Canceled) {
				return nil
			}
			return ctx.Err()
		case <-ticker.C:
			if err := evidence.Tick(ctx); err != nil {
				return err
			}
			if !renewed && time.Since(started) >= time.Minute {
				if err := evidence.RenewInventory(ctx); err != nil {
					return err
				}
				if err := evidence.Tick(ctx); err != nil {
					return err
				}
				marker := struct {
					SchemaVersion            string `json:"schema_version"`
					RunID                    string `json:"run_id"`
					ReadySHA256              string `json:"ready_sha256"`
					InputsSHA256             string `json:"inputs_sha256"`
					MinimumIntervalSeconds   int    `json:"minimum_interval_seconds"`
					OrdinarySourceSync       bool   `json:"ordinary_source_sync"`
					QuoteRefreshChecked      bool   `json:"quote_refresh_checked"`
					ControllerRefreshChecked bool   `json:"controller_refresh_checked"`
				}{signal.SchemaVersion, signal.RunID, signal.ReadySHA256, signal.InputsSHA256, 60, true, true, true}
				if _, err := fleetCapacityBrowserWrite("/results/decision-native-renewed.json", marker); err != nil {
					return err
				}
				renewed = true
			}
		}
	}
}

func commitmentDecisionAssertBrowserPersisted(t *testing.T, ctx context.Context, f *mutationReplayFixture, admin, analyst *store.Store, inputs commitmentDecisionBrowserInputs, proof commitmentDecisionBrowserProof) {
	t.Helper()
	if proof.SchemaVersion != "1" || proof.Status != "PASS" || proof.RunID != inputs.RunID || proof.TenantID != f.tenant || proof.ReadySHA256 != inputs.ReadySHA256 || proof.InputsSHA256 != portfolio.Hash(inputs) || proof.WorkloadID != inputs.WorkloadID || proof.RequesterID != jointFinanceSubject || proof.ReviewerID != decisionNativeReviewer || proof.ReviewerID == proof.RequesterID || len(proof.Cases) != 2 || !proof.OIDCPKCE || !proof.OIDCAuthorizationCode || !proof.UIIDsOnlyRequests || !proof.ActualAnalyst || !proof.PersistedReload || !proof.IndependentFinance || !proof.ExactReviewVersion || !proof.IdempotentReviewReplay || !proof.RoutineNativeRenewalBeforeFinance || !proof.Fixture || proof.PurchaseAuthorized || proof.ExecutionAuthorized || proof.VerifiedSaving != nil {
		t.Fatal("native decision browser proof binding differs")
	}
	for index, row := range proof.Cases {
		if row.Case != inputs.Cases[index].Case || !daemonFixtureUUID.MatchString(row.PreparationRequestID) || !daemonFixtureUUID.MatchString(row.RequestID) || !daemonFixtureSHA.MatchString(row.DecisionID) || !daemonFixtureSHA.MatchString(row.DecisionSHA256) || !daemonFixtureSHA.MatchString(row.InputSHA256) {
			t.Fatal("native decision case IDs differ")
		}
		expected := []string{"RECOMMEND_PURCHASE_PENDING_FINANCE", "DO_NOT_PURCHASE"}[index]
		if row.Outcome != expected {
			t.Fatal("native decision model outcome differs")
		}
		var requestRaw, terminalRaw, preparationRaw []byte
		var status, purpose, hash, creator, workload string
		err := admin.Pool.QueryRow(ctx, `SELECT r.document,x.status,x.purpose,x.document,x.content_hash,r.document->>'creator_id',r.document->>'workload_id' FROM entities r JOIN commitment_decision_results x ON (x.tenant_id,x.request_id)=(r.tenant_id,r.id) WHERE r.tenant_id=$1 AND r.kind='recommendations' AND r.id=$2`, f.tenant, row.RequestID).Scan(&requestRaw, &status, &purpose, &terminalRaw, &hash, &creator, &workload)
		if err != nil || status != "ASSESSED" || purpose != "DECISION" || hash != row.DecisionSHA256 || creator != jointFinanceSubject || workload != inputs.WorkloadID {
			t.Fatal("native decision immutable row or authenticated creator differs")
		}
		var request, terminal model.Document
		decision040Decode(t, requestRaw, &request)
		decision040Decode(t, terminalRaw, &terminal)
		selection := source.Object(request["selection"])
		if portfolio.Hash(terminal) != hash || model.String(terminal, "id") != row.DecisionID || model.String(terminal, "status") != expected || model.String(request, "input_sha256") != row.InputSHA256 || model.String(selection, "portfolio_analysis_request_id") != inputs.Cases[index].PortfolioAnalysisRequestID || model.String(selection, "offer_receipt_id") != inputs.Cases[index].OfferReceiptID || terminal["purchase_authorized"] != false || terminal["execution_authorized"] != false || terminal["verified_saving"] != nil || terminal["finance_approval_required"] != true {
			t.Fatal("native decision persisted payload/IDs/authority differs")
		}
		if err = admin.Pool.QueryRow(ctx, "SELECT document FROM commitment_decision_results WHERE tenant_id=$1 AND request_id=$2 AND purpose='PREPARE' AND status='ASSESSED'", f.tenant, row.PreparationRequestID).Scan(&preparationRaw); err != nil {
			t.Fatal("native decision actual persisted PREPARE absent")
		}
		preparation := model.Document{}
		decision040Decode(t, preparationRaw, &preparation)
		if selection["post_optimization_assessment_id"] != preparation["post_optimization_assessment_id"] || selection["forecast_id"] != preparation["forecast_id"] {
			t.Fatal("native decision did not select its actual producer outputs")
		}
		var exactEvidence bool
		err = admin.Pool.QueryRow(ctx, `SELECT count(*)=2 AND bool_and(document->>'writer_role'='finops_commitment_portfolio' AND document->>'request_id'=$2 AND document->>'workload_id'=$3 AND document->>'payload_sha256'=public.fleet_history_json_hash(document->'payload')) FROM entities WHERE tenant_id=$1 AND kind='commitment_decision_evidence' AND id=ANY($4::text[])`, f.tenant, row.PreparationRequestID, inputs.WorkloadID, []string{model.String(selection, "post_optimization_assessment_id"), model.String(selection, "forecast_id")}).Scan(&exactEvidence)
		if err != nil || !exactEvidence {
			t.Fatal("native decision producer evidence/role/hash closure differs")
		}
	}
	var approval []byte
	var count int
	if err := admin.Pool.QueryRow(ctx, "SELECT count(*) FROM entities WHERE tenant_id=$1 AND kind='approvals' AND document->>'commitment_decision_id'=$2", f.tenant, proof.Cases[0].RequestID).Scan(&count); err != nil || count != 1 {
		t.Fatal("native Finance idempotency did not retain exactly one approval")
	}
	if err := admin.Pool.QueryRow(ctx, "SELECT document FROM entities WHERE tenant_id=$1 AND kind='approvals' AND id=$2", f.tenant, proof.ApprovalID).Scan(&approval); err != nil {
		t.Fatal("native independent Finance approval row absent")
	}
	var document model.Document
	decision040Decode(t, approval, &document)
	review := source.Object(document["review"])
	if model.String(document, "commitment_decision_id") != proof.Cases[0].RequestID || model.String(review, "actor_id") != decisionNativeReviewer || model.String(review, "decision_sha256") != proof.Cases[0].DecisionSHA256 || model.String(review, "input_sha256") != proof.Cases[0].InputSHA256 || model.String(review, "approval_scope") != "COMMITMENT_RECOMMENDATION_REVIEW_NO_PURCHASE" || review["purchase_authorized"] != false || review["execution_authorized"] != false {
		t.Fatal("native Finance exact decision/version/independence/authority differs")
	}
	var noDNPReview bool
	if err := admin.Pool.QueryRow(ctx, "SELECT NOT EXISTS(SELECT 1 FROM entities WHERE tenant_id=$1 AND kind='approvals' AND document->>'commitment_decision_id'=$2)", f.tenant, proof.Cases[1].RequestID).Scan(&noDNPReview); err != nil || !noDNPReview {
		t.Fatal("uneconomic decision acquired a Finance approval")
	}
	_ = analyst // Replay is performed by the real Worker only after host daemon absence.
	if _, err := fleetCapacityBrowserWrite("/results/decision-native-proof.json", model.Document{"schema_version": "1", "status": "PASS", "run_id": inputs.RunID, "ready_sha256": inputs.ReadySHA256, "inputs_sha256": portfolio.Hash(inputs), "workload_id": inputs.WorkloadID, "cases": proof.Cases, "approval_id": proof.ApprovalID, "actual_database_reread": true, "independent_finance": true, "exactly_one_approval": true, "provider_history_and_source_transports": "SIMULATED_PROVIDER_SHAPED_FIXTURE", "historical_customer_or_live_provenance": false, "fixture": true, "purchase_authorized": false, "execution_authorized": false, "verified_saving": nil}); err != nil && !errors.Is(err, os.ErrExist) {
		t.Fatal("native decision proof publication failed", err)
	}
}
func commitmentDecisionPositiveBrowserPhase(t *testing.T, ctx context.Context, f *mutationReplayFixture, admin, analyst *store.Store, evidence commitmentPortfolioNativeEvidence, modelToken string, decision commitmentDecisionNativeEvidence) *commitmentPortfolioBrowserProof {
	t.Helper()
	mode := os.Getenv("COMMITMENT_PORTFOLIO_BROWSER")
	if mode == "" {
		return nil
	}
	if mode != "ISOLATED_REAL_OIDC" || os.Getenv("COMMITMENT_PORTFOLIO_NATIVE_LAB") != "ISOLATED_VERSIONED_MINIO_CLICKHOUSE" || !f.api.Config.Fixture || !strings.HasPrefix(admin.Pool.Config().ConnConfig.Database, "fixture_http_") || evidence.CanonicalRows != 218 || evidence.ArchiveReadbacks < 1 || evidence.Selection.SourceID != portfolioNativeSource || analyst == nil {
		t.Fatal("portfolio browser fixture boundary differs")
	}
	runID := os.Getenv("COMMITMENT_PORTFOLIO_BROWSER_RUN_ID")
	if !daemonFixtureUUID.MatchString(runID) {
		t.Fatal("portfolio browser run identity invalid")
	}
	setupCtx, cancelSetup := context.WithTimeout(ctx, 180*time.Second)
	defer cancelSetup()
	if err := admin.Migrate(setupCtx, "../../migrations"); err != nil {
		t.Fatal("decision native schema", err)
	}
	if !(&portfolio.Worker{Pool: analyst.Pool, Tenant: f.tenant}).Ready(setupCtx) {
		t.Fatal("portfolio browser analytical credential scope differs")
	}
	validatorCtx := oidc.ClientContext(ctx, &http.Client{Timeout: 30 * time.Second})
	validator, e := auth.New(validatorCtx, "http://localhost:8081/realms/finops", "finops", "http://browser-web:8081/realms/finops/protocol/openid-connect/certs")
	if e != nil {
		t.Fatal(e)
	}
	listener, e := net.Listen("tcp", "0.0.0.0:8097")
	if e != nil {
		t.Fatal("portfolio browser API listener", e)
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
			t.Error("portfolio browser API termination", e)
		}
	}()
	ready := commitmentPortfolioBrowserReady{SchemaVersion: "1", RunID: runID, TenantID: f.tenant, Selection: evidence.Selection, Fixture: true}
	raw, e := fleetCapacityBrowserWrite("/results/portfolio-browser-ready.json", ready)
	if e != nil {
		t.Fatal(e)
	}
	signal := fleetCapacityBrowserSignal{SchemaVersion: "1", RunID: runID, ReadySHA256: fleetbilling.BytesHash(raw)}
	inputs := commitmentDecisionBrowserInputs{SchemaVersion: "1", RunID: runID, TenantID: f.tenant, ReadySHA256: signal.ReadySHA256, WorkloadID: decisionNativeWorkload, Cases: decision.Cases}
	if _, e = fleetCapacityBrowserWrite("/results/decision-browser-inputs.json", inputs); e != nil {
		t.Fatal(e)
	}
	currentSignal := commitmentDecisionFixtureSignal{SchemaVersion: "1", RunID: runID, ReadySHA256: signal.ReadySHA256, InputsSHA256: portfolio.Hash(inputs)}
	workerReady := commitmentPortfolioBrowserSecrets(t, analyst, runID, f.tenant, modelToken)
	if _, e = fleetCapacityBrowserWrite("/results/portfolio-worker-ready.json", workerReady); e != nil {
		t.Fatal(e)
	}
	var refreshRequest commitmentDecisionFixtureSignal
	if e = fleetCapacityBrowserWait(setupCtx, "decision-native-refresh-request.json", &refreshRequest); e != nil || refreshRequest != currentSignal {
		t.Fatal("decision current native refresh request unproved", e)
	}
	if e = decision.Refresh(setupCtx); e != nil {
		t.Fatal("decision actual current native refresh failed", e)
	}
	if _, e = fleetCapacityBrowserWrite("/results/decision-native-current.json", currentSignal); e != nil {
		t.Fatal(e)
	}
	var workerStarted, browserStarted fleetCapacityBrowserSignal
	if e = fleetCapacityBrowserWait(setupCtx, "portfolio-worker-started.json", &workerStarted); e != nil || workerStarted != signal {
		t.Fatal("portfolio dedicated daemon startup is unproved", e)
	}
	if e = fleetCapacityBrowserWait(setupCtx, "portfolio-browser-start.json", &browserStarted); e != nil || setupCtx.Err() != nil {
		t.Fatal("portfolio real identity/browser startup is unproved", e)
	}
	journeyCtx, cancelJourney, e := fleetCapacityBrowserJourneyContext(ctx, browserStarted, signal)
	if e != nil {
		t.Fatal(e)
	}
	defer cancelJourney()
	tickCtx, stopTicks := context.WithCancel(journeyCtx)
	tickDone := make(chan error, 1)
	go func() { tickDone <- commitmentDecisionNativeTicks(tickCtx, decision, currentSignal) }()
	ticksStopped := false
	defer func() {
		if !ticksStopped {
			stopTicks()
			if tickErr := <-tickDone; tickErr != nil {
				t.Error("decision native routine tick failed", tickErr)
			}
		}
	}()
	var posted commitmentPortfolioBrowserRequest
	if e = fleetCapacityBrowserWait(journeyCtx, "portfolio-request.json", &posted); e != nil || posted.SchemaVersion != "1" || posted.RunID != runID || !daemonFixtureUUID.MatchString(posted.RequestID) {
		t.Fatal("portfolio actual browser request is unproved", e)
	}
	var proof commitmentPortfolioBrowserProof
	if e = fleetCapacityBrowserWait(journeyCtx, "portfolio-browser-result.json", &proof); e != nil {
		t.Fatal("portfolio actual browser result absent", e)
	}
	if proof.SchemaVersion != "1" || proof.Status != "PASS" || proof.RunID != runID || proof.TenantID != f.tenant || proof.RequestID != posted.RequestID || proof.CreatorID != jointFinanceSubject || proof.SelectionSHA256 != portfolio.Hash(evidence.Selection) || !daemonFixtureSHA.MatchString(proof.AnalysisID) || !daemonFixtureSHA.MatchString(proof.AnalysisSHA256) || !proof.OIDCPKCE || !proof.OIDCAuthorizationCode || !proof.UIIDsOnlyRequest || !proof.ActualPortfolioWorker || !proof.ObservedUtilization || !proof.ObservedUnusedCommitment || !proof.SparseRIUnknown || !proof.NativeConcentration || !proof.PersistedReload || !proof.Fixture || proof.RecommendationAuthorized || proof.PurchaseAuthorized || proof.CustomerExecutionAuthorized || proof.ExpectedSavings != nil || proof.EstimatedSaving != nil || proof.VerifiedSaving != nil {
		t.Fatal("portfolio browser result binding differs")
	}
	finance := f.token(f.tenant, jointFinanceSubject, "FINANCE")
	first := commitmentPortfolioGet(t, f, finance, posted.RequestID)
	commitmentPortfolioAssertNative(t, first, evidence)
	analysis := sourceDocument(first["analysis"])
	if model.String(first, "creator_id") != jointFinanceSubject || model.String(analysis, "request_id") != posted.RequestID || model.String(analysis, "id") != proof.AnalysisID || portfolio.Hash(analysis) != proof.AnalysisSHA256 || len(source.Rows(analysis["positions"])) != proof.PositionCount || len(source.Rows(analysis["unmatched_billing"])) != proof.UnmatchedBillingCount {
		t.Fatal("portfolio browser result differs from durable native analysis")
	}
	var decisionProof commitmentDecisionBrowserProof
	if e = fleetCapacityBrowserWait(journeyCtx, "decision-browser-result.json", &decisionProof); e != nil {
		t.Fatal("actual native decision browser result absent", e)
	}
	commitmentDecisionAssertBrowserPersisted(t, journeyCtx, f, admin, analyst, inputs, decisionProof)
	var completed fleetCapacityBrowserSignal
	if e = fleetCapacityBrowserWait(journeyCtx, "portfolio-worker-complete.json", &completed); e != nil || completed != signal {
		t.Fatal("portfolio daemon exclusion is unproved", e)
	}
	stopTicks()
	if tickErr := <-tickDone; tickErr != nil {
		t.Fatal("decision native routine tick failed", tickErr)
	}
	ticksStopped = true
	calculator, e := portfolio.NewHTTPCalculator(journeyCtx, portfolioNativeModel, "LOCAL_PRIVATE", modelToken)
	if e != nil {
		t.Fatal(e)
	}
	worker := portfolio.Worker{Pool: analyst.Pool, Tenant: f.tenant, Calculator: calculator}
	if replayed, e := worker.Process(journeyCtx, posted.RequestID); e != nil || !replayed {
		t.Fatal("portfolio actual daemon immutable replay failed", e)
	}
	second := commitmentPortfolioGet(t, f, finance, posted.RequestID)
	if portfolio.Hash(first) != portfolio.Hash(second) {
		t.Fatal("portfolio actual daemon persisted replay changed")
	}
	for _, row := range decisionProof.Cases {
		for _, requestID := range []string{row.PreparationRequestID, row.RequestID} {
			if replayed, e := worker.ProcessDecision(journeyCtx, requestID); e != nil || !replayed {
				t.Fatal("actual native decision immutable daemon replay failed", e)
			}
		}
	}
	commitmentDecisionAssertBrowserPersisted(t, journeyCtx, f, admin, analyst, inputs, decisionProof)
	return &proof
}
