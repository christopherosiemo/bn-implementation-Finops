package service

// Optional acceptance bridge for the production App and the separately owned
// analytical daemon. The host owns services and the two-file secret volume.
// This fixture never invokes Process for the browser's queued request.
import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/auth"
	portfolio "github.com/christopherosiemo/bn-implementation-Finops/internal/commitmentportfolio"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/fleetbilling"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/source"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/coreos/go-oidc/v3/oidc"
)

type commitmentPortfolioBrowserReady struct {
	SchemaVersion               string              `json:"schema_version"`
	RunID                       string              `json:"run_id"`
	TenantID                    string              `json:"tenant_id"`
	Selection                   portfolio.Selection `json:"selection"`
	Fixture                     bool                `json:"fixture"`
	CustomerExecutionAuthorized bool                `json:"customer_execution_authorized"`
}

type commitmentPortfolioWorkerFile struct {
	SHA256 string `json:"sha256"`
	Size   int    `json:"size"`
}

type commitmentPortfolioWorkerFiles struct {
	Database   commitmentPortfolioWorkerFile `json:"database"`
	ModelToken commitmentPortfolioWorkerFile `json:"model_token"`
}

type commitmentPortfolioWorkerReady struct {
	SchemaVersion       string                         `json:"schema_version"`
	RunID               string                         `json:"run_id"`
	TenantID            string                         `json:"tenant_id"`
	Purpose             string                         `json:"purpose"`
	ConfigurationSHA256 string                         `json:"configuration_sha256"`
	Files               commitmentPortfolioWorkerFiles `json:"files"`
}

type commitmentPortfolioBrowserRequest struct {
	SchemaVersion string `json:"schema_version"`
	RunID         string `json:"run_id"`
	RequestID     string `json:"request_id"`
}

type commitmentPortfolioBrowserProof struct {
	SchemaVersion               string  `json:"schema_version"`
	Status                      string  `json:"status"`
	RunID                       string  `json:"run_id"`
	TenantID                    string  `json:"tenant_id"`
	RequestID                   string  `json:"request_id"`
	AnalysisID                  string  `json:"analysis_id"`
	AnalysisSHA256              string  `json:"analysis_sha256"`
	SelectionSHA256             string  `json:"selection_sha256"`
	CreatorID                   string  `json:"creator_id"`
	PositionCount               int     `json:"position_count"`
	UnmatchedBillingCount       int     `json:"unmatched_billing_count"`
	OIDCPKCE                    bool    `json:"oidc_pkce"`
	OIDCAuthorizationCode       bool    `json:"oidc_authorization_code"`
	UIIDsOnlyRequest            bool    `json:"ui_ids_only_request"`
	ActualPortfolioWorker       bool    `json:"actual_portfolio_worker"`
	ObservedUtilization         bool    `json:"observed_utilization"`
	ObservedUnusedCommitment    bool    `json:"observed_unused_commitment"`
	SparseRIUnknown             bool    `json:"sparse_ri_unknown"`
	NativeConcentration         bool    `json:"native_concentration"`
	PersistedReload             bool    `json:"persisted_reload"`
	Fixture                     bool    `json:"fixture"`
	RecommendationAuthorized    bool    `json:"recommendation_authorized"`
	PurchaseAuthorized          bool    `json:"purchase_authorized"`
	CustomerExecutionAuthorized bool    `json:"customer_execution_authorized"`
	ExpectedSavings             *string `json:"expected_savings"`
	EstimatedSaving             *string `json:"estimated_saving"`
	VerifiedSaving              *string `json:"verified_saving"`
}

func commitmentPortfolioWorkerEnvironment(tenant string) map[string]string {
	return map[string]string{
		"COMMITMENT_PORTFOLIO_ENABLED":          "true",
		"COMMITMENT_PORTFOLIO_TENANT_ID":        tenant,
		"COMMITMENT_PORTFOLIO_DATABASE_FILE":    "/run/secrets/commitment-portfolio-database",
		"COMMITMENT_PORTFOLIO_DATABASE_MODE":    "LOCAL_PRIVATE",
		"COMMITMENT_PORTFOLIO_MODEL_URL":        portfolioNativeModel,
		"COMMITMENT_PORTFOLIO_MODEL_TOKEN_FILE": "/run/secrets/commitment-portfolio-model-token",
	}
}

func commitmentPortfolioBrowserSchema(t *testing.T, ctx context.Context, admin *store.Store) {
	t.Helper()
	dir := t.TempDir()
	entries, e := os.ReadDir("../../migrations")
	if e != nil {
		t.Fatal(e)
	}
	count := 0
	for _, entry := range entries {
		if entry.IsDir() || !regexp.MustCompile(`^(00[1-9]|0[12][0-9]|03[0-9])_[a-z0-9_]+\.sql$`).MatchString(entry.Name()) {
			continue
		}
		raw, e := os.ReadFile(filepath.Join("../../migrations", entry.Name()))
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join(dir, entry.Name()), raw, 0600); e != nil {
			t.Fatal(e)
		}
		count++
	}
	if count != 39 {
		t.Fatal("portfolio browser schema prefix differs", count)
	}
	if e = admin.Migrate(ctx, dir); e != nil {
		t.Fatal("portfolio browser schema", e)
	}
}

func commitmentPortfolioBrowserSecrets(t *testing.T, analyst *store.Store, runID, tenant, token string) commitmentPortfolioWorkerReady {
	t.Helper()
	dir := "/portfolio-secrets"
	s, e := os.Lstat(dir)
	resolved, re := filepath.EvalSymlinks(dir)
	entries, de := os.ReadDir(dir)
	if e != nil || re != nil || de != nil || !s.IsDir() || s.Mode()&os.ModeSymlink != 0 || s.Mode().Perm() != 0700 || resolved != dir || len(entries) != 0 {
		t.Fatal("portfolio browser secret volume is not fresh and private")
	}
	database := []byte(analyst.Pool.Config().ConnString() + "\n")
	modelToken := []byte(token + "\n")
	if len(database) == 0 || len(database) > 8192 || len(token) < 32 || len(token) > 4096 || strings.ContainsAny(token, "\r\n") || string(database) == string(modelToken) {
		t.Fatal("portfolio browser private credentials differ")
	}
	for name, raw := range map[string][]byte{"commitment-portfolio-database": database, "commitment-portfolio-model-token": modelToken} {
		if e = fleetCapacityDaemonWriteBytes(filepath.Join(dir, name), raw, 0600); e != nil {
			t.Fatal("portfolio browser secret publication", e)
		}
	}
	return commitmentPortfolioWorkerReady{SchemaVersion: "1", RunID: runID, TenantID: tenant, Purpose: "commitment-portfolio-reader", ConfigurationSHA256: portfolio.Hash(commitmentPortfolioWorkerEnvironment(tenant)), Files: commitmentPortfolioWorkerFiles{
		Database:   commitmentPortfolioWorkerFile{SHA256: fleetbilling.BytesHash(database), Size: len(database)},
		ModelToken: commitmentPortfolioWorkerFile{SHA256: fleetbilling.BytesHash(modelToken), Size: len(modelToken)},
	}}
}

func commitmentPortfolioPositiveBrowserPhase(t *testing.T, ctx context.Context, f *mutationReplayFixture, admin, analyst *store.Store, evidence commitmentPortfolioNativeEvidence, modelToken string) *commitmentPortfolioBrowserProof {
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
	commitmentPortfolioBrowserSchema(t, setupCtx, admin)
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
	workerReady := commitmentPortfolioBrowserSecrets(t, analyst, runID, f.tenant, modelToken)
	if _, e = fleetCapacityBrowserWrite("/results/portfolio-worker-ready.json", workerReady); e != nil {
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
	var completed fleetCapacityBrowserSignal
	if e = fleetCapacityBrowserWait(journeyCtx, "portfolio-worker-complete.json", &completed); e != nil || completed != signal {
		t.Fatal("portfolio daemon exclusion is unproved", e)
	}
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
	return &proof
}
