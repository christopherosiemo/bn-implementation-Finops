package main

import (
	"context"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/activity"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/auth"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/deploymentobserver"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/native"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/safety"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/service"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/telemetry"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/workflow"
)

func main() {
	if e := run(); e != nil {
		slog.Error("service stopped", "error", e)
		os.Exit(1)
	}
}
func run() error {
	cfg := service.LoadConfig()
	mode := flag.String("mode", cfg.Role, "api|worker|ingester|database-assessor|storage-assessor|hardware-reader|fleet-history-reader|signer|executor|activity-ingress|telemetry-reader|telemetry-ingress|deployment-observer|migrate")
	flag.Parse()
	cfg.Role = *mode
	if !cfg.Fixture {
		if err := store.ValidateDatabaseTransport(cfg.DatabaseURL); err != nil {
			return err
		}
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	var db *store.Store
	var e error
	if cfg.Role == "hardware-reader" {
		db, e = store.OpenHardwareReader(ctx, cfg.DatabaseURL)
	} else if cfg.Role == "migrate" {
		db, e = store.Open(ctx, cfg.DatabaseURL)
	} else {
		db, e = store.OpenRuntime(ctx, cfg.DatabaseURL, cfg.Role)
	}
	if e != nil {
		return e
	}
	defer db.Pool.Close()
	if cfg.Role == "migrate" {
		dir := os.Getenv("MIGRATIONS_DIR")
		if dir == "" {
			dir = "migrations"
		}
		return db.Migrate(ctx, dir)
	}
	var handler http.Handler
	var nativeServer *native.Server
	switch cfg.Role {
	case "deployment-observer":
		issuer := os.Getenv("DEPLOYMENT_OIDC_ISSUER")
		if issuer == "" {
			issuer = cfg.Issuer
		}
		jwks := os.Getenv("DEPLOYMENT_OIDC_JWKS_URL")
		if jwks == "" && issuer == cfg.Issuer {
			jwks = cfg.JWKSURL
		}
		audience := os.Getenv("DEPLOYMENT_OIDC_AUDIENCE")
		if audience == "" {
			audience = "finops-deployment-observer"
		}
		observer, err := deploymentobserver.New(ctx, db, issuer, audience, jwks, cfg.Fixture, cfg.Audience, os.Getenv("ACTIVITY_OIDC_AUDIENCE"), os.Getenv("TELEMETRY_OIDC_AUDIENCE"))
		if err != nil {
			return err
		}
		handler = observer.Handler()
	case "telemetry-reader", "telemetry-ingress":
		storage, err := native.StorageFromEnvironment(ctx, cfg.Fixture)
		if err != nil {
			return err
		}
		pipeline := &native.Pipeline{Store: db, Archive: storage.Archive, ReadObject: storage.Read, WriteFacts: storage.WriteFacts}
		nativeServer = &native.Server{Store: db, Pipeline: pipeline, Fixture: cfg.Fixture}
		if cfg.Role == "telemetry-ingress" {
			issuer := os.Getenv("TELEMETRY_OIDC_ISSUER")
			if issuer == "" {
				issuer = cfg.Issuer
			}
			audience := os.Getenv("TELEMETRY_OIDC_AUDIENCE")
			if audience == "" {
				audience = "finops-telemetry"
			}
			activityAudience := os.Getenv("ACTIVITY_OIDC_AUDIENCE")
			if activityAudience == "" {
				activityAudience = "finops-activity"
			}
			if audience == cfg.Audience || audience == activityAudience {
				return &service.Problem{Status: 500, Message: "native telemetry audience must differ from human and activity audiences"}
			}
			jwks := os.Getenv("TELEMETRY_OIDC_JWKS_URL")
			if jwks == "" && issuer == cfg.Issuer {
				jwks = cfg.JWKSURL
			}
			validator, err := auth.New(ctx, issuer, audience, jwks)
			if err != nil {
				return err
			}
			nativeServer.Auth, nativeServer.Issuer = validator, issuer
		} else {
			nativeServer.ReaderToken = os.Getenv("TELEMETRY_READER_TOKEN")
			if nativeServer.ReaderToken == "" {
				return &service.Problem{Status: 500, Message: "TELEMETRY_READER_TOKEN is required"}
			}
			nativeServer.Bindings, err = native.BindingsFromEnv(os.Getenv("TELEMETRY_READ_BINDINGS_JSON"), cfg.Fixture)
			if err != nil {
				return err
			}
			if cfg.Fixture && len(nativeServer.Bindings) == 0 {
				nativeServer.Bindings = map[string]native.ReadBinding{"fixture-prometheus-dev-api": {Binding: telemetry.Binding{TenantID: "tenant-demo", ResourceID: "resource-dev-api", WorkloadID: "workload-dev", Provider: "AWS", ProviderResourceID: "i-0123456789abcdef0", AccountID: "111122223333", Region: "eu-west-1"}, Endpoint: "http://prometheus:9090", RequiredLabels: map[string]string{"finops_resource_id": "resource-dev-api"}}}
			}
		}
		nativeHandler := nativeServer.Handler()
		handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/healthz" {
				if err := db.Pool.Ping(r.Context()); err != nil {
					service.JSON(w, 503, map[string]string{"status": "degraded"})
					return
				}
				service.JSON(w, 200, map[string]any{"status": "ok", "role": cfg.Role, "fixture": cfg.Fixture})
				return
			}
			if cfg.Role == "telemetry-reader" && r.URL.Path != "/evaluate" && r.URL.Path != "/capacity-input" || cfg.Role == "telemetry-ingress" && r.URL.Path != "/v1/metrics" {
				http.NotFound(w, r)
				return
			}
			nativeHandler.ServeHTTP(w, r)
		})
	case "activity-ingress":
		issuer := os.Getenv("ACTIVITY_OIDC_ISSUER")
		if issuer == "" {
			issuer = cfg.Issuer
		}
		audience := os.Getenv("ACTIVITY_OIDC_AUDIENCE")
		if audience == "" {
			audience = "finops-activity"
		}
		if audience == cfg.Audience {
			return &service.Problem{Status: 500, Message: "activity audience must differ from console audience"}
		}
		jwks := os.Getenv("ACTIVITY_OIDC_JWKS_URL")
		if jwks == "" && issuer == cfg.Issuer {
			jwks = cfg.JWKSURL
		}
		v, e := auth.New(ctx, issuer, audience, jwks)
		if e != nil {
			return e
		}
		handler = activity.NewServer(db, v, issuer).Handler()
	case "api":
		v, e := auth.New(ctx, cfg.Issuer, cfg.Audience, cfg.JWKSURL)
		if e != nil {
			return e
		}
		handler = (&service.API{Store: db, Config: cfg, Auth: v, Client: &http.Client{Timeout: service.HTTPTimeout}}).Handler()
	case "signer":
		key, e := safety.PrivateKey(cfg.PrivateKey)
		if e != nil {
			return e
		}
		if cfg.SignerToken == "" {
			return &service.Problem{Status: 500, Message: "SIGNER_TOKEN is required"}
		}
		handler = (&service.SecureService{Store: db, Config: cfg, Private: key}).Handler()
	case "executor":
		key, e := safety.PublicKey(cfg.PublicKey)
		if e != nil {
			return e
		}
		if cfg.ExecutorToken == "" {
			return &service.Problem{Status: 500, Message: "EXECUTOR_TOKEN is required"}
		}
		handler = (&service.SecureService{Store: db, Config: cfg, Public: key}).Handler()
	case "worker", "ingester", "database-assessor", "storage-assessor", "object-storage-assessor", "hardware-reader", "fleet-history-reader":
		handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/healthz" {
				http.NotFound(w, r)
				return
			}
			if e := db.Pool.Ping(r.Context()); e != nil {
				service.JSON(w, 503, map[string]string{"status": "degraded"})
				return
			}
			service.JSON(w, 200, map[string]string{"status": "ok", "role": cfg.Role})
		})
	default:
		return &service.Problem{Status: 500, Message: "unknown APP_ROLE"}
	}
	server := &http.Server{Addr: ":" + cfg.Port, Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 40 * time.Second, WriteTimeout: 40 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	errs := make(chan error, 2)
	go func() {
		slog.Info("service listening", "role", cfg.Role, "port", cfg.Port, "fixture", cfg.Fixture)
		if e := server.ListenAndServe(); e != nil && e != http.ErrServerClosed {
			errs <- e
		}
	}()
	if cfg.Role == "worker" {
		go func() {
			if e := workflow.Run(ctx, cfg, db); e != nil {
				errs <- e
			}
		}()
	}
	if cfg.Role == "ingester" {
		go func() {
			if e := workflow.RunIngester(ctx, cfg, db); e != nil {
				errs <- e
			}
		}()
	}
	if cfg.Role == "database-assessor" {
		go func() {
			if err := service.RunDatabaseAssessor(ctx, cfg, db); err != nil {
				errs <- err
			}
		}()
	}
	if cfg.Role == "storage-assessor" {
		go func() {
			if err := service.RunStorageAssessor(ctx, cfg, db); err != nil {
				errs <- err
			}
		}()
	}
	if cfg.Role == "object-storage-assessor" {
		go func() {
			if err := service.RunObjectStorageAssessor(ctx, cfg, db); err != nil {
				errs <- err
			}
		}()
	}
	if cfg.Role == "hardware-reader" {
		go func() {
			if e := workflow.RunHardwareReader(ctx, cfg, db); e != nil {
				errs <- e
			}
		}()
	}
	if cfg.Role == "fleet-history-reader" {
		go func() {
			if err := workflow.RunFleetHistoryReader(ctx, cfg, db); err != nil {
				errs <- err
			}
		}()
	}
	if cfg.Role == "telemetry-reader" {
		go func() {
			if err := nativeServer.Run(ctx); err != nil {
				errs <- err
			}
		}()
	}
	select {
	case <-ctx.Done():
	case e = <-errs:
		cancel()
	}
	shutdown, done := context.WithTimeout(context.Background(), 10*time.Second)
	defer done()
	_ = server.Shutdown(shutdown)
	return e
}
