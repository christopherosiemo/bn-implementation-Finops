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

	"github.com/christopherosiemo/bn-implementation-Finops/internal/auth"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/safety"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/service"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
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
	mode := flag.String("mode", cfg.Role, "api|worker|ingester|signer|executor|migrate")
	flag.Parse()
	cfg.Role = *mode
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	db, e := store.Open(ctx, cfg.DatabaseURL)
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
	switch cfg.Role {
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
	case "worker", "ingester":
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
