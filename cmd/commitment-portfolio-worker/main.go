package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	w "github.com/christopherosiemo/bn-implementation-Finops/internal/commitmentportfolio"
)

func healthcheck(transport http.RoundTripper) error {
	if transport == nil {
		transport = &http.Transport{Proxy: nil}
	}
	client := &http.Client{Timeout: 2 * time.Second, Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, _ := http.NewRequest(http.MethodGet, "http://127.0.0.1:8080/readyz", nil)
	response, e := client.Do(request)
	if e != nil {
		return errors.New("READINESS_REFUSED")
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	if response.StatusCode != http.StatusOK {
		return errors.New("READINESS_REFUSED")
	}
	return nil
}
func commandMode(args []string) (string, error) {
	if len(args) == 0 {
		return "serve", nil
	}
	if len(args) == 1 && args[0] == "--healthcheck" {
		return "healthcheck", nil
	}
	return "", errors.New("ARGUMENTS_REFUSED")
}
func run(ctx context.Context) error {
	cfg, e := w.ReadConfig()
	if e != nil {
		return errors.New("COMMITMENT_PORTFOLIO_STARTUP_REFUSED")
	}
	var worker *w.Worker
	if cfg.Enabled {
		worker, e = w.Open(ctx, cfg)
		if e != nil {
			return errors.New("COMMITMENT_PORTFOLIO_STARTUP_REFUSED")
		}
		defer worker.Close()
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(rw http.ResponseWriter, r *http.Request) { rw.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/readyz", func(rw http.ResponseWriter, r *http.Request) {
		check, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if worker == nil || !worker.Ready(check) {
			rw.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		rw.WriteHeader(http.StatusOK)
	})
	server := &http.Server{Addr: ":8080", Handler: mux, ReadHeaderTimeout: 2 * time.Second, WriteTimeout: 3 * time.Second, IdleTimeout: 30 * time.Second}
	errCh := make(chan error, 1)
	go func() { errCh <- server.ListenAndServe() }()
	if worker != nil {
		go func() {
			_ = worker.Run(ctx, func(completed int, result error) {
				status := "IDLE"
				if result != nil {
					status = "REFUSED"
				} else if completed > 0 {
					status = "PROCESSED"
				}
				_ = json.NewEncoder(os.Stdout).Encode(struct {
					Status    string `json:"status"`
					Completed int    `json:"completed"`
				}{status, completed})
			})
		}()
	}
	select {
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
		return nil
	case <-errCh:
		return errors.New("COMMITMENT_PORTFOLIO_HEALTH_SERVER_REFUSED")
	}
}
func main() {
	mode, e := commandMode(os.Args[1:])
	if e != nil {
		os.Exit(2)
	}
	if mode == "healthcheck" {
		if healthcheck(nil) != nil {
			os.Exit(1)
		}
		return
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if e = run(ctx); e != nil {
		_, _ = os.Stderr.WriteString("COMMITMENT_PORTFOLIO_STARTUP_REFUSED\n")
		os.Exit(1)
	}
}
