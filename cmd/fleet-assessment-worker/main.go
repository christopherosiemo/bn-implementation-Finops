// A default-disabled, commissioned analytical queue reader. No migrations,
// provider discovery, signing, archive writes or execution are available.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	w "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetassessmentworker"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

const readinessTimeout = 2 * time.Second

type invocation uint8

const (
	serve invocation = iota
	probe
	forbidden
)

func commandMode(args []string) invocation {
	if len(args) == 0 {
		return serve
	}
	if len(args) == 1 && args[0] == "--healthcheck" {
		return probe
	}
	return forbidden
}

// The probe has a fixed loopback destination and no configuration or credential
// loading. An injected transport is used only by the package's bounded tests.
func readinessProbe(transport http.RoundTripper) bool {
	ctx, cancel := context.WithTimeout(context.Background(), readinessTimeout)
	defer cancel()
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, "http://127.0.0.1:8080/readyz", nil)
	if e != nil {
		return false
	}
	client := &http.Client{Transport: transport, Timeout: readinessTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, e := client.Do(req)
	if e != nil {
		return false
	}
	defer response.Body.Close()
	return response.StatusCode == http.StatusOK
}

func run() int {
	switch commandMode(os.Args[1:]) {
	case probe:
		transport := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: readinessTimeout}).DialContext, DisableKeepAlives: true, ResponseHeaderTimeout: readinessTimeout}
		defer transport.CloseIdleConnections()
		if readinessProbe(transport) {
			return 0
		}
		return 1
	case forbidden:
		fmt.Fprintln(os.Stderr, "FLEET_ASSESSMENT_ARGUMENTS_FORBIDDEN")
		return 1
	}
	c, e := w.ConfigFromEnvironment(os.Getenv)
	if e != nil {
		fmt.Fprintln(os.Stderr, "FLEET_ASSESSMENT_CONFIGURATION_INVALID")
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	worker, e := w.Open(ctx, c)
	if e != nil {
		fmt.Fprintln(os.Stderr, "FLEET_ASSESSMENT_STARTUP_REFUSED")
		return 1
	}
	defer worker.Close()
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(out http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			out.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		out.Header().Set("Content-Type", "application/json")
		_, _ = out.Write([]byte(`{"status":"ok"}`))
	})
	mux.HandleFunc("/readyz", func(out http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			out.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		check, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if !worker.Ready(check) {
			out.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		out.Header().Set("Content-Type", "application/json")
		_, _ = out.Write([]byte(`{"status":"ready"}`))
	})
	server := &http.Server{Addr: ":8080", Handler: mux, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second}
	failed := make(chan error, 1)
	go func() { failed <- server.ListenAndServe() }()
	done := make(chan error, 1)
	go func() { done <- worker.Run(ctx, func(p w.PollResult) { _ = json.NewEncoder(os.Stdout).Encode(p) }) }()
	status := 0
	select {
	case <-ctx.Done():
	case <-done:
	case e := <-failed:
		if e != http.ErrServerClosed {
			status = 1
			fmt.Fprintln(os.Stderr, "FLEET_ASSESSMENT_HEALTH_SERVER_REFUSED")
		}
	}
	stop()
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = server.Shutdown(shutdown)
	return status
}
func main() { os.Exit(run()) }
