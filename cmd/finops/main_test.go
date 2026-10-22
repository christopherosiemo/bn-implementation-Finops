package main

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestEveryNonFixtureProcessRejectsPlaintextBeforeConnecting(t *testing.T) {
	for _, role := range []string{"api", "worker", "ingester", "hardware-reader", "fleet-history-reader", "signer", "executor", "activity-ingress", "telemetry-reader", "telemetry-ingress", "deployment-observer", "migrate"} {
		t.Run(role, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestTransportGuardChild$")
			for _, value := range os.Environ() {
				key := strings.SplitN(value, "=", 2)[0]
				if key != "FIXTURE_MODE" && key != "DATA_MODE" && key != "DATABASE_URL" && key != "APP_ROLE" && key != "FINOPS_TRANSPORT_GUARD_CHILD" {
					command.Env = append(command.Env, value)
				}
			}
			command.Env = append(command.Env, "FINOPS_TRANSPORT_GUARD_CHILD=1", "FIXTURE_MODE=false", "DATA_MODE=aws", "APP_ROLE="+role,
				"DATABASE_URL=postgres://fixture@127.0.0.1:1/finops?sslmode=disable")
			if err := command.Run(); err != nil {
				t.Fatal("process did not reject plaintext at the transport guard before attempting a connection")
			}
		})
	}
}

func TestTransportGuardChild(t *testing.T) {
	if os.Getenv("FINOPS_TRANSPORT_GUARD_CHILD") != "1" {
		return
	}
	if err := run(); err == nil || err.Error() != "DATABASE_VERIFIED_TLS_REQUIRED" {
		os.Exit(2)
	}
	os.Exit(0)
}
