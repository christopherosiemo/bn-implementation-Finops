// An optional single-job private fixture process. No daemon, HTTP endpoint,
// cloud call, signer, approval, journal delivery, migration or cleanup is run.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/groupfixtureworker"
)

func run() int {
	if len(os.Args) != 1 {
		fmt.Fprintln(os.Stderr, "GROUP_FIXTURE_PREPARER_ARGUMENTS_FORBIDDEN")
		return 1
	}
	config, err := groupfixtureworker.ConfigFromEnvironment(os.Getenv)
	if err != nil {
		fmt.Fprintln(os.Stderr, "GROUP_FIXTURE_PREPARER_CONFIGURATION_INVALID")
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	worker, err := groupfixtureworker.Open(ctx, config)
	if err != nil {
		fmt.Fprintln(os.Stderr, "GROUP_FIXTURE_PREPARER_STARTUP_REFUSED")
		return 1
	}
	defer worker.Close()
	result, err := worker.Run(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, "GROUP_FIXTURE_PREPARER_JOB_REFUSED")
		return 1
	}
	// Only immutable IDs/hashes and no customer authority are emitted.
	if json.NewEncoder(os.Stdout).Encode(result) != nil {
		return 1
	}
	return 0
}

func main() { os.Exit(run()) }
