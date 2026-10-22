package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/groupfixturecommission"
)

func run() int {
	if len(os.Args) != 1 {
		fmt.Fprintln(os.Stderr, "ISOLATED_GROUP_COMMISSION_ARGUMENTS_REFUSED")
		return 1
	}
	if groupfixturecommission.StagePrivateInput(os.Stdin) != nil {
		fmt.Fprintln(os.Stderr, "ISOLATED_GROUP_COMMISSION_PRIVATE_INPUT_REFUSED")
		return 1
	}
	raw, e := os.ReadFile("/secrets/job.json")
	if e != nil {
		fmt.Fprintln(os.Stderr, "ISOLATED_GROUP_COMMISSION_PRIVATE_JOB_REQUIRED")
		return 1
	}
	c, e := groupfixturecommission.Decode(raw)
	if e != nil {
		fmt.Fprintln(os.Stderr, "ISOLATED_GROUP_COMMISSION_JOB_REFUSED")
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	result, e := groupfixturecommission.Run(ctx, c)
	if e != nil {
		fmt.Fprintln(os.Stderr, "ISOLATED_GROUP_COMMISSION_REFUSED")
		return 1
	}
	if json.NewEncoder(os.Stdout).Encode(result) != nil {
		return 1
	}
	return 0
}
func main() { os.Exit(run()) }
