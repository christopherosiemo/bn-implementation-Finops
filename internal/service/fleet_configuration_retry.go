package service

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
)

const (
	fleetConfigurationRequestBudget = 25 * time.Second
	fleetConfigurationBusyBudget    = 2 * time.Second
	fleetConfigurationBusyDelay     = 100 * time.Millisecond
)

// The attempt owns a complete Store.Do call. It has returned only after commit
// or rollback, so no database, graph, idempotency or source lock spans a wait.
// The caller preserves the exact body/hash/If-Match/key and reauthorizes and
// reselects current bindings inside each fresh transaction.
func fleetConfigurationTransaction(parent context.Context, requestPath string, attempt func(context.Context) error) error {
	parts := strings.Split(strings.TrimPrefix(requestPath, "/v1/"), "/")
	if len(parts) != 3 || !fleetConfigurationRoute(parts) {
		return attempt(parent)
	}
	requestCtx, cancel := context.WithTimeout(parent, fleetConfigurationRequestBudget)
	defer cancel()
	err := attempt(requestCtx)
	if !errors.Is(err, store.ErrFleetHistorySourceBusy) {
		return fleetConfigurationBudgetError(parent, requestCtx, err)
	}
	retryCtx, stop := context.WithTimeout(requestCtx, fleetConfigurationBusyBudget)
	defer stop()
	for {
		timer := time.NewTimer(fleetConfigurationBusyDelay)
		select {
		case <-parent.Done():
			timer.Stop()
			return parent.Err()
		case <-retryCtx.Done():
			timer.Stop()
			if parent.Err() != nil {
				return parent.Err()
			}
			return store.ErrFleetHistorySourceBusy
		case <-timer.C:
		}
		err = attempt(retryCtx)
		if errors.Is(err, store.ErrFleetHistorySourceBusy) {
			continue
		}
		if parent.Err() != nil {
			return parent.Err()
		}
		if retryCtx.Err() != nil && (errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)) {
			return store.ErrFleetHistorySourceBusy
		}
		return fleetConfigurationBudgetError(parent, requestCtx, err)
	}
}

func fleetConfigurationBudgetError(parent, requestCtx context.Context, err error) error {
	if parent.Err() != nil {
		return parent.Err()
	}
	if requestCtx.Err() != nil && (errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled)) {
		return problem(503, "FLEET_CONFIGURATION_REQUEST_BUDGET_EXCEEDED", "fleet configuration request exceeded its synchronous budget; retry the same request with the same Idempotency-Key")
	}
	return err
}
