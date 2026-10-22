package service

import (
	"context"
	"errors"
	"testing"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
)

func TestFleetConfigurationRetryOnlyTypedBusyAndHonorsCancellation(t *testing.T) {
	path := "/v1/fleet-history-registrations/issued/configuration-proposals"
	for _, original := range []error{store.ErrConflict, store.ErrFleetConfigurationBinding, errors.New("FLEET_HISTORY_SOURCE_BUSY")} {
		calls := 0
		got := fleetConfigurationTransaction(context.Background(), path, func(context.Context) error { calls++; return original })
		if got != original || calls != 1 {
			t.Fatal("nonbusy error retried", calls)
		}
	}
	calls := 0
	got := fleetConfigurationTransaction(context.Background(), "/v1/fleet-history-scopes", func(context.Context) error { calls++; return store.ErrFleetHistorySourceBusy })
	if !errors.Is(got, store.ErrFleetHistorySourceBusy) || calls != 1 {
		t.Fatal("retry escaped configuration routes", calls)
	}
	ctx, cancel := context.WithCancel(context.Background())
	calls = 0
	got = fleetConfigurationTransaction(ctx, path, func(context.Context) error { calls++; cancel(); return store.ErrFleetHistorySourceBusy })
	if !errors.Is(got, context.Canceled) || calls != 1 {
		t.Fatal("canceled request retried or became busy authority", calls)
	}
}
