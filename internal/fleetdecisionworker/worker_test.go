package fleetdecisionworker

import (
	"context"
	"errors"
	"testing"
)

func TestWorkerRefusesUncommissionedConfiguration(t *testing.T) {
	for _, w := range []Worker{{}, {Tenant: "tenant"}} {
		if _, _, e := w.Process(context.Background(), "request"); !errors.Is(e, ErrJob) {
			t.Fatal("missing commissioned store accepted")
		}
		if _, e := w.RunOnce(context.Background(), 1); !errors.Is(e, ErrJob) {
			t.Fatal("missing store polled")
		}
	}
}
