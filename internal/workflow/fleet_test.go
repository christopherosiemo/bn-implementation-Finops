package workflow

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"go.temporal.io/sdk/testsuite"
)

type fleetActivitiesFixture struct {
	mu                      sync.Mutex
	nextCalls, observeCalls int
	delivered               []string
	seenRecovery            bool
	resume, failHealth      bool
	cancelAfterIntent       func()
}

func (f *fleetActivitiesFixture) FleetNext(_ context.Context, in FleetNextInput) (FleetDecision, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nextCalls++
	if f.nextCalls == 1 {
		return FleetDecision{State: "READY", CommandID: "apply-1", Operation: "APPLY"}, nil
	}
	if f.failHealth && f.nextCalls == 2 {
		f.seenRecovery = in.RecoveryOnly
		return FleetDecision{State: "READY", CommandID: "restore-1", Operation: "ROLLBACK"}, nil
	}
	return FleetDecision{State: "COMPLETE"}, nil
}
func (f *fleetActivitiesFixture) FleetAuthorize(_ context.Context, in FleetCommandInput) (FleetIntent, error) {
	if in.Operation == "APPLY" && f.cancelAfterIntent != nil {
		f.cancelAfterIntent()
	}
	return FleetIntent{CommandID: in.CommandID, IntentRecorded: true, DeliveryRequired: !f.resume || in.Operation == "ROLLBACK"}, nil
}
func (f *fleetActivitiesFixture) FleetDeliver(_ context.Context, in FleetCommandInput) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.delivered = append(f.delivered, in.Operation)
	if in.Operation == "APPLY" {
		return errors.New("response lost after pipeline accepted command")
	}
	return nil
}
func (f *fleetActivitiesFixture) FleetObserve(_ context.Context, in FleetCommandInput) (FleetObservation, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.observeCalls++
	if f.observeCalls < 3 {
		return FleetObservation{State: "PENDING"}, nil
	}
	if in.Operation == "ROLLBACK" {
		return FleetObservation{State: "ROLLED_BACK"}, nil
	}
	if f.failHealth {
		return FleetObservation{State: "FAILED", ReasonCode: "SLO_LATENCY_REGRESSION"}, nil
	}
	return FleetObservation{State: "HEALTHY"}, nil
}

func TestFleetUnknownApplyReconcilesWithoutDuplicateDelivery(t *testing.T) {
	for _, resume := range []bool{false, true} {
		var suite testsuite.WorkflowTestSuite
		env := suite.NewTestWorkflowEnvironment()
		f := &fleetActivitiesFixture{resume: resume}
		env.RegisterActivity(f)
		env.ExecuteWorkflow(FleetV4, FleetInput{"tenant", "execution"})
		if err := env.GetWorkflowError(); err != nil {
			t.Fatal(err)
		}
		f.mu.Lock()
		expected := 1
		if resume {
			expected = 0
		}
		if len(f.delivered) != expected || f.observeCalls != 3 {
			t.Fatalf("uncertainty caused redispatch or abandoned reconciliation: %+v", f.delivered)
		}
		f.mu.Unlock()
	}
}

func TestFleetFailedHealthRestoresAndCannotExpand(t *testing.T) {
	var suite testsuite.WorkflowTestSuite
	env := suite.NewTestWorkflowEnvironment()
	f := &fleetActivitiesFixture{failHealth: true}
	env.RegisterActivity(f)
	env.ExecuteWorkflow(FleetV4, FleetInput{"tenant", "execution"})
	if err := env.GetWorkflowError(); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.seenRecovery || len(f.delivered) != 2 || f.delivered[0] != "APPLY" || f.delivered[1] != "ROLLBACK" {
		t.Fatal("failed child expanded instead of durable compensation", f.delivered)
	}
}

func TestFleetCancellationPreservesInFlightReconciliation(t *testing.T) {
	var suite testsuite.WorkflowTestSuite
	env := suite.NewTestWorkflowEnvironment()
	f := &fleetActivitiesFixture{failHealth: true}
	env.RegisterActivity(f)
	env.RegisterDelayedCallback(func() { env.CancelWorkflow() }, 5*time.Second)
	env.ExecuteWorkflow(FleetV4, FleetInput{"tenant", "execution"})
	// The disconnected recovery path may finish successfully despite cancellation;
	// the persisted obligation must be reconciled and rolled back either way.
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.seenRecovery || len(f.delivered) != 2 || f.delivered[1] != "ROLLBACK" {
		t.Fatal("cancellation stranded owned apply", f.delivered)
	}
}

func TestFleetCancellationAfterIntentSuppressesForwardDelivery(t *testing.T) {
	var suite testsuite.WorkflowTestSuite
	env := suite.NewTestWorkflowEnvironment()
	f := &fleetActivitiesFixture{failHealth: true, cancelAfterIntent: func() { env.CancelWorkflow() }}
	env.RegisterActivity(f)
	env.ExecuteWorkflow(FleetV4, FleetInput{"tenant", "execution"})
	if err := env.GetWorkflowError(); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.seenRecovery || len(f.delivered) != 1 || f.delivered[0] != "ROLLBACK" || f.observeCalls < 3 {
		t.Fatal("cancelled forward intent was delivered or its reconciliation abandoned", f.delivered)
	}
}
