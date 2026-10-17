package workflow

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/testsuite"
)

type fakeActivities struct {
	mu                             sync.Mutex
	stages                         []StageInput
	operations                     []string
	stopError, owned, paused, live bool
	now                            time.Time
}

func (f *fakeActivities) Control(context.Context, model.WorkflowInput) (Control, error) {
	return Control{Restore: f.paused, StopAt: f.now}, nil
}
func (f *fakeActivities) Sign(context.Context, model.WorkflowInput) (model.Envelope, error) {
	return model.Envelope{Plan: model.Plan{Fixture: !f.live, RestoreAt: f.now.Add(3 * time.Second)}}, nil
}
func (f *fakeActivities) Stage(_ context.Context, s StageInput) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stages = append(f.stages, s)
	return nil
}
func (f *fakeActivities) Owned(context.Context, model.WorkflowInput) (bool, error) {
	return f.owned, nil
}
func (f *fakeActivities) Dispatch(_ context.Context, in DispatchInput) (model.ProviderState, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.operations = append(f.operations, in.Operation)
	if in.Operation == "STOP" {
		if f.stopError {
			return model.ProviderState{}, temporal.NewNonRetryableApplicationError("uncertain provider stop", "ProviderError", errors.New("timeout"))
		}
		return model.ProviderState{State: "stopped"}, nil
	}
	return model.ProviderState{State: "running", Healthy: true}, nil
}
func TestDurableOccurrenceRestoresAndCompletes(t *testing.T) {
	for _, live := range []bool{false, true} {
		t.Run(map[bool]string{false: "logical-fixture", true: "live-health-span"}[live], func(t *testing.T) {
			var suite testsuite.WorkflowTestSuite
			env := suite.NewTestWorkflowEnvironment()
			now := time.Now()
			env.SetStartTime(now)
			f := &fakeActivities{now: now, owned: true, live: live}
			env.RegisterActivity(f)
			env.ExecuteWorkflow(Occurrence, model.WorkflowInput{TenantID: "tenant", ExecutionID: "execution", PlanID: "plan"})
			if e := env.GetWorkflowError(); e != nil {
				t.Fatal(e)
			}
			if !env.IsWorkflowCompleted() {
				t.Fatal("workflow not completed")
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			last := f.stages[len(f.stages)-1]
			if last.Status != "COMPLETED" || last.Owned {
				t.Fatalf("unexpected final state %+v", last)
			}
			if live && env.Now().Sub(now) < 60*time.Second {
				t.Fatal("health stabilization shorter than 60s")
			}
			hasStop, hasStart := false, false
			for _, op := range f.operations {
				hasStop = hasStop || op == "STOP"
				hasStart = hasStart || op == "START"
			}
			if !hasStop || !hasStart {
				t.Fatal("missing do/compensation pair")
			}
		})
	}
}
func TestOverrideBeforeStopSkipsMutation(t *testing.T) {
	var suite testsuite.WorkflowTestSuite
	env := suite.NewTestWorkflowEnvironment()
	f := &fakeActivities{now: time.Now(), paused: true}
	env.RegisterActivity(f)
	env.ExecuteWorkflow(Occurrence, model.WorkflowInput{TenantID: "t"})
	if e := env.GetWorkflowError(); e != nil {
		t.Fatal(e)
	}
	if len(f.operations) != 0 {
		t.Fatal("paused occurrence mutated")
	}
	if f.stages[len(f.stages)-1].Status != "SKIPPED" {
		t.Fatal("pause did not skip")
	}
}
func TestUncertainStopStillRestoresWithoutClaimingSuccess(t *testing.T) {
	var suite testsuite.WorkflowTestSuite
	env := suite.NewTestWorkflowEnvironment()
	f := &fakeActivities{now: time.Now(), owned: true, stopError: true}
	env.RegisterActivity(f)
	env.ExecuteWorkflow(Occurrence, model.WorkflowInput{TenantID: "t"})
	if e := env.GetWorkflowError(); e != nil {
		t.Fatal(e)
	}
	last := f.stages[len(f.stages)-1]
	if last.Status != "FAILED" || last.Stage != "ROLLED_BACK" {
		t.Fatalf("uncertain stop claimed successful: %+v", last)
	}
	started := false
	for _, op := range f.operations {
		started = started || op == "START"
	}
	if !started {
		t.Fatal("uncertain mutation lost restoration obligation")
	}
}
