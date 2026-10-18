package workflow

import (
	"context"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"go.temporal.io/sdk/testsuite"
	"testing"
	"time"
)

type sloRecoveryActivities struct {
	fakeActivities
	controls int
}

func (f *sloRecoveryActivities) Control(context.Context, model.WorkflowInput) (Control, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.controls++
	if f.controls == 2 {
		return Control{Restore: true, Disqualified: true, ReasonCode: "SLO_ERROR_RATE_BREACH", StopAt: f.now}, nil
	}
	// Subsequent healthy telemetry cannot erase the first observed failure.
	return Control{StopAt: f.now}, nil
}
func (f *sloRecoveryActivities) Sign(context.Context, model.WorkflowInput) (model.Envelope, error) {
	return model.Envelope{Plan: model.Plan{Fixture: true, SchemaVersion: "3", SLOObjectiveID: "objective", RestoreAt: f.now.Add(time.Hour)}}, nil
}
func TestSLOBreachRestoresOnceAndCannotBecomeCompletedAfterGoodTelemetry(t *testing.T) {
	var suite testsuite.WorkflowTestSuite
	env := suite.NewTestWorkflowEnvironment()
	now := time.Now()
	env.SetStartTime(now)
	f := &sloRecoveryActivities{fakeActivities: fakeActivities{now: now, owned: true}}
	env.RegisterActivity(f)
	env.ExecuteWorkflow(Occurrence, model.WorkflowInput{TenantID: "tenant", ExecutionID: "execution", PlanID: "plan"})
	if err := env.GetWorkflowError(); err != nil {
		t.Fatal(err)
	}
	if !env.IsWorkflowCompleted() {
		t.Fatal("compensation did not complete")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	last := f.stages[len(f.stages)-1]
	if last.Status != "FAILED" || last.Stage != "ROLLED_BACK" || last.Owned || last.Error != "SLO_ERROR_RATE_BREACH" {
		t.Fatalf("latergood telemetry erased occurrence failure:%+v", last)
	}
	stops, starts, health := 0, 0, 0
	for _, op := range f.operations {
		switch op {
		case "STOP":
			stops++
		case "START":
			starts++
		case "HEALTH":
			health++
		}
	}
	if stops != 1 || starts == 0 || health < 3 || f.controls < 4 {
		t.Fatalf("incorrect mutation/recovery sequence:stop%d,start%d,health%d,controls%d", stops, starts, health, f.controls)
	}
}
