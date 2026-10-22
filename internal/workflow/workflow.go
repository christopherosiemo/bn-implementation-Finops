package workflow

import (
	"context"
	"errors"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"go.temporal.io/sdk/temporal"
	tw "go.temporal.io/sdk/workflow"
)

type StageInput struct {
	Input                model.WorkflowInput
	Status, Stage, Error string
	Owned                bool
}
type SignInput struct{ Input model.WorkflowInput }
type DispatchInput struct {
	Input     model.WorkflowInput
	Envelope  model.Envelope
	Operation string
}
type Control struct {
	Restore      bool
	StopAt       time.Time
	Disqualified bool
	ReasonCode   string
}

// Occurrence is a durable resource-scoped stop AND restoration obligation.
// Once a stop is attempted, its compensation is never abandoned on cancellation,
// approval expiry, pause, service restart or an uncertain provider response.
func Occurrence(ctx tw.Context, in model.WorkflowInput) error {
	ctx = tw.WithActivityOptions(ctx, tw.ActivityOptions{StartToCloseTimeout: 45 * time.Second, RetryPolicy: &temporal.RetryPolicy{InitialInterval: time.Second, MaximumInterval: 15 * time.Second, MaximumAttempts: 3}})
	stage := func(status, step string, owned bool, err string) {
		_ = tw.ExecuteActivity(ctx, "Stage", StageInput{in, status, step, err, owned}).Get(ctx, nil)
	}
	var control Control
	if e := tw.ExecuteActivity(ctx, "Control", in).Get(ctx, &control); e != nil {
		stage("FAILED", "PRECHECK", false, e.Error())
		return e
	}
	if delay := control.StopAt.Sub(tw.Now(ctx)); delay > 0 {
		if e := tw.Sleep(ctx, delay); e != nil {
			return e
		}
	}
	var envelope model.Envelope
	if control.Restore {
		stage("SKIPPED", "PRECHECK", false, "restoration override or safety control cancelled this occurrence")
		return nil
	}
	if e := tw.ExecuteActivity(ctx, "Sign", in).Get(ctx, &envelope); e != nil {
		stage("SKIPPED", "PRECHECK", false, e.Error())
		return nil
	}
	stage("EXECUTING", "STOPPING", false, "")
	var state model.ProviderState
	stopErr := tw.ExecuteActivity(ctx, "Dispatch", DispatchInput{in, envelope, "STOP"}).Get(ctx, &state)
	if stopErr == nil && state.State != "stopped" {
		deadline := tw.Now(ctx).Add(10 * time.Minute)
		for state.State != "stopped" && tw.Now(ctx).Before(deadline) {
			if e := tw.Sleep(ctx, 15*time.Second); e != nil {
				stopErr = e
				break
			}
			if envelope.Plan.SLOObjectiveID != "" {
				var c Control
				if e := tw.ExecuteActivity(ctx, "Control", in).Get(ctx, &c); e != nil {
					stopErr = e
					break
				} else if c.Disqualified {
					stopErr = errors.New(c.ReasonCode)
					break
				}
			}
			if e := tw.ExecuteActivity(ctx, "Dispatch", DispatchInput{in, envelope, "DESCRIBE"}).Get(ctx, &state); e != nil {
				stopErr = e
				break
			}
		}
		if stopErr == nil && state.State != "stopped" {
			stopErr = errors.New("stop transition exceeded ten minutes; restoring immediately")
		}
	}
	// All paths after STOP use a disconnected context: worker or caller cancellation
	// cannot cancel restoration. Executor independently requires persisted stop intent.
	recovery, _ := tw.NewDisconnectedContext(ctx)
	recovery = tw.WithActivityOptions(recovery, tw.ActivityOptions{StartToCloseTimeout: 45 * time.Second, RetryPolicy: &temporal.RetryPolicy{InitialInterval: time.Second, MaximumInterval: 30 * time.Second, MaximumAttempts: 3}})
	sloError := ""
	if stopErr == nil {
		stage("EXECUTING", "STOPPED", true, "")
		poll := 15 * time.Second
		if envelope.Plan.Fixture {
			poll = time.Second
		}
		for tw.Now(ctx).Before(envelope.Plan.RestoreAt) {
			var c Control
			e := tw.ExecuteActivity(ctx, "Control", in).Get(ctx, &c)
			if e != nil && envelope.Plan.SLOObjectiveID != "" {
				sloError = "SLO_OBSERVATION_UNAVAILABLE"
			}
			if c.Disqualified {
				sloError = c.ReasonCode
			}
			if e != nil || c.Restore {
				break
			}
			var observed model.ProviderState
			if e = tw.ExecuteActivity(ctx, "Dispatch", DispatchInput{in, envelope, "DESCRIBE"}).Get(ctx, &observed); e != nil || observed.State == "running" {
				break
			}
			wait := poll
			if remaining := envelope.Plan.RestoreAt.Sub(tw.Now(ctx)); remaining < wait {
				wait = remaining
			}
			if e = tw.Sleep(ctx, wait); e != nil {
				break
			}
		}
	}
	stepError := sloError
	if stopErr != nil {
		stepError = stopErr.Error()
	}
	_ = tw.ExecuteActivity(recovery, "Stage", StageInput{in, "RESTORING", "STARTING", stepError, true}).Get(recovery, nil)
	// A failed stop that has no persisted intention is safely terminal; otherwise
	// retry until restoration, even if execution authorization subsequently expires.
	healthyCount := 0
	attempts := 0
	poll := 15 * time.Second
	if envelope.Plan.Fixture {
		poll = time.Second
	}
	for {
		attempts++
		var result model.ProviderState
		e := tw.ExecuteActivity(recovery, "Dispatch", DispatchInput{in, envelope, "START"}).Get(recovery, &result)
		if attempts == 1 && stopErr != nil {
			var owned bool
			if oe := tw.ExecuteActivity(recovery, "Owned", in).Get(recovery, &owned); oe == nil && !owned {
				_ = tw.ExecuteActivity(recovery, "Stage", StageInput{in, "FAILED", "STOP_FAILED", stopErr.Error(), false}).Get(recovery, nil)
				return nil
			}
		}
		if e == nil && result.State == "running" {
			if envelope.Plan.SLOObjectiveID != "" {
				var c Control
				if err := tw.ExecuteActivity(recovery, "Control", in).Get(recovery, &c); err != nil {
					if stepError == "" {
						stepError = "SLO_OBSERVATION_UNAVAILABLE"
					}
				} else if c.Disqualified {
					stepError = c.ReasonCode
				}
			}
			if stepError != "" && envelope.Plan.SLOObjectiveID != "" {
				_ = tw.ExecuteActivity(recovery, "Stage", StageInput{in, "RESTORING", "STARTING", stepError, true}).Get(recovery, nil)
			}
			e = tw.ExecuteActivity(recovery, "Dispatch", DispatchInput{in, envelope, "HEALTH"}).Get(recovery, &result)
			if e == nil && result.Healthy {
				healthyCount++
			} else {
				healthyCount = 0
			}
			required := 5
			if envelope.Plan.Fixture {
				required = 3
			}
			if healthyCount >= required {
				status, step := "COMPLETED", "VERIFY_ECONOMICS"
				if stepError != "" {
					status, step = "FAILED", "ROLLED_BACK"
				}
				_ = tw.ExecuteActivity(recovery, "Stage", StageInput{in, status, step, stepError, false}).Get(recovery, nil)
				return nil
			}
		}
		if attempts >= 40 && !envelope.Plan.Fixture {
			message := "restoration or mandatory health checks incomplete; durable recovery continues"
			if e != nil {
				message = e.Error()
			}
			_ = tw.ExecuteActivity(recovery, "Stage", StageInput{in, "RESTORING", "RESTORATION_ALERT", message, true}).Get(recovery, nil)
			poll = 5 * time.Minute
		}
		if envelope.Plan.Fixture && attempts >= 10 {
			_ = tw.ExecuteActivity(recovery, "Stage", StageInput{in, "RESTORING", "HEALTH_ALERT", "fixture health check failed; restore already started, waiting for healthy scenario", false}).Get(recovery, nil)
			poll = 2 * time.Second
		}
		if e := tw.Sleep(recovery, poll); e != nil {
			return e
		}
	}
}

// This interface makes the workflow activities straightforward to substitute in
// Temporal's deterministic test environment.
type Runner interface {
	Stage(context.Context, StageInput) error
}
