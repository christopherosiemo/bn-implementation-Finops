package workflow

import (
	"errors"
	"time"

	"go.temporal.io/sdk/temporal"
	tw "go.temporal.io/sdk/workflow"
)

// FleetInput contains identifiers only. Activities load immutable v4 records,
// signatures, exact saved plans and current authority using their own identities.
// This workflow is separate from Occurrence so existing v3 histories replay.
type FleetInput struct {
	TenantID    string `json:"tenant_id"`
	ExecutionID string `json:"execution_id"`
}

type FleetNextInput struct {
	Input        FleetInput `json:"input"`
	RecoveryOnly bool       `json:"recovery_only"`
}

type FleetDecision struct {
	State       string `json:"state"` // READY, WAIT, COMPLETE, TAKEOVER
	CommandID   string `json:"command_id"`
	Operation   string `json:"operation"` // APPLY or ROLLBACK
	ReasonCode  string `json:"reason_code"`
	WaitSeconds int64  `json:"wait_seconds"`
}

type FleetCommandInput struct {
	Input        FleetInput `json:"input"`
	CommandID    string     `json:"command_id"`
	Operation    string     `json:"operation"`
	RecoveryOnly bool       `json:"recovery_only"`
}

type FleetIntent struct {
	CommandID        string `json:"command_id"`
	IntentRecorded   bool   `json:"intent_recorded"`
	DeliveryRequired bool   `json:"delivery_required"`
}

type FleetObservation struct {
	State      string `json:"state"` // PENDING, HEALTHY, FAILED, ROLLED_BACK, TAKEOVER
	ReasonCode string `json:"reason_code"`
}

func fleetPoll(seconds int64) time.Duration {
	if seconds < 15 {
		seconds = 15
	}
	if seconds > 300 {
		seconds = 300
	}
	return time.Duration(seconds) * time.Second
}

// FleetV4 drives the customer deployment pipeline; it never applies Terraform
// itself. Authorization must atomically persist intent and retain the shared
// disruption reservation before a delivery can occur. A missing response always
// enters reconciliation. Delivery has one Temporal attempt; it is never retried
// by this workflow after an unknown apply outcome.
//
// FleetNext selects pending owned work before new work, and cannot choose a new
// child while an earlier command is unresolved. FleetObserve consumes machine
// attestations and rechecks health. A failure permanently disqualifies positive
// economics before FleetNext can prepare an owned compensation child. Every
// compensation still needs a fresh saved plan bound to current state.
func FleetV4(ctx tw.Context, in FleetInput) error {
	if in.TenantID == "" || in.ExecutionID == "" {
		return errors.New("FLEET_WORKFLOW_IDENTITY_REQUIRED")
	}
	recovery, _ := tw.NewDisconnectedContext(ctx)
	opts := tw.ActivityOptions{StartToCloseTimeout: 45 * time.Second, RetryPolicy: &temporal.RetryPolicy{InitialInterval: time.Second, MaximumInterval: 15 * time.Second, MaximumAttempts: 3}}
	recovery = tw.WithActivityOptions(recovery, opts)
	delivery := tw.WithActivityOptions(recovery, tw.ActivityOptions{StartToCloseTimeout: 45 * time.Second, RetryPolicy: &temporal.RetryPolicy{MaximumAttempts: 1}})
	recoveryOnly := false
	for {
		if ctx.Err() != nil {
			recoveryOnly = true
		}
		var next FleetDecision
		if err := tw.ExecuteActivity(recovery, "FleetNext", FleetNextInput{in, recoveryOnly}).Get(recovery, &next); err != nil {
			// Database or observer outages cannot clear ownership or its reservation.
			if err = tw.Sleep(recovery, 15*time.Second); err != nil {
				return err
			}
			continue
		}
		switch next.State {
		case "COMPLETE", "TAKEOVER":
			// TAKEOVER is terminal only after an audited operator explicitly accepts
			// the complete recovery obligation; expiry or timeout cannot select it.
			return nil
		case "WAIT":
			if err := tw.Sleep(recovery, fleetPoll(next.WaitSeconds)); err != nil {
				return err
			}
			continue
		case "READY":
		default:
			if err := tw.Sleep(recovery, 15*time.Second); err != nil {
				return err
			}
			continue
		}
		if next.CommandID == "" || next.Operation != "APPLY" && next.Operation != "ROLLBACK" || recoveryOnly && next.Operation != "ROLLBACK" {
			if err := tw.Sleep(recovery, 15*time.Second); err != nil {
				return err
			}
			continue
		}
		command := FleetCommandInput{in, next.CommandID, next.Operation, recoveryOnly}
		var intent FleetIntent
		if err := tw.ExecuteActivity(recovery, "FleetAuthorize", command).Get(recovery, &intent); err != nil {
			// Fresh authority, policy, state and safety can change between selection
			// and authorization. Re-select rather than dispatch a stale decision.
			if err = tw.Sleep(recovery, 15*time.Second); err != nil {
				return err
			}
			continue
		}
		if !intent.IntentRecorded || intent.CommandID != command.CommandID {
			if err := tw.Sleep(recovery, 15*time.Second); err != nil {
				return err
			}
			continue
		}
		// Even an activity crash after sending must only reconcile this ID.
		if ctx.Err() != nil {
			recoveryOnly = true
			command.RecoveryOnly = true
		}
		// Cancellation between selection and authorization may suppress forward
		// delivery, but cannot erase its durable intent. The observer must still
		// prove the outcome before the reservation can be released. The delivery
		// adapter also rechecks current database authority immediately before I/O.
		if intent.DeliveryRequired && (!recoveryOnly || command.Operation == "ROLLBACK") {
			_ = tw.ExecuteActivity(delivery, "FleetDeliver", command).Get(delivery, nil)
		}
		for {
			if ctx.Err() != nil {
				recoveryOnly = true
				command.RecoveryOnly = true
			}
			var observation FleetObservation
			err := tw.ExecuteActivity(recovery, "FleetObserve", command).Get(recovery, &observation)
			if err == nil {
				switch observation.State {
				case "HEALTHY", "ROLLED_BACK", "FAILED":
					// Failed effects remain owned until FleetNext issues compensation.
					// Rollback never causes another APPLY in this execution.
					if observation.State != "HEALTHY" {
						recoveryOnly = true
					}
					goto observed
				case "TAKEOVER":
					return nil
				}
			}
			if err = tw.Sleep(recovery, 15*time.Second); err != nil {
				return err
			}
		}
	observed:
	}
}
