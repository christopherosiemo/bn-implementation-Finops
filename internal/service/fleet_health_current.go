package service

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"sort"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/evidence"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/fleet"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/slo"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/workload"
	"github.com/jackc/pgx/v5"
)

type fleetHealthPopulation struct {
	Window          fleet.CohortWindow
	MemberWindowIDs []string
	NativeIDs       []string
	SLOIDs          []string
	Receipts        map[string][]fleetSLOReceipt
	Status          string
	Reasons         []string
	DefiniteFailure bool
}

func fleetHealthLimits(o slo.Objective) fleet.CohortLimits {
	l := o.Limits
	return fleet.CohortLimits{ObjectiveID: o.ID, ObjectiveVersion: o.Version, ObjectiveSHA256: slo.ObjectiveHash(o), MaximumErrorRatePPM: l.MaxErrorRatePPM, MinimumAvailabilityPPM: l.MinAvailabilityPPM, MaximumP95MS: l.MaxP95LatencyMS, MaximumP99MS: l.MaxP99LatencyMS, MinimumLatencySamples: l.MinLatencySamples, MaximumRegressionPercent: o.Regression.MaxPercent}
}

func fleetCollectHealthPopulation(ctx context.Context, tx *store.Tx, b fleet.Binding, asg, role string, ids []string, objective slo.Objective, profile workload.Profile, start, end, now time.Time) (fleetHealthPopulation, error) {
	p := fleetHealthPopulation{Window: fleet.CohortWindow{Binding: b, ASG: asg, Role: role, ObjectiveID: objective.ID, ObjectiveVersion: objective.Version, ObjectiveSHA256: slo.ObjectiveHash(objective), Start: start, End: end, Members: []fleet.CohortMemberWindow{}}, MemberWindowIDs: []string{}, NativeIDs: []string{}, SLOIDs: []string{}, Receipts: map[string][]fleetSLOReceipt{}, Status: "CLEAR", Reasons: []string{}}
	mark := func(status, reason string) {
		if status == "BREACH" || p.Status != "BREACH" {
			p.Status = status
		}
		p.Reasons = append(p.Reasons, reason)
		p.DefiniteFailure = true
	}
	for _, id := range fleetHealthSorted(ids) {
		binding, err := fleetHealthMemberBinding(ctx, tx, b, id)
		if errors.Is(err, pgx.ErrNoRows) {
			mark("BLOCKED", "COHORT_PHYSICAL_RESOURCE_MAPPING_REQUIRED")
			continue
		}
		if err != nil {
			return p, err
		}
		source, err := fleetHealthSource(ctx, tx, binding, objective.ID)
		if err != nil {
			mark("BLOCKED", "COHORT_MEMBER_REGISTERED_SLO_SOURCE_REQUIRED")
			continue
		}
		rows, err := fleetHealthReceipts(ctx, tx, source, start, end)
		if err != nil {
			return p, err
		}
		p.Receipts[id] = rows
		member := fleetBuildMemberWindow(binding, objective, source, start, end, now, rows)
		if member.Status != "CLEAR" {
			pending := fleetMemberDeliveryPending(member, start, end, now, rows)
			for _, reason := range member.ReasonCodes {
				if pending {
					if p.Status != "BREACH" {
						p.Status = "BLOCKED"
					}
					p.Reasons = append(p.Reasons, "COHORT_RECEIPT_DELIVERY_PENDING")
				} else {
					mark(member.Status, reason)
				}
			}
			continue
		}
		stored, err := fleetHealthPersistMember(ctx, tx, member)
		if err != nil {
			return p, err
		}
		p.MemberWindowIDs = append(p.MemberWindowIDs, model.String(stored, "id"))
		p.Window.Members = append(p.Window.Members, member.Member)
		native, err := fleetHealthNativeWindow(ctx, tx, binding, profile, start, end, now)
		if errors.Is(err, pgx.ErrNoRows) || err != nil && err.Error() == "COHORT_FULL_WINDOW_NATIVE_CPU_MEMORY_REQUIRED" {
			if !now.After(end.Add(2 * time.Minute)) {
				if p.Status != "BREACH" {
					p.Status = "BLOCKED"
				}
				p.Reasons = append(p.Reasons, "COHORT_NATIVE_DELIVERY_PENDING")
			} else {
				mark("BLOCKED", "COHORT_FULL_WINDOW_NATIVE_CPU_MEMORY_REQUIRED")
			}
			continue
		}
		if err != nil {
			return p, err
		}
		p.NativeIDs = append(p.NativeIDs, model.String(native, "id"))
		// Keep the ordinary current objective-sized evaluation distinct from the
		// stage snapshot. CaptureBaseline checks hard limits with real current
		// samples; separate cohort comparison proves cross-source regression.
		currentEnd := now.UTC().Truncate(time.Minute)
		currentStart := currentEnd.Add(-time.Duration(objective.EvaluationMinutes) * time.Minute)
		current, err := tx.SLOReceipts(ctx, binding.ResourceID, objective.ID, currentStart, currentEnd)
		if err != nil {
			return p, err
		}
		evaluation := slo.Evaluate(slo.Input{Now: now, Objective: objective, Source: source, Receipts: current, CaptureBaseline: true})
		if evaluation.Status != "CLEAR" {
			currentRows, e := fleetHealthReceipts(ctx, tx, source, currentStart, currentEnd)
			if e != nil {
				return p, e
			}
			currentMember := fleetBuildMemberWindow(binding, objective, source, currentStart, currentEnd, now, currentRows)
			if fleetMemberDeliveryPending(currentMember, currentStart, currentEnd, now, currentRows) {
				if p.Status != "BREACH" {
					p.Status = "BLOCKED"
				}
				p.Reasons = append(p.Reasons, "COHORT_CURRENT_SLO_DELIVERY_PENDING")
			} else {
				status := "BLOCKED"
				if currentMember.Status == "BREACH" {
					status = "BREACH"
				}
				mark(status, "COHORT_FRESH_CURRENT_HARD_SLO_REQUIRED")
			}
			continue
		}
		saved, err := tx.SLOEvaluationCreate(ctx, slo.Document(evaluation))
		if err != nil {
			return p, err
		}
		p.SLOIDs = append(p.SLOIDs, model.String(saved, "id"))
	}
	if len(ids) == 0 {
		mark("BLOCKED", "COHORT_NONEMPTY_PHYSICAL_POPULATION_REQUIRED")
	}
	p.Reasons = uniqueFleetHealthReasons(p.Reasons)
	return p, nil
}

func uniqueFleetHealthReasons(reasons []string) []string {
	m := map[string]bool{}
	for _, reason := range reasons {
		if reason != "" {
			m[reason] = true
		}
	}
	return slo.SortedReasons(m)
}

func fleetLoadFrozenBaseline(ctx context.Context, tx *store.Tx, parent fleet.Plan, now time.Time) (model.Document, fleet.CohortWindow, error) {
	var id string
	for _, ref := range parent.Proofs {
		if ref.Kind != "SLO_EVALUATION" {
			continue
		}
		proof, err := tx.FleetProof(ctx, ref.ID)
		if err != nil {
			return nil, fleet.CohortWindow{}, err
		}
		id = model.String(proof, "cohort_baseline_id")
	}
	if id == "" {
		return nil, fleet.CohortWindow{}, errors.New("COHORT_PRIVATE_FROZEN_BASELINE_REQUIRED")
	}
	d, err := fleetHealthOne(ctx, tx, "SELECT document FROM fleet_cohort_baselines WHERE tenant_id=$1 AND id=$2", tx.Tenant, id)
	if err != nil {
		return nil, fleet.CohortWindow{}, err
	}
	var b fleet.Binding
	var start, end, expires time.Time
	if fleetHealthDecode(d["binding"], &b) != nil || b != parent.Binding || fleetHealthDecode(d["window_start"], &start) != nil || fleetHealthDecode(d["window_end"], &end) != nil || fleetHealthDecode(d["expires_at"], &expires) != nil || !expires.After(now) || end.After(parent.CreatedAt) || end.Before(parent.CreatedAt.Add(-2*time.Minute)) {
		return nil, fleet.CohortWindow{}, errors.New("COHORT_FROZEN_BASELINE_BINDING_OR_TIME_INVALID")
	}
	membership, err := fleetHealthMembership(ctx, tx, model.String(d, "membership_receipt_id"), b, now, 24*time.Hour)
	if err != nil {
		return nil, fleet.CohortWindow{}, err
	}
	if !fleetHealthIDsEqual(model.Strings(d, "member_ids"), model.Strings(membership, "old_instance_ids")) || len(model.Strings(d, "member_ids")) != parent.Old.DesiredCount {
		return nil, fleet.CohortWindow{}, errors.New("COHORT_FROZEN_PHYSICAL_MEMBERS_CHANGED")
	}
	w := fleet.CohortWindow{Binding: b, ASG: parent.Old.ID, Role: "FROZEN_BLUE_BASELINE", ObjectiveID: model.String(d, "objective_id"), ObjectiveVersion: model.Number(d, "objective_version"), ObjectiveSHA256: model.String(d, "objective_hash"), Start: start, End: end, Members: []fleet.CohortMemberWindow{}}
	for _, wid := range model.Strings(d, "member_window_ids") {
		memberDoc, getErr := fleetHealthOne(ctx, tx, "SELECT document FROM fleet_member_slo_windows WHERE tenant_id=$1 AND id=$2", tx.Tenant, wid)
		if getErr != nil {
			return nil, w, getErr
		}
		var member fleetMemberEvaluation
		if fleetHealthDecode(memberDoc, &member) != nil || member.Status != "CLEAR" || member.Hash != fleetMemberEvaluationHash(member) || !member.WindowStart.Equal(start) || !member.WindowEnd.Equal(end) {
			return nil, w, errors.New("COHORT_FROZEN_MEMBER_HASH_INVALID")
		}
		source, getErr := tx.SLOSource(ctx, member.Member.SourceID)
		if getErr != nil {
			return nil, w, getErr
		}
		if !source.Enabled || slo.SourceHash(source) != member.Member.SourceSHA256 {
			return nil, w, errors.New("COHORT_FROZEN_MEMBER_SOURCE_CHANGED")
		}
		w.Members = append(w.Members, member.Member)
	}
	if len(model.Strings(d, "native_evaluation_ids")) != len(w.Members) {
		return nil, w, errors.New("COHORT_FROZEN_NATIVE_EVIDENCE_REQUIRED")
	}
	seenNative := map[string]bool{}
	for _, id := range model.Strings(d, "native_evaluation_ids") {
		native, getErr := fleetHealthOne(ctx, tx, "SELECT document FROM telemetry_evaluations WHERE tenant_id=$1 AND id=$2", tx.Tenant, id)
		if getErr != nil {
			return nil, w, getErr
		}
		active, getErr := fleetHealthNativeAuthority(ctx, tx, native)
		instanceID := model.String(evidence.Object(native["binding"]), "provider_resource_id")
		if getErr != nil {
			return nil, w, getErr
		}
		if !active || seenNative[instanceID] || !slices.Contains(model.Strings(d, "member_ids"), instanceID) {
			return nil, w, errors.New("COHORT_FROZEN_NATIVE_SOURCE_CHANGED")
		}
		seenNative[instanceID] = true
	}
	return d, w, nil
}

func fleetMembershipTimeline(ctx context.Context, tx *store.Tx, selected model.Document, childID string, oldIDs, greenIDs []string, start, end, now time.Time) ([]string, error) {
	rows, err := tx.Query(ctx, "SELECT id,document FROM source_receipts WHERE tenant_id=$1 AND kind='AWS_FLEET_MEMBERSHIP' AND source_id=$2 AND document->>'child_id'=$3 AND document->>'position'='AFTER' AND (document->>'collected_at')::timestamptz >= $4 AND (document->>'collected_at')::timestamptz <= $5 ORDER BY (document->>'collected_at')::timestamptz,id", tx.Tenant, selected["source_id"], childID, start, now.Add(5*time.Second))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	observations := map[int64]bool{}
	ids := []string{}
	for rows.Next() {
		var id string
		var raw []byte
		if err = rows.Scan(&id, &raw); err != nil {
			return nil, err
		}
		var d model.Document
		if err = json.Unmarshal(raw, &d); err != nil {
			return nil, err
		}
		var at time.Time
		if fleetHealthDecode(d["collected_at"], &at) != nil || !fleetHealthIDsEqual(model.Strings(d, "old_instance_ids"), oldIDs) || !fleetHealthIDsEqual(model.Strings(d, "candidate_instance_ids"), greenIDs) || model.String(d, "config_hash") != model.String(selected, "config_hash") || model.String(d, "child_sha256") != model.String(selected, "child_sha256") || fleet.Digest(d["binding"]) != fleet.Digest(selected["binding"]) {
			return nil, errors.New("COHORT_NATIVE_MEMBERSHIP_CHANGED_DURING_WINDOW")
		}
		observations[at.UTC().Truncate(time.Minute).Unix()] = true
		ids = append(ids, id)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	rows.Close()
	var binding fleet.Binding
	if fleetHealthDecode(selected["binding"], &binding) != nil {
		return nil, errors.New("COHORT_NATIVE_MEMBERSHIP_BINDING_INVALID")
	}
	for _, id := range ids {
		if _, err = fleetHealthMembership(ctx, tx, id, binding, now, 24*time.Hour); err != nil {
			return nil, err
		}
	}
	pending := false
	for minute := start; minute.Before(end); minute = minute.Add(time.Minute) {
		if !observations[minute.Unix()] {
			if now.After(minute.Add(3 * time.Minute)) {
				return ids, errors.New("COHORT_CONTINUOUS_NATIVE_MEMBERSHIP_REQUIRED")
			}
			pending = true
		}
	}
	if pending {
		return ids, errors.New("COHORT_NATIVE_MEMBERSHIP_DELIVERY_PENDING")
	}
	return ids, nil
}

// buildFleetCohortHealth accepts an immutable command ID only. It is intentionally
// unregistered: no Fleet runtime or console can create authority through this
// component until the complete R2 integration is accepted.
func (a *API) evaluateFleetCohortHealth(ctx context.Context, tx *store.Tx, commandID string) (model.Document, error) {
	command, err := tx.FleetCommand(ctx, commandID)
	if err != nil {
		return nil, err
	}
	if err = fleetHealthLock(ctx, tx, model.String(command, "workload_id")); err != nil {
		return nil, err
	}
	parent, err := tx.FleetSigned(ctx, model.String(command, "parent_id"))
	if err != nil {
		return nil, err
	}
	child, err := tx.FleetChild(ctx, model.String(command, "child_id"))
	if err != nil {
		return nil, err
	}
	if parent.Plan.Binding.TenantID != tx.Tenant || child.Plan.Binding != parent.Plan.Binding || child.Plan.ParentSHA256 != fleet.Digest(parent.Plan) || model.String(command, "child_sha256") != fleet.Digest(child.Plan) {
		return nil, errors.New("COHORT_APPLIED_OWNED_COMMAND_REQUIRED")
	}
	now, mode := a.now(), "FORWARD"
	if model.String(command, "operation") == "ROLLBACK" {
		mode = "OWNED_RECOVERY"
	}
	if mode == "FORWARD" {
		var failed bool
		if err = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM fleet_cohort_failures WHERE tenant_id=$1 AND execution_id=$2)", tx.Tenant, command["execution_id"]).Scan(&failed); err != nil {
			return nil, err
		}
		if failed {
			return model.Document{"status": "BLOCKED", "reason_codes": []string{"COHORT_PERMANENT_FAILURE_DISQUALIFIES_FORWARD_AND_SAVINGS"}, "positive_savings_eligible": false, "execution_authorized": false}, nil
		}
		if err = fleetForwardObservationAuthority(ctx, tx, parent.Plan.ID); err != nil {
			return nil, err
		}
	}
	if !model.Bool(command, "dispatch_intent") || model.String(command, "outcome") != "APPLIED" || model.String(command, "owned_receipt_id") == "" || model.Bool(command, "restored") {
		return nil, errors.New("COHORT_APPLIED_OWNED_COMMAND_REQUIRED")
	}
	owned, err := fleetHealthOne(ctx, tx, "SELECT document FROM fleet_callbacks WHERE tenant_id=$1 AND id=$2 AND command_id=$3", tx.Tenant, command["owned_receipt_id"], commandID)
	if err != nil {
		return nil, err
	}
	var appliedAt time.Time
	if fleetHealthDecode(owned["received_at"], &appliedAt) != nil {
		return nil, errors.New("COHORT_SERVER_APPLIED_ANCHOR_REQUIRED")
	}
	objectiveDoc, err := tx.SLOObjectiveLatest(ctx, parent.Plan.Binding.WorkloadID)
	if err != nil {
		return nil, err
	}
	objective, err := slo.ParseObjective(objectiveDoc)
	if err != nil {
		return nil, err
	}
	var stage fleet.Stage
	for _, candidate := range parent.Plan.Stages {
		if candidate.ID == child.Plan.StageID {
			stage = candidate
		}
	}
	stage = fleetChildObservationStage(stage, child.Plan)
	preparation := mode == "FORWARD" && stage.Kind == fleet.Prepare && child.Plan.Transition.CandidateAfter == 0 && child.Plan.Transition.TrafficAfter == 0
	terminalDrain := mode == "FORWARD" && stage.Kind == fleet.DrainOld && child.Plan.Transition.OldAfter == 0
	if mode == "OWNED_RECOVERY" {
		// Owned inverse application is authorized separately by SignRecovery and
		// SQL013. Health does not call ValidatePlan, the failed original window,
		// current parent expiry, pause or revoked historical telemetry revisions.
		stage.MinimumObservationSeconds = int64(objective.EvaluationMinutes) * 60
		original, e := tx.FleetChild(ctx, child.Plan.CompensationFor)
		if e != nil {
			return nil, e
		}
		originalOwned, e := tx.FleetOwnedReceiptForChild(ctx, original.Plan.ID)
		if e != nil {
			return nil, e
		}
		if child.Plan.CompensationReceiptSHA256 != fleet.Digest(originalOwned) || child.Plan.ParentID != original.Plan.ParentID || child.Plan.Transition.OldAfter != original.Plan.Transition.OldBefore || child.Plan.Transition.CandidateAfter != original.Plan.Transition.CandidateBefore || child.Plan.Transition.TrafficAfter != original.Plan.Transition.TrafficBefore {
			return nil, errors.New("COHORT_RECOVERY_MUST_MATCH_OWNED_INVERSE")
		}
	}
	start, end, observationErr := fleetStageWindow(appliedAt, now, stage)
	if mode == "OWNED_RECOVERY" {
		start, end, observationErr = fleetRecoveryWindow(appliedAt, now, objective.EvaluationMinutes)
	}
	var baselineDoc model.Document
	var baseline fleet.CohortWindow
	if mode == "FORWARD" {
		if !objective.Regression.Enabled {
			return nil, errors.New("COHORT_EXPLICIT_REGRESSION_OBJECTIVE_REQUIRED")
		}
		baselineDoc, baseline, err = fleetLoadFrozenBaseline(ctx, tx, parent.Plan, now)
		if err != nil {
			return nil, err
		}
		if baseline.ObjectiveID != objective.ID || baseline.ObjectiveVersion != objective.Version || baseline.ObjectiveSHA256 != slo.ObjectiveHash(objective) {
			return nil, errors.New("COHORT_OBJECTIVE_CHANGED_SINCE_FROZEN_BASELINE")
		}
	}
	profileDoc, err := tx.WorkloadSafetyLatest(ctx, parent.Plan.Binding.WorkloadID)
	if err != nil {
		return nil, err
	}
	var profile workload.Profile
	if fleetHealthDecode(profileDoc, &profile) != nil || workload.Validate(profile) != nil || mode == "FORWARD" && profile.Statefulness != "STATELESS" {
		return nil, errors.New("COHORT_STATELESS_SAFETY_PROFILE_REQUIRED")
	}
	if mode == "FORWARD" && (model.String(baselineDoc, "safety_profile_id") != profile.ID || model.String(baselineDoc, "safety_profile_hash") != model.String(profileDoc, "hash")) {
		return nil, errors.New("COHORT_SAFETY_PROFILE_CHANGED_SINCE_BASELINE")
	}
	if end.Sub(start) < 2*time.Minute {
		return model.Document{"status": "PENDING", "reason_codes": []string{"COHORT_SIGNED_OBSERVATION_PENDING"}, "execution_authorized": false}, nil
	}
	membershipDoc, err := fleetHealthOne(ctx, tx, "SELECT document||jsonb_build_object('writer_role',writer_role,'created_at',created_at) FROM source_receipts WHERE tenant_id=$1 AND kind='AWS_FLEET_MEMBERSHIP' AND document->>'position'='AFTER' AND document->>'child_id'=$2 AND document->>'child_sha256'=$3 ORDER BY (document->>'collected_at')::timestamptz DESC,id DESC LIMIT 1", tx.Tenant, child.Plan.ID, fleet.Digest(child.Plan))
	if err != nil {
		return nil, err
	}
	membership, err := fleetHealthMembership(ctx, tx, model.String(membershipDoc, "id"), parent.Plan.Binding, now, 5*time.Minute)
	if err != nil {
		return nil, err
	}
	oldIDs, greenIDs := model.Strings(owned, "old_instance_ids"), model.Strings(owned, "candidate_instance_ids")
	if !fleetHealthIDsEqual(oldIDs, model.Strings(membership, "old_instance_ids")) || !fleetHealthIDsEqual(greenIDs, model.Strings(membership, "candidate_instance_ids")) || len(oldIDs) != child.Plan.Transition.OldAfter || len(greenIDs) != child.Plan.Transition.CandidateAfter {
		return nil, errors.New("COHORT_POST_APPLY_NATIVE_MEMBERSHIP_DIFFERS")
	}
	timeline, timelineErr := fleetMembershipTimeline(ctx, tx, membership, child.Plan.ID, oldIDs, greenIDs, start, end, now)
	blue := fleetHealthPopulation{Status: "CLEAR", MemberWindowIDs: []string{}, NativeIDs: []string{}, SLOIDs: []string{}, Receipts: map[string][]fleetSLOReceipt{}}
	if len(oldIDs) > 0 {
		blue, err = fleetCollectHealthPopulation(ctx, tx, parent.Plan.Binding, parent.Plan.Old.ID, "CURRENT_BLUE_CONTROL", oldIDs, objective, profile, start, end, now)
		if err != nil {
			return nil, err
		}
	} else if !terminalDrain {
		blue.Status, blue.Reasons, blue.DefiniteFailure = "BLOCKED", []string{"COHORT_NONEMPTY_BLUE_REQUIRED"}, true
	}
	green := fleetHealthPopulation{Status: "CLEAR", Window: fleet.CohortWindow{}, MemberWindowIDs: []string{}, NativeIDs: []string{}, SLOIDs: []string{}, Receipts: map[string][]fleetSLOReceipt{}}
	if len(greenIDs) > 0 {
		green, err = fleetCollectHealthPopulation(ctx, tx, parent.Plan.Binding, parent.Plan.Candidate.ID, "CURRENT_GREEN", greenIDs, objective, profile, start, end, now)
		if err != nil {
			return nil, err
		}
	} else if mode == "FORWARD" && !preparation {
		green.Status, green.Reasons, green.DefiniteFailure = "BLOCKED", []string{"COHORT_NONEMPTY_GREEN_REQUIRED"}, true
	}
	status, reasons := "CLEAR", append(append([]string{}, blue.Reasons...), green.Reasons...)
	if blue.Status != "CLEAR" || green.Status != "CLEAR" {
		status = "BLOCKED"
	}
	if blue.Status == "BREACH" || green.Status == "BREACH" {
		status = "BREACH"
	}
	if timelineErr != nil {
		if status != "BREACH" {
			status = "BLOCKED"
		}
		reasons = append(reasons, timelineErr.Error())
	}
	var comparison any
	comparisonFailure := false
	if mode == "FORWARD" && status == "CLEAR" && (preparation || terminalDrain) {
		prior := model.Document{}
		if terminalDrain {
			prior, err = fleetPriorDrainControl(ctx, tx, command, child.Plan, objective, profileDoc, greenIDs, now)
			if err != nil {
				return nil, err
			}
			for _, member := range green.Window.Members {
				if slices.Contains(model.Strings(baselineDoc, "member_ids"), member.InstanceID) {
					return nil, errors.New("COHORT_GREEN_REUSES_FROZEN_BLUE_PHYSICAL_INSTANCE")
				}
			}
		}
		continuous := fleetCheckRegression(baseline, blue, green, objective.Regression.MaxPercent, true)
		label := "PREPARATION_BLUE_ONLY"
		if terminalDrain {
			label = "REVIEWED_TERMINAL_DRAIN_GREEN_ONLY"
		}
		comparison, status, reasons = model.Document{"mode": label, "continuous_and_full_regression": continuous, "prior_control_window_id": prior["id"], "prior_control_window_hash": prior["hash"]}, continuous.Status, append(reasons, continuous.ReasonCodes...)
		comparisonFailure = status != "CLEAR"
	} else if mode == "FORWARD" && status == "CLEAR" {
		result := fleet.CompareCohorts(fleet.CohortInput{Now: now, Parent: parent.Plan, Limits: fleetHealthLimits(objective), FrozenBlueMemberIDs: model.Strings(baselineDoc, "member_ids"), CurrentBlueMemberIDs: oldIDs, CurrentGreenMemberIDs: greenIDs, Baseline: baseline, BlueControl: blue.Window, Green: green.Window})
		continuous := fleetCheckContinuousRegression(baseline, blue, green, objective.Regression.MaxPercent)
		comparison, status, reasons = model.Document{"full_window": result, "continuous_minutes": continuous}, result.Status, append(reasons, result.ReasonCodes...)
		if continuous.Status != "CLEAR" {
			if continuous.Status == "BREACH" || status != "BREACH" {
				status = continuous.Status
			}
			reasons = append(reasons, continuous.ReasonCodes...)
		}
		comparisonFailure = status != "CLEAR"
	} else {
		comparison = model.Document{"mode": mode, "blue": blue.Window, "green": green.Window, "hard_limits_only": mode == "OWNED_RECOVERY"}
	}
	if observationErr != nil {
		if status == "CLEAR" {
			status = "BLOCKED"
		}
		reasons = append(reasons, observationErr.Error())
	}
	definiteFailure := blue.DefiniteFailure || green.DefiniteFailure || timelineErr != nil && timelineErr.Error() != "COHORT_NATIVE_MEMBERSHIP_DELIVERY_PENDING" || comparisonFailure || status == "BREACH"
	if observationErr != nil && observationErr.Error() != "COHORT_SIGNED_OBSERVATION_PENDING" {
		definiteFailure = true
	}
	return a.persistFleetCohortHealth(ctx, tx, command, child.Plan, mode, status, uniqueFleetHealthReasons(reasons), baselineDoc, membership, timeline, blue, green, start, end, comparison, definiteFailure)
}

func (a *API) persistFleetCohortHealth(ctx context.Context, tx *store.Tx, command model.Document, child fleet.ChildPlan, mode, status string, reasons []string, baseline, membership model.Document, timeline []string, blue, green fleetHealthPopulation, start, end time.Time, comparison any, definiteFailure bool) (model.Document, error) {
	commandID := model.String(command, "id")
	members := append(append([]string{}, blue.MemberWindowIDs...), green.MemberWindowIDs...)
	native := append(append([]string{}, blue.NativeIDs...), green.NativeIDs...)
	slis := append(append([]string{}, blue.SLOIDs...), green.SLOIDs...)
	sort.Strings(members)
	sort.Strings(native)
	sort.Strings(slis)
	d := model.Document{"schema_version": "1", "mode": mode, "status": status, "reason_codes": reasons, "command_id": commandID, "binding": evidence.Object(child.Binding), "child_sha256": fleet.Digest(child), "membership_receipt_id": membership["id"], "membership_timeline_ids": timeline, "member_window_ids": members, "native_evaluation_ids": native, "slo_evaluation_ids": slis, "window_start": start, "window_end": end, "comparison": comparison, "comparison_sha256": fleet.Digest(comparison), "execution_authorized": false}
	if status == "CLEAR" {
		profile, err := tx.WorkloadSafetyLatest(ctx, child.Binding.WorkloadID)
		if err != nil {
			return nil, err
		}
		d["safety_profile_id"], d["safety_profile_hash"] = profile["id"], profile["hash"]
		objective, err := tx.SLOObjectiveLatest(ctx, child.Binding.WorkloadID)
		if err != nil {
			return nil, err
		}
		d["objective_id"], d["objective_version"], d["objective_hash"] = objective["id"], objective["version"], objective["hash"]
	}
	var baselineID any
	if mode == "FORWARD" {
		baselineID = baseline["id"]
		d["baseline_id"], d["baseline_evaluation_ids"] = baselineID, model.Strings(baseline, "member_window_ids")
	}
	hash := fleet.Digest(d)
	stored, err := fleetHealthOne(ctx, tx, "SELECT document FROM fleet_cohort_windows WHERE tenant_id=$1 AND command_id=$2 AND content_hash=$3", tx.Tenant, commandID, hash)
	if errors.Is(err, pgx.ErrNoRows) {
		raw, marshalErr := json.Marshal(d)
		if marshalErr != nil {
			return nil, marshalErr
		}
		stored, err = fleetHealthOne(ctx, tx, "INSERT INTO fleet_cohort_windows(tenant_id,id,command_id,baseline_id,mode,status,content_hash,document) VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING document", tx.Tenant, "fleet-window-"+hash, commandID, baselineID, mode, status, hash, raw)
	}
	if err != nil {
		return nil, err
	}
	// Pending signed duration is not a safety failure. A real earlier breach is
	// latched even while the remainder of the signed canary is still measuring.
	unsafe := status == "BREACH" || status == "BLOCKED" && definiteFailure
	if unsafe {
		if _, err = tx.Exec(ctx, "INSERT INTO fleet_cohort_failures(tenant_id,id,execution_id,command_id,window_id,document) VALUES($1,$2,$3,$4,$5,'{}') ON CONFLICT(tenant_id,execution_id) DO NOTHING", tx.Tenant, model.ID(), command["execution_id"], commandID, stored["id"]); err != nil {
			return nil, err
		}
	}
	if status != "CLEAR" {
		return stored, nil
	}
	if mode == "FORWARD" {
		var failed bool
		if err = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM fleet_cohort_failures WHERE tenant_id=$1 AND execution_id=$2)", tx.Tenant, command["execution_id"]).Scan(&failed); err != nil {
			return nil, err
		}
		if failed {
			return nil, errors.New("COHORT_PERMANENT_FAILURE_DISQUALIFIES_FORWARD_AND_SAVINGS")
		}
	}
	proof := model.Document{"id": "cohort-proof-" + hash, "kind": "COHORT_HEALTH", "version": "1", "binding": evidence.Object(child.Binding), "status": "CLEAR", "mode": mode, "command_id": commandID, "child_sha256": fleet.Digest(child), "cohort_window_id": stored["id"], "membership_receipt_id": membership["id"], "native_evaluation_ids": native, "slo_evaluation_ids": slis, "comparison_sha256": fleet.Digest(comparison), "expires_at": a.now().Add(time.Minute), "source_refs": []model.Document{{"table": "fleet_cohort_windows", "id": stored["id"], "sha256": hash}}}
	proof["safety_profile_id"], proof["safety_profile_hash"] = d["safety_profile_id"], d["safety_profile_hash"]
	if mode == "FORWARD" {
		proof["baseline_evaluation_ids"] = model.Strings(baseline, "member_window_ids")
	}
	proofRaw, err := json.Marshal(proof)
	if err != nil {
		return nil, err
	}
	if _, err = tx.Exec(ctx, "INSERT INTO fleet_proof_sets(tenant_id,id,kind,version,content_hash,document) VALUES($1,$2,'COHORT_HEALTH','1',$3,$4) ON CONFLICT(tenant_id,id) DO NOTHING", tx.Tenant, proof["id"], fleet.Digest(proof), proofRaw); err != nil {
		return nil, err
	}
	health := model.Document{"status": "HEALTHY", "mode": mode, "cohort_window_id": stored["id"], "cohort_proof_id": proof["id"], "cohort_slo_status": "CLEAR", "membership_receipt_id": membership["id"], "native_evaluation_ids": native, "slo_evaluation_ids": slis}
	out, _, err := tx.FleetHealthEvidenceAppend(ctx, commandID, health)
	return out, err
}
