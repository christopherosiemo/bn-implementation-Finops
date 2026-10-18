package service

import (
	"context"
	"encoding/json"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
)

// Caller holds scheduling-control exclusively. Absence of any provider receipt
// then proves no STOP intent can have been committed for this execution. An
// existing unowned intent is deliberately ambiguous: it may represent an AWS
// request whose response was lost, and must use start-now instead of a skip.
func bindCurrentScheduleSkip(ctx context.Context, t *store.Tx, actor string, schedule model.Document, now time.Time) (bool, error) {
	rows, err := t.Query(ctx, `SELECT e.document,p.document,
 po.execution_id IS NOT NULL,coalesce(po.stop_intent,false),coalesce(po.stop_owned,false),coalesce(po.restored,false)
 FROM entities e JOIN entities p ON p.tenant_id=e.tenant_id AND p.kind='change_plans' AND p.id=e.document->>'change_plan_id'
 LEFT JOIN provider_operations po ON po.tenant_id=e.tenant_id AND po.execution_id=e.id
 WHERE e.tenant_id=$1 AND e.kind='executions' AND p.document->'payload'->>'schedule_id'=$2
 AND ((e.document->>'status'='QUEUED' AND e.document->>'stage'='PRECHECK')
 OR (e.document->>'status'='EXECUTING' AND e.document->>'stage'='STOPPING'))
 AND coalesce(e.document->>'start_now','false')<>'true'
 ORDER BY e.id LIMIT 129`, t.Tenant, model.String(schedule, "id"))
	if err != nil {
		return false, err
	}
	type candidate struct {
		executionID string
		stopAt      time.Time
	}
	candidates := []candidate{}
	count := 0
	for rows.Next() {
		count++
		var executionBody, planBody []byte
		var exists, intent, owned, restored bool
		if err = rows.Scan(&executionBody, &planBody, &exists, &intent, &owned, &restored); err != nil {
			rows.Close()
			return false, err
		}
		var execution, plan model.Document
		if err = json.Unmarshal(executionBody, &execution); err == nil {
			err = json.Unmarshal(planBody, &plan)
		}
		if err != nil {
			rows.Close()
			return false, err
		}
		p, err := decodePlan(plan)
		if err != nil {
			rows.Close()
			return false, err
		}
		if p.TenantID != t.Tenant || p.ID != model.String(execution, "change_plan_id") || p.ScheduleID != model.String(schedule, "id") || p.WorkloadID != model.String(schedule, "workload_id") || p.WorkloadID != model.String(execution, "workload_id") || len(p.Operations) != 2 || p.Operations[0].ResourceID != model.String(execution, "resource_id") || model.String(plan, "status") != "APPROVED" || p.StopAt.IsZero() || now.Before(p.StopAt) || !now.Before(p.StopAt.Add(15*time.Minute)) || !now.Before(p.ExpiresAt) {
			continue
		}
		if exists && intent && !owned && !restored {
			rows.Close()
			return false, problem(409, "SKIP_STOP_INTENT_UNCERTAIN", "a current stop intent may already have dispatched; use start_now to request its restoration")
		}
		if !exists {
			candidates = append(candidates, candidate{model.String(execution, "id"), p.StopAt.UTC()})
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return false, err
	}
	// Refuse to assign an unbounded or ambiguous set to one occurrence. Keeping
	// the future flag is unsafe when uninspected current intents might exist.
	if count > 128 {
		return false, problem(409, "SKIP_OCCURRENCE_SELECTION_LIMIT", "too many pending occurrences to safely assign a one-shot skip")
	}
	if len(candidates) == 0 {
		return false, nil
	}
	location, err := time.LoadLocation(model.String(schedule, "timezone"))
	if err != nil {
		return false, err
	}
	stopAt := candidates[0].stopAt
	date := stopAt.In(location).Format("2006-01-02")
	ids := []string{}
	for _, candidate := range candidates {
		if !candidate.stopAt.Equal(stopAt) {
			return false, problem(409, "SKIP_OCCURRENCE_AMBIGUOUS", "multiple current stop occurrences require an explicit start_now request")
		}
		ids = append(ids, candidate.executionID)
	}
	skipped, err := ScheduleStopSkipped(ctx, t, model.String(schedule, "id"), stopAt)
	if err != nil || skipped {
		return skipped, err
	}
	details := model.Document{"schedule_id": schedule["id"], "stop_at": stopAt.Format(time.RFC3339Nano), "local_date": date, "timezone": schedule["timezone"], "execution_ids": ids, "assignment": "CURRENT_UNISSUED_OCCURRENCE"}
	org, err := t.Get(ctx, "org", t.Tenant)
	if err != nil {
		return false, err
	}
	if model.Bool(org, "fixture") {
		generation := model.String(org, "fixture_generation")
		if generation == "" {
			generation = "initial"
		}
		details["fixture_generation"] = generation
	}
	err = t.Audit(ctx, actor, "schedule.stop_skipped", model.String(schedule, "id"), details)
	return err == nil, err
}
