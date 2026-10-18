package workflow

import (
	"context"
	"encoding/json"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/service"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
)

func ingestTenant(ctx context.Context, a *Activities, t *store.Tx) error {
	jobs, e := t.List(ctx, "ingestion_jobs")
	if e != nil {
		return e
	}
	producer := &service.API{Config: a.Config, Client: a.HTTP}
	if a.Config.Fixture {
		if e = producer.PrepareFixtureEvidence(ctx, t); e != nil {
			return e
		}
		jobs, e = t.List(ctx, "ingestion_jobs")
		if e != nil {
			return e
		}
	}
	for _, j := range jobs {
		if model.String(j, "status") == "PERSISTED" {
			if e = producer.SealFixtureEvidence(ctx, t, j); e != nil {
				return e
			}
			continue
		}
		var raw, canonical model.Document
		b, _ := json.Marshal(j["raw"])
		_ = json.Unmarshal(b, &raw)
		b, _ = json.Marshal(j["canonical"])
		_ = json.Unmarshal(b, &canonical)
		if e = service.PersistEvidence(ctx, t.Tenant, model.String(j, "source_id"), raw, canonical); e != nil {
			return e
		}
		j["status"], j["persisted_at"] = "PERSISTED", model.Now()
		if _, e = t.Update(ctx, "ingestion_jobs", model.String(j, "id"), model.Number(j, "version"), j); e != nil {
			return e
		}
		if e = producer.SealFixtureEvidence(ctx, t, j); e != nil {
			return e
		}
		if e = t.Audit(ctx, "ingestion-worker", "billing.ingested", model.String(j, "id"), model.Document{"source_id": j["source_id"], "storage": "immutable raw + FOCUS ClickHouse facts"}); e != nil {
			return e
		}
	}
	rows, e := t.Query(ctx, "SELECT a.document FROM audit_events a LEFT JOIN entities e ON e.tenant_id=a.tenant_id AND e.kind='audit_archives' AND e.id=a.id WHERE a.tenant_id=$1 AND e.id IS NULL ORDER BY a.created_at LIMIT 200", t.Tenant)
	if e != nil {
		return e
	}
	events := []model.Document{}
	for rows.Next() {
		var b []byte
		if e = rows.Scan(&b); e != nil {
			rows.Close()
			return e
		}
		var d model.Document
		if e = json.Unmarshal(b, &d); e != nil {
			rows.Close()
			return e
		}
		events = append(events, d)
	}
	rows.Close()
	if e = service.ArchiveAudit(ctx, t.Tenant, events); e != nil {
		return e
	}
	for _, d := range events {
		if _, e = t.Create(ctx, "audit_archives", model.Document{"id": d["id"], "archived_at": model.Now()}); e != nil {
			return e
		}
	}
	return nil
}

func scheduleDue(ctx context.Context, a *Activities, t *store.Tx) error {
	return scheduleDueAt(ctx, a, t, time.Time{})
}

// The clock is server-selected. Tests can exercise a later calendar occurrence
// without sleeping a day; no request or configuration can select this instant.
func scheduleDueAt(ctx context.Context, a *Activities, t *store.Tx, now time.Time) error {
	// Use the same guard as pause/skip/policy controls before reading their
	// versions or acquiring BuildPlan's dependency-graph guard. The caller
	// commits this scheduling transaction before any notification network I/O.
	if _, e := t.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", t.Tenant+":scheduling-control"); e != nil {
		return e
	}
	if now.IsZero() {
		// Sample the production clock after waiting for controls/dispatches;
		// a previously captured minute may no longer be the due occurrence.
		now = time.Now()
	}
	schedules, e := t.List(ctx, "schedules")
	if e != nil {
		return e
	}
	org, e := t.Get(ctx, "org", t.Tenant)
	if e != nil {
		return e
	}
	if model.Bool(org, "paused") {
		return nil
	}
	for _, s := range schedules {
		if model.Bool(s, "paused") {
			continue
		}
		loc, e := time.LoadLocation(model.String(s, "timezone"))
		if e != nil {
			continue
		}
		local := now.In(loc)
		date := local.Format("2006-01-02")
		if model.String(s, "last_occurrence_date") == date {
			continue
		}
		if local.Format("15:04") != model.String(s, "stop_time") {
			continue
		}
		weekday := int(local.Weekday())
		if weekday == 0 {
			weekday = 7
		}
		allowed := false
		if days, ok := s["days"].([]any); ok {
			for _, v := range days {
				if f, ok := v.(float64); ok && int(f) == weekday {
					allowed = true
				}
			}
		}
		if !allowed {
			continue
		}
		// Match NextWindow's IANA/date construction, including its single
		// resolution of a repeated local minute at a DST transition.
		stop := time.Date(local.Year(), local.Month(), local.Day(), local.Hour(), local.Minute(), 0, 0, loc).UTC()
		s["last_occurrence_date"] = date
		skipped, e := service.ScheduleStopSkipped(ctx, t, model.String(s, "id"), stop)
		if e != nil {
			return e
		}
		if skipped {
			// An operator can bind the cancellation to a queued occurrence
			// before this scheduler tick. Preserve that decision without a
			// second proposal or a duplicate immutable skip receipt.
			if _, e = t.Update(ctx, "schedules", model.String(s, "id"), model.Number(s, "version"), s); e != nil {
				return e
			}
			continue
		}
		if model.Bool(s, "skip_next_stop") {
			// Preserve this exact calendar occurrence after consuming the flag.
			s["skip_next_stop"] = false
			if _, e = t.Update(ctx, "schedules", model.String(s, "id"), model.Number(s, "version"), s); e != nil {
				return e
			}
			details := model.Document{"schedule_id": s["id"], "stop_at": stop.Format(time.RFC3339Nano), "local_date": date, "timezone": s["timezone"]}
			if model.Bool(org, "fixture") {
				generation := model.String(org, "fixture_generation")
				if generation == "" {
					generation = "initial"
				}
				details["fixture_generation"] = generation
			}
			if e = t.Audit(ctx, "scheduler", "schedule.stop_skipped", model.String(s, "id"), details); e != nil {
				return e
			}
			continue
		}
		recs, e := t.List(ctx, "recommendations")
		if e != nil {
			return e
		}
		for _, r := range recs {
			if model.String(r, "workload_id") != model.String(s, "workload_id") || model.String(r, "status") != "VALIDATED" {
				continue
			}
			plan, e := service.BuildPlan(ctx, t, model.String(r, "id"), model.String(s, "id"), a.Config.Fixture)
			if e != nil {
				_ = t.Audit(ctx, "scheduler", "schedule.blocked", model.String(s, "id"), model.Document{"reason": e.Error()})
				break
			}
			if model.String(s, "mode") == "AUTOPILOT" && model.Bool(s, "autopilot_opt_in") && model.String(s, "approved_by") != "" {
				payload := model.Clone(plan)
				plan["status"] = "APPROVED"
				plan, e = t.Update(ctx, "change_plans", model.String(plan, "id"), model.Number(plan, "version"), plan)
				if e != nil {
					return e
				}
				if _, e = t.Create(ctx, "approvals", model.Document{"change_plan_id": plan["id"], "approved_by": "policy:" + model.String(s, "approved_by"), "approved_at": model.Now(), "payload": payload}); e != nil {
					return e
				}
				if _, e = t.Create(ctx, "executions", model.Document{"change_plan_id": plan["id"], "resource_id": plan["resource_id"], "workload_id": plan["workload_id"], "schedule_id": plan["schedule_id"], "status": "QUEUED", "stage": "PRECHECK", "created_at": model.Now(), "restoration_owned": false}); e != nil {
					return e
				}
			} else {
				if e = t.Event(ctx, "approval.required", plan); e != nil {
					return e
				}
			}
			break
		}
		if _, e = t.Update(ctx, "schedules", model.String(s, "id"), model.Number(s, "version"), s); e != nil {
			return e
		}
	}
	return nil
}
