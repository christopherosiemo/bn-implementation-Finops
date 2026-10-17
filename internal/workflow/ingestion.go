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
	if a.Config.Fixture && len(jobs) == 0 {
		records := []model.Document{}
		for day := 0; day < 14; day++ {
			start := time.Date(2026, 9, 1+day, 20, 0, 0, 0, time.UTC)
			records = append(records, model.Document{"identity_line_item_id": "fixture-billing-" + start.Format("20060102"), "line_item_line_item_type": "Usage", "line_item_unblended_cost": "4.800000000000", "line_item_currency_code": "GBP", "line_item_resource_id": "i-0123456789abcdef0", "line_item_usage_account_id": "111122223333", "product_servicecode": "AmazonEC2", "product_region_code": "eu-west-1", "line_item_usage_start_date": start.Format(time.RFC3339), "line_item_usage_end_date": start.Add(10 * time.Hour).Format(time.RFC3339), "resource_tags": model.Document{"finops:environment": "NON_PRODUCTION"}})
		}
		raw := model.Document{"source_id": "fixture-cur2", "source_version": "fixture-cur-v1", "invoice_totals": model.Document{"GBP": "67.200000000000"}, "records": records}
		var canonical model.Document
		if e = a.call(ctx, a.Config.EconomicsURL, a.Config.EconomicsToken, "/normalize", raw, &canonical); e != nil {
			return e
		}
		metrics := []model.Document{}
		for hour := 0; hour < 14*24; hour++ {
			at := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC).Add(time.Duration(hour) * time.Hour)
			for _, name := range []string{"cpu_utilization", "network_in", "network_out"} {
				value := "0.000000000000"
				if name == "cpu_utilization" {
					value = "2.500000000000"
				}
				metrics = append(metrics, model.Document{"resource_id": "i-0123456789abcdef0", "metric_name": name, "source_time": at.Format(time.RFC3339), "value": value, "fixture": true})
			}
		}
		raw["metric_records"] = metrics
		canonical["metric_facts"] = metrics
		j, e := t.Create(ctx, "ingestion_jobs", model.Document{"id": "fixture-billing-ingestion", "status": "PENDING", "source_id": "fixture-cur2", "raw": raw, "canonical": canonical})
		if e != nil {
			return e
		}
		jobs = append(jobs, j)
	}
	for _, j := range jobs {
		if model.String(j, "status") == "PERSISTED" {
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
	now := time.Now()
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
		s["last_occurrence_date"] = date
		if model.Bool(s, "skip_next_stop") {
			s["skip_next_stop"] = false
			if _, e = t.Update(ctx, "schedules", model.String(s, "id"), model.Number(s, "version"), s); e != nil {
				return e
			}
			if e = t.Audit(ctx, "scheduler", "schedule.stop_skipped", model.String(s, "id"), nil); e != nil {
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
