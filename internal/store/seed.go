package store

import (
	"context"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/jackc/pgx/v5"
)

func (t *Tx) Seed(ctx context.Context, fixture bool) error {
	if _, e := t.Exec(ctx, "INSERT INTO tenant_registry(tenant_id) VALUES($1) ON CONFLICT DO NOTHING", t.Tenant); e != nil {
		return e
	}
	// Serialize concurrent first requests without using a privileged cross-tenant query.
	if _, e := t.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", t.Tenant+":seed"); e != nil {
		return e
	}
	_, e := t.Get(ctx, "org", t.Tenant)
	if e == nil {
		return nil
	}
	if e != pgx.ErrNoRows {
		return e
	}
	org := model.Document{"id": t.Tenant, "name": "Cloud Cost Autopilot pilot", "paused": false, "residency": "EU", "fixture": fixture}
	if _, e = t.Create(ctx, "org", org); e != nil {
		return e
	}
	policy := model.Document{"id": "policy-default", "name": "Non-production scheduling guardrails", "mode": "ASSISTED_EXECUTION", "workload_autopilot_ids": []string{}, "paused": false, "risk_class": "R1", "min_observation_days": 14, "max_signal_age_seconds": 300, "delete_resources": false, "production_changes": false, "max_off_hours": 23, "start_lead_minutes": 15}
	if !fixture {
		policy["mode"] = "RECOMMEND"
	}
	if _, e = t.Create(ctx, "policies", policy); e != nil {
		return e
	}
	if !fixture {
		return t.Audit(ctx, "system", "organization.created", t.Tenant, nil)
	}
	account := model.Document{"id": "account-fixture", "provider": "AWS", "name": "AWS sandbox · deterministic fixture", "account_id": "111122223333", "region": "eu-west-1", "status": "CONNECTED", "last_synced_at": model.Now(), "billing_status": "RECONCILED", "fixture": true}
	if _, e = t.Create(ctx, "cloud_accounts", account); e != nil {
		return e
	}
	w := model.Document{"id": "workload-dev", "name": "Developer API sandbox", "environment": "NON_PRODUCTION", "owner": "platform@example.test", "timezone": "Europe/London", "incident": "CLEAR", "deployment": "CLEAR", "job": "CLEAR", "signals_at": model.Now(), "health_url": "fixture://dev-api/health", "criticality": "NON_PRODUCTION", "workload_evidence_complete": true, "work_preserved": true}
	if _, e = t.Create(ctx, "workloads", w); e != nil {
		return e
	}
	base := model.Document{"provider": "AWS", "resource_type": "EC2", "cloud_account_id": "account-fixture", "account_id": "111122223333", "region": "eu-west-1", "workload_id": "workload-dev", "environment": "NON_PRODUCTION", "state": "running", "configuration_authority": "TERRAFORM", "runtime_stop_start_delegated": true, "root_device_type": "ebs", "instance_store": false, "fleet_managed": false, "spot": false, "stop_protection": false, "commitment_known": true, "uncovered_on_demand": true, "unknown_drift": false, "stable_network": true, "blocking_dependencies": false, "observation_days": 14, "hourly_effective_cost": "0.480000000000", "monthly_effective_cost": "350.400000000000", "currency": "GBP", "instance_type": "m6i.2xlarge", "last_seen_at": model.Now(), "eligibility": "ELIGIBLE", "blockers": []string{}}
	for _, r := range []struct {
		id, name, instance string
		field              string
		value              any
		reason             string
	}{
		{"resource-dev-api", "dev-api-01", "i-0123456789abcdef0", "", nil, ""},
		{"resource-protected", "production-database", "i-0123456789abcdef1", "stop_protection", true, "BLOCKED_STOP_PROTECTION"},
		{"resource-commitment", "reserved-build-server", "i-0123456789abcdef2", "uncovered_on_demand", false, "BLOCKED_COMMITMENT_EXPOSURE"},
	} {
		d := model.Clone(base)
		d["id"], d["name"], d["provider_resource_id"] = r.id, r.name, r.instance
		if r.field != "" {
			d[r.field] = r.value
			d["eligibility"] = "BLOCKED"
			d["blockers"] = []string{r.reason}
		}
		if _, e = t.Create(ctx, "resources", d); e != nil {
			return e
		}
	}
	schedule := model.Document{"id": "schedule-dev", "name": "Developer evenings", "workload_id": "workload-dev", "resource_id": "resource-dev-api", "stop_time": "20:00", "ready_time": "07:00", "timezone": "Europe/London", "days": []int{1, 2, 3, 4, 5}, "mode": "ASSISTED_EXECUTION", "paused": false, "skip_next_stop": false, "start_lead_minutes": 15}
	if _, e = t.Create(ctx, "schedules", schedule); e != nil {
		return e
	}
	rec := model.Document{"id": "recommendation-dev", "workload_id": "workload-dev", "resource_id": "resource-dev-api", "title": "Stop idle developer EC2 outside working hours", "category": "NON_PRODUCTION_SCHEDULING", "risk_class": "R1", "status": "VALIDATED", "reason_code": "ELIGIBLE", "monthly_saving": "144.000000000000", "annual_saving": "1728.000000000000", "confidence": "HIGH", "currency": "GBP", "evidence": "14 complete days; no overnight work; uncovered on-demand compute; EBS and static infrastructure cost remain included.", "evidence_window_days": 14, "expires_at": time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339), "created_at": model.Now(), "fixture": true}
	if _, e = t.Create(ctx, "recommendations", rec); e != nil {
		return e
	}
	if _, e = t.Create(ctx, "data_quality", model.Document{"id": "quality-billing", "name": "CUR 2.0 fixture reconciliation", "status": "HEALTHY", "reconciliation_ratio": "1.0000", "source_version": "fixture-cur-v1", "invoice_final": true, "message": "Deterministic test billing; not a customer invoice."}); e != nil {
		return e
	}
	return t.Audit(ctx, "system", "fixture.seeded", t.Tenant, model.Document{"fixture": true})
}
