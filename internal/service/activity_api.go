package service

import (
	"context"
	"encoding/json"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/activity"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/auth"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/evidence"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
)

func (a *API) registerActivity(ctx context.Context, t *store.Tx, i auth.Identity, in model.Document) (model.Document, int, error) {
	if e := requireRole(i, "PLATFORM_ADMIN"); e != nil {
		return nil, 0, e
	}
	for k := range in {
		if k != "resource_id" && k != "subject" && k != "metric_definition" {
			return nil, 0, problem(422, "ACTIVITY_REGISTRATION_INVALID", "resource, machine subject and metric definition required")
		}
	}
	res, e := t.Get(ctx, "resources", model.String(in, "resource_id"))
	if e != nil {
		return nil, 0, e
	}
	var metric store.ActivityMetric
	b, _ := json.Marshal(in["metric_definition"])
	if e = json.Unmarshal(b, &metric); e != nil {
		return nil, 0, problem(422, "ACTIVITY_DEFINITION_INVALID", "versioned work unit definition required")
	}
	source, e := t.ActivityRegister(ctx, store.ActivitySource{ResourceID: model.String(res, "id"), WorkloadID: model.String(res, "workload_id"), ProviderResourceID: model.String(res, "provider_resource_id"), AccountID: model.String(res, "account_id"), Region: model.String(res, "region"), Issuer: env("ACTIVITY_OIDC_ISSUER", a.Config.Issuer), Subject: model.String(in, "subject"), MetricDefinition: metric, Enabled: true})
	if e != nil {
		return nil, 0, evidenceProblem(e)
	}
	out := evidence.Object(source)
	e = t.Audit(ctx, i.Subject, "activity_source.registered", source.ID, model.Document{"resource_id": res["id"], "subject": source.Subject, "metric_definition": metric})
	return out, 201, e
}

func activitySources(ctx context.Context, t *store.Tx) ([]model.Document, error) {
	sources, e := t.ActivitySources(ctx)
	if e != nil {
		return nil, e
	}
	out := []model.Document{}
	for _, source := range sources {
		d := evidence.Object(source)
		latest, err := t.ActivityLatest(ctx, source.ResourceID)
		d["reason_code"] = "ACTIVITY_MISSING"
		d["status"] = "UNKNOWN"
		if err == nil {
			signal := activity.FreshActivity(time.Now(), latest, 2*time.Minute)
			d["last_received_at"], d["reason_code"], d["status"] = latest.ReceivedAt.UTC().Format(time.RFC3339Nano), signal.ReasonCode, signal.Status
			d["interval_end"], d["sequence"] = latest.IntervalEnd.UTC().Format(time.RFC3339Nano), latest.Sequence
		}
		out = append(out, d)
	}
	return out, nil
}
