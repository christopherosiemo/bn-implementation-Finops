package workflow

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/activity"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/service"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/jackc/pgx/v5"
	"go.temporal.io/api/serviceerror"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/worker"
)

type Activities struct {
	Store  *store.Store
	Config service.Config
	HTTP   *http.Client
}

func (a *Activities) call(ctx context.Context, target, token, path string, in, out any) error {
	b, _ := json.Marshal(in)
	req, e := http.NewRequestWithContext(ctx, "POST", strings.TrimRight(target, "/")+path, bytes.NewReader(b))
	if e != nil {
		return e
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	res, e := a.HTTP.Do(req)
	if e != nil {
		return e
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(res.Body, 2<<20))
	if res.StatusCode/100 != 2 {
		if res.StatusCode < 500 {
			return temporal.NewNonRetryableApplicationError(string(body), "SafetyBlocked", nil)
		}
		return fmt.Errorf("service %s unavailable (%d)", path, res.StatusCode)
	}
	return json.Unmarshal(body, out)
}
func (a *Activities) Sign(ctx context.Context, in model.WorkflowInput) (model.Envelope, error) {
	var e model.Envelope
	err := a.call(ctx, a.Config.SignerURL, a.Config.SignerToken, "/sign", model.Document{"tenant_id": in.TenantID, "plan_id": in.PlanID, "execution_id": in.ExecutionID}, &e)
	return e, err
}
func (a *Activities) Dispatch(ctx context.Context, in DispatchInput) (model.ProviderState, error) {
	var out model.ProviderState
	e := a.call(ctx, a.Config.ExecutorURL, a.Config.ExecutorToken, "/dispatch", model.Dispatch{Envelope: in.Envelope, ExecutionID: in.Input.ExecutionID, Operation: in.Operation}, &out)
	return out, e
}
func (a *Activities) Stage(ctx context.Context, in StageInput) error {
	return a.Store.Do(ctx, in.Input.TenantID, func(t *store.Tx) error {
		d, e := t.Get(ctx, "executions", in.Input.ExecutionID)
		if e != nil {
			return e
		}
		previousStatus, previousStage := model.String(d, "status"), model.String(d, "stage")
		if previousStatus == in.Status && previousStage == in.Stage && model.String(d, "error") == in.Error && model.Bool(d, "restoration_owned") == in.Owned {
			return nil
		}
		restorationStarted := in.Status == "RESTORING" && in.Owned && model.String(d, "restoration_started_at") == ""
		if restorationStarted {
			d["restoration_started_at"] = model.Now()
		}
		restorationCompleted := (in.Status == "COMPLETED" || in.Stage == "ROLLED_BACK") && !in.Owned && model.String(d, "restoration_started_at") != "" && model.String(d, "restoration_completed_at") == ""
		if restorationCompleted {
			d["restoration_completed_at"] = model.Now()
		}
		d["status"], d["stage"], d["error"], d["restoration_owned"], d["updated_at"] = in.Status, in.Stage, in.Error, in.Owned, model.Now()
		if model.String(d, "started_at") == "" {
			d["started_at"] = model.Now()
		}
		if in.Status == "COMPLETED" {
			d["completed_at"] = model.Now()
		}
		d, e = t.Update(ctx, "executions", in.Input.ExecutionID, model.Number(d, "version"), d)
		if e != nil {
			return e
		}
		if in.Stage == "STOPPED" || in.Status == "COMPLETED" {
			r, e := t.Get(ctx, "resources", model.String(d, "resource_id"))
			if e != nil {
				return e
			}
			r["state"] = "running"
			if in.Stage == "STOPPED" {
				r["state"] = "stopped"
			}
			r["last_seen_at"] = model.Now()
			if _, e = t.Update(ctx, "resources", model.String(r, "id"), model.Number(r, "version"), r); e != nil {
				return e
			}
		}
		if e = t.Audit(ctx, "temporal-worker", "execution.stage_changed", in.Input.ExecutionID, model.Document{"stage": in.Stage, "status": in.Status, "error": in.Error}); e != nil {
			return e
		}
		for event, emit := range map[string]bool{"restoration.started": restorationStarted, "restoration.completed": restorationCompleted} {
			if emit {
				payload := model.Document{"execution_id": in.Input.ExecutionID, "resource_id": d["resource_id"], "status": in.Status, "stage": in.Stage}
				if e = t.Audit(ctx, "temporal-worker", event, in.Input.ExecutionID, payload); e != nil {
					return e
				}
				if e = t.Event(ctx, event, payload); e != nil {
					return e
				}
			}
		}
		if previousStatus == in.Status && previousStage == in.Stage {
			return nil
		}
		event := "execution.stage_changed"
		if in.Status == "COMPLETED" {
			event = "execution.completed"
		}
		if in.Status == "FAILED" || in.Stage == "RESTORATION_ALERT" || in.Stage == "HEALTH_ALERT" {
			event = "execution.failed"
		}
		return t.Event(ctx, event, d)
	})
}
func (a *Activities) Control(ctx context.Context, in model.WorkflowInput) (Control, error) {
	var c Control
	e := a.Store.Do(ctx, in.TenantID, func(t *store.Tx) error {
		d, e := t.Get(ctx, "executions", in.ExecutionID)
		if e != nil {
			return e
		}
		p, e := t.Get(ctx, "change_plans", in.PlanID)
		if e != nil {
			return e
		}
		c.StopAt, e = time.Parse(time.RFC3339Nano, model.String(p, "stop_at"))
		if e != nil {
			return e
		}
		org, e := t.Get(ctx, "org", in.TenantID)
		if e != nil {
			return e
		}
		s, e := t.Get(ctx, "schedules", model.String(d, "schedule_id"))
		if e != nil {
			return e
		}
		w, e := t.Get(ctx, "workloads", model.String(d, "workload_id"))
		if e != nil {
			return e
		}
		c.Restore = model.Bool(d, "start_now") || model.Bool(org, "paused") || model.Bool(s, "paused") || model.String(w, "incident") != "CLEAR" || model.String(w, "job") == "ACTIVE" || model.String(w, "deployment") == "ACTIVE"
		payload := model.Document{}
		encoded, _ := json.Marshal(p["payload"])
		_ = json.Unmarshal(encoded, &payload)
		if model.String(payload, "schema_version") == "3" {
			latest, err := t.ActivityLatest(ctx, model.String(d, "resource_id"))
			// Lost trusted inputs are restoration requests, never cancellation of
			// the executor's already persisted ownership obligation.
			c.Restore = model.Bool(d, "start_now") || model.Bool(org, "paused") || model.Bool(s, "paused") || err != nil || activity.FreshActivity(time.Now(), latest, 2*time.Minute).Status != "CLEAR"
			if err := service.DependencyPlanReady(ctx, t, model.String(d, "resource_id"), model.String(payload, "dependency_review_id"), model.String(payload, "dependency_graph_hash"), time.Now()); err != nil {
				c.Restore = true
			}
		}
		return nil
	})
	return c, e
}
func (a *Activities) Owned(ctx context.Context, in model.WorkflowInput) (bool, error) {
	owned := false
	e := a.Store.Do(ctx, in.TenantID, func(t *store.Tx) error {
		e := t.QueryRow(ctx, "SELECT stop_intent FROM provider_operations WHERE tenant_id=$1 AND execution_id=$2", t.Tenant, in.ExecutionID).Scan(&owned)
		if e == pgx.ErrNoRows {
			return nil
		}
		return e
	})
	return owned, e
}
func Run(ctx context.Context, cfg service.Config, db *store.Store) error {
	c, e := client.Dial(client.Options{HostPort: cfg.TemporalAddress, Namespace: cfg.TemporalNamespace, Logger: sdkLogger{}})
	if e != nil {
		return e
	}
	defer c.Close()
	a := &Activities{db, cfg, &http.Client{Timeout: 35 * time.Second}}
	w := worker.New(c, service.TaskQueue, worker.Options{})
	w.RegisterWorkflow(Occurrence)
	w.RegisterActivity(a)
	if e = w.Start(); e != nil {
		return e
	}
	defer w.Stop()
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
			if e = dispatchQueued(ctx, c, a); e != nil {
				slog.Error("dispatch tick", "error", e)
			}
		}
	}
}
func dispatchQueued(ctx context.Context, c client.Client, a *Activities) error {
	rows, e := a.Store.Pool.Query(ctx, "SELECT tenant_id FROM tenant_registry")
	if e != nil {
		return e
	}
	tenants := []string{}
	for rows.Next() {
		var t string
		if e = rows.Scan(&t); e != nil {
			rows.Close()
			return e
		}
		tenants = append(tenants, t)
	}
	rows.Close()
	for _, tenant := range tenants {
		var queued []model.Document
		e = a.Store.Do(ctx, tenant, func(t *store.Tx) error {
			var e error
			queued, e = t.List(ctx, "executions")
			if e != nil {
				return e
			}
			if e := scheduleDue(ctx, a, t); e != nil {
				return e
			}
			return deliverOutbox(ctx, a, t)
		})
		if e != nil {
			slog.Error("tenant dispatch", "tenant", tenant, "error", e)
			continue
		}
		for _, x := range queued {
			if model.String(x, "status") != "QUEUED" {
				continue
			}
			in := model.WorkflowInput{TenantID: tenant, ExecutionID: model.String(x, "id"), PlanID: model.String(x, "change_plan_id")}
			_, e = c.ExecuteWorkflow(ctx, client.StartWorkflowOptions{ID: "occurrence/" + tenant + "/" + in.ExecutionID, TaskQueue: service.TaskQueue}, Occurrence, in)
			var already *serviceerror.WorkflowExecutionAlreadyStarted
			if e != nil && !errors.As(e, &already) {
				slog.Error("start occurrence", "execution", in.ExecutionID, "error", e)
			}
		}
	}
	return nil
}
func deliverOutbox(ctx context.Context, a *Activities, t *store.Tx) error {
	if a.Config.WebhookURL == "" {
		return nil
	}
	if a.Config.WebhookSecret == "" {
		return errors.New("WEBHOOK_SECRET is required when WEBHOOK_URL is configured")
	}
	target, e := url.Parse(a.Config.WebhookURL)
	if e != nil || target.Host == "" || target.User != nil || target.Fragment != "" || target.Scheme != "https" && (!a.Config.Fixture || target.Scheme != "http") {
		return errors.New("webhook destination must use HTTPS without embedded credentials; HTTP is allowed only for fixtures")
	}
	rows, e := t.Query(ctx, "SELECT id,event_type,payload FROM outbox WHERE tenant_id=$1 AND delivered_at IS NULL AND next_attempt<=now() ORDER BY created_at LIMIT 20 FOR UPDATE SKIP LOCKED", t.Tenant)
	if e != nil {
		return e
	}
	type event struct {
		id, kind string
		payload  []byte
	}
	events := []event{}
	for rows.Next() {
		var x event
		if e = rows.Scan(&x.id, &x.kind, &x.payload); e != nil {
			rows.Close()
			return e
		}
		events = append(events, x)
	}
	if e = rows.Err(); e != nil {
		rows.Close()
		return e
	}
	rows.Close()
	for _, x := range events {
		body, _ := json.Marshal(model.Document{"id": x.id, "tenant_id": t.Tenant, "type": x.kind, "data": json.RawMessage(x.payload)})
		req, e := http.NewRequestWithContext(ctx, "POST", a.Config.WebhookURL, bytes.NewReader(body))
		if e != nil {
			return e
		}
		mac := hmac.New(sha256.New, []byte(a.Config.WebhookSecret))
		mac.Write(body)
		req.Header.Set("X-Autopilot-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", x.id)
		client := *a.HTTP
		client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		res, e := client.Do(req)
		ok := e == nil && res.StatusCode/100 == 2
		if res != nil {
			_ = res.Body.Close()
		}
		if ok {
			_, e = t.Exec(ctx, "UPDATE outbox SET delivered_at=now(),attempts=attempts+1 WHERE tenant_id=$1 AND id=$2", t.Tenant, x.id)
		} else {
			_, e = t.Exec(ctx, "UPDATE outbox SET attempts=attempts+1,next_attempt=now()+interval '1 minute' WHERE tenant_id=$1 AND id=$2", t.Tenant, x.id)
		}
		if e != nil {
			return e
		}
	}
	return nil
}

type sdkLogger struct{}

func (sdkLogger) Debug(msg string, keyvals ...interface{}) { slog.Debug(msg, keyvals...) }
func (sdkLogger) Info(msg string, keyvals ...interface{})  { slog.Info(msg, keyvals...) }
func (sdkLogger) Warn(msg string, keyvals ...interface{})  { slog.Warn(msg, keyvals...) }
func (sdkLogger) Error(msg string, keyvals ...interface{}) { slog.Error(msg, keyvals...) }
