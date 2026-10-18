package service

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/auth"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/telemetry"
)

type telemetryRegistration struct {
	ResourceID    string                 `json:"resource_id"`
	Kind          string                 `json:"kind"`
	ReadBindingID string                 `json:"read_binding_id,omitempty"`
	Subject       string                 `json:"subject,omitempty"`
	Definitions   []telemetry.Definition `json:"definitions"`
}
type telemetryReadCatalogEntry struct {
	Binding        telemetry.Binding `json:"binding"`
	RequiredLabels map[string]string `json:"required_labels"`
}

func (a *API) telemetryCatalog() (map[string]telemetryReadCatalogEntry, error) {
	out := map[string]telemetryReadCatalogEntry{}
	raw := os.Getenv("TELEMETRY_BINDING_CATALOG_JSON")
	if raw != "" {
		if json.Unmarshal([]byte(raw), &out) != nil {
			return nil, errors.New("TELEMETRY_BINDING_CATALOG_INVALID")
		}
		return out, nil
	}
	if a.Config.Fixture {
		out["fixture-prometheus-dev-api"] = telemetryReadCatalogEntry{Binding: telemetry.Binding{TenantID: "tenant-demo", ResourceID: "resource-dev-api", WorkloadID: "workload-dev", Provider: "AWS", ProviderResourceID: "i-0123456789abcdef0", AccountID: "111122223333", Region: "eu-west-1"}, RequiredLabels: map[string]string{"finops_resource_id": "resource-dev-api"}}
	}
	return out, nil
}
func telemetryStrict(in model.Document, out any) error {
	raw, err := json.Marshal(in)
	if err != nil {
		return err
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil || d.Decode(&struct{}{}) != io.EOF {
		return problem(422, "TELEMETRY_FIELDS_INVALID", "use the versioned telemetry request; identity and evidence are server-selected")
	}
	return nil
}
func telemetryBoundResource(ctx context.Context, t *store.Tx, i auth.Identity, d model.Document) error {
	c, err := telemetry.ParseConnection(d)
	if err != nil {
		return err
	}
	w, err := t.Get(ctx, "workloads", c.Binding.WorkloadID)
	if err != nil {
		return err
	}
	return workloadAccess(i, w)
}
func nativeCursor(r *http.Request, tenant, kind, scope string) (string, int, error) {
	limit := 50
	if s := r.URL.Query().Get("limit"); s != "" {
		n, e := strconv.Atoi(s)
		if e != nil || n < 1 || n > 100 {
			return "", 0, problem(422, "PAGE_INVALID", "limit must be between 1 and 100")
		}
		limit = n
	}
	if s := r.URL.Query().Get("cursor"); s != "" {
		raw, e := base64.RawURLEncoding.DecodeString(s)
		var c struct{ Tenant, Kind, Scope, After string }
		if e != nil || json.Unmarshal(raw, &c) != nil || c.Tenant != tenant || c.Kind != kind || c.Scope != scope {
			return "", 0, problem(422, "CURSOR_INVALID", "cursor belongs to a different query")
		}
		return c.After, limit, nil
	}
	return "", limit, nil
}
func nativePage(rows []model.Document, limit int, tenant, kind, scope string) model.Document {
	var cursor any
	if len(rows) > limit {
		rows = rows[:limit]
		raw, _ := json.Marshal(struct{ Tenant, Kind, Scope, After string }{tenant, kind, scope, model.String(rows[len(rows)-1], "id")})
		cursor = base64.RawURLEncoding.EncodeToString(raw)
	}
	return model.Document{"items": rows, "next_cursor": cursor}
}
func (a *API) telemetryGet(ctx context.Context, t *store.Tx, i auth.Identity, r *http.Request) (any, bool, error) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/v1/"), "/")
	if len(parts) == 1 && parts[0] == "telemetry-connections" {
		workload := r.URL.Query().Get("workload_id")
		if workload != "" {
			w, e := t.Get(ctx, "workloads", workload)
			if e != nil {
				return nil, true, e
			}
			if e = workloadAccess(i, w); e != nil {
				return nil, true, e
			}
		} else if i.Can("APPLICATION_OWNER") && !i.Can("FINOPS_ADMIN", "PLATFORM_ADMIN", "FINANCE", "APPROVER", "VIEWER", "AUDITOR") {
			return nil, true, problem(403, "WORKLOAD_SCOPE_REQUIRED", "select an owned workload")
		}
		after, limit, err := nativeCursor(r, i.Tenant, "telemetry-connections", workload)
		if err != nil {
			return nil, true, err
		}
		rows, err := t.TelemetryConnectionPage(ctx, after, workload, limit+1)
		return nativePage(rows, limit, i.Tenant, "telemetry-connections", workload), true, err
	}
	if len(parts) == 1 && parts[0] == "metric-definitions" {
		id := r.URL.Query().Get("connection_id")
		c, e := t.TelemetryConnection(ctx, id)
		if e != nil {
			return nil, true, e
		}
		if e = telemetryBoundResource(ctx, t, i, c); e != nil {
			return nil, true, e
		}
		typed, e := telemetry.ParseConnection(c)
		return model.Document{"items": typed.Definitions, "next_cursor": nil, "connection_id": id, "config_hash": c["config_hash"]}, true, e
	}
	if len(parts) < 2 || parts[0] != "telemetry-connections" {
		return nil, false, nil
	}
	c, err := t.TelemetryConnection(ctx, parts[1])
	if err != nil {
		return nil, true, err
	}
	if err = telemetryBoundResource(ctx, t, i, c); err != nil {
		return nil, true, err
	}
	if len(parts) == 2 {
		return c, true, nil
	}
	if len(parts) == 3 && parts[2] == "receipts" {
		after, limit, e := nativeCursor(r, i.Tenant, "telemetry-receipts", parts[1])
		if e != nil {
			return nil, true, e
		}
		rows, e := t.TelemetryReceiptPage(ctx, parts[1], after, limit+1)
		return nativePage(rows, limit, i.Tenant, "telemetry-receipts", parts[1]), true, e
	}
	if len(parts) == 4 && parts[2] == "sync" {
		j, e := t.TelemetrySyncGet(ctx, parts[3])
		if e != nil {
			return nil, true, e
		}
		if model.String(j, "connection_id") != parts[1] {
			return nil, true, problem(404, "NOT_FOUND", "sync not found")
		}
		delete(j, "lease_token")
		delete(j, "lease_until")
		return j, true, nil
	}
	if len(parts) == 3 && parts[2] == "evaluations" {
		after, limit, e := nativeCursor(r, i.Tenant, "telemetry-evaluations", parts[1])
		if e != nil {
			return nil, true, e
		}
		rows, e := t.TelemetryEvaluationPage(ctx, parts[1], after, limit+1)
		return nativePage(rows, limit, i.Tenant, "telemetry-evaluations", parts[1]), true, e
	}
	return nil, true, problem(404, "NOT_FOUND", "telemetry route not found")
}
func (a *API) telemetryMutate(ctx context.Context, t *store.Tx, i auth.Identity, r *http.Request, in model.Document, parts []string) (model.Document, int, bool, error) {
	if len(parts) < 1 || parts[0] != "telemetry-connections" {
		return nil, 0, false, nil
	}
	if err := requireRole(i, "PLATFORM_ADMIN"); err != nil {
		return nil, 0, true, err
	}
	var current model.Document
	var err error
	if len(parts) > 1 {
		current, err = t.TelemetryConnection(ctx, parts[1])
		if err != nil {
			return nil, 0, true, err
		}
		if err = telemetryBoundResource(ctx, t, i, current); err != nil {
			return nil, 0, true, err
		}
	}
	if current != nil {
		if err = match(r, current); err != nil {
			return nil, 0, true, err
		}
	}
	if len(parts) == 1 || len(parts) == 3 && parts[2] == "revisions" {
		var req telemetryRegistration
		if err = telemetryStrict(in, &req); err != nil {
			return nil, 0, true, err
		}
		res, e := t.Get(ctx, "resources", req.ResourceID)
		if e != nil {
			return nil, 0, true, e
		}
		w, e := t.Get(ctx, "workloads", model.String(res, "workload_id"))
		if e != nil {
			return nil, 0, true, e
		}
		if e = workloadAccess(i, w); e != nil {
			return nil, 0, true, e
		}
		binding := telemetry.Binding{TenantID: i.Tenant, ResourceID: req.ResourceID, WorkloadID: model.String(w, "id"), Provider: model.String(res, "provider"), ProviderResourceID: model.String(res, "provider_resource_id"), AccountID: model.String(res, "account_id"), Region: model.String(res, "region")}
		if req.Kind == "PROMETHEUS" {
			if req.Subject != "" {
				return nil, 0, true, problem(422, "TELEMETRY_SOURCE_FIELDS_INVALID", "Prometheus uses an approved read binding")
			}
			catalog, e := a.telemetryCatalog()
			if e != nil {
				return nil, 0, true, e
			}
			entry, ok := catalog[req.ReadBindingID]
			if !ok || entry.Binding != binding || len(entry.RequiredLabels) == 0 {
				return nil, 0, true, problem(422, "TELEMETRY_READ_BINDING_NOT_APPROVED", "configure an exact tenant/resource read binding before registration")
			}
			for n := range req.Definitions {
				d := &req.Definitions[n]
				if d.Attributes == nil {
					d.Attributes = map[string]string{}
				}
				for key, value := range entry.RequiredLabels {
					if old, ok := d.Attributes[key]; ok && old != value {
						return nil, 0, true, problem(422, "TELEMETRY_SELECTOR_BINDING_CONFLICT", "required source labels cannot be changed")
					}
					d.Attributes[key] = value
				}
				if d.Type != "GAUGE" {
					if d.EpochAttributes == nil {
						d.EpochAttributes = map[string]string{}
					}
					for key, value := range entry.RequiredLabels {
						if old, ok := d.EpochAttributes[key]; ok && old != value {
							return nil, 0, true, problem(422, "TELEMETRY_SELECTOR_BINDING_CONFLICT", "epoch selector must preserve the resource binding")
						}
						d.EpochAttributes[key] = value
					}
				}
			}
		} else if req.Kind == "OTLP" {
			if req.ReadBindingID != "" || req.Subject == "" {
				return nil, 0, true, problem(422, "TELEMETRY_MACHINE_BINDING_REQUIRED", "OTLP requires a registered machine subject")
			}
			for n := range req.Definitions {
				d := &req.Definitions[n]
				if d.ResourceAttributes == nil {
					d.ResourceAttributes = map[string]string{}
				}
				for key, value := range map[string]string{"finops.resource.id": binding.ResourceID, "finops.tenant.id": i.Tenant} {
					if old, ok := d.ResourceAttributes[key]; ok && old != value {
						return nil, 0, true, problem(422, "TELEMETRY_ATTRIBUTE_BINDING_CONFLICT", "required resource attributes cannot be changed")
					}
					d.ResourceAttributes[key] = value
				}
			}
		}
		id := model.ID()
		var expected int64
		if current != nil {
			if err = match(r, current); err != nil {
				return nil, 0, true, err
			}
			id = model.String(current, "id")
			expected = model.Number(current, "version")
		}
		c := telemetry.Connection{SchemaVersion: "1", ID: id, Version: expected + 1, Kind: req.Kind, ReadBindingID: req.ReadBindingID, Binding: binding, Enabled: true, Definitions: req.Definitions}
		if req.Kind == "OTLP" {
			c.Issuer = env("TELEMETRY_OIDC_ISSUER", a.Config.Issuer)
			c.Subject = req.Subject
		}
		if e = telemetry.ValidateConnection(c); e != nil {
			return nil, 0, true, problem(422, e.Error(), "invalid registered telemetry definition")
		}
		out, e := t.TelemetryConnectionAppend(ctx, id, expected, telemetry.Document(c))
		if e == nil {
			e = t.Audit(ctx, i.Subject, "telemetry.connection_revised", id, model.Document{"version": out["version"], "config_hash": out["config_hash"]})
		}
		return out, 201, true, e
	}
	if len(parts) != 3 {
		return nil, 0, true, problem(404, "NOT_FOUND", "telemetry route not found")
	}
	switch parts[2] {
	case "revoke":
		if err = match(r, current); err != nil {
			return nil, 0, true, err
		}
		var req struct {
			Reason string `json:"reason"`
		}
		if err = telemetryStrict(in, &req); err != nil {
			return nil, 0, true, err
		}
		if strings.TrimSpace(req.Reason) == "" || len(req.Reason) > 2000 {
			return nil, 0, true, problem(422, "REVOCATION_REASON_REQUIRED", "record a bounded source revocation reason")
		}
		out, replay, e := t.TelemetryRevocationAppend(ctx, model.String(current, "revision_id"), req.Reason)
		if e == nil && !replay {
			e = t.Audit(ctx, i.Subject, "telemetry.source_revoked", parts[1], out)
		}
		return out, 200, true, e
	case "sync":
		if len(in) > 0 {
			return nil, 0, true, problem(422, "TELEMETRY_FIELDS_INVALID", "history dates are selected by the server")
		}
		if model.String(current, "kind") != "PROMETHEUS" {
			return nil, 0, true, problem(422, "TELEMETRY_PROTOCOL_MISMATCH", "OTLP is a current authenticated push stream")
		}
		days, tz := a.telemetryHistoryPolicy(ctx, t, current)
		loc, e := time.LoadLocation(tz)
		if e != nil {
			return nil, 0, true, e
		}
		now := a.now().In(loc)
		end := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, loc)
		start := end.AddDate(0, 0, -days)
		out, _, e := t.TelemetrySyncRequest(ctx, parts[1], r.Header.Get("Idempotency-Key"), model.Document{"start": start.UTC(), "end": end.UTC(), "history_days": days})
		if e == nil {
			delete(out, "lease_token")
			delete(out, "lease_until")
			e = t.Audit(ctx, i.Subject, "telemetry.sync_requested", parts[1], model.Document{"sync_id": out["id"], "history_days": days})
		}
		return out, 202, true, e
	case "evaluate":
		var req struct {
			Mode string `json:"mode"`
		}
		if err = telemetryStrict(in, &req); err != nil {
			return nil, 0, true, err
		}
		if req.Mode != "history" && req.Mode != "window" {
			return nil, 0, true, problem(422, "TELEMETRY_MODE_INVALID", "select history or window")
		}
		days, tz := a.telemetryHistoryPolicy(ctx, t, current)
		result, e := a.nativeEvaluation(ctx, model.Document{"tenant_id": i.Tenant, "connection_id": parts[1], "mode": req.Mode, "days": days, "timezone": tz, "minutes": 5})
		if e != nil {
			return nil, 0, true, e
		}
		// Do not relabel a result returned after a concurrent revision. The reader
		// binds its own immutable selection; publication rechecks current authority
		// under the connection lock as well.
		if model.String(result, "connection_id") != parts[1] || model.String(result, "config_hash") != model.String(current, "config_hash") {
			return nil, 0, true, problem(409, "TELEMETRY_CONFIG_CHANGED", "the telemetry revision changed during evaluation; refresh and retry")
		}
		if len(model.Strings(result, "receipt_ids")) == 0 {
			return nil, 0, true, problem(422, "TELEMETRY_EVIDENCE_MISSING", "wait for persisted native evidence before recording an evaluation")
		}
		out, e := t.TelemetryEvaluationCreate(ctx, result)
		return out, 201, true, e
	}
	return nil, 0, true, problem(404, "NOT_FOUND", "telemetry route not found")
}
func (a *API) telemetryHistoryPolicy(ctx context.Context, t *store.Tx, c model.Document) (int, string) {
	typed, err := telemetry.ParseConnection(c)
	if err != nil {
		return 30, "UTC"
	}
	d, err := t.WorkloadSafetyLatest(ctx, typed.Binding.WorkloadID)
	if err != nil {
		return 30, "UTC"
	}
	p, err := parseSafetyProfile(d)
	if err != nil {
		return 30, "UTC"
	}
	if p.HighSeasonality {
		return 90, p.Timezone
	}
	w, err := t.Get(ctx, "workloads", typed.Binding.WorkloadID)
	if err == nil && p.Criticality == "NON_PRODUCTION" && model.String(w, "environment") == "NON_PRODUCTION" {
		return 14, p.Timezone
	}
	return 30, p.Timezone
}
func (a *API) nativeEvaluation(ctx context.Context, input model.Document) (model.Document, error) {
	token := os.Getenv("TELEMETRY_READER_TOKEN")
	if token == "" {
		return nil, problem(503, "TELEMETRY_READER_NOT_CONFIGURED", "native evidence evaluation is unavailable")
	}
	raw, _ := json.Marshal(input)
	req, e := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(env("TELEMETRY_READER_URL", "http://telemetry-reader:8095"), "/")+"/evaluate", bytes.NewReader(raw))
	if e != nil {
		return nil, e
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	client := a.Client
	if client == nil {
		client = &http.Client{Timeout: 2 * time.Minute}
	}
	res, e := client.Do(req)
	if e != nil {
		return nil, problem(503, "TELEMETRY_EVALUATION_UNAVAILABLE", "native evidence evaluation could not complete")
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return nil, problem(503, "TELEMETRY_EVALUATION_UNAVAILABLE", "inspect source coverage and the native reader")
	}
	var out model.Document
	if json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&out) != nil {
		return nil, problem(503, "TELEMETRY_EVALUATION_INVALID", "native reader returned an invalid evaluation")
	}
	return out, nil
}
