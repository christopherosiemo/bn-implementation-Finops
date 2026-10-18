package service

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/auth"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/workload"
	"github.com/jackc/pgx/v5"
)

func parseSafetyProfile(d model.Document) (workload.Profile, error) {
	d = model.Clone(d)
	for _, key := range []string{"tenant_id", "hash", "created_at", "writer_role"} {
		delete(d, key)
	}
	raw, err := json.Marshal(d)
	if err != nil {
		return workload.Profile{}, err
	}
	return workload.Decode(raw)
}
func safetyProfileRequest(in model.Document) (workload.Profile, error) {
	for _, key := range []string{"id", "version", "workload_id", "tenant_id", "hash", "created_at", "writer_role"} {
		if _, ok := in[key]; ok {
			return workload.Profile{}, errors.New("SAFETY_IDENTITY_SERVER_SELECTED")
		}
	}
	for _, key := range []string{"schema_version", "criticality", "statefulness", "high_seasonality", "timezone", "min_replicas", "min_zones", "headroom", "saturation", "rto_seconds", "rpo_seconds", "maintenance", "recurring_blackouts", "blackouts", "demand_events", "max_simultaneous_change_ppm", "vm_cooldown_seconds"} {
		if value, ok := in[key]; !ok || value == nil && key != "rpo_seconds" {
			return workload.Profile{}, errors.New("SAFETY_PROFILE_FIELDS_REQUIRED")
		}
	}
	for name, keys := range map[string][]string{"headroom": {"cpu_free_ppm", "memory_free_ppm", "reserve_above_forecast_ppm"}, "saturation": {"cpu_p99_ppm", "memory_p99_ppm"}} {
		nested, ok := in[name].(map[string]any)
		if !ok {
			return workload.Profile{}, errors.New("SAFETY_PROFILE_FIELDS_REQUIRED")
		}
		for _, key := range keys {
			if nested[key] == nil {
				return workload.Profile{}, errors.New("SAFETY_PROFILE_FIELDS_REQUIRED")
			}
		}
	}
	raw, err := json.Marshal(in)
	if err != nil {
		return workload.Profile{}, err
	}
	return workload.Decode(raw)
}
func (a *API) workloadSafetyMutate(ctx context.Context, t *store.Tx, i auth.Identity, r *http.Request, in model.Document, parts []string) (model.Document, int, bool, error) {
	if len(parts) != 3 || parts[0] != "workloads" || parts[2] != "safety-profiles" {
		return nil, 0, false, nil
	}
	if err := requireRole(i, "PLATFORM_ADMIN"); err != nil {
		return nil, 0, true, err
	}
	w, err := t.Get(ctx, "workloads", parts[1])
	if err != nil {
		return nil, 0, true, err
	}
	if err = workloadAccess(i, w); err != nil {
		return nil, 0, true, err
	}
	p, err := safetyProfileRequest(in)
	if err != nil {
		return nil, 0, true, problem(422, err.Error(), "provide explicit workload safety requirements; observations are selected separately")
	}
	latest, err := t.WorkloadSafetyLatest(ctx, parts[1])
	if err != nil && err != pgx.ErrNoRows {
		return nil, 0, true, err
	}
	if latest == nil {
		latest = model.Document{"version": 0}
	}
	if err = match(r, latest); err != nil {
		return nil, 0, true, err
	}
	out, err := t.WorkloadSafetyAppend(ctx, parts[1], model.Number(latest, "version"), p)
	if err == nil {
		err = t.Audit(ctx, i.Subject, "workload.safety_revised", parts[1], model.Document{"profile_id": out["id"], "version": out["version"], "hash": out["hash"]})
	}
	return out, 201, true, err
}
func (a *API) workloadSafetyGet(ctx context.Context, t *store.Tx, i auth.Identity, r *http.Request) (any, bool, error) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/v1/"), "/")
	if len(parts) != 3 || parts[0] != "workloads" || (parts[2] != "safety-profiles" && parts[2] != "safety-evaluation") {
		return nil, false, nil
	}
	w, err := t.Get(ctx, "workloads", parts[1])
	if err != nil {
		return nil, true, err
	}
	if err = workloadAccess(i, w); err != nil {
		return nil, true, err
	}
	latest, err := t.WorkloadSafetyLatest(ctx, parts[1])
	if err != nil && err != pgx.ErrNoRows {
		return nil, true, err
	}
	if parts[2] == "safety-profiles" {
		limit := 50
		if s := r.URL.Query().Get("limit"); s != "" {
			n, e := strconv.Atoi(s)
			if e != nil || n < 1 || n > 100 {
				return nil, true, problem(422, "PAGE_INVALID", "limit must be between 1 and 100")
			}
			limit = n
		}
		var after int64
		if cursor := r.URL.Query().Get("cursor"); cursor != "" {
			raw, e := base64.RawURLEncoding.DecodeString(cursor)
			var c struct {
				Tenant   string `json:"tenant"`
				Workload string `json:"workload"`
				Version  int64  `json:"version"`
			}
			if e != nil || json.Unmarshal(raw, &c) != nil || c.Tenant != i.Tenant || c.Workload != parts[1] || c.Version < 0 {
				return nil, true, problem(422, "CURSOR_INVALID", "cursor belongs to a different query")
			}
			after = c.Version
		}
		rows, e := t.WorkloadSafetyHistory(ctx, parts[1], after, limit)
		if e != nil {
			return nil, true, e
		}
		var next any
		if len(rows) == limit {
			raw, _ := json.Marshal(model.Document{"tenant": i.Tenant, "workload": parts[1], "version": model.Number(rows[len(rows)-1], "version")})
			next = base64.RawURLEncoding.EncodeToString(raw)
		}
		version := model.Number(latest, "version")
		return model.Document{"version": version, "latest": latest, "items": rows, "next_cursor": next}, true, nil
	}
	if latest == nil {
		return model.Document{"status": "BLOCKED", "reason_codes": []string{"SAFETY_PROFILE_REQUIRED"}, "workload_id": parts[1]}, true, nil
	}
	p, e := parseSafetyProfile(latest)
	if e != nil {
		return nil, true, e
	}
	// Readiness is selected against the present clock, never a caller's claimed
	// past maintenance time. This view does not issue execution authority.
	window := workload.EvaluateWindow(p, a.now(), a.now().Add(15*time.Minute))
	reasons := append([]string{}, window.ReasonCodes...)
	reasons = append(reasons, "RECOVERY_EVIDENCE_REQUIRED")
	if p.Statefulness == "UNKNOWN" {
		reasons = append(reasons, "STATEFULNESS_UNKNOWN")
	}
	if p.Statefulness != "STATELESS" {
		reasons = append(reasons, "RPO_EVIDENCE_REQUIRED")
	}
	status := "CLEAR"
	if len(reasons) > 0 {
		status = "BLOCKED"
	}
	return model.Document{"workload_id": parts[1], "profile": latest, "status": status, "reason_codes": reasons, "window": window, "requirements_only": true, "execution_authorized": false, "recovery_evidence_status": "UNAVAILABLE"}, true, nil
}
