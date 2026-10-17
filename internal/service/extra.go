package service

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/auth"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
)

func (a *API) extraMutate(ctx context.Context, t *store.Tx, i auth.Identity, r *http.Request, in model.Document) (model.Document, int, bool, error) {
	path := strings.TrimPrefix(r.URL.Path, "/v1/")
	parts := strings.Split(path, "/")
	if path == "workloads" {
		if e := requireRole(i, "PLATFORM_ADMIN"); e != nil {
			return nil, 0, true, e
		}
		if model.String(in, "name") == "" || model.String(in, "owner") == "" || model.String(in, "environment") != "NON_PRODUCTION" || model.String(in, "health_url") == "" {
			return nil, 0, true, problem(422, "WORKLOAD_FIELDS_REQUIRED", "name,owner,NON_PRODUCTION environment and health_url required")
		}
		d := model.Clone(in)
		d["incident"], d["deployment"], d["job"], d["signals_at"] = "UNKNOWN", "UNKNOWN", "UNKNOWN", model.Now()
		out, e := t.Create(ctx, "workloads", d)
		if e == nil {
			e = t.Audit(ctx, i.Subject, "workload.created", model.String(out, "id"), out)
		}
		return out, 201, true, e
	}
	if len(parts) == 2 && parts[0] == "policies" {
		if e := requireRole(i, "PLATFORM_ADMIN"); e != nil {
			return nil, 0, true, e
		}
		d, e := t.Get(ctx, "policies", parts[1])
		if e != nil {
			return nil, 0, true, e
		}
		if e = match(r, d); e != nil {
			return nil, 0, true, e
		}
		if v, ok := in["paused"]; ok {
			if _, ok = v.(bool); !ok {
				return nil, 0, true, problem(422, "INVALID_POLICY", "paused must be boolean")
			}
			d["paused"] = v
		}
		if _, ok := in["workload_autopilot_ids"]; ok {
			ids := model.Strings(in, "workload_autopilot_ids")
			for _, id := range ids {
				w, e := t.Get(ctx, "workloads", id)
				if e != nil || model.String(w, "environment") != "NON_PRODUCTION" {
					return nil, 0, true, problem(422, "INVALID_POLICY_SCOPE", "Autopilot can be granted only for known non-production workloads")
				}
			}
			d["workload_autopilot_ids"] = ids
			d["autopilot_expires_at"] = time.Now().Add(30 * 24 * time.Hour).UTC().Format(time.RFC3339)
		}
		out, e := t.Update(ctx, "policies", parts[1], model.Number(d, "version"), d)
		if e == nil {
			e = t.Audit(ctx, i.Subject, "policy.updated", parts[1], out)
		}
		return out, 200, true, e
	}
	if len(parts) == 3 && parts[0] == "resources" && parts[2] == "configure" {
		if e := requireRole(i, "PLATFORM_ADMIN"); e != nil {
			return nil, 0, true, e
		}
		d, e := t.Get(ctx, "resources", parts[1])
		if e != nil {
			return nil, 0, true, e
		}
		if e = match(r, d); e != nil {
			return nil, 0, true, e
		}
		if wid := model.String(in, "workload_id"); wid != "" {
			w, e := t.Get(ctx, "workloads", wid)
			if e != nil {
				return nil, 0, true, e
			}
			d["workload_id"], d["environment"] = wid, w["environment"]
		}
		for _, k := range []string{"runtime_stop_start_delegated", "stable_network", "configuration_authority", "unknown_drift", "blocking_dependencies"} {
			if v, ok := in[k]; ok {
				d[k] = v
			}
		}
		d["eligibility"] = "PENDING_ANALYSIS"
		out, e := t.Update(ctx, "resources", parts[1], model.Number(d, "version"), d)
		if e == nil {
			e = t.Audit(ctx, i.Subject, "resource.runtime_delegation_updated", parts[1], out)
		}
		return out, 200, true, e
	}
	if path == "billing/import" {
		if e := requireRole(i, "FINANCE", "FINOPS_ADMIN"); e != nil {
			return nil, 0, true, e
		}
		source := model.String(in, "source_id")
		if source == "" || model.String(in, "source_version") == "" {
			return nil, 0, true, problem(422, "SOURCE_REQUIRED", "immutable source_id and source_version required")
		}
		canonical, e := a.economics(ctx, "normalize", in)
		if e != nil {
			return nil, 0, true, e
		}
		job, e := t.Create(ctx, "ingestion_jobs", model.Document{"source_id": source, "status": "PENDING", "raw": in, "canonical": canonical, "created_at": model.Now()})
		if e != nil {
			return nil, 0, true, e
		}
		if evidenceRaw, ok := in["evidence"]; ok {
			var evidence model.Document
			b, _ := json.Marshal(evidenceRaw)
			if e = json.Unmarshal(b, &evidence); e != nil {
				return nil, 0, true, problem(422, "INVALID_EVIDENCE", "evidence must be a JSON object")
			}
			rid := model.String(in, "resource_id")
			res, e := t.Get(ctx, "resources", rid)
			if e != nil {
				return nil, 0, true, e
			}
			if model.String(evidence, "resource_id") != rid || model.String(evidence, "source_version") != model.String(in, "source_version") {
				return nil, 0, true, problem(422, "EVIDENCE_BINDING_INVALID", "evidence resource and source version must match import")
			}
			if _, e = a.economics(ctx, "evaluate", evidence); e != nil {
				return nil, 0, true, e
			}
			if _, e = t.Create(ctx, "billing_evidence", model.Document{"resource_id": rid, "source_id": source, "source_version": in["source_version"], "ingestion_job_id": job["id"], "evidence": evidence}); e != nil {
				return nil, 0, true, e
			}
			res["commitment_known"], res["uncovered_on_demand"], res["observation_days"] = model.Bool(evidence, "commitment_known"), model.Bool(evidence, "uncovered_on_demand"), model.Number(evidence, "baseline_days")
			res["currency"] = evidence["currency"]
			res["billing_source_version"] = in["source_version"]
			if _, e = t.Update(ctx, "resources", rid, model.Number(res, "version"), res); e != nil {
				return nil, 0, true, e
			}
		}
		if e = t.Audit(ctx, i.Subject, "billing.import_queued", model.String(job, "id"), model.Document{"source_id": source, "source_version": in["source_version"]}); e != nil {
			return nil, 0, true, e
		}
		return model.Document{"ingestion_job": job, "normalization": canonical}, 202, true, nil
	}
	return nil, 0, false, nil
}
