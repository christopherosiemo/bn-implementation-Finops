package service

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/auth"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
)

func (a *API) extraMutate(ctx context.Context, t *store.Tx, i auth.Identity, r *http.Request, in model.Document) (model.Document, int, bool, error) {
	if d,status,handled,e:=a.objectStorageAccessMutate(ctx,t,i,r,in);handled{return d,status,true,e}
	if d,status,handled,e:=a.networkMutate(ctx,t,i,r,in);handled{return d,status,true,e}
	if d, status, handled, e := a.objectStorageMutate(ctx, t, i, r, in); handled {
		return d, status, true, e
	}
	if d, status, handled, e := a.storageMutate(ctx, t, i, r, in); handled {
		return d, status, true, e
	}
	if d, status, handled, e := a.databaseMutate(ctx, t, i, r, in); handled {
		return d, status, true, e
	}
	path := strings.TrimPrefix(r.URL.Path, "/v1/")
	parts := strings.Split(path, "/")
	if d, status, handled, e := a.sloMutate(ctx, t, i, r, in, parts); handled {
		return d, status, true, e
	}
	if d, status, handled, e := a.dependencyMutate(ctx, t, i, r, in, parts); handled {
		return d, status, true, e
	}
	if path == "activity-sources" {
		d, status, e := a.registerActivity(ctx, t, i, in)
		return d, status, true, e
	}
	if d, status, handled, e := a.sourceMutate(ctx, t, i, r, in, parts); handled {
		return d, status, true, e
	}
	if d, status, handled, e := a.readinessMutate(ctx, t, i, r, in, parts); handled {
		return d, status, true, e
	}
	if path == "workloads" {
		if e := requireRole(i, "PLATFORM_ADMIN"); e != nil {
			return nil, 0, true, e
		}
		observeOnly := in["observation_only"] == true
		validEnvironment := model.String(in, "environment") == "NON_PRODUCTION" || (observeOnly && model.String(in, "environment") == "PRODUCTION")
		if model.String(in, "name") == "" || model.String(in, "owner") == "" || !validEnvironment || (!observeOnly && model.String(in, "health_url") == "") {
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
		if e := lockSchedulingControl(ctx, t, false); e != nil {
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
		if model.String(in, "schema_version") != "2" {
			return nil, 0, true, problem(422, "EVIDENCE_V2_REQUIRED", "new evidence imports require schema_version 2")
		}
		source := model.String(in, "source_id")
		if source == "" || model.String(in, "source_version") == "" {
			return nil, 0, true, problem(422, "SOURCE_REQUIRED", "immutable source_id and source_version required")
		}
		canonical, e := a.economics(ctx, "normalize", in)
		if e != nil {
			return nil, 0, true, e
		}
		job, e := t.Create(ctx, "ingestion_jobs", model.Document{"source_id": source, "source_version": in["source_version"], "source_provenance": "CUSTOMER_IMPORT", "status": "PENDING", "raw": in, "canonical": canonical, "created_at": model.Now()})
		if e != nil {
			return nil, 0, true, e
		}
		if _, ok := in["evidence"]; ok {
			return nil, 0, true, problem(422, "LEGACY_EVIDENCE_REJECTED", "import source records, then seal a baseline from persisted canonical evidence")
		}
		if e = t.Audit(ctx, i.Subject, "billing.import_queued", model.String(job, "id"), model.Document{"source_id": source, "source_version": in["source_version"]}); e != nil {
			return nil, 0, true, e
		}
		if _, e = t.Create(ctx, "data_quality", model.Document{"name": "Customer billing import", "status": "PROVISIONAL", "source_id": source, "source_version": in["source_version"], "ingestion_job_id": job["id"], "reason_code": "TRUSTED_SOURCE_REQUIRED", "message": "Customer-imported records can be inspected but cannot authorize live stops or verified savings without trusted AWS and workload-source provenance."}); e != nil {
			return nil, 0, true, e
		}
		return model.Document{"ingestion_job": job, "normalization": canonical}, 202, true, nil
	}
	return nil, 0, false, nil
}
