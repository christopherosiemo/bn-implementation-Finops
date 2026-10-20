package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/auth"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/commitmentportfolio"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/evidence"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/safety"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/jackc/pgx/v5"
)

type API struct {
	Store  *store.Store
	Config Config
	Auth   *auth.Validator
	Client *http.Client
	// Clock is injected by deterministic acceptance tests, never configured by
	// requests or environment. Production always uses the process UTC clock.
	Clock func() time.Time
}

const maxMutationBodyBytes int64 = 4 << 20

func (a *API) now() time.Time {
	if a.Clock != nil {
		return a.Clock().UTC()
	}
	return time.Now().UTC()
}

type Problem struct {
	Status  int
	Code    string
	Message string
}

func (p *Problem) Error() string                     { return p.Message }
func problem(status int, code, message string) error { return &Problem{status, code, message} }
func JSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func fail(w http.ResponseWriter, e error) {
	p := &Problem{500, "INTERNAL_ERROR", "request failed"}
	if errors.Is(e, pgx.ErrNoRows) {
		p = &Problem{404, "NOT_FOUND", "resource not found"}
	} else if errors.Is(e, store.ErrConflict) {
		p = &Problem{409, "VERSION_CONFLICT", e.Error()}
	} else if errors.Is(e, store.ErrTelemetryConflict) {
		p = &Problem{409, "TELEMETRY_REPLAY_CONFLICT", "the source revision or immutable request conflicts"}
	} else if errors.Is(e, store.ErrTelemetrySource) {
		p = &Problem{422, "TELEMETRY_SOURCE_INVALID", "the registered source is unavailable or no longer matches its resource"}
	} else if errors.Is(e, store.ErrFleetHistorySourceBusy) {
		w.Header().Set("Retry-After", "1")
		p = &Problem{503, "FLEET_HISTORY_SOURCE_BUSY", "source synchronization is busy; retry the same request with the same Idempotency-Key"}
	} else if errors.Is(e, store.ErrFleetHistorySource) {
		p = &Problem{422, "FLEET_HISTORY_SOURCE_UNAVAILABLE", "fleet history requires current registered native sources with unchanged bindings"}
	} else if errors.Is(e, store.ErrFleetHistoryBounds) {
		p = &Problem{503, "FLEET_HISTORY_POPULATION_LIMIT", "the selected history exceeds the supported evaluation bound"}
	} else {
		var found *Problem
		if errors.As(e, &found) {
			p = found
		} else {
			slog.Error("request failed", "error", e)
		}
	}
	JSON(w, p.Status, model.Document{"error": p.Code, "message": p.Message})
}
func (a *API) Handler() http.Handler { return http.HandlerFunc(a.ServeHTTP) }
func (a *API) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/healthz" {
		if e := a.Store.Pool.Ping(r.Context()); e != nil {
			JSON(w, 503, model.Document{"status": "degraded"})
			return
		}
		JSON(w, 200, model.Document{"status": "ok", "role": "api", "fixture": a.Config.Fixture})
		return
	}
	if commitmentportfolio.Route(r.URL.Path) {
		(&commitmentportfolio.API{Pool: a.Store.Pool, Auth: a.Auth, Now: a.now}).ServeHTTP(w, r)
		return
	}
	i, e := a.Auth.Validate(r)
	if e != nil {
		fail(w, problem(401, "UNAUTHORIZED", e.Error()))
		return
	}
	if !i.Can("FINOPS_ADMIN", "PLATFORM_ADMIN", "FINANCE", "APPLICATION_OWNER", "APPROVER", "VIEWER", "AUDITOR") {
		fail(w, problem(403, "FORBIDDEN", "a FinOps organization role is required"))
		return
	}
	if !strings.HasPrefix(r.URL.Path, "/v1/") {
		fail(w, problem(404, "NOT_FOUND", "route not found"))
		return
	}
	if r.Method == http.MethodGet {
		a.get(w, r, i)
		return
	}
	if r.Method != http.MethodPost {
		fail(w, problem(405, "METHOD_NOT_ALLOWED", "use GET or POST"))
		return
	}
	if !i.Can("FINOPS_ADMIN", "PLATFORM_ADMIN", "APPROVER", "APPLICATION_OWNER", "FINANCE") {
		fail(w, problem(403, "FORBIDDEN", "mutation role required"))
		return
	}
	// Cached responses must obey the same current route roles as fresh writes.
	if e := authorizeMutationRole(i, r.URL.Path); e != nil && !(r.URL.Path == "/v1/approvals" && i.Roles["FINANCE"]) {
		fail(w, e)
		return
	}
	key := r.Header.Get("Idempotency-Key")
	if len(key) < 8 || len(key) > 200 {
		fail(w, problem(400, "IDEMPOTENCY_KEY_REQUIRED", "provide an Idempotency-Key between 8 and 200 characters"))
		return
	}
	body, e := io.ReadAll(http.MaxBytesReader(w, r.Body, maxMutationBodyBytes))
	if e != nil {
		var oversized *http.MaxBytesError
		if errors.As(e, &oversized) {
			fail(w, problem(http.StatusRequestEntityTooLarge, "BODY_TOO_LARGE", "request body exceeds 4 MiB"))
			return
		}
		fail(w, e)
		return
	}
	var input model.Document
	if len(body) > 0 {
		if e = json.Unmarshal(body, &input); e != nil {
			fail(w, problem(400, "INVALID_JSON", "invalid JSON request"))
			return
		}
	}
	if input == nil {
		input = model.Document{}
	}
	if e := authorizeMutationBodyRole(i, r.URL.Path, input); e != nil {
		fail(w, e)
		return
	}
	sum := sha256.Sum256([]byte(i.Subject + "\n" + r.Method + "\n" + r.URL.Path + "\n" + string(body)))
	hash := hex.EncodeToString(sum[:])
	allocationReportRequest := r.URL.Path == "/v1/allocation-reports"
	fleetHistoryScopeRequest := r.URL.Path == "/v1/fleet-history-scopes"
	if allocationReportRequest || fleetHistoryScopeRequest {
		// Leave room inside the console's 30s and server's 40s deadlines.
		// Keep synchronous report work inside the normal response budget.
		ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
		defer cancel()
		r = r.WithContext(ctx)
	}
	status := 200
	var output model.Document
	e = fleetConfigurationTransaction(r.Context(), r.URL.Path, func(ctx context.Context) error {
		r := r.WithContext(ctx)
		status, output = 200, nil
		return a.Store.Do(ctx, i.Tenant, func(t *store.Tx) error {
			if e := authorizeMutationBodyRole(i, r.URL.Path, input); e != nil {
				return e
			}
			if e := t.Seed(r.Context(), a.Config.Fixture); e != nil {
				return e
			}
			if _, e := t.Exec(r.Context(), "INSERT INTO idempotency(tenant_id,key,request_hash) VALUES($1,$2,$3) ON CONFLICT DO NOTHING", i.Tenant, key, hash); e != nil {
				return e
			}
			var oldhash string
			var oldstatus *int
			var oldbody []byte
			if e := t.QueryRow(r.Context(), "SELECT request_hash,status,response FROM idempotency WHERE tenant_id=$1 AND key=$2 FOR UPDATE", i.Tenant, key).Scan(&oldhash, &oldstatus, &oldbody); e != nil {
				return e
			}
			if oldhash != hash {
				return problem(409, "IDEMPOTENCY_CONFLICT", "key already used for a different request")
			}
			if oldstatus != nil {
				if e := authorizeMutationReplay(r.Context(), t, i, r.URL.Path, input); e != nil {
					return e
				}
				status = *oldstatus
				return json.Unmarshal(oldbody, &output)
			}
			var e error
			output, status, e = a.mutate(r.Context(), t, i, r, input)
			if e != nil {
				return e
			}
			b, _ := json.Marshal(output)
			_, e = t.Exec(r.Context(), "UPDATE idempotency SET status=$3,response=$4 WHERE tenant_id=$1 AND key=$2", i.Tenant, key, status, b)
			return e
		})
	})
	if e != nil {
		if allocationReportRequest && errors.Is(r.Context().Err(), context.DeadlineExceeded) {
			e = problem(503, "ALLOCATION_REPORT_BUDGET_EXCEEDED", "report exceeded its synchronous request budget; retry with the same Idempotency-Key to reconcile the outcome")
		}
		if fleetHistoryScopeRequest && errors.Is(r.Context().Err(), context.DeadlineExceeded) {
			e = problem(503, "FLEET_HISTORY_REQUEST_BUDGET_EXCEEDED", "history evaluation exceeded its synchronous request budget; retry with the same Idempotency-Key to reconcile the outcome")
		}
		fail(w, e)
		return
	}
	if v := model.Number(output, "version"); v > 0 {
		w.Header().Set("ETag", fmt.Sprintf("\"%d\"", v))
	}
	JSON(w, status, output)
}
func (a *API) get(w http.ResponseWriter, r *http.Request, i auth.Identity) {
	var out any
	e := a.Store.Do(r.Context(), i.Tenant, func(t *store.Tx) error {
		if e := t.Seed(r.Context(), a.Config.Fixture); e != nil {
			return e
		}
		if result, handled, err := a.allocationGet(r.Context(), t, i, r); handled {
			out = result
			return err
		}
		if result, handled, err := a.commitmentDecisionGet(r.Context(), t, i, r); handled {
			out = result
			return err
		}
		if result, handled, err := a.fleetCapacityGet(r.Context(), t, i, r); handled {
			out = result
			return err
		}
		if result, handled, err := a.fleetNativeAssessmentGet(r.Context(), t, i, r); handled {
			out = result
			return err
		}
		if result, handled, err := a.fleetJointDecisionGet(r.Context(), t, i, r); handled {
			out = result
			return err
		}
		if result, handled, err := a.fleetGroupAuthorityGet(r.Context(), t, i, r); handled {
			out = result
			return err
		}
		if result, handled, err := a.fleetFixtureGet(r.Context(), t, i, r); handled {
			out = result
			return err
		}
		if result, handled, err := a.fleetConfigurationGet(r.Context(), t, i, r); handled {
			out = result
			return err
		}
		if result, handled, err := a.fleetHistoryGet(r.Context(), t, i, r); handled {
			out = result
			return err
		}
		if result, handled, err := a.configurationGet(r.Context(), t, i, r); handled {
			out = result
			return err
		}
		if result, handled, err := a.capacityGet(r.Context(), t, i, r); handled {
			out = result
			return err
		}
		if result, handled, err := a.workloadSafetyGet(r.Context(), t, i, r); handled {
			out = result
			return err
		}
		if result, handled, err := a.telemetryGet(r.Context(), t, i, r); handled {
			out = result
			return err
		}
		if result,handled,err:=a.objectStorageAccessGet(r.Context(),t,i,r);handled{out=result;return err}
		if result, handled, err := a.objectStorageGet(r.Context(), t, i, r); handled {
			out = result
			return err
		}
		if result, handled, err := a.storageGet(r.Context(), t, i, r); handled {
			out = result
			return err
		}
		if result, handled, err := a.databaseGet(r.Context(), t, i, r); handled {
			out = result
			return err
		}
		if r.URL.Path == "/v1/dashboard" {
			d := model.Document{"fixture": a.Config.Fixture}
			org, e := t.Get(r.Context(), "org", i.Tenant)
			if e != nil {
				return e
			}
			d["org"] = org
			readinessRows, e := t.EvidenceList(r.Context(), "readiness", "")
			if e != nil {
				return e
			}
			latest := map[string]model.Document{}
			for _, row := range readinessRows {
				latest[model.String(row, "resource_id")] = row
			}
			reports := []model.Document{}
			for _, row := range latest {
				reports = append(reports, row)
			}
			d["readiness"] = reports
			connections, err := t.SourceList(r.Context())
			if err != nil {
				return err
			}
			d["source_connections"] = connections
			collectors, err := activitySources(r.Context(), t)
			if err != nil {
				return err
			}
			d["activity_sources"] = collectors
			for _, k := range []string{"cloud_accounts", "resources", "workloads", "recommendations", "policies", "schedules", "change_plans", "executions", "data_quality"} {
				rows, e := t.List(r.Context(), k)
				if e != nil {
					return e
				}
				d[k] = rows
			}
			databaseRows, err := a.databaseRecommendations(r.Context(), t)
			if err != nil {
				return err
			}
			d["recommendations"] = append(d["recommendations"].([]model.Document), databaseRows...)
			storageRows, err := a.storageRecommendations(r.Context(), t)
			if err != nil {
				return err
			}
			d["recommendations"] = append(d["recommendations"].([]model.Document), storageRows...)
			if _, e := t.Exec(r.Context(), "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", t.Tenant+":dependency-graph"); e != nil {
				return e
			}
			if _, _, e := reconcileSLOClaims(r.Context(), t); e != nil {
				return e
			}
			for k, table := range map[string]string{"audit": "audit_events", "savings": "savings_ledger"} {
				rows, e := t.Evidence(r.Context(), table)
				if e != nil {
					return e
				}
				d[k] = rows
			}
			graph, err := dependencyGraph(r.Context(), t)
			if err != nil {
				return err
			}
			d["dependency_graph"] = graph
			objectives, err := t.SLOObjectives(r.Context())
			if err != nil {
				return err
			}
			d["slo_objectives"] = objectives
			sloSources, err := t.SLOSources(r.Context())
			if err != nil {
				return err
			}
			d["slo_sources"] = sloSources
			sloStates := []model.Document{}
			resources, err := t.List(r.Context(), "resources")
			if err != nil {
				return err
			}
			for _, res := range resources {
				state, err := currentSLO(r.Context(), t, res, nil, true, time.Time{}, time.Time{})
				if err != nil {
					return err
				}
				sloStates = append(sloStates, state)
			}
			d["slo_evaluations"] = sloStates
			restrictDashboard(i, d)
			out = d
			return nil
		}
		if scopedOwner(i) {
			return problem(403, "WORKLOAD_SCOPE_DENIED", "application owners use the scoped dashboard")
		}
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/v1/"), "/")
		if len(parts) == 3 && parts[0] == "workloads" && parts[2] == "slo-objectives" {
			d, e := sloObjectiveHistory(r.Context(), t, parts[1])
			out = d
			if e == nil {
				w.Header().Set("ETag", fmt.Sprintf("\"%d\"", model.Number(d, "version")))
			}
			return e
		}
		if len(parts) == 1 && parts[0] == "slo-sources" {
			d, e := t.SLOSources(r.Context())
			out = d
			return e
		}
		if len(parts) == 3 && parts[0] == "resources" && parts[2] == "slo-evaluation" {
			res, e := t.Get(r.Context(), "resources", parts[1])
			if e != nil {
				return e
			}
			d, e := currentSLO(r.Context(), t, res, nil, true, time.Time{}, time.Time{})
			out = d
			return e
		}
		if len(parts) == 1 && parts[0] == "resource-graph" {
			d, e := dependencyGraph(r.Context(), t)
			out = d
			if e == nil {
				w.Header().Set("ETag", fmt.Sprintf("\"%d\"", model.Number(d, "version")))
			}
			return e
		}
		if len(parts) == 3 && parts[0] == "resources" && parts[2] == "dependency-reviews" {
			d, e := dependencyReviews(r.Context(), t, parts[1], time.Now())
			out = d
			return e
		}
		if len(parts) == 1 && parts[0] == "activity-sources" {
			d, err := activitySources(r.Context(), t)
			out = d
			return err
		}
		if d, handled, err := sourceGet(r.Context(), t, r.URL.Path); handled {
			out = d
			return err
		}
		if len(parts) == 3 && parts[0] == "resources" && parts[2] == "readiness" {
			d, err := a.readiness(r.Context(), t, parts[1], false)
			out = d
			return err
		}
		kind := strings.ReplaceAll(parts[0], "-", "_")
		allowed := map[string]bool{"cloud_accounts": true, "resources": true, "workloads": true, "recommendations": true, "policies": true, "schedules": true, "change_plans": true, "executions": true, "approvals": true, "data_quality": true}
		if !allowed[kind] {
			return problem(404, "NOT_FOUND", "unknown API resource")
		}
		if len(parts) == 2 {
			d, e := t.Get(r.Context(), kind, parts[1])
			if e != nil {
				return e
			}
			out = d
			w.Header().Set("ETag", fmt.Sprintf("\"%d\"", model.Number(d, "version")))
			return nil
		}
		rows, e := t.List(r.Context(), kind)
		if e == nil && kind == "recommendations" {
			var dbRows []model.Document
			dbRows, e = a.databaseRecommendations(r.Context(), t)
			rows = append(rows, dbRows...)
			if e == nil {
				var storageRows []model.Document
				storageRows, e = a.storageRecommendations(r.Context(), t)
				rows = append(rows, storageRows...)
			}
		}
		out = rows
		return e
	})
	if e != nil {
		fail(w, e)
		return
	}
	if d, ok := out.(model.Document); ok && model.Number(d, "version") > 0 {
		w.Header().Set("ETag", fmt.Sprintf("\"%d\"", model.Number(d, "version")))
	}
	JSON(w, 200, out)
}
func requireRole(i auth.Identity, roles ...string) error {
	if !i.Can(roles...) {
		return problem(403, "FORBIDDEN", "your role cannot perform this operation")
	}
	return nil
}
func match(r *http.Request, d model.Document) error {
	h := strings.Trim(r.Header.Get("If-Match"), "\"")
	if h == "" {
		return problem(428, "IF_MATCH_REQUIRED", "provide current resource ETag in If-Match")
	}
	v, e := strconv.ParseInt(h, 10, 64)
	if e != nil || v != model.Number(d, "version") {
		return store.ErrConflict
	}
	return nil
}
func (a *API) mutate(ctx context.Context, t *store.Tx, i auth.Identity, r *http.Request, in model.Document) (model.Document, int, error) {
	path := strings.TrimPrefix(r.URL.Path, "/v1/")
	parts := strings.Split(path, "/")
	if out, status, handled, err := a.allocationMutate(ctx, t, i, r, in, parts); handled {
		return out, status, err
	}
	if out, status, handled, err := a.commitmentDecisionMutate(ctx, t, i, r, in, parts); handled {
		return out, status, err
	}
	if out, status, handled, err := a.fleetCapacityMutate(ctx, t, i, r, in, parts); handled {
		return out, status, err
	}
	if out, status, handled, err := a.fleetNativeAssessmentMutate(ctx, t, i, r, in, parts); handled {
		return out, status, err
	}
	if out, status, handled, err := a.fleetJointDecisionMutate(ctx, t, i, r, in, parts); handled {
		return out, status, err
	}
	if out, status, handled, err := a.fleetGroupAuthorityMutate(ctx, t, i, r, in, parts); handled {
		return out, status, err
	}
	if out, status, handled, err := a.fleetFixtureMutate(ctx, t, i, r, in, parts); handled {
		return out, status, err
	}
	if out, status, handled, err := a.fleetConfigurationMutate(ctx, t, i, r, in, parts); handled {
		return out, status, err
	}
	if out, status, handled, err := a.fleetHistoryMutate(ctx, t, i, r, in, parts); handled {
		return out, status, err
	}
	if out, status, handled, err := a.configurationMutate(ctx, t, i, r, in, parts); handled {
		return out, status, err
	}
	if out, status, handled, err := a.capacityMutate(ctx, t, i, r, in, parts); handled {
		return out, status, err
	}
	if out, status, handled, err := a.workloadSafetyMutate(ctx, t, i, r, in, parts); handled {
		return out, status, err
	}
	if out, status, handled, err := a.telemetryMutate(ctx, t, i, r, in, parts); handled {
		return out, status, err
	}
	switch path {
	case "cloud-accounts":
		if e := requireRole(i, "PLATFORM_ADMIN"); e != nil {
			return nil, 0, e
		}
		if model.String(in, "provider") != "AWS" {
			return nil, 0, problem(422, "UNSUPPORTED_PROVIDER", "this pilot supports AWS only")
		}
		if !a.Config.Fixture {
			if e := ValidateAWSTenant(i.Tenant); e != nil {
				return nil, 0, e
			}
		}
		region := model.String(in, "region")
		if region == "" {
			region = a.Config.AWSRegion
		}
		account := model.String(in, "account_id")
		if account == "" && a.Config.Fixture {
			account = "111122223333"
		}
		if len(account) != 12 {
			return nil, 0, problem(422, "INVALID_ACCOUNT", "AWS account_id must contain 12 digits")
		}
		for _, c := range account {
			if c < '0' || c > '9' {
				return nil, 0, problem(422, "INVALID_ACCOUNT", "AWS account_id must contain 12 digits")
			}
		}
		status := "CONNECTED"
		if !a.Config.Fixture {
			status = "DISCOVERY_PENDING"
		}
		d, e := t.Create(ctx, "cloud_accounts", model.Document{"provider": "AWS", "name": model.String(in, "name"), "account_id": account, "region": region, "status": status, "fixture": a.Config.Fixture, "last_synced_at": model.Now()})
		if e != nil {
			return nil, 0, e
		}
		if !a.Config.Fixture {
			if _, e = t.Create(ctx, "discovery_jobs", model.Document{"cloud_account_id": d["id"], "status": "PENDING", "created_at": model.Now()}); e != nil {
				return nil, 0, e
			}
		}
		_ = t.Audit(ctx, i.Subject, "cloud_account.connected", model.String(d, "id"), d)
		return d, 201, nil
	case "recommendations":
		if e := requireRole(i, "FINOPS_ADMIN", "PLATFORM_ADMIN"); e != nil {
			return nil, 0, e
		}
		resources, e := t.List(ctx, "resources")
		if e != nil {
			return nil, 0, e
		}
		created := []model.Document{}
		for _, res := range resources {
			if databaseResource(res) || storageResource(res) {
				continue
			}
			wid := model.String(res, "workload_id")
			if filter := model.String(in, "workload_id"); filter != "" && filter != wid {
				continue
			}
			if wid == "" {
				continue
			}
			ready, e := a.readiness(ctx, t, model.String(res, "id"), true)
			if e != nil {
				return nil, 0, e
			}
			status := "BLOCKED"
			confidence := "LOW"
			if model.Bool(ready, "pre_execution_ready") {
				status = "VALIDATED"
				confidence = "HIGH"
			}
			econ := evidence.Object(ready["economics"])
			d, e := t.Create(ctx, "recommendations", model.Document{"workload_id": wid, "resource_id": res["id"], "title": "Schedule idle non-production EC2 off hours", "category": "NON_PRODUCTION_SCHEDULING", "risk_class": "R1", "status": status, "reason_code": ready["reason_code"], "blockers": ready["blockers"], "pre_execution_ready": ready["pre_execution_ready"], "readiness_id": ready["id"], "baseline_id": ready["baseline_id"], "measurement_id": ready["measurement_id"], "verification_status": ready["verification_status"], "readiness_status": ready["status"], "monthly_saving": nil, "annual_saving": econ["annualised_estimate"], "currency": res["currency"], "confidence": confidence, "evidence": "Immutable source-bound baseline; financial verification requires post-activation evidence.", "economics": econ, "created_at": model.Now(), "expires_at": time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339), "fixture": a.Config.Fixture})
			if e != nil {
				return nil, 0, e
			}
			created = append(created, d)
			_ = t.Event(ctx, "recommendation.created", d)
		}
		_ = t.Audit(ctx, i.Subject, "recommendations.generated", i.Tenant, model.Document{"count": len(created)})
		return model.Document{"recommendations": created}, 201, nil
	case "schedules":
		if wid := model.String(in, "workload_id"); wid != "" {
			w, e := t.Get(ctx, "workloads", wid)
			if e != nil {
				return nil, 0, e
			}
			if model.Bool(w, "observation_only") {
				return nil, 0, problem(422, "OBSERVATION_ONLY_WORKLOAD", "this workload is registered for read-only assessment")
			}
		}
		if e := requireRole(i, "PLATFORM_ADMIN", "APPLICATION_OWNER"); e != nil {
			return nil, 0, e
		}
		wid := model.String(in, "workload_id")
		w, e := t.Get(ctx, "workloads", wid)
		if e != nil {
			return nil, 0, e
		}
		if e = workloadAccess(i, w); e != nil {
			return nil, 0, e
		}
		if model.String(w, "environment") != "NON_PRODUCTION" {
			return nil, 0, problem(422, "BLOCKED_PRODUCTION", "schedules support explicit non-production workloads only")
		}
		if !model.Bool(in, "memory_state_acknowledged") || !model.Bool(in, "public_ip_change_acknowledged") {
			return nil, 0, problem(422, "ACKNOWLEDGEMENT_REQUIRED", "acknowledge loss of in-memory state and network identity implications")
		}
		if e = validateSchedule(in); e != nil {
			return nil, 0, e
		}
		mode := model.String(in, "mode")
		if mode == "" {
			in["mode"] = "RECOMMEND"
			if a.Config.Fixture {
				in["mode"] = "ASSISTED_EXECUTION"
			}
		}
		if mode == "AUTOPILOT" && (!model.Bool(in, "autopilot_opt_in") || !i.Can("PLATFORM_ADMIN")) {
			return nil, 0, problem(422, "EXPLICIT_AUTOPILOT_REQUIRED", "Autopilot requires platform-admin opt-in")
		}
		if mode != "" && mode != "AUTOPILOT" && mode != "ASSISTED_EXECUTION" && mode != "OBSERVE" && mode != "RECOMMEND" && mode != "FROZEN" {
			return nil, 0, problem(422, "INVALID_MODE", "invalid schedule execution mode")
		}
		if mode == "AUTOPILOT" {
			p, e := t.Get(ctx, "policies", "policy-default")
			if e != nil {
				return nil, 0, e
			}
			allowed := false
			for _, id := range model.Strings(p, "workload_autopilot_ids") {
				if id == wid {
					allowed = true
				}
			}
			if !allowed {
				return nil, 0, problem(422, "AUTOPILOT_POLICY_REQUIRED", "policy must explicitly allow scheduling Autopilot for this workload")
			}
		}
		in["paused"], in["skip_next_stop"], in["approved_by"] = false, false, i.Subject
		if mode == "AUTOPILOT" {
			in["autopilot_expires_at"] = time.Now().Add(30 * 24 * time.Hour).UTC().Format(time.RFC3339)
		}
		d, e := t.Create(ctx, "schedules", in)
		if e == nil {
			e = t.Audit(ctx, i.Subject, "schedule.created", model.String(d, "id"), d)
		}
		return d, 201, e
	case "change-plans":
		if e := requireRole(i, "PLATFORM_ADMIN", "FINOPS_ADMIN"); e != nil {
			return nil, 0, e
		}
		if !model.Bool(in, "memory_state_acknowledged") || !model.Bool(in, "public_ip_change_acknowledged") {
			return nil, 0, problem(422, "ACKNOWLEDGEMENT_REQUIRED", "acknowledge memory-state loss and possible public-IP change")
		}
		d, e := BuildPlan(ctx, t, model.String(in, "recommendation_id"), model.String(in, "schedule_id"), a.Config.Fixture)
		if e == nil {
			e = t.Audit(ctx, i.Subject, "change_plan.created", model.String(d, "id"), d)
		}
		return d, 201, e
	case "approvals":
		if e := requireRole(i, "APPROVER", "PLATFORM_ADMIN"); e != nil {
			return nil, 0, e
		}
		plan, e := t.Get(ctx, "change_plans", model.String(in, "change_plan_id"))
		if e != nil {
			return nil, 0, e
		}
		w, e := t.Get(ctx, "workloads", model.String(plan, "workload_id"))
		if e != nil {
			return nil, 0, e
		}
		if e = workloadAccess(i, w); e != nil {
			return nil, 0, e
		}
		if e = match(r, plan); e != nil {
			return nil, 0, e
		}
		if model.String(plan, "status") != "AWAITING_APPROVAL" {
			return nil, 0, problem(409, "INVALID_STATE", "plan is not awaiting approval")
		}
		payload := model.Clone(plan)
		plan["status"] = "APPROVED"
		plan, e = t.Update(ctx, "change_plans", model.String(plan, "id"), model.Number(plan, "version"), plan)
		if e != nil {
			return nil, 0, e
		}
		approval, e := t.Create(ctx, "approvals", model.Document{"change_plan_id": plan["id"], "approved_by": i.Subject, "approved_at": model.Now(), "policy_version": plan["policy_version"], "payload": payload})
		if e == nil {
			_ = t.Audit(ctx, i.Subject, "approval.completed", model.String(plan, "id"), approval)
			_ = t.Event(ctx, "approval.completed", approval)
		}
		return model.Document{"approval": approval, "change_plan": plan, "id": plan["id"], "version": plan["version"]}, 201, e
	case "executions":
		if e := requireRole(i, "PLATFORM_ADMIN"); e != nil {
			return nil, 0, e
		}
		p, e := t.Get(ctx, "change_plans", model.String(in, "change_plan_id"))
		if e != nil {
			return nil, 0, e
		}
		if _, e = t.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", t.Tenant+":plan:"+model.String(p, "id")); e != nil {
			return nil, 0, e
		}
		if e = match(r, p); e != nil {
			return nil, 0, e
		}
		if model.String(p, "status") != "APPROVED" {
			return nil, 0, problem(409, "APPROVAL_REQUIRED", "approve this exact plan first")
		}
		parsed, e := decodePlan(p)
		if e != nil {
			return nil, 0, e
		}
		res, e := t.Get(ctx, "resources", model.String(p, "resource_id"))
		if e != nil {
			return nil, 0, e
		}
		if e = readinessPlanCheck(ctx, t, parsed, res); e != nil {
			return nil, 0, e
		}
		existing, e := t.List(ctx, "executions")
		if e != nil {
			return nil, 0, e
		}
		for _, x := range existing {
			if model.String(x, "change_plan_id") == model.String(p, "id") {
				return nil, 0, problem(409, "ALREADY_EXECUTED", "this immutable plan already has an execution")
			}
		}
		d, e := t.Create(ctx, "executions", model.Document{"change_plan_id": p["id"], "resource_id": p["resource_id"], "workload_id": p["workload_id"], "schedule_id": p["schedule_id"], "status": "QUEUED", "stage": "PRECHECK", "created_at": model.Now(), "restoration_owned": false})
		if e == nil {
			_ = t.Audit(ctx, i.Subject, "execution.queued", model.String(d, "id"), d)
			_ = t.Event(ctx, "execution.started", d)
		}
		return d, 202, e
	case "control/pause":
		if e := requireRole(i, "PLATFORM_ADMIN"); e != nil {
			return nil, 0, e
		}
		if e := lockSchedulingControl(ctx, t, false); e != nil {
			return nil, 0, e
		}
		d, e := t.Get(ctx, "org", i.Tenant)
		if e != nil {
			return nil, 0, e
		}
		if e = match(r, d); e != nil {
			return nil, 0, e
		}
		d["paused"] = model.Bool(in, "paused")
		d, e = t.Update(ctx, "org", i.Tenant, model.Number(d, "version"), d)
		if e == nil {
			e = t.Audit(ctx, i.Subject, "autopilot.pause_changed", i.Tenant, d)
		}
		return d, 200, e
	case "savings/verify":
		if e := requireRole(i, "FINOPS_ADMIN", "FINANCE", "PLATFORM_ADMIN"); e != nil {
			return nil, 0, e
		}
		return a.verifySavings(ctx, t, i, in)
	case "demo/reset":
		if !a.Config.Fixture {
			return nil, 0, problem(404, "NOT_FOUND", "fixture reset is unavailable in AWS mode")
		}
		if e := requireRole(i, "PLATFORM_ADMIN"); e != nil {
			return nil, 0, e
		}
		rows, e := t.List(ctx, "executions")
		if e != nil {
			return nil, 0, e
		}
		for _, x := range rows {
			if s := model.String(x, "status"); s != "COMPLETED" && s != "FAILED" && s != "SKIPPED" {
				return nil, 0, problem(409, "EXECUTION_ACTIVE", "complete restoration before resetting the demo")
			}
		}
		_, e = t.Exec(ctx, "DELETE FROM entities WHERE tenant_id=$1 AND kind NOT IN ('ingestion_jobs','audit_archives')", t.Tenant)
		if e != nil {
			return nil, 0, e
		}
		if e = t.Seed(ctx, true); e != nil {
			return nil, 0, e
		}
		_ = t.Audit(ctx, i.Subject, "fixture.reset", i.Tenant, nil)
		return model.Document{"reset": true, "audit_preserved": true, "ledger_preserved": true}, 200, nil
	case "demo/scenario":
		if !a.Config.Fixture {
			return nil, 0, problem(404, "NOT_FOUND", "fixture scenarios are unavailable in AWS mode")
		}
		if e := requireRole(i, "PLATFORM_ADMIN"); e != nil {
			return nil, 0, e
		}
		w, e := t.Get(ctx, "workloads", "workload-dev")
		if e != nil {
			return nil, 0, e
		}
		w["incident"], w["deployment"], w["job"], w["signals_at"], w["fixture_unhealthy"] = "CLEAR", "CLEAR", "CLEAR", model.Now(), false
		switch model.String(in, "scenario") {
		case "incident":
			w["incident"] = "ACTIVE"
		case "job":
			w["job"] = "ACTIVE"
		case "deployment":
			w["deployment"] = "ACTIVE"
		case "stale":
			w["signals_at"] = time.Now().Add(-10 * time.Minute).UTC().Format(time.RFC3339)
		case "unhealthy":
			w["fixture_unhealthy"] = true
		case "healthy":
		default:
			return nil, 0, problem(422, "UNKNOWN_SCENARIO", "unknown fixture scenario")
		}
		w, e = t.Update(ctx, "workloads", "workload-dev", model.Number(w, "version"), w)
		if e == nil {
			e = t.Audit(ctx, i.Subject, "fixture.scenario_changed", "workload-dev", in)
		}
		return w, 200, e
	}
	if out, status, handled, e := a.extraMutate(ctx, t, i, r, in); handled {
		return out, status, e
	}
	if len(parts) == 3 && parts[0] == "schedules" && (parts[2] == "pause" || parts[2] == "skip-next-stop") {
		if e := requireRole(i, "PLATFORM_ADMIN", "APPLICATION_OWNER"); e != nil {
			return nil, 0, e
		}
		if e := lockSchedulingControl(ctx, t, false); e != nil {
			return nil, 0, e
		}
		d, e := t.Get(ctx, "schedules", parts[1])
		if e != nil {
			return nil, 0, e
		}
		workload, e := t.Get(ctx, "workloads", model.String(d, "workload_id"))
		if e != nil {
			return nil, 0, e
		}
		if e = workloadAccess(i, workload); e != nil {
			return nil, 0, e
		}
		if e = match(r, d); e != nil {
			return nil, 0, e
		}
		if parts[2] == "pause" {
			d["paused"] = model.Bool(in, "paused")
		} else {
			bound, err := bindCurrentScheduleSkip(ctx, t, i.Subject, d, a.now())
			if err != nil {
				return nil, 0, err
			}
			d["skip_next_stop"] = !bound
		}
		d, e = t.Update(ctx, "schedules", parts[1], model.Number(d, "version"), d)
		if e == nil {
			e = t.Audit(ctx, i.Subject, "schedule."+parts[2], parts[1], d)
		}
		return d, 200, e
	}
	if len(parts) == 3 && parts[0] == "workloads" && parts[2] == "signals" {
		if e := requireRole(i, "PLATFORM_ADMIN", "APPLICATION_OWNER"); e != nil {
			return nil, 0, e
		}
		d, e := t.Get(ctx, "workloads", parts[1])
		if e != nil {
			return nil, 0, e
		}
		if e = workloadAccess(i, d); e != nil {
			return nil, 0, e
		}
		if e = match(r, d); e != nil {
			return nil, 0, e
		}
		for _, k := range []string{"incident", "deployment", "job"} {
			s := model.String(in, k)
			if s != "CLEAR" && s != "ACTIVE" && s != "UNKNOWN" {
				return nil, 0, problem(422, "INVALID_SIGNAL", "signals must be CLEAR, ACTIVE or UNKNOWN")
			}
			d[k] = s
		}
		d["signals_at"] = model.Now()
		d, e = t.Update(ctx, "workloads", parts[1], model.Number(d, "version"), d)
		if e == nil {
			e = t.Audit(ctx, i.Subject, "workload.signals_updated", parts[1], in)
		}
		return d, 200, e
	}
	if len(parts) == 3 && parts[0] == "executions" && parts[2] == "start-now" {
		if e := requireRole(i, "PLATFORM_ADMIN", "APPLICATION_OWNER"); e != nil {
			return nil, 0, e
		}
		if e := lockExecutionControl(ctx, t, parts[1]); e != nil {
			return nil, 0, e
		}
		d, e := t.Get(ctx, "executions", parts[1])
		if e != nil {
			return nil, 0, e
		}
		workload, e := t.Get(ctx, "workloads", model.String(d, "workload_id"))
		if e != nil {
			return nil, 0, e
		}
		if e = workloadAccess(i, workload); e != nil {
			return nil, 0, e
		}
		if e = match(r, d); e != nil {
			return nil, 0, e
		}
		d["start_now"] = true
		d, e = t.Update(ctx, "executions", parts[1], model.Number(d, "version"), d)
		if e == nil {
			e = t.Audit(ctx, i.Subject, "execution.restoration_requested", parts[1], nil)
		}
		return d, 202, e
	}
	return nil, 0, problem(404, "NOT_FOUND", "route not found")
}
func valueOr(d model.Document, k string, def any) any {
	if v, ok := d[k]; ok && v != nil {
		return v
	}
	return def
}
func validateSchedule(d model.Document) error {
	var days []int
	if values, ok := d["days"].([]any); ok {
		for _, x := range values {
			f, ok := x.(float64)
			if !ok || f != float64(int(f)) {
				return problem(422, "INVALID_SCHEDULE", "days must be ISO weekdays")
			}
			days = append(days, int(f))
		}
	}
	_, _, e := safety.NextWindow(time.Now(), model.String(d, "timezone"), model.String(d, "stop_time"), model.String(d, "ready_time"), days)
	if e != nil {
		return problem(422, "INVALID_SCHEDULE", e.Error())
	}
	return nil
}
