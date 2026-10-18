package service

import (
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/provider"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/safety"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/jackc/pgx/v5"
)

type SecureService struct {
	Store   *store.Store
	Config  Config
	Private ed25519.PrivateKey
	Public  ed25519.PublicKey
}

func (s *SecureService) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			if e := s.Store.Pool.Ping(r.Context()); e != nil {
				JSON(w, 503, model.Document{"status": "degraded"})
				return
			}
			JSON(w, 200, model.Document{"status": "ok", "role": s.Config.Role})
			return
		}
		secret := s.Config.ExecutorToken
		if s.Config.Role == "signer" {
			secret = s.Config.SignerToken
		}
		provided := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if secret == "" || subtle.ConstantTimeCompare([]byte(secret), []byte(provided)) != 1 {
			fail(w, problem(401, "UNAUTHORIZED", "service authentication required"))
			return
		}
		if r.Method != "POST" {
			fail(w, problem(405, "METHOD_NOT_ALLOWED", "use POST"))
			return
		}
		if s.Config.Role == "signer" && r.URL.Path == "/sign" {
			var in struct {
				TenantID    string `json:"tenant_id"`
				PlanID      string `json:"plan_id"`
				ExecutionID string `json:"execution_id"`
			}
			if e := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); e != nil {
				fail(w, problem(400, "INVALID_JSON", "invalid signing request"))
				return
			}
			var out model.Envelope
			e := s.Store.Do(r.Context(), in.TenantID, func(t *store.Tx) error {
				d, e := t.Get(r.Context(), "change_plans", in.PlanID)
				if e != nil {
					return e
				}
				p, e := decodePlan(d)
				if e != nil {
					return e
				}
				if p.Fixture != s.Config.Fixture {
					return problem(422, "MODE_MISMATCH", "plan mode differs from signing service mode")
				}
				if e = validateApproval(r.Context(), t, d, p); e != nil {
					return e
				}
				execution, e := t.Get(r.Context(), "executions", in.ExecutionID)
				if e != nil {
					return e
				}
				if model.String(execution, "change_plan_id") != p.ID {
					return problem(422, "EXECUTION_MISMATCH", "execution plan mismatch")
				}
				if e = precheck(r.Context(), t, p, time.Now()); e != nil {
					return e
				}
				var b []byte
				e = t.QueryRow(r.Context(), "SELECT envelope FROM signed_plans WHERE tenant_id=$1 AND plan_id=$2", t.Tenant, p.ID).Scan(&b)
				if e == nil {
					return json.Unmarshal(b, &out)
				}
				if e != pgx.ErrNoRows {
					return e
				}
				out, e = safety.Sign(p, s.Private)
				if e != nil {
					return e
				}
				b, _ = json.Marshal(out)
				if _, e = t.Exec(r.Context(), "INSERT INTO signed_plans(tenant_id,plan_id,nonce,envelope) VALUES($1,$2,$3,$4)", t.Tenant, p.ID, p.Nonce, b); e != nil {
					return e
				}
				return t.Audit(r.Context(), "signer", "change_plan.signed", p.ID, model.Document{"nonce": p.Nonce, "algorithm": "Ed25519"})
			})
			if e != nil {
				fail(w, e)
				return
			}
			JSON(w, 200, out)
			return
		}
		if s.Config.Role == "executor" && r.URL.Path == "/dispatch" {
			var in model.Dispatch
			if e := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); e != nil {
				fail(w, problem(400, "INVALID_JSON", "invalid dispatch"))
				return
			}
			out, e := s.dispatch(r.Context(), in)
			if e != nil {
				fail(w, e)
				return
			}
			JSON(w, 200, out)
			return
		}
		fail(w, problem(404, "NOT_FOUND", "unknown service route"))
	})
}
func validateApproval(ctx context.Context, t *store.Tx, d model.Document, p model.Plan) error {
	if p.TenantID != t.Tenant || p.ID != model.String(d, "id") {
		return problem(422, "PLAN_BINDING_INVALID", "invalid plan identity")
	}
	if model.String(d, "status") != "APPROVED" {
		return problem(422, "APPROVAL_REQUIRED", "immutable plan requires approval")
	}
	approvals, e := t.List(ctx, "approvals")
	if e != nil {
		return e
	}
	for _, a := range approvals {
		if model.String(a, "change_plan_id") == p.ID {
			var writer string
			if e = t.QueryRow(ctx, "SELECT writer_role FROM entities WHERE tenant_id=$1 AND kind='approvals' AND id=$2", t.Tenant, model.String(a, "id")).Scan(&writer); e != nil {
				return e
			}
			policyApproval := strings.HasPrefix(model.String(a, "approved_by"), "policy:")
			if !policyApproval && writer != "finops_api" {
				continue
			}
			if policyApproval {
				if writer != "finops_worker" && writer != "finops_api" {
					continue
				}
				schedule, e := t.Get(ctx, "schedules", p.ScheduleID)
				if e != nil {
					return e
				}
				if model.String(schedule, "mode") != "AUTOPILOT" || !model.Bool(schedule, "autopilot_opt_in") {
					continue
				}
			}
			var original model.Document
			b, _ := json.Marshal(a["payload"])
			_ = json.Unmarshal(b, &original)
			o, e := decodePlan(original)
			if e != nil {
				return e
			}
			current, _ := json.Marshal(p)
			approved, _ := json.Marshal(o)
			if string(current) == string(approved) {
				return nil
			}
		}
	}
	return problem(422, "APPROVAL_INVALID", "approval does not match immutable payload")
}
func precheck(ctx context.Context, t *store.Tx, p model.Plan, now time.Time) error {
	if p.TenantID != t.Tenant || len(p.Operations) != 2 {
		return problem(422, "PLAN_BINDING_INVALID", "invalid target binding")
	}
	if p.RiskClass != "R1" {
		return problem(422, "RISK_CLASS_INVALID", "this executor supports R1 scheduling only")
	}
	if !now.Before(p.ExpiresAt) {
		return problem(422, "PLAN_EXPIRED", "plan expired")
	}
	if p.StopAt.IsZero() || now.Before(p.StopAt) || !now.Before(p.StopAt.Add(15*time.Minute)) {
		return problem(422, "OUTSIDE_STOP_WINDOW", "stop is outside the signed occurrence window")
	}
	org, e := t.Get(ctx, "org", t.Tenant)
	if e != nil {
		return e
	}
	if model.Bool(org, "paused") {
		return problem(422, "BLOCKED_AUTOPILOT_PAUSED", "organisation is paused")
	}
	policy, e := t.Get(ctx, "policies", p.PolicyID)
	if e != nil {
		return e
	}
	if model.Number(policy, "version") != p.PolicyVersion {
		return problem(422, "POLICY_VERSION_CHANGED", "policy changed since planning")
	}
	res, e := t.Get(ctx, "resources", p.Operations[0].ResourceID)
	if e != nil {
		return e
	}
	if e = readinessPlanCheck(ctx, t, p, res); e != nil {
		return e
	}
	stale := p.ResourceSnapshotHash == "" && model.Number(res, "version") != p.ResourceVersion || p.ResourceSnapshotHash != "" && safety.SnapshotHash(res) != p.ResourceSnapshotHash
	if stale || model.String(res, "provider_resource_id") != p.Operations[0].ProviderResourceID {
		return problem(422, "STALE_RECOMMENDATION", "resource changed since planning")
	}
	if model.String(res, "workload_id") != p.WorkloadID || model.String(res, "account_id") != p.Operations[0].AccountID || model.String(res, "region") != p.Operations[0].Region {
		return problem(422, "TARGET_BINDING_INVALID", "resource, workload, region and account must match the plan")
	}
	res["commitment_known"], res["uncovered_on_demand"], res["observation_days"] = true, true, 14
	w, e := t.Get(ctx, "workloads", p.WorkloadID)
	if e != nil {
		return e
	}
	if p.SchemaVersion == "3" {
		w, e = trustedWorkload(ctx, t, res, w)
		if e != nil {
			return evidenceProblem(e)
		}
	}
	if blocked := safety.Eligibility(res, w, policy, now); len(blocked) > 0 {
		return problem(422, blocked[0], "stop precondition failed")
	}
	schedule, e := t.Get(ctx, "schedules", p.ScheduleID)
	if e != nil {
		return e
	}
	if model.String(schedule, "workload_id") != p.WorkloadID {
		return problem(422, "SCHEDULE_BINDING_INVALID", "schedule must own the target workload")
	}
	if model.Bool(schedule, "paused") || model.Bool(schedule, "skip_next_stop") {
		return problem(422, "BLOCKED_SCHEDULE_PAUSED", "schedule paused or next stop skipped")
	}
	mode := model.String(schedule, "mode")
	if mode != "ASSISTED_EXECUTION" && mode != "AUTOPILOT" {
		return problem(422, "BLOCKED_EXECUTION_MODE", "schedule mode prohibits stop")
	}
	if mode == "AUTOPILOT" {
		allowed := false
		for _, id := range model.Strings(policy, "workload_autopilot_ids") {
			if id == p.WorkloadID {
				allowed = true
			}
		}
		for _, doc := range []model.Document{schedule, policy} {
			expiry, e := time.Parse(time.RFC3339, model.String(doc, "autopilot_expires_at"))
			if e != nil || !now.Before(expiry) {
				return problem(422, "AUTOPILOT_APPROVAL_EXPIRED", "temporary Autopilot authority expired")
			}
		}
		if !allowed || !model.Bool(schedule, "autopilot_opt_in") {
			return problem(422, "AUTOPILOT_POLICY_REQUIRED", "workload Autopilot is not explicitly allowed")
		}
	}
	return nil
}
func (s *SecureService) dispatch(ctx context.Context, in model.Dispatch) (model.ProviderState, error) {
	var out model.ProviderState
	p := in.Envelope.Plan
	restoring := in.Operation == "START" || in.Operation == "DESCRIBE" || in.Operation == "HEALTH"
	if in.Operation != "STOP" && !restoring {
		return out, problem(422, "OPERATION_NOT_ALLOWED", "only STOP, START, DESCRIBE and HEALTH allowed")
	}
	if e := safety.Verify(in.Envelope, s.Public, p.TenantID, time.Now(), restoring); e != nil {
		return out, problem(422, "SIGNATURE_INVALID", e.Error())
	}
	e := s.Store.Do(ctx, p.TenantID, func(t *store.Tx) error {
		// The persisted signature and execution binding reject invented execution IDs
		// and replaying a nonce against another occurrence.
		var signed []byte
		if e := t.QueryRow(ctx, "SELECT envelope FROM signed_plans WHERE tenant_id=$1 AND plan_id=$2 AND nonce=$3", t.Tenant, p.ID, p.Nonce).Scan(&signed); e != nil {
			return e
		}
		var known model.Envelope
		if e := json.Unmarshal(signed, &known); e != nil {
			return e
		}
		if known.Signature != in.Envelope.Signature {
			return problem(422, "SIGNATURE_INVALID", "signature differs from approved envelope")
		}
		execution, e := t.Get(ctx, "executions", in.ExecutionID)
		if e != nil {
			return e
		}
		if model.String(execution, "change_plan_id") != p.ID {
			return problem(422, "EXECUTION_MISMATCH", "wrong execution")
		}
		if in.Operation == "STOP" && model.Bool(execution, "start_now") {
			return problem(422, "STOP_CANCELLED", "restoration override cancels the pending stop")
		}
		op := p.Operations[0]
		targetKey := op.AccountID + ":" + op.Region + ":" + op.ProviderResourceID
		if _, e = t.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", p.TenantID+":"+targetKey); e != nil {
			return e
		}
		var intent, owned, restored bool
		var data []byte
		e = t.QueryRow(ctx, "SELECT stop_intent,stop_owned,restored,document FROM provider_operations WHERE tenant_id=$1 AND execution_id=$2 FOR UPDATE", t.Tenant, in.ExecutionID).Scan(&intent, &owned, &restored, &data)
		if e != nil && e != pgx.ErrNoRows {
			return e
		}
		exists := e == nil
		state := model.Document{}
		if exists {
			_ = json.Unmarshal(data, &state)
		}
		if p.Fixture != s.Config.Fixture {
			return problem(422, "MODE_MISMATCH", "fixture plan cannot execute against live AWS")
		}
		var aws *provider.AWS
		if !s.Config.Fixture {
			if e = ValidateAWSTenant(p.TenantID); e != nil {
				return e
			}
			if !strings.Contains(s.Config.AWSExecutionRole, ":"+op.AccountID+":") {
				return problem(422, "ACCOUNT_MISMATCH", "execution role account differs from plan")
			}
			aws, e = provider.NewAWS(ctx, op.Region, s.Config.AWSExecutionRole, s.Config.AWSExternalID)
			if e != nil {
				return e
			}
		}
		current := model.ProviderState{State: "running", Healthy: true}
		if s.Config.Fixture {
			if v := model.String(state, "state"); v != "" {
				current.State = v
				current.Healthy = v == "running"
			}
			workload, e := t.Get(ctx, "workloads", p.WorkloadID)
			if e != nil {
				return e
			}
			if model.Bool(workload, "fixture_unhealthy") {
				current.Healthy = false
			}
		} else {
			current, e = aws.Describe(ctx, op)
			if e != nil {
				return e
			}
		}
		// Completion consumes restoration authority permanently. A replayed
		// HEALTH/DESCRIBE may observe a later manual stop, but must not rewrite
		// the completed receipt and make an old START capability usable again.
		if restored && restoring {
			out = current
			return nil
		}
		dispatched := false
		switch in.Operation {
		case "STOP":
			if restored {
				return problem(409, "OCCURRENCE_COMPLETED", "this occurrence has already restored")
			}
			if owned || intent && current.State == "stopped" {
				owned = true
				current.State = "stopped"
				current.Healthy = false
				break
			}
			if exists && intent {
				// The first dispatch may still be in flight after an uncertain
				// response. Observe its outcome; another STOP cannot acquire a
				// second mutation merely because Describe still reports running.
				out = current
				return nil
			}
			if e = precheck(ctx, t, p, time.Now()); e != nil {
				return e
			}
			if current.State != "running" || !current.Healthy {
				return problem(422, "RESOURCE_NOT_HEALTHY_RUNNING", "instance must be healthy and running before stop")
			}
			if !s.Config.Fixture {
				res, e := t.Get(ctx, "resources", op.ResourceID)
				if e != nil {
					return e
				}
				if e = aws.Preflight(ctx, op, res); e != nil {
					return problem(422, "LIVE_SAFETY_PRECHECK_FAILED", e.Error())
				}
				healthy, e := s.probe(ctx, p.HealthURL)
				if e != nil || !healthy {
					return problem(422, "HEALTH_PRECHECK_FAILED", "mandatory workload probe failed")
				}
			}
			// Commit intention before the provider call so a worker crash or uncertain
			// response cannot lose the duty to restore. The API cannot write this table.
			if !exists {
				state = model.Document{"state": current.State, "nonce": p.Nonce}
				b, _ := json.Marshal(state)
				if _, e = t.Exec(ctx, "INSERT INTO provider_operations(tenant_id,execution_id,resource_id,stop_intent,document) VALUES($1,$2,$3,true,$4)", t.Tenant, in.ExecutionID, targetKey, b); e != nil {
					return e
				}
				if e = t.Commit(ctx); e != nil {
					return e
				}
				next, e := s.Store.Begin(ctx, p.TenantID)
				if e != nil {
					return e
				}
				*t = *next
				if _, e = t.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", p.TenantID+":"+op.AccountID+":"+op.Region+":"+op.ProviderResourceID); e != nil {
					return e
				}
				// Committing intent releases the first lock. Re-read consumption
				// before dispatch in case another recovery completed meanwhile.
				if e = t.QueryRow(ctx, "SELECT stop_intent,stop_owned,restored FROM provider_operations WHERE tenant_id=$1 AND execution_id=$2 FOR UPDATE", t.Tenant, in.ExecutionID).Scan(&intent, &owned, &restored); e != nil {
					return e
				}
				if restored || !intent || owned {
					return problem(409, "OCCURRENCE_COMPLETED", "stop authority was consumed while intent was persisted")
				}
				intent = true
			}
			if s.Config.Fixture {
				current = model.ProviderState{State: "stopped", Healthy: false}
				owned = true
				dispatched = true
			} else {
				if e = aws.Stop(ctx, op); e != nil {
					return finalizeStopError(ctx, t, in.ExecutionID, state, op, !exists && !owned, e)
				}
				dispatched = true
				current, e = aws.Describe(ctx, op)
				if e != nil {
					return e
				}
				owned = current.State == "stopped" || current.State == "stopping"
			}
		case "START":
			if restored {
				out = current
				return nil
			}
			if !exists || !intent {
				return problem(422, "RESTORATION_NOT_OWNED", "this occurrence did not initiate a stop")
			}
			if current.State == "stopping" {
				out = current
				return nil
			}
			if current.State == "running" {
				break
			}
			if current.State != "stopped" && current.State != "pending" {
				return problem(422, "INVALID_RESTORE_STATE", "cannot safely restore provider state")
			}
			if s.Config.Fixture {
				current = model.ProviderState{State: "running", Healthy: true}
				dispatched = true
			} else if current.State == "stopped" {
				if e = aws.Start(ctx, p.Operations[1]); e != nil {
					return e
				}
				dispatched = true
				current, e = aws.Describe(ctx, op)
				if e != nil {
					return e
				}
			}
			owned = true
		case "HEALTH":
			if current.State == "running" && current.Healthy && !s.Config.Fixture {
				current.Healthy, e = s.probe(ctx, p.HealthURL)
				if e != nil {
					return e
				}
			}
		case "DESCRIBE":
		}
		if exists || intent {
			if owned && current.State == "stopped" && model.String(state, "stopped_at") == "" {
				state["stopped_at"] = model.Now()
			}
			if owned && current.State == "running" && model.String(state, "stopped_at") != "" && model.String(state, "running_at") == "" {
				state["running_at"] = model.Now()
			}
			if in.Operation == "HEALTH" && !restored {
				if current.State == "running" && current.Healthy {
					since, e := time.Parse(time.RFC3339Nano, model.String(state, "healthy_since"))
					if e != nil {
						since = time.Now()
						state["healthy_since"] = since.UTC().Format(time.RFC3339Nano)
						state["healthy_checks"] = int64(0)
					}
					count := model.Number(state, "healthy_checks") + 1
					state["healthy_checks"] = count
					span := 60 * time.Second
					if s.Config.Fixture {
						span = 2 * time.Second
					}
					restored = count >= 3 && time.Since(since) >= span
				} else {
					delete(state, "healthy_since")
					state["healthy_checks"] = int64(0)
					restored = false
				}
			}
			state["state"], state["nonce"] = current.State, p.Nonce
			b, _ := json.Marshal(state)
			if _, e = t.Exec(ctx, "UPDATE provider_operations SET stop_owned=$3,restored=$4,document=$5,updated_at=now() WHERE tenant_id=$1 AND execution_id=$2", t.Tenant, in.ExecutionID, owned, restored, b); e != nil {
				return e
			}
		}
		out = current
		if dispatched {
			return t.Audit(ctx, "executor", "provider."+strings.ToLower(in.Operation), op.ResourceID, model.Document{"execution_id": in.ExecutionID, "provider_resource_id": op.ProviderResourceID, "state": current.State, "restoration_owned": intent})
		}
		return nil
	})
	return out, e
}

// A definitive first-request rejection grants no restoration capability. An
// older intent may represent a lost successful response, so it must keep its
// duty to restore even if a later retry is rejected. Commit cancellation before
// returning the provider error, which otherwise rolls back this transaction.
func finalizeStopError(ctx context.Context, t *store.Tx, executionID string, state model.Document, op model.Operation, firstDispatch bool, cause error) error {
	if !firstDispatch || !provider.StopDefinitelyRejected(cause) {
		return cause
	}
	state = model.Clone(state)
	state["stop_rejected"], state["reason_code"] = true, "STOP_DEFINITIVELY_REJECTED"
	b, e := json.Marshal(state)
	if e != nil {
		return e
	}
	updated, e := t.Exec(ctx, "UPDATE provider_operations SET stop_intent=false,stop_owned=false,restored=true,document=$3,updated_at=now() WHERE tenant_id=$1 AND execution_id=$2 AND NOT stop_owned AND NOT restored", t.Tenant, executionID, b)
	if e != nil {
		return e
	}
	if updated.RowsAffected() != 1 {
		return problem(409, "STOP_OWNERSHIP_CHANGED", "stop authority changed before rejection was persisted")
	}
	if e = t.Audit(ctx, "executor", "provider.stop.rejected", op.ResourceID, model.Document{"execution_id": executionID, "provider_resource_id": op.ProviderResourceID, "reason_code": "STOP_DEFINITIVELY_REJECTED"}); e != nil {
		return e
	}
	if e = t.Commit(ctx); e != nil {
		return e
	}
	return cause
}

func (s *SecureService) probe(ctx context.Context, target string) (bool, error) {
	if e := validateHealthURL(target, s.Config); e != nil {
		return false, e
	}
	u, e := url.Parse(target)
	if e != nil || u.Scheme != "https" && u.Scheme != "http" || u.User != nil {
		return false, errors.New("invalid health URL")
	}
	if !s.Config.Fixture && (u.Scheme != "https" || u.Port() != "" && u.Port() != "443") {
		return false, errors.New("live health URL requires HTTPS on port 443")
	}
	allowed := false
	for _, h := range strings.Split(s.Config.HealthAllowedHosts, ",") {
		if strings.TrimSpace(h) == u.Hostname() {
			allowed = true
		}
	}
	if !allowed {
		return false, errors.New("health host not explicitly allowlisted")
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, e := net.SplitHostPort(addr)
		if e != nil {
			return nil, e
		}
		ips, e := net.DefaultResolver.LookupIPAddr(ctx, host)
		if e != nil {
			return nil, e
		}
		for _, ip := range ips {
			if ip.IP.IsLoopback() || ip.IP.IsLinkLocalUnicast() || ip.IP.IsLinkLocalMulticast() || ip.IP.IsUnspecified() {
				return nil, errors.New("health destination blocked")
			}
		}
		if len(ips) == 0 {
			return nil, errors.New("health destination unresolved")
		}
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, net.JoinHostPort(ips[0].IP.String(), port))
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("health redirects prohibited") }}
	req, e := http.NewRequestWithContext(ctx, "GET", target, nil)
	if e != nil {
		return false, e
	}
	res, e := client.Do(req)
	if e != nil {
		return false, e
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return false, fmt.Errorf("health status %d", res.StatusCode)
	}
	return true, nil
}

func validateHealthURL(target string, c Config) error {
	u, e := url.Parse(target)
	if e != nil || u.User != nil || u.Fragment != "" || u.Hostname() == "" {
		return errors.New("invalid health URL")
	}
	if !c.Fixture && (u.Scheme != "https" || u.Port() != "" && u.Port() != "443") {
		return errors.New("live health URL requires HTTPS on port 443")
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return errors.New("invalid health URL scheme")
	}
	for _, h := range strings.Split(c.HealthAllowedHosts, ",") {
		if strings.TrimSpace(h) == u.Hostname() {
			return nil
		}
	}
	return errors.New("health host not explicitly allowlisted")
}
