package service

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/auth"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/evidence"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/safety"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
)

// This exercises the real executor and API mutation handler under independently
// authenticated PostgreSQL roles. The economics HTTP double only supplies an
// already-valid fixture baseline; no financial or live-AWS claim is tested here.
func TestStopControlHandoffSerializesAcceptedCancellation(t *testing.T) {
	admin, roles := financialSourceTestDatabase(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	tenant := "stop-controls-" + model.ID()
	worker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in model.Document
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			JSON(w, 422, model.Document{"error": "invalid test evidence"})
			return
		}
		if r.URL.Path == "/normalize" {
			rows := []model.Document{}
			for _, raw := range evidence.Rows(in["records"]) {
				rows = append(rows, model.Document{"ResourceId": raw["line_item_resource_id"], "SubAccountId": raw["line_item_usage_account_id"], "RegionId": raw["product_region_code"], "BillingCurrency": "GBP", "x_SourceId": in["source_id"], "x_SourceVersion": in["source_version"], "x_SourceRecordId": raw["identity_line_item_id"], "BilledCost": raw["line_item_unblended_cost"], "EffectiveCost": raw["line_item_unblended_cost"], "ContractedCost": raw["ContractedCost"], "ChargePeriodStart": raw["line_item_usage_start_date"], "ChargePeriodEnd": raw["line_item_usage_end_date"], "ServiceName": "AmazonEC2", "x_ProviderFields": raw})
			}
			JSON(w, 200, model.Document{"records": rows, "totals": in["invoice_totals"]})
			return
		}
		JSON(w, 200, model.Document{"status": "MEASURING", "reason_code": "VERIFICATION_WINDOW_INCOMPLETE", "pre_execution_ready": true, "baseline_id": in["baseline_id"], "fingerprint": evidence.Hash(in), "claim_key": "control-test", "coverage_intervals": []model.Document{}})
	}))
	defer worker.Close()
	api := &API{Store: roles["api"], Config: Config{Fixture: true, EconomicsURL: worker.URL}, Client: worker.Client()}
	if err := roles["api"].Do(ctx, tenant, func(tx *store.Tx) error { return tx.Seed(ctx, true) }); err != nil {
		t.Fatal(err)
	}
	if err := roles["ingester"].Do(ctx, tenant, func(tx *store.Tx) error {
		if err := api.PrepareFixtureEvidence(ctx, tx); err != nil {
			return err
		}
		jobs, err := tx.List(ctx, "ingestion_jobs")
		if err != nil {
			return err
		}
		for _, job := range jobs {
			job["status"] = "PERSISTED"
			job, err = tx.Update(ctx, "ingestion_jobs", model.String(job, "id"), model.Number(job, "version"), job)
			if err != nil {
				return err
			}
			if err = api.SealFixtureEvidence(ctx, tx, job); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var template model.Plan
	if err := roles["api"].Do(ctx, tenant, func(tx *store.Tx) error {
		ready, err := api.readiness(ctx, tx, "resource-dev-api", true)
		if err != nil {
			return err
		}
		if !model.Bool(ready, "pre_execution_ready") {
			return fmt.Errorf("fixture not ready: %v", ready["reason_code"])
		}
		rec, err := tx.Create(ctx, "recommendations", model.Document{"resource_id": "resource-dev-api", "workload_id": "workload-dev", "status": "VALIDATED", "pre_execution_ready": true, "readiness_id": ready["id"]})
		if err != nil {
			return err
		}
		plan, err := BuildPlan(ctx, tx, model.String(rec, "id"), "schedule-dev", true)
		if err != nil {
			return err
		}
		template, err = decodePlan(plan)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	service := &SecureService{Store: roles["executor"], Config: Config{Fixture: true, Role: "executor"}, Public: public}
	identity := auth.Identity{Tenant: tenant, Subject: "control-operator", Roles: map[string]bool{"PLATFORM_ADMIN": true}}
	var canUpdate bool
	if err := roles["executor"].Pool.QueryRow(ctx, "SELECT has_table_privilege(current_user,'public.entities','UPDATE')").Scan(&canUpdate); err != nil || canUpdate {
		t.Fatal("control serialization must not grant executor entity UPDATE", err)
	}
	type control struct{ name, path, kind, id, code string }
	controls := []control{
		{"start-now", "executions/%s/start-now", "executions", "", "STOP_CANCELLED"},
		{"organization-pause", "control/pause", "org", tenant, "BLOCKED_AUTOPILOT_PAUSED"},
		{"schedule-pause", "schedules/schedule-dev/pause", "schedules", "schedule-dev", "BLOCKED_SCHEDULE_PAUSED"},
		{"skip-next-stop", "schedules/schedule-dev/skip-next-stop", "schedules", "schedule-dev", "BLOCKED_SCHEDULE_PAUSED"},
		{"policy-pause", "policies/policy-default", "policies", "policy-default", "POLICY_VERSION_CHANGED"},
	}
	for _, late := range []bool{false, true} {
		for _, c := range controls {
			phase := "accepted-during-intent-handoff/"
			if late {
				phase = "dispatch-linearizes-before-late-control/"
			}
			t.Run(phase+c.name, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
				defer cancel()
				// Reset control state only, retaining immutable source/readiness.
				p := template
				p.ID, p.Nonce = model.ID(), model.ID()
				p.CreatedAt, p.StopAt, p.ExpiresAt = time.Now().UTC(), time.Now().UTC().Add(-time.Second), time.Now().UTC().Add(10*time.Minute)
				executionID := model.ID()
				if err := roles["api"].Do(ctx, tenant, func(tx *store.Tx) error {
					for _, item := range []struct{ kind, id string }{{"org", tenant}, {"schedules", "schedule-dev"}, {"policies", "policy-default"}} {
						d, err := tx.Get(ctx, item.kind, item.id)
						if err != nil {
							return err
						}
						d["paused"], d["skip_next_stop"] = false, false
						d, err = tx.Update(ctx, item.kind, item.id, model.Number(d, "version"), d)
						if err != nil {
							return err
						}
						if item.kind == "policies" {
							p.PolicyVersion = model.Number(d, "version")
						}
					}
					if _, err := tx.Create(ctx, "change_plans", model.Document{"id": p.ID, "payload": p, "status": "APPROVED"}); err != nil {
						return err
					}
					_, err := tx.Create(ctx, "executions", model.Document{"id": executionID, "change_plan_id": p.ID, "workload_id": p.WorkloadID, "resource_id": p.Operations[0].ResourceID, "schedule_id": p.ScheduleID, "status": "EXECUTING", "stage": "STOPPING"})
					return err
				}); err != nil {
					t.Fatal(err)
				}
				envelope, err := safety.Sign(p, private)
				if err != nil {
					t.Fatal(err)
				}
				if err = roles["signer"].Do(ctx, tenant, func(tx *store.Tx) error {
					if err := precheck(ctx, tx, p, time.Now()); err != nil {
						return err
					}
					body, _ := json.Marshal(envelope)
					_, err := tx.Exec(ctx, "INSERT INTO signed_plans(tenant_id,plan_id,nonce,envelope) VALUES($1,$2,$3,$4)", tenant, p.ID, p.Nonce, body)
					return err
				}); err != nil {
					t.Fatal("valid pre-control STOP must pass", err)
				}
				barrier, err := admin.Begin(ctx, tenant)
				if err != nil {
					t.Fatal(err)
				}
				defer barrier.Rollback(context.Background())
				barrierKey := tenant + ":test-dispatch-barrier:" + executionID
				if _, err = barrier.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", barrierKey); err != nil {
					t.Fatal(err)
				}
				// Only the owner of this disposable database can install this
				// deterministic barrier. There is no runtime/configuration hook.
				if _, err = admin.Pool.Exec(ctx, `CREATE OR REPLACE FUNCTION public.test_stop_control_barrier() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.execution_id=TG_ARGV[0] THEN PERFORM pg_advisory_xact_lock(hashtextextended(TG_ARGV[1],0)); END IF; RETURN NEW; END $$`); err != nil {
					t.Fatal(err)
				}
				event := "INSERT"
				condition := ""
				if late {
					event, condition = "UPDATE", " WHEN (NEW.stop_owned AND NOT OLD.stop_owned)"
				}
				if _, err = admin.Pool.Exec(ctx, "CREATE TRIGGER test_stop_control_barrier BEFORE "+event+" ON provider_operations FOR EACH ROW"+condition+" EXECUTE FUNCTION public.test_stop_control_barrier('"+executionID+"','"+barrierKey+"')"); err != nil {
					t.Fatal(err)
				}
				defer func() {
					cancel()
					_ = barrier.Rollback(context.Background())
					cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
					defer stop()
					if _, err := admin.Pool.Exec(cleanup, "DROP TRIGGER IF EXISTS test_stop_control_barrier ON provider_operations"); err != nil {
						t.Error(err)
					}
				}()
				type result struct {
					state model.ProviderState
					err   error
				}
				dispatched := make(chan result, 1)
				go func() {
					state, err := service.dispatch(ctx, model.Dispatch{Envelope: envelope, ExecutionID: executionID, Operation: "STOP"})
					dispatched <- result{state, err}
				}()
				prefix := "INSERT INTO provider_operations%"
				if late {
					prefix = "UPDATE provider_operations SET stop_owned%"
				}
				barrierReached := false
				for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
					select {
					case got := <-dispatched:
						t.Fatalf("executor returned before private barrier: state=%+v error=%v", got.state, got.err)
					default:
					}
					if err := admin.Pool.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event='advisory' AND query LIKE $1)", prefix).Scan(&barrierReached); err != nil {
						t.Fatal(err)
					}
					if barrierReached {
						break
					}
					time.Sleep(10 * time.Millisecond)
				}
				if !barrierReached {
					t.Fatal("executor did not reach private barrier")
				}
				var resourceBlocker *store.Tx
				if !late {
					resourceBlocker, err = admin.Begin(ctx, tenant)
					if err != nil {
						t.Fatal(err)
					}
					defer resourceBlocker.Rollback(context.Background())
					var pid int
					if err = resourceBlocker.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&pid); err != nil {
						t.Fatal(err)
					}
					queued := make(chan error, 1)
					op := p.Operations[0]
					go func() {
						_, err := resourceBlocker.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", tenant+":"+op.AccountID+":"+op.Region+":"+op.ProviderResourceID)
						queued <- err
					}()
					waitStopControlSQL(t, ctx, admin, "resource waiter queues before intent commits", "SELECT EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1 AND locktype='advisory' AND NOT granted)", pid)
					if err = barrier.Commit(ctx); err != nil {
						t.Fatal(err)
					}
					if err = <-queued; err != nil {
						t.Fatal(err)
					}
				}
				path, id := c.path, c.id
				if c.name == "start-now" {
					path, id = fmt.Sprintf(path, executionID), executionID
				}
				var version int64
				if err = roles["api"].Do(ctx, tenant, func(tx *store.Tx) error {
					d, err := tx.Get(ctx, c.kind, id)
					version = model.Number(d, "version")
					return err
				}); err != nil {
					t.Fatal(err)
				}
				request := httptest.NewRequest(http.MethodPost, "/v1/"+path, strings.NewReader(`{"paused":true}`))
				request.Header.Set("If-Match", fmt.Sprintf(`"%d"`, version))
				controlTx, err := roles["api"].Begin(ctx, tenant)
				if err != nil {
					t.Fatal(err)
				}
				defer controlTx.Rollback(context.Background())
				var controlPID int
				if err = controlTx.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&controlPID); err != nil {
					t.Fatal(err)
				}
				controlled := make(chan error, 1)
				go func() {
					_, status, err := api.mutate(ctx, controlTx, identity, request, model.Document{"paused": true})
					if err == nil && status != 200 && status != 202 {
						err = fmt.Errorf("unexpected control response: %d", status)
					}
					if err == nil {
						err = controlTx.Commit(ctx)
					}
					controlled <- err
				}()
				if late {
					waitStopControlSQL(t, ctx, admin, "late control waits for dispatch commit", "SELECT EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1 AND locktype='advisory' AND NOT granted)", controlPID)
					select {
					case err := <-controlled:
						t.Fatalf("control returned before dispatch linearized: %v", err)
					default:
					}
					if err = barrier.Commit(ctx); err != nil {
						t.Fatal(err)
					}
				}
				ambiguousSkip := !late && c.name == "skip-next-stop"
				if err = <-controlled; ambiguousSkip {
					var refused *Problem
					if !errors.As(err, &refused) || refused.Status != 409 || refused.Code != "SKIP_STOP_INTENT_UNCERTAIN" {
						t.Fatal("an existing unowned intent must not be called unissued", err)
					}
					_ = controlTx.Rollback(ctx)
					if err = roles["api"].Do(ctx, tenant, func(tx *store.Tx) error {
						schedule, err := tx.Get(ctx, "schedules", p.ScheduleID)
						if err != nil {
							return err
						}
						if model.Bool(schedule, "skip_next_stop") {
							return errors.New("ambiguous skip mutated the future flag")
						}
						execution, err := tx.Get(ctx, "executions", executionID)
						if err != nil {
							return err
						}
						request := httptest.NewRequest(http.MethodPost, "/v1/executions/"+executionID+"/start-now", nil)
						request.Header.Set("If-Match", fmt.Sprintf(`"%d"`, model.Number(execution, "version")))
						_, _, err = api.mutate(ctx, tx, identity, request, model.Document{})
						return err
					}); err != nil {
						t.Fatal("explicit start-now could not replace ambiguous skip", err)
					}
				} else if err != nil {
					t.Fatal("authorized control could not commit", err)
				}
				if resourceBlocker != nil {
					if err = resourceBlocker.Commit(ctx); err != nil {
						t.Fatal(err)
					}
				}
				got := <-dispatched
				var intent, owned, restored bool
				var reason string
				var stops int
				read := func() {
					t.Helper()
					if err := roles["executor"].Do(ctx, tenant, func(tx *store.Tx) error {
						if err := tx.QueryRow(ctx, "SELECT stop_intent,stop_owned,restored,coalesce(document->>'reason_code','') FROM provider_operations WHERE tenant_id=$1 AND execution_id=$2", tenant, executionID).Scan(&intent, &owned, &restored, &reason); err != nil {
							return err
						}
						return tx.QueryRow(ctx, "SELECT count(*) FROM audit_events WHERE tenant_id=$1 AND action='provider.stop' AND document->'details'->>'execution_id'=$2", tenant, executionID).Scan(&stops)
					}); err != nil {
						t.Fatal(err)
					}
				}
				read()
				if late {
					if got.err != nil || got.state.State != "stopped" || !intent || !owned || restored || stops != 1 {
						t.Fatalf("dispatch did not precede late control exactly once: %+v, intent=%v owned=%v restored=%v stops=%d", got, intent, owned, restored, stops)
					}
					// Pause/policy changes and start-now cannot strand an owned stop.
					current, err := service.dispatch(ctx, model.Dispatch{Envelope: envelope, ExecutionID: executionID, Operation: "START"})
					if err != nil || current.State != "running" {
						t.Fatalf("accepted control stranded owned restoration: %+v %v", current, err)
					}
					// Complete application readiness so the following case cannot
					// reuse an actively owned resource occurrence.
					for n := 0; n < 3; n++ {
						if _, err = service.dispatch(ctx, model.Dispatch{Envelope: envelope, ExecutionID: executionID, Operation: "HEALTH"}); err != nil {
							t.Fatal(err)
						}
						if n == 0 {
							time.Sleep(2100 * time.Millisecond)
						}
					}
					read()
					if !restored {
						t.Fatal("owned restoration did not finish its real fixture health probes")
					}
				} else {
					var refused *Problem
					code := c.code
					if ambiguousSkip {
						code = "STOP_CANCELLED"
					}
					if !errors.As(got.err, &refused) || refused.Code != code || intent || owned || !restored || stops != 0 {
						t.Fatalf("accepted control was missed: %+v, reason=%s intent=%v owned=%v restored=%v stops=%d", got, reason, intent, owned, restored, stops)
					}
					if reason != "STOP_CANCELLED" && reason != "STOP_PRECONDITIONS_CHANGED" {
						t.Fatal("unissued intent was not durably consumed", reason)
					}
					if err = roles["executor"].Do(ctx, tenant, func(tx *store.Tx) error {
						_, err := tx.Exec(ctx, `UPDATE provider_operations SET document=jsonb_set(document,'{state}','"stopped"'::jsonb) WHERE tenant_id=$1 AND execution_id=$2`, tenant, executionID)
						return err
					}); err != nil {
						t.Fatal(err)
					}
					current, err := service.dispatch(ctx, model.Dispatch{Envelope: envelope, ExecutionID: executionID, Operation: "START"})
					if err != nil || current.State != "stopped" {
						t.Fatalf("cancelled unissued STOP acquired a later manual stop: %+v %v", current, err)
					}
				}
			})
		}
	}
	t.Run("skip-binds-one-unissued-occurrence-without-borrowing-the-next", func(t *testing.T) {
		for _, lastDate := range []string{"", "2000-01-01", time.Now().UTC().Format("2006-01-02")} {
			p := template
			p.ID, p.Nonce = model.ID(), model.ID()
			p.StopAt, p.CreatedAt, p.ExpiresAt = time.Now().UTC().Add(-time.Second), time.Now().UTC(), time.Now().UTC().Add(10*time.Minute)
			executionID := model.ID()
			if err := roles["api"].Do(ctx, tenant, func(tx *store.Tx) error {
				for _, item := range []struct{ kind, id string }{{"org", tenant}, {"policies", "policy-default"}, {"schedules", "schedule-dev"}} {
					d, err := tx.Get(ctx, item.kind, item.id)
					if err != nil {
						return err
					}
					d["paused"], d["skip_next_stop"] = false, false
					if item.kind == "schedules" {
						d["last_occurrence_date"] = lastDate
					}
					d, err = tx.Update(ctx, item.kind, item.id, model.Number(d, "version"), d)
					if err != nil {
						return err
					}
					if item.kind == "policies" {
						p.PolicyVersion = model.Number(d, "version")
					}
				}
				if _, err := tx.Create(ctx, "change_plans", model.Document{"id": p.ID, "payload": p, "status": "APPROVED"}); err != nil {
					return err
				}
				_, err := tx.Create(ctx, "executions", model.Document{"id": executionID, "change_plan_id": p.ID, "workload_id": p.WorkloadID, "resource_id": p.Operations[0].ResourceID, "status": "QUEUED", "stage": "PRECHECK"})
				return err
			}); err != nil {
				t.Fatal(err)
			}
			if err := roles["executor"].Do(ctx, tenant, func(tx *store.Tx) error { return precheck(ctx, tx, p, time.Now()) }); err != nil {
				t.Fatal("uncancelled fixture plan must start eligible", err)
			}
			if err := roles["api"].Do(ctx, tenant, func(tx *store.Tx) error {
				d, err := tx.Get(ctx, "schedules", p.ScheduleID)
				if err != nil {
					return err
				}
				r := httptest.NewRequest(http.MethodPost, "/v1/schedules/"+p.ScheduleID+"/skip-next-stop", nil)
				r.Header.Set("If-Match", fmt.Sprintf(`"%d"`, model.Number(d, "version")))
				out, status, err := api.mutate(ctx, tx, identity, r, model.Document{})
				if err == nil && (status != 200 || model.Bool(out, "skip_next_stop")) {
					return errors.New("current occurrence retained tomorrow's one-shot flag")
				}
				return err
			}); err != nil {
				t.Fatal("known unissued current occurrence could not bind skip", err)
			}
			if err := roles["executor"].Do(ctx, tenant, func(tx *store.Tx) error {
				blocked := precheck(ctx, tx, p, time.Now())
				var refused *Problem
				if !errors.As(blocked, &refused) || refused.Code != "BLOCKED_STOP_OCCURRENCE_SKIPPED" {
					return fmt.Errorf("exact skipped plan remained eligible: %v", blocked)
				}
				for _, next := range []time.Time{p.StopAt.Add(time.Nanosecond), p.StopAt.Add(24 * time.Hour)} {
					skipped, err := ScheduleStopSkipped(ctx, tx, p.ScheduleID, next)
					if err != nil || skipped {
						return fmt.Errorf("skip leaked into later occurrence: %v", err)
					}
				}
				next := p
				next.StopAt = p.StopAt.Add(time.Nanosecond)
				return precheck(ctx, tx, next, time.Now())
			}); err != nil {
				t.Fatal("one skip cancelled more than one logical fixture occurrence", err)
			}
			if err := roles["worker"].Do(ctx, tenant, func(tx *store.Tx) error {
				d, err := tx.Get(ctx, "executions", executionID)
				if err != nil {
					return err
				}
				d["status"], d["stage"] = "FAILED", "STOP_FAILED"
				_, err = tx.Update(ctx, "executions", executionID, model.Number(d, "version"), d)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			// Reset generations never borrow an old exact-timestamp receipt.
			if err := roles["api"].Do(ctx, tenant, func(tx *store.Tx) error {
				org, err := tx.Get(ctx, "org", tenant)
				if err != nil {
					return err
				}
				original := model.String(org, "fixture_generation")
				org["fixture_generation"] = model.ID()
				org, err = tx.Update(ctx, "org", tenant, model.Number(org, "version"), org)
				if err != nil {
					return err
				}
				if skipped, err := ScheduleStopSkipped(ctx, tx, p.ScheduleID, p.StopAt); err != nil || skipped {
					return fmt.Errorf("reset reused old skip receipt: %v", err)
				}
				org["fixture_generation"] = original
				_, err = tx.Update(ctx, "org", tenant, model.Number(org, "version"), org)
				return err
			}); err != nil {
				t.Fatal(err)
			}
		}
	})
	t.Run("ambiguous-prior-intent-retains-owned-restoration-after-skip-refusal", func(t *testing.T) {
		p := template
		p.ID, p.Nonce = model.ID(), model.ID()
		p.StopAt, p.CreatedAt, p.ExpiresAt = time.Now().UTC().Add(-time.Second), time.Now().UTC(), time.Now().UTC().Add(10*time.Minute)
		executionID := model.ID()
		if err := roles["api"].Do(ctx, tenant, func(tx *store.Tx) error {
			if _, err := tx.Create(ctx, "change_plans", model.Document{"id": p.ID, "payload": p, "status": "APPROVED"}); err != nil {
				return err
			}
			_, err := tx.Create(ctx, "executions", model.Document{"id": executionID, "change_plan_id": p.ID, "workload_id": p.WorkloadID, "resource_id": p.Operations[0].ResourceID, "status": "EXECUTING", "stage": "STOPPING"})
			return err
		}); err != nil {
			t.Fatal(err)
		}
		envelope, err := safety.Sign(p, private)
		if err != nil {
			t.Fatal(err)
		}
		if err = roles["signer"].Do(ctx, tenant, func(tx *store.Tx) error {
			body, _ := json.Marshal(envelope)
			_, err := tx.Exec(ctx, "INSERT INTO signed_plans(tenant_id,plan_id,nonce,envelope) VALUES($1,$2,$3,$4)", tenant, p.ID, p.Nonce, body)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if err = roles["executor"].Do(ctx, tenant, func(tx *store.Tx) error {
			body, _ := json.Marshal(model.Document{"state": "stopped", "nonce": p.Nonce})
			_, err := tx.Exec(ctx, "INSERT INTO provider_operations(tenant_id,execution_id,resource_id,stop_intent,document) VALUES($1,$2,$3,true,$4)", tenant, executionID, p.Operations[0].AccountID+":"+p.Operations[0].Region+":"+p.Operations[0].ProviderResourceID, body)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		err = roles["api"].Do(ctx, tenant, func(tx *store.Tx) error {
			d, err := tx.Get(ctx, "schedules", p.ScheduleID)
			if err != nil {
				return err
			}
			r := httptest.NewRequest(http.MethodPost, "/v1/schedules/"+p.ScheduleID+"/skip-next-stop", nil)
			r.Header.Set("If-Match", fmt.Sprintf(`"%d"`, model.Number(d, "version")))
			_, _, err = api.mutate(ctx, tx, identity, r, model.Document{})
			return err
		})
		var refused *Problem
		if !errors.As(err, &refused) || refused.Code != "SKIP_STOP_INTENT_UNCERTAIN" {
			t.Fatal("uncertain prior STOP was treated as known unissued", err)
		}
		if err = roles["api"].Do(ctx, tenant, func(tx *store.Tx) error {
			d, err := tx.Get(ctx, "schedules", p.ScheduleID)
			if err != nil || model.Bool(d, "skip_next_stop") {
				return errors.New("skip refusal changed a later schedule occurrence")
			}
			execution, err := tx.Get(ctx, "executions", executionID)
			if err != nil {
				return err
			}
			r := httptest.NewRequest(http.MethodPost, "/v1/executions/"+executionID+"/start-now", nil)
			r.Header.Set("If-Match", fmt.Sprintf(`"%d"`, model.Number(execution, "version")))
			_, _, err = api.mutate(ctx, tx, identity, r, model.Document{})
			return err
		}); err != nil {
			t.Fatal(err)
		}
		state, err := service.dispatch(ctx, model.Dispatch{Envelope: envelope, ExecutionID: executionID, Operation: "START"})
		if err != nil || state.State != "running" {
			t.Fatal("skip ambiguity stranded a previously issued uncertain STOP", state, err)
		}
	})
}

func waitStopControlSQL(t *testing.T, ctx context.Context, db *store.Store, description, query string, args ...any) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var ok bool
		if err := db.Pool.QueryRow(ctx, query, args...).Scan(&ok); err != nil {
			t.Fatal(description, err)
		}
		if ok {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("timed out: ", description)
}

func TestStopControlSLOLatchingOrdersGraphBeforeProviderReceipt(t *testing.T) {
	admin, roles := financialSourceTestDatabase(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	tenant := "stop-slo-order-" + model.ID()
	now := time.Now().UTC()
	op := model.Operation{Type: "EC2_STOP", ResourceID: "resource-dev-api", ProviderResourceID: "i-0123456789abcdef0", AccountID: "111122223333", Region: "eu-west-1"}
	start := op
	start.Type = "EC2_START"
	p := model.Plan{ID: model.ID(), TenantID: tenant, WorkloadID: "workload-dev", ScheduleID: "schedule-dev", Nonce: model.ID(), SchemaVersion: "3", Fixture: true, RiskClass: "R1", CreatedAt: now, StopAt: now, ExpiresAt: now.Add(10 * time.Minute), MeasurementID: model.ID(), SLOObjectiveID: "previous-objective", Operations: []model.Operation{op, start}}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := safety.Sign(p, private)
	if err != nil {
		t.Fatal(err)
	}
	executionID := model.ID()
	if err = roles["api"].Do(ctx, tenant, func(tx *store.Tx) error {
		if err := tx.Seed(ctx, true); err != nil {
			return err
		}
		_, err := tx.Create(ctx, "executions", model.Document{"id": executionID, "change_plan_id": p.ID, "workload_id": p.WorkloadID, "resource_id": op.ResourceID, "status": "RESTORING"})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err = roles["signer"].Do(ctx, tenant, func(tx *store.Tx) error {
		body, _ := json.Marshal(envelope)
		_, err := tx.Exec(ctx, "INSERT INTO signed_plans(tenant_id,plan_id,nonce,envelope) VALUES($1,$2,$3,$4)", tenant, p.ID, p.Nonce, body)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	// Seed a previously issued, owned fixture stop. This grants no new-stop
	// financial authority; the real observer must latch its unavailable SLO
	// authority while the real executor reconciles this existing receipt.
	if err = roles["executor"].Do(ctx, tenant, func(tx *store.Tx) error {
		body, _ := json.Marshal(model.Document{"state": "stopped", "nonce": p.Nonce})
		_, err := tx.Exec(ctx, "INSERT INTO provider_operations(tenant_id,execution_id,resource_id,stop_intent,stop_owned,document) VALUES($1,$2,$3,true,true,$4)", tenant, executionID, op.AccountID+":"+op.Region+":"+op.ProviderResourceID, body)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	observer, err := roles["worker"].Begin(ctx, tenant)
	if err != nil {
		t.Fatal(err)
	}
	defer observer.Rollback(context.Background())
	if _, err = observer.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", tenant+":dependency-graph"); err != nil {
		t.Fatal(err)
	}
	service := &SecureService{Store: roles["executor"], Config: Config{Fixture: true, Role: "executor"}, Public: public}
	done := make(chan error, 1)
	go func() {
		state, err := service.dispatch(ctx, model.Dispatch{Envelope: envelope, ExecutionID: executionID, Operation: "STOP"})
		if err == nil && state.State != "stopped" {
			err = errors.New("existing stop did not reconcile its stopped state")
		}
		done <- err
	}()
	waitStopControlSQL(t, ctx, admin, "executor waits on graph before locking provider receipt", "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event='advisory' AND query LIKE 'SELECT pg_advisory_xact_lock(hashtextextended%')")
	// If STOP already held the receipt, this real observer's trigger would
	// deadlock (graph -> receipt against receipt -> graph). It must complete
	// while STOP is still waiting, then release both locks together.
	reason, err := ObserveSLO(ctx, observer, p, executionID)
	if err != nil || reason != "SLO_AUTHORITY_REQUIRED" {
		t.Fatal("SLO observer could not durably latch before STOP", reason, err)
	}
	if err = observer.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err = <-done; err != nil {
		t.Fatal("SLO observer deadlocked or consumed restoration ownership", err)
	}
	if err = roles["api"].Do(ctx, tenant, func(tx *store.Tx) error {
		rows, err := tx.SLOViolations(ctx, p.MeasurementID)
		if err != nil {
			return err
		}
		if len(rows) != 1 || model.String(rows[0], "reason_code") != reason {
			return errors.New("missing immutable SLO failure latch")
		}
		org, err := tx.Get(ctx, "org", tenant)
		if err != nil {
			return err
		}
		org["paused"] = true
		_, err = tx.Update(ctx, "org", tenant, model.Number(org, "version"), org)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	state, err := service.dispatch(ctx, model.Dispatch{Envelope: envelope, ExecutionID: executionID, Operation: "START"})
	if err != nil || state.State != "running" {
		t.Fatalf("SLO latch/pause stranded owned restoration: %+v %v", state, err)
	}
}
