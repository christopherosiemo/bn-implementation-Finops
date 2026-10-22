package store

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/fleet"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/jackc/pgx/v5"
)

type fleetProtocolTest struct {
	*telemetryTest
	private ed25519.PrivateKey
	public  ed25519.PublicKey
}

func newFleetProtocolTest(t *testing.T) *fleetProtocolTest {
	f := newTelemetryTest(t)
	private := ed25519.NewKeyFromSeed(make([]byte, 32))
	return &fleetProtocolTest{f, private, private.Public().(ed25519.PublicKey)}
}

// These private API-owned proof rows are protocol fixtures, not claims that a
// financial/history/cohort factory or a customer pipeline has been integrated.
// The tests exercise the SQL authority/dispatch/recovery boundary with signed
// payloads. Public API inputs must never expose this private factory contract.
func (f *fleetProtocolTest) proof(kind, suffix string, binding fleet.Binding, now time.Time) fleet.ProofRef {
	d := model.Document{"id": kind + suffix, "kind": kind, "version": "1", "binding": fleetDocument(binding), "expires_at": now.Add(5 * time.Hour), "source_refs": []any{model.Document{"table": "fixture-only-protocol-authority", "id": "not-live"}}}
	f.must("finops_api", func(tx *Tx) error {
		raw, _ := json.Marshal(d)
		_, e := tx.Exec(f.ctx, "INSERT INTO fleet_proof_sets(tenant_id,id,kind,version,content_hash,document) VALUES($1,$2,$3,'1',$4,$5)", f.tenant, d["id"], kind, fleet.Digest(d), raw)
		return e
	})
	return fleet.ProofRef{Kind: kind, ID: model.String(d, "id"), Version: "1", SHA256: fleet.Digest(d), ObservedAt: now.Add(-time.Minute), ExpiresAt: now.Add(5 * time.Hour)}
}
func (f *fleetProtocolTest) parent() fleet.Envelope {
	now := time.Now().UTC()
	suffix := model.ID()
	p := fleet.Plan{SchemaVersion: "4", Kind: fleet.Kind, ID: "parent-" + suffix, Binding: fleet.Binding{TenantID: f.tenant, ResourceID: "resource", WorkloadID: "workload", Provider: "AWS", ProviderResourceID: "asg-blue", AccountID: "111122223333", Region: "eu-west-1"}, CreatorID: "requester", Environment: "NON_PRODUCTION", IaC: fleet.IaCBinding{Authority: "TERRAFORM", Repository: "https://github.com/customer/config", GitCommit: strings.Repeat("a", 40), Workspace: "sandbox", StateLineage: "state-lineage", StateSerial: 10, ConfigurationSHA256: strings.Repeat("b", 64), TerraformVersion: "1.13.3", PipelineID: "customer-pipeline"}, Governance: fleet.Governance{RiskClass: "R2", Enabled: true, PolicyID: "policy", PolicyVersion: 1, PolicySHA256: strings.Repeat("c", 64), ApproverRole: fleet.ApproverRole}, Old: fleet.Cohort{ID: "asg-blue", ASGAddress: "aws_autoscaling_group.blue", LaunchTemplateAddress: "aws_launch_template.blue", LaunchTemplateVersion: 1, InstanceType: "m6i.4xlarge", DesiredCount: 20, Stateless: true}, Candidate: fleet.Cohort{ID: "asg-green", ASGAddress: "aws_autoscaling_group.green", LaunchTemplateAddress: "aws_launch_template.green", LaunchTemplateVersion: 2, InstanceType: "m6i.2xlarge", DesiredCount: 0, Stateless: true}, Traffic: fleet.TrafficControl{Authority: "CUSTOMER_TERRAFORM_PIPELINE", Address: "aws_lb_listener_rule.app", OldTargetGroupARN: "arn:aws:elasticloadbalancing:eu-west-1:111122223333:targetgroup/blue/id", CandidateTargetGroupARN: "arn:aws:elasticloadbalancing:eu-west-1:111122223333:targetgroup/green/id"}, Budget: fleet.Budget{BaselineCount: 20, MaxInFlight: 2, MaxUnavailable: 2, MaxBlastRadiusPPM: 100000, MaxSurgeCount: 20, Currency: "GBP", MaximumCost: "48", OldInstanceHourlyCost: "0.4", CandidateInstanceHourlyCost: "0.2", MaximumDurationSeconds: 14400}, CreatedAt: now.Add(-time.Minute), ExpiresAt: now.Add(5 * time.Hour), Nonce: "parent-nonce-" + suffix}
	for _, kind := range []string{"NATIVE_HISTORY", "CAPACITY_ASSESSMENT", "WORKLOAD_SAFETY_PROFILE", "CONFIGURATION_AUTHORITY", "DEPENDENCY_REVIEW", "SLO_EVALUATION", "BILLING_PRICE"} {
		p.Proofs = append(p.Proofs, f.proof(kind, suffix, p.Binding, now))
	}
	p.Stages = fleet.DefaultStages(p, false)
	f.must("finops_api", func(tx *Tx) error { _, e := tx.FleetPlanCreate(f.ctx, p); return e })
	a := fleet.Approval{ID: model.ID(), TenantID: f.tenant, ActorID: "independent-approver", Role: fleet.ApproverRole, PlanSHA256: fleet.Digest(p), ApprovedAt: now}
	f.must("finops_api", func(tx *Tx) error { _, _, e := tx.FleetApprovalAppend(f.ctx, p.ID, a); return e })
	env, e := fleet.Sign(p, []fleet.Approval{a}, f.private, now)
	if e != nil {
		f.t.Fatal(e)
	}
	f.must("finops_signer", func(tx *Tx) error { _, _, e := tx.FleetEnvelopeAppend(f.ctx, env, f.public); return e })
	f.must("finops_api", func(tx *Tx) error {
		_, e := tx.FleetObserverRegister(f.ctx, model.Document{"id": "observer-" + suffix, "pipeline_id": p.IaC.PipelineID, "issuer": "https://machine.invalid", "subject": "pipeline-observer", "audience": "finops-deployment-observer", "binding": fleetDocument(p.Binding)})
		return e
	})
	return env
}
func (f *fleetProtocolTest) child(p fleet.Envelope, stage int, sequence uint64, transition fleet.Transition) fleet.ChildEnvelope {
	now := time.Now().UTC()
	suffix := model.ID()
	s := p.Plan.Stages[stage]
	iac := p.Plan.IaC
	iac.ConfigurationSHA256 = s.ConfigurationSHA256
	c := fleet.ChildPlan{SchemaVersion: "4", ID: "child-" + suffix, ParentID: p.Plan.ID, ParentSHA256: fleet.Digest(p.Plan), StageID: s.ID, StageSHA256: fleet.Digest(s), Sequence: sequence, Binding: p.Plan.Binding, IaC: iac, SavedPlanSHA256: fleet.BytesDigest([]byte(suffix)), PlanJSONSHA256: strings.Repeat("f", 64), Changes: []fleet.AllowedChange{}, Transition: transition, CreatedAt: now, ExpiresAt: now.Add(10 * time.Minute), Nonce: "nonce-" + suffix}
	for _, kind := range []string{"NATIVE_CURRENT", "WORKLOAD_SAFETY_PROFILE", "DEPENDENCY_REVIEW", "SLO_EVALUATION", "INCIDENT_STATE", "HEALTH_CHECK", "CANDIDATE_HEALTH"} {
		c.Proofs = append(c.Proofs, f.proof(kind, suffix, p.Plan.Binding, now))
	}
	env, e := fleet.SignChild(c, p, f.private, now)
	if e != nil {
		f.t.Fatal(e)
	}
	f.must("finops_signer", func(tx *Tx) error { _, _, e := tx.FleetChildAppend(f.ctx, env, f.public); return e })
	return env
}
func (f *fleetProtocolTest) execution(p fleet.Envelope) model.Document {
	var d model.Document
	f.must("finops_api", func(tx *Tx) error {
		var e error
		d, _, e = tx.FleetExecutionCreate(f.ctx, p.Plan.ID, "start")
		return e
	})
	return d
}
func (f *fleetProtocolTest) authorize(execution model.Document, c fleet.ChildEnvelope) model.Document {
	var d model.Document
	f.must("finops_worker", func(tx *Tx) error {
		var first bool
		var e error
		d, first, e = tx.FleetAuthorize(f.ctx, model.String(execution, "id"), c.Plan.ID, c.Plan.ID)
		if e == nil && !first {
			return errors.New("first dispatch was suppressed")
		}
		return e
	})
	return d
}
func (f *fleetProtocolTest) submission(p fleet.Envelope, c fleet.ChildEnvelope, cmd model.Document, outcome string) FleetCallbackSubmission {
	b := FleetCallback{SchemaVersion: "4", CommandID: model.String(cmd, "id"), ChildID: c.Plan.ID, ChildSHA256: fleet.Digest(c.Plan), SavedPlanSHA256: c.Plan.SavedPlanSHA256, ChildNonce: c.Plan.Nonce, StateLineage: c.Plan.IaC.StateLineage, BeforeStateSerial: c.Plan.IaC.StateSerial, AfterStateSerial: c.Plan.IaC.StateSerial + 1, Outcome: outcome, ObservedAt: time.Now().UTC(), OldInstanceIDs: []string{}, CandidateInstanceIDs: []string{}}
	for i := 0; i < c.Plan.Transition.OldAfter; i++ {
		b.OldInstanceIDs = append(b.OldInstanceIDs, fmt.Sprintf("i-%017x", i+1))
	}
	for i := 0; i < c.Plan.Transition.CandidateAfter; i++ {
		b.CandidateInstanceIDs = append(b.CandidateInstanceIDs, fmt.Sprintf("i-%017x", i+100))
	}
	raw, _ := json.Marshal(b)
	return FleetCallbackSubmission{SourceID: "observer-" + strings.TrimPrefix(p.Plan.ID, "parent-"), Issuer: "https://machine.invalid", Subject: "pipeline-observer", Audience: "finops-deployment-observer", RawBody: raw}
}
func (f *fleetProtocolTest) callback(p fleet.Envelope, c fleet.ChildEnvelope, cmd model.Document, outcome, key string) model.Document {
	var d model.Document
	in := f.submission(p, c, cmd, outcome)
	if outcome == "APPLIED" {
		var b FleetCallback
		_ = json.Unmarshal(in.RawBody, &b)
		for i, j := 0, len(b.OldInstanceIDs)-1; i < j; i, j = i+1, j-1 {
			b.OldInstanceIDs[i], b.OldInstanceIDs[j] = b.OldInstanceIDs[j], b.OldInstanceIDs[i]
		}
		in.RawBody, _ = json.Marshal(b)
	}
	f.must("finops_deployment_observer", func(tx *Tx) error {
		var e error
		d, _, e = tx.FleetCallbackAppend(f.ctx, model.String(cmd, "id"), key, in)
		return e
	})
	if outcome == "APPLIED" && !sort.StringsAreSorted(model.Strings(d, "old_instance_ids")) {
		f.t.Fatal("callback membership was not canonicalized independently of raw bytes")
	}
	return d
}
func (f *fleetProtocolTest) prepared(p fleet.Envelope) model.Document {
	e := f.execution(p)
	c := f.child(p, 0, 1, fleet.Transition{OldBefore: 20, OldAfter: 20})
	cmd := f.authorize(e, c)
	f.callback(p, c, cmd, "NO_OP", "prepare-noop")
	return e
}
func TestFleetProtocolWriterIsolationReplayAndNoRedispatchAfterUnknown(t *testing.T) {
	f := newFleetProtocolTest(t)
	p := f.parent()
	e := f.execution(p)
	c := f.child(p, 0, 1, fleet.Transition{OldBefore: 20, OldAfter: 20})
	cmd := f.authorize(e, c)
	in := f.submission(p, c, cmd, "UNKNOWN")
	f.must("finops_deployment_observer", func(tx *Tx) error {
		_, replay, e := tx.FleetCallbackAppend(f.ctx, model.String(cmd, "id"), "callback", in)
		if e == nil && replay {
			return errors.New("unexpected replay")
		}
		return e
	})
	f.must("finops_deployment_observer", func(tx *Tx) error {
		_, replay, e := tx.FleetCallbackAppend(f.ctx, model.String(cmd, "id"), "callback", in)
		if e == nil && !replay {
			return errors.New("callback not replayed")
		}
		return e
	})
	f.must("finops_worker", func(tx *Tx) error {
		d, first, e := tx.FleetAuthorize(f.ctx, model.String(e, "id"), c.Plan.ID, c.Plan.ID)
		if e == nil && (first || model.String(d, "outcome") != "UNKNOWN" || d["reservation_released_at"] != nil) {
			return errors.New("unknown outcome released or redispatched")
		}
		return e
	})
	if err := f.run("finops_worker", func(tx *Tx) error {
		_, e := tx.Exec(f.ctx, "UPDATE fleet_command_states SET dispatched_at=dispatched_at-interval '2 hours' WHERE tenant_id=$1 AND command_id=$2", f.tenant, model.String(cmd, "id"))
		return e
	}); err == nil {
		t.Fatal("worker backdated immutable observation timer")
	}
	wrong := in
	wrong.Subject = "human"
	if err := f.run("finops_deployment_observer", func(tx *Tx) error {
		_, _, e := tx.FleetCallbackAppend(f.ctx, model.String(cmd, "id"), "callback", wrong)
		return e
	}); err == nil {
		t.Fatal("wrong machine replay accepted")
	}
	changed := in
	changed.RawBody = append(append([]byte{}, in.RawBody...), byte(' '))
	if err := f.run("finops_deployment_observer", func(tx *Tx) error {
		_, _, e := tx.FleetCallbackAppend(f.ctx, model.String(cmd, "id"), "callback", changed)
		return e
	}); !errors.Is(err, ErrFleetConflict) {
		t.Fatal("changed raw replay accepted", err)
	}
	for _, role := range []string{"finops_api", "finops_worker", "finops_signer", "finops_ingester", "finops_telemetry_reader", "finops_telemetry_ingress"} {
		if err := f.run(role, func(tx *Tx) error {
			_, _, e := tx.FleetCallbackAppend(f.ctx, model.String(cmd, "id"), "forged-"+role, in)
			return e
		}); err == nil {
			t.Fatal("non-observer published callback", role)
		}
	}
	if err := f.run("finops_worker", func(tx *Tx) error {
		_, e := tx.Exec(f.ctx, "UPDATE fleet_reservations SET released_at=clock_timestamp() WHERE tenant_id=$1", f.tenant)
		return e
	}); err == nil {
		t.Fatal("worker directly released reservation")
	}
	if err := f.run("finops_deployment_observer", func(tx *Tx) error {
		_, e := tx.Exec(f.ctx, "UPDATE fleet_command_states SET outcome='APPLIED' WHERE tenant_id=$1", f.tenant)
		return e
	}); err == nil {
		t.Fatal("observer directly mutated ownership")
	}
	f.must("finops_api", func(tx *Tx) error {
		if _, e := tx.Exec(f.ctx, "SELECT set_config('app.tenant_id','other-tenant',true)"); e != nil {
			return e
		}
		_, e := tx.FleetPlan(f.ctx, p.Plan.ID)
		if e != pgx.ErrNoRows {
			return fmt.Errorf("cross tenant visible: %v", e)
		}
		return nil
	})
	if err := f.run("finops_api", func(tx *Tx) error {
		_, e := tx.Exec(f.ctx, "UPDATE fleet_plans SET document='{}' WHERE tenant_id=$1", f.tenant)
		return e
	}); err == nil {
		t.Fatal("immutable plan changed")
	}
}
func TestFleetProtocolGlobalReservationConcurrentParentsAndAppliedDoesNotRelease(t *testing.T) {
	f := newFleetProtocolTest(t)
	p1, p2 := f.parent(), f.parent()
	e1, e2 := f.prepared(p1), f.prepared(p2)
	c1 := f.child(p1, 1, 2, fleet.Transition{OldBefore: 20, OldAfter: 20, CandidateAfter: 2, InFlight: 2})
	c2 := f.child(p2, 1, 2, c1.Plan.Transition)
	var wg sync.WaitGroup
	start := make(chan struct{})
	errs := make(chan error, 2)
	commands := make(chan model.Document, 2)
	for _, v := range []struct {
		e model.Document
		c fleet.ChildEnvelope
	}{{e1, c1}, {e2, c2}} {
		wg.Add(1)
		go func(v struct {
			e model.Document
			c fleet.ChildEnvelope
		}) {
			defer wg.Done()
			<-start
			err := f.run("finops_worker", func(tx *Tx) error {
				d, first, e := tx.FleetAuthorize(f.ctx, model.String(v.e, "id"), v.c.Plan.ID, "capacity")
				if e == nil {
					if !first {
						return errors.New("not first")
					}
					commands <- d
				}
				return e
			})
			errs <- err
		}(v)
	}
	close(start)
	wg.Wait()
	close(errs)
	success := 0
	for err := range errs {
		if err == nil {
			success++
		}
	}
	if success != 1 {
		t.Fatalf("expected exactly one global budget winner, got %d", success)
	}
	cmd := <-commands
	p, c := p1, c1
	if model.String(cmd, "parent_id") == p2.Plan.ID {
		p, c = p2, c2
	}
	f.callback(p, c, cmd, "APPLIED", "applied")
	f.must("finops_worker", func(tx *Tx) error {
		d, e := tx.FleetCommand(f.ctx, model.String(cmd, "id"))
		if e == nil && (model.String(d, "owned_receipt_id") == "" || d["reservation_released_at"] != nil) {
			return errors.New("APPLIED released reservation or lacked ownership")
		}
		return e
	})
	if err := f.run("finops_api", func(tx *Tx) error {
		_, _, e := tx.FleetHealthEvidenceAppend(f.ctx, model.String(cmd, "id"), model.Document{"status": "HEALTHY", "cohort_slo_status": "CLEAR"})
		return e
	}); err == nil {
		t.Fatal("console-style healthy boolean released authority")
	}
	if err := f.run("finops_worker", func(tx *Tx) error {
		_, e := tx.FleetExecutionFinish(f.ctx, model.String(e1, "id"), "COMPLETED")
		return e
	}); err == nil {
		t.Fatal("incomplete stage marked complete")
	}
}
func TestFleetProtocolRejectsSkippedStagesAndDefinitiveFailureCannotRevive(t *testing.T) {
	f := newFleetProtocolTest(t)
	p := f.parent()
	e := f.execution(p)
	skipped := f.child(p, 1, 1, fleet.Transition{OldBefore: 20, OldAfter: 20, CandidateAfter: 2, InFlight: 2})
	if err := f.run("finops_worker", func(tx *Tx) error {
		_, _, e := tx.FleetAuthorize(f.ctx, model.String(e, "id"), skipped.Plan.ID, "skip")
		return e
	}); err == nil {
		t.Fatal("skipped preparation dispatched")
	}
	c := f.child(p, 0, 2, fleet.Transition{OldBefore: 20, OldAfter: 20})
	cmd := f.authorize(e, c)
	f.callback(p, c, cmd, "DEFINITELY_NOT_APPLIED", "definite")
	f.must("finops_worker", func(tx *Tx) error {
		d, e := tx.FleetCommand(f.ctx, model.String(cmd, "id"))
		if e == nil && d["reservation_released_at"] == nil {
			return errors.New("definite no-dispatch retained reservation")
		}
		return e
	})
	in := f.submission(p, c, cmd, "APPLIED")
	if err := f.run("finops_deployment_observer", func(tx *Tx) error {
		_, _, e := tx.FleetCallbackAppend(f.ctx, model.String(cmd, "id"), "contradiction", in)
		return e
	}); err == nil {
		t.Fatal("definite outcome contradicted")
	}
	f.must("finops_worker", func(tx *Tx) error {
		d, e := tx.FleetExecution(f.ctx, model.String(e, "id"))
		if e == nil && !model.Bool(d, "recovery_only") {
			return errors.New("failure latch missing")
		}
		return e
	})
	if err := f.run("finops_worker", func(tx *Tx) error {
		_, e := tx.FleetExecutionFinish(f.ctx, model.String(e, "id"), "COMPLETED")
		return e
	}); err == nil {
		t.Fatal("definite failure revived as complete")
	}
}
func TestFleetProtocolOwnedRecoverySurvivesPauseAndSharesRetainedBudget(t *testing.T) {
	f := newFleetProtocolTest(t)
	p := f.parent()
	e := f.prepared(p)
	if err := f.run("finops_worker", func(tx *Tx) error {
		_, err := tx.FleetExecutionFinish(f.ctx, model.String(e, "id"), "ROLLED_BACK")
		return err
	}); err == nil {
		t.Fatal("execution without an owned inverse was reported rolled back")
	}
	c := f.child(p, 1, 2, fleet.Transition{OldBefore: 20, OldAfter: 20, CandidateAfter: 2, InFlight: 2})
	cmd := f.authorize(e, c)
	f.callback(p, c, cmd, "APPLIED", "owned")
	f.must("finops_api", func(tx *Tx) error {
		_, e := tx.FleetControlAppend(f.ctx, p.Plan.ID, 0, "PAUSED", "supervisor paused forward stages")
		return e
	})
	var owned fleet.OwnedReceipt
	f.must("finops_signer", func(tx *Tx) error { var e error; owned, e = tx.FleetOwnedReceiptForChild(f.ctx, c.Plan.ID); return e })
	r := c.Plan
	r.ID = "recovery-" + model.ID()
	r.Sequence = 3
	r.CompensationFor = c.Plan.ID
	r.CompensationReceiptSHA256 = fleet.Digest(owned)
	r.Nonce = "fresh-recovery"
	r.IaC.StateSerial = owned.AfterStateSerial
	r.CreatedAt = time.Now().UTC()
	r.ExpiresAt = r.CreatedAt.Add(10 * time.Minute)
	r.SavedPlanSHA256 = strings.Repeat("e", 64)
	r.Transition = fleet.Transition{OldBefore: 20, OldAfter: 20, CandidateBefore: 2, CandidateAfter: 0, InFlight: 2}
	recovery, err := fleet.SignRecovery(r, c, p, owned, f.private, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	f.must("finops_signer", func(tx *Tx) error { _, _, e := tx.FleetChildAppend(f.ctx, recovery, f.public); return e })
	recoveryCmd := f.authorize(e, recovery)
	if model.String(recoveryCmd, "operation") != "ROLLBACK" || model.String(recoveryCmd, "shared_reservation") != model.String(cmd, "id") {
		t.Fatal("recovery double counted retained budget", recoveryCmd)
	}
	f.must("finops_worker", func(tx *Tx) error {
		_, first, e := tx.FleetAuthorize(f.ctx, model.String(e, "id"), recovery.Plan.ID, recovery.Plan.ID)
		if e == nil && first {
			return errors.New("recovery redispatched")
		}
		return e
	})
	if err := f.run("finops_worker", func(tx *Tx) error {
		_, e := tx.FleetExecutionFinish(f.ctx, model.String(e, "id"), "ROLLED_BACK")
		return e
	}); err == nil {
		t.Fatal("unobserved rollback declared complete")
	}
}

func TestFleetProtocolTerminalObservationUsesOriginalDispatchBoundary(t *testing.T) {
	f := newFleetProtocolTest(t)
	f.must("finops_worker", func(tx *Tx) error {
		for _, test := range []struct {
			minimum int
			offset  time.Duration
			want    bool
		}{{0, 0, true}, {60, 60*time.Second - time.Microsecond, false}, {60, 60 * time.Second, true}, {3600, 3599 * time.Second, false}, {3600, 3600 * time.Second, true}, {-1, time.Hour, false}} {
			dispatch := time.Now().UTC().Truncate(time.Microsecond)
			var got bool
			if e := tx.QueryRow(f.ctx, "SELECT fleet_observation_elapsed($1,$2,$3)", dispatch, dispatch.Add(test.offset), test.minimum).Scan(&got); e != nil {
				return e
			}
			if got != test.want {
				return fmt.Errorf("observation interval minimum=%d offset=%s got=%t", test.minimum, test.offset, got)
			}
		}
		var missingRejected bool
		if e := tx.QueryRow(f.ctx, "SELECT fleet_observation_elapsed(NULL,clock_timestamp(),60) IS DISTINCT FROM true").Scan(&missingRejected); e != nil {
			return e
		}
		if !missingRejected {
			return errors.New("missing original dispatch proved observation")
		}
		return nil
	})
}

func TestFleetProtocolDatabaseDeadlineDoesNotExtendToParentTTL(t *testing.T) {
	f := newFleetProtocolTest(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	f.must("finops_worker", func(tx *Tx) error {
		for _, test := range []struct {
			created, expires, want time.Time
			duration               int
		}{{now.Add(-2 * time.Hour), now.Add(time.Hour), now.Add(-time.Hour), 3600}, {now, now.Add(30 * time.Minute), now.Add(30 * time.Minute), 3600}} {
			d := model.Document{"created_at": test.created, "expires_at": test.expires, "budget": model.Document{"maximum_duration_seconds": test.duration}}
			raw, _ := json.Marshal(d)
			var got time.Time
			if e := tx.QueryRow(f.ctx, "SELECT fleet_forward_deadline($1::jsonb)", raw).Scan(&got); e != nil {
				return e
			}
			if !got.Equal(test.want) {
				return fmt.Errorf("database forward deadline %s != %s", got, test.want)
			}
		}
		return nil
	})
}

func TestFleetProtocolMalformedCallbackIsInputError(t *testing.T) {
	f := newFleetProtocolTest(t)
	for _, raw := range []string{"{", `{"command_id":"x"}`, `{"unrecognised":true}`, `{} {}`} {
		err := f.run("finops_deployment_observer", func(tx *Tx) error {
			_, _, e := tx.FleetCallbackAppend(f.ctx, "x", "invalid", FleetCallbackSubmission{RawBody: []byte(raw)})
			return e
		})
		if !errors.Is(err, ErrFleetInvalid) {
			t.Fatalf("malformed callback returned %v instead of input error", err)
		}
	}
}
