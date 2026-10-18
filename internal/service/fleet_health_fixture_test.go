package service

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/evidence"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/fleet"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/slo"
	trustedsource "github.com/christopherosiemo/bn-implementation-Finops/internal/source"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/telemetry"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/workload"
)

// These fixtures exercise the private protocol and real role-separated SQL
// publication boundary. The native metadata checkpoints and parent non-SLO
// proofs are labelled protocol fixtures, not a live AWS/S3/ClickHouse/customer
// pipeline acceptance claim. SLI receipts and owned callback timestamps use the
// real PostgreSQL receive clock; no ingress backfill or clock override exists.
type fleetCohortProtocolFixture struct {
	*fleetHealthProtocolTest
	api           *API
	binding       fleet.Binding
	objective     slo.Objective
	profile       model.Document
	registration  model.Document
	sources       map[string]slo.Source
	connections   map[string]model.Document
	nativeMinutes map[string]map[int64][]telemetry.Segment
	blue, green   []string
	private       ed25519.PrivateKey
}

func newFleetCohortProtocolFixture(t *testing.T, greenCount ...int) *fleetCohortProtocolFixture {
	f := &fleetCohortProtocolFixture{fleetHealthProtocolTest: newFleetHealthProtocolTest(t), sources: map[string]slo.Source{}, connections: map[string]model.Document{}, nativeMinutes: map[string]map[int64][]telemetry.Segment{}, private: ed25519.NewKeyFromSeed(make([]byte, 32))}
	f.api = &API{Store: f.db}
	f.binding = fleet.Binding{TenantID: f.tenant, ResourceID: "logical-fleet", WorkloadID: "workload", Provider: "AWS", ProviderResourceID: "asg-blue", AccountID: "111122223333", Region: "eu-west-1"}
	for i := 1; i <= 20; i++ {
		f.blue = append(f.blue, fmt.Sprintf("i-%017x", i))
	}
	count := 2
	if len(greenCount) > 0 {
		count = greenCount[0]
	}
	for i := 100; i < 100+count; i++ {
		f.green = append(f.green, fmt.Sprintf("i-%017x", i))
	}
	f.must("finops_api", func(tx *store.Tx) error {
		if _, e := tx.Exec(f.ctx, "INSERT INTO tenant_registry(tenant_id) VALUES($1)", f.tenant); e != nil {
			return e
		}
		if _, e := tx.Create(f.ctx, "workloads", model.Document{"id": f.binding.WorkloadID, "environment": "NON_PRODUCTION"}); e != nil {
			return e
		}
		if _, e := tx.Create(f.ctx, "resources", model.Document{"id": f.binding.ResourceID, "workload_id": f.binding.WorkloadID, "provider": "AWS", "provider_resource_id": "asg-blue", "account_id": f.binding.AccountID, "region": f.binding.Region}); e != nil {
			return e
		}
		for _, id := range append(append([]string{}, f.blue...), f.green...) {
			if _, e := tx.Create(f.ctx, "resources", model.Document{"id": "physical-" + id, "workload_id": f.binding.WorkloadID, "provider": "AWS", "provider_resource_id": id, "account_id": f.binding.AccountID, "region": f.binding.Region}); e != nil {
				return e
			}
		}
		p := workload.Profile{SchemaVersion: "1", Criticality: "NON_PRODUCTION", Statefulness: "STATELESS", Timezone: "UTC", MinReplicas: 1, MinZones: 1, Headroom: workload.Headroom{CPUFreePPM: 300000, MemoryFreePPM: 300000, ReserveAboveForecastPPM: 300000}, Saturation: workload.Saturation{CPUP99PPM: 850000, MemoryP99PPM: 850000}, RTOSeconds: 900, MaxSimultaneousChangePPM: 100000, VMCooldownSeconds: 600}
		var e error
		f.profile, e = tx.WorkloadSafetyAppend(f.ctx, f.binding.WorkloadID, 0, p)
		if e != nil {
			return e
		}
		f.registration, e = tx.SourceCreate(f.ctx, trustedsource.FixtureRegistration(f.tenant, "membership-source"))
		return e
	})
	f.installObjective()
	f.observe(time.Now().UTC().Truncate(time.Minute))
	return f
}

func (f *fleetCohortProtocolFixture) installObjective() {
	_, o, _, _, _, _ := fleetHealthWindowFixture(2)
	f.must("finops_api", func(tx *store.Tx) error {
		d, e := tx.SLOObjectiveAppend(f.ctx, f.binding.WorkloadID, f.objective.Version, slo.Document(o))
		if e != nil {
			return e
		}
		f.objective, e = slo.ParseObjective(d)
		if e != nil {
			return e
		}
		for _, id := range append(append([]string{}, f.blue...), f.green...) {
			s := slo.Source{SchemaVersion: "1", ID: fmt.Sprintf("sli-%d-%s", f.objective.Version, id), TenantID: f.tenant, ObjectiveID: f.objective.ID, WorkloadID: f.binding.WorkloadID, ResourceID: "physical-" + id, ProviderResourceID: id, AccountID: f.binding.AccountID, Region: f.binding.Region, Issuer: "https://machine.invalid", Subject: "independent-sli-gateway", Enabled: true}
			s, e = tx.SLORegister(f.ctx, s)
			if e != nil {
				return e
			}
			f.sources[id] = s
		}
		return nil
	})
}

func (f *fleetCohortProtocolFixture) observe(end time.Time) {
	f.observeMembers(end, append(append([]string{}, f.blue...), f.green...))
}

func (f *fleetCohortProtocolFixture) observeMembers(end time.Time, ids []string) {
	f.t.Helper()
	start := end.Add(-2 * time.Minute)
	for _, id := range ids {
		s := f.sources[id]
		f.must("finops_activity", func(tx *store.Tx) error {
			for at := start; at.Before(end); at = at.Add(time.Minute) {
				lo, hi := int64(99), int64(100)
				in := slo.Interval{SchemaVersion: "1", SourceID: s.ID, ObjectiveID: s.ObjectiveID, WorkloadID: s.WorkloadID, ResourceID: s.ResourceID, Sequence: at.Add(time.Minute).Unix() / 60, IntervalStart: at, IntervalEnd: at.Add(time.Minute), RequestCount: 1000, AvailabilityGoodSeconds: 60, AvailabilityTotalSeconds: 60, Latency: slo.Histogram{Unit: "milliseconds", SampleCount: 1000, Buckets: []slo.Bucket{{UpperBoundMS: &lo}, {UpperBoundMS: &hi, Count: 1000}, {}}}}
				raw, _ := json.Marshal(in)
				if _, _, e := tx.SLOAppend(f.ctx, store.SLOSubmission{Interval: in, RawBody: raw, Issuer: s.Issuer, Subject: s.Subject, IdempotencyKey: fmt.Sprintf("minute-%d", in.Sequence)}); e != nil {
					return e
				}
			}
			return nil
		})
		f.native(id, start, end)
	}
}

func (f *fleetCohortProtocolFixture) native(id string, start, end time.Time) {
	f.t.Helper()
	c := f.connections[id]
	if c == nil {
		connection := telemetry.Connection{SchemaVersion: "1", ID: "native-" + id, Version: 1, Kind: "PROMETHEUS", ReadBindingID: "private-protocol-prometheus", Enabled: true, Binding: telemetry.Binding{TenantID: f.tenant, ResourceID: "physical-" + id, WorkloadID: f.binding.WorkloadID, Provider: "AWS", ProviderResourceID: id, AccountID: f.binding.AccountID, Region: f.binding.Region}, Definitions: []telemetry.Definition{}}
		for _, metric := range []string{"cpu_utilization", "memory_utilization"} {
			connection.Definitions = append(connection.Definitions, telemetry.Definition{ID: metric, Version: "1", Metric: metric, Name: metric, Unit: "ratio", Type: "GAUGE", CadenceSeconds: 60, MaxGapSeconds: 120, Attributes: map[string]string{}, ResourceAttributes: map[string]string{}})
		}
		f.must("finops_api", func(tx *store.Tx) error {
			var e error
			c, e = tx.TelemetryConnectionAppend(f.ctx, connection.ID, 0, telemetry.Document(connection))
			return e
		})
		f.connections[id] = c
	}
	typed, e := telemetry.ParseConnection(c)
	if e != nil {
		f.t.Fatal(e)
	}
	if f.nativeMinutes[id] == nil {
		f.nativeMinutes[id] = map[int64][]telemetry.Segment{}
	}
	segments := []telemetry.Segment{}
	for at := start; at.Before(end); at = at.Add(time.Minute) {
		if f.nativeMinutes[id][at.Unix()] == nil {
			if at.Before(time.Now().UTC().Truncate(time.Minute).Add(-2 * time.Minute)) {
				f.t.Fatal("native protocol collector missed an actual minute; history cannot be fabricated")
			}
			for _, def := range typed.Definitions {
				f.nativeMinutes[id][at.Unix()] = append(f.nativeMinutes[id][at.Unix()], telemetry.Segment{ID: model.ID(), DefinitionID: def.ID, StreamID: id + def.ID, Metric: def.Metric, Type: "GAUGE", Unit: "ratio", Start: at, End: at.Add(time.Minute), Status: "OBSERVED", Value: "0.25", SampleIDs: []string{model.ID()}, RawHashes: []string{strings.Repeat("a", 64)}})
			}
		}
		segments = append(segments, f.nativeMinutes[id][at.Unix()]...)
	}
	evaluation := telemetry.EvaluateWindow(telemetry.WindowInput{Now: end, Definitions: typed.Definitions, Segments: segments, Minutes: int(end.Sub(start) / time.Minute), RequiredMetrics: []string{"cpu_utilization", "memory_utilization"}})
	if evaluation.Status != "READY" {
		f.t.Fatal("private native fixture", evaluation.ReasonCodes, evaluation.Metrics)
	}
	d := model.Document{"binding": c["binding"], "source_kind": "PROMETHEUS", "raw_sha256": strings.Repeat("a", 64), "canonical_hash": strings.Repeat("b", 64), "collected_at": time.Now().UTC(), "start": start, "end": end, "query_start": start, "query_end": end, "sample_count": len(segments), "rejection_count": 0, "warning_count": 0}
	var receipt model.Document
	f.must("finops_telemetry_reader", func(tx *store.Tx) error {
		batch, _, e := tx.TelemetryBatchPrepare(f.ctx, typed.ID, model.String(c, "config_hash"), fmt.Sprintf("native-%s-%d-%d", model.String(c, "config_hash")[:12], start.Unix(), end.Unix()), d)
		if e != nil {
			return e
		}
		if _, _, e = tx.TelemetryCheckpointAppend(f.ctx, model.String(batch, "id"), "RAW_PERSISTED", model.Document{"bucket": "private-protocol-raw", "key": "tenant/" + f.tenant + "/native/fixture.raw", "version_id": "protocol-only-version", "body_sha256": d["raw_sha256"]}); e != nil {
			return e
		}
		if _, _, e = tx.TelemetryCheckpointAppend(f.ctx, model.String(batch, "id"), "ANALYTICS_PERSISTED", model.Document{"database": "finops", "table": "native_telemetry", "write_id": batch["id"], "canonical_hash": d["canonical_hash"], "sample_count": d["sample_count"], "canonical_bucket": "private-protocol-raw", "canonical_key": "tenant/" + f.tenant + "/native/fixture.canonical", "canonical_version_id": "protocol-canonical-version", "canonical_body_sha256": strings.Repeat("c", 64)}); e != nil {
			return e
		}
		receipt, _, e = tx.TelemetryPublish(f.ctx, model.String(batch, "id"))
		return e
	})
	f.must("finops_api", func(tx *store.Tx) error {
		_, e := tx.TelemetryEvaluationCreate(f.ctx, model.Document{"connection_id": typed.ID, "config_hash": c["config_hash"], "receipt_ids": []string{model.String(receipt, "id")}, "evaluation": telemetry.Document(evaluation)})
		return e
	})
}

func (f *fleetCohortProtocolFixture) membership(child *fleet.ChildEnvelope, oldIDs, greenIDs []string) model.Document {
	f.t.Helper()
	position, childID, childHash, parentID := "DISCOVERY", "", "", ""
	if child != nil {
		position, childID, childHash, parentID = "AFTER", child.Plan.ID, fleet.Digest(child.Plan), child.Plan.ParentID
	}
	config := trustedsource.ConfigurationHash(f.registration)
	revisionID := model.ID()
	d := model.Document{"id": model.ID(), "source_id": "membership-source", "revision_id": revisionID, "kind": "AWS_FLEET_MEMBERSHIP", "binding": evidence.Object(f.binding), "parent_id": parentID, "child_id": childID, "child_sha256": childHash, "position": position, "old_asg": "asg-blue", "candidate_asg": "asg-green", "old_instance_ids": fleetHealthSorted(oldIDs), "candidate_instance_ids": fleetHealthSorted(greenIDs), "groups": []model.Document{{"name": "asg-blue", "minimum": len(oldIDs), "desired": len(oldIDs), "maximum": len(oldIDs)}, {"name": "asg-green", "minimum": len(greenIDs), "desired": len(greenIDs), "maximum": len(greenIDs)}}, "collected_at": time.Now().UTC(), "registration_version": 1, "read_role_binding_id": "fixture-payer", "config_hash": config, "raw_object": model.Document{"bucket": "private-protocol-native", "key": "tenant/" + f.tenant + "/fleet/private-protocol.raw", "version_id": "private-protocol-version", "body_sha256": strings.Repeat("a", 64)}}
	f.must("finops_ingester", func(tx *store.Tx) error {
		if _, e := tx.SourceRevisionCreate(f.ctx, model.Document{"id": revisionID, "source_id": "membership-source", "revision_hash": fleet.Digest(d), "config_hash": config, "registration_version": 1}); e != nil {
			return e
		}
		_, e := tx.SourceReceiptCreate(f.ctx, d)
		return e
	})
	return d
}

func (f *fleetCohortProtocolFixture) privateProof(kind string, b fleet.Binding, expires time.Time) fleet.ProofRef {
	d := model.Document{"id": model.ID(), "kind": kind, "version": "1", "binding": evidence.Object(b), "expires_at": expires, "source_refs": []model.Document{{"table": "private-protocol-fixture", "id": "not-a-live-factory"}}}
	f.must("finops_api", func(tx *store.Tx) error {
		raw, _ := json.Marshal(d)
		_, e := tx.Exec(f.ctx, "INSERT INTO fleet_proof_sets(tenant_id,id,kind,version,content_hash,document) VALUES($1,$2,$3,'1',$4,$5)", f.tenant, d["id"], kind, fleet.Digest(d), raw)
		return e
	})
	return fleet.ProofRef{Kind: kind, ID: model.String(d, "id"), Version: "1", SHA256: fleet.Digest(d), ObservedAt: time.Now().UTC(), ExpiresAt: expires}
}

func (f *fleetCohortProtocolFixture) parent(baseline model.Document, legacy ...bool) fleet.Envelope {
	return f.parentPolicy(baseline, len(legacy) > 0 && legacy[0], false, false)
}

func (f *fleetCohortProtocolFixture) parentPolicy(baseline model.Document, legacy, cleanup, testPolicy bool) fleet.Envelope {
	now := time.Now().UTC()
	p := fleet.Plan{SchemaVersion: "4", Kind: fleet.Kind, ID: model.ID(), Binding: f.binding, CreatorID: "requester", Environment: "NON_PRODUCTION", IaC: fleet.IaCBinding{Authority: "TERRAFORM", Repository: "https://github.com/customer/config", GitCommit: strings.Repeat("a", 40), Workspace: "sandbox", StateLineage: "private-protocol-lineage", StateSerial: 10, ConfigurationSHA256: strings.Repeat("b", 64), TerraformVersion: "1.13.3", PipelineID: "private-protocol-pipeline"}, Governance: fleet.Governance{RiskClass: "R2", Enabled: true, PolicyID: "private-protocol-policy", PolicyVersion: 1, PolicySHA256: strings.Repeat("c", 64), ApproverRole: fleet.ApproverRole}, Old: fleet.Cohort{ID: "asg-blue", ASGAddress: "aws_autoscaling_group.blue", LaunchTemplateAddress: "aws_launch_template.blue", LaunchTemplateVersion: 1, InstanceType: "m6i.4xlarge", DesiredCount: 20, Stateless: true}, Candidate: fleet.Cohort{ID: "asg-green", ASGAddress: "aws_autoscaling_group.green", LaunchTemplateAddress: "aws_launch_template.green", LaunchTemplateVersion: 2, InstanceType: "m6i.2xlarge", Stateless: true}, Traffic: fleet.TrafficControl{Authority: "CUSTOMER_TERRAFORM_PIPELINE", Address: "aws_lb_listener_rule.app", OldTargetGroupARN: "arn:aws:elasticloadbalancing:eu-west-1:111122223333:targetgroup/blue/id", CandidateTargetGroupARN: "arn:aws:elasticloadbalancing:eu-west-1:111122223333:targetgroup/green/id"}, Budget: fleet.Budget{BaselineCount: 20, MaxInFlight: 2, MaxUnavailable: 2, MaxBlastRadiusPPM: 100000, MaxSurgeCount: 20, Currency: "GBP", MaximumCost: "48", OldInstanceHourlyCost: "0.4", CandidateInstanceHourlyCost: "0.2", MaximumDurationSeconds: 14400}, CreatedAt: now, ExpiresAt: now.Add(5 * time.Hour), Nonce: model.ID()}
	for _, kind := range []string{"NATIVE_HISTORY", "CAPACITY_ASSESSMENT", "WORKLOAD_SAFETY_PROFILE", "CONFIGURATION_AUTHORITY", "DEPENDENCY_REVIEW", "BILLING_PRICE"} {
		p.Proofs = append(p.Proofs, f.privateProof(kind, p.Binding, now.Add(5*time.Hour)))
	}
	if cleanup {
		p.Budget.MaximumDurationSeconds = 18000
		p.Budget.MaximumCost = "60"
		p.ExpiresAt = now.Add(6 * time.Hour)
	}
	if legacy {
		// Synthetic legacy protocol envelope only; no historical telemetry or
		// pre-plan baseline is fabricated. Owned callbacks keep real DB clocks.
		p.CreatedAt, p.ExpiresAt = now.Add(-4*time.Hour+45*time.Second), now.Add(46*time.Second)
		p.Proofs = append(p.Proofs, f.privateProof("SLO_EVALUATION", p.Binding, now.Add(5*time.Hour)))
	} else {
		var baselineExpiry time.Time
		_ = fleetHealthDecode(baseline["expires_at"], &baselineExpiry)
		p.Proofs = append(p.Proofs, fleet.ProofRef{Kind: "SLO_EVALUATION", ID: model.String(baseline, "proof_id"), Version: "1", SHA256: model.String(baseline, "proof_hash"), ObservedAt: now, ExpiresAt: baselineExpiry})
	}
	p.Stages = fleet.DefaultStages(p, cleanup)
	if testPolicy {
		for i := range p.Stages {
			if p.Stages[i].Kind != fleet.Prepare {
				p.Stages[i].MinimumObservationSeconds = 120
			}
		}
	}
	f.must("finops_api", func(tx *store.Tx) error { _, e := tx.FleetPlanCreate(f.ctx, p); return e })
	approval := fleet.Approval{ID: model.ID(), TenantID: f.tenant, ActorID: "independent-approver", Role: fleet.ApproverRole, PlanSHA256: fleet.Digest(p), ApprovedAt: now}
	f.must("finops_api", func(tx *store.Tx) error { _, _, e := tx.FleetApprovalAppend(f.ctx, p.ID, approval); return e })
	envelope, e := fleet.Sign(p, []fleet.Approval{approval}, f.private, now)
	if e != nil {
		f.t.Fatal(e)
	}
	f.must("finops_signer", func(tx *store.Tx) error {
		_, _, e := tx.FleetEnvelopeAppend(f.ctx, envelope, f.private.Public().(ed25519.PublicKey))
		return e
	})
	f.must("finops_api", func(tx *store.Tx) error {
		_, e := tx.FleetObserverRegister(f.ctx, model.Document{"id": "observer-" + p.ID, "pipeline_id": p.IaC.PipelineID, "issuer": "https://machine.invalid", "subject": "private-protocol-observer", "audience": "finops-deployment-observer", "binding": evidence.Object(p.Binding)})
		return e
	})
	return envelope
}

func (f *fleetCohortProtocolFixture) child(parent fleet.Envelope, stage int, sequence uint64, transition fleet.Transition) fleet.ChildEnvelope {
	now := time.Now().UTC()
	s := parent.Plan.Stages[stage]
	iac := parent.Plan.IaC
	iac.ConfigurationSHA256 = s.ConfigurationSHA256
	f.must("finops_api", func(tx *store.Tx) error {
		return tx.QueryRow(f.ctx, `SELECT greatest($3::bigint,coalesce(max((callback.document->>'after_state_serial')::bigint),$3::bigint)) FROM fleet_callbacks callback JOIN fleet_commands command ON command.tenant_id=callback.tenant_id AND command.id=callback.command_id WHERE callback.tenant_id=$1 AND command.parent_id=$2`, f.tenant, parent.Plan.ID, iac.StateSerial).Scan(&iac.StateSerial)
	})
	c := fleet.ChildPlan{SchemaVersion: "4", ID: model.ID(), ParentID: parent.Plan.ID, ParentSHA256: fleet.Digest(parent.Plan), StageID: s.ID, StageSHA256: fleet.Digest(s), Sequence: sequence, Binding: f.binding, IaC: iac, SavedPlanSHA256: strings.Repeat("d", 64), PlanJSONSHA256: strings.Repeat("e", 64), Changes: []fleet.AllowedChange{}, Transition: transition, CreatedAt: now, ExpiresAt: now.Add(10 * time.Minute), Nonce: model.ID()}
	c.SavedPlanSHA256 = fleet.Digest(model.Document{"private_protocol_saved_plan": c.ID, "transition": transition, "state_serial": iac.StateSerial})
	c.PlanJSONSHA256 = fleet.Digest(model.Document{"private_protocol_plan_json": c.ID, "transition": transition})
	if c.ExpiresAt.After(fleet.ForwardDeadline(parent.Plan)) {
		c.ExpiresAt = fleet.ForwardDeadline(parent.Plan)
	}
	for _, kind := range []string{"NATIVE_CURRENT", "WORKLOAD_SAFETY_PROFILE", "DEPENDENCY_REVIEW", "SLO_EVALUATION", "INCIDENT_STATE", "HEALTH_CHECK", "CANDIDATE_HEALTH"} {
		c.Proofs = append(c.Proofs, f.privateProof(kind, f.binding, now.Add(10*time.Minute)))
	}
	signed, e := fleet.SignChild(c, parent, f.private, now)
	if e != nil {
		f.t.Fatal(e)
	}
	f.must("finops_signer", func(tx *store.Tx) error {
		_, _, e := tx.FleetChildAppend(f.ctx, signed, f.private.Public().(ed25519.PublicKey))
		return e
	})
	return signed
}

func (f *fleetCohortProtocolFixture) execution(parent fleet.Envelope) model.Document {
	var out model.Document
	f.must("finops_api", func(tx *store.Tx) error {
		var e error
		out, _, e = tx.FleetExecutionCreate(f.ctx, parent.Plan.ID, "private-protocol-start")
		return e
	})
	return out
}

func (f *fleetCohortProtocolFixture) apply(parent fleet.Envelope, child fleet.ChildEnvelope, execution model.Document, outcome string) model.Document {
	var command model.Document
	f.must("finops_worker", func(tx *store.Tx) error {
		var e error
		command, _, e = tx.FleetAuthorize(f.ctx, model.String(execution, "id"), child.Plan.ID, child.Plan.ID)
		return e
	})
	callback := store.FleetCallback{SchemaVersion: "4", CommandID: model.String(command, "id"), ChildID: child.Plan.ID, ChildSHA256: fleet.Digest(child.Plan), SavedPlanSHA256: child.Plan.SavedPlanSHA256, ChildNonce: child.Plan.Nonce, StateLineage: child.Plan.IaC.StateLineage, BeforeStateSerial: child.Plan.IaC.StateSerial, AfterStateSerial: child.Plan.IaC.StateSerial + 1, Outcome: outcome, ObservedAt: time.Now().UTC(), OldInstanceIDs: append([]string{}, f.blue[:child.Plan.Transition.OldAfter]...), CandidateInstanceIDs: append([]string{}, f.green[:child.Plan.Transition.CandidateAfter]...)}
	if outcome == "NO_OP" {
		callback.AfterStateSerial = callback.BeforeStateSerial
	}
	raw, _ := json.Marshal(callback)
	f.must("finops_deployment_observer", func(tx *store.Tx) error {
		_, _, e := tx.FleetCallbackAppend(f.ctx, model.String(command, "id"), "callback", store.FleetCallbackSubmission{SourceID: "observer-" + parent.Plan.ID, Issuer: "https://machine.invalid", Subject: "private-protocol-observer", Audience: "finops-deployment-observer", RawBody: raw})
		return e
	})
	f.must("finops_worker", func(tx *store.Tx) error {
		var e error
		command, e = tx.FleetCommand(f.ctx, model.String(command, "id"))
		return e
	})
	return command
}

func (f *fleetCohortProtocolFixture) recovery(parent fleet.Envelope, original fleet.ChildEnvelope) fleet.ChildEnvelope {
	now := time.Now().UTC()
	var owned fleet.OwnedReceipt
	f.must("finops_api", func(tx *store.Tx) error {
		var e error
		owned, e = tx.FleetOwnedReceiptForChild(f.ctx, original.Plan.ID)
		return e
	})
	c := original.Plan
	c.ID, c.Sequence, c.CreatedAt, c.ExpiresAt, c.Nonce = model.ID(), original.Plan.Sequence+1, now, now.Add(10*time.Minute), model.ID()
	c.CompensationFor, c.CompensationReceiptSHA256 = original.Plan.ID, fleet.Digest(owned)
	c.IaC.StateSerial = owned.AfterStateSerial
	c.Transition = fleet.Transition{OldBefore: original.Plan.Transition.OldAfter, OldAfter: original.Plan.Transition.OldBefore, CandidateBefore: original.Plan.Transition.CandidateAfter, CandidateAfter: original.Plan.Transition.CandidateBefore, TrafficBefore: original.Plan.Transition.TrafficAfter, TrafficAfter: original.Plan.Transition.TrafficBefore, InFlight: original.Plan.Transition.InFlight, Unavailable: original.Plan.Transition.Unavailable}
	signed, e := fleet.SignRecovery(c, original, parent, owned, f.private, now)
	if e != nil {
		f.t.Fatal(e)
	}
	f.must("finops_signer", func(tx *store.Tx) error {
		_, _, e := tx.FleetChildAppend(f.ctx, signed, f.private.Public().(ed25519.PublicKey))
		return e
	})
	return signed
}
