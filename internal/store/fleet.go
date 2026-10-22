package store

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/fleet"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/jackc/pgx/v5"
)

var ErrFleetConflict = errors.New("FLEET_REPLAY_CONFLICT")
var ErrFleetSource = errors.New("FLEET_SOURCE_INVALID")
var ErrFleetInvalid = errors.New("FLEET_CALLBACK_INVALID")

func (t *Tx) fleetLock(ctx context.Context, workload string) error {
	_, e := t.Exec(ctx, "SELECT fleet_lock($1,$2)", t.Tenant, workload)
	return e
}
func fleetDocument(v any) model.Document {
	b, _ := json.Marshal(v)
	var d model.Document
	_ = json.Unmarshal(b, &d)
	return d
}
func (t *Tx) fleetTyped(ctx context.Context, table, id string, out any) error {
	allowed := map[string]bool{"fleet_plans": true, "fleet_envelopes": true, "fleet_children": true}
	if !allowed[table] {
		return ErrFleetSource
	}
	var raw []byte
	if e := t.QueryRow(ctx, "SELECT document FROM "+table+" WHERE tenant_id=$1 AND id=$2", t.Tenant, id).Scan(&raw); e != nil {
		return e
	}
	return json.Unmarshal(raw, out)
}
func (t *Tx) FleetPlan(ctx context.Context, id string) (model.Document, error) {
	return t.sourceOne(ctx, "SELECT document FROM fleet_plans WHERE tenant_id=$1 AND id=$2", t.Tenant, id)
}
func (t *Tx) FleetPlans(ctx context.Context) ([]model.Document, error) {
	return t.sourceRows(ctx, "SELECT document FROM fleet_plans WHERE tenant_id=$1 ORDER BY created_at,id", t.Tenant)
}
func (t *Tx) FleetTypedPlan(ctx context.Context, id string) (fleet.FleetPlanV4, error) {
	var p fleet.FleetPlanV4
	e := t.fleetTyped(ctx, "fleet_plans", id, &p)
	return p, e
}
func (t *Tx) FleetSigned(ctx context.Context, id string) (fleet.Envelope, error) {
	var p fleet.Envelope
	e := t.fleetTyped(ctx, "fleet_envelopes", id, &p)
	return p, e
}
func (t *Tx) FleetChild(ctx context.Context, id string) (fleet.ChildEnvelope, error) {
	var c fleet.ChildEnvelope
	e := t.fleetTyped(ctx, "fleet_children", id, &c)
	return c, e
}
func (t *Tx) FleetChildren(ctx context.Context, parentID string) ([]model.Document, error) {
	return t.sourceRows(ctx, "SELECT document FROM fleet_children WHERE tenant_id=$1 AND parent_id=$2 ORDER BY (document->'plan'->>'sequence')::numeric,created_at,id", t.Tenant, parentID)
}

// ProofAppend is for private server-selected factories. A console API must never
// expose this document as an input contract. Every source reference is read from
// tenant-owned immutable evidence and hashed here, rather than accepting a flag.
func (t *Tx) FleetProofAppend(ctx context.Context, d model.Document) (model.Document, error) {
	d = model.Clone(d)
	binding := fleetDocument(d["binding"])
	if model.String(binding, "tenant_id") != t.Tenant {
		return nil, ErrFleetSource
	}
	if e := t.fleetLock(ctx, model.String(binding, "workload_id")); e != nil {
		return nil, e
	}
	refs, ok := d["source_refs"].([]any)
	if !ok || len(refs) == 0 || len(refs) > 4096 {
		return nil, ErrFleetSource
	}
	for _, raw := range refs {
		ref := fleetDocument(raw)
		var source model.Document
		var e error
		switch model.String(ref, "table") {
		case "source_receipts":
			source, e = t.SourceReceiptGet(ctx, model.String(ref, "id"))
		case "telemetry_evaluations":
			source, e = t.TelemetryEvaluation(ctx, model.String(ref, "id"))
		case "workload_safety_profiles":
			source, e = t.WorkloadSafetyGet(ctx, model.String(ref, "id"))
		case "slo_evaluations":
			source, e = t.SLOEvaluationGet(ctx, model.String(ref, "id"))
		case "dependency_reviews":
			source, e = t.sourceOne(ctx, "SELECT document FROM dependency_reviews WHERE tenant_id=$1 AND id=$2", t.Tenant, model.String(ref, "id"))
		default:
			return nil, ErrFleetSource
		}
		if e != nil {
			return nil, e
		}
		if fleet.Digest(source) != model.String(ref, "sha256") {
			return nil, ErrFleetSource
		}
		sb := fleetDocument(source["binding"])
		workload := model.String(sb, "workload_id")
		if workload == "" {
			workload = model.String(source, "workload_id")
		}
		if workload != "" && workload != model.String(binding, "workload_id") {
			return nil, ErrFleetSource
		}
		for _, key := range []string{"account_id", "region", "provider"} {
			if value := model.String(sb, key); value != "" && value != model.String(binding, key) {
				return nil, ErrFleetSource
			}
		}
	}
	if model.String(d, "id") == "" {
		d["id"] = model.ID()
	}
	raw, e := json.Marshal(d)
	if e != nil {
		return nil, e
	}
	return t.sourceOne(ctx, "INSERT INTO fleet_proof_sets(tenant_id,id,kind,version,content_hash,document) VALUES($1,$2,$3,$4,$5,$6) RETURNING document", t.Tenant, d["id"], d["kind"], d["version"], fleet.Digest(d), raw)
}
func (t *Tx) FleetProof(ctx context.Context, id string) (model.Document, error) {
	return t.sourceOne(ctx, "SELECT document||jsonb_build_object('hash',content_hash,'writer_role',writer_role,'created_at',created_at) FROM fleet_proof_sets WHERE tenant_id=$1 AND id=$2", t.Tenant, id)
}
func (t *Tx) FleetPlanCreate(ctx context.Context, p fleet.FleetPlanV4) (model.Document, error) {
	if p.Binding.TenantID != t.Tenant {
		return nil, ErrFleetSource
	}
	if e := fleet.ValidatePlan(p, p.Binding, time.Now().UTC()); e != nil {
		return nil, e
	}
	if e := t.fleetLock(ctx, p.Binding.WorkloadID); e != nil {
		return nil, e
	}
	raw, e := json.Marshal(p)
	if e != nil {
		return nil, e
	}
	return t.sourceOne(ctx, "INSERT INTO fleet_plans(tenant_id,id,workload_id,content_hash,document) VALUES($1,$2,$3,$4,$5) RETURNING document", t.Tenant, p.ID, p.Binding.WorkloadID, fleet.Digest(p), raw)
}
func (t *Tx) FleetApprovalAppend(ctx context.Context, parentID string, a fleet.Approval) (model.Document, bool, error) {
	p, e := t.FleetTypedPlan(ctx, parentID)
	if e != nil {
		return nil, false, e
	}
	if e = t.fleetLock(ctx, p.Binding.WorkloadID); e != nil {
		return nil, false, e
	}
	if e = fleet.ValidateApprovals(p, []fleet.Approval{a}, time.Now().UTC()); e != nil {
		return nil, false, e
	}
	old, e := t.sourceOne(ctx, "SELECT document FROM fleet_approvals WHERE tenant_id=$1 AND parent_id=$2 AND actor_id=$3", t.Tenant, parentID, a.ActorID)
	if e == nil {
		if fleet.Digest(old) != fleet.Digest(a) {
			return nil, false, ErrFleetConflict
		}
		return old, true, nil
	}
	if e != pgx.ErrNoRows {
		return nil, false, e
	}
	raw, _ := json.Marshal(a)
	out, e := t.sourceOne(ctx, "INSERT INTO fleet_approvals(tenant_id,id,parent_id,actor_id,document) VALUES($1,$2,$3,$4,$5) RETURNING document", t.Tenant, a.ID, parentID, a.ActorID, raw)
	return out, false, e
}
func (t *Tx) FleetApprovals(ctx context.Context, parentID string) ([]model.Document, error) {
	return t.sourceRows(ctx, "SELECT document FROM fleet_approvals WHERE tenant_id=$1 AND parent_id=$2 ORDER BY created_at,id", t.Tenant, parentID)
}
func (t *Tx) FleetEnvelopeAppend(ctx context.Context, envelope fleet.Envelope, key ed25519.PublicKey) (model.Document, bool, error) {
	if envelope.Plan.Binding.TenantID != t.Tenant {
		return nil, false, ErrFleetSource
	}
	if e := fleet.Verify(envelope, key, envelope.Plan.Binding, time.Now().UTC()); e != nil {
		return nil, false, e
	}
	if e := t.fleetLock(ctx, envelope.Plan.Binding.WorkloadID); e != nil {
		return nil, false, e
	}
	raw, _ := json.Marshal(envelope)
	return t.fleetImmutable(ctx, "fleet_envelopes", envelope.Plan.ID, fleet.Digest(envelope), "INSERT INTO fleet_envelopes(tenant_id,id,content_hash,document) VALUES($1,$2,$3,$4) RETURNING document", raw)
}
func (t *Tx) fleetImmutable(ctx context.Context, table, id, hash, query string, raw []byte) (model.Document, bool, error) {
	if table != "fleet_envelopes" {
		return nil, false, ErrFleetSource
	}
	old, e := t.sourceOne(ctx, "SELECT document||jsonb_build_object('_content_hash',content_hash) FROM "+table+" WHERE tenant_id=$1 AND id=$2", t.Tenant, id)
	if e == nil {
		if model.String(old, "_content_hash") != hash {
			return nil, false, ErrFleetConflict
		}
		delete(old, "_content_hash")
		return old, true, nil
	}
	if e != pgx.ErrNoRows {
		return nil, false, e
	}
	out, e := t.sourceOne(ctx, query, t.Tenant, id, hash, raw)
	return out, false, e
}
func (t *Tx) FleetControlAppend(ctx context.Context, parentID string, expected int64, status, reason string) (model.Document, error) {
	p, e := t.FleetTypedPlan(ctx, parentID)
	if e != nil {
		return nil, e
	}
	if e = t.fleetLock(ctx, p.Binding.WorkloadID); e != nil {
		return nil, e
	}
	var version int64
	if e = t.QueryRow(ctx, "SELECT coalesce(max(version),0) FROM fleet_controls WHERE tenant_id=$1 AND parent_id=$2", t.Tenant, parentID).Scan(&version); e != nil {
		return nil, e
	}
	if expected != version || expected < 0 || expected == int64(^uint64(0)>>1) || reason == "" {
		return nil, ErrConflict
	}
	d := model.Document{"id": model.ID(), "tenant_id": t.Tenant, "parent_id": parentID, "version": version + 1, "status": status, "reason": reason}
	raw, _ := json.Marshal(d)
	return t.sourceOne(ctx, "INSERT INTO fleet_controls(tenant_id,id,parent_id,version,status,document) VALUES($1,$2,$3,$4,$5,$6) RETURNING document", t.Tenant, d["id"], parentID, version+1, status, raw)
}
func (t *Tx) FleetChildAppend(ctx context.Context, c fleet.ChildEnvelope, key ed25519.PublicKey) (model.Document, bool, error) {
	p, e := t.FleetSigned(ctx, c.Plan.ParentID)
	if e != nil {
		return nil, false, e
	}
	if e = t.fleetLock(ctx, p.Plan.Binding.WorkloadID); e != nil {
		return nil, false, e
	}
	var compensation, ownedID any
	if c.Plan.CompensationFor == "" {
		e = fleet.VerifyChild(c, p, key, p.Plan.Binding, time.Now().UTC())
	} else {
		original, err := t.FleetChild(ctx, c.Plan.CompensationFor)
		if err != nil {
			return nil, false, err
		}
		receipt, err := t.FleetOwnedReceiptForChild(ctx, c.Plan.CompensationFor)
		if err != nil {
			return nil, false, err
		}
		e = fleet.VerifyRecovery(c, original, p, receipt, key, p.Plan.Binding, time.Now().UTC())
		compensation, ownedID = c.Plan.CompensationFor, receipt.ID
	}
	if e != nil {
		return nil, false, e
	}
	raw, _ := json.Marshal(c)
	hash := fleet.Digest(c.Plan)
	old, e := t.sourceOne(ctx, "SELECT document||jsonb_build_object('_content_hash',content_hash) FROM fleet_children WHERE tenant_id=$1 AND id=$2", t.Tenant, c.Plan.ID)
	if e == nil {
		if model.String(old, "_content_hash") != hash {
			return nil, false, ErrFleetConflict
		}
		delete(old, "_content_hash")
		return old, true, nil
	}
	if e != pgx.ErrNoRows {
		return nil, false, e
	}
	out, e := t.sourceOne(ctx, "INSERT INTO fleet_children(tenant_id,id,parent_id,stage_id,content_hash,compensation_for,ownership_receipt_id,document) VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING document", t.Tenant, c.Plan.ID, c.Plan.ParentID, c.Plan.StageID, hash, compensation, ownedID, raw)
	return out, false, e
}
func (t *Tx) FleetObserverRegister(ctx context.Context, d model.Document) (model.Document, error) {
	d = model.Clone(d)
	if model.String(d, "id") == "" {
		d["id"] = model.ID()
	}
	raw, e := json.Marshal(d)
	if e != nil {
		return nil, e
	}
	return t.sourceOne(ctx, "INSERT INTO fleet_observer_sources(tenant_id,id,document) VALUES($1,$2,$3) RETURNING document", t.Tenant, d["id"], raw)
}
func (t *Tx) FleetObserverRevoke(ctx context.Context, id, reason string) (model.Document, error) {
	d := model.Document{"source_id": id, "reason": reason}
	raw, _ := json.Marshal(d)
	return t.sourceOne(ctx, "INSERT INTO fleet_observer_revocations(tenant_id,id,source_id,document) VALUES($1,$2,$3,$4) RETURNING document", t.Tenant, model.ID(), id, raw)
}
func (t *Tx) FleetObserver(ctx context.Context, id string) (model.Document, error) {
	return t.sourceOne(ctx, "SELECT document||jsonb_build_object('revoked',EXISTS(SELECT 1 FROM fleet_observer_revocations r WHERE r.tenant_id=fleet_observer_sources.tenant_id AND r.source_id=fleet_observer_sources.id)) FROM fleet_observer_sources WHERE tenant_id=$1 AND id=$2", t.Tenant, id)
}

const fleetExecutionProjection = `document||jsonb_build_object('status',status,'recovery_only',recovery_only,'updated_at',updated_at)`

func (t *Tx) FleetExecution(ctx context.Context, id string) (model.Document, error) {
	return t.sourceOne(ctx, "SELECT "+fleetExecutionProjection+" FROM fleet_executions WHERE tenant_id=$1 AND id=$2", t.Tenant, id)
}
func (t *Tx) FleetExecutions(ctx context.Context) ([]model.Document, error) {
	return t.sourceRows(ctx, "SELECT "+fleetExecutionProjection+" FROM fleet_executions WHERE tenant_id=$1 ORDER BY created_at,id", t.Tenant)
}
func (t *Tx) FleetExecutionCreate(ctx context.Context, parentID, key string) (model.Document, bool, error) {
	if key == "" || len(key) > 200 {
		return nil, false, ErrFleetConflict
	}
	p, e := t.FleetTypedPlan(ctx, parentID)
	if e != nil {
		return nil, false, e
	}
	if e = t.fleetLock(ctx, p.Binding.WorkloadID); e != nil {
		return nil, false, e
	}
	old, e := t.sourceOne(ctx, "SELECT "+fleetExecutionProjection+" FROM fleet_executions WHERE tenant_id=$1 AND parent_id=$2 AND idempotency_key=$3", t.Tenant, parentID, key)
	if e == nil {
		return old, true, nil
	}
	if e != pgx.ErrNoRows {
		return nil, false, e
	}
	out, e := t.sourceOne(ctx, "INSERT INTO fleet_executions(tenant_id,id,parent_id,workload_id,idempotency_key,document) VALUES($1,$2,$3,$4,$5,'{}') RETURNING "+fleetExecutionProjection, t.Tenant, model.ID(), parentID, p.Binding.WorkloadID, key)
	return out, false, e
}
func (t *Tx) FleetExecutionFinish(ctx context.Context, id, status string) (model.Document, error) {
	execution, e := t.FleetExecution(ctx, id)
	if e != nil {
		return nil, e
	}
	if e = t.fleetLock(ctx, model.String(execution, "workload_id")); e != nil {
		return nil, e
	}
	return t.sourceOne(ctx, "UPDATE fleet_executions SET status=$3,updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2 RETURNING "+fleetExecutionProjection, t.Tenant, id, status)
}

const fleetCommandProjection = `c.document||jsonb_build_object('dispatch_intent',s.dispatch_intent,'dispatched_at',s.dispatched_at,'outcome',s.outcome,'owned_receipt_id',s.owned_receipt_id,'health_evidence_id',s.health_evidence_id,'restored',s.restored,'reservation_released_at',r.released_at,'reservation_release_reason',r.release_reason)`

func (t *Tx) FleetCommand(ctx context.Context, id string) (model.Document, error) {
	return t.sourceOne(ctx, "SELECT "+fleetCommandProjection+" FROM fleet_commands c JOIN fleet_command_states s ON s.tenant_id=c.tenant_id AND s.command_id=c.id JOIN fleet_reservations r ON r.tenant_id=c.tenant_id AND r.command_id=c.id WHERE c.tenant_id=$1 AND c.id=$2", t.Tenant, id)
}
func (t *Tx) FleetCommands(ctx context.Context, executionID string) ([]model.Document, error) {
	return t.sourceRows(ctx, "SELECT "+fleetCommandProjection+" FROM fleet_commands c JOIN fleet_command_states s ON s.tenant_id=c.tenant_id AND s.command_id=c.id JOIN fleet_reservations r ON r.tenant_id=c.tenant_id AND r.command_id=c.id WHERE c.tenant_id=$1 AND c.execution_id=$2 ORDER BY c.created_at,c.id", t.Tenant, executionID)
}
func (t *Tx) FleetCommandReserve(ctx context.Context, executionID, childID, key string) (model.Document, bool, error) {
	if key == "" || len(key) > 200 {
		return nil, false, ErrFleetConflict
	}
	execution, e := t.FleetExecution(ctx, executionID)
	if e != nil {
		return nil, false, e
	}
	if e = t.fleetLock(ctx, model.String(execution, "workload_id")); e != nil {
		return nil, false, e
	}
	var id string
	e = t.QueryRow(ctx, "SELECT id FROM fleet_commands WHERE tenant_id=$1 AND execution_id=$2 AND idempotency_key=$3", t.Tenant, executionID, key).Scan(&id)
	if e == nil {
		d, e := t.FleetCommand(ctx, id)
		if e == nil && model.String(d, "child_id") != childID {
			return nil, false, ErrFleetConflict
		}
		return d, true, e
	}
	if e != pgx.ErrNoRows {
		return nil, false, e
	}
	id = model.ID()
	_, e = t.Exec(ctx, "INSERT INTO fleet_commands(tenant_id,id,execution_id,child_id,parent_id,workload_id,idempotency_key,operation,document) VALUES($1,$2,$3,$4,$5,$6,$7,'APPLY','{}')", t.Tenant, id, executionID, childID, execution["parent_id"], execution["workload_id"], key)
	if e != nil {
		return nil, false, e
	}
	out, e := t.FleetCommand(ctx, id)
	return out, false, e
}
func (t *Tx) FleetDispatchMark(ctx context.Context, commandID string) (model.Document, bool, error) {
	cmd, e := t.FleetCommand(ctx, commandID)
	if e != nil {
		return nil, false, e
	}
	if e = t.fleetLock(ctx, model.String(cmd, "workload_id")); e != nil {
		return nil, false, e
	}
	result, e := t.Exec(ctx, "UPDATE fleet_command_states SET dispatch_intent=true,dispatched_at=clock_timestamp(),updated_at=clock_timestamp() WHERE tenant_id=$1 AND command_id=$2 AND NOT dispatch_intent", t.Tenant, commandID)
	if e != nil {
		return nil, false, e
	}
	out, e := t.FleetCommand(ctx, commandID)
	return out, result.RowsAffected() == 1, e
}
func (t *Tx) FleetAuthorize(ctx context.Context, executionID, childID, key string) (model.Document, bool, error) {
	cmd, _, e := t.FleetCommandReserve(ctx, executionID, childID, key)
	if e != nil {
		return nil, false, e
	}
	return t.FleetDispatchMark(ctx, model.String(cmd, "id"))
}

type FleetCallback struct {
	SchemaVersion        string    `json:"schema_version"`
	CommandID            string    `json:"command_id"`
	ChildID              string    `json:"child_id"`
	ChildSHA256          string    `json:"child_sha256"`
	SavedPlanSHA256      string    `json:"saved_plan_sha256"`
	ChildNonce           string    `json:"child_nonce"`
	StateLineage         string    `json:"state_lineage"`
	BeforeStateSerial    uint64    `json:"before_state_serial"`
	AfterStateSerial     uint64    `json:"after_state_serial"`
	Outcome              string    `json:"outcome"`
	ObservedAt           time.Time `json:"observed_at"`
	OldInstanceIDs       []string  `json:"old_instance_ids"`
	CandidateInstanceIDs []string  `json:"candidate_instance_ids"`
	ReasonCode           string    `json:"reason_code,omitempty"`
}
type FleetCallbackSubmission struct {
	SourceID, Issuer, Subject, Audience string
	RawBody                             []byte
}

func (t *Tx) FleetCallbackAppend(ctx context.Context, commandID, key string, in FleetCallbackSubmission) (model.Document, bool, error) {
	if key == "" || len(key) > 200 || len(in.RawBody) > 1<<20 {
		return nil, false, ErrFleetConflict
	}
	var body FleetCallback
	decoder := json.NewDecoder(bytes.NewReader(in.RawBody))
	decoder.DisallowUnknownFields()
	if e := decoder.Decode(&body); e != nil {
		return nil, false, ErrFleetInvalid
	}
	if decoder.Decode(new(any)) != io.EOF || body.ObservedAt.IsZero() {
		return nil, false, ErrFleetInvalid
	}
	if body.CommandID != commandID {
		return nil, false, ErrFleetSource
	}
	cmd, e := t.FleetCommand(ctx, commandID)
	if e != nil {
		return nil, false, e
	}
	if e = t.fleetLock(ctx, model.String(cmd, "workload_id")); e != nil {
		return nil, false, e
	}
	digest := fleet.BytesDigest(in.RawBody)
	source, e := t.FleetObserver(ctx, in.SourceID)
	if e != nil {
		return nil, false, e
	}
	if model.String(source, "issuer") != in.Issuer || model.String(source, "subject") != in.Subject || model.String(source, "audience") != in.Audience {
		return nil, false, ErrFleetSource
	}
	old, e := t.sourceOne(ctx, "SELECT document FROM fleet_callbacks WHERE tenant_id=$1 AND command_id=$2 AND idempotency_key=$3", t.Tenant, commandID, key)
	if e == nil {
		if model.String(old, "body_sha256") != digest || model.String(old, "source_id") != in.SourceID {
			return nil, false, ErrFleetConflict
		}
		return old, true, nil
	}
	if e != pgx.ErrNoRows {
		return nil, false, e
	}
	if model.Bool(source, "revoked") {
		return nil, false, ErrFleetSource
	}
	child, e := t.FleetChild(ctx, model.String(cmd, "child_id"))
	if e != nil {
		return nil, false, e
	}
	id := model.ID()
	var ownedHash any
	if body.Outcome == "APPLIED" {
		owned := fleet.OwnedReceipt{ID: id, ParentID: child.Plan.ParentID, ChildID: child.Plan.ID, ChildSHA256: fleet.Digest(child.Plan), Binding: child.Plan.Binding, PipelineID: child.Plan.IaC.PipelineID, SavedPlanSHA256: child.Plan.SavedPlanSHA256, Status: "APPLIED", BeforeStateSerial: body.BeforeStateSerial, AfterStateSerial: body.AfterStateSerial, ObservedAt: body.ObservedAt}
		ownedHash = fleet.Digest(owned)
	}
	payload := in.RawBody
	out, e := t.sourceOne(ctx, "INSERT INTO fleet_callbacks(tenant_id,id,command_id,source_id,idempotency_key,issuer,subject,audience,body_sha256,owned_hash,raw_body,payload) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING document", t.Tenant, id, commandID, in.SourceID, key, in.Issuer, in.Subject, in.Audience, digest, ownedHash, in.RawBody, payload)
	return out, false, e
}
func (t *Tx) FleetCallbacks(ctx context.Context, commandID string) ([]model.Document, error) {
	return t.sourceRows(ctx, "SELECT document FROM fleet_callbacks WHERE tenant_id=$1 AND command_id=$2 ORDER BY created_at,id", t.Tenant, commandID)
}
func (t *Tx) FleetOwnedReceiptForChild(ctx context.Context, childID string) (fleet.OwnedReceipt, error) {
	var receipt fleet.OwnedReceipt
	var raw []byte
	e := t.QueryRow(ctx, "SELECT f.document->'owned_receipt' FROM fleet_callbacks f JOIN fleet_command_states s ON s.tenant_id=f.tenant_id AND s.owned_receipt_id=f.id JOIN fleet_commands c ON c.tenant_id=s.tenant_id AND c.id=s.command_id WHERE c.tenant_id=$1 AND c.child_id=$2 AND NOT s.restored", t.Tenant, childID).Scan(&raw)
	if e == nil {
		e = json.Unmarshal(raw, &receipt)
	}
	return receipt, e
}
func (t *Tx) FleetHealthEvidenceAppend(ctx context.Context, commandID string, d model.Document) (model.Document, bool, error) {
	cmd, e := t.FleetCommand(ctx, commandID)
	if e != nil {
		return nil, false, e
	}
	if e = t.fleetLock(ctx, model.String(cmd, "workload_id")); e != nil {
		return nil, false, e
	}
	d = model.Clone(d)
	d["command_id"] = commandID
	hash := fleet.Digest(d)
	old, e := t.sourceOne(ctx, "SELECT document FROM fleet_health_evidence WHERE tenant_id=$1 AND command_id=$2 AND content_hash=$3 ORDER BY created_at LIMIT 1", t.Tenant, commandID, hash)
	if e == nil {
		return old, true, nil
	}
	if e != pgx.ErrNoRows {
		return nil, false, e
	}
	raw, _ := json.Marshal(d)
	out, e := t.sourceOne(ctx, "INSERT INTO fleet_health_evidence(tenant_id,id,command_id,content_hash,document) VALUES($1,$2,$3,$4,$5) RETURNING document", t.Tenant, model.ID(), commandID, hash, raw)
	return out, false, e
}
func (t *Tx) FleetReservationRelease(ctx context.Context, commandID, evidenceID string) (model.Document, bool, error) {
	cmd, e := t.FleetCommand(ctx, commandID)
	if e != nil {
		return nil, false, e
	}
	if e = t.fleetLock(ctx, model.String(cmd, "workload_id")); e != nil {
		return nil, false, e
	}
	old, e := t.sourceOne(ctx, "SELECT document FROM fleet_release_events WHERE tenant_id=$1 AND command_id=$2 AND evidence_id=$3", t.Tenant, commandID, evidenceID)
	if e == nil {
		return old, true, nil
	}
	if e != pgx.ErrNoRows {
		return nil, false, e
	}
	out, e := t.sourceOne(ctx, "INSERT INTO fleet_release_events(tenant_id,id,command_id,evidence_id) VALUES($1,$2,$3,$4) RETURNING document", t.Tenant, model.ID(), commandID, evidenceID)
	return out, false, e
}
func (t *Tx) FleetExecutionEvent(ctx context.Context, executionID string, d model.Document) error {
	raw, e := json.Marshal(d)
	if e != nil {
		return e
	}
	_, e = t.Exec(ctx, "INSERT INTO fleet_execution_events(tenant_id,id,execution_id,document) VALUES($1,$2,$3,$4)", t.Tenant, model.ID(), executionID, raw)
	return e
}
