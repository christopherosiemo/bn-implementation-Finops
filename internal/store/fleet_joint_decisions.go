package store

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

var ErrFleetJointDecision = errors.New("FLEET_JOINT_DECISION_INPUTS_CHANGED")

const jointJoins = ` FROM public.fleet_joint_decision_requests r LEFT JOIN public.fleet_joint_decisions d ON d.tenant_id=r.tenant_id AND d.request_id=r.id LEFT JOIN public.fleet_joint_decision_refusals f ON f.tenant_id=r.tenant_id AND f.request_id=r.id`
const jointProjection = `SELECT r.document||jsonb_build_object('version',1,'created_at',r.created_at,'status',CASE WHEN f.id IS NOT NULL THEN 'REFUSED' WHEN d.id IS NULL THEN 'QUEUED' ELSE 'ASSESSED' END,'decision',d.document,'decision_summary',NULL,'refusal',f.document)` + jointJoins
const jointPageProjection = `SELECT r.document||jsonb_build_object('version',1,'created_at',r.created_at,'status',CASE WHEN f.id IS NOT NULL THEN 'REFUSED' WHEN d.id IS NULL THEN 'QUEUED' ELSE 'ASSESSED' END,'decision',NULL,'refusal',f.document,'decision_summary',CASE WHEN d.id IS NULL THEN NULL ELSE jsonb_build_object('id',d.id,'physical_status',d.document->'physical_status','status','BLOCKED','member_count',jsonb_array_length(d.document->'members'),'scenario',d.document->'scenario','execution_authorized',false,'verified_saving',NULL) END)` + jointJoins

func (t *Tx) FleetJointDecisionGet(ctx context.Context, id string) (model.Document, error) {
	return t.fleetCapacityOne(ctx, jointProjection+` WHERE r.tenant_id=$1 AND r.id=$2`, t.Tenant, id)
}
func (t *Tx) FleetJointDecisionPage(ctx context.Context, workload, after string, limit int) ([]model.Document, error) {
	if workload == "" || limit < 1 || limit > 101 {
		return nil, ErrConflict
	}
	return t.fleetCapacityRows(ctx, jointPageProjection+` WHERE r.tenant_id=$1 AND r.workload_id=$2 AND r.id>$3 ORDER BY r.id LIMIT $4`, t.Tenant, workload, after, limit)
}
func (t *Tx) FleetJointDecisionPending(ctx context.Context, after string, limit int) ([]model.Document, error) {
	if limit < 1 || limit > 101 {
		return nil, ErrConflict
	}
	return t.fleetCapacityRows(ctx, jointProjection+` WHERE r.tenant_id=$1 AND r.id>$2 AND d.id IS NULL AND f.id IS NULL ORDER BY r.id LIMIT $3`, t.Tenant, after, limit)
}

func (t *Tx) fleetJointInputPair(ctx context.Context, assessment, capacity string) (model.Document, error) {
	d, e := t.fleetCapacityOne(ctx, `SELECT public.fleet_joint_decision_inputs($1,$2,$3)`, t.Tenant, assessment, capacity)
	if e != nil {
		var pg *pgconn.PgError
		if errors.As(e, &pg) && pg.Code == "P0001" && strings.HasPrefix(pg.Message, "joint decision ") {
			return nil, ErrFleetJointDecision
		}
		return nil, fleetFixtureError(e)
	}
	return d, nil
}
func jointInputRefs(d model.Document) []any {
	return []any{d["assessment_ref"], d["scope_ref"], d["batch_ref"]}
}

// Request IDs refer to existing035/036 public resources; all document IDs,
// monetary fields and source pins are selected inside the database fence.
func (t *Tx) FleetJointDecisionCreate(ctx context.Context, workload, actor, assessment, capacity string, profileVersion int64) (model.Document, error) {
	if workload == "" || actor == "" || assessment == "" || capacity == "" || profileVersion < 1 {
		return nil, ErrConflict
	}
	in, e := t.fleetJointInputPair(ctx, assessment, capacity)
	if e != nil {
		return nil, e
	}
	observation := sourceDocument(in["assessment"])
	selection := sourceDocument(observation["selection"])
	profile := sourceDocument(selection["safety_profile"])
	groups := sourceDocument(selection["groups"])
	binding := sourceDocument(groups["binding"])
	old := sourceDocument(binding["old"])
	target := sourceDocument(old["target"])
	if model.String(target, "workload_id") != workload || model.Number(profile, "version") != profileVersion {
		return nil, ErrConflict
	}
	id := model.ID()
	d := model.Document{"schema_version": "1", "id": id, "workload_id": workload, "creator_id": actor, "assessment_request_id": assessment, "capacity_batch_request_id": capacity, "selection": selection, "input_refs": jointInputRefs(in), "execution_authorized": false, "verified_saving": nil}
	raw, e := json.Marshal(d)
	if e != nil {
		return nil, e
	}
	_, e = t.Exec(ctx, `INSERT INTO public.fleet_joint_decision_requests(tenant_id,id,workload_id,creator_id,assessment_request_id,capacity_request_id,content_hash,document,raw_document) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, t.Tenant, id, workload, actor, assessment, capacity, fleetNativeHash(d), raw, raw)
	if e != nil {
		return nil, e
	}
	return t.FleetJointDecisionGet(ctx, id)
}

func (t *Tx) FleetJointDecisionInputs(ctx context.Context, id string) (model.Document, error) {
	req, e := t.FleetJointDecisionGet(ctx, id)
	if e != nil {
		return nil, e
	}
	in, e := t.fleetJointInputPair(ctx, model.String(req, "assessment_request_id"), model.String(req, "capacity_batch_request_id"))
	if e != nil {
		return nil, e
	}
	if fleetNativeHash(req["input_refs"]) != fleetNativeHash(jointInputRefs(in)) || fleetNativeHash(req["selection"]) != fleetNativeHash(sourceDocument(in["assessment"])["selection"]) {
		return nil, ErrFleetJointDecision
	}
	return in, nil
}

func (t *Tx) FleetJointDecisionAppend(ctx context.Context, id, inputHash string, d model.Document) (model.Document, bool, error) {
	// Serialize only this readonly analytical queue item, after graph ordering.
	if _, e := t.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, t.Tenant+":dependency-graph"); e != nil {
		return nil, false, e
	}
	if _, e := t.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, t.Tenant+":joint-decision:"+id); e != nil {
		return nil, false, e
	}
	existing, e := t.fleetCapacityOne(ctx, `SELECT document FROM public.fleet_joint_decisions WHERE tenant_id=$1 AND request_id=$2`, t.Tenant, id)
	if e == nil {
		if fleetNativeHash(existing) != fleetNativeHash(d) {
			return nil, false, ErrFleetJointDecision
		}
		out, e := t.FleetJointDecisionGet(ctx, id)
		return out, true, e
	}
	if !errors.Is(e, pgx.ErrNoRows) {
		return nil, false, e
	}
	in, e := t.FleetJointDecisionInputs(ctx, id)
	if e != nil {
		return nil, false, e
	}
	if inputHash != fleetNativeHash(in) {
		return nil, false, ErrFleetJointDecision
	}
	raw, e := json.Marshal(d)
	if e != nil {
		return nil, false, e
	}
	if len(raw) > 2<<20 {
		return nil, false, ErrFleetCapacityBounds
	}
	_, e = t.Exec(ctx, `INSERT INTO public.fleet_joint_decisions(tenant_id,id,request_id,content_hash,input_snapshot_hash,document,raw_document) VALUES($1,$2,$3,$4,$5,$6,$7)`, t.Tenant, d["id"], id, fleetNativeHash(d), inputHash, raw, raw)
	if e != nil {
		return nil, false, e
	}
	out, e := t.FleetJointDecisionGet(ctx, id)
	return out, false, e
}

// Refusal is a terminal analytical outcome, never a substitute decision or a
// source of money/authority. SQL repeats the negative currentness check for
// stale-input reasons; transient locks, transport and permission errors do not
// become terminal outcomes.
func (t *Tx) FleetJointDecisionRefuse(ctx context.Context, id, reason string) (model.Document, bool, error) {
	if reason != "JOINT_DECISION_INPUTS_CHANGED" && reason != "JOINED_MODEL_SUMMARY_UNSUPPORTED" && reason != "RESERVE_ARITHMETIC_OR_UNSUPPORTED_PRECISION" && reason != "RATE_ARITHMETIC_OR_UNSUPPORTED_PRECISION" && reason != "JOINED_INPUT_FORMAT_UNSUPPORTED" {
		return nil, false, ErrConflict
	}
	if _, e := t.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, t.Tenant+":dependency-graph"); e != nil {
		return nil, false, e
	}
	current, e := t.FleetJointDecisionGet(ctx, id)
	if e != nil {
		return nil, false, e
	}
	if current["decision"] != nil || current["refusal"] != nil {
		return current, true, nil
	}
	var now time.Time
	if e = t.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); e != nil {
		return nil, false, e
	}
	d := model.Document{"schema_version": "1", "id": "", "request_id": id, "reason_codes": []string{reason}, "observed_at": now.UTC().Format(time.RFC3339Nano), "execution_authorized": false, "verified_saving": nil}
	d["id"] = "group-joint-refusal-" + fleetNativeHash(d)
	raw, e := json.Marshal(d)
	if e != nil {
		return nil, false, e
	}
	_, e = t.Exec(ctx, `INSERT INTO public.fleet_joint_decision_refusals(tenant_id,id,request_id,content_hash,document,raw_document) VALUES($1,$2,$3,$4,$5,$6)`, t.Tenant, d["id"], id, fleetNativeHash(d), raw, raw)
	if e != nil {
		return nil, false, e
	}
	out, e := t.FleetJointDecisionGet(ctx, id)
	return out, false, e
}
