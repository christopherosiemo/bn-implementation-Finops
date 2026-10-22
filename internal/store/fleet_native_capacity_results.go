package store

import (
	"context"
	"encoding/json"
	"errors"
	"sort"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/jackc/pgx/v5"
)

func (t *Tx) fleetCapacityLock(ctx context.Context) error {
	_, e := t.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, t.Tenant+":dependency-graph")
	return e
}

// ScopeAppend publishes the complete original point before member processing.
// Replay returns that exact historical scope even after source invalidation.
func (t *Tx) FleetCapacityBatchScopeAppend(ctx context.Context, requestID, initialSnapshotHash string, d model.Document) (model.Document, bool, error) {
	if e := t.fleetCapacityLock(ctx); e != nil {
		return nil, false, e
	}
	old, e := t.FleetCapacityBatchScopeGet(ctx, requestID)
	if e == nil {
		return old, true, nil
	}
	if e != pgx.ErrNoRows {
		return nil, false, e
	}
	snapshot, e := t.FleetCapacityBatchResolve(ctx, requestID)
	if e != nil {
		return nil, false, e
	}
	if fleetNativeHash(snapshot) != initialSnapshotHash {
		return nil, false, ErrFleetCapacityEvidence
	}
	cloneRaw, e := json.Marshal(d)
	if e != nil {
		return nil, false, e
	}
	d, e = fleetCapacityDecodeDocument(cloneRaw)
	if e != nil {
		return nil, false, e
	}
	d["schema_version"] = "1"
	d["request_id"] = requestID
	scope := sourceDocument(d["scope"])
	scope["snapshot_sha256"] = ""
	d["scope"] = scope
	scope["snapshot_sha256"] = fleetNativeHash(d)
	raw, e := json.Marshal(d)
	if e != nil {
		return nil, false, e
	}
	if len(raw) > 128<<10 {
		return nil, false, ErrFleetCapacityBounds
	}
	_, e = t.Exec(ctx, `INSERT INTO public.fleet_native_capacity_scopes(tenant_id,request_id,content_hash,input_snapshot_hash,document,raw_document) VALUES($1,$2,$3,$4,$5,$6)`, t.Tenant, requestID, fleetNativeHash(d), initialSnapshotHash, raw, raw)
	if e != nil {
		return nil, false, e
	}
	out, e := t.FleetCapacityBatchScopeGet(ctx, requestID)
	return out, false, e
}

// ScopeEvidence resolves only the immutable native rows pinned by the issued
// scope. It is historical readback, never a claim that its sources remain live.
func (t *Tx) FleetCapacityBatchScopeEvidence(ctx context.Context, requestID string) (model.Document, error) {
	d, e := t.FleetCapacityBatchScopeGet(ctx, requestID)
	if e != nil {
		return nil, e
	}
	var pins []struct {
		ReceiptID string `json:"receipt_id"`
	}
	if fleetFixtureDecode(d["source_pins"], &pins) != nil || len(pins) > 4 {
		return nil, ErrFleetCapacityEvidence
	}
	rows := []model.Document{}
	for _, p := range pins {
		r, e := t.fleetCapacityReceipt(ctx, p.ReceiptID)
		if e != nil {
			return nil, e
		}
		pair, e := t.fleetCapacityPair(ctx, r)
		if e != nil {
			return nil, e
		}
		rows = append(rows, pair)
	}
	return model.Document{"scope_record": d, "native_evidence": rows}, nil
}

// MemberInputs supplies current facts only for an instance in the immutable
// roster. An unavailable current group/profile is an explicit gap; it does not
// erase already completed members or admit a different roster generation.
func (t *Tx) FleetCapacityBatchMemberInputs(ctx context.Context, requestID, instance string) (model.Document, error) {
	if e := t.fleetCapacityLock(ctx); e != nil {
		return nil, e
	}
	issued, e := t.FleetCapacityBatchScopeGet(ctx, requestID)
	if e != nil {
		return nil, e
	}
	scope := sourceDocument(issued["scope"])
	allowed := false
	for _, id := range model.Strings(scope, "current_member_ids") {
		if instance == id {
			allowed = true
		}
	}
	if !allowed {
		return nil, ErrFleetCapacityEvidence
	}
	gap := func(reason string) model.Document {
		return model.Document{"scope_record": issued, "instance_id": instance, "current": false, "reason_codes": []string{reason}, "resource": nil, "connection": nil, "hardware": nil, "profile": nil}
	}
	snapshot, e := t.FleetCapacityBatchResolve(ctx, requestID)
	if e != nil {
		if errors.Is(e, ErrConflict) || errors.Is(e, ErrFleetCapacityEvidence) || errors.Is(e, ErrFleetNativeCurrent) || errors.Is(e, pgx.ErrNoRows) {
			return gap("FLEET_CAPACITY_SCOPE_NOT_CURRENT"), nil
		}
		return nil, e
	}
	// Membership/template point receipt IDs must not move during the batch.
	var currentPins []struct {
		Receipt model.Document `json:"receipt"`
	}
	current := []string{}
	for _, kind := range []string{"memberships", "templates"} {
		currentPins = nil
		if fleetFixtureDecode(snapshot[kind], &currentPins) != nil {
			return nil, ErrFleetCapacityEvidence
		}
		for _, p := range currentPins {
			current = append(current, model.String(p.Receipt, "id"))
		}
	}
	pinned := []string{}
	var refs []struct {
		ID string `json:"receipt_id"`
	}
	if fleetFixtureDecode(issued["source_pins"], &refs) != nil {
		return nil, ErrFleetCapacityEvidence
	}
	for _, p := range refs {
		pinned = append(pinned, p.ID)
	}
	sort.Strings(current)
	sort.Strings(pinned)
	if fleetNativeHash(current) != fleetNativeHash(pinned) {
		return gap("FLEET_CAPACITY_POINT_CHANGED"), nil
	}
	selection := sourceDocument(scope["selection"])
	binding := sourceDocument(sourceDocument(selection["groups"])["binding"])
	target := sourceDocument(sourceDocument(binding["old"])["target"])
	matching, e := t.fleetCapacityRows(ctx, `SELECT document||jsonb_build_object('id',id,'version',version) FROM public.entities WHERE tenant_id=$1 AND kind='resources' AND document->>'workload_id'=$2 AND document->>'provider'='AWS' AND document->>'account_id'=$3 AND document->>'region'=$4 AND document->>'provider_resource_id'=$5 ORDER BY id LIMIT 2`, t.Tenant, model.String(target, "workload_id"), model.String(target, "account_id"), model.String(target, "region"), instance)
	if e != nil {
		return nil, e
	}
	if len(matching) != 1 {
		return gap("FLEET_CAPACITY_RESOURCE_MAPPING_UNAVAILABLE"), nil
	}
	resource := matching[0]
	connections, e := t.fleetCapacityRows(ctx, `SELECT `+telemetryConnectionProjection+` FROM public.telemetry_connections c JOIN public.telemetry_source_revisions r ON r.tenant_id=c.tenant_id AND r.connection_id=c.id AND r.connection_version=c.version WHERE c.tenant_id=$1 AND c.config->'binding'->>'workload_id'=$2 AND c.config->'binding'->>'resource_id'=$3 AND c.config->'binding'->>'provider_resource_id'=$4 AND c.config->>'enabled'='true' AND NOT EXISTS(SELECT 1 FROM public.telemetry_source_revocations v WHERE v.tenant_id=r.tenant_id AND v.revision_id=r.id) AND NOT EXISTS(SELECT 1 FROM public.telemetry_connections n WHERE n.tenant_id=c.tenant_id AND n.id=c.id AND n.version>c.version) ORDER BY c.id LIMIT 3`, t.Tenant, model.String(target, "workload_id"), model.String(resource, "id"), instance)
	if e != nil {
		return nil, e
	}
	active := connections
	if len(active) != 1 {
		return gap("FLEET_CAPACITY_TELEMETRY_MAPPING_UNAVAILABLE"), nil
	}
	rawBinding, _ := json.Marshal(binding)
	hardware, e := t.fleetCapacityRows(ctx, `SELECT document||jsonb_build_object('writer_role',writer_role,'created_at',created_at) FROM public.source_receipts WHERE tenant_id=$1 AND id=ANY(public.fleet_native_current_pin_ids($1,$2)) AND kind='AWS_EC2_HARDWARE' AND document->'binding'->>'resource_id'=$3 AND document->'binding'->>'provider_resource_id'=$4 ORDER BY id LIMIT 2`, t.Tenant, rawBinding, model.String(resource, "id"), instance)
	if e != nil {
		return nil, e
	}
	machines := []model.Document{}
	for _, h := range hardware {
		pair, e := t.fleetCapacityPair(ctx, h)
		if e != nil {
			return nil, e
		}
		machines = append(machines, pair)
	}
	if len(machines) != 1 {
		return gap("FLEET_CAPACITY_HARDWARE_UNAVAILABLE"), nil
	}
	return model.Document{"scope_record": issued, "instance_id": instance, "current": true, "reason_codes": []string{}, "resource": resource, "connection": active[0], "hardware": machines[0], "profile": snapshot["profile"]}, nil
}

func (t *Tx) FleetCapacityBatchMemberAppend(ctx context.Context, requestID, inputHash string, d model.Document) (model.Document, bool, error) {
	if e := t.fleetCapacityLock(ctx); e != nil {
		return nil, false, e
	}
	instance := model.String(d, "instance_id")
	old, e := t.fleetCapacityOne(ctx, fleetCapacityMemberProjection+` WHERE m.tenant_id=$1 AND m.request_id=$2 AND m.instance_id=$3`, t.Tenant, requestID, instance)
	if e == nil {
		return old, true, nil
	}
	if e != pgx.ErrNoRows {
		return nil, false, e
	}
	inputs, e := t.FleetCapacityBatchMemberInputs(ctx, requestID, instance)
	if e != nil {
		return nil, false, e
	}
	if fleetNativeHash(inputs) != inputHash {
		return nil, false, ErrFleetCapacityEvidence
	}
	if !model.Bool(inputs, "current") && (model.String(d, "status") != "UNAVAILABLE" || model.Bool(d, "model_evaluated") || model.Bool(d, "model_requested") || d["binding"] != nil || d["hardware"] != nil || d["telemetry"] != nil || d["model_evaluation"] != nil) {
		return nil, false, ErrFleetCapacityEvidence
	}
	raw, e := json.Marshal(d)
	if e != nil {
		return nil, false, e
	}
	if len(raw) > 1<<20 {
		return nil, false, ErrFleetCapacityBounds
	}
	_, e = t.Exec(ctx, `INSERT INTO public.fleet_native_capacity_members(tenant_id,id,request_id,instance_id,content_hash,input_snapshot_hash,document,raw_document) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, t.Tenant, d["id"], requestID, instance, fleetNativeHash(d), inputHash, raw, raw)
	if e != nil {
		return nil, false, e
	}
	out, e := t.FleetCapacityBatchMemberGet(ctx, model.String(d, "id"))
	return out, false, e
}

func (t *Tx) FleetCapacityBatchComplete(ctx context.Context, requestID string, d model.Document) (model.Document, bool, error) {
	if e := t.fleetCapacityLock(ctx); e != nil {
		return nil, false, e
	}
	request, e := t.FleetCapacityBatchGet(ctx, requestID)
	if e != nil {
		return nil, false, e
	}
	if request["batch"] != nil {
		return request, true, nil
	}
	issued, e := t.FleetCapacityBatchScopeGet(ctx, requestID)
	if e != nil {
		return nil, false, e
	}
	if fleetNativeHash(d["scope"]) != fleetNativeHash(issued["scope"]) {
		return nil, false, ErrFleetCapacityEvidence
	}
	raw, e := json.Marshal(d)
	if e != nil {
		return nil, false, e
	}
	if len(raw) > 256<<10 {
		return nil, false, ErrFleetCapacityBounds
	}
	_, e = t.Exec(ctx, `INSERT INTO public.fleet_native_capacity_batches(tenant_id,id,request_id,content_hash,input_snapshot_hash,document,raw_document) VALUES($1,$2,$3,$4,$5,$6,$7)`, t.Tenant, model.ID(), requestID, fleetNativeHash(d), model.String(sourceDocument(issued["scope"]), "snapshot_sha256"), raw, raw)
	if e != nil {
		return nil, false, e
	}
	out, e := t.FleetCapacityBatchGet(ctx, requestID)
	return out, false, e
}
