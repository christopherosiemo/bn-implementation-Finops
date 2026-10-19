package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sort"

	g "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetgroup"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/jackc/pgx/v5"
)

var ErrFleetCapacityEvidence = errors.New("FLEET_CAPACITY_EVIDENCE_CHANGED")
var ErrFleetCapacityBounds = errors.New("FLEET_CAPACITY_INPUT_POPULATION_LIMIT")

func fleetCapacityDecodeDocument(raw []byte) (model.Document, error) {
	var d model.Document
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	e := decoder.Decode(&d)
	return d, e
}
func (t *Tx) fleetCapacityOne(ctx context.Context, q string, args ...any) (model.Document, error) {
	var raw []byte
	if e := t.QueryRow(ctx, q, args...).Scan(&raw); e != nil {
		return nil, e
	}
	return fleetCapacityDecodeDocument(raw)
}
func (t *Tx) fleetCapacityPair(ctx context.Context, d model.Document) (model.Document, error) {
	revision, e := t.fleetCapacityOne(ctx, `SELECT document||jsonb_build_object('writer_role',writer_role,'created_at',created_at) FROM public.source_revisions WHERE tenant_id=$1 AND id=$2`, t.Tenant, model.String(d, "revision_id"))
	if e != nil {
		return nil, e
	}
	return model.Document{"receipt": d, "revision": revision}, nil
}
func (t *Tx) fleetCapacityRows(ctx context.Context, q string, args ...any) ([]model.Document, error) {
	rows, e := t.Query(ctx, q, args...)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []model.Document{}
	for rows.Next() {
		var raw []byte
		if e = rows.Scan(&raw); e != nil {
			return nil, e
		}
		d, e := fleetCapacityDecodeDocument(raw)
		if e != nil {
			return nil, e
		}
		out = append(out, d)
	}
	return out, rows.Err()
}
func (t *Tx) fleetCapacityReceipt(ctx context.Context, id string) (model.Document, error) {
	return t.fleetCapacityOne(ctx, `SELECT document||jsonb_build_object('writer_role',writer_role,'created_at',created_at) FROM public.source_receipts WHERE tenant_id=$1 AND id=$2`, t.Tenant, id)
}

const fleetCapacityProjection = `SELECT r.document||jsonb_build_object('version',1,'created_at',r.created_at,'status',CASE WHEN b.id IS NULL THEN 'QUEUED' ELSE 'ASSESSED' END,'scope',s.document,'batch',b.document) FROM public.fleet_native_capacity_requests r LEFT JOIN public.fleet_native_capacity_scopes s ON s.tenant_id=r.tenant_id AND s.request_id=r.id LEFT JOIN public.fleet_native_capacity_batches b ON b.tenant_id=r.tenant_id AND b.request_id=r.id`

func (t *Tx) FleetCapacityBatchRequestCreate(ctx context.Context, workload, actor, oldID, candidateID string, profileVersion int64) (model.Document, error) {
	if workload == "" || actor == "" || profileVersion < 1 {
		return nil, ErrConflict
	}
	binding, e := t.FleetNativeSelectionCurrent(ctx, oldID, candidateID)
	if e != nil {
		return nil, e
	}
	if binding.Old.Target.WorkloadID != workload {
		return nil, ErrFleetNativeCurrent
	}
	var profileID, profileHash, oldHash, candidateHash string
	var actualVersion int64
	if e = t.QueryRow(ctx, `SELECT id,version,content_hash FROM public.workload_safety_profiles WHERE tenant_id=$1 AND workload_id=$2 ORDER BY version DESC LIMIT 1`, t.Tenant, workload).Scan(&profileID, &actualVersion, &profileHash); e != nil {
		return nil, e
	}
	if actualVersion != profileVersion {
		return nil, ErrConflict
	}
	if e = t.QueryRow(ctx, `SELECT o.content_hash,c.content_hash FROM public.fleet_configuration_proposals o JOIN public.fleet_configuration_proposals c ON c.tenant_id=o.tenant_id WHERE o.tenant_id=$1 AND o.id=$2 AND c.id=$3`, t.Tenant, oldID, candidateID).Scan(&oldHash, &candidateHash); e != nil {
		return nil, e
	}
	id := model.ID()
	d := model.Document{"schema_version": "1", "id": id, "workload_id": workload, "creator_id": actor, "selection": model.Document{"groups": model.Document{"old_configuration_proposal": g.SnapshotRef{ID: oldID, SHA256: oldHash}, "candidate_configuration_proposal": g.SnapshotRef{ID: candidateID, SHA256: candidateHash}, "binding": binding}, "safety_profile": g.VersionedRef{ID: profileID, Version: actualVersion, SHA256: profileHash}}, "execution_authorized": false, "verified_saving": nil}
	raw, e := json.Marshal(d)
	if e != nil {
		return nil, e
	}
	_, e = t.Exec(ctx, `INSERT INTO public.fleet_native_capacity_requests(tenant_id,id,workload_id,creator_id,old_proposal_id,candidate_proposal_id,safety_profile_id,safety_profile_version,content_hash,document,raw_document) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, t.Tenant, id, workload, actor, oldID, candidateID, profileID, actualVersion, fleetNativeHash(d), raw, raw)
	if e != nil {
		return nil, e
	}
	return t.FleetCapacityBatchGet(ctx, id)
}

func (t *Tx) FleetCapacityBatchGet(ctx context.Context, id string) (model.Document, error) {
	return t.fleetCapacityOne(ctx, fleetCapacityProjection+` WHERE r.tenant_id=$1 AND r.id=$2`, t.Tenant, id)
}
func (t *Tx) FleetCapacityBatchPage(ctx context.Context, workload, after string, limit int) ([]model.Document, error) {
	if workload == "" || limit < 1 || limit > 101 {
		return nil, ErrConflict
	}
	return t.fleetCapacityRows(ctx, fleetCapacityProjection+` WHERE r.tenant_id=$1 AND r.workload_id=$2 AND r.id>$3 ORDER BY r.id LIMIT $4`, t.Tenant, workload, after, limit)
}
func (t *Tx) FleetCapacityBatchPending(ctx context.Context, after string, limit int) ([]model.Document, error) {
	if limit < 1 || limit > 101 {
		return nil, ErrConflict
	}
	return t.fleetCapacityRows(ctx, fleetCapacityProjection+` WHERE r.tenant_id=$1 AND r.id>$2 AND b.id IS NULL ORDER BY r.id LIMIT $3`, t.Tenant, after, limit)
}

const fleetCapacityMemberProjection = `SELECT jsonb_build_object('schema_version','1','kind','FLEET_NATIVE_CAPACITY_MEMBER_V1','id',m.id,'request_id',m.request_id,'instance_id',m.instance_id,'sha256',m.content_hash,'member',m.document,'created_at',m.created_at,'writer_role',m.writer_role) FROM public.fleet_native_capacity_members m`
const fleetCapacityMemberSummaryProjection = `SELECT jsonb_build_object('schema_version','1','id',m.id,'request_id',m.request_id,'instance_id',m.instance_id,'sha256',m.content_hash,'status',m.document->>'status','model_evaluated',m.document->'model_evaluated','capacity_suitable',m.document->'capacity_suitable','reason_codes',m.document->'reason_codes','created_at',m.created_at) FROM public.fleet_native_capacity_members m`

func (t *Tx) FleetCapacityBatchMemberGet(ctx context.Context, id string) (model.Document, error) {
	return t.fleetCapacityOne(ctx, fleetCapacityMemberProjection+` WHERE m.tenant_id=$1 AND m.id=$2`, t.Tenant, id)
}
func (t *Tx) FleetCapacityBatchMemberPage(ctx context.Context, requestID, after string, limit int) ([]model.Document, error) {
	if requestID == "" || limit < 1 || limit > 101 {
		return nil, ErrConflict
	}
	return t.fleetCapacityRows(ctx, fleetCapacityMemberSummaryProjection+` WHERE m.tenant_id=$1 AND m.request_id=$2 AND m.id>$3 ORDER BY m.id LIMIT $4`, t.Tenant, requestID, after, limit)
}

// Resolve is the initial private native selection. No financial job, invented
// group resource, caller observations or old017 result is used as a substitute.
// The worker authenticates the exact versioned raw objects before ScopeAppend.
func (t *Tx) FleetCapacityBatchResolve(ctx context.Context, requestID string) (model.Document, error) {
	r, e := t.FleetCapacityBatchGet(ctx, requestID)
	if e != nil {
		return nil, e
	}
	selection := sourceDocument(r["selection"])
	groups := sourceDocument(selection["groups"])
	oldID := model.String(sourceDocument(groups["old_configuration_proposal"]), "id")
	candidateID := model.String(sourceDocument(groups["candidate_configuration_proposal"]), "id")
	current, e := t.FleetNativeSelectionCurrent(ctx, oldID, candidateID)
	if e != nil {
		return nil, e
	}
	var originallySelected g.Binding
	if fleetFixtureDecode(groups["binding"], &originallySelected) != nil || g.Digest(current) != g.Digest(originallySelected) {
		return nil, ErrFleetCapacityEvidence
	}
	profile, e := t.WorkloadSafetyLatest(ctx, current.Old.Target.WorkloadID)
	if e != nil {
		return nil, e
	}
	selectedProfile := sourceDocument(selection["safety_profile"])
	if model.String(profile, "id") != model.String(selectedProfile, "id") || model.String(profile, "hash") != model.String(selectedProfile, "sha256") || model.Number(profile, "version") != model.Number(selectedProfile, "version") {
		return nil, ErrFleetCapacityEvidence
	}
	sources := []string{current.Old.SourceID}
	if current.Candidate.SourceID != current.Old.SourceID {
		sources = append(sources, current.Candidate.SourceID)
	}
	sort.Strings(sources)
	registrations := model.Document{}
	for _, id := range sources {
		d, e := t.SourceGet(ctx, id)
		if e != nil {
			return nil, e
		}
		registrations[id] = d
	}
	rawBinding, _ := json.Marshal(current)
	var ids []string
	var metadataBytes int64
	if e = t.QueryRow(ctx, `SELECT coalesce(array_agg(id ORDER BY id),ARRAY[]::text[]),coalesce(sum(octet_length(document::text)),0) FROM public.source_receipts WHERE tenant_id=$1 AND id=ANY(public.fleet_native_current_pin_ids($1,$2)) AND kind IN('AWS_FLEET_MEMBERSHIP','AWS_FLEET_LAUNCH_TEMPLATES')`, t.Tenant, rawBinding).Scan(&ids, &metadataBytes); e != nil {
		return nil, e
	}
	if len(ids) > 4 || metadataBytes > 8<<20 {
		return nil, ErrFleetCapacityBounds
	}
	memberships, templates, hardware := []model.Document{}, []model.Document{}, []model.Document{}
	instanceIDs := []string{}
	for _, id := range ids {
		d, e := t.fleetCapacityReceipt(ctx, id)
		if e != nil {
			return nil, e
		}
		p, e := t.fleetCapacityPair(ctx, d)
		if e != nil {
			return nil, e
		}
		switch model.String(d, "kind") {
		case "AWS_FLEET_MEMBERSHIP":
			memberships = append(memberships, p)
			if model.String(d, "history_registration_id") == current.Old.Registration.ID {
				var body struct {
					Groups []struct {
						Members []struct {
							ID string `json:"instance_id"`
						} `json:"members"`
					} `json:"groups"`
				}
				if fleetFixtureDecode(d, &body) != nil || len(body.Groups) != 1 || len(body.Groups[0].Members) > 256 {
					return nil, ErrFleetCapacityBounds
				}
				for _, m := range body.Groups[0].Members {
					instanceIDs = append(instanceIDs, m.ID)
				}
			}
		case "AWS_FLEET_LAUNCH_TEMPLATES":
			templates = append(templates, p)
		case "AWS_EC2_HARDWARE":
			hardware = append(hardware, p)
		}
	}
	// Individual hardware/resources/connections are selected only by MemberInputs.
	// The initial roster never materializes a fleet's entire hardware catalogue.
	return model.Document{"selection": selection, "profile": profile, "registrations": registrations, "memberships": memberships, "templates": templates, "hardware": hardware, "resources": []model.Document{}, "connections": []model.Document{}}, nil
}

func (t *Tx) FleetCapacityBatchScopeGet(ctx context.Context, requestID string) (model.Document, error) {
	return t.fleetCapacityOne(ctx, `SELECT document FROM public.fleet_native_capacity_scopes WHERE tenant_id=$1 AND request_id=$2`, t.Tenant, requestID)
}

func fleetCapacityNotFound(e error) bool { return errors.Is(e, pgx.ErrNoRows) }
