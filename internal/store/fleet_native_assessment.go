package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"time"

	g "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetgroup"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/jackc/pgx/v5"
)

var ErrFleetNativeCurrent = errors.New("FLEET_NATIVE_SELECTION_NOT_CURRENT")
var ErrFleetNativeEvidence = errors.New("FLEET_NATIVE_EVIDENCE_CHANGED")
var ErrFleetNativeBounds = errors.New("FLEET_NATIVE_INPUT_POPULATION_LIMIT")

func fleetNativeHash(v any) string {
	raw, _ := json.Marshal(v)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func (t *Tx) FleetNativeSelectionCurrent(ctx context.Context, oldID, candidateID string) (g.Binding, error) {
	var out g.Binding
	var raw []byte
	if e := t.QueryRow(ctx, `SELECT public.fleet_native_selection_current($1,$2,$3)`, t.Tenant, oldID, candidateID).Scan(&raw); e != nil {
		return out, fleetFixtureError(e)
	}
	if raw == nil || json.Unmarshal(raw, &out) != nil || g.ValidateBinding(out) != nil {
		return out, ErrFleetNativeCurrent
	}
	return out, nil
}

func (t *Tx) FleetNativeAssessmentRequestCreate(ctx context.Context, workload, actor, oldID, candidateID string, profileVersion int64) (model.Document, error) {
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
	var profileID, profileHash string
	var actualVersion int64
	if e = t.QueryRow(ctx, `SELECT id,version,content_hash FROM public.workload_safety_profiles WHERE tenant_id=$1 AND workload_id=$2 ORDER BY version DESC LIMIT 1`, t.Tenant, workload).Scan(&profileID, &actualVersion, &profileHash); e != nil {
		return nil, e
	}
	if actualVersion != profileVersion {
		return nil, ErrConflict
	}
	var oldHash, candidateHash string
	if e = t.QueryRow(ctx, `SELECT o.content_hash,c.content_hash FROM public.fleet_configuration_proposals o JOIN public.fleet_configuration_proposals c ON c.tenant_id=o.tenant_id WHERE o.tenant_id=$1 AND o.id=$2 AND c.id=$3`, t.Tenant, oldID, candidateID).Scan(&oldHash, &candidateHash); e != nil {
		return nil, e
	}
	id := model.ID()
	d := model.Document{"schema_version": "1", "id": id, "workload_id": workload, "creator_id": actor, "selection": model.Document{"groups": model.Document{"old_configuration_proposal": g.SnapshotRef{ID: oldID, SHA256: oldHash}, "candidate_configuration_proposal": g.SnapshotRef{ID: candidateID, SHA256: candidateHash}, "binding": binding}, "safety_profile": g.VersionedRef{ID: profileID, Version: actualVersion, SHA256: profileHash}}, "execution_authorized": false, "verified_saving": nil}
	raw, e := json.Marshal(d)
	if e != nil {
		return nil, e
	}
	_, e = t.Exec(ctx, `INSERT INTO public.fleet_native_assessment_requests(tenant_id,id,workload_id,creator_id,old_proposal_id,candidate_proposal_id,safety_profile_id,safety_profile_version,content_hash,document,raw_document) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, t.Tenant, id, workload, actor, oldID, candidateID, profileID, actualVersion, fleetNativeHash(d), raw, raw)
	if e != nil {
		return nil, e
	}
	return t.FleetNativeAssessmentGet(ctx, id)
}

const fleetNativeProjection = `SELECT r.document||jsonb_build_object('version',1,'created_at',r.created_at,'status',CASE WHEN a.id IS NULL THEN 'QUEUED' ELSE 'ASSESSED' END,'assessment',a.document) FROM public.fleet_native_assessment_requests r LEFT JOIN public.fleet_native_assessments a ON a.tenant_id=r.tenant_id AND a.request_id=r.id`

func (t *Tx) FleetNativeAssessmentGet(ctx context.Context, id string) (model.Document, error) {
	return t.sourceOne(ctx, fleetNativeProjection+` WHERE r.tenant_id=$1 AND r.id=$2`, t.Tenant, id)
}
func (t *Tx) FleetNativeAssessmentPage(ctx context.Context, workload, after string, limit int) ([]model.Document, error) {
	if workload == "" || limit < 1 || limit > 101 {
		return nil, ErrConflict
	}
	return t.sourceRows(ctx, fleetNativeProjection+` WHERE r.tenant_id=$1 AND r.workload_id=$2 AND r.id>$3 ORDER BY r.id LIMIT $4`, t.Tenant, workload, after, limit)
}
func (t *Tx) FleetNativeAssessmentPending(ctx context.Context, after string, limit int) ([]model.Document, error) {
	if limit < 1 || limit > 101 {
		return nil, ErrConflict
	}
	return t.sourceRows(ctx, fleetNativeProjection+` WHERE r.tenant_id=$1 AND r.id>$2 AND a.id IS NULL ORDER BY r.id LIMIT $3`, t.Tenant, after, limit)
}

func (t *Tx) fleetNativePair(ctx context.Context, d model.Document) (model.Document, error) {
	revision, e := t.SourceRevisionGet(ctx, model.String(d, "revision_id"))
	if e != nil {
		return nil, e
	}
	return model.Document{"receipt": d, "revision": revision}, nil
}
func (t *Tx) fleetNativeNewest(ctx context.Context, source, kind, history string) (model.Document, error) {
	rows, e := t.sourceRows(ctx, `SELECT document||jsonb_build_object('writer_role',writer_role,'created_at',created_at) FROM public.source_receipts WHERE tenant_id=$1 AND source_id=$2 AND kind=$3 AND ($4='' OR document->>'history_registration_id'=$4) ORDER BY (document->>'collected_at')::timestamptz DESC NULLS LAST,created_at DESC,id DESC LIMIT 2`, t.Tenant, source, kind, history)
	if e != nil {
		return nil, e
	}
	if len(rows) == 0 {
		return nil, nil
	}
	// Same native instant with different raw contents is not an economic order.
	first, _ := time.Parse(time.RFC3339Nano, model.String(rows[0], "collected_at"))
	if len(rows) > 1 {
		second, _ := time.Parse(time.RFC3339Nano, model.String(rows[1], "collected_at"))
		if !first.IsZero() && first.Equal(second) {
			var a, b struct {
				Raw model.Document `json:"raw_object"`
			}
			_ = fleetFixtureDecode(rows[0], &a)
			_ = fleetFixtureDecode(rows[1], &b)
			if model.String(a.Raw, "body_sha256") != model.String(b.Raw, "body_sha256") {
				return nil, ErrFleetNativeEvidence
			}
		}
	}
	return t.fleetNativePair(ctx, rows[0])
}

// This private bounded resolver selects authentic current rows. The transport
// decoder separately reads every exact versioned raw pin. No HTTP input can
// supply any receipt, source selection, price, population or result ID.
func (t *Tx) FleetNativeAssessmentSnapshot(ctx context.Context, requestID string) (model.Document, error) {
	request, e := t.FleetNativeAssessmentGet(ctx, requestID)
	if e != nil {
		return nil, e
	}
	var selected struct {
		Groups struct {
			Old       g.SnapshotRef `json:"old_configuration_proposal"`
			Candidate g.SnapshotRef `json:"candidate_configuration_proposal"`
			Binding   g.Binding     `json:"binding"`
		} `json:"groups"`
		Profile g.VersionedRef `json:"safety_profile"`
	}
	if e = fleetFixtureDecode(request["selection"], &selected); e != nil {
		return nil, e
	}
	current, e := t.FleetNativeSelectionCurrent(ctx, selected.Groups.Old.ID, selected.Groups.Candidate.ID)
	if e != nil {
		return nil, e
	}
	if g.Digest(current) != g.Digest(selected.Groups.Binding) {
		return nil, ErrFleetNativeCurrent
	}
	var profileID, profileHash string
	var profileVersion int64
	if e = t.QueryRow(ctx, `SELECT id,version,content_hash FROM public.workload_safety_profiles WHERE tenant_id=$1 AND workload_id=$2 ORDER BY version DESC LIMIT 1`, t.Tenant, current.Old.Target.WorkloadID).Scan(&profileID, &profileVersion, &profileHash); e != nil {
		return nil, e
	}
	if selected.Profile != (g.VersionedRef{ID: profileID, Version: profileVersion, SHA256: profileHash}) {
		return nil, ErrFleetNativeCurrent
	}
	registrations := model.Document{}
	memberships := []model.Document{}
	templates := []model.Document{}
	hardware := []model.Document{}
	billing := []model.Document{}
	sources := []string{current.Old.SourceID}
	if current.Candidate.SourceID != current.Old.SourceID {
		sources = append(sources, current.Candidate.SourceID)
	}
	sort.Strings(sources)
	for _, id := range sources {
		reg, e := t.SourceGet(ctx, id)
		if e != nil {
			return nil, e
		}
		registrations[id] = reg
		pair, e := t.fleetNativeNewest(ctx, id, "AWS_FLEET_LAUNCH_TEMPLATES", "")
		if e != nil {
			return nil, e
		}
		if pair != nil {
			templates = append(templates, pair)
		}
	}
	for _, s := range []g.Selection{current.Old, current.Candidate} {
		pair, e := t.fleetNativeNewest(ctx, s.SourceID, "AWS_FLEET_MEMBERSHIP", s.Registration.ID)
		if e != nil {
			return nil, e
		}
		if pair != nil {
			memberships = append(memberships, pair)
		}
	}
	// Choose the latest capture before checking ambiguity. Filtering conflicts
	// first could silently resurrect an older hardware observation.
	rows, e := t.sourceRows(ctx, `SELECT document||jsonb_build_object('writer_role',writer_role,'created_at',created_at) FROM (SELECT DISTINCT ON(document->'binding'->>'provider_resource_id') * FROM public.source_receipts WHERE tenant_id=$1 AND source_id=ANY($2) AND kind='AWS_EC2_HARDWARE' AND document->'binding'->>'workload_id'=$3 ORDER BY document->'binding'->>'provider_resource_id',(document->>'collected_at')::timestamptz DESC,created_at DESC,id DESC) h WHERE NOT EXISTS(SELECT 1 FROM public.source_receipts n WHERE n.tenant_id=h.tenant_id AND n.source_id=h.source_id AND n.kind=h.kind AND n.document->'binding'->>'provider_resource_id'=h.document->'binding'->>'provider_resource_id' AND (n.document->>'collected_at')::timestamptz=(h.document->>'collected_at')::timestamptz AND n.document->'raw_object'->>'body_sha256' IS DISTINCT FROM h.document->'raw_object'->>'body_sha256') ORDER BY id LIMIT 513`, t.Tenant, sources, current.Old.Target.WorkloadID)
	if e != nil {
		return nil, e
	}
	for _, d := range rows {
		pair, e := t.fleetNativePair(ctx, d)
		if e != nil {
			return nil, e
		}
		hardware = append(hardware, pair)
	}
	commitment, e := t.sourceOne(ctx, `SELECT document||jsonb_build_object('writer_role',writer_role,'created_at',created_at) FROM public.source_receipts WHERE tenant_id=$1 AND source_id=$2 AND kind='AWS_COMMITMENT' ORDER BY created_at DESC,id DESC LIMIT 1`, t.Tenant, current.Old.SourceID)
	if e != nil && e != pgx.ErrNoRows {
		return nil, e
	}
	if commitment == nil {
		commitment = model.Document{}
	}
	heads, e := t.sourceRows(ctx, `SELECT r.document||jsonb_build_object('writer_role',r.writer_role,'created_at',r.created_at,'_selected_head',c.document->>'receipt_id') FROM public.source_checkpoints c JOIN public.source_receipts r ON r.tenant_id=c.tenant_id AND r.id=c.document->>'receipt_id' WHERE c.tenant_id=$1 AND c.source_id=$2 AND c.checkpoint_key LIKE $3 AND r.kind='AWS_CUR2' AND r.source_id=$2 ORDER BY c.checkpoint_key LIMIT 25`, t.Tenant, current.Old.SourceID, "month:"+current.Old.SourceConfigSHA256+":%")
	if e != nil {
		return nil, e
	}
	jobIDs := []string{}
	for _, head := range heads {
		jobIDs = append(jobIDs, model.String(head, "ingestion_job_id"))
	}
	// Do not materialize full raw+canonical jobs and only afterwards discover
	// that the worker's snapshot budget was exceeded. The selected head rows
	// and source guard are already held; PostgreSQL computes these lengths
	// before any job document crosses the driver boundary.
	var jobBytes, jobRows int64
	if e = t.QueryRow(ctx, `SELECT coalesce(sum(octet_length(document::text)),0),coalesce(sum(CASE WHEN jsonb_typeof(document->'raw'->'records')='array' THEN jsonb_array_length(document->'raw'->'records') ELSE 100001 END),0) FROM unnest($2::text[]) wanted(id) JOIN public.entities ON tenant_id=$1 AND kind='ingestion_jobs' AND entities.id=wanted.id`, t.Tenant, jobIDs).Scan(&jobBytes, &jobRows); e != nil {
		return nil, e
	}
	if jobBytes > 32<<20 || jobRows > 100000 {
		return nil, ErrFleetNativeBounds
	}
	for _, d := range heads {
		head := model.String(d, "_selected_head")
		delete(d, "_selected_head")
		revision, e := t.SourceRevisionGet(ctx, model.String(d, "revision_id"))
		if e != nil {
			return nil, e
		}
		job, e := t.Get(ctx, "ingestion_jobs", model.String(d, "ingestion_job_id"))
		if e != nil {
			return nil, e
		}
		billing = append(billing, model.Document{"receipt": d, "revision": revision, "job": job, "current_receipt_id": head})
	}
	return model.Document{"selection": sourceDocument(request["selection"])["groups"], "registrations": registrations, "memberships": memberships, "templates": templates, "hardware": hardware, "billing_source_id": current.Old.SourceID, "commitment": commitment, "billing": billing}, nil
}

// Each returned017 result is bound to its own real instance/resource and the
// latest privately selected hardware receipt. It never proves group capacity.
func (t *Tx) FleetNativeAssessmentMembers(ctx context.Context, requestID string, snapshot model.Document) ([]model.Document, error) {
	request, e := t.FleetNativeAssessmentGet(ctx, requestID)
	if e != nil {
		return nil, e
	}
	var refs []struct {
		Receipt model.Document `json:"receipt"`
	}
	if e = fleetFixtureDecode(snapshot["hardware"], &refs); e != nil {
		return nil, e
	}
	ids := []string{}
	for _, r := range refs {
		ids = append(ids, model.String(r.Receipt, "id"))
	}
	return t.sourceRows(ctx, `SELECT jsonb_build_object('instance_id',a.document->'binding'->>'provider_resource_id','resource_id',a.resource_id,'result_id',a.id,'result_sha256',a.content_hash,'hardware_receipt_id',a.hardware_receipt_id,'status',a.document->>'status','demand_meaning',CASE WHEN a.document->'model_evaluation'->>'model_version'='capacity-weekday-block-v2' AND EXISTS(SELECT 1 FROM jsonb_array_elements(a.document->'model_evaluation'->'metrics') m WHERE m->>'name'='demand' AND m->>'semantic_role'='REQUEST_THROUGHPUT_PROXY' AND m->>'source_metric'='request_count' AND m->>'source_unit' IN('count','requests') AND m->>'unit'=(m->>'source_unit')||'/second' AND m->>'statistic'='OBSERVED_INTERVAL_RATE' AND coalesce(m->'denominator','null')='null'::jsonb) THEN 'REQUEST_THROUGHPUT_PROXY' WHEN a.document->'model_evaluation'->>'model_version'='capacity-weekday-block-v1' THEN 'LEGACY_UNPROVEN_PROXY' ELSE 'UNAVAILABLE' END) FROM (SELECT DISTINCT ON(resource_id) * FROM public.native_capacity_results WHERE tenant_id=$1 AND workload_id=$2 ORDER BY resource_id,created_at DESC,id DESC) a JOIN public.entities r ON r.tenant_id=a.tenant_id AND r.kind='resources' AND r.id=a.resource_id JOIN public.source_receipts h ON h.tenant_id=a.tenant_id AND h.id=a.hardware_receipt_id JOIN public.telemetry_source_revisions tr ON tr.tenant_id=a.tenant_id AND tr.id=a.revision_id WHERE a.safety_profile_id=$3 AND a.hardware_receipt_id=ANY($4) AND a.document->'binding'->>'provider_resource_id'=r.document->>'provider_resource_id' AND r.document->>'workload_id'=a.workload_id AND r.document->>'provider'='AWS' AND r.document->>'account_id'=a.document->'binding'->>'account_id' AND r.document->>'region'=a.document->'binding'->>'region' AND h.document->'resource_version'=to_jsonb(r.version) AND NOT EXISTS(SELECT 1 FROM public.telemetry_source_revocations v WHERE v.tenant_id=tr.tenant_id AND v.revision_id=tr.id) AND NOT EXISTS(SELECT 1 FROM public.telemetry_connections c WHERE c.tenant_id=tr.tenant_id AND c.id=tr.connection_id AND c.version>tr.connection_version) ORDER BY a.resource_id LIMIT 257`, t.Tenant, model.String(request, "workload_id"), model.String(sourceDocument(sourceDocument(request["selection"])["safety_profile"]), "id"), ids)
}

func sourceDocument(v any) model.Document {
	raw, _ := json.Marshal(v)
	out := model.Document{}
	_ = json.Unmarshal(raw, &out)
	return out
}

// Publication repeats selection, source/head and resource/profile resolution
// under the same database guards through INSERT+COMMIT. Readback alone cannot
// turn a formerly current snapshot into new authority after a correction.
func (t *Tx) FleetNativeAssessmentAppend(ctx context.Context, requestID, snapshotHash string, d model.Document) (model.Document, bool, error) {
	// Acquire the same graph guard before the replay read as the current
	// resolver uses. Concurrent private publications then observe the first
	// immutable result instead of racing its unique request constraint.
	if _, e := t.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, t.Tenant+":dependency-graph"); e != nil {
		return nil, false, e
	}
	old, e := t.FleetNativeAssessmentGet(ctx, requestID)
	if e != nil {
		return nil, false, e
	}
	if old["assessment"] != nil {
		return old, true, nil
	}
	snapshot, e := t.FleetNativeAssessmentSnapshot(ctx, requestID)
	if e != nil {
		return nil, false, e
	}
	if fleetNativeHash(snapshot) != snapshotHash {
		return nil, false, ErrFleetNativeEvidence
	}
	members, e := t.FleetNativeAssessmentMembers(ctx, requestID, snapshot)
	if e != nil {
		return nil, false, e
	}
	var published []model.Document
	if e = fleetFixtureDecode(sourceDocument(d["capacity"])["members"], &published); e != nil {
		return nil, false, e
	}
	allowed := map[string]string{}
	for _, m := range members {
		allowed[model.String(m, "instance_id")] = fleetNativeHash(m)
	}
	for _, m := range published {
		if allowed[model.String(m, "instance_id")] != fleetNativeHash(m) {
			return nil, false, ErrFleetNativeEvidence
		}
	}
	raw, e := json.Marshal(d)
	if e != nil {
		return nil, false, e
	}
	if len(raw) > 1<<20 || model.String(d, "id") == "" || model.String(d, "status") != "BLOCKED" || model.Bool(d, "execution_authorized") {
		return nil, false, ErrFleetNativeEvidence
	}
	_, e = t.Exec(ctx, `INSERT INTO public.fleet_native_assessments(tenant_id,id,request_id,content_hash,input_snapshot_hash,document,raw_document) VALUES($1,$2,$3,$4,$5,$6,$7)`, t.Tenant, d["id"], requestID, fleetNativeHash(d), snapshotHash, raw, raw)
	if e != nil {
		return nil, false, e
	}
	out, e := t.FleetNativeAssessmentGet(ctx, requestID)
	return out, false, e
}

// Keep the independently observed publication clock available to workers.
func (t *Tx) FleetNativeAssessmentNow(ctx context.Context) (time.Time, error) {
	var now time.Time
	e := t.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now)
	return now.UTC(), e
}
