package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/fleetfixture"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/fleetgroup"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

var ErrFleetFixtureBusy = errors.New("FLEET_FIXTURE_SOURCE_BUSY")

func fleetFixtureError(e error) error {
	var p *pgconn.PgError
	if errors.As(e, &p) && p.Code == "55P03" {
		return ErrFleetFixtureBusy
	}
	return e
}
func fleetFixtureDecode(v any, out any) error {
	raw, e := json.Marshal(v)
	if e != nil {
		return e
	}
	return json.Unmarshal(raw, out)
}
func FleetFixtureProposalDocument(d model.Document) (fleetfixture.Proposal, error) {
	var p fleetfixture.Proposal
	e := fleetFixtureDecode(d["proposal"], &p)
	return p, e
}

// Installation is private commissioning metadata, never a public image/URL or
// command input. The producer verifies its actual toolchain before this call.
func (t *Tx) FleetFixtureProfileInstall(ctx context.Context, in fleetfixture.Installation) (fleetfixture.Profile, error) {
	var p fleetfixture.Profile
	var modelRaw []byte
	var modelHash string
	if e := t.QueryRow(ctx, `SELECT model,model_hash FROM public.fleet_fixture_profile_templates WHERE id=$1`, in.TemplateID).Scan(&modelRaw, &modelHash); e != nil {
		return p, e
	}
	if e := json.Unmarshal(modelRaw, &p.Model); e != nil {
		return p, e
	}
	p.SchemaVersion = "1"
	p.ID = "fixture-profile-" + model.ID()
	p.Generation = model.ID()
	p.Name = "Isolated built-in Terraform group fixture"
	p.RealmKind = fleetgroup.IsolatedFixture
	p.ModelKind = fleetgroup.BuiltinFixtureArtifact
	p.ModelVersion = fleetgroup.GitSchemaVersion
	p.ModelSHA256 = modelHash
	p.Installation = in
	raw, e := json.Marshal(p)
	if e != nil {
		return p, e
	}
	_, e = t.Exec(ctx, `INSERT INTO public.fleet_fixture_profiles(id,generation,content_hash,document,raw_document) VALUES($1,$2,$3,$4,$5)`, p.ID, p.Generation, fleetgroup.BytesDigest(raw), raw, raw)
	return p, e
}

func (t *Tx) FleetFixtureProfiles(ctx context.Context) ([]model.Document, error) {
	return t.sourceRows(ctx, `SELECT document||jsonb_build_object('hash',content_hash) FROM public.fleet_fixture_profiles ORDER BY id`)
}

// Profiles are a shared immutable model catalog. Bound the public read before
// transporting JSON; tenant scoping belongs to the API's opaque page cursor.
func (t *Tx) FleetFixtureProfilePage(ctx context.Context, after string, limit int) ([]model.Document, error) {
	if limit < 1 || limit > 101 {
		return nil, fleetfixture.ErrSelection
	}
	return t.sourceRows(ctx, `SELECT document||jsonb_build_object('hash',content_hash) FROM public.fleet_fixture_profiles WHERE id>$1 ORDER BY id LIMIT $2`, after, limit)
}

func (t *Tx) FleetFixtureProfile(ctx context.Context, id string) (fleetfixture.Profile, error) {
	var p fleetfixture.Profile
	var raw []byte
	e := t.QueryRow(ctx, `SELECT document FROM public.fleet_fixture_profiles WHERE id=$1`, id).Scan(&raw)
	if e == nil {
		e = json.Unmarshal(raw, &p)
	}
	return p, e
}

func (t *Tx) FleetFixtureSelectionCurrent(ctx context.Context, old, candidate string) (fleetgroup.Binding, error) {
	var b fleetgroup.Binding
	var raw []byte
	e := t.QueryRow(ctx, `SELECT public.fleet_fixture_selection_current($1,$2,$3)`, t.Tenant, old, candidate).Scan(&raw)
	if e != nil {
		return b, fleetFixtureError(e)
	}
	if raw == nil {
		return b, fleetfixture.ErrCurrent
	}
	e = json.Unmarshal(raw, &b)
	return b, e
}
func (t *Tx) FleetFixtureCurrent(ctx context.Context, id string) (fleetfixture.Proposal, error) {
	var p fleetfixture.Proposal
	var raw []byte
	e := t.QueryRow(ctx, `SELECT public.fleet_fixture_proposal_current($1,$2)`, t.Tenant, id).Scan(&raw)
	if e != nil {
		return p, fleetFixtureError(e)
	}
	if raw == nil {
		return p, fleetfixture.ErrCurrent
	}
	e = json.Unmarshal(raw, &p)
	return p, e
}

func (t *Tx) FleetFixtureProposalCreate(ctx context.Context, actor string, in fleetfixture.SelectionRequest) (model.Document, error) {
	if !fleetfixture.Actor(actor) {
		return nil, fleetfixture.ErrSelection
	}
	raw, _ := json.Marshal(in)
	if _, e := fleetfixture.DecodeSelection(raw); e != nil {
		return nil, e
	}
	b, e := t.FleetFixtureSelectionCurrent(ctx, in.OldConfigurationProposalID, in.CandidateConfigurationProposalID)
	if e != nil {
		return nil, e
	}
	if e = fleetgroup.ValidateBinding(b); e != nil {
		return nil, e
	}
	profile, e := t.FleetFixtureProfile(ctx, in.FixtureProfileID)
	if e != nil {
		return nil, e
	}
	old, e := t.FleetConfigurationProposalGet(ctx, in.OldConfigurationProposalID)
	if e != nil {
		return nil, e
	}
	candidate, e := t.FleetConfigurationProposalGet(ctx, in.CandidateConfigurationProposalID)
	if e != nil {
		return nil, e
	}
	ref := func(d model.Document) fleetfixture.ConfigurationRef {
		return fleetfixture.ConfigurationRef{ID: model.String(d, "id"), SHA256: model.String(d, "hash"), ScopeReferenceRoot: model.String(d, "scope_reference_root"), CustomerStatus: "BLOCKED", CustomerReasons: model.Strings(d, "reason_codes")}
	}
	p := fleetfixture.Proposal{SchemaVersion: "1", ID: model.ID(), Purpose: "ISOLATED_GROUP_FIXTURE_PROPOSAL", CreatorID: actor, WorkloadID: b.Old.Target.WorkloadID, Profile: profile, Realm: fleetgroup.Realm{Kind: profile.RealmKind, FixtureID: profile.ID, Generation: profile.Generation, ModelSHA256: profile.ModelSHA256}, Binding: b, Old: ref(old), Candidate: ref(candidate)}
	raw, e = json.Marshal(p)
	if e != nil {
		return nil, e
	}
	_, e = t.Exec(ctx, `INSERT INTO public.fleet_fixture_proposals(tenant_id,id,workload_id,profile_id,profile_generation,old_configuration_proposal_id,candidate_configuration_proposal_id,content_hash,document,raw_document) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, t.Tenant, p.ID, p.WorkloadID, profile.ID, profile.Generation, old["id"], candidate["id"], fleetgroup.BytesDigest(raw), raw, raw)
	if e != nil {
		return nil, fleetFixtureError(e)
	}
	return t.FleetFixtureProposalGet(ctx, p.ID)
}

// Version is a projection of immutable milestones, not an UPDATE to history:
// selected=1, privately prepared=2, independently approved=3.
const fleetFixtureProjection = `SELECT jsonb_build_object('id',p.id,'version',1+CASE WHEN g.id IS NULL THEN 0 ELSE 1 END+CASE WHEN a.id IS NULL THEN 0 ELSE 1 END,'status',CASE WHEN a.id IS NOT NULL THEN 'APPROVED' WHEN g.id IS NOT NULL THEN 'AWAITING_APPROVAL' ELSE 'WAITING_FOR_PROGRAM' END,'proposal',p.document,'hash',p.content_hash,'created_at',p.created_at,'writer_role',p.writer_role,'prepared_program',CASE WHEN g.id IS NULL THEN NULL ELSE jsonb_build_object('id',g.id,'program_hash',g.program_hash,'manifest_hash',g.manifest_hash,'journal_review_hash',g.journal_review_hash,'proof_hash',g.proof_hash,'created_at',g.created_at,'producer_role',g.producer_role,'expires_at',g.program->'expires_at') END,'approval',CASE WHEN a.id IS NULL THEN NULL ELSE a.document||jsonb_build_object('hash',a.content_hash,'created_at',a.created_at,'writer_role',a.writer_role) END,'readiness',jsonb_build_object('status','BLOCKED','runtime_available',false,'customer_execution_authorized',false,'reason_codes',CASE WHEN g.id IS NULL THEN jsonb_build_array('PROGRAM_NOT_PREPARED','FLEET_FIXTURE_RUNTIME_NOT_CONNECTED') WHEN a.id IS NULL THEN jsonb_build_array('INDEPENDENT_PROGRAM_APPROVAL_REQUIRED','FLEET_FIXTURE_RUNTIME_NOT_CONNECTED') ELSE jsonb_build_array('EXACT_JOURNAL_AUTHORIZATION_REQUIRED','FLEET_FIXTURE_RUNTIME_NOT_CONNECTED') END,'estimated_saving',NULL,'verified_saving',NULL)) FROM public.fleet_fixture_proposals p LEFT JOIN public.fleet_fixture_prepared_programs g ON g.tenant_id=p.tenant_id AND g.proposal_id=p.id LEFT JOIN public.fleet_fixture_approvals a ON a.tenant_id=p.tenant_id AND a.proposal_id=p.id`

func (t *Tx) FleetFixtureProposalGet(ctx context.Context, id string) (model.Document, error) {
	return t.sourceOne(ctx, fleetFixtureProjection+` WHERE p.tenant_id=$1 AND p.id=$2`, t.Tenant, id)
}
func (t *Tx) FleetFixtureProposalPage(ctx context.Context, workload, after string, limit int) ([]model.Document, error) {
	if limit < 1 || limit > 101 {
		return nil, fleetfixture.ErrSelection
	}
	return t.sourceRows(ctx, fleetFixtureProjection+` WHERE p.tenant_id=$1 AND p.workload_id=$2 AND ($3='' OR (p.created_at,p.id)<(SELECT created_at,id FROM public.fleet_fixture_proposals WHERE tenant_id=$1 AND workload_id=$2 AND id=$3)) ORDER BY p.created_at DESC,p.id DESC LIMIT $4`, t.Tenant, workload, after, limit)
}

// This private producer method is deliberately unreachable from HTTP. The
// producer must authenticate tool invocation and encrypted object readback;
// structural hashes alone are not native provider or pipeline attestations.
func (t *Tx) FleetFixturePreparedProgramAppend(ctx context.Context, proposalID string, in fleetfixture.Preparation) (model.Document, error) {
	p, e := t.FleetFixtureCurrent(ctx, proposalID)
	if e != nil {
		return nil, e
	}
	mapping, e := t.FleetFixtureMapping(ctx, proposalID)
	if e != nil {
		return nil, e
	}
	if in.Program.ArtifactContext.Mapping != mapping || in.Program.ArtifactContext.RepositoryID != proposalID || in.Program.ArtifactContext.PipelineID != "fixture-pipeline-"+p.Profile.Generation || in.Program.ArtifactContext.Workspace != "default" {
		return nil, fleetfixture.ErrPreparation
	}
	var now time.Time
	if e = t.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&now); e != nil {
		return nil, e
	}
	now = now.UTC()
	if e = fleetfixture.ValidatePreparation(p, in, now); e != nil {
		return nil, e
	}
	program, ph, e := fleetfixture.ProgramBytes(in.Program)
	if e != nil {
		return nil, e
	}
	review, e := json.Marshal(in.JournalReview)
	if e != nil {
		return nil, e
	}
	proofs, e := fleetfixture.ProofBytes(in.GitProofs)
	if e != nil {
		return nil, e
	}
	refs, e := json.Marshal(in.Artifacts)
	if e != nil {
		return nil, e
	}
	id := model.ID()
	_, e = t.Exec(ctx, `INSERT INTO public.fleet_fixture_prepared_programs(tenant_id,id,proposal_id,program_hash,manifest_hash,journal_review_hash,program,program_raw,journal_review,journal_review_raw,proof_hash,artifact_refs) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, t.Tenant, id, proposalID, ph, in.Program.ManifestSHA256, fleetgroup.BytesDigest(review), program, program, review, review, fleetgroup.BytesDigest(proofs), refs)
	if e != nil {
		return nil, fleetFixtureError(e)
	}
	return t.FleetFixturePreparedProgramGet(ctx, proposalID)
}

// Mapping is resolved from the selected declared metadata under currentness
// guards. It labels the isolated model and never attests a native AWS mapping.
func (t *Tx) FleetFixtureMapping(ctx context.Context, proposalID string) (fleetgroup.ModelMapping, error) {
	p, e := t.FleetFixtureCurrent(ctx, proposalID)
	if e != nil {
		return fleetgroup.ModelMapping{}, e
	}
	o, e := t.FleetConfigurationGet(ctx, p.Binding.Old.Declaration.ID)
	if e != nil {
		return fleetgroup.ModelMapping{}, e
	}
	c, e := t.FleetConfigurationGet(ctx, p.Binding.Candidate.Declaration.ID)
	if e != nil {
		return fleetgroup.ModelMapping{}, e
	}
	om, e := FleetConfigurationMetadata(o)
	if e != nil {
		return fleetgroup.ModelMapping{}, e
	}
	cm, e := FleetConfigurationMetadata(c)
	if e != nil {
		return fleetgroup.ModelMapping{}, e
	}
	if om.Terraform.Traffic == nil {
		return fleetgroup.ModelMapping{}, fleetfixture.ErrMapping
	}
	return fleetgroup.ModelMapping{OldDeclaredASG: om.Terraform.ASGAddress, CandidateDeclaredASG: cm.Terraform.ASGAddress, DeclaredListenerRule: om.Terraform.Traffic.ListenerRuleAddress, OldModel: "terraform_data.old", CandidateModel: "terraform_data.candidate", TrafficModel: "terraform_data.traffic"}, nil
}

// Safe review payload: exact program/manifest and readable journal policy. Raw
// state, Git objects, storage paths and artifact bytes remain private.
func (t *Tx) FleetFixturePreparedProgramGet(ctx context.Context, proposalID string) (model.Document, error) {
	return t.sourceOne(ctx, `SELECT jsonb_build_object('id',id,'proposal_id',proposal_id,'program_hash',program_hash,'manifest_hash',manifest_hash,'journal_review_hash',journal_review_hash,'program',program,'journal_review',journal_review,'proof_hash',proof_hash,'producer_role',producer_role,'created_at',created_at) FROM public.fleet_fixture_prepared_programs WHERE tenant_id=$1 AND proposal_id=$2`, t.Tenant, proposalID)
}

func (t *Tx) FleetFixtureApprove(ctx context.Context, id string, expected int64, actor string) (model.Document, error) {
	if !fleetfixture.Actor(actor) {
		return nil, fleetfixture.ErrSelfApproval
	}
	p, e := t.FleetFixtureCurrent(ctx, id)
	if e != nil {
		return nil, e
	}
	if p.CreatorID == actor {
		return nil, fleetfixture.ErrSelfApproval
	}
	record, e := t.FleetFixtureProposalGet(ctx, id)
	if e != nil {
		return nil, e
	}
	if model.Number(record, "version") != expected {
		return nil, ErrConflict
	}
	g, e := t.FleetFixturePreparedProgramGet(ctx, id)
	if errors.Is(e, pgx.ErrNoRows) {
		return nil, fleetfixture.ErrProgram
	}
	if e != nil {
		return nil, e
	}
	if record["approval"] != nil {
		return nil, ErrConflict
	}
	var program fleetgroup.GitProgram
	if e = fleetFixtureDecode(g["program"], &program); e != nil {
		return nil, e
	}
	var now time.Time
	if e = t.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&now); e != nil {
		return nil, e
	}
	if e = fleetgroup.ValidateGitProgram(program, fleetgroup.Expected{Binding: p.Binding, Realm: p.Realm}, now.UTC()); e != nil {
		return nil, e
	}
	a := model.Document{"schema_version": "1", "id": model.ID(), "proposal_id": id, "proposal_hash": record["hash"], "prepared_program_id": g["id"], "program_hash": g["program_hash"], "manifest_hash": g["manifest_hash"], "journal_review_hash": g["journal_review_hash"], "actor_id": actor, "role": fleetgroup.ApproverRole, "approval_scope": "EXACT_FIXTURE_PROGRAM_AND_JOURNAL_REVIEW", "customer_execution_authorized": false, "estimated_saving": nil, "verified_saving": nil}
	raw, e := json.Marshal(a)
	if e != nil {
		return nil, e
	}
	_, e = t.Exec(ctx, `INSERT INTO public.fleet_fixture_approvals(tenant_id,id,proposal_id,prepared_program_id,actor_id,program_hash,manifest_hash,journal_review_hash,content_hash,document,raw_document) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, t.Tenant, a["id"], id, g["id"], actor, g["program_hash"], g["manifest_hash"], g["journal_review_hash"], fleetgroup.BytesDigest(raw), raw, raw)
	if e != nil {
		return nil, fleetFixtureError(e)
	}
	return t.FleetFixtureProposalGet(ctx, id)
}
