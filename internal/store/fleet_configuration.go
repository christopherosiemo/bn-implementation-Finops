package store

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"sort"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/configuration"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/fleethistory"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/jackc/pgx/v5"
)

var ErrFleetConfigurationBinding = errors.New("FLEET_CONFIGURATION_CURRENT_BINDING_REQUIRED")

// FleetConfigurationMetadata unwraps metadata only. The immutable wrapper's
// binding is resolved separately from a real Fleet-history registration.
func FleetConfigurationMetadata(d model.Document) (configuration.FleetDeclaration, error) {
	b, e := json.Marshal(d["metadata"])
	if e != nil {
		return configuration.FleetDeclaration{}, e
	}
	return configuration.DecodeFleetDeclaration(b)
}

func (t *Tx) fleetConfigurationCurrent(ctx context.Context, registrationID string) (model.Document, fleethistory.Registration, error) {
	if registrationID == "" || len(registrationID) > 256 {
		return nil, fleethistory.Registration{}, ErrFleetConfigurationBinding
	}
	if _, e := t.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", t.Tenant+":dependency-graph"); e != nil {
		return nil, fleethistory.Registration{}, e
	}
	if e := t.fleetHistoryLock(ctx, registrationID); e != nil {
		return nil, fleethistory.Registration{}, e
	}
	rdoc, e := t.FleetHistoryRegistrationGet(ctx, registrationID)
	if e != nil {
		return nil, fleethistory.Registration{}, e
	}
	r, e := FleetHistoryRegistrationDocument(rdoc)
	if e != nil {
		return nil, r, e
	}
	if e = t.fleetHistorySourceLock(ctx, r.SourceID); e != nil {
		return nil, r, e
	}
	// This DB helper repeats all guards for direct SQL writers. Taking the
	// nonblocking source guard above keeps a busy source error transaction-usable.
	var current []byte
	if e = t.QueryRow(ctx, "SELECT public.fleet_configuration_registration($1,$2)", t.Tenant, registrationID).Scan(&current); e != nil {
		return nil, r, e
	}
	if current == nil {
		return nil, r, ErrFleetConfigurationBinding
	}
	return rdoc, r, nil
}

func fleetConfigurationActor(actor string) bool {
	if actor == "" || len(actor) > 512 {
		return false
	}
	for _, c := range actor {
		if c < 32 || c == 127 {
			return false
		}
	}
	return true
}

// FleetConfigurationAppend creates one immutable metadata revision per actual
// registered fleet. It neither verifies Terraform address mappings nor enrolls
// the declared pipeline identity in any observer, signer or execution registry.
func (t *Tx) FleetConfigurationAppend(ctx context.Context, registrationID string, expected int64, actor string, metadata configuration.FleetDeclaration) (model.Document, error) {
	if expected < 0 || expected == math.MaxInt64 || !fleetConfigurationActor(actor) {
		return nil, ErrConflict
	}
	if e := configuration.ValidateFleetDeclaration(metadata); e != nil {
		return nil, e
	}
	rdoc, r, e := t.fleetConfigurationCurrent(ctx, registrationID)
	if e != nil {
		return nil, e
	}
	prior, e := t.FleetConfigurationLatest(ctx, registrationID)
	if e != nil && !errors.Is(e, pgx.ErrNoRows) {
		return nil, e
	}
	if int64(model.Number(prior, "version")) != expected {
		return nil, ErrConflict
	}
	var sourceVersion int64
	if e = t.QueryRow(ctx, "SELECT version FROM public.source_registrations WHERE tenant_id=$1 AND id=$2", t.Tenant, r.SourceID).Scan(&sourceVersion); e != nil {
		return nil, e
	}
	// Map conversion makes the metadata representation and hash deterministic
	// with the repository's canonical map JSON, without changing legacy v1 types.
	b, _ := json.Marshal(metadata)
	var meta model.Document
	if e = json.Unmarshal(b, &meta); e != nil {
		return nil, e
	}
	out := model.Document{"schema_version": "1", "id": model.ID(), "version": expected + 1, "registration_id": r.ID, "registration_version": r.Version, "registration_hash": rdoc["hash"], "fleet_id": r.FleetID, "asg_arn": r.ASGARN, "binding": r.Binding, "source_id": r.SourceID, "source_registration_version": sourceVersion, "source_config_hash": r.SourceConfigHash, "metadata": meta, "status": "DECLARED_NOT_ATTESTED", "reason_codes": configuration.FleetDeclarationReasons(), "execution_authorized": false, "estimated_saving": nil, "verified_saving": nil, "declared_by": actor}
	raw, h, e := fleetHistoryBytes(out)
	if e != nil {
		return nil, e
	}
	_, e = t.Exec(ctx, `INSERT INTO public.fleet_configuration_declarations(tenant_id,id,registration_id,registration_version,workload_id,version,content_hash,document,raw_document) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, t.Tenant, out["id"], r.ID, r.Version, r.Binding.WorkloadID, expected+1, h, raw, raw)
	if e != nil {
		return nil, e
	}
	return t.FleetConfigurationGet(ctx, model.String(out, "id"))
}

func (t *Tx) FleetConfigurationLatest(ctx context.Context, registrationID string) (model.Document, error) {
	return t.sourceOne(ctx, `SELECT document||jsonb_build_object('hash',content_hash,'created_at',created_at,'writer_role',writer_role) FROM public.fleet_configuration_declarations WHERE tenant_id=$1 AND registration_id=$2 ORDER BY version DESC LIMIT 1`, t.Tenant, registrationID)
}
func (t *Tx) FleetConfigurationGet(ctx context.Context, id string) (model.Document, error) {
	return t.sourceOne(ctx, `SELECT document||jsonb_build_object('hash',content_hash,'created_at',created_at,'writer_role',writer_role) FROM public.fleet_configuration_declarations WHERE tenant_id=$1 AND id=$2`, t.Tenant, id)
}
func (t *Tx) FleetConfigurationPage(ctx context.Context, registrationID, after string, limit int) ([]model.Document, error) {
	if registrationID == "" {
		return nil, ErrFleetConfigurationBinding
	}
	if _, e := fleetHistoryPageLimit(limit); e != nil {
		return nil, e
	}
	return t.sourceRows(ctx, `SELECT document||jsonb_build_object('hash',content_hash,'created_at',created_at,'writer_role',writer_role) FROM public.fleet_configuration_declarations WHERE tenant_id=$1 AND registration_id=$2 AND ($3='' OR (created_at,id)<(SELECT created_at,id FROM public.fleet_configuration_declarations WHERE tenant_id=$1 AND registration_id=$2 AND id=$3)) ORDER BY created_at DESC,id DESC LIMIT $4`, t.Tenant, registrationID, after, limit)
}

func fleetConfigurationReasons(extra ...[]string) []string {
	out := append([]string{}, configuration.FleetProposalReasons()...)
	for _, items := range extra {
		out = append(out, items...)
	}
	sort.Strings(out)
	unique := []string{}
	for _, s := range out {
		if s != "" && (len(unique) == 0 || unique[len(unique)-1] != s) {
			unique = append(unique, s)
		}
	}
	return unique
}

// FleetConfigurationProposalCreate accepts only immutable server IDs and the
// current declaration CAS version. A selected singleton capacity assessment,
// native rate sample or artifact cannot become Fleet authority through this path.
func (t *Tx) FleetConfigurationProposalCreate(ctx context.Context, registrationID, declarationID, scopeID string, expected int64, actor string) (model.Document, error) {
	if expected < 1 || !fleetConfigurationActor(actor) {
		return nil, ErrConflict
	}
	b, _ := json.Marshal(configuration.FleetProposalSelection{DeclarationID: declarationID, ScopeID: scopeID})
	if _, e := configuration.DecodeFleetProposalSelection(b); e != nil {
		return nil, e
	}
	rdoc, r, e := t.fleetConfigurationCurrent(ctx, registrationID)
	if e != nil {
		return nil, e
	}
	decl, e := t.FleetConfigurationGet(ctx, declarationID)
	if e != nil {
		return nil, e
	}
	latest, e := t.FleetConfigurationLatest(ctx, registrationID)
	if e != nil {
		return nil, e
	}
	if model.String(latest, "id") != declarationID || int64(model.Number(latest, "version")) != expected || model.String(decl, "registration_id") != registrationID || int64(model.Number(decl, "registration_version")) != r.Version || model.String(decl, "registration_hash") != model.String(rdoc, "hash") {
		return nil, ErrConflict
	}
	scope, e := t.FleetHistoryScopeGet(ctx, scopeID)
	if e != nil {
		return nil, e
	}
	if model.String(scope, "registration_id") != registrationID || int64(model.Number(scope, "registration_version")) != r.Version || model.String(scope, "registration_hash") != model.String(rdoc, "hash") {
		return nil, ErrFleetConfigurationBinding
	}
	var now time.Time
	if e = t.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&now); e != nil {
		return nil, e
	}
	// Every source ID comes from guarded scope references. Acquire shared Sync
	// guards before invoking the SQL resolver so busy sources stay typed errors.
	rows, e := t.Query(ctx, `SELECT document->>'source_id' FROM public.fleet_history_scope_references WHERE tenant_id=$1 AND scope_id=$2 AND kind='SOURCE_STATE' AND document->>'source_system'='AWS_SOURCE_CONNECTION' ORDER BY document->>'source_id' LIMIT 1025`, t.Tenant, scopeID)
	if e != nil {
		return nil, e
	}
	sources := []string{}
	for rows.Next() {
		var id string
		if e = rows.Scan(&id); e != nil {
			rows.Close()
			return nil, e
		}
		sources = append(sources, id)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, e
	}
	if len(sources) > 1024 {
		return nil, ErrFleetHistoryBounds
	}
	for _, id := range sources {
		if e = t.fleetHistorySourceLock(ctx, id); e != nil {
			return nil, e
		}
	}
	var sourceRaw []byte
	if e = t.QueryRow(ctx, "SELECT public.fleet_configuration_scope_sources($1,$2,$3,$4)", t.Tenant, registrationID, scopeID, now).Scan(&sourceRaw); e != nil {
		return nil, e
	}
	if sourceRaw == nil {
		return nil, ErrFleetConfigurationBinding
	}
	if len(sourceRaw) > 32<<10 {
		return nil, ErrFleetHistoryBounds
	}
	states := []fleethistory.SourceState{}
	if e = json.Unmarshal(sourceRaw, &states); e != nil {
		return nil, e
	}
	reasons := model.Strings(scope, "reason_codes")
	if model.Number(scope, "selected_observation_count") == 0 {
		reasons = append(reasons, "GROUP_MEMBERSHIP_UNOBSERVED")
	}
	for _, s := range states {
		if s.Status != "ACTIVE" {
			reasons = append(reasons, "FLEET_CONFIGURATION_SOURCE_NOT_HEALTHY")
		}
	}
	out := model.Document{"schema_version": "1", "id": model.ID(), "purpose": "FLEET_CONFIGURATION_PROPOSAL", "registration_id": r.ID, "registration_version": r.Version, "registration_hash": rdoc["hash"], "binding": r.Binding, "fleet_id": r.FleetID, "asg_arn": r.ASGARN, "declaration_id": declarationID, "declaration_version": expected, "declaration_hash": decl["hash"], "scope_id": scopeID, "scope_hash": scope["hash"], "scope_reference_root": scope["reference_root"], "definition_id": scope["definition_id"], "definition_version": scope["definition_version"], "definition_hash": scope["definition_hash"], "history_start": scope["start"], "history_end": scope["end"], "membership_status": scope["membership_status"], "observation_count": scope["observation_count"], "selected_observation_count": scope["selected_observation_count"], "source_states": json.RawMessage(sourceRaw), "as_of": now.UTC(), "status": "BLOCKED", "reason_codes": fleetConfigurationReasons(reasons), "execution_authorized": false, "estimated_saving": nil, "verified_saving": nil, "change_plan_id": nil, "proposed_by": actor}
	raw, h, e := fleetHistoryBytes(out)
	if e != nil {
		return nil, e
	}
	if len(raw) > 64<<10 {
		return nil, ErrFleetHistoryBounds
	}
	_, e = t.Exec(ctx, `INSERT INTO public.fleet_configuration_proposals(tenant_id,id,registration_id,registration_version,workload_id,declaration_id,scope_id,content_hash,document,raw_document) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, t.Tenant, out["id"], r.ID, r.Version, r.Binding.WorkloadID, declarationID, scopeID, h, raw, raw)
	if e != nil {
		return nil, e
	}
	return t.FleetConfigurationProposalGet(ctx, model.String(out, "id"))
}

func (t *Tx) FleetConfigurationProposalGet(ctx context.Context, id string) (model.Document, error) {
	return t.sourceOne(ctx, `SELECT document||jsonb_build_object('hash',content_hash,'created_at',created_at,'writer_role',writer_role) FROM public.fleet_configuration_proposals WHERE tenant_id=$1 AND id=$2`, t.Tenant, id)
}
func (t *Tx) FleetConfigurationProposalPage(ctx context.Context, registrationID, after string, limit int) ([]model.Document, error) {
	if registrationID == "" {
		return nil, ErrFleetConfigurationBinding
	}
	if _, e := fleetHistoryPageLimit(limit); e != nil {
		return nil, e
	}
	return t.sourceRows(ctx, `SELECT document||jsonb_build_object('hash',content_hash,'created_at',created_at,'writer_role',writer_role) FROM public.fleet_configuration_proposals WHERE tenant_id=$1 AND registration_id=$2 AND ($3='' OR (created_at,id)<(SELECT created_at,id FROM public.fleet_configuration_proposals WHERE tenant_id=$1 AND registration_id=$2 AND id=$3)) ORDER BY created_at DESC,id DESC LIMIT $4`, t.Tenant, registrationID, after, limit)
}
