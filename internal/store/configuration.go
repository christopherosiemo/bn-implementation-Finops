package store

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"sort"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/configuration"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/telemetry"
	"github.com/jackc/pgx/v5"
)

var ErrConfigurationBinding = errors.New("configuration declaration or assessment no longer matches current resource, requirements and source")

func (t *Tx) ConfigurationAuthorityLatest(ctx context.Context, resource string) (model.Document, error) {
	return t.sourceOne(ctx, "SELECT document FROM configuration_authority_revisions WHERE tenant_id=$1 AND resource_id=$2 ORDER BY version DESC LIMIT 1", t.Tenant, resource)
}
func (t *Tx) ConfigurationAuthorityGet(ctx context.Context, id string) (model.Document, error) {
	return t.sourceOne(ctx, "SELECT document FROM configuration_authority_revisions WHERE tenant_id=$1 AND id=$2", t.Tenant, id)
}
func (t *Tx) ConfigurationAuthorityPage(ctx context.Context, resource, after string, limit int) ([]model.Document, error) {
	if resource == "" || limit < 1 || limit > 101 {
		return nil, ErrConflict
	}
	return t.sourceRows(ctx, "SELECT document FROM configuration_authority_revisions WHERE tenant_id=$1 AND resource_id=$2 AND ($3='' OR (created_at,id)<(SELECT created_at,id FROM configuration_authority_revisions WHERE tenant_id=$1 AND resource_id=$2 AND id=$3)) ORDER BY created_at DESC,id DESC LIMIT $4", t.Tenant, resource, after, limit)
}
func (t *Tx) ConfigurationAuthorityAppend(ctx context.Context, resource string, expected int64, actor string, d configuration.Declaration) (model.Document, error) {
	if expected < 0 || expected == math.MaxInt64 || actor == "" {
		return nil, ErrConflict
	}
	if _, err := t.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", t.Tenant+":dependency-graph"); err != nil {
		return nil, err
	}
	latest, err := t.ConfigurationAuthorityLatest(ctx, resource)
	if err != nil && err != pgx.ErrNoRows {
		return nil, err
	}
	if model.Number(latest, "version") != expected {
		return nil, ErrConflict
	}
	r, err := t.Get(ctx, "resources", resource)
	if err != nil {
		return nil, err
	}
	b, err := configuration.NewBinding(t.Tenant, r)
	if err != nil {
		return nil, err
	}
	if err = configuration.ValidateBinding(d, b); err != nil {
		return nil, err
	}
	if _, err = t.Get(ctx, "workloads", b.WorkloadID); err != nil {
		return nil, err
	}
	out := configuration.DeclarationDocument(d)
	out["id"], out["version"], out["binding"] = model.ID(), expected+1, b
	out["status"], out["reason_codes"], out["execution_authorized"] = "DECLARED_NOT_ATTESTED", configuration.Reasons(b), false
	out["observed_commit"], out["observed_state_serial"], out["declared_by"] = nil, nil, actor
	raw, err := json.Marshal(out)
	if err != nil {
		return nil, err
	}
	snapshot, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	return t.sourceOne(ctx, "INSERT INTO configuration_authority_revisions(tenant_id,id,resource_id,workload_id,version,resource_version,resource_snapshot_hash,resource_snapshot,content_hash,document) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING document", t.Tenant, out["id"], resource, b.WorkloadID, expected+1, b.ResourceVersion, b.ResourceSnapshotHash, snapshot, telemetry.Hash(out), raw)
}

func (t *Tx) ConfigurationProposalGet(ctx context.Context, id string) (model.Document, error) {
	return t.sourceOne(ctx, "SELECT document FROM configuration_proposals WHERE tenant_id=$1 AND id=$2", t.Tenant, id)
}
func (t *Tx) ConfigurationProposalPage(ctx context.Context, workload, after string, limit int) ([]model.Document, error) {
	if workload == "" || limit < 1 || limit > 101 {
		return nil, ErrConflict
	}
	return t.sourceRows(ctx, "SELECT document FROM configuration_proposals WHERE tenant_id=$1 AND workload_id=$2 AND ($3='' OR (created_at,id)<(SELECT created_at,id FROM configuration_proposals WHERE tenant_id=$1 AND workload_id=$2 AND id=$3)) ORDER BY created_at DESC,id DESC LIMIT $4", t.Tenant, workload, after, limit)
}

// ConfigurationProposalCreate selects evidence from immutable server records.
// No patch, price, receipt, commit or execution authority is caller-supplied.
func (t *Tx) ConfigurationProposalCreate(ctx context.Context, workload, authorityID, assessmentID string, expected int64, actor string) (model.Document, error) {
	if expected < 1 || actor == "" {
		return nil, ErrConflict
	}
	if _, err := t.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", t.Tenant+":dependency-graph"); err != nil {
		return nil, err
	}
	authority, err := t.ConfigurationAuthorityGet(ctx, authorityID)
	if err != nil {
		return nil, err
	}
	var binding configuration.Binding
	rawBinding, _ := json.Marshal(authority["binding"])
	if json.Unmarshal(rawBinding, &binding) != nil || binding.WorkloadID != workload || binding.TenantID != t.Tenant {
		return nil, ErrConfigurationBinding
	}
	latest, err := t.ConfigurationAuthorityLatest(ctx, binding.ResourceID)
	if err != nil {
		return nil, err
	}
	if model.String(latest, "id") != authorityID || model.Number(latest, "version") != expected {
		return nil, ErrConflict
	}
	r, err := t.Get(ctx, "resources", binding.ResourceID)
	if err != nil {
		return nil, err
	}
	current, err := configuration.NewBinding(t.Tenant, r)
	if err != nil || current != binding {
		return nil, ErrConfigurationBinding
	}
	assessment, err := t.CapacityAssessmentGet(ctx, assessmentID)
	if err != nil {
		return nil, err
	}
	profile, err := t.WorkloadSafetyLatest(ctx, workload)
	if err != nil {
		return nil, err
	}
	c, err := t.TelemetryConnection(ctx, model.String(assessment, "connection_id"))
	if err != nil {
		return nil, err
	}
	typed, err := telemetry.ParseConnection(c)
	if err != nil || typed.Binding != binding.Binding || model.Bool(c, "revoked") || !typed.Enabled || model.String(assessment, "workload_id") != workload || model.String(assessment, "resource_id") != binding.ResourceID || model.String(assessment, "safety_profile_id") != model.String(profile, "id") || model.Number(assessment, "safety_profile_version") != model.Number(profile, "version") || model.String(assessment, "safety_profile_hash") != model.String(profile, "hash") || model.Number(assessment, "connection_version") != typed.Version || model.String(assessment, "revision_id") != model.String(c, "revision_id") || model.String(assessment, "config_hash") != model.String(c, "config_hash") || model.String(assessment, "status") != "BLOCKED" || model.Bool(assessment, "execution_authorized") {
		return nil, ErrConfigurationBinding
	}
	reasons := append([]string{"DECLARED_NOT_ATTESTED", "CONFIGURATION_STATE_UNOBSERVED", "NATIVE_CAPACITY_NOT_VALIDATED", "NATIVE_PRICE_UNAVAILABLE"}, configuration.Reasons(binding)...)
	reasons = append(reasons, model.Strings(assessment, "reason_codes")...)
	sort.Strings(reasons)
	unique := []string{}
	for _, reason := range reasons {
		if reason != "" && (len(unique) == 0 || unique[len(unique)-1] != reason) {
			unique = append(unique, reason)
		}
	}
	out := model.Document{"schema_version": "1", "binding": binding, "workload_id": workload, "resource_id": binding.ResourceID, "authority_id": authorityID, "authority_version": expected, "authority_hash": authority["hash"], "capacity_assessment_id": assessmentID, "capacity_assessment_hash": assessment["hash"], "population_hash": assessment["population_hash"], "connection_id": c["id"], "connection_version": c["version"], "revision_id": c["revision_id"], "config_hash": c["config_hash"], "safety_profile_id": profile["id"], "safety_profile_version": profile["version"], "safety_profile_hash": profile["hash"], "status": "BLOCKED", "reason_codes": unique, "execution_authorized": false, "estimated_saving": nil, "verified_saving": nil, "change_plan_id": nil, "proposed_by": actor}
	raw, err := json.Marshal(out)
	if err != nil {
		return nil, err
	}
	return t.sourceOne(ctx, "INSERT INTO configuration_proposals(tenant_id,id,workload_id,resource_id,authority_id,capacity_assessment_id,content_hash,document) VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING document", t.Tenant, model.ID(), workload, binding.ResourceID, authorityID, assessmentID, telemetry.Hash(out), raw)
}
