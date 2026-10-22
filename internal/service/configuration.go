package service

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/auth"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/configuration"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/jackc/pgx/v5"
)

func configurationResource(ctx context.Context, tx *store.Tx, identity auth.Identity, resourceID string) (model.Document, error) {
	r, err := tx.Get(ctx, "resources", resourceID)
	if err != nil {
		return nil, err
	}
	w, err := tx.Get(ctx, "workloads", model.String(r, "workload_id"))
	if err != nil {
		return nil, err
	}
	if err = workloadAccess(identity, w); err != nil {
		return nil, err
	}
	return r, nil
}

func (a *API) configurationGet(ctx context.Context, tx *store.Tx, identity auth.Identity, r *http.Request) (any, bool, error) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/v1/"), "/")
	resourceRoute := len(parts) == 3 && parts[0] == "resources" && parts[2] == "configuration-authorities"
	proposalRoute := len(parts) >= 3 && len(parts) <= 4 && parts[0] == "workloads" && parts[2] == "configuration-proposals"
	if !resourceRoute && !proposalRoute {
		return nil, false, nil
	}
	// Ownership and inventory updates use the same lock. Keep scoped
	// authorization and the returned immutable history in one stable mapping.
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", identity.Tenant+":dependency-graph"); err != nil {
		return nil, true, err
	}
	if resourceRoute {
		if _, err := configurationResource(ctx, tx, identity, parts[1]); err != nil {
			return nil, true, err
		}
		latest, err := tx.ConfigurationAuthorityLatest(ctx, parts[1])
		if err != nil && err != pgx.ErrNoRows {
			return nil, true, err
		}
		after, limit, err := nativeCursor(r, identity.Tenant, "configuration-authorities", parts[1])
		if err != nil {
			return nil, true, err
		}
		rows, err := tx.ConfigurationAuthorityPage(ctx, parts[1], after, limit+1)
		out := nativePage(rows, limit, identity.Tenant, "configuration-authorities", parts[1])
		out["version"], out["latest"] = model.Number(latest, "version"), latest
		return out, true, err
	}
	w, err := tx.Get(ctx, "workloads", parts[1])
	if err != nil {
		return nil, true, err
	}
	if err = workloadAccess(identity, w); err != nil {
		return nil, true, err
	}
	if len(parts) == 4 {
		proposal, err := tx.ConfigurationProposalGet(ctx, parts[3])
		if err == nil && model.String(proposal, "workload_id") != parts[1] {
			return nil, true, problem(404, "NOT_FOUND", "proposal not found in this workload")
		}
		if err == nil {
			proposal["review_currentness"], err = configurationProposalCurrentness(ctx, tx, proposal, a.now())
		}
		return proposal, true, err
	}
	after, limit, err := nativeCursor(r, identity.Tenant, "configuration-proposals", parts[1])
	if err != nil {
		return nil, true, err
	}
	rows, err := tx.ConfigurationProposalPage(ctx, parts[1], after, limit+1)
	return nativePage(rows, limit, identity.Tenant, "configuration-proposals", parts[1]), true, err
}

func configurationProposalCurrentness(ctx context.Context, tx *store.Tx, proposal model.Document, now time.Time) (model.Document, error) {
	stale, blocked := []string{}, []string{}
	var declared configuration.Binding
	raw, err := json.Marshal(proposal["binding"])
	if err != nil || json.Unmarshal(raw, &declared) != nil {
		blocked = append(blocked, "CONFIGURATION_PROPOSAL_BINDING_UNAVAILABLE")
	} else {
		resource, readErr := tx.Get(ctx, "resources", declared.ResourceID)
		if readErr != nil {
			blocked = append(blocked, "CONFIGURATION_RESOURCE_UNAVAILABLE")
		} else if current, bindErr := configuration.NewBinding(tx.Tenant, resource); bindErr != nil || current != declared {
			stale = append(stale, "RESOURCE_CONFIGURATION_CHANGED")
		}
		latest, latestErr := tx.ConfigurationAuthorityLatest(ctx, declared.ResourceID)
		if latestErr != nil {
			blocked = append(blocked, "CONFIGURATION_AUTHORITY_UNAVAILABLE")
		} else if model.String(latest, "id") != model.String(proposal, "authority_id") || model.Number(latest, "version") != model.Number(proposal, "authority_version") || model.String(latest, "hash") != model.String(proposal, "authority_hash") {
			stale = append(stale, "CONFIGURATION_AUTHORITY_SUPERSEDED")
		}
	}
	assessment, assessmentErr := tx.CapacityAssessmentGet(ctx, model.String(proposal, "capacity_assessment_id"))
	if assessmentErr != nil {
		blocked = append(blocked, "CAPACITY_ASSESSMENT_UNAVAILABLE")
	} else if model.String(assessment, "hash") != model.String(proposal, "capacity_assessment_hash") {
		stale = append(stale, "CAPACITY_ASSESSMENT_CHANGED")
	}
	profile, profileErr := tx.WorkloadSafetyLatest(ctx, model.String(proposal, "workload_id"))
	if profileErr != nil {
		blocked = append(blocked, "WORKLOAD_SAFETY_PROFILE_UNAVAILABLE")
	} else if model.String(profile, "id") != model.String(proposal, "safety_profile_id") || model.Number(profile, "version") != model.Number(proposal, "safety_profile_version") || model.String(profile, "hash") != model.String(proposal, "safety_profile_hash") {
		stale = append(stale, "WORKLOAD_SAFETY_PROFILE_CHANGED")
	}
	connection, connectionErr := tx.TelemetryConnection(ctx, model.String(proposal, "connection_id"))
	if connectionErr != nil {
		blocked = append(blocked, "TELEMETRY_SOURCE_UNAVAILABLE")
	} else if !model.Bool(connection, "enabled") || model.Bool(connection, "revoked") || model.Number(connection, "version") != model.Number(proposal, "connection_version") || model.String(connection, "revision_id") != model.String(proposal, "revision_id") || model.String(connection, "config_hash") != model.String(proposal, "config_hash") {
		stale = append(stale, "TELEMETRY_SOURCE_CHANGED_OR_REVOKED")
	}
	reasons := databaseSortedReasons(append(stale, blocked...))
	status := "CURRENT"
	if len(blocked) > 0 {
		status = "BLOCKED"
	} else if len(stale) > 0 {
		status = "STALE"
	}
	return model.Document{
		"schema_version": "1",
		"status": status,
		"checked_at": now,
		"reason_codes": reasons,
		"repository_revision_status": "UNBOUND",
		"review_status": "BLOCKED",
		"review_blockers": []string{"IAC_SOURCE_REVISION_UNBOUND", "CONFIGURATION_PATCH_AND_PLAN_UNAVAILABLE"},
		"execution_authorized": false,
	}, nil
}

func (a *API) configurationMutate(ctx context.Context, tx *store.Tx, identity auth.Identity, r *http.Request, in model.Document, parts []string) (model.Document, int, bool, error) {
	authorityRoute := len(parts) == 3 && parts[0] == "resources" && parts[2] == "configuration-authorities"
	proposalRoute := len(parts) == 3 && parts[0] == "workloads" && parts[2] == "configuration-proposals"
	if !authorityRoute && !proposalRoute {
		return nil, 0, false, nil
	}
	if err := requireRole(identity, "PLATFORM_ADMIN"); err != nil {
		return nil, 0, true, err
	}
	if authorityRoute {
		if _, err := configurationResource(ctx, tx, identity, parts[1]); err != nil {
			return nil, 0, true, err
		}
		raw, err := json.Marshal(in)
		if err != nil {
			return nil, 0, true, err
		}
		declaration, err := configuration.Decode(raw)
		if err != nil {
			return nil, 0, true, problem(422, err.Error(), "declare repository, dedicated pipeline identity and Terraform mapping; observed proof and secrets are not accepted")
		}
		latest, err := tx.ConfigurationAuthorityLatest(ctx, parts[1])
		if err != nil && err != pgx.ErrNoRows {
			return nil, 0, true, err
		}
		if latest == nil {
			latest = model.Document{"version": 0}
		}
		if err = match(r, latest); err != nil {
			return nil, 0, true, err
		}
		out, err := tx.ConfigurationAuthorityAppend(ctx, parts[1], model.Number(latest, "version"), identity.Subject, declaration)
		if err != nil && strings.HasPrefix(err.Error(), "CONFIGURATION_") {
			return nil, 0, true, problem(422, err.Error(), "use canonical Terraform metadata matching the current resource provider")
		}
		if err == nil {
			err = tx.Audit(ctx, identity.Subject, "configuration.authority_declared", parts[1], model.Document{"authority_id": out["id"], "version": out["version"], "hash": out["hash"], "status": "DECLARED_NOT_ATTESTED"})
		}
		return out, 201, true, err
	}
	w, err := tx.Get(ctx, "workloads", parts[1])
	if err != nil {
		return nil, 0, true, err
	}
	if err = workloadAccess(identity, w); err != nil {
		return nil, 0, true, err
	}
	var request struct {
		AuthorityID          string `json:"authority_id"`
		CapacityAssessmentID string `json:"capacity_assessment_id"`
	}
	if err = telemetryStrict(in, &request); err != nil || request.AuthorityID == "" || request.CapacityAssessmentID == "" {
		return nil, 0, true, problem(422, "CONFIGURATION_PROPOSAL_SELECTION_INVALID", "select an existing declaration and capacity assessment; price, patch, plan and proof fields are server-selected or unavailable")
	}
	authority, err := tx.ConfigurationAuthorityGet(ctx, request.AuthorityID)
	if err != nil {
		return nil, 0, true, err
	}
	// Authorize through the server-selected resource, never request-provided scope.
	var binding configuration.Binding
	raw, _ := json.Marshal(authority["binding"])
	if json.Unmarshal(raw, &binding) != nil || binding.WorkloadID != parts[1] {
		return nil, 0, true, problem(422, "CONFIGURATION_PROPOSAL_BINDING_INVALID", "declaration must belong to this workload")
	}
	if _, err = configurationResource(ctx, tx, identity, binding.ResourceID); err != nil {
		return nil, 0, true, err
	}
	if err = match(r, authority); err != nil {
		return nil, 0, true, err
	}
	out, err := tx.ConfigurationProposalCreate(ctx, parts[1], request.AuthorityID, request.CapacityAssessmentID, model.Number(authority, "version"), identity.Subject)
	if errors.Is(err, store.ErrConfigurationBinding) {
		return nil, 0, true, problem(422, "CONFIGURATION_PROPOSAL_BINDING_INVALID", "resource, safety requirements, source or assessment changed; refresh their evidence before recording a proposal")
	}
	if err == nil {
		err = tx.Audit(ctx, identity.Subject, "configuration.proposal_blocked", model.String(out, "id"), model.Document{"authority_id": request.AuthorityID, "capacity_assessment_id": request.CapacityAssessmentID, "status": "BLOCKED"})
	}
	return out, 201, true, err
}
