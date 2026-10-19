package service

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/auth"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/fleethistory"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/source"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
)

type fleetHistoryRegistrationRequest struct {
	WorkloadID         string `json:"workload_id"`
	FleetID            string `json:"fleet_id"`
	ASGARN             string `json:"asg_arn"`
	SourceConnectionID string `json:"source_connection_id"`
	CadenceSeconds     int    `json:"cadence_seconds"`
	MaxGapSeconds      int    `json:"max_gap_seconds"`
}
type fleetDemandDefinitionRequest struct {
	RegistrationID       string `json:"registration_id"`
	ActivitySourceID     string `json:"activity_source_id"`
	BusinessOperation    string `json:"business_operation"`
	SemanticContractID   string `json:"semantic_contract_id"`
	SemanticContractHash string `json:"semantic_contract_hash"`
}
type fleetHistoryScopeRequest struct {
	RegistrationID    string `json:"registration_id"`
	DefinitionID      string `json:"definition_id"`
	DefinitionVersion int64  `json:"definition_version"`
}

func fleetHistoryRoute(parts []string) bool {
	return len(parts) > 0 && (parts[0] == "fleet-history-registrations" || parts[0] == "fleet-demand-definitions" || parts[0] == "fleet-history-scopes")
}
func fleetHistoryWorkload(ctx context.Context, tx *store.Tx, identity auth.Identity, workloadID string) error {
	if workloadID == "" {
		return problem(422, "HISTORY_WORKLOAD_REQUIRED", "select an existing workload")
	}
	w, err := tx.Get(ctx, "workloads", workloadID)
	if err != nil {
		return err
	}
	return workloadAccess(identity, w)
}
func fleetHistoryRegistered(ctx context.Context, tx *store.Tx, identity auth.Identity, id string) (model.Document, fleethistory.Registration, error) {
	d, err := tx.FleetHistoryRegistrationGet(ctx, id)
	if err != nil {
		return nil, fleethistory.Registration{}, err
	}
	r, err := store.FleetHistoryRegistrationDocument(d)
	if err == nil {
		err = fleetHistoryWorkload(ctx, tx, identity, r.Binding.WorkloadID)
	}
	return d, r, err
}

func (a *API) fleetHistoryGet(ctx context.Context, tx *store.Tx, identity auth.Identity, r *http.Request) (any, bool, error) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/v1/"), "/")
	if !fleetHistoryRoute(parts) {
		return nil, false, nil
	}
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", identity.Tenant+":dependency-graph"); err != nil {
		return nil, true, err
	}
	if len(parts) == 1 {
		scope := r.URL.Query().Get("registration_id")
		if parts[0] == "fleet-history-registrations" {
			scope = r.URL.Query().Get("workload_id")
			if err := fleetHistoryWorkload(ctx, tx, identity, scope); err != nil {
				return nil, true, err
			}
		} else {
			if scope == "" {
				return nil, true, problem(422, "HISTORY_REGISTRATION_REQUIRED", "select a fleet history registration")
			}
			if _, _, err := fleetHistoryRegistered(ctx, tx, identity, scope); err != nil {
				return nil, true, err
			}
		}
		after, limit, err := nativeCursor(r, identity.Tenant, parts[0], scope)
		if err != nil {
			return nil, true, err
		}
		var rows []model.Document
		switch parts[0] {
		case "fleet-history-registrations":
			rows, err = tx.FleetHistoryRegistrationPage(ctx, scope, after, limit+1)
		case "fleet-demand-definitions":
			rows, err = tx.FleetDemandDefinitionPage(ctx, scope, after, limit+1)
		case "fleet-history-scopes":
			rows, err = tx.FleetHistoryScopePage(ctx, scope, after, limit+1)
		}
		return nativePage(rows, limit, identity.Tenant, parts[0], scope), true, err
	}
	if parts[0] == "fleet-history-registrations" && len(parts) <= 3 {
		d, _, err := fleetHistoryRegistered(ctx, tx, identity, parts[1])
		if err != nil || len(parts) == 2 {
			return d, true, err
		}
		if parts[2] == "observations" {
			after, limit, err := nativeCursor(r, identity.Tenant, "fleet-history-observations", parts[1])
			if err != nil {
				return nil, true, err
			}
			rows, err := tx.FleetHistoryObservationPage(ctx, parts[1], after, limit+1)
			return nativePage(rows, limit, identity.Tenant, "fleet-history-observations", parts[1]), true, err
		}
	}
	if parts[0] == "fleet-demand-definitions" && len(parts) == 2 {
		d, err := tx.FleetDemandDefinitionGet(ctx, parts[1])
		if err == nil {
			_, _, err = fleetHistoryRegistered(ctx, tx, identity, model.String(d, "registration_id"))
		}
		return d, true, err
	}
	if parts[0] == "fleet-history-scopes" && len(parts) <= 3 {
		d, err := tx.FleetHistoryScopeGet(ctx, parts[1])
		if err != nil {
			return nil, true, err
		}
		binding, _ := d["binding"].(map[string]any)
		if err = fleetHistoryWorkload(ctx, tx, identity, model.String(binding, "workload_id")); err != nil {
			return nil, true, err
		}
		if len(parts) == 2 {
			return d, true, nil
		}
		if parts[2] == "references" {
			kind := r.URL.Query().Get("kind")
			if kind != "" && kind != "REGISTRATION" && kind != "DEFINITION" && kind != "OBSERVATION" && kind != "DEMAND_RECEIPT" && kind != "SOURCE_STATE" {
				return nil, true, problem(422, "HISTORY_REFERENCE_KIND_INVALID", "select a supported immutable reference kind")
			}
			scope := parts[1] + ":" + kind
			after, limit, err := nativeCursor(r, identity.Tenant, "fleet-history-references", scope)
			if err != nil {
				return nil, true, err
			}
			if after != "" {
				ordinal, parse := strconv.ParseInt(after, 10, 32)
				if parse != nil || ordinal < 0 || ordinal > model.Number(d, "reference_count") {
					return nil, true, problem(422, "CURSOR_INVALID", "reference cursor contains an invalid ordinal")
				}
			}
			rows, err := tx.FleetHistoryScopeReferencePage(ctx, parts[1], kind, after, limit+1)
			var cursor any
			if len(rows) > limit {
				rows = rows[:limit]
				raw, _ := json.Marshal(struct{ Tenant, Kind, Scope, After string }{identity.Tenant, "fleet-history-references", scope, model.String(rows[len(rows)-1], "cursor")})
				cursor = base64.RawURLEncoding.EncodeToString(raw)
			}
			return model.Document{"items": rows, "next_cursor": cursor}, true, err
		}
	}
	return nil, true, problem(404, "NOT_FOUND", "fleet history resource not found")
}

func (a *API) fleetHistoryMutate(ctx context.Context, tx *store.Tx, identity auth.Identity, r *http.Request, in model.Document, parts []string) (model.Document, int, bool, error) {
	if !fleetHistoryRoute(parts) {
		return nil, 0, false, nil
	}
	if err := requireRole(identity, "PLATFORM_ADMIN"); err != nil {
		return nil, 0, true, err
	}
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", identity.Tenant+":dependency-graph"); err != nil {
		return nil, 0, true, err
	}
	creating := len(parts) == 1
	if !creating && (len(parts) != 3 || parts[2] != "revisions" || parts[0] == "fleet-history-scopes") {
		return nil, 0, true, problem(404, "NOT_FOUND", "fleet history mutation not found")
	}
	var out model.Document
	var err error
	switch parts[0] {
	case "fleet-history-registrations":
		var request fleetHistoryRegistrationRequest
		if telemetryStrict(in, &request) != nil {
			return nil, 0, true, problem(422, "HISTORY_REGISTRATION_FIELDS_INVALID", "select source, workload, exact ASG ARN and observation cadence; provenance is server-selected")
		}
		if err = fleetHistoryWorkload(ctx, tx, identity, request.WorkloadID); err != nil {
			return nil, 0, true, err
		}
		latest := model.Document{"version": int64(0)}
		id := model.ID()
		var old fleethistory.Registration
		if !creating {
			id = parts[1]
			latest, old, err = fleetHistoryRegistered(ctx, tx, identity, id)
			if err != nil {
				return nil, 0, true, err
			}
		}
		if err = match(r, latest); err != nil {
			return nil, 0, true, err
		}
		var src model.Document
		src, err = tx.SourceGet(ctx, request.SourceConnectionID)
		if err != nil {
			return nil, 0, true, err
		}
		arn := strings.Split(request.ASGARN, ":")
		if len(arn) != 8 {
			return nil, 0, true, problem(422, "HISTORY_ASG_ARN_INVALID", "provide the complete native Ireland ASG ARN")
		}
		typed := fleethistory.Registration{SchemaVersion: "1", ID: id, Version: model.Number(latest, "version") + 1, FleetID: request.FleetID, Binding: fleethistory.Binding{TenantID: identity.Tenant, WorkloadID: request.WorkloadID, Provider: "AWS", AccountID: arn[4], Region: "eu-west-1"}, ASGARN: request.ASGARN, SourceID: request.SourceConnectionID, SourceSystem: "AWS_SOURCE_CONNECTION", SourceRegistrationVersion: model.Number(src, "version"), SourceConfigHash: source.ConfigurationHash(src), CadenceSeconds: request.CadenceSeconds, MaxGapSeconds: request.MaxGapSeconds}
		if fleethistory.ValidateRegistration(typed) != nil {
			return nil, 0, true, problem(422, "HISTORY_REGISTRATION_INVALID", "provide an exact ASG ARN and a cadence and maximum gap between one and 600 seconds")
		}
		if typed.CadenceSeconds < 15 {
			return nil, 0, true, problem(422, "HISTORY_NATIVE_CADENCE_UNSUPPORTED", "the current native reader supports observation cadence from 15 to 600 seconds")
		}
		accountApproved := model.String(src, "payer_account_id") == typed.Binding.AccountID
		for _, account := range model.Strings(src, "usage_account_ids") {
			accountApproved = accountApproved || account == typed.Binding.AccountID
		}
		if !model.Bool(src, "enabled") || model.Bool(src, "revoked") || model.String(src, "region") != typed.Binding.Region || !accountApproved {
			return nil, 0, true, store.ErrFleetHistorySource
		}
		if !creating && (old.Binding != typed.Binding || old.FleetID != typed.FleetID || old.ASGARN != typed.ASGARN) {
			return nil, 0, true, problem(422, "HISTORY_IDENTITY_IMMUTABLE", "create a separate registration when fleet or workload identity changes")
		}
		out, err = tx.FleetHistoryRegistrationAppend(ctx, model.Number(latest, "version"), typed)
	case "fleet-demand-definitions":
		var request fleetDemandDefinitionRequest
		if telemetryStrict(in, &request) != nil {
			return nil, 0, true, problem(422, "DEMAND_DEFINITION_FIELDS_INVALID", "select a registered completed-work source and semantic contract; counts and units are server-selected")
		}
		var registered fleethistory.Registration
		_, registered, err = fleetHistoryRegistered(ctx, tx, identity, request.RegistrationID)
		if err != nil {
			return nil, 0, true, err
		}
		latest := model.Document{"version": int64(0)}
		id := model.ID()
		if !creating {
			id = parts[1]
			latest, err = tx.FleetDemandDefinitionGet(ctx, id)
			if err != nil {
				return nil, 0, true, err
			}
			if model.String(latest, "registration_id") != registered.ID {
				return nil, 0, true, problem(422, "DEMAND_IDENTITY_IMMUTABLE", "a demand definition remains bound to its original fleet registration")
			}
		}
		if err = match(r, latest); err != nil {
			return nil, 0, true, err
		}
		var activity store.ActivitySource
		activity, err = tx.ActivitySource(ctx, request.ActivitySourceID)
		if err != nil {
			return nil, 0, true, err
		}
		if !activity.Enabled || activity.WorkloadID != registered.Binding.WorkloadID || activity.AccountID != registered.Binding.AccountID || activity.Region != registered.Binding.Region {
			return nil, 0, true, problem(422, "DEMAND_SOURCE_BINDING_INVALID", "the enabled independent source must match this workload, account and region")
		}
		typed := fleethistory.DemandDefinition{SchemaVersion: "1", ID: id, Version: model.Number(latest, "version") + 1, Binding: registered.Binding, Aggregation: "SINGLE_EXTERNAL_TOTAL", Meaning: "COMPLETED_WORK", BusinessOperation: request.BusinessOperation, Unit: activity.MetricDefinition.Unit, Metric: "activity.Completed", MetricDefinitionID: activity.MetricDefinition.ID, MetricDefinitionVersion: activity.MetricDefinition.Version, ValueField: "COMPLETED", Origin: "INDEPENDENT_EXTERNAL_SYSTEM", SemanticContractID: request.SemanticContractID, SemanticContractHash: request.SemanticContractHash, SourceID: activity.ID, SourceSystem: "ACTIVITY_SOURCE", SourceConfigHash: source.Hash(source.Object(activity)), Temporality: "DELTA", CadenceSeconds: 60, MaxGapSeconds: 60}
		if fleethistory.ValidateDemandDefinition(registered, typed) != nil {
			return nil, 0, true, problem(422, "DEMAND_DEFINITION_INVALID", "declare the completed business operation and versioned semantic contract")
		}
		out, err = tx.FleetDemandDefinitionAppend(ctx, registered.ID, model.Number(latest, "version"), typed)
	case "fleet-history-scopes":
		var request fleetHistoryScopeRequest
		if telemetryStrict(in, &request) != nil || request.RegistrationID == "" || request.DefinitionID == "" || request.DefinitionVersion < 1 {
			return nil, 0, true, problem(422, "HISTORY_SCOPE_SELECTION_INVALID", "select a registration and current demand definition version; historical evidence is server-selected")
		}
		if _, err = tx.Exec(ctx, "SELECT fleet_history_lock($1,$2)", identity.Tenant, request.RegistrationID); err != nil {
			return nil, 0, true, err
		}
		var registered model.Document
		registered, _, err = fleetHistoryRegistered(ctx, tx, identity, request.RegistrationID)
		if err != nil {
			return nil, 0, true, err
		}
		if err = match(r, registered); err != nil {
			return nil, 0, true, err
		}
		var definition model.Document
		definition, err = tx.FleetDemandDefinitionGet(ctx, request.DefinitionID)
		if err != nil {
			return nil, 0, true, err
		}
		if model.String(definition, "registration_id") != request.RegistrationID || model.Number(definition, "version") != request.DefinitionVersion {
			return nil, 0, true, store.ErrConflict
		}
		out, err = tx.FleetHistoryScopeCapture(ctx, request.RegistrationID, request.DefinitionID)
	}
	if err == nil {
		err = tx.Audit(ctx, identity.Subject, "fleet.history_recorded", model.String(out, "id"), model.Document{"collection": parts[0], "hash": out["hash"], "execution_authorized": false})
	}
	return out, http.StatusCreated, true, err
}
