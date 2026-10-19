package service

import (
	"context"
	"strings"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/auth"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
)

// Mutation authorization is independent of state preconditions. A committed
// response can be replayed after its original If-Match, readiness or approval
// has advanced, but only by a caller who is still allowed to use that route.
type mutationAuthorization struct {
	roles []string
	// Workload ownership is resolved again on a cache hit. A kind of workloads
	// uses the ID directly; other kinds resolve their CURRENT workload mapping.
	scopeKind string
	scopeID   string
}

func mutationAuthorizationFor(path string, in model.Document) (mutationAuthorization, bool) {
	p := strings.Split(strings.TrimPrefix(path, "/v1/"), "/")
	for _, part := range p {
		if part == "" {
			return mutationAuthorization{}, false
		}
	}
	platform := []string{"PLATFORM_ADMIN"}
	finops := []string{"FINOPS_ADMIN", "PLATFORM_ADMIN"}
	finance := []string{"FINOPS_ADMIN", "FINANCE"}
	owner := []string{"PLATFORM_ADMIN", "APPLICATION_OWNER"}
	rule := func(roles []string) (mutationAuthorization, bool) {
		return mutationAuthorization{roles: roles}, true
	}
	if len(p) == 1 {
		switch p[0] {
		case "cloud-accounts", "workloads", "executions", "activity-sources", "resource-graph", "slo-sources", "telemetry-connections", "fleet-history-registrations", "fleet-demand-definitions", "fleet-history-scopes", "fleet-fixture-proposals":
			return rule(platform)
		case "recommendations", "change-plans", "source-connections":
			return rule(finops)
		case "allocation-policies", "allocation-reports":
			return rule(finance)
		case "schedules":
			return mutationAuthorization{roles: owner, scopeKind: "workloads", scopeID: model.String(in, "workload_id")}, true
		case "approvals":
			if in["commitment_decision_id"] != nil {
				return rule([]string{"FINANCE"})
			}
			return mutationAuthorization{roles: []string{"APPROVER", "PLATFORM_ADMIN"}, scopeKind: "change_plans", scopeID: model.String(in, "change_plan_id")}, true
		}
	}
	if len(p) == 2 {
		switch p[0] + "/" + p[1] {
		case "control/pause", "demo/reset", "demo/scenario":
			return rule(platform)
		case "billing/import", "evidence/baselines", "evidence/measurements":
			return rule(finance)
		case "savings/verify":
			return rule([]string{"FINOPS_ADMIN", "FINANCE", "PLATFORM_ADMIN"})
		}
		if p[0] == "policies" {
			return rule(platform)
		}
	}
	if len(p) == 3 {
		switch p[0] {
		case "fleet-group-authorizations":
			if p[2] == "approvals" {
				return rule([]string{"APPROVER"})
			}
		case "fleet-fixture-proposals":
			if p[2] == "approvals" {
				return rule([]string{"APPROVER"})
			}
			if p[2] == "runs" {
				return rule(platform)
			}
		case "schedules":
			if p[2] == "pause" || p[2] == "skip-next-stop" {
				return mutationAuthorization{roles: owner, scopeKind: "schedules", scopeID: p[1]}, true
			}
		case "executions":
			if p[2] == "start-now" {
				return mutationAuthorization{roles: owner, scopeKind: "executions", scopeID: p[1]}, true
			}
		case "workloads":
			switch p[2] {
			case "fleet-native-assessments", "fleet-joint-decisions", "commitment-decisions", "commitment-decision-inputs":
				return mutationAuthorization{roles: finance, scopeKind: "workloads", scopeID: p[1]}, true
			case "signals":
				return mutationAuthorization{roles: owner, scopeKind: "workloads", scopeID: p[1]}, true
			case "capacity-assessments", "fleet-native-capacity-batches":
				return mutationAuthorization{roles: []string{"FINOPS_ADMIN", "PLATFORM_ADMIN", "APPLICATION_OWNER"}, scopeKind: "workloads", scopeID: p[1]}, true
			case "slo-objectives", "safety-profiles", "configuration-proposals":
				return rule(platform)
			}
		case "resources":
			if p[2] == "configure" || p[2] == "dependency-reviews" || p[2] == "configuration-authorities" {
				return rule(platform)
			}
		case "source-connections":
			if p[2] == "sync" || p[2] == "revoke" {
				return rule(finops)
			}
		case "telemetry-connections":
			if p[2] == "revisions" || p[2] == "revoke" || p[2] == "sync" || p[2] == "evaluate" {
				return rule(platform)
			}
		case "fleet-history-registrations":
			if p[2] == "revisions" || p[2] == "configuration-authorities" || p[2] == "configuration-proposals" {
				return rule(platform)
			}
		case "fleet-demand-definitions":
			if p[2] == "revisions" {
				return rule(platform)
			}
		}
	}
	if len(p) == 4 && p[0] == "resources" && p[2] == "readiness" && p[3] == "refresh" {
		return rule(finops)
	}
	return mutationAuthorization{}, false
}

func authorizeMutationBodyRole(i auth.Identity, path string, in model.Document) error {
	rule, ok := mutationAuthorizationFor(path, in)
	if !ok {
		return problem(404, "NOT_FOUND", "route not found")
	}
	if path == "/v1/approvals" && in["commitment_decision_id"] != nil {
		if !i.Roles["FINANCE"] {
			return problem(403, "FINANCE_REQUIRED", "independent Finance review required")
		}
		if len(in) != 2 || in["change_plan_id"] != nil {
			return problem(422, "EXACT_DECISION_REVIEW_REQUIRED", "select one exact financial decision")
		}
	}
	return requireRole(i, rule.roles...)
}

func authorizeMutationRole(i auth.Identity, path string) error {
	rule, ok := mutationAuthorizationFor(path, nil)
	if !ok {
		return problem(404, "NOT_FOUND", "route not found")
	}
	return requireRole(i, rule.roles...)
}

func authorizeMutationReplay(ctx context.Context, t *store.Tx, i auth.Identity, path string, in model.Document) error {
	rule, ok := mutationAuthorizationFor(path, in)
	if !ok {
		return problem(404, "NOT_FOUND", "route not found")
	}
	if err := requireRole(i, rule.roles...); err != nil {
		return err
	}
	if path == "/v1/approvals" && in["commitment_decision_id"] != nil {
		return commitmentDecisionReviewReplay(ctx, t, i, in)
	}
	// Resolve workload authorization again even on exact cached responses. A
	// replay neither refreshes evidence nor substitutes the caller's old role.
	parts := strings.Split(strings.TrimPrefix(path, "/v1/"), "/")
	if len(parts) == 3 && parts[0] == "workloads" && (parts[2] == "fleet-native-assessments" || parts[2] == "fleet-native-capacity-batches" || parts[2] == "fleet-joint-decisions" || parts[2] == "commitment-decisions" || parts[2] == "commitment-decision-inputs") {
		if _, err := t.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", i.Tenant+":dependency-graph"); err != nil {
			return err
		}
		return fleetHistoryWorkload(ctx, t, i, parts[1])
	}
	if len(parts) == 3 && parts[0] == "fleet-group-authorizations" && parts[2] == "approvals" {
		_, err := fleetGroupAuthorityAccess(ctx, t, i, parts[1])
		return err
	}
	if len(parts) > 0 && parts[0] == "fleet-fixture-proposals" {
		if len(parts) == 3 {
			_, err := fleetFixtureAccess(ctx, t, i, parts[1])
			return err
		}
		if len(parts) == 1 {
			for _, field := range []string{"old_configuration_proposal_id", "candidate_configuration_proposal_id"} {
				d, err := t.FleetConfigurationProposalGet(ctx, model.String(in, field))
				if err != nil {
					return err
				}
				if err = fleetHistoryWorkload(ctx, t, i, model.String(sourceObject(d["binding"]), "workload_id")); err != nil {
					return err
				}
			}
			return nil
		}
	}
	if path == "/v1/schedules" && model.String(in, "mode") == "AUTOPILOT" && !i.Can("PLATFORM_ADMIN") {
		return problem(403, "FORBIDDEN", "platform administrator required for Autopilot schedules")
	}
	if !scopedOwner(i) || rule.scopeKind == "" {
		return nil
	}
	// Only the replay branch acquires this guard. Taking it before a fresh
	// mutation would reverse the scheduling/execution control lock order.
	// Inventory/owner updates use the same guard; authorize and select the
	// cached result under one stable current workload mapping.
	if _, err := t.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", t.Tenant+":dependency-graph"); err != nil {
		return err
	}
	wid := rule.scopeID
	if rule.scopeKind != "workloads" {
		current, err := t.Get(ctx, rule.scopeKind, rule.scopeID)
		if err != nil {
			return err
		}
		wid = model.String(current, "workload_id")
	}
	w, err := t.Get(ctx, "workloads", wid)
	if err != nil {
		return err
	}
	return workloadAccess(i, w)
}
