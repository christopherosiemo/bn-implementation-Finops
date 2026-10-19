package service

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/auth"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
)

func TestMutationAuthorizationCoversExactRoutesWithoutBroadeningRoles(t *testing.T) {
	groups := []struct{ paths, allowed string }{
		{"cloud-accounts workloads executions control/pause demo/reset demo/scenario policies/id resources/id/configure activity-sources resource-graph resources/id/dependency-reviews workloads/id/slo-objectives slo-sources workloads/id/safety-profiles resources/id/configuration-authorities workloads/id/configuration-proposals telemetry-connections telemetry-connections/id/revisions telemetry-connections/id/revoke telemetry-connections/id/sync telemetry-connections/id/evaluate fleet-history-registrations fleet-history-registrations/id/revisions fleet-demand-definitions fleet-demand-definitions/id/revisions fleet-history-scopes", "PLATFORM_ADMIN"},
		{"recommendations change-plans source-connections source-connections/id/sync source-connections/id/revoke resources/id/readiness/refresh", "FINOPS_ADMIN PLATFORM_ADMIN"},
		{"approvals", "APPROVER PLATFORM_ADMIN"},
		{"schedules schedules/id/pause schedules/id/skip-next-stop workloads/id/signals executions/id/start-now", "PLATFORM_ADMIN APPLICATION_OWNER"},
		{"savings/verify", "FINOPS_ADMIN FINANCE PLATFORM_ADMIN"},
		{"billing/import evidence/baselines evidence/measurements allocation-policies allocation-reports", "FINOPS_ADMIN FINANCE"},
		{"workloads/id/capacity-assessments", "FINOPS_ADMIN PLATFORM_ADMIN APPLICATION_OWNER"},
	}
	for _, group := range groups {
		for _, path := range strings.Fields(group.paths) {
			for _, role := range []string{"PLATFORM_ADMIN", "FINOPS_ADMIN", "FINANCE", "APPROVER", "APPLICATION_OWNER", "AUDITOR", "VIEWER", "ORGANISATION_OWNER", "UNKNOWN"} {
				t.Run(path+"/"+role, func(t *testing.T) {
					i := auth.Identity{Roles: map[string]bool{role: true}}
					allowed := role == "ORGANISATION_OWNER" || strings.Contains(" "+group.allowed+" ", " "+role+" ")
					if err := authorizeMutationRole(i, "/v1/"+path); (err == nil) != allowed {
						t.Fatalf("current role authorization changed: allowed=%v error=%v", allowed, err)
					}
				})
			}
		}
	}
	for _, path := range []string{"", "schedules/", "schedules//pause", "schedules/id/revisions", "workloads/id/unknown", "source-connections/id", "telemetry-connections/id", "telemetry-connections/id/evaluate/extra", "fleet-history-scopes/id/revisions", "allocation-sources", "allocation-reports/id", "unknown"} {
		if err := authorizeMutationRole(auth.Identity{Roles: map[string]bool{"ORGANISATION_OWNER": true}}, "/v1/"+path); err == nil {
			t.Fatal("unknown mutation route gained replay authority", path)
		} else {
			var p *Problem
			if !errors.As(err, &p) || p.Status != 404 {
				t.Fatal("unknown mutation route must fail closed", path, err)
			}
		}
	}
}

func TestMutationReplayAuthorizationResolvesAllOwnerScopeKinds(t *testing.T) {
	for _, test := range []struct{ path, kind, id string }{
		{"schedules", "workloads", "body-workload"},
		{"schedules/path-schedule/pause", "schedules", "path-schedule"},
		{"schedules/path-schedule/skip-next-stop", "schedules", "path-schedule"},
		{"workloads/path-workload/signals", "workloads", "path-workload"},
		{"workloads/path-workload/capacity-assessments", "workloads", "path-workload"},
		{"approvals", "change_plans", "body-plan"},
		{"executions/path-execution/start-now", "executions", "path-execution"},
	} {
		rule, ok := mutationAuthorizationFor("/v1/"+test.path, model.Document{"workload_id": "body-workload", "change_plan_id": "body-plan"})
		if !ok || rule.scopeKind != test.kind || rule.scopeID != test.id {
			t.Fatalf("wrong current ownership target for %s: %+v", test.path, rule)
		}
	}
	owner := auth.Identity{Roles: map[string]bool{"APPLICATION_OWNER": true}}
	if err := authorizeMutationReplay(context.Background(), nil, owner, "/v1/schedules", model.Document{"mode": "AUTOPILOT"}); err == nil {
		t.Fatal("demoted Autopilot creator retained platform replay authority")
	}
	platform := auth.Identity{Roles: map[string]bool{"PLATFORM_ADMIN": true}}
	if err := authorizeMutationReplay(context.Background(), nil, platform, "/v1/schedules", model.Document{"mode": "AUTOPILOT"}); err != nil {
		t.Fatal("current platform role cannot reconcile a committed Autopilot response", err)
	}
}
