package service

import (
	"github.com/christopherosiemo/bn-implementation-Finops/internal/auth"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"testing"
)

func TestSavingsOverlapUsesHalfOpenWindows(t *testing.T) {
	a := []model.Document{{"start": "2026-09-01T00:00:00Z", "end": "2026-09-02T00:00:00Z"}}
	if !CoverageOverlaps(a, []model.Document{{"start": "2026-09-01T12:00:00Z", "end": "2026-09-03T00:00:00Z"}}) {
		t.Fatal("overlap missed")
	}
	if CoverageOverlaps(a, []model.Document{{"start": "2026-09-02T00:00:00Z", "end": "2026-09-03T00:00:00Z"}}) {
		t.Fatal("adjacent windows overlap")
	}
}
func TestApplicationOwnerCannotOperateUnassignedWorkload(t *testing.T) {
	i := auth.Identity{Tenant: "tenant", Subject: "subject-a", Email: "a@example.test", Roles: map[string]bool{"APPLICATION_OWNER": true}}
	if workloadAccess(i, model.Document{"owner": "b@example.test"}) == nil {
		t.Fatal("unassigned workload permitted")
	}
	if e := workloadAccess(i, model.Document{"owner": "a@example.test"}); e != nil {
		t.Fatal(e)
	}
	d := model.Document{"workloads": []model.Document{{"id": "a", "owner": "a@example.test"}, {"id": "b", "owner": "b@example.test"}}, "resources": []model.Document{{"id": "a", "workload_id": "a"}, {"id": "b", "workload_id": "b"}}, "dependency_graph": model.Document{"version": 9, "graph_hash": "hidden", "nodes": []model.Document{{"id": "workload:b"}}, "edges": []model.Document{{"from": "workload:b", "to": "resource:a"}}, "reviews": []model.Document{{"reviewed_by": "other-owner"}}}}
	restrictDashboard(i, d)
	if len(d["resources"].([]model.Document)) != 1 {
		t.Fatal("dashboard leaked unassigned resources")
	}
	graph := d["dependency_graph"].(model.Document)
	if model.String(graph, "status") != "UNKNOWN" || len(graph["nodes"].([]model.Document)) != 0 || len(graph["edges"].([]model.Document)) != 0 || len(graph["reviews"].([]model.Document)) != 0 || model.String(graph, "graph_hash") != "" {
		t.Fatal("scoped dashboard exposed hidden topology or implied its absence")
	}
}
