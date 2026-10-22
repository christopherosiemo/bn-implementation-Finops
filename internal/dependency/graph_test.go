package dependency

import (
	"errors"
	"testing"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
)

func graphFixture() ([]model.Document, []model.Document) {
	w := []model.Document{{"id": "dev", "owner": "owner@example.test", "owner_subject": "owner", "environment": "NON_PRODUCTION"}}
	r := []model.Document{{"id": "vm", "provider": "AWS", "provider_resource_id": "i-pilot", "account_id": "111122223333", "region": "eu-west-1", "resource_type": "EC2", "workload_id": "dev", "environment": "NON_PRODUCTION", "configuration_authority": "TERRAFORM", "runtime_stop_start_delegated": true, "state": "running"}}
	return r, w
}
func hasReason(reasons []string, reason string) bool {
	for _, r := range reasons {
		if r == reason {
			return true
		}
	}
	return false
}

func TestAutomaticMappingAndExplicitEdgesHaveNoSoftBypass(t *testing.T) {
	r, w := graphFixture()
	nodes := Inventory(r, w)
	edges, e := Edges(nodes, []model.Document{{"type": "RUNS_ON", "from": "workload:dev", "to": "resource:vm", "source": "OPERATOR_DECLARED"}, {"type": "RUNS_ON", "from": "workload:dev", "to": "resource:vm"}})
	if e != nil {
		t.Fatal(e)
	}
	if len(edges) != 1 || edges[0]["source"] != "DISCOVERED_MAPPING" {
		t.Fatal("mapping was duplicated or spoofed")
	}
	if reasons := Assess(nodes, edges, "vm"); len(reasons) != 0 {
		t.Fatalf("own standalone mapping blocked: %v", reasons)
	}
	w = append(w, model.Document{"id": "consumer", "owner": "other", "environment": "NON_PRODUCTION"})
	nodes = Inventory(r, w)
	for kind := range edgeTypes {
		declared := []model.Document{{"type": kind, "from": "workload:consumer", "to": "resource:vm", "source": "DISCOVERED_MAPPING"}}
		out, e := Edges(nodes, declared)
		if e != nil {
			t.Fatal(e)
		}
		found := false
		for _, edge := range out {
			if edge["from"] == "workload:consumer" {
				found = true
				if edge["source"] != "OPERATOR_DECLARED" {
					t.Fatal("caller upgraded declaration to a server mapping")
				}
			}
		}
		if !found || !hasReason(Assess(nodes, out, "vm"), "BLOCKED_DEPENDENCY_HARD_CONSUMER") {
			t.Fatalf("%s did not remain a hard dependency", kind)
		}
	}
	if _, e = Edges(nodes, []model.Document{{"type": "DEPENDS_ON", "from": "workload:consumer", "to": "resource:vm", "hard": false}}); e == nil {
		t.Fatal("soft-edge field accepted")
	}
}

func TestUnknownEndpointsSelfEdgesCyclesAndInvalidTypesFailClosed(t *testing.T) {
	r, w := graphFixture()
	nodes := Inventory(r, w)
	for _, tc := range []struct {
		edge   model.Document
		reason string
	}{
		{model.Document{"type": "DEPENDS_ON", "from": "workload:missing", "to": "resource:vm"}, "BLOCKED_DEPENDENCY_ENDPOINT_UNKNOWN"},
		{model.Document{"type": "DEPENDS_ON", "from": "resource:vm", "to": "resource:vm"}, "BLOCKED_DEPENDENCY_SELF_EDGE"},
		{model.Document{"type": "DEPENDS_ON", "from": "resource:vm", "to": "workload:dev"}, "BLOCKED_DEPENDENCY_CYCLE"},
		{model.Document{"type": "LOOKS_IDLE", "from": "workload:dev", "to": "resource:vm"}, "BLOCKED_DEPENDENCY_EDGE_TYPE"},
	} {
		_, e := Edges(nodes, []model.Document{tc.edge})
		var invalid *ValidationError
		if !errors.As(e, &invalid) || invalid.Code != tc.reason || e.Error() != tc.reason {
			t.Fatalf("want typed %s got %v", tc.reason, e)
		}
	}
	if _, e := Edges(append(nodes, nodes[0]), nil); e == nil {
		t.Fatal("duplicate canonical identity accepted")
	}
}

func TestTransitiveConsumersProductionAndUnknownOwnershipBlock(t *testing.T) {
	r, w := graphFixture()
	w = append(w, model.Document{"id": "checkout", "owner": "production-owner", "environment": "PRODUCTION"})
	other := model.Clone(r[0])
	other["id"], other["provider_resource_id"], other["workload_id"], other["environment"], other["state"] = "other", "i-other", "checkout", "PRODUCTION", "stopped"
	r = append(r, other)
	nodes := Inventory(r, w)
	edges, e := Edges(nodes, []model.Document{{"type": "DEPENDS_ON", "from": "resource:other", "to": "resource:vm"}})
	if e != nil {
		t.Fatal(e)
	}
	reasons := Assess(nodes, edges, "vm")
	if !hasReason(reasons, "BLOCKED_DEPENDENCY_PRODUCTION") || !hasReason(reasons, "BLOCKED_DEPENDENCY_HARD_CONSUMER") {
		t.Fatalf("transitive stopped production consumer missed: %v", reasons)
	}
	w[1]["owner"], w[1]["environment"] = "", "UNKNOWN"
	nodes = Inventory(r, w)
	reasons = Assess(nodes, edges, "vm")
	if !hasReason(reasons, "BLOCKED_DEPENDENCY_OWNER_UNKNOWN") || !hasReason(reasons, "BLOCKED_DEPENDENCY_ENVIRONMENT_UNKNOWN") {
		t.Fatalf("unknown consumer treated safe: %v", reasons)
	}
	if !hasReason(Assess(nodes, edges, "absent"), "BLOCKED_DEPENDENCY_TARGET_UNKNOWN") {
		t.Fatal("missing target did not block")
	}
}

func TestInventoryHashTracksAuthorityNotHeartbeat(t *testing.T) {
	r, w := graphFixture()
	original := InventoryHash(Inventory(r, w))
	r[0]["state"], r[0]["last_seen_at"], r[0]["version"] = "stopped", "new-heartbeat", 99
	w[0]["signals_at"], w[0]["version"] = "new-signals", 100
	r[0]["name"], w[0]["name"] = "Pilot instance", "Sandbox workload"
	for _, node := range Inventory(r, w) {
		if model.String(node, "name") == "" {
			t.Fatal("display name omitted from graph inventory")
		}
	}
	if InventoryHash(Inventory(r, w)) != original {
		t.Fatal("display name, heartbeat or runtime state invalidated owner review")
	}
	for _, field := range []string{"provider_resource_id", "account_id", "region", "workload_id", "environment", "configuration_authority", "runtime_stop_start_delegated"} {
		copy := []model.Document{model.Clone(r[0])}
		copy[0][field] = "changed"
		if InventoryHash(Inventory(copy, w)) == original {
			t.Fatalf("binding change %s omitted from inventory hash", field)
		}
	}
	w[0]["owner"] = "another-owner"
	if InventoryHash(Inventory(r, w)) == original {
		t.Fatal("owner reassignment retained review")
	}
	if GraphHash(1, original, nil) == GraphHash(2, original, nil) {
		t.Fatal("graph revision omitted from binding")
	}
}

func TestOutwardFleetMembershipIsNotAnExecutionLoophole(t *testing.T) {
	r, w := graphFixture()
	w = append(w, model.Document{"id": "controller", "owner": "operator", "environment": "NON_PRODUCTION"})
	nodes := Inventory(r, w)
	for _, kind := range []string{"MEMBER_OF", "MANAGED_BY", "SCALES_WITH"} {
		edges, e := Edges(nodes, []model.Document{{"type": kind, "from": "resource:vm", "to": "workload:controller"}})
		if e != nil {
			t.Fatal(e)
		}
		if !hasReason(Assess(nodes, edges, "vm"), "BLOCKED_DEPENDENCY_MANAGED_RELATIONSHIP") {
			t.Fatalf("outward %s relation did not block standalone executor", kind)
		}
	}
}
