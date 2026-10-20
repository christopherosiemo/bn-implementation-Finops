package dependency

import (
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"testing"
)

func TestDatabaseNativeTopologyIsDirectedAndBound(t *testing.T) {
	cluster := model.Document{"id": "cluster", "resource_type": "RDS_CLUSTER", "provider_resource_id": "arn:cluster", "account_id": "111122223333", "region": "eu-west-1"}
	instance := model.Document{"id": "instance", "resource_type": "RDS_INSTANCE", "provider_resource_id": "arn:instance", "account_id": "111122223333", "region": "eu-west-1", "provider_relationships": []model.Document{{"type": "MEMBER_OF", "target_resource_id": "cluster", "target_provider_resource_id": "arn:cluster"}}}
	nodes := Inventory([]model.Document{instance, cluster}, nil)
	edges, err := Edges(nodes, nil)
	if err != nil || len(edges) != 1 || model.String(edges[0], "from") != "resource:instance" || model.String(edges[0], "to") != "resource:cluster" {
		t.Fatal("native topology", edges, err)
	}
	before := InventoryHash(nodes)
	instance["provider_relationships"] = []model.Document{}
	if InventoryHash(Inventory([]model.Document{instance, cluster}, nil)) == before {
		t.Fatal("changed topology retained review hash")
	}
	instance["provider_relationships"] = []model.Document{{"type": "MEMBER_OF", "target_resource_id": "cluster", "target_provider_resource_id": "arn:wrong"}}
	if _, err = Edges(Inventory([]model.Document{instance, cluster}, nil), nil); err == nil {
		t.Fatal("confused native ARN accepted")
	}
}
