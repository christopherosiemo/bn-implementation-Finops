package dependency

import (
	"strings"
	"testing"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
)

func storageGraphFixture() []model.Document {
	base := func(id, kind, native string) model.Document {
		return model.Document{"id": id, "tenant_id": "tenant-ebs", "provider": "AWS", "account_id": "111122223333", "region": "eu-west-1", "resource_type": kind, "provider_resource_id": native}
	}
	rel := func(kind, id, native string) model.Document {
		return model.Document{"type": kind, "target_resource_id": id, "target_provider_resource_id": native, "basis": "NATIVE_EBS_POINT_RELATIONSHIP"}
	}
	volume := base("volume", "EBS_VOLUME", "vol-0123456789abcdef0")
	instance := base("instance", "EC2", "i-0123456789abcdef0")
	snapshot := base("snapshot", "EBS_SNAPSHOT", "snap-0123456789abcdef0")
	image := base("image", "AMI_REFERENCE", "ami-0123456789abcdef0")
	volume["provider_relationships"] = []model.Document{rel("ATTACHED_TO", "instance", "i-0123456789abcdef0")}
	snapshot["provider_relationships"] = []model.Document{rel("BACKED_BY", "volume", "vol-0123456789abcdef0"), rel("DEPENDS_ON", "image", "ami-0123456789abcdef0")}
	return []model.Document{volume, instance, snapshot, image}
}

func storageStopGraphFixture() ([]model.Document, []model.Document) {
	resources := storageGraphFixture()
	for _, r := range resources[:3] {
		r["workload_id"] = "dev"
		r["environment"] = "NON_PRODUCTION"
	}
	for _, r := range []model.Document{resources[0], resources[2]} {
		native := model.Document{"volume_id": resources[0]["provider_resource_id"], "state": "completed", "snapshot_id": r["provider_resource_id"]}
		if r["resource_type"] == "EBS_VOLUME" {
			native = model.Document{"volume_id": r["provider_resource_id"], "state": "in-use", "multi_attach_enabled": false, "operator": model.Document{"managed": false, "principal": nil}, "attachments": []model.Document{{"volume_id": r["provider_resource_id"], "instance_id": resources[1]["provider_resource_id"], "state": "attached", "device": "/dev/sdf", "associated_resource": nil, "instance_owning_service": nil}}}
		}
		r["storage_stop_context"] = model.Document{"schema_version": "1", "basis": "CURRENT_INGESTER_EBS_CONFIGURATION_V1", "writer_role": "finops_ingester", "tenant_id": r["tenant_id"], "resource_id": r["id"], "provider_resource_id": r["provider_resource_id"], "resource_type": r["resource_type"], "account_id": r["account_id"], "region": r["region"], "workload_id": r["workload_id"], "config_hash": strings.Repeat("1", 64), "native": native}
	}
	return resources, []model.Document{{"id": "dev", "owner": "operator", "owner_subject": "operator-subject", "environment": "NON_PRODUCTION"}}
}

func TestStorageEC2StopPhysicalContextPreservesStrictAssessment(t *testing.T) {
	r, w := storageStopGraphFixture()
	nodes := Inventory(r, w)
	edges, err := Edges(nodes, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !hasReason(Assess(nodes, edges, "instance"), "BLOCKED_DEPENDENCY_HARD_CONSUMER") {
		t.Fatal("strict generic assessment changed")
	}
	if reasons := AssessEC2Stop(nodes, edges, "instance"); len(reasons) != 0 {
		t.Fatal("owned exclusive physical storage blocked EC2 stop", reasons)
	}
	before := InventoryHash(nodes)
	context := storageStopObject(r[0]["storage_stop_context"])
	native := storageStopObject(context["native"])
	native["multi_attach_enabled"] = true
	context["native"] = native
	r[0]["storage_stop_context"] = context
	if InventoryHash(Inventory(r, w)) == before {
		t.Fatal("changed bounded proof facts retained review hash")
	}
	legacy, workloads := graphFixture()
	legacyNodes := Inventory(legacy, workloads)
	legacyEdges, e := Edges(legacyNodes, nil)
	if e != nil {
		t.Fatal(e)
	}
	if got, want := strings.Join(AssessEC2Stop(legacyNodes, legacyEdges, "vm"), ","), strings.Join(Assess(legacyNodes, legacyEdges, "vm"), ","); got != want {
		t.Fatal("legacy no-EBS assessment changed")
	}
}

func TestStorageEC2StopUnknownSharedAndForeignContextBlocks(t *testing.T) {
	for _, name := range []string{"no-proof", "wrong-issuer", "wrong-tenant", "wrong-account", "wrong-config-reference", "unknown-multiattach", "multiattach", "shared-attachment", "wrong-instance", "service-owned", "unknown-operator", "unknown-workload", "unknown-owner", "unknown-environment", "production", "unknown-snapshot-proof"} {
		t.Run(name, func(t *testing.T) {
			r, w := storageStopGraphFixture()
			c := storageStopObject(r[0]["storage_stop_context"])
			n := storageStopObject(c["native"])
			a := storageStopObject(n["attachments"].([]any)[0])
			switch name {
			case "no-proof":
				delete(r[0], "storage_stop_context")
			case "wrong-issuer":
				c["writer_role"] = "finops_api"
			case "wrong-tenant":
				c["tenant_id"] = "foreign"
			case "wrong-account":
				c["account_id"] = "999988887777"
			case "wrong-config-reference":
				c["config_hash"] = ""
			case "unknown-multiattach":
				delete(n, "multi_attach_enabled")
			case "multiattach":
				n["multi_attach_enabled"] = true
			case "shared-attachment":
				n["attachments"] = []model.Document{a, model.Clone(a)}
			case "wrong-instance":
				a["instance_id"] = "i-fffffffffffffffff"
				n["attachments"] = []model.Document{a}
			case "service-owned":
				a["associated_resource"] = "arn:aws:ecs:eu-west-1:111122223333:task/other"
				n["attachments"] = []model.Document{a}
			case "unknown-operator":
				delete(n, "operator")
			case "unknown-workload":
				r[0]["workload_id"] = ""
			case "unknown-owner":
				w[0]["owner"] = ""
				w[0]["owner_subject"] = ""
			case "unknown-environment":
				r[0]["environment"] = "UNKNOWN"
			case "production":
				r[0]["environment"] = "PRODUCTION"
			case "unknown-snapshot-proof":
				delete(r[2], "storage_stop_context")
			}
			c["native"] = n
			if name != "no-proof" {
				r[0]["storage_stop_context"] = c
			}
			nodes := Inventory(r, w)
			edges, e := Edges(nodes, nil)
			if e != nil {
				t.Fatal(e)
			}
			if len(AssessEC2Stop(nodes, edges, "instance")) == 0 {
				t.Fatal("unknown/shared/foreign context bypassed STOP safety")
			}
		})
	}
}

func TestStorageEC2StopRetainsDeclaredAndTransitiveConsumers(t *testing.T) {
	for _, target := range []string{"instance", "volume", "snapshot"} {
		t.Run(target, func(t *testing.T) {
			r, w := storageStopGraphFixture()
			consumer := model.Document{"id": "consumer", "tenant_id": "tenant-ebs", "provider": "AWS", "account_id": "111122223333", "region": "eu-west-1", "resource_type": "EC2", "provider_resource_id": "i-fffffffffffffffff", "workload_id": "dev", "environment": "NON_PRODUCTION"}
			r = append(r, consumer)
			nodes := Inventory(r, w)
			edges, e := Edges(nodes, []model.Document{{"type": "DEPENDS_ON", "from": "resource:consumer", "to": "resource:" + target}})
			if e != nil {
				t.Fatal(e)
			}
			if !hasReason(AssessEC2Stop(nodes, edges, "instance"), "BLOCKED_DEPENDENCY_HARD_CONSUMER") {
				t.Fatal("declared/transitive runtime consumer hidden by physical context")
			}
		})
	}
	r, w := storageStopGraphFixture()
	nodes := Inventory(r, w)
	edges, e := Edges(nodes, []model.Document{{"type": "PAID_BY_COMMITMENT", "from": "resource:snapshot", "to": "resource:image"}})
	if e != nil {
		t.Fatal(e)
	}
	if !hasReason(AssessEC2Stop(nodes, edges, "instance"), "BLOCKED_DEPENDENCY_COMMITMENT_RELATIONSHIP") {
		t.Fatal("physical context removed commitment guard")
	}
}

func TestStorageNativeTopologyIsDirectedScopedAndReviewBound(t *testing.T) {
	resources := storageGraphFixture()
	nodes := Inventory(resources, nil)
	edges, err := Edges(nodes, nil)
	if err != nil || len(edges) != 3 {
		t.Fatal("native EBS topology failed", edges, err)
	}
	for _, edge := range edges {
		if edge["source"] != "DISCOVERED_MAPPING" {
			t.Fatal("native source lost")
		}
		if edge["from"] == "resource:volume" && edge["to"] == "resource:snapshot" {
			t.Fatal("reciprocal backup edge invented")
		}
	}
	before := InventoryHash(nodes)
	resources[0]["provider_relationships"] = []model.Document{}
	if InventoryHash(Inventory(resources, nil)) == before {
		t.Fatal("changed native attachments retained review hash")
	}
	resources = storageGraphFixture()
	resources[1]["tenant_id"] = "foreign"
	if InventoryHash(Inventory(resources, nil)) == before {
		t.Fatal("changed scoped endpoint retained review hash")
	}
}

func TestStorageNativeGraphRejectsConfusedEndpointsAndEdgeKinds(t *testing.T) {
	for _, tc := range []struct {
		name, field string
		value       any
	}{
		{"foreign-tenant", "tenant_id", "foreign"},
		{"unknown-tenant", "tenant_id", nil},
		{"foreign-account", "account_id", "999988887777"},
		{"wrong-region", "region", "us-east-1"},
		{"wrong-provider", "provider", "AZURE"},
		{"wrong-native-instance", "provider_resource_id", "i-fffffffffffffffff"},
		{"wrong-resource-kind", "resource_type", "RDS_INSTANCE"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resources := storageGraphFixture()
			resources[1][tc.field] = tc.value
			if _, err := Edges(Inventory(resources, nil), nil); err == nil {
				t.Fatal("confused EBS endpoint accepted")
			}
		})
	}
	resources := storageGraphFixture()
	resources[0]["provider_relationships"] = []model.Document{{"type": "BACKED_BY", "target_resource_id": "snapshot", "target_provider_resource_id": "snap-0123456789abcdef0", "basis": "NATIVE_EBS_POINT_RELATIONSHIP"}}
	if _, err := Edges(Inventory(resources, nil), nil); err == nil {
		t.Fatal("opposite backup direction accepted")
	}
	resources = storageGraphFixture()
	resources[2]["provider_relationships"] = []model.Document{{"type": "CONFIGURED_BY", "target_resource_id": "image", "target_provider_resource_id": "ami-0123456789abcdef0", "basis": "NATIVE_EBS_POINT_RELATIONSHIP"}}
	if _, err := Edges(Inventory(resources, nil), nil); err == nil {
		t.Fatal("native image promoted to configuration authority")
	}
}

func TestStorageNativeGraphPreservesLegacyInventoryAndDeclaredSource(t *testing.T) {
	resources, workloads := graphFixture()
	before := InventoryHash(Inventory(resources, workloads))
	resources[0]["tenant_id"] = "legacy-server-tenant"
	if InventoryHash(Inventory(resources, workloads)) != before {
		t.Fatal("legacy EC2 inventory wire changed without EBS")
	}
	resources = storageGraphFixture()
	nodes := Inventory(resources, nil)
	edges, err := Edges(nodes, []model.Document{{"type": "ATTACHED_TO", "from": "resource:volume", "to": "resource:instance", "source": "OPERATOR_DECLARED"}})
	if err != nil || len(edges) != 3 {
		t.Fatal("native duplicate failed", err)
	}
	for _, edge := range edges {
		if edge["from"] == "resource:volume" && edge["source"] != "DISCOVERED_MAPPING" {
			t.Fatal("native relationship lost to declared source")
		}
	}
	resources[0]["provider_relationships"] = []model.Document{}
	edges, err = Edges(Inventory(resources, nil), []model.Document{{"type": "ATTACHED_TO", "from": "resource:volume", "to": "resource:instance", "source": "DISCOVERED_MAPPING"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, edge := range edges {
		if edge["from"] == "resource:volume" && edge["source"] != "OPERATOR_DECLARED" {
			t.Fatal("caller manufactured native authority")
		}
	}
}
