package dependency

import (
	"encoding/json"
	"strings"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
)

func storageNativeResource(n model.Document) bool {
	kind := model.String(n, "resource_type")
	return kind == "EBS_VOLUME" || kind == "EBS_SNAPSHOT"
}

// AssessEC2Stop retains strict Assess and all its ownership, environment and
// managed/commitment checks. It removes only HARD_CONSUMER when every cause in
// the entire original inbound closure is a proven physical EBS component or
// that component's own workload mapping. No edge or consumer is dropped.
func AssessEC2Stop(nodes, edges []model.Document, targetResource string) []string {
	strict := Assess(nodes, edges, targetResource)
	hard := false
	for _, reason := range strict {
		if reason == "BLOCKED_DEPENDENCY_HARD_CONSUMER" {
			hard = true
		}
	}
	if !hard {
		return strict
	}
	index, err := inventoryIndex(nodes)
	if err != nil {
		return strict
	}
	target := targetResource
	if !strings.HasPrefix(target, "resource:") {
		target = "resource:" + target
	}
	targetNode := index[target]
	if model.String(targetNode, "resource_type") != "EC2" || model.String(targetNode, "provider") != "AWS" {
		return strict
	}
	validated, err := Edges(nodes, edges)
	if err != nil {
		return strict
	}
	physical, physicalEdges := map[string]bool{}, map[string]bool{}
	key := func(edge model.Document) string {
		return model.String(edge, "type") + "\x00" + model.String(edge, "from") + "\x00" + model.String(edge, "to")
	}
	for _, edge := range validated {
		from := model.String(edge, "from")
		if edge["to"] == target && edge["type"] == "ATTACHED_TO" && edge["source"] == "DISCOVERED_MAPPING" && storageStopVolume(index[from], targetNode) {
			physical[from] = true
			physicalEdges[key(edge)] = true
		}
	}
	for _, edge := range validated {
		from, to := model.String(edge, "from"), model.String(edge, "to")
		if physical[to] && edge["type"] == "BACKED_BY" && edge["source"] == "DISCOVERED_MAPPING" && storageStopSnapshot(index[from], index[to], targetNode) {
			physical[from] = true
			physicalEdges[key(edge)] = true
		}
	}
	incoming := map[string][]model.Document{}
	for _, edge := range validated {
		to := model.String(edge, "to")
		incoming[to] = append(incoming[to], edge)
	}
	own := "workload:" + model.String(targetNode, "workload_id")
	seen := map[string]bool{}
	queue := []string{target}
	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		if seen[id] {
			continue
		}
		seen[id] = true
		for _, edge := range incoming[id] {
			from := model.String(edge, "from")
			ownMapping := (id == target || physical[id]) && from == own && edge["type"] == "RUNS_ON" && edge["source"] == "DISCOVERED_MAPPING"
			if !ownMapping && !physicalEdges[key(edge)] {
				return strict
			}
			queue = append(queue, from)
		}
	}
	out := []string{}
	for _, reason := range strict {
		if reason != "BLOCKED_DEPENDENCY_HARD_CONSUMER" {
			out = append(out, reason)
		}
	}
	return out
}

func storageStopObject(value any) model.Document {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil
	}
	var out model.Document
	if json.Unmarshal(raw, &out) != nil {
		return nil
	}
	return out
}
func storageStopScope(n, target model.Document) (model.Document, bool) {
	c := storageStopObject(n["storage_stop_context"])
	if model.String(n, "kind") != "RESOURCE" || model.String(n, "tenant_id") == "" || n["tenant_id"] != target["tenant_id"] || n["provider"] != "AWS" || target["provider"] != "AWS" || model.String(n, "account_id") == "" || n["account_id"] != target["account_id"] || model.String(n, "region") == "" || n["region"] != target["region"] || model.String(n, "workload_id") == "" || n["workload_id"] != target["workload_id"] || n["environment"] != "NON_PRODUCTION" || target["environment"] != "NON_PRODUCTION" || n["workload_environment"] != "NON_PRODUCTION" || target["workload_environment"] != "NON_PRODUCTION" || model.String(n, "owner") == "" && model.String(n, "owner_subject") == "" || n["owner"] != target["owner"] || n["owner_subject"] != target["owner_subject"] || model.Bool(n, "fleet_managed") || c["schema_version"] != "1" || model.String(c, "basis") != "CURRENT_INGESTER_EBS_CONFIGURATION_V1" || c["writer_role"] != "finops_ingester" || c["tenant_id"] != n["tenant_id"] || c["resource_id"] != n["resource_id"] || c["provider_resource_id"] != n["provider_resource_id"] || c["resource_type"] != n["resource_type"] || c["account_id"] != n["account_id"] || c["region"] != n["region"] || c["workload_id"] != n["workload_id"] || len(model.String(c, "config_hash")) != 64 {
		return nil, false
	}
	return storageStopObject(c["native"]), true
}
func storageStopVolume(volume, target model.Document) bool {
	n, ok := storageStopScope(volume, target)
	if !ok || volume["resource_type"] != "EBS_VOLUME" || n["volume_id"] != volume["provider_resource_id"] || n["state"] != "in-use" || n["multi_attach_enabled"] != false {
		return false
	}
	operator := storageStopObject(n["operator"])
	if operator["managed"] != false || !storageStopEmpty(operator["principal"]) {
		return false
	}
	var attachments []model.Document
	raw, _ := json.Marshal(n["attachments"])
	if json.Unmarshal(raw, &attachments) != nil || len(attachments) != 1 {
		return false
	}
	a := attachments[0]
	return a["volume_id"] == volume["provider_resource_id"] && a["instance_id"] == target["provider_resource_id"] && a["state"] == "attached" && model.String(a, "device") != "" && storageStopEmpty(a["associated_resource"]) && storageStopEmpty(a["instance_owning_service"])
}
func storageStopEmpty(value any) bool { return value == nil || value == "" }
func storageStopSnapshot(snapshot, volume, target model.Document) bool {
	n, ok := storageStopScope(snapshot, target)
	return ok && snapshot["resource_type"] == "EBS_SNAPSHOT" && n["snapshot_id"] == snapshot["provider_resource_id"] && n["volume_id"] == volume["provider_resource_id"] && n["state"] == "completed"
}

// Add tenant scope only for the new EBS sources and the endpoints they actually
// reference. A tenant with no EBS relationships keeps the legacy inventory wire
// and review hashes, including existing EC2 and RDS schedule contracts.
func storageNativeScope(resources []model.Document) map[string]bool {
	ids := map[string]bool{}
	for _, r := range resources {
		if !storageNativeResource(r) {
			continue
		}
		ids[model.String(r, "id")] = true
		var relationships []model.Document
		raw, _ := json.Marshal(r["provider_relationships"])
		_ = json.Unmarshal(raw, &relationships)
		for _, rel := range relationships {
			ids[model.String(rel, "target_resource_id")] = true
		}
	}
	return ids
}

// These are the collector's point-in-time physical relationships. They never
// confer historical ownership, configuration proof, or mutation authority.
func storageNativeRelationships(n model.Document, index map[string]model.Document) ([]model.Document, error) {
	raw, err := json.Marshal(n["provider_relationships"])
	if err != nil {
		return nil, invalid("BLOCKED_DEPENDENCY_NATIVE_BINDING", model.String(n, "id"))
	}
	var relationships []model.Document
	if json.Unmarshal(raw, &relationships) != nil || len(relationships) > MaxEdges {
		return nil, invalid("BLOCKED_DEPENDENCY_NATIVE_BINDING", model.String(n, "id"))
	}
	out := []model.Document{}
	for _, rel := range relationships {
		target := index["resource:"+model.String(rel, "target_resource_id")]
		if target == nil || model.String(n, "provider") != "AWS" || model.String(target, "provider") != "AWS" || model.String(n, "tenant_id") == "" || target["tenant_id"] != n["tenant_id"] || model.String(n, "account_id") == "" || target["account_id"] != n["account_id"] || model.String(n, "region") == "" || target["region"] != n["region"] || model.String(target, "provider_resource_id") == "" || target["provider_resource_id"] != rel["target_provider_resource_id"] {
			return nil, invalid("BLOCKED_DEPENDENCY_NATIVE_BINDING", model.String(n, "id"))
		}
		kind, fromKind, toKind := model.String(rel, "type"), model.String(n, "resource_type"), model.String(target, "resource_type")
		allowed := fromKind == "EBS_VOLUME" && kind == "ATTACHED_TO" && toKind == "EC2" || fromKind == "EBS_SNAPSHOT" && kind == "BACKED_BY" && toKind == "EBS_VOLUME" || fromKind == "EBS_SNAPSHOT" && kind == "DEPENDS_ON" && toKind == "AMI_REFERENCE"
		if kind == "CONFIGURED_BY" && toKind == "IAC_AUTHORITY_REFERENCE" {
			ref := model.Document{}
			raw, _ := json.Marshal(target["configuration_authority_reference"])
			_ = json.Unmarshal(raw, &ref)
			allowed = model.String(rel, "basis") == "REGISTERED_CONFIGURATION_DECLARATION" && model.String(ref, "basis") == "REGISTERED_CONFIGURATION_DECLARATION" && model.String(ref, "status") == "DECLARED_NOT_ATTESTED" && ref["execution_authorized"] == false && model.String(ref, "id") != "" && model.String(target, "provider_resource_id") == "configuration-authority:"+model.String(ref, "id") && rel["authority_id"] == ref["id"] && rel["authority_version"] == ref["version"] && rel["authority_sha256"] == ref["sha256"] && len(model.String(ref, "sha256")) == 64
		} else if model.String(rel, "basis") != "NATIVE_EBS_POINT_RELATIONSHIP" {
			allowed = false
		}
		if !allowed {
			return nil, invalid("BLOCKED_DEPENDENCY_EDGE_TYPE", kind)
		}
		out = append(out, model.Document{"type": kind, "to": target["id"]})
	}
	return out, nil
}
