// Package dependency evaluates a reviewed, hard dependency graph. It never
// infers absence of dependencies from missing data or low utilization.
package dependency

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
)

const MaxNodes = 4096
const MaxEdges = 8192

type ValidationError struct{ Code, NodeID string }

func (e *ValidationError) Error() string { return e.Code }
func invalid(code, node string) error    { return &ValidationError{Code: code, NodeID: node} }

var edgeTypes = map[string]bool{"RUNS_ON": true, "ATTACHED_TO": true, "ROUTES_TO": true, "DEPENDS_ON": true, "BACKED_BY": true, "MEMBER_OF": true, "MANAGED_BY": true, "SCALES_WITH": true, "PROTECTED_BY": true, "CONFIGURED_BY": true, "PAID_BY_COMMITMENT": true}

// Inventory projects server-resolved nodes only. Caller-supplied node metadata
// cannot establish ownership, classification or an AWS target binding.
func Inventory(resources, workloads []model.Document) []model.Document {
	nodes := []model.Document{}
	storageScope := storageNativeScope(resources)
	byWorkload := map[string]model.Document{}
	for _, w := range workloads {
		id := model.String(w, "id")
		byWorkload[id] = w
		n := model.Document{"id": "workload:" + id, "kind": "WORKLOAD", "workload_id": id}
		for _, k := range []string{"name", "owner", "owner_subject", "environment", "criticality"} {
			n[k] = w[k]
		}
		nodes = append(nodes, n)
	}
	for _, r := range resources {
		id := model.String(r, "id")
		wid := model.String(r, "workload_id")
		w := byWorkload[wid]
		n := model.Document{"id": "resource:" + id, "kind": "RESOURCE", "resource_id": id, "workload_id": wid, "owner": w["owner"], "owner_subject": w["owner_subject"], "workload_environment": w["environment"]}
		for _, k := range []string{"name", "provider", "provider_resource_id", "resource_type", "account_id", "region", "environment", "configuration_authority", "runtime_stop_start_delegated", "fleet_managed", "criticality"} {
			n[k] = r[k]
		}
		if r["provider_relationships"] != nil {
			n["provider_relationships"] = r["provider_relationships"]
		}
		if storageScope[id] {
			n["tenant_id"] = r["tenant_id"]
		}
		if model.String(r, "resource_type") == "IAC_AUTHORITY_REFERENCE" && r["configuration_authority_reference"] != nil {
			n["configuration_authority_reference"] = r["configuration_authority_reference"]
		}
		if storageNativeResource(r) && r["storage_stop_context"] != nil {
			n["storage_stop_context"] = r["storage_stop_context"]
		}
		nodes = append(nodes, n)
	}
	sort.Slice(nodes, func(i, j int) bool { return model.String(nodes[i], "id") < model.String(nodes[j], "id") })
	return nodes
}

func inventoryIndex(nodes []model.Document) (map[string]model.Document, error) {
	if len(nodes) > MaxNodes {
		return nil, invalid("BLOCKED_DEPENDENCY_GRAPH_LIMIT", "")
	}
	index := map[string]model.Document{}
	for _, n := range nodes {
		id, kind := model.String(n, "id"), model.String(n, "kind")
		valid := kind == "RESOURCE" && model.String(n, "resource_id") != "" && id == "resource:"+model.String(n, "resource_id") || kind == "WORKLOAD" && model.String(n, "workload_id") != "" && id == "workload:"+model.String(n, "workload_id")
		if !valid || index[id] != nil {
			return nil, invalid("BLOCKED_DEPENDENCY_INVENTORY_INVALID", id)
		}
		index[id] = n
	}
	return index, nil
}

// Edges resolves automatic workload mappings before validating every declared
// edge. All relationships are hard; source is derived, never caller authority.
func Edges(nodes, submitted []model.Document) ([]model.Document, error) {
	index, e := inventoryIndex(nodes)
	if e != nil {
		return nil, e
	}
	if len(submitted) > MaxEdges {
		return nil, invalid("BLOCKED_DEPENDENCY_GRAPH_LIMIT", "")
	}
	canonical := map[string]model.Document{}
	put := func(kind, from, to, source string) error {
		if !edgeTypes[kind] {
			return invalid("BLOCKED_DEPENDENCY_EDGE_TYPE", kind)
		}
		if index[from] == nil {
			return invalid("BLOCKED_DEPENDENCY_ENDPOINT_UNKNOWN", from)
		}
		if index[to] == nil {
			return invalid("BLOCKED_DEPENDENCY_ENDPOINT_UNKNOWN", to)
		}
		if from == to {
			return invalid("BLOCKED_DEPENDENCY_SELF_EDGE", from)
		}
		key := kind + "\x00" + from + "\x00" + to
		if existing := canonical[key]; existing == nil || source == "DISCOVERED_MAPPING" {
			canonical[key] = model.Document{"type": kind, "from": from, "to": to, "source": source}
		}
		return nil
	}
	for _, n := range nodes {
		if model.String(n, "kind") == "RESOURCE" && model.String(n, "workload_id") != "" {
			if e = put("RUNS_ON", "workload:"+model.String(n, "workload_id"), model.String(n, "id"), "DISCOVERED_MAPPING"); e != nil {
				return nil, e
			}
		}
		if model.String(n, "kind") == "RESOURCE" && (model.String(n, "resource_type") == "RDS_INSTANCE" || model.String(n, "resource_type") == "RDS_CLUSTER") {
			raw, _ := json.Marshal(n["provider_relationships"])
			var relationships []model.Document
			_ = json.Unmarshal(raw, &relationships)
			for _, rel := range relationships {
				target := index["resource:"+model.String(rel, "target_resource_id")]
				if target == nil || model.String(target, "provider_resource_id") != model.String(rel, "target_provider_resource_id") || model.String(target, "account_id") != model.String(n, "account_id") || model.String(target, "region") != model.String(n, "region") {
					return nil, invalid("BLOCKED_DEPENDENCY_NATIVE_BINDING", model.String(n, "id"))
				}
				kind := model.String(rel, "type")
				if kind != "MEMBER_OF" && kind != "DEPENDS_ON" {
					return nil, invalid("BLOCKED_DEPENDENCY_EDGE_TYPE", kind)
				}
				if e = put(kind, model.String(n, "id"), model.String(target, "id"), "DISCOVERED_MAPPING"); e != nil {
					return nil, e
				}
			}
		}
		if storageNativeResource(n) {
			relationships, err := storageNativeRelationships(n, index)
			if err != nil {
				return nil, err
			}
			for _, rel := range relationships {
				if e = put(model.String(rel, "type"), model.String(n, "id"), model.String(rel, "to"), "DISCOVERED_MAPPING"); e != nil {
					return nil, e
				}
			}
		}
	}
	for _, edge := range submitted {
		for k := range edge {
			if k != "type" && k != "from" && k != "to" && k != "source" {
				return nil, invalid("BLOCKED_DEPENDENCY_EDGE_FIELDS", k)
			}
		}
		if e = put(model.String(edge, "type"), model.String(edge, "from"), model.String(edge, "to"), "OPERATOR_DECLARED"); e != nil {
			return nil, e
		}
	}
	if len(canonical) > MaxEdges {
		return nil, invalid("BLOCKED_DEPENDENCY_GRAPH_LIMIT", "")
	}
	keys := make([]string, 0, len(canonical))
	for k := range canonical {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]model.Document, 0, len(keys))
	adj := map[string][]string{}
	for _, key := range keys {
		edge := canonical[key]
		out = append(out, edge)
		from := model.String(edge, "from")
		adj[from] = append(adj[from], model.String(edge, "to"))
	}
	visited := map[string]int{}
	var visit func(string) error
	visit = func(id string) error {
		if visited[id] == 1 {
			return invalid("BLOCKED_DEPENDENCY_CYCLE", id)
		}
		if visited[id] == 2 {
			return nil
		}
		visited[id] = 1
		for _, to := range adj[id] {
			if e := visit(to); e != nil {
				return e
			}
		}
		visited[id] = 2
		return nil
	}
	for _, n := range nodes {
		if e = visit(model.String(n, "id")); e != nil {
			return nil, e
		}
	}
	return out, nil
}

// InventoryHash excludes mutable heartbeat, health, state and row-version data.
// Changes to bindings, mapping, ownership, classification or authority invalidate
// a review even when no operator-declared edge was changed.
func InventoryHash(nodes []model.Document) string {
	stable := make([]model.Document, 0, len(nodes))
	for _, node := range nodes {
		copy := model.Document{}
		for _, k := range []string{"id", "kind", "resource_id", "workload_id", "owner", "owner_subject", "environment", "workload_environment", "criticality", "provider", "provider_resource_id", "resource_type", "account_id", "region", "configuration_authority", "runtime_stop_start_delegated", "fleet_managed"} {
			copy[k] = node[k]
		}
		if node["provider_relationships"] != nil {
			copy["provider_relationships"] = node["provider_relationships"]
		}
		if node["tenant_id"] != nil {
			copy["tenant_id"] = node["tenant_id"]
		}
		if node["configuration_authority_reference"] != nil {
			copy["configuration_authority_reference"] = node["configuration_authority_reference"]
		}
		if node["storage_stop_context"] != nil {
			copy["storage_stop_context"] = node["storage_stop_context"]
		}
		stable = append(stable, copy)
	}
	sort.Slice(stable, func(i, j int) bool { return model.String(stable[i], "id") < model.String(stable[j], "id") })
	return hash(stable)
}

func GraphHash(version int64, inventory string, edges []model.Document) string {
	return hash(model.Document{"version": version, "inventory_hash": inventory, "edges": edges})
}
func hash(value any) string {
	b, _ := json.Marshal(value)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Assess traverses the transitive inbound consuming closure. The target's own
// discovered workload mapping is the only permitted incoming relationship in
// this single-resource execution increment; utilization cannot waive another
// component's dependency on this instance.
func Assess(nodes, edges []model.Document, targetResource string) []string {
	index, e := inventoryIndex(nodes)
	if e != nil {
		return []string{e.Error()}
	}
	target := targetResource
	if !strings.HasPrefix(target, "resource:") {
		target = "resource:" + target
	}
	node := index[target]
	if node == nil || model.String(node, "kind") != "RESOURCE" {
		return []string{"BLOCKED_DEPENDENCY_TARGET_UNKNOWN"}
	}
	validated, e := Edges(nodes, edges)
	if e != nil {
		return []string{e.Error()}
	}
	reasons := map[string]bool{}
	ownID := model.String(node, "workload_id")
	own := "workload:" + ownID
	if ownID == "" || index[own] == nil {
		reasons["BLOCKED_DEPENDENCY_MAPPING_UNKNOWN"] = true
	}
	if model.String(node, "provider") == "" || model.String(node, "provider_resource_id") == "" || model.String(node, "account_id") == "" || model.String(node, "region") == "" {
		reasons["BLOCKED_DEPENDENCY_BINDING_UNKNOWN"] = true
	}
	incoming := map[string][]model.Document{}
	for _, edge := range validated {
		to := model.String(edge, "to")
		incoming[to] = append(incoming[to], edge)
	}
	queue := []string{target}
	seen := map[string]bool{}
	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		if seen[id] {
			continue
		}
		seen[id] = true
		n := index[id]
		if model.String(n, "owner") == "" && model.String(n, "owner_subject") == "" {
			reasons["BLOCKED_DEPENDENCY_OWNER_UNKNOWN"] = true
		}
		env := model.String(n, "environment")
		if env == "" || env == "UNKNOWN" {
			reasons["BLOCKED_DEPENDENCY_ENVIRONMENT_UNKNOWN"] = true
		} else if env != "NON_PRODUCTION" {
			reasons["BLOCKED_DEPENDENCY_PRODUCTION"] = true
		}
		if model.Bool(n, "fleet_managed") {
			reasons["BLOCKED_DEPENDENCY_MANAGED_RELATIONSHIP"] = true
		}
		for _, edge := range incoming[id] {
			from := model.String(edge, "from")
			allowed := id == target && from == own && model.String(edge, "type") == "RUNS_ON" && model.String(edge, "source") == "DISCOVERED_MAPPING"
			if !allowed {
				reasons["BLOCKED_DEPENDENCY_HARD_CONSUMER"] = true
			}
			queue = append(queue, from)
		}
	}
	for _, edge := range validated {
		if !seen[model.String(edge, "from")] && !seen[model.String(edge, "to")] {
			continue
		}
		switch model.String(edge, "type") {
		case "MEMBER_OF", "MANAGED_BY", "SCALES_WITH":
			reasons["BLOCKED_DEPENDENCY_MANAGED_RELATIONSHIP"] = true
		case "PAID_BY_COMMITMENT":
			reasons["BLOCKED_DEPENDENCY_COMMITMENT_RELATIONSHIP"] = true
		}
	}
	out := make([]string, 0, len(reasons))
	for reason := range reasons {
		out = append(out, reason)
	}
	sort.Strings(out)
	return out
}
