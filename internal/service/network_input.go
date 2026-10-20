package service

// Projection of native, server-selected snapshots only. No request can supply
// topology, flow completeness, cost amounts or marginal-rate authority here.
import (
	"fmt"
	"math/big"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/evidence"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
)

func networkProjectionRef(kind, id string, value any) model.Document {
	hash := evidence.Hash(value)
	return storageRef(kind, id, hash, hash)
}
func networkProjectionStamp(value any) string {
	if at, ok := value.(time.Time); ok {
		return at.UTC().Format(time.RFC3339Nano)
	}
	if s, ok := value.(string); ok {
		if at, e := time.Parse(time.RFC3339Nano, s); e == nil {
			return at.UTC().Format(time.RFC3339Nano)
		}
	}
	return ""
}
func networkProjectionRat(value any) *big.Rat {
	if n, ok := value.(uint64); ok {
		return new(big.Rat).SetInt(new(big.Int).SetUint64(n))
	}
	n, ok := databaseDecimal(value)
	if !ok || n.Sign() < 0 {
		return nil
	}
	return n
}
func networkProjectionQuantity(value any) any {
	if n := networkProjectionRat(value); n != nil {
		return databaseInputMoney(n)
	}
	return nil
}
func networkProjectionZero(value any) bool {
	n := networkProjectionRat(value)
	return n != nil && n.Sign() == 0
}
func networkProjectionComplete(metrics model.Document, name, stat string) bool {
	for _, c := range storageRows(metrics["coverage"]) {
		if model.String(c, "metric") != name {
			continue
		}
		status := model.String(c, "status")
		if status != "COMPLETE_OBSERVED" && status != "COMPLETE_ZERO_OBSERVED" {
			return false
		}
		return model.String(c, "statistic") == stat && model.Number(c, "expected_periods") > 0 && model.Number(c, "expected_periods") == model.Number(c, "observed_periods") && model.Number(c, "missing_periods") == 0 && model.Number(c, "periods_without_positive_sample_count") == 0
	}
	return false
}
func networkProjectionCollection(top model.Document, kind string) bool {
	for _, c := range storageRows(top["coverage"]) {
		if model.String(c, "resource_type") == kind {
			return c["complete"] == true && model.String(c, "status") == "COLLECTED"
		}
	}
	return false
}
func networkProjectionString(value string) any {
	if value == "" {
		return nil
	}
	return value
}
func networkProjectionHas(values []string, key string) bool {
	for _, v := range values {
		if v == key {
			return true
		}
	}
	return false
}

// networkProjectInput keeps absent topology and unclassified traffic visible.
// Complete file delivery alone never becomes complete traffic attribution.
func networkProjectInput(r, canonical, policy, binding, billing model.Document, rates []model.Document, now time.Time) (model.Document, []string) {
	reasons := []string{}
	if rates == nil {
		rates = []model.Document{}
	}
	if model.String(canonical, "resource_id") != model.String(r, "id") || canonical["account_id"] != r["account_id"] || canonical["region"] != r["region"] {
		reasons = append(reasons, "NETWORK_NATIVE_SCOPE_MISMATCH")
	}
	top := storageObject(canonical["topology"])
	metrics := storageObject(canonical["metrics"])
	flows := storageObject(canonical["flows"])
	selection := storageObject(metrics["selection"])
	start, end := networkProjectionStamp(selection["start"]), networkProjectionStamp(selection["end"])
	if start == "" {
		start = networkProjectionStamp(billing["start"])
	}
	if end == "" {
		end = networkProjectionStamp(billing["end"])
	}
	if start == "" || end == "" {
		return nil, databaseSortedReasons(append(reasons, "NETWORK_EVIDENCE_WINDOW_UNKNOWN"))
	}
	facts := map[string]model.Document{}
	scoped := true
	for _, raw := range storageRows(top["resources"]) {
		d := storageObject(raw["network_configuration"])
		if len(d) == 0 {
			d = raw
		}
		if d["account_id"] != r["account_id"] || d["region"] != r["region"] {
			scoped = false
			continue
		}
		id := model.String(d, "provider_resource_id")
		if id == "" || facts[id] != nil {
			scoped = false
			continue
		}
		facts[id] = d
	}
	if !scoped {
		reasons = append(reasons, "NETWORK_TOPOLOGY_NATIVE_SCOPE_MISMATCH")
	}
	config := storageObject(r["network_configuration"])
	if len(config) == 0 {
		config = facts[model.String(r, "provider_resource_id")]
	}
	natID := model.String(r, "provider_resource_id")
	vpc := model.String(config, "vpc_id")
	mode := strings.ToUpper(model.String(config, "availability_mode"))
	if mode != "ZONAL" && mode != "REGIONAL" {
		mode = "UNKNOWN"
	}
	topologyHash := model.String(top, "topology_hash")
	if topologyHash == "" {
		topologyHash = evidence.Hash(top)
	}
	observed, _ := time.Parse(time.RFC3339Nano, networkProjectionStamp(canonical["observed_at"]))
	current := !observed.IsZero() && !observed.After(now.Add(time.Minute)) && now.Sub(observed) <= 30*time.Minute && model.String(canonical, "config_hash") == NetworkConfigurationHash(r)
	if expected := model.String(r, "network_topology_hash"); expected != "" && expected != topologyHash {
		current = false
	}
	version := fmt.Sprint(canonical["source_version"])
	if version == "<nil>" || version == "" {
		version = topologyHash
	}
	p := model.Clone(storageObject(policy["policy"]))
	if p == nil {
		p = model.Document{}
	}
	owner, authority := model.String(r, "owner"), model.String(r, "configuration_authority")
	if owner == "" {
		owner = model.String(config, "owner")
	}
	if authority == "" {
		authority = model.String(config, "configuration_authority")
	}
	if owner == "" || model.String(p, "owner") != owner {
		reasons = append(reasons, "NETWORK_RESOURCE_OWNERSHIP_NOT_EVIDENCED")
	}
	if authority == "" || authority == "UNKNOWN" || model.String(p, "configuration_authority") != authority {
		reasons = append(reasons, "NETWORK_RESOURCE_CONFIGURATION_AUTHORITY_NOT_EVIDENCED")
	}
	// OTHER does not establish a supported declarative authority.
	if p["configuration_authority"] == "OTHER" {
		p["configuration_authority"] = "UNKNOWN"
	}
	if policy != nil && model.String(policy, "id") != "" {
		p["source_ref"] = storageRef("NETWORK_POLICY", model.String(policy, "id"), strconv.FormatInt(model.Number(policy, "version"), 10), networkPolicyHash(policy))
	} else {
		p["source_ref"] = nil
	}
	totals, maxima := storageObject(metrics["totals"]), storageObject(metrics["maxima"])
	sourceBytes, destBytes := networkProjectionRat(totals["BytesInFromSource"]), networkProjectionRat(totals["BytesInFromDestination"])
	var total *big.Rat
	if sourceBytes != nil && destBytes != nil {
		total = new(big.Rat).Add(sourceBytes, destBytes)
	}
	active := networkProjectionRat(maxima["ActiveConnectionCount"])
	telemetryComplete := networkProjectionComplete(metrics, "BytesInFromSource", "Sum") && networkProjectionComplete(metrics, "BytesInFromDestination", "Sum") && networkProjectionComplete(metrics, "ActiveConnectionCount", "Maximum") && total != nil && active != nil
	if model.String(selection, "nat_gateway_id") != natID {
		telemetryComplete = false
	}
	// A regional metric request is scoped to one native AZ. It cannot establish
	// a whole-gateway denominator across a larger or unknown active footprint.
	if mode == "REGIONAL" {
		azs := map[string]bool{}
		for _, address := range storageRows(config["addresses"]) {
			if az := model.String(address, "availability_zone"); az != "" {
				azs[az] = true
			}
		}
		if len(azs) != 1 || !azs[model.String(selection, "availability_zone")] {
			telemetryComplete = false
		}
		for _, coverage := range storageRows(metrics["coverage"]) {
			if model.String(coverage, "metric") == "RegionalAvailabilityZoneFootprint" && model.String(coverage, "status") != "COMPLETE_OBSERVED" {
				telemetryComplete = false
			}
		}
	}
	natENIs := map[string]bool{}
	for _, address := range storageRows(config["addresses"]) {
		if id := model.String(address, "network_interface_id"); id != "" {
			natENIs[id] = true
		}
	}
	flowCoverage := storageObject(flows["coverage"])
	selected := []model.Document{}
	captured := new(big.Rat)
	allNativeStatus := true
	for _, f := range storageRows(flows["cohorts"]) {
		if !natENIs[model.String(f, "interface_id")] || model.String(f, "flow_direction") != "ingress" {
			continue
		}
		if model.String(f, "vpc_id") != vpc || model.String(f, "log_status") != "OK" || model.String(f, "action") != "ACCEPT" || model.Number(f, "unknown_byte_records") != 0 {
			allNativeStatus = false
		}
		n := networkProjectionRat(f["bytes"])
		if n == nil {
			allNativeStatus = false
			continue
		}
		captured.Add(captured, n)
		selected = append(selected, f)
	}
	scopeCovers := len(natENIs) > 0
	registeredIDs := model.Strings(flowCoverage, "resource_ids")
	if !networkProjectionHas(registeredIDs, vpc) {
		for eni := range natENIs {
			if !networkProjectionHas(registeredIDs, eni) {
				scopeCovers = false
			}
		}
	}
	flowComplete := telemetryComplete && flows["complete"] == true && scopeCovers && allNativeStatus && total != nil && captured.Cmp(total) == 0 && networkProjectionStamp(flowCoverage["start"]) == start && networkProjectionStamp(flowCoverage["end"]) == end && networkProjectionZero(flowCoverage["skipdata_records"]) && networkProjectionZero(flowCoverage["unknown_attribution_records"])
	if len(selected) > 128 {
		selected = selected[:128]
		flowComplete = false
		reasons = append(reasons, "NETWORK_EVALUATION_COHORT_BOUND_EXCEEDED")
	}
	routeComplete := networkProjectionCollection(top, "ROUTE_TABLE") && networkProjectionCollection(top, "SUBNET") && networkProjectionCollection(top, "NETWORK_INTERFACE")
	routesUsed := map[string]bool{}
	sourceAZs := map[string]bool{}
	cohorts := []model.Document{}
	usedCharges := map[string]*big.Rat{}
	for _, f := range selected {
		reply := model.String(f, "destination_service") == ""
		service := strings.ToLower(model.String(f, "destination_service"))
		if reply {
			service = strings.ToLower(model.String(f, "source_service"))
		}
		clientKey, serviceKey := "source_addresses", "destination_addresses"
		if reply {
			clientKey, serviceKey = "destination_addresses", "source_addresses"
		}
		clientSubnet, clientAZ, clientKnown := networkProjectionClients(f, facts, clientKey, vpc)
		serviceRegion, serviceKnown := networkProjectionServiceScope(f, facts, serviceKey, service, model.String(r, "region"))
		rt, pathKnown := networkProjectionRoute(f, facts, serviceKey, clientSubnet, vpc, natID)
		pathKnown = pathKnown && clientKnown && routeComplete
		if rt != "" {
			routesUsed[rt] = true
		}
		if clientAZ != "" {
			sourceAZs[clientAZ] = true
		}
		family := "H"
		if service == "s3" || service == "dynamodb" {
			family = "A"
		} else if service != "" && networkProjectionService(facts, service, model.String(r, "region"), "Interface") {
			family = "B"
		} else if mode == "ZONAL" && clientKnown && pathKnown && clientAZ != model.String(config, "availability_zone") {
			family = "C"
		}
		byteN := networkProjectionRat(f["bytes"])
		fraction := new(big.Rat)
		if total != nil && total.Sign() > 0 {
			fraction.Quo(byteN, total)
		}
		// Native integer byte ratios stay exact, including 1/3. Round money at
		// persistence, never the authoritative population allocation itself.
		allocationKnown := total != nil && total.Sign() > 0 && total.IsInt() && byteN.IsInt()
		alloc := []model.Document{}
		if allocationKnown {
			for _, charge := range storageRows(billing["components"]) {
				category := model.String(charge, "category")
				if category != "NAT_HOURLY" && category != "NAT_PROCESSING" {
					continue
				}
				id := model.String(charge, "id")
				alloc = append(alloc, model.Document{"component_id": id, "numerator": byteN.Num().String(), "denominator": total.Num().String()})
				if usedCharges[id] == nil {
					usedCharges[id] = new(big.Rat)
				}
				usedCharges[id].Add(usedCharges[id], fraction)
			}
		}
		endpointAvailable := networkProjectionService(facts, service, model.String(r, "region"), "Gateway")
		if family == "B" {
			endpointAvailable = networkProjectionService(facts, service, model.String(r, "region"), "Interface")
		}
		existing := any(nil)
		if networkProjectionCollection(top, "VPC_ENDPOINT") {
			existing = false
			for _, endpoint := range facts {
				if model.String(endpoint, "resource_type") == "VPC_ENDPOINT" && model.String(endpoint, "vpc_id") == vpc && model.String(endpoint, "service_name") == "com.amazonaws."+model.String(r, "region")+"."+service {
					if family == "A" && strings.EqualFold(model.String(endpoint, "endpoint_type"), "Gateway") && networkProjectionHas(model.Strings(endpoint, "route_table_ids"), rt) {
						existing = true
					}
					if family == "B" && strings.EqualFold(model.String(endpoint, "endpoint_type"), "Interface") {
						existing = true
					}
				}
			}
		}
		technical := networkProjectionTechnical(p)
		technical["endpoint_available"] = endpointAvailable
		technical["endpoint_scope_compatible"] = clientKnown && serviceKnown && pathKnown
		technical["current_endpoint"] = existing
		targetKind := "architecture-review:"
		if family == "A" {
			targetKind = "gateway-endpoint:"
		} else if family == "B" {
			targetKind = "interface-endpoint:"
		}
		targetAZs := model.Number(p, "required_azs")
		if targetAZs > 0 && targetAZs <= 16 {
			technical["target_az_count"] = targetAZs
			technical["topology_footprint_known"] = family != "B"
			if family == "B" {
				for _, serviceFact := range facts {
					if model.String(serviceFact, "resource_type") == "VPC_ENDPOINT_SERVICE" && model.String(serviceFact, "service_name") == "com.amazonaws."+model.String(r, "region")+"."+service {
						zones := model.Strings(serviceFact, "availability_zones")
						technical["topology_footprint_known"] = len(zones) >= int(targetAZs) && networkProjectionHas(zones, clientAZ)
					}
				}
			}
		}
		costs := []model.Document{}
		if family == "B" {
			for _, rate := range rates {
				if rate["service"] == service {
					component := model.String(rate, "component")
					if component == "ENDPOINT_HOURLY" || component == "ENDPOINT_PROCESSING" {
						costs = append(costs, model.Document{"component": component, "rate_id": rate["id"]})
					}
				}
			}
		}
		id := "network-" + evidence.Hash(model.Document{"flow": f["id"], "generation": flows["generation_id"], "path": rt})
		cohort := model.Document{"id": id, "family": family, "bytes": databaseInputMoney(byteN), "traffic_complete": flowComplete, "attribution_complete": flowComplete && clientKnown && pathKnown && serviceKnown, "destination_service": networkProjectionString(service), "destination_region": networkProjectionString(serviceRegion), "traffic_source": "FLOW_LOGS", "current_path": []string{"subnet:" + clientSubnet, "route-table:" + rt, "nat:" + natID, "service:" + service}, "target_path": []string{"subnet:" + clientSubnet, "route-table:" + rt, targetKind + service}, "billing_allocations": alloc, "technical": technical, "candidate_costs": costs, "source_ref": networkProjectionRef("NETWORK_EXCLUSIVE_COHORT", id, model.Document{"population": flows["population_hash"], "flow": f, "path": rt})}
		cohorts = append(cohorts, cohort)
	}
	// No NAT capture is not an invented zero capture. Complete CloudWatch zero
	// can establish an apparently-idle review independently of Flow Logs.
	if len(cohorts) == 0 {
		family := "H"
		if model.String(r, "resource_type") == "NAT_GATEWAY" {
			family = "D"
		}
		technical := networkProjectionTechnical(p)
		bytes := any(nil)
		if total != nil {
			bytes = databaseInputMoney(total)
		}
		if model.String(r, "resource_type") == "ELASTIC_IP" || model.String(r, "resource_type") == "PUBLIC_IPV4" {
			family = "E"
			bytes = nil
			technical["public_ipv4_kind"] = "UNKNOWN"
			technical["association_state"] = "UNKNOWN"
			switch model.String(config, "public_ipv4_classification") {
			case "UNASSOCIATED_ELASTIC_IP":
				technical["public_ipv4_kind"], technical["association_state"] = "ELASTIC_IP", "UNASSOCIATED"
			case "ASSOCIATED_ELASTIC_IP":
				technical["public_ipv4_kind"], technical["association_state"] = "ELASTIC_IP", "ASSOCIATED"
			case "EC2_PUBLIC_IPV4", "SERVICE_MANAGED_PUBLIC_IPV4":
				technical["public_ipv4_kind"], technical["association_state"] = config["public_ipv4_classification"], "ASSOCIATED"
			}
			if model.String(config, "classification") == "UNASSOCIATED_ELASTIC_IP" {
				technical["public_ipv4_kind"], technical["association_state"] = "ELASTIC_IP", "UNASSOCIATED"
			}
			if model.String(config, "classification") == "ASSOCIATED_ELASTIC_IP" {
				technical["public_ipv4_kind"], technical["association_state"] = "ELASTIC_IP", "ASSOCIATED"
			}
		}
		alloc := []model.Document{}
		for _, charge := range storageRows(billing["components"]) {
			id := model.String(charge, "id")
			frac := "1"
			if model.String(charge, "category") == "NAT_PROCESSING" && total != nil && total.Sign() == 0 {
				frac = "0"
			}
			alloc = append(alloc, model.Document{"component_id": id, "fraction": frac})
			usedCharges[id], _ = new(big.Rat).SetString(frac)
		}
		cohorts = append(cohorts, model.Document{"id": "network-resource-review", "family": family, "bytes": bytes, "traffic_complete": telemetryComplete, "attribution_complete": false, "destination_service": nil, "destination_region": nil, "traffic_source": "UNKNOWN", "current_path": []string{"resource:" + natID}, "target_path": []string{"review-only:no-mutation"}, "billing_allocations": alloc, "technical": technical, "candidate_costs": []model.Document{}, "source_ref": networkProjectionRef("NETWORK_RESOURCE_REVIEW", natID, canonical)})
	}
	// Resource-bound transfer lines remain visible as independently allocated
	// burden reviews; absent destination attribution does not become a saving.
	for _, charge := range storageRows(billing["components"]) {
		family := ""
		switch model.String(charge, "category") {
		case "CROSS_AZ_TRANSFER":
			family = "F"
		case "CROSS_REGION_TRANSFER":
			family = "G"
		case "INTERNET_EGRESS":
			family = "H"
		}
		if family == "" {
			continue
		}
		id := model.String(charge, "id")
		used := usedCharges[id]
		if used != nil && used.Cmp(big.NewRat(1, 1)) >= 0 {
			continue
		}
		fraction := big.NewRat(1, 1)
		if used != nil {
			fraction.Sub(fraction, used)
		}
		cohorts = append(cohorts, model.Document{"id": "network-billing-review-" + id, "family": family, "bytes": nil, "traffic_complete": false, "attribution_complete": false, "destination_service": nil, "destination_region": nil, "traffic_source": "UNKNOWN", "current_path": []string{"resource:" + natID, "billing-component:" + id}, "target_path": []string{"architecture-review:preserve-resilience-and-purpose"}, "billing_allocations": []model.Document{{"component_id": id, "fraction": databaseInputMoney(fraction)}}, "technical": networkProjectionTechnical(p), "candidate_costs": []model.Document{}, "source_ref": networkProjectionRef("NETWORK_TRANSFER_BURDEN_REVIEW", id, charge)})
	}
	rtIDs := []string{}
	for rt := range routesUsed {
		rtIDs = append(rtIDs, rt)
	}
	if len(rtIDs) == 0 {
		rtIDs = model.Strings(config, "route_table_consumers")
	}
	sort.Strings(rtIDs)
	sourceAZ := ""
	if len(sourceAZs) == 1 {
		for az := range sourceAZs {
			sourceAZ = az
		}
	}
	var processed any
	if total != nil {
		processed = databaseInputMoney(total)
	}
	observationRef := objectStorageModelRef(metrics["source_ref"])
	if observationRef == nil {
		observationRef = networkProjectionRef("NETWORK_METRIC_SNAPSHOT", natID, metrics)
	}
	input := model.Document{"schema_version": "1", "model_version": "network-v1", "binding": binding, "as_of": now.UTC().Format(time.RFC3339Nano), "topology": model.Document{"revision": version, "hash": topologyHash, "mode": mode, "vpc_id": networkProjectionString(vpc), "source_az": networkProjectionString(sourceAZ), "nat_az": config["availability_zone"], "route_table_ids": rtIDs, "route_current": current, "route_certain": routeComplete && scoped && len(rtIDs) > 0, "source_ref": networkProjectionRef("NETWORK_TOPOLOGY", natID, top)}, "policy": p, "observation": model.Document{"start": start, "end": end, "telemetry_complete": telemetryComplete, "flow_complete": flowComplete, "processed_bytes": processed, "byte_basis": "BYTES_IN_FROM_SOURCE_PLUS_BYTES_IN_FROM_DESTINATION", "maximum_active_connections": networkProjectionQuantity(maxima["ActiveConnectionCount"]), "source_ref": observationRef}, "billing": billing, "rates": rates, "cohorts": cohorts}
	return input, databaseSortedReasons(reasons)
}

func networkProjectionTechnical(p model.Document) model.Document {
	return model.Document{"endpoint_available": nil, "endpoint_scope_compatible": nil, "current_endpoint": nil, "dns_compatible": p["dns_change_approved"], "on_premises_compatible": p["on_premises_required"] == false, "cross_vpc_compatible": p["cross_vpc_required"] == false, "security_compatible": p["security_reviewed"], "resilience_preserved": p["resilience_known"], "rto_compatible": p["recovery_known"], "topology_footprint_known": nil, "target_az_count": nil, "nat_hourly_avoidable": false, "idle_threshold_bytes": "0", "public_ipv4_kind": nil, "association_state": nil, "purpose": p["traffic_purpose"]}
}
func networkProjectionService(facts map[string]model.Document, service, region, kind string) bool {
	for _, d := range facts {
		if model.String(d, "resource_type") != "VPC_ENDPOINT_SERVICE" || model.String(d, "service_name") != "com.amazonaws."+region+"."+service {
			continue
		}
		for _, t := range model.Strings(d, "service_types") {
			if t == kind {
				return true
			}
		}
	}
	return false
}
func networkProjectionClients(flow model.Document, facts map[string]model.Document, key, vpc string) (string, string, bool) {
	addresses := model.Strings(flow, key)
	if len(addresses) == 0 || flow[key+"_complete"] != true {
		return "", "", false
	}
	subnet, az := "", ""
	for _, address := range addresses {
		matches := []model.Document{}
		for _, eni := range facts {
			if model.String(eni, "resource_type") != "NETWORK_INTERFACE" || model.String(eni, "vpc_id") != vpc {
				continue
			}
			if model.String(eni, "private_ip") == address || networkProjectionHas(model.Strings(eni, "private_ipv4_addresses"), address) {
				matches = append(matches, eni)
			}
		}
		if len(matches) != 1 {
			return "", "", false
		}
		candidate := matches[0]
		s := model.String(candidate, "subnet_id")
		subnetFact := facts[s]
		a := model.String(subnetFact, "availability_zone")
		if s == "" || a == "" || model.String(subnetFact, "vpc_id") != vpc {
			return "", "", false
		}
		if subnet != "" && (subnet != s || az != a) {
			return "", "", false
		}
		subnet, az = s, a
	}
	return subnet, az, true
}
func networkProjectionServiceScope(flow model.Document, facts map[string]model.Document, key, service, region string) (string, bool) {
	addresses := model.Strings(flow, key)
	if len(addresses) == 0 || flow[key+"_complete"] != true {
		return "", false
	}
	for _, prefix := range facts {
		if model.String(prefix, "resource_type") != "AWS_SERVICE_PREFIX_LIST" || model.String(prefix, "service_name") != "com.amazonaws."+region+"."+service || prefix["entries_complete"] != true || model.String(prefix, "provider_owner_basis") != "AWS_DESCRIBE_PREFIX_LISTS_NATIVE_SERVICE_CATALOGUE" {
			continue
		}
		all := true
		for _, a := range addresses {
			ip, e := netip.ParseAddr(a)
			matched := false
			if e == nil {
				for _, c := range model.Strings(prefix, "cidrs") {
					if p, e := netip.ParsePrefix(c); e == nil && p.Contains(ip) {
						matched = true
					}
				}
			}
			if !matched {
				all = false
			}
		}
		if all {
			return region, true
		}
	}
	return "", false
}
func networkProjectionRoute(flow model.Document, facts map[string]model.Document, key, subnet, vpc, nat string) (string, bool) {
	if subnet == "" {
		return "", false
	}
	tables := []model.Document{}
	mains := []model.Document{}
	for _, d := range facts {
		if model.String(d, "resource_type") != "ROUTE_TABLE" || model.String(d, "vpc_id") != vpc {
			continue
		}
		for _, a := range storageRows(d["associations"]) {
			if model.String(a, "subnet_id") == subnet {
				tables = append(tables, d)
			}
			if a["main"] == "true" || a["main"] == true {
				mains = append(mains, d)
			}
		}
	}
	if len(tables) == 0 {
		tables = mains
	}
	if len(tables) != 1 {
		return "", false
	}
	table := tables[0]
	addresses := model.Strings(flow, key)
	if len(addresses) == 0 || flow[key+"_complete"] != true {
		return model.String(table, "provider_resource_id"), false
	}
	for _, address := range addresses {
		ip, e := netip.ParseAddr(address)
		if e != nil {
			return model.String(table, "provider_resource_id"), false
		}
		best := -1
		target := ""
		tie := false
		for _, route := range storageRows(table["routes"]) {
			if model.String(route, "state") != "active" {
				continue
			}
			cidrs := []string{}
			if s := model.String(route, "destination_cidr"); s != "" {
				cidrs = append(cidrs, s)
			}
			if s := model.String(route, "destination_ipv6_cidr"); s != "" {
				cidrs = append(cidrs, s)
			}
			if pl := model.String(route, "destination_prefix_list_id"); pl != "" {
				p := facts[pl]
				if p == nil || p["entries_complete"] != true {
					return model.String(table, "provider_resource_id"), false
				}
				cidrs = append(cidrs, model.Strings(p, "cidrs")...)
			}
			for _, cidr := range cidrs {
				p, e := netip.ParsePrefix(cidr)
				if e != nil {
					return model.String(table, "provider_resource_id"), false
				}
				if !p.Contains(ip) {
					continue
				}
				t := model.String(route, "nat_gateway_id")
				if p.Bits() > best {
					best, target, tie = p.Bits(), t, false
				} else if p.Bits() == best && target != t {
					tie = true
				}
			}
		}
		if best < 0 || target != nat || tie {
			return model.String(table, "provider_resource_id"), false
		}
	}
	return model.String(table, "provider_resource_id"), true
}
