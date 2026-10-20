package provider

import (
	"context"
	"fmt"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/network"
)

type networkCollection struct {
	action, collection, kind, id string
	unpaged                      bool
}

var networkCollections = []networkCollection{
	{"DescribeVpcs", "vpcSet", "VPC", "vpcId", false}, {"DescribeSubnets", "subnetSet", "SUBNET", "subnetId", false}, {"DescribeAvailabilityZones", "availabilityZoneInfo", "AVAILABILITY_ZONE", "zoneId", true},
	{"DescribeRouteTables", "routeTableSet", "ROUTE_TABLE", "routeTableId", false}, {"DescribeNatGateways", "natGatewaySet", "NAT_GATEWAY", "natGatewayId", false}, {"DescribeAddresses", "addressesSet", "ELASTIC_IP", "allocationId", true},
	{"DescribeInternetGateways", "internetGatewaySet", "INTERNET_GATEWAY", "internetGatewayId", false}, {"DescribeEgressOnlyInternetGateways", "egressOnlyInternetGatewaySet", "EGRESS_ONLY_INTERNET_GATEWAY", "egressOnlyInternetGatewayId", false},
	{"DescribeNetworkInterfaces", "networkInterfaceSet", "NETWORK_INTERFACE", "networkInterfaceId", false}, {"DescribeSecurityGroups", "securityGroupInfo", "SECURITY_GROUP", "groupId", false},
	{"DescribeVpcEndpoints", "vpcEndpointSet", "VPC_ENDPOINT", "vpcEndpointId", false}, {"DescribeVpcEndpointServices", "serviceDetailSet", "VPC_ENDPOINT_SERVICE", "serviceName", false},
	{"DescribeVpcPeeringConnections", "vpcPeeringConnectionSet", "VPC_PEERING", "vpcPeeringConnectionId", false}, {"DescribeTransitGatewayAttachments", "transitGatewayAttachments", "TRANSIT_GATEWAY_ATTACHMENT", "transitGatewayAttachmentId", false},
	{"DescribeFlowLogs", "flowLogSet", "FLOW_LOG", "flowLogId", false}, {"DescribeLoadBalancers", "LoadBalancers", "LOAD_BALANCER", "LoadBalancerArn", false},
	{"DescribePrefixLists", "prefixListSet", "AWS_SERVICE_PREFIX_LIST", "prefixListId", false},
}

func networkValue(d model.Document, n *rdsNode, key, native string) {
	d[key] = nil
	if x := n.get(native); x != nil {
		d[key] = strings.TrimSpace(x.text)
	}
}
func networkNested(n *rdsNode, name string) []model.Document {
	if n == nil || n.get(name) == nil {
		return nil
	}
	out := []model.Document{}
	for _, x := range n.list(name) {
		out = append(out, model.Document{"native": rdsNormalizedNode(x)})
	}
	return out
}
func networkStrings(n *rdsNode, name string) []string {
	if n.get(name) == nil {
		return nil
	}
	out := []string{}
	for _, x := range n.list(name) {
		out = append(out, strings.TrimSpace(x.text))
	}
	sort.Strings(out)
	return out
}
func networkItem(n *rdsNode, s network.Scope, c networkCollection, hash string, at time.Time) (model.Document, error) {
	id := n.value(c.id)
	if id == "" || len(id) > 2048 {
		return nil, network.ErrEvidence
	}
	for _, key := range []string{"ownerId", "OwnerId"} {
		if owner := n.value(key); owner != "" && owner != s.AccountID && c.kind != "VPC_ENDPOINT_SERVICE" {
			return nil, network.ErrEvidence
		}
	}
	if arn := n.value("LoadBalancerArn"); arn != "" && !strings.HasPrefix(arn, "arn:aws:elasticloadbalancing:"+s.Region+":"+s.AccountID+":loadbalancer/") {
		return nil, network.ErrEvidence
	}
	if region := n.value("regionName"); region != "" && region != s.Region {
		return nil, network.ErrEvidence
	}
	d := model.Document{"provider": "AWS", "resource_type": c.kind, "provider_resource_id": id, "account_id": s.AccountID, "region": s.Region, "last_seen": at, "raw_page_sha256": hash, "native": rdsNormalizedNode(n), "owner": nil, "workload_id": nil, "configuration_authority": nil}
	for key, native := range map[string]string{"vpc_id": "vpcId", "subnet_id": "subnetId", "availability_zone": "availabilityZone", "availability_zone_id": "availabilityZoneId", "state": "state", "create_time": "createTime", "connectivity_type": "connectivityType", "availability_mode": "availabilityMode", "auto_provision_zones": "autoProvisionZones", "auto_scaling_ips": "autoScalingIps", "public_ip": "publicIp", "private_ip": "privateIpAddress", "network_interface_id": "networkInterfaceId", "association_id": "associationId", "instance_id": "instanceId", "customer_owned_ip": "customerOwnedIp", "public_ipv4_pool": "publicIpv4Pool", "service_name": "serviceName", "endpoint_type": "vpcEndpointType", "requester_managed": "requesterManaged", "interface_type": "interfaceType", "source_dest_check": "sourceDestCheck"} {
		networkValue(d, n, key, native)
	}
	if az := model.String(d, "availability_zone"); az != "" && !strings.HasPrefix(az, s.Region) {
		return nil, network.ErrEvidence
	}
	if c.kind == "NAT_GATEWAY" {
		mode := model.String(d, "availability_mode")
		if mode != "" && mode != "regional" && mode != "zonal" {
			d["topology_reason_code"] = "UNSUPPORTED_NATIVE_NAT_AVAILABILITY_MODE"
		}
		// A missing availability mode remains unknown. In particular, a regional
		// NAT has no hosting subnet and may span more than one active AZ.
		d["addresses"] = nil
		if n.get("natGatewayAddressSet") != nil {
			a := []model.Document{}
			for _, x := range n.list("natGatewayAddressSet") {
				z := model.Document{"native": rdsNormalizedNode(x)}
				for key, field := range map[string]string{"allocation_id": "allocationId", "association_id": "associationId", "network_interface_id": "networkInterfaceId", "private_ip": "privateIp", "public_ip": "publicIp", "availability_zone": "availabilityZone", "availability_zone_id": "availabilityZoneId", "status": "status", "is_primary": "isPrimary"} {
					networkValue(z, x, key, field)
				}
				a = append(a, z)
			}
			d["addresses"] = a
		}
		d["route_table_consumers"] = []string{}
	}
	if c.kind == "ROUTE_TABLE" {
		routes := []model.Document{}
		for _, x := range n.list("routeSet") {
			v := model.Document{"native": rdsNormalizedNode(x)}
			for key, field := range map[string]string{"destination_cidr": "destinationCidrBlock", "destination_ipv6_cidr": "destinationIpv6CidrBlock", "destination_prefix_list_id": "destinationPrefixListId", "nat_gateway_id": "natGatewayId", "gateway_id": "gatewayId", "network_interface_id": "networkInterfaceId", "transit_gateway_id": "transitGatewayId", "vpc_peering_connection_id": "vpcPeeringConnectionId", "egress_only_internet_gateway_id": "egressOnlyInternetGatewayId", "state": "state", "origin": "origin"} {
				networkValue(v, x, key, field)
			}
			routes = append(routes, v)
		}
		d["routes"] = routes
		associations := []model.Document{}
		for _, x := range n.list("associationSet") {
			v := model.Document{"native": rdsNormalizedNode(x)}
			for key, field := range map[string]string{"id": "routeTableAssociationId", "subnet_id": "subnetId", "gateway_id": "gatewayId", "main": "main"} {
				networkValue(v, x, key, field)
			}
			associations = append(associations, v)
		}
		d["associations"] = associations
	}
	if c.kind == "VPC_ENDPOINT" {
		d["route_table_ids"] = networkStrings(n, "routeTableIdSet")
		d["subnet_ids"] = networkStrings(n, "subnetIdSet")
		d["network_interface_ids"] = networkStrings(n, "networkInterfaceIdSet")
		networkValue(d, n, "private_dns_enabled", "privateDnsEnabled")
		networkValue(d, n, "policy_document", "policyDocument")
	}
	if c.kind == "NETWORK_INTERFACE" {
		d["attachment"] = nil
		if n.get("attachment") != nil {
			d["attachment"] = rdsNormalizedNode(n.get("attachment"))
		}
		d["association"] = nil
		if n.get("association") != nil {
			d["association"] = rdsNormalizedNode(n.get("association"))
		}
		d["private_ip_addresses"] = networkNested(n, "privateIpAddressesSet")
		privateIPs := []string{}
		if ip := n.value("privateIpAddress"); ip != "" {
			privateIPs = append(privateIPs, ip)
		}
		for _, p := range n.list("privateIpAddressesSet") {
			ip := p.value("privateIpAddress")
			found := false
			for _, prior := range privateIPs {
				if prior == ip {
					found = true
				}
			}
			if ip != "" && !found {
				privateIPs = append(privateIPs, ip)
			}
		}
		sort.Strings(privateIPs)
		d["private_ipv4_addresses"] = privateIPs
		d["groups"] = networkNested(n, "groupSet")
		assignments := []model.Document{}
		associations := []*rdsNode{}
		if a := n.get("association"); a != nil {
			associations = append(associations, a)
		}
		for _, ip := range n.list("privateIpAddressesSet") {
			if a := ip.get("association"); a != nil {
				associations = append(associations, a)
			}
		}
		seen := map[string]bool{}
		for _, a := range associations {
			ip := a.value("publicIp")
			if ip == "" || seen[ip] {
				continue
			}
			seen[ip] = true
			classification := "EC2_PUBLIC_IPV4"
			if n.value("requesterManaged") == "true" {
				classification = "SERVICE_MANAGED_PUBLIC_IPV4"
			}
			if a.value("allocationId") != "" {
				classification = "ASSOCIATED_ELASTIC_IP"
			}
			assignments = append(assignments, model.Document{"public_ip": ip, "allocation_id": a.value("allocationId"), "association_id": a.value("associationId"), "ip_owner_id": a.value("ipOwnerId"), "classification": classification})
		}
		d["public_ipv4_assignments"] = assignments
	}
	if c.kind == "ELASTIC_IP" {
		d["allocation_id"] = id
		classification := "ASSOCIATED_ELASTIC_IP"
		if model.String(d, "association_id") == "" && model.String(d, "instance_id") == "" && model.String(d, "network_interface_id") == "" {
			classification = "UNASSOCIATED_ELASTIC_IP"
		}
		if model.String(d, "customer_owned_ip") != "" || strings.HasPrefix(model.String(d, "public_ipv4_pool"), "ipv4pool-ec2-") {
			classification = "BYOIP_OR_CUSTOMER_OWNED_REVIEW"
		}
		d["public_ipv4_classification"] = classification
		d["age_known"] = false
	}
	if c.kind == "AVAILABILITY_ZONE" {
		networkValue(d, n, "availability_zone", "zoneName")
		d["availability_zone_id"] = id
	}
	if c.kind == "AWS_SERVICE_PREFIX_LIST" {
		name := n.value("prefixListName")
		if name != "com.amazonaws."+s.Region+".s3" && name != "com.amazonaws."+s.Region+".dynamodb" {
			return nil, network.ErrEvidence
		}
		cidrs := networkStrings(n, "cidrSet")
		if len(cidrs) == 0 {
			return nil, network.ErrEvidence
		}
		for _, cidr := range cidrs {
			if _, e := netip.ParsePrefix(cidr); e != nil {
				return nil, network.ErrEvidence
			}
		}
		d["prefix_list_id"] = id
		d["service_name"] = name
		d["cidrs"] = cidrs
		d["provider_owner_basis"] = "AWS_DESCRIBE_PREFIX_LISTS_NATIVE_SERVICE_CATALOGUE"
		d["entries_complete"] = true
		d["native_version"] = nil
	}
	if c.kind == "VPC_ENDPOINT_SERVICE" {
		types := []string{}
		for _, item := range n.list("serviceType") {
			if v := item.value("serviceType"); v != "" {
				types = append(types, v)
			}
		}
		d["service_types"] = types
		d["availability_zones"] = networkStrings(n, "availabilityZoneSet")
		networkValue(d, n, "private_dns_name", "privateDnsName")
		networkValue(d, n, "provider_service_owner", "owner")
	}
	if c.kind == "LOAD_BALANCER" {
		networkValue(d, n, "vpc_id", "VpcId")
		networkValue(d, n, "scheme", "Scheme")
		networkValue(d, n, "load_balancer_type", "Type")
		d["availability_zones"] = networkNested(n, "AvailabilityZones")
	}
	tags, e := ebsTags(n)
	if e != nil {
		return nil, e
	}
	d["tags"] = tags
	return d, nil
}
func (r *networkRead) collect(ctx context.Context, c networkCollection) ([]model.Document, error) {
	out := []model.Document{}
	seenIDs := map[string]bool{}
	seenTokens := map[string]bool{}
	token := ""
	for page := 0; page < 1000; page++ {
		v := url.Values{}
		if c.action == "DescribePrefixLists" {
			v.Set("Filter.1.Name", "prefix-list-name")
			v.Set("Filter.1.Value.1", "com.amazonaws."+r.scope.Region+".s3")
			v.Set("Filter.1.Value.2", "com.amazonaws."+r.scope.Region+".dynamodb")
		}
		if !c.unpaged {
			v.Set("MaxResults", "100")
		}
		if c.action == "DescribeLoadBalancers" {
			v.Del("MaxResults")
			v.Set("PageSize", "400")
			if token != "" {
				v.Set("Marker", token)
			}
		} else if token != "" {
			v.Set("NextToken", token)
		}
		raw, e := r.query(ctx, c.action, v)
		if e != nil {
			return nil, e
		}
		n, e := ebsTree(raw, c.action)
		if e != nil {
			return nil, network.ErrEvidence
		}
		if c.action == "DescribeLoadBalancers" {
			n = n.get("DescribeLoadBalancersResult")
			if n == nil {
				return nil, network.ErrEvidence
			}
		}
		if n.get(c.collection) == nil {
			return nil, network.ErrEvidence
		}
		for _, x := range n.list(c.collection) {
			d, e := networkItem(x, r.scope, c, network.BytesHash(raw), time.Now().UTC())
			if e != nil || seenIDs[model.String(d, "provider_resource_id")] {
				return nil, network.ErrEvidence
			}
			seenIDs[model.String(d, "provider_resource_id")] = true
			out = append(out, d)
			if len(out) > 100000 {
				return nil, network.ErrEvidence
			}
		}
		next := n.value("nextToken")
		if c.action == "DescribeLoadBalancers" {
			next = n.value("NextMarker")
		}
		if next == "" {
			return out, nil
		}
		if c.unpaged || len(next) > 4096 || seenTokens[next] {
			return nil, network.ErrEvidence
		}
		seenTokens[next] = true
		token = next
	}
	return nil, network.ErrEvidence
}

// NetworkDiscover is an optional independent read. A denied topology collection
// is explicit and does not erase the other collections or EC2 discovery.
func (a *AWS) NetworkDiscover(ctx context.Context, s network.Scope) (network.Discovery, error) {
	out := network.Discovery{SchemaVersion: "NETWORK_TOPOLOGY_V1", Scope: s, StartedAt: time.Now().UTC(), Resources: []model.Document{}, Coverage: []model.Document{}, Complete: true}
	r, e := newNetworkRead(a, s)
	if e != nil {
		return out, e
	}
	// Authenticate before any optional read; account confusion is not a partial
	// inventory and must fail the entire optional network operation.
	c, e := a.cfg.Credentials.Retrieve(ctx)
	if e != nil {
		return out, network.ErrEvidence
	}
	if e = r.identity(ctx, c); e != nil {
		return out, e
	}
	for _, collection := range networkCollections {
		items, e := r.collect(ctx, collection)
		status, reason := "COLLECTED", ""
		if e != nil {
			out.Complete = false
			status = "UNAVAILABLE"
			reason = "NETWORK_READ_INCOMPLETE"
			if q, ok := e.(*QueryRejection); ok {
				reason = q.Code
			}
			items = nil
		}
		out.Coverage = append(out.Coverage, model.Document{"action": collection.action, "resource_type": collection.kind, "status": status, "reason_code": reason, "count": len(items), "complete": e == nil, "missing_is_zero": false})
		out.Resources = append(out.Resources, items...)
	}
	// Join only native IDs. Associations are analytical and are not EC2 stop
	// dependencies; unknown main-route or regional-NAT AZ semantics stay unknown.
	byID := map[string]model.Document{}
	for _, d := range out.Resources {
		byID[model.String(d, "provider_resource_id")] = d
	}
	for _, d := range out.Resources {
		if model.String(d, "resource_type") != "NAT_GATEWAY" {
			continue
		}
		if mode := model.String(d, "availability_mode"); mode == "zonal" {
			if subnet := byID[model.String(d, "subnet_id")]; subnet != nil {
				d["availability_zone"] = subnet["availability_zone"]
				d["availability_zone_id"] = subnet["availability_zone_id"]
			}
		}
		consumers := []string{}
		for _, rt := range out.Resources {
			if model.String(rt, "resource_type") != "ROUTE_TABLE" {
				continue
			}
			for _, route := range rt["routes"].([]model.Document) {
				if model.String(route, "nat_gateway_id") == model.String(d, "provider_resource_id") {
					consumers = append(consumers, model.String(rt, "provider_resource_id"))
					break
				}
			}
		}
		sort.Strings(consumers)
		d["route_table_consumers"] = consumers
	}
	sort.Slice(out.Resources, func(i, j int) bool {
		return fmt.Sprint(out.Resources[i]["resource_type"], "/", out.Resources[i]["provider_resource_id"]) < fmt.Sprint(out.Resources[j]["resource_type"], "/", out.Resources[j]["provider_resource_id"])
	})
	stable := []model.Document{}
	for _, d := range out.Resources {
		v := model.Document{}
		for k, value := range d {
			if k != "last_seen" && k != "raw_page_sha256" {
				v[k] = value
			}
		}
		stable = append(stable, v)
		configuration := model.Document{}
		for k, value := range v {
			configuration[k] = value
		}
		d["network_configuration"] = configuration
	}
	out.TopologyHash = network.Hash(model.Document{"scope": s, "resources": stable, "coverage": out.Coverage})
	out.CollectedAt = time.Now().UTC()
	out.Raw = r.raw()
	out.RawSHA256 = network.BytesHash(out.Raw)
	return out, nil
}
