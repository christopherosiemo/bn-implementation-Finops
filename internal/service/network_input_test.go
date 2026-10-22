package service

import (
	"github.com/christopherosiemo/bn-implementation-Finops/internal/evidence"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"testing"
	"time"
)

func networkProjectionFixture() (model.Document, model.Document, model.Document, model.Document, model.Document, time.Time) {
	now := time.Date(2026, 10, 20, 1, 0, 0, 0, time.UTC)
	start, end := "2026-10-06T00:00:00Z", "2026-10-20T00:00:00Z"
	account, region := "111122223333", "eu-west-1"
	fact := func(id, kind string, details model.Document) model.Document {
		d := model.Document{"provider_resource_id": id, "resource_type": kind, "account_id": account, "region": region}
		for k, v := range details {
			d[k] = v
		}
		return d
	}
	nat := fact("nat-projection", "NAT_GATEWAY", model.Document{"availability_mode": "zonal", "availability_zone": "eu-west-1a", "vpc_id": "vpc-projection", "subnet_id": "subnet-nat", "addresses": []model.Document{{"network_interface_id": "eni-nat"}}, "route_table_consumers": []string{"rtb-client"}})
	r := model.Document{"id": "resource-projection", "provider": "AWS", "provider_resource_id": "nat-projection", "account_id": account, "region": region, "resource_type": "NAT_GATEWAY", "owner": "network-owner", "configuration_authority": "TERRAFORM", "network_configuration": nat, "network_topology_hash": "a" + evidence.Hash(nat)[1:]}
	facts := []model.Document{nat, fact("subnet-client", "SUBNET", model.Document{"vpc_id": "vpc-projection", "availability_zone": "eu-west-1b"}), fact("eni-client", "NETWORK_INTERFACE", model.Document{"vpc_id": "vpc-projection", "subnet_id": "subnet-client", "private_ip": "10.0.1.10", "private_ipv4_addresses": []string{"10.0.1.10"}}), fact("rtb-client", "ROUTE_TABLE", model.Document{"vpc_id": "vpc-projection", "associations": []model.Document{{"subnet_id": "subnet-client", "main": "false"}}, "routes": []model.Document{{"destination_cidr": "0.0.0.0/0", "nat_gateway_id": "nat-projection", "state": "active"}}}), fact("pl-s3", "AWS_SERVICE_PREFIX_LIST", model.Document{"service_name": "com.amazonaws.eu-west-1.s3", "cidrs": []string{"52.95.0.0/16"}, "entries_complete": true, "provider_owner_basis": "AWS_DESCRIBE_PREFIX_LISTS_NATIVE_SERVICE_CATALOGUE"}), fact("com.amazonaws.eu-west-1.s3", "VPC_ENDPOINT_SERVICE", model.Document{"service_name": "com.amazonaws.eu-west-1.s3", "service_types": []string{"Gateway", "Interface"}})}
	coverage := []model.Document{}
	for _, kind := range []string{"ROUTE_TABLE", "SUBNET", "NETWORK_INTERFACE", "VPC_ENDPOINT", "VPC_ENDPOINT_SERVICE", "AWS_SERVICE_PREFIX_LIST"} {
		coverage = append(coverage, model.Document{"resource_type": kind, "status": "COLLECTED", "complete": true})
	}
	metricCoverage := []model.Document{}
	for _, m := range []string{"BytesInFromSource", "BytesInFromDestination", "ActiveConnectionCount"} {
		stat := "Sum"
		if m == "ActiveConnectionCount" {
			stat = "Maximum"
		}
		metricCoverage = append(metricCoverage, model.Document{"metric": m, "statistic": stat, "expected_periods": 336, "observed_periods": 336, "missing_periods": 0, "periods_without_positive_sample_count": 0, "status": "COMPLETE_OBSERVED"})
	}
	baseFlow := model.Document{"interface_id": "eni-nat", "vpc_id": "vpc-projection", "subnet_id": "subnet-nat", "flow_direction": "ingress", "log_status": "OK", "action": "ACCEPT", "unknown_byte_records": 0, "source_addresses_complete": true, "destination_addresses_complete": true}
	forward := model.Clone(baseFlow)
	forward["id"], forward["bytes"], forward["destination_service"], forward["source_addresses"], forward["destination_addresses"] = "forward", "400", "S3", []string{"10.0.1.10"}, []string{"52.95.1.2"}
	reply := model.Clone(baseFlow)
	reply["id"], reply["bytes"], reply["source_service"], reply["source_addresses"], reply["destination_addresses"] = "reply", "600", "S3", []string{"52.95.1.2"}, []string{"10.0.1.10"}
	c := model.Document{"schema_version": "1", "resource_id": r["id"], "account_id": account, "region": region, "config_hash": NetworkConfigurationHash(r), "observed_at": now.Format(time.RFC3339), "source_version": "1", "topology": model.Document{"resources": facts, "coverage": coverage, "topology_hash": r["network_topology_hash"]}, "metrics": model.Document{"selection": model.Document{"nat_gateway_id": "nat-projection", "start": start, "end": end, "period_seconds": 3600}, "coverage": metricCoverage, "totals": model.Document{"BytesInFromSource": "400", "BytesInFromDestination": "600", "BytesOutToSource": "600", "BytesOutToDestination": "400"}, "maxima": model.Document{"ActiveConnectionCount": "2"}}, "flows": model.Document{"generation_id": "generation-projection", "population_hash": evidence.Hash(baseFlow), "complete": true, "coverage": model.Document{"start": start, "end": end, "skipdata_records": 0, "unknown_attribution_records": 0, "resource_ids": []string{"vpc-projection"}, "complete_traffic_census": false}, "cohorts": []model.Document{forward, reply}}}
	p := model.Document{"id": "policy-projection", "version": 1, "resource_id": r["id"], "policy": model.Document{"owner": "network-owner", "configuration_authority": "TERRAFORM", "criticality": "NON_PRODUCTION", "security_reviewed": true, "endpoint_policy_reviewed": true, "network_policy_known": true, "dependencies_known": true, "recovery_known": true, "resilience_known": true, "required_azs": 2, "ha_required": true, "on_premises_required": false, "cross_vpc_required": false, "dns_change_approved": true}}
	bill := model.Document{"currency": "GBP", "start": start, "end": end, "components": []model.Document{{"id": "nat-hour", "category": "NAT_HOURLY"}, {"id": "nat-data", "category": "NAT_PROCESSING"}}}
	return r, c, p, storageBinding("tenant-projection", r), bill, now
}
func TestNetworkProjectionBidirectionalBytesAndExactClientRoutes(t *testing.T) {
	r, c, p, b, bill, now := networkProjectionFixture()
	input, reasons := networkProjectInput(r, c, p, b, bill, nil, now)
	if len(reasons) != 0 {
		t.Fatal(reasons)
	}
	o := storageObject(input["observation"])
	if o["processed_bytes"] != "1000.000000000000" || o["flow_complete"] != true || o["telemetry_complete"] != true {
		t.Fatal(o)
	}
	rows := storageRows(input["cohorts"])
	if len(rows) != 2 {
		t.Fatal(rows)
	}
	for _, row := range rows {
		if row["family"] != "A" || row["destination_region"] != "eu-west-1" || row["attribution_complete"] != true {
			t.Fatal(row)
		}
		path := model.Strings(row, "current_path")
		if path[0] != "subnet:subnet-client" || path[1] != "route-table:rtb-client" {
			t.Fatal("used capture NAT subnet as workload subnet", path)
		}
		if storageObject(row["technical"])["endpoint_scope_compatible"] != true {
			t.Fatal(row)
		}
	}
}
func TestNetworkProjectionBestEffortDeliveryDoesNotManufactureFullTraffic(t *testing.T) {
	for _, change := range []string{"missing-counter", "wrong-nat", "partial-capture", "missing-status", "skipdata", "missing-scope", "wrong-window", "egress-duplicate"} {
		t.Run(change, func(t *testing.T) {
			r, c, p, b, bill, now := networkProjectionFixture()
			m := storageObject(c["metrics"])
			f := storageObject(c["flows"])
			cov := storageObject(f["coverage"])
			switch change {
			case "missing-counter":
				m["coverage"] = []model.Document{}
			case "wrong-nat":
				sel := storageObject(m["selection"])
				sel["nat_gateway_id"] = "nat-other"
				m["selection"] = sel
			case "partial-capture":
				flows := storageRows(f["cohorts"])
				flows[0]["bytes"] = "399"
				f["cohorts"] = flows
			case "missing-status":
				delete(cov, "skipdata_records")
			case "skipdata":
				cov["skipdata_records"] = 1
			case "missing-scope":
				cov["resource_ids"] = []string{"eni-other"}
			case "wrong-window":
				cov["start"] = "2026-10-07T00:00:00Z"
			case "egress-duplicate":
				flows := storageRows(f["cohorts"])
				for _, row := range flows {
					row["flow_direction"] = "egress"
				}
				f["cohorts"] = flows
			}
			f["coverage"] = cov
			c["flows"], c["metrics"] = f, m
			input, _ := networkProjectInput(r, c, p, b, bill, nil, now)
			if storageObject(input["observation"])["flow_complete"] != false {
				t.Fatal("delivery orduplicate byteview becamefulltraffic", input)
			}
		})
	}
}
func TestNetworkProjectionServiceRegionRequiresNativeServiceAndPrefixScope(t *testing.T) {
	for _, change := range []string{"no-prefix", "wrong-region-prefix", "no-service-class", "incomplete-addresses", "wrong-client"} {
		t.Run(change, func(t *testing.T) {
			r, c, p, b, bill, now := networkProjectionFixture()
			top := storageObject(c["topology"])
			facts := storageRows(top["resources"])
			flows := storageObject(c["flows"])
			rows := storageRows(flows["cohorts"])
			switch change {
			case "no-prefix":
				for i, fact := range facts {
					if fact["resource_type"] == "AWS_SERVICE_PREFIX_LIST" {
						facts = append(facts[:i], facts[i+1:]...)
						break
					}
				}
			case "wrong-region-prefix":
				for _, fact := range facts {
					if fact["resource_type"] == "AWS_SERVICE_PREFIX_LIST" {
						fact["service_name"] = "com.amazonaws.us-east-1.s3"
					}
				}
			case "no-service-class":
				rows[0]["destination_service"] = nil
			case "incomplete-addresses":
				rows[0]["destination_addresses_complete"] = false
			case "wrong-client":
				rows[0]["source_addresses"] = []string{"10.0.9.99"}
			}
			top["resources"] = facts
			flows["cohorts"] = rows
			c["topology"], c["flows"] = top, flows
			input, _ := networkProjectInput(r, c, p, b, bill, nil, now)
			row := storageRows(input["cohorts"])[0]
			if storageObject(row["technical"])["endpoint_scope_compatible"] == true {
				t.Fatal("unsupported native destination or sourcejoin authorizedendpoint", row)
			}
		})
	}
}
func TestNetworkProjectionMoreSpecificRoutePreventsAssumedNATPath(t *testing.T) {
	r, c, p, b, bill, now := networkProjectionFixture()
	top := storageObject(c["topology"])
	facts := storageRows(top["resources"])
	for _, fact := range facts {
		if fact["resource_type"] == "ROUTE_TABLE" {
			fact["routes"] = append(storageRows(fact["routes"]), model.Document{"destination_cidr": "52.95.0.0/16", "transit_gateway_id": "tgw-review", "state": "active"})
		}
	}
	top["resources"] = facts
	c["topology"] = top
	input, _ := networkProjectInput(r, c, p, b, bill, nil, now)
	for _, row := range storageRows(input["cohorts"]) {
		if row["attribution_complete"] == true || storageObject(row["technical"])["endpoint_scope_compatible"] == true {
			t.Fatal("ignoredlongestprefixpath", row)
		}
	}
}
func TestNetworkProjectionExistingGatewayAndCrossAccountFacts(t *testing.T) {
	r, c, p, b, bill, now := networkProjectionFixture()
	top := storageObject(c["topology"])
	facts := storageRows(top["resources"])
	facts = append(facts, model.Document{"provider_resource_id": "vpce-s3", "resource_type": "VPC_ENDPOINT", "account_id": r["account_id"], "region": r["region"], "vpc_id": "vpc-projection", "service_name": "com.amazonaws.eu-west-1.s3", "endpoint_type": "Gateway", "route_table_ids": []string{"rtb-client"}})
	top["resources"] = facts
	c["topology"] = top
	input, _ := networkProjectInput(r, c, p, b, bill, nil, now)
	if storageObject(storageRows(input["cohorts"])[0]["technical"])["current_endpoint"] != true {
		t.Fatal(input)
	}
	facts[0]["account_id"] = "999900001111"
	top["resources"] = facts
	c["topology"] = top
	_, reasons := networkProjectInput(r, c, p, b, bill, nil, now)
	if !networkProjectionHas(reasons, "NETWORK_TOPOLOGY_NATIVE_SCOPE_MISMATCH") {
		t.Fatal(reasons)
	}
}
func TestNetworkProjectionUnassociatedEIPDoesNotInventVPCOrIdleTraffic(t *testing.T) {
	r, c, p, b, bill, now := networkProjectionFixture()
	r["resource_type"], r["provider_resource_id"], r["network_configuration"] = "ELASTIC_IP", "eipalloc-review", model.Document{"public_ipv4_classification": "UNASSOCIATED_ELASTIC_IP"}
	c["config_hash"] = NetworkConfigurationHash(r)
	c["metrics"] = model.Document{}
	c["flows"] = model.Document{}
	input, _ := networkProjectInput(r, c, p, b, bill, nil, now)
	cohort := storageRows(input["cohorts"])[0]
	tech := storageObject(cohort["technical"])
	if cohort["family"] != "E" || cohort["bytes"] != nil || tech["public_ipv4_kind"] != "ELASTIC_IP" || tech["association_state"] != "UNASSOCIATED" || storageObject(input["topology"])["vpc_id"] != nil {
		t.Fatal(input)
	}
}

func TestNetworkProjectionPolicyCannotInventOwnershipOrAuthority(t *testing.T) {
	for _, field := range []string{"owner", "configuration_authority"} {
		r, c, p, b, bill, now := networkProjectionFixture()
		delete(r, field)
		c["config_hash"] = NetworkConfigurationHash(r)
		_, reasons := networkProjectInput(r, c, p, b, bill, nil, now)
		expected := "NETWORK_RESOURCE_OWNERSHIP_NOT_EVIDENCED"
		if field == "configuration_authority" {
			expected = "NETWORK_RESOURCE_CONFIGURATION_AUTHORITY_NOT_EVIDENCED"
		}
		if !networkProjectionHas(reasons, expected) {
			t.Fatal("policy form replaced unknown native authority", field, reasons)
		}
	}
}

func TestNetworkProjectionRegionalHistoricalFootprintRemainsUnknown(t *testing.T) {
	r, c, p, b, bill, now := networkProjectionFixture()
	config := storageObject(r["network_configuration"])
	config["availability_mode"] = "regional"
	config["addresses"] = []model.Document{{"network_interface_id": "eni-nat", "availability_zone": "eu-west-1a"}}
	r["network_configuration"] = config
	c["config_hash"] = NetworkConfigurationHash(r)
	metrics := storageObject(c["metrics"])
	sel := storageObject(metrics["selection"])
	sel["availability_zone"] = "eu-west-1a"
	metrics["selection"] = sel
	metrics["coverage"] = append(storageRows(metrics["coverage"]), model.Document{"metric": "RegionalAvailabilityZoneFootprint", "status": "UNKNOWN"})
	c["metrics"] = metrics
	input, _ := networkProjectInput(r, c, p, b, bill, nil, now)
	if storageObject(input["observation"])["telemetry_complete"] != false || storageObject(input["observation"])["flow_complete"] != false {
		t.Fatal("current regionalAZbecamehistoricalfootprint", input)
	}
}

func TestNetworkProjectionNonterminatingNativeRatioIsExact(t *testing.T) {
	r, c, p, b, bill, now := networkProjectionFixture()
	metrics := storageObject(c["metrics"])
	metrics["totals"] = model.Document{"BytesInFromSource": "1", "BytesInFromDestination": "2"}
	c["metrics"] = metrics
	flows := storageObject(c["flows"])
	rows := storageRows(flows["cohorts"])
	rows[0]["bytes"], rows[1]["bytes"] = "1", "2"
	flows["cohorts"] = rows
	c["flows"] = flows
	input, _ := networkProjectInput(r, c, p, b, bill, nil, now)
	cohort := storageRows(input["cohorts"])[0]
	allocations := storageRows(cohort["billing_allocations"])
	if len(allocations) != 2 || allocations[0]["numerator"] != "1" || allocations[0]["denominator"] != "3" || allocations[0]["fraction"] != nil {
		t.Fatal("authoritative1/3ratio rounded", cohort)
	}
}
