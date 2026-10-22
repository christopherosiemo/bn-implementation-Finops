package provider

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/network"
)

var networkTestScope = network.Scope{TenantID: "tenant-network", AccountID: "111122223333", Region: "eu-west-1"}

func networkTestNative(t *testing.T, req *http.Request, body string) (string, int) {
	t.Helper()
	v, _ := url.ParseQuery(body)
	action := v.Get("Action")
	if req.URL.Scheme != "https" || !strings.Contains(req.Header.Get("Authorization"), "AWS4-HMAC-SHA256") {
		t.Fatal("unsigned transport")
	}
	if action == "GetCallerIdentity" {
		return rdsTestIdentity(), 200
	}
	for _, c := range networkCollections {
		if c.action != action {
			continue
		}
		items := ""
		token := ""
		switch action {
		case "DescribeVpcs":
			items = "<item><vpcId>vpc-11111111</vpcId><ownerId>111122223333</ownerId></item>"
		case "DescribeSubnets":
			items = "<item><subnetId>subnet-11111111</subnetId><vpcId>vpc-11111111</vpcId><ownerId>111122223333</ownerId><availabilityZone>eu-west-1a</availabilityZone><availabilityZoneId>euw1-az1</availabilityZoneId></item>"
		case "DescribeNatGateways":
			if v.Get("NextToken") == "" {
				items = "<item><natGatewayId>nat-11111111</natGatewayId><vpcId>vpc-11111111</vpcId><subnetId>subnet-11111111</subnetId><state>available</state><availabilityMode>zonal</availabilityMode><connectivityType>public</connectivityType><natGatewayAddressSet><item><networkInterfaceId>eni-11111111</networkInterfaceId><allocationId>eipalloc-11111111</allocationId><publicIp>203.0.113.10</publicIp></item></natGatewayAddressSet><tagSet/></item>"
				token = "next"
			} else {
				items = "<item><natGatewayId>nat-22222222</natGatewayId><vpcId>vpc-11111111</vpcId><state>available</state><availabilityMode>regional</availabilityMode><autoProvisionZones>enabled</autoProvisionZones><natGatewayAddressSet><item><availabilityZone>eu-west-1b</availabilityZone><publicIp>203.0.113.11</publicIp></item></natGatewayAddressSet></item>"
			}
		case "DescribeRouteTables":
			items = "<item><routeTableId>rtb-11111111</routeTableId><vpcId>vpc-11111111</vpcId><ownerId>111122223333</ownerId><routeSet><item><destinationCidrBlock>0.0.0.0/0</destinationCidrBlock><natGatewayId>nat-11111111</natGatewayId><state>active</state></item></routeSet><associationSet><item><subnetId>subnet-11111111</subnetId><main>false</main></item></associationSet></item>"
		case "DescribeVpcEndpoints":
			items = "<item><vpcEndpointId>vpce-11111111</vpcEndpointId><vpcId>vpc-11111111</vpcId><vpcEndpointType>Gateway</vpcEndpointType><serviceName>com.amazonaws.eu-west-1.s3</serviceName><routeTableIdSet><item>rtb-11111111</item></routeTableIdSet></item>"
		case "DescribeVpcEndpointServices":
			items = "<item><serviceName>com.amazonaws.eu-west-1.s3</serviceName><owner>amazon</owner><serviceType><item><serviceType>Gateway</serviceType></item></serviceType><availabilityZoneSet><item>eu-west-1a</item></availabilityZoneSet></item>"
		case "DescribePrefixLists":
			items = "<item><prefixListId>pl-11111111</prefixListId><prefixListName>com.amazonaws.eu-west-1.s3</prefixListName><cidrSet><item>52.95.128.0/24</item></cidrSet></item>"
		case "DescribeAddresses":
			items = "<item><allocationId>eipalloc-11111111</allocationId><publicIp>203.0.113.1</publicIp><associationId>eipassoc-11111111</associationId></item><item><allocationId>eipalloc-22222222</allocationId><publicIp>203.0.113.2</publicIp></item>"
		}
		if action == "DescribeLoadBalancers" {
			return "<DescribeLoadBalancersResponse><DescribeLoadBalancersResult><LoadBalancers/></DescribeLoadBalancersResult></DescribeLoadBalancersResponse>", 200
		}
		return ebsTestPage(action, c.collection, items, token), 200
	}
	t.Fatalf("mutation or unknown action %s", action)
	return "", 500
}
func TestNetworkNativePaginationTopologyRegionalAndPublicIPs(t *testing.T) {
	a := rdsTestAWS(t, func(req *http.Request, body string) (string, int) { return networkTestNative(t, req, body) })
	out, e := a.NetworkDiscover(context.Background(), networkTestScope)
	if e != nil || !out.Complete || out.TopologyHash == "" {
		t.Fatal(out, e)
	}
	byID := map[string]model.Document{}
	for _, d := range out.Resources {
		byID[model.String(d, "provider_resource_id")] = d
	}
	zonal := byID["nat-11111111"]
	regional := byID["nat-22222222"]
	if zonal["availability_zone"] != "eu-west-1a" || len(zonal["route_table_consumers"].([]string)) != 1 || regional["availability_mode"] != "regional" || regional["subnet_id"] != nil || regional["availability_zone"] != nil {
		t.Fatal("NAT semantics inferred", zonal, regional)
	}
	if byID["eipalloc-11111111"]["public_ipv4_classification"] != "ASSOCIATED_ELASTIC_IP" || byID["eipalloc-22222222"]["public_ipv4_classification"] != "UNASSOCIATED_ELASTIC_IP" {
		t.Fatal("publicIP classification")
	}
	if len(byID["pl-11111111"]["cidrs"].([]string)) != 1 || byID["com.amazonaws.eu-west-1.s3"]["service_types"].([]string)[0] != "Gateway" || byID["com.amazonaws.eu-west-1.s3"]["provider_service_owner"] != "amazon" {
		t.Fatal("native service endpoint/prefix catalogue lost")
	}
	s, frames, e := NetworkCaptureFrames(out.Raw)
	if e != nil || s != networkTestScope || len(frames) < 17 {
		t.Fatal("native capture", e)
	}
	again, e := a.NetworkDiscover(context.Background(), networkTestScope)
	if e != nil || again.TopologyHash != out.TopologyHash {
		t.Fatal("capture clock changed topology hash", e)
	}
}
func TestNetworkNativeOptionalDeniedThrottleAndScope(t *testing.T) {
	for _, which := range []string{"denied", "throttle", "wrong owner", "wrong AZ", "repeated token"} {
		t.Run(which, func(t *testing.T) {
			calls := 0
			a := rdsTestAWS(t, func(req *http.Request, body string) (string, int) {
				v, _ := url.ParseQuery(body)
				action := v.Get("Action")
				if action == "DescribeNatGateways" {
					calls++
					if which == "denied" {
						return "<Response><Errors><Error><Code>UnauthorizedOperation</Code></Error></Errors></Response>", 403
					}
					if which == "throttle" && calls == 1 {
						return "<Response><Errors><Error><Code>RequestLimitExceeded</Code></Error></Errors></Response>", 400
					}
					if which == "repeated token" {
						return ebsTestPage(action, "natGatewaySet", "", "same"), 200
					}
				}
				text, status := networkTestNative(t, req, body)
				if action == "DescribeSubnets" && which == "wrong owner" {
					text = strings.ReplaceAll(text, "111122223333", "444455556666")
				}
				if action == "DescribeSubnets" && which == "wrong AZ" {
					text = strings.ReplaceAll(text, "eu-west-1a", "us-west-2a")
				}
				return text, status
			})
			out, e := a.NetworkDiscover(context.Background(), networkTestScope)
			if e != nil {
				t.Fatal(e)
			}
			if which == "throttle" {
				if !out.Complete || calls != 3 {
					t.Fatal(out, calls)
				}
			} else if out.Complete || len(out.Resources) == 0 {
				t.Fatal("optional failure discarded or called complete", out)
			}
		})
	}
	a := rdsTestAWS(t, func(req *http.Request, body string) (string, int) {
		return strings.ReplaceAll(rdsTestIdentity(), "111122223333", "444455556666"), 200
	})
	if _, e := a.NetworkDiscover(context.Background(), networkTestScope); e == nil {
		t.Fatal("wrong caller accepted")
	}
}
func TestNetworkNATMetricsMissingIsNotZeroAndRegionalDimensions(t *testing.T) {
	for _, mode := range []string{"zonal", "regional"} {
		t.Run(mode, func(t *testing.T) {
			now := time.Now().UTC().Add(-2 * time.Hour).Truncate(time.Hour)
			sel := network.MetricSelection{NATGatewayID: "nat-11111111", Start: now, End: now.Add(time.Hour), PeriodSeconds: 3600}
			if mode == "regional" {
				sel.AvailabilityZone = "eu-west-1a"
			}
			a := rdsTestAWS(t, func(req *http.Request, body string) (string, int) {
				v, _ := url.ParseQuery(body)
				switch v.Get("Action") {
				case "GetCallerIdentity":
					return rdsTestIdentity(), 200
				case "DescribeNatGateways":
					return ebsTestPage("DescribeNatGateways", "natGatewaySet", "<item><natGatewayId>nat-11111111</natGatewayId><availabilityMode>"+mode+"</availabilityMode><natGatewayAddressSet><item><availabilityZone>eu-west-1a</availabilityZone></item></natGatewayAddressSet></item>", ""), 200
				case "GetMetricStatistics":
					if mode == "regional" && v.Get("Dimensions.member.2.Value") != "eu-west-1a" || mode == "zonal" && v.Get("Dimensions.member.2.Name") != "" {
						t.Fatal("wrong native dimension")
					}
					points := ""
					if v.Get("MetricName") != "BytesInFromDestination" {
						points = "<member><Timestamp>" + now.Format(time.RFC3339) + "</Timestamp><" + v.Get("Statistics.member.1") + ">0</" + v.Get("Statistics.member.1") + "><SampleCount>60</SampleCount><Unit>" + v.Get("Unit") + "</Unit></member>"
					}
					return "<GetMetricStatisticsResponse><GetMetricStatisticsResult><Datapoints>" + points + "</Datapoints></GetMetricStatisticsResult></GetMetricStatisticsResponse>", 200
				}
				t.Fatal("unknown request")
				return "", 500
			})
			out, e := a.NetworkNATMetrics(context.Background(), networkTestScope, sel)
			if e != nil {
				t.Fatal(e)
			}
			for _, c := range out.Coverage {
				status := c["status"]
				if c["metric"] == "BytesInFromDestination" {
					if status != "GAPS" {
						t.Fatal("missing manufactured zero", c)
					}
				} else if status != "COMPLETE_ZERO_OBSERVED" {
					t.Fatal("zero lost", c)
				}
			}
			if mode == "regional" {
				sel.AvailabilityZone = "eu-west-1b"
				if _, e = a.NetworkNATMetrics(context.Background(), networkTestScope, sel); e == nil {
					t.Fatal("unbound regionalAZ")
				}
			}
		})
	}
}
