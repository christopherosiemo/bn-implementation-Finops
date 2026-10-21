package provider

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/awsservice"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
)

func TestAWSServiceELBPagesSubtypesTopologyAndDeniedReads(t *testing.T) {
	const alb = "arn:aws:elasticloadbalancing:eu-west-1:111122223333:loadbalancer/app/web/123"
	const nlb = "arn:aws:elasticloadbalancing:eu-west-1:111122223333:loadbalancer/net/private/456"
	const listener = "arn:aws:elasticloadbalancing:eu-west-1:111122223333:listener/app/web/123/abc"
	const tg = "arn:aws:elasticloadbalancing:eu-west-1:111122223333:targetgroup/web/789"
	roots := 0
	reader := lambdaTestAWS(t, func(r *http.Request, body string) (string, int) {
		if r.URL.Host == "sts.eu-west-1.amazonaws.com" {
			return rdsTestIdentity(), 200
		}
		p, e := url.ParseQuery(body)
		if e != nil {
			t.Fatal(e)
		}
		action, version := p.Get("Action"), p.Get("Version")
		result := ""
		switch action {
		case "DescribeLoadBalancers":
			roots++
			if version == serviceELBClassic {
				result = "<LoadBalancerDescriptions><member><LoadBalancerName>legacy</LoadBalancerName><Scheme>internal</Scheme><Instances><member><InstanceId>i-123</InstanceId></member></Instances></member></LoadBalancerDescriptions>"
			} else if p.Get("Marker") == "" {
				result = "<LoadBalancers><member><LoadBalancerArn>" + alb + "</LoadBalancerArn><LoadBalancerName>web</LoadBalancerName><Type>application</Type></member></LoadBalancers><NextMarker>page2</NextMarker>"
			} else if p.Get("Marker") == "page2" {
				result = "<LoadBalancers><member><LoadBalancerArn>" + nlb + "</LoadBalancerArn><LoadBalancerName>private</LoadBalancerName><Type>network</Type></member></LoadBalancers>"
			} else {
				t.Fatal("unexpected root cursor")
			}
		case "DescribeLoadBalancerAttributes":
			if p.Get("LoadBalancerArn") == alb {
				return "<ErrorResponse><Error><Code>AccessDenied</Code><Message>private native diagnostic</Message></Error></ErrorResponse>", 403
			}
			result = "<Attributes/>"
		case "DescribeTags":
			result = "<TagDescriptions/>"
		case "DescribeListeners":
			if p.Get("LoadBalancerArn") == alb {
				result = "<Listeners><member><ListenerArn>" + listener + "</ListenerArn><Port>443</Port><Protocol>HTTPS</Protocol><DefaultActions><member><Type>forward</Type><TargetGroupArn>" + tg + "</TargetGroupArn><AuthenticateOidcConfig><ClientSecret>never-retain</ClientSecret></AuthenticateOidcConfig></member></DefaultActions></member></Listeners>"
			} else {
				result = "<Listeners/>"
			}
		case "DescribeRules":
			result = "<Rules/>"
		case "DescribeTargetGroups":
			if p.Get("LoadBalancerArn") == alb {
				result = "<TargetGroups><member><TargetGroupArn>" + tg + "</TargetGroupArn><TargetGroupName>web</TargetGroupName><LoadBalancerArns><member>" + alb + "</member></LoadBalancerArns><TargetType>instance</TargetType></member></TargetGroups>"
			} else {
				result = "<TargetGroups/>"
			}
		case "DescribeTargetGroupAttributes":
			result = "<Attributes/>"
		case "DescribeTargetHealth":
			result = "<TargetHealthDescriptions><member><Target><Id>i-123</Id></Target><TargetHealth><State>healthy</State></TargetHealth></member></TargetHealthDescriptions>"
		case "DescribeInstanceHealth":
			result = "<InstanceStates><member><InstanceId>i-123</InstanceId><State>InService</State></member></InstanceStates>"
		default:
			t.Fatalf("unplanned metadata action %s", action)
		}
		return fmt.Sprintf("<%sResponse><%sResult>%s</%sResult></%sResponse>", action, action, result, action, action), 200
	})
	reg := awsservice.Registration{ID: "source-elb", TenantID: "tenant-demo", AccountID: "111122223333", Region: "eu-west-1", ReadRoleBindingID: "read", Version: 1, Enabled: true, ServiceFamilies: []string{"ELB"}, ScopeMode: "ACCOUNT"}
	cursor := ""
	subtypes := map[string]bool{}
	related := false
	partial := false
	for n := 0; n < 3; n++ {
		out, e := reader.ServiceInventory(context.Background(), reg, "ELB", cursor)
		if e != nil {
			t.Fatal(e)
		}
		if strings.Contains(string(out.Raw), "never-retain") || strings.Contains(string(out.Raw), "private native diagnostic") {
			t.Fatal("sensitive payload retained")
		}
		for _, resource := range out.Resources {
			cfg := awsservice.Document(resource["aws_service_configuration"])
			if resource["resource_type"] == "LOAD_BALANCER" {
				subtypes[model.String(cfg, "subtype")] = true
			}
			if len(awsservice.Rows(resource["provider_relationships"])) > 0 {
				related = true
			}
		}
		if len(out.Reasons) > 0 {
			partial = true
			if out.Complete {
				t.Fatal("denied enrichment claimed complete")
			}
		}
		cursor = out.NextCursor
	}
	if roots != 3 || cursor != "" || !subtypes["ALB"] || !subtypes["NLB"] || !subtypes["CLASSIC"] || !related || !partial {
		t.Fatalf("missing native inventory: roots=%d types=%v relationship=%v partial=%v", roots, subtypes, related, partial)
	}
}

func TestAWSServiceELBRejectsForeignResourceAndSourceCursor(t *testing.T) {
	reader := lambdaTestAWS(t, func(r *http.Request, _ string) (string, int) {
		if r.URL.Host == "sts.eu-west-1.amazonaws.com" {
			return rdsTestIdentity(), 200
		}
		return "<DescribeLoadBalancersResponse><DescribeLoadBalancersResult><LoadBalancers><member><LoadBalancerArn>arn:aws:elasticloadbalancing:eu-west-1:999999999999:loadbalancer/app/foreign/1</LoadBalancerArn><LoadBalancerName>foreign</LoadBalancerName><Type>application</Type></member></LoadBalancers></DescribeLoadBalancersResult></DescribeLoadBalancersResponse>", 200
	})
	reg := awsservice.Registration{ID: "source-elb", TenantID: "tenant-demo", AccountID: "111122223333", Region: "eu-west-1", ReadRoleBindingID: "read", Version: 1, Enabled: true, ServiceFamilies: []string{"ELB"}, ScopeMode: "ACCOUNT"}
	if _, e := reader.ServiceInventory(context.Background(), reg, "ELB", ""); e == nil {
		t.Fatal("foreign resource accepted")
	}
	if _, e := reader.ServiceInventory(context.Background(), reg, "ELB", "invented-cursor"); e == nil {
		t.Fatal("invalid cursor accepted")
	}
}
