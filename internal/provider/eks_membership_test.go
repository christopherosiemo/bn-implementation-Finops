package provider

import (
	"context"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/awsservice"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestEKSNativeMembershipPinsASGEC2OwnerAndZone(t *testing.T) {
	for _, foreign := range []bool{false, true} {
		t.Run(map[bool]string{false: "matching", true: "foreign-owner"}[foreign], func(t *testing.T) {
			tr := &serviceTestTransport{}
			tr.handle = func(req *http.Request, _ model.Document, v url.Values) (string, int) {
				switch v.Get("Action") {
				case "DescribeAutoScalingGroups":
					return serviceTestXML("DescribeAutoScalingGroups", `<AutoScalingGroups><member><AutoScalingGroupName>eks-workers</AutoScalingGroupName><AutoScalingGroupARN>arn:aws:autoscaling:eu-west-1:111122223333:autoScalingGroup:uuid:autoScalingGroupName/eks-workers</AutoScalingGroupARN><Instances><member><InstanceId>i-0123456789abcdef0</InstanceId><AvailabilityZone>eu-west-1a</AvailabilityZone></member></Instances></member></AutoScalingGroups>`)
				case "DescribeInstances":
					owner := "111122223333"
					if foreign {
						owner = "999900001111"
					}
					return `<DescribeInstancesResponse><reservationSet><item><ownerId>` + owner + `</ownerId><instancesSet><item><instanceId>i-0123456789abcdef0</instanceId><instanceState><name>running</name></instanceState><placement><availabilityZone>eu-west-1a</availabilityZone></placement></item></instancesSet></item></reservationSet></DescribeInstancesResponse>`, 200
				}
				t.Errorf("unexpected action %s", v.Get("Action"))
				return "", 500
			}
			rows, raw, e := serviceTestAWS(tr).EKSMembership(context.Background(), awsservice.Scope{TenantID: "tenant", AccountID: "111122223333", Region: "eu-west-1"}, []string{"eks-workers"}, []string{"i-0123456789abcdef0"})
			if foreign {
				if e == nil {
					t.Fatal("foreign EC2 owner accepted")
				}
				return
			}
			if e != nil || len(rows) != 1 || rows[0]["state"] != "running" || len(raw) == 0 {
				t.Fatalf("membership unavailable: %v %#v", e, rows)
			}
			for _, call := range tr.calls {
				if !strings.HasPrefix(call, "GetCallerIdentity") && !strings.HasPrefix(call, "Describe") {
					t.Fatalf("unexpected mutation %s", call)
				}
			}
		})
	}
}
