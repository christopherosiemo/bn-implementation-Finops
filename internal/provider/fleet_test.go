package provider

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
)

func fleetXML(name, account, members string, desired int) string {
	return fmt.Sprintf(`<member><AutoScalingGroupName>%s</AutoScalingGroupName><AutoScalingGroupARN>arn:aws:autoscaling:eu-west-1:%s:autoScalingGroup:uuid:autoScalingGroupName/%s</AutoScalingGroupARN><DesiredCapacity>%d</DesiredCapacity><MinSize>0</MinSize><MaxSize>20</MaxSize><AvailabilityZones><member>eu-west-1a</member></AvailabilityZones><LaunchTemplate><LaunchTemplateId>lt-0123456789abcdef0</LaunchTemplateId><Version>3</Version></LaunchTemplate><Instances>%s</Instances></member>`, name, account, name, desired, members)
}
func fleetAWS(t *testing.T, respond func(url.Values) string) *AWS {
	t.Helper()
	return &AWS{cfg: aws.Config{Region: "eu-west-1", Credentials: aws.NewCredentialsCache(credentials.NewStaticCredentialsProvider("fixture", "fixture", ""))}, client: &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host != "autoscaling.eu-west-1.amazonaws.com" || r.URL.Scheme != "https" {
			t.Error("unexpected provider endpoint")
		}
		raw, _ := io.ReadAll(r.Body)
		v, _ := url.ParseQuery(string(raw))
		if v.Get("Action") != "DescribeAutoScalingGroups" || v.Get("Version") != "2011-01-01" {
			t.Error("unexpected or mutating AWS action")
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(respond(v)))}, nil
	})}}
}
func TestNativeFleetMembershipKeepsRealZeroAndCompleteRawPages(t *testing.T) {
	member := `<member><InstanceId>i-0123456789abcdef0</InstanceId><AvailabilityZone>eu-west-1a</AvailabilityZone><LifecycleState>InService</LifecycleState><HealthStatus>Healthy</HealthStatus><LaunchTemplate><LaunchTemplateId>lt-0123456789abcdef0</LaunchTemplateId><Version>3</Version></LaunchTemplate></member>`
	calls := 0
	a := fleetAWS(t, func(v url.Values) string {
		calls++
		if v.Get("AutoScalingGroupNames.member.1") != "blue" || v.Get("AutoScalingGroupNames.member.2") != "green" {
			t.Error("group scope changed")
		}
		groups, next := fleetXML("blue", "111122223333", member, 1), "<NextToken>page-2</NextToken>"
		if v.Get("NextToken") == "page-2" {
			groups, next = fleetXML("green", "111122223333", "", 0), ""
		}
		return `<DescribeAutoScalingGroupsResponse><DescribeAutoScalingGroupsResult><AutoScalingGroups>` + groups + `</AutoScalingGroups>` + next + `</DescribeAutoScalingGroupsResult></DescribeAutoScalingGroupsResponse>`
	})
	r, err := a.FleetInventory(context.Background(), "eu-west-1", "111122223333", []string{"green", "blue"})
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(r.Raw)
	if calls != 2 || len(r.Groups) != 2 || r.Groups[1].Desired == nil || *r.Groups[1].Desired != 0 || r.Groups[1].Members == nil || len(r.Groups[1].Members) != 0 || r.RawSHA256 != hex.EncodeToString(sum[:]) || !strings.Contains(string(r.Raw), member) {
		t.Fatal("native empty group or raw provenance lost")
	}
}
func TestNativeFleetMembershipRejectsScopeGapsAndConflictingPages(t *testing.T) {
	for _, tc := range []struct{ name, groups, next string }{
		{"wrong-account", fleetXML("blue", "999900001111", "", 0), ""},
		{"missing-green", fleetXML("blue", "111122223333", "", 0), ""},
		{"unknown-capacity", strings.Replace(fleetXML("blue", "111122223333", "", 0), "<DesiredCapacity>0</DesiredCapacity>", "", 1), ""},
		{"duplicate-group", fleetXML("blue", "111122223333", "", 0) + fleetXML("blue", "111122223333", "", 0), ""},
		{"pagination-loop", fleetXML("blue", "111122223333", "", 0), "<NextToken>same</NextToken>"},
		{"wrong-zone", fleetXML("blue", "111122223333", `<member><InstanceId>i-0123456789abcdef0</InstanceId><AvailabilityZone>us-east-1a</AvailabilityZone><LifecycleState>InService</LifecycleState><HealthStatus>Healthy</HealthStatus></member>`, 1), ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := fleetAWS(t, func(url.Values) string {
				return `<DescribeAutoScalingGroupsResponse><DescribeAutoScalingGroupsResult><AutoScalingGroups>` + tc.groups + `</AutoScalingGroups>` + tc.next + `</DescribeAutoScalingGroupsResult></DescribeAutoScalingGroupsResponse>`
			})
			if _, err := a.FleetInventory(context.Background(), "eu-west-1", "111122223333", []string{"blue", "green"}); err == nil {
				t.Fatal("unknown cohort accepted")
			}
		})
	}
}
