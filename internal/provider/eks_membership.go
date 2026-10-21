package provider

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/url"
	"strings"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/awsservice"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
)

// EKSMembership independently joins native ASG membership and EC2 owner/state.
// Only exact approved names/instance IDs are queried; no tag/name inference or
// Kubernetes node labels can manufacture AWS membership.
func (a *AWS) EKSMembership(ctx context.Context, scope awsservice.Scope, names, instanceIDs []string) ([]model.Document, []byte, error) {
	r, e := newServiceRead(a, scope)
	if e != nil || len(names) > 100 || len(instanceIDs) > 1000 {
		return nil, nil, awsservice.ErrEvidence
	}
	members := map[string]model.Document{}
	seenNames := map[string]bool{}
	if len(names) > 0 {
		q := url.Values{"Action": {"DescribeAutoScalingGroups"}, "Version": {"2011-01-01"}, "MaxRecords": {"100"}}
		for n, name := range names {
			if !fleetGroupName.MatchString(name) || seenNames[name] {
				return nil, nil, awsservice.ErrEvidence
			}
			seenNames[name] = true
			q.Set(fmt.Sprintf("AutoScalingGroupNames.member.%d", n+1), name)
		}
		seen := map[string]bool{}
		observed := map[string]bool{}
		for p := 0; p < 32; p++ {
			c, e := r.credentials(ctx)
			if e != nil {
				return nil, nil, e
			}
			raw, e := r.send(ctx, c, "autoscaling", "POST", "/", q.Encode(), "")
			if e != nil {
				return nil, nil, e
			}
			var x struct {
				XMLName xml.Name
				Result  struct {
					Groups []FleetGroup `xml:"AutoScalingGroups>member"`
					Next   string       `xml:"NextToken"`
				} `xml:"DescribeAutoScalingGroupsResult"`
			}
			if xml.Unmarshal(raw, &x) != nil || x.XMLName.Local != "DescribeAutoScalingGroupsResponse" {
				return nil, nil, awsservice.ErrEvidence
			}
			for _, g := range x.Result.Groups {
				if !seenNames[g.Name] || observed[g.Name] || !strings.HasPrefix(g.ARN, "arn:aws:autoscaling:"+scope.Region+":"+scope.AccountID+":autoScalingGroup:") || !strings.HasSuffix(g.ARN, ":autoScalingGroupName/"+g.Name) {
					return nil, nil, awsservice.ErrEvidence
				}
				observed[g.Name] = true
				for _, m := range g.Members {
					if !fleetInstance.MatchString(m.InstanceID) || members[m.InstanceID] != nil || !strings.HasPrefix(m.Zone, scope.Region) {
						return nil, nil, awsservice.ErrEvidence
					}
					members[m.InstanceID] = model.Document{"instance_id": m.InstanceID, "asg_name": g.Name, "asg_arn": g.ARN, "zone": m.Zone, "account_id": scope.AccountID, "region": scope.Region, "state": "UNKNOWN", "native_asg_page_sha256": awsservice.BytesHash(raw)}
				}
			}
			if x.Result.Next == "" {
				if len(observed) != len(seenNames) {
					return nil, nil, awsservice.ErrEvidence
				}
				break
			}
			if p == 31 || len(x.Result.Next) > 4096 || seen[x.Result.Next] {
				return nil, nil, awsservice.ErrEvidence
			}
			seen[x.Result.Next] = true
			q.Set("NextToken", x.Result.Next)
		}
	}
	seenIDs := map[string]bool{}
	for first := 0; first < len(instanceIDs); first += 100 {
		q := url.Values{"Action": {"DescribeInstances"}, "Version": {"2016-11-15"}}
		wanted := map[string]bool{}
		for n, id := range instanceIDs[first:min(first+100, len(instanceIDs))] {
			if !fleetInstance.MatchString(id) || seenIDs[id] {
				return nil, nil, awsservice.ErrEvidence
			}
			seenIDs[id] = true
			wanted[id] = true
			q.Set(fmt.Sprintf("InstanceId.%d", n+1), id)
		}
		c, e := r.credentials(ctx)
		if e != nil {
			return nil, nil, e
		}
		raw, e := r.send(ctx, c, "ec2", "POST", "/", q.Encode(), "")
		if e != nil {
			return nil, nil, e
		}
		var x struct {
			XMLName      xml.Name
			Next         string `xml:"nextToken"`
			Reservations []struct {
				Owner     string `xml:"ownerId"`
				Instances []struct {
					ID    string `xml:"instanceId"`
					State struct {
						Name string `xml:"name"`
					} `xml:"instanceState"`
					Placement struct {
						Zone string `xml:"availabilityZone"`
					} `xml:"placement"`
				} `xml:"instancesSet>item"`
			} `xml:"reservationSet>item"`
		}
		if xml.Unmarshal(raw, &x) != nil || x.XMLName.Local != "DescribeInstancesResponse" || x.Next != "" {
			return nil, nil, awsservice.ErrEvidence
		}
		observed := map[string]bool{}
		for _, reservation := range x.Reservations {
			if reservation.Owner != scope.AccountID {
				return nil, nil, awsservice.ErrEvidence
			}
			for _, instance := range reservation.Instances {
				if !wanted[instance.ID] || observed[instance.ID] {
					return nil, nil, awsservice.ErrEvidence
				}
				observed[instance.ID] = true
				if m := members[instance.ID]; m != nil {
					if m["zone"] != instance.Placement.Zone {
						return nil, nil, awsservice.ErrEvidence
					}
					m["state"], m["native_ec2_page_sha256"] = instance.State.Name, awsservice.BytesHash(raw)
				}
			}
		}
		if len(observed) != len(wanted) {
			return nil, nil, awsservice.ErrEvidence
		}
	}
	rows := []model.Document{}
	for _, id := range instanceIDs {
		if m := members[id]; m != nil {
			rows = append(rows, m)
		}
	}
	body, _ := json.Marshal(model.Document{"schema_version": "EKS_NATIVE_MEMBERSHIP_V1", "scope": scope, "memberships": rows, "basis": "SANITIZED_NATIVE_ASG_AND_EC2_OWNER_STATE_POINT_READ"})
	return rows, body, nil
}
