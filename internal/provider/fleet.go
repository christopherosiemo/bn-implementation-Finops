package provider

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

// FleetInventoryEvidence is a read result, not an execution or health receipt.
// The ingestion pipeline must archive Raw and persist a typed source receipt
// before any assessment can select it as authoritative cohort membership.
type FleetInventoryEvidence struct {
	SchemaVersion string       `json:"schema_version"`
	Provider      string       `json:"provider"`
	AccountID     string       `json:"account_id"`
	Region        string       `json:"region"`
	CollectedAt   time.Time    `json:"collected_at"`
	RawSHA256     string       `json:"raw_sha256"`
	Groups        []FleetGroup `json:"groups"`
	Raw           []byte       `json:"-"`
}
type FleetMember struct {
	InstanceID     string              `xml:"InstanceId" json:"instance_id"`
	Zone           string              `xml:"AvailabilityZone" json:"zone"`
	Lifecycle      string              `xml:"LifecycleState" json:"lifecycle"`
	Health         string              `xml:"HealthStatus" json:"health"`
	LaunchTemplate FleetLaunchTemplate `xml:"LaunchTemplate" json:"launch_template"`
}
type FleetLaunchTemplate struct {
	ID      string `xml:"LaunchTemplateId" json:"id"`
	Version string `xml:"Version" json:"version"`
}
type FleetGroup struct {
	Name           string              `xml:"AutoScalingGroupName" json:"name"`
	ARN            string              `xml:"AutoScalingGroupARN" json:"arn"`
	Desired        *int                `xml:"DesiredCapacity" json:"desired"`
	Minimum        *int                `xml:"MinSize" json:"minimum"`
	Maximum        *int                `xml:"MaxSize" json:"maximum"`
	LaunchTemplate FleetLaunchTemplate `xml:"LaunchTemplate" json:"launch_template"`
	Zones          []string            `xml:"AvailabilityZones>member" json:"zones"`
	Members        []FleetMember       `xml:"Instances>member" json:"members"`
	Suspended      []struct {
		Name string `xml:"ProcessName" json:"name"`
	} `xml:"SuspendedProcesses>member" json:"suspended_processes"`
	MixedPolicy                      *struct{}  `xml:"MixedInstancesPolicy" json:"mixed_policy"`
	Tags                             []FleetTag `xml:"Tags>member" json:"tags"`
	DesiredCapacityType              string     `xml:"DesiredCapacityType" json:"desired_capacity_type"`
	CapacityRebalance                *bool      `xml:"CapacityRebalance" json:"capacity_rebalance"`
	NewInstancesProtectedFromScaleIn *bool      `xml:"NewInstancesProtectedFromScaleIn" json:"new_instances_protected_from_scale_in"`
}
type FleetTag struct {
	Key               string `xml:"Key" json:"key"`
	Value             string `xml:"Value" json:"value"`
	PropagateAtLaunch *bool  `xml:"PropagateAtLaunch" json:"propagate_at_launch"`
}

var fleetGroupName = regexp.MustCompile(`^[A-Za-z0-9_.:/+=,@-]{1,255}$`)
var fleetAccount = regexp.MustCompile(`^[0-9]{12}$`)
var fleetInstance = regexp.MustCompile(`^i-[a-f0-9]{8}([a-f0-9]{9})?$`)

func (a *AWS) fleetRead(ctx context.Context, region string, values url.Values) ([]byte, error) {
	values.Set("Action", "DescribeAutoScalingGroups")
	values.Set("Version", "2011-01-01")
	body := values.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://autoscaling."+region+".amazonaws.com/", strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept-Encoding", "identity")
	creds, err := a.cfg.Credentials.Retrieve(ctx)
	if err != nil {
		return nil, errors.New("FLEET_READ_IDENTITY_UNAVAILABLE")
	}
	hash := sha256.Sum256([]byte(body))
	if err = v4.NewSigner().SignHTTP(ctx, creds, req, hex.EncodeToString(hash[:]), "autoscaling", region, time.Now()); err != nil {
		return nil, err
	}
	// Even an injected client must not redirect a signed source request.
	client := *a.client
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	res, err := client.Do(req)
	if err != nil {
		return nil, errors.New("FLEET_INVENTORY_UNAVAILABLE")
	}
	defer res.Body.Close()
	if encoding := res.Header.Get("Content-Encoding"); encoding != "" && encoding != "identity" {
		return nil, errors.New("FLEET_INVENTORY_ENCODING_UNSUPPORTED")
	}
	raw, err := io.ReadAll(io.LimitReader(res.Body, (16<<20)+1))
	if err != nil || len(raw) > 16<<20 {
		return nil, errors.New("FLEET_INVENTORY_RESPONSE_LIMIT")
	}
	if res.StatusCode != 200 {
		return nil, &QueryRejection{Action: "DescribeAutoScalingGroups", Code: "ProviderRejected", StatusCode: res.StatusCode}
	}
	return raw, nil
}

// FleetInventory fetches exactly the approved group names. A missing candidate
// ASG is unknown; an existing group with desired=0 is a real empty cohort.
func (a *AWS) FleetInventory(ctx context.Context, region, account string, names []string) (FleetInventoryEvidence, error) {
	out := FleetInventoryEvidence{SchemaVersion: "1", Provider: "AWS", AccountID: account, Region: region, Groups: []FleetGroup{}}
	if region != "eu-west-1" || !fleetAccount.MatchString(account) || len(names) < 1 || len(names) > 100 {
		return out, errors.New("FLEET_INVENTORY_SCOPE_INVALID")
	}
	wanted := map[string]bool{}
	for _, name := range names {
		if !fleetGroupName.MatchString(name) || wanted[name] {
			return out, errors.New("FLEET_INVENTORY_SCOPE_INVALID")
		}
		wanted[name] = true
	}
	values := url.Values{"MaxRecords": {"100"}}
	ordered := append([]string{}, names...)
	sort.Strings(ordered)
	for i, name := range ordered {
		values.Set(fmt.Sprintf("AutoScalingGroupNames.member.%d", i+1), name)
	}
	seenGroups, seenInstances, tokens := map[string]bool{}, map[string]bool{}, map[string]bool{}
	var raw bytes.Buffer
	for pages := 0; pages < 100; pages++ {
		body, err := a.fleetRead(ctx, region, values)
		if err != nil {
			return out, err
		}
		var response struct {
			XMLName xml.Name
			Result  struct {
				Groups []FleetGroup `xml:"AutoScalingGroups>member"`
				Next   string       `xml:"NextToken"`
			} `xml:"DescribeAutoScalingGroupsResult"`
		}
		if xml.Unmarshal(body, &response) != nil || response.XMLName.Local != "DescribeAutoScalingGroupsResponse" {
			return out, errors.New("FLEET_INVENTORY_RESPONSE_INVALID")
		}
		// Retain complete provider pages and their exact request selectors.
		selector := values.Encode()
		_ = binary.Write(&raw, binary.BigEndian, uint32(len(selector)))
		raw.WriteString(selector)
		_ = binary.Write(&raw, binary.BigEndian, uint64(len(body)))
		raw.Write(body)
		if raw.Len() > 32<<20 {
			return out, errors.New("FLEET_INVENTORY_RESPONSE_LIMIT")
		}
		for _, g := range response.Result.Groups {
			prefix := "arn:aws:autoscaling:" + region + ":" + account + ":autoScalingGroup:"
			if !wanted[g.Name] || seenGroups[g.Name] || !strings.HasPrefix(g.ARN, prefix) || !strings.HasSuffix(g.ARN, ":autoScalingGroupName/"+g.Name) || g.Minimum == nil || g.Desired == nil || g.Maximum == nil || *g.Minimum < 0 || *g.Desired < *g.Minimum || *g.Maximum < *g.Desired || len(g.Zones) == 0 {
				return out, errors.New("FLEET_INVENTORY_BINDING_MISMATCH")
			}
			seenGroups[g.Name] = true
			zones := map[string]bool{}
			for _, zone := range g.Zones {
				if !strings.HasPrefix(zone, region) || zones[zone] {
					return out, errors.New("FLEET_ZONE_BINDING_INVALID")
				}
				zones[zone] = true
			}
			for _, m := range g.Members {
				if !fleetInstance.MatchString(m.InstanceID) || seenInstances[m.InstanceID] || !zones[m.Zone] || m.Lifecycle == "" || m.Health == "" {
					return out, errors.New("FLEET_MEMBERSHIP_INVALID")
				}
				seenInstances[m.InstanceID] = true
			}
			if g.Members == nil {
				g.Members = []FleetMember{}
			}
			out.Groups = append(out.Groups, g)
		}
		if response.Result.Next == "" {
			if len(seenGroups) != len(wanted) {
				return out, errors.New("FLEET_GROUP_NOT_OBSERVED")
			}
			sort.Slice(out.Groups, func(i, j int) bool { return out.Groups[i].Name < out.Groups[j].Name })
			out.Raw = append([]byte{}, raw.Bytes()...)
			sum := sha256.Sum256(out.Raw)
			out.RawSHA256 = hex.EncodeToString(sum[:])
			out.CollectedAt = time.Now().UTC()
			return out, nil
		}
		if tokens[response.Result.Next] {
			return out, errors.New("FLEET_INVENTORY_PAGINATION_CONFLICT")
		}
		tokens[response.Result.Next] = true
		values.Set("NextToken", response.Result.Next)
	}
	return out, errors.New("FLEET_INVENTORY_PAGINATION_LIMIT")
}
