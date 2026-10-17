package provider

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
)

type AWS struct {
	cfg    aws.Config
	client *http.Client
}

func NewAWS(ctx context.Context, region, role, external string) (*AWS, error) {
	c, e := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if e != nil {
		return nil, e
	}
	if role == "" {
		return nil, errors.New("explicit customer target role required")
	}
	p := stscreds.NewAssumeRoleProvider(sts.NewFromConfig(c), role, func(o *stscreds.AssumeRoleOptions) {
		o.RoleSessionName = "finops-pilot"
		if external != "" {
			o.ExternalID = aws.String(external)
		}
	})
	c.Credentials = aws.NewCredentialsCache(p)
	return &AWS{c, &http.Client{Timeout: 30 * time.Second}}, nil
}
func (a *AWS) query(ctx context.Context, region, action string, values url.Values, out any) error {
	if region == "" {
		region = a.cfg.Region
	}
	if !validRegion(region) {
		return errors.New("invalid AWS region")
	}
	values.Set("Action", action)
	values.Set("Version", "2016-11-15")
	body := values.Encode()
	u := "https://ec2." + region + ".amazonaws.com/"
	req, e := http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader(body))
	if e != nil {
		return e
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	creds, e := a.cfg.Credentials.Retrieve(ctx)
	if e != nil {
		return e
	}
	sum := sha256.Sum256([]byte(body))
	if e = v4.NewSigner().SignHTTP(ctx, creds, req, hex.EncodeToString(sum[:]), "ec2", region, time.Now()); e != nil {
		return e
	}
	res, e := a.client.Do(req)
	if e != nil {
		return e
	}
	defer res.Body.Close()
	b, e := io.ReadAll(io.LimitReader(res.Body, 16<<20))
	if e != nil {
		return e
	}
	if res.StatusCode/100 != 2 {
		var failure struct {
			Errors []struct {
				Code string `xml:"Code"`
			} `xml:"Errors>Error"`
		}
		_ = xml.Unmarshal(b, &failure)
		code := "ProviderError"
		if len(failure.Errors) > 0 {
			code = failure.Errors[0].Code
		}
		return fmt.Errorf("AWS %s failed: %s (%d)", action, code, res.StatusCode)
	}
	if out != nil {
		return xml.Unmarshal(b, out)
	}
	return nil
}
func validRegion(s string) bool {
	if len(s) < 7 || len(s) > 32 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

type instance struct {
	ID        string `xml:"instanceId"`
	Type      string `xml:"instanceType"`
	Root      string `xml:"rootDeviceType"`
	Lifecycle string `xml:"instanceLifecycle"`
	State     struct {
		Name string `xml:"name"`
	} `xml:"instanceState"`
	Placement struct {
		Zone string `xml:"availabilityZone"`
	} `xml:"placement"`
	Tags []struct {
		Key   string `xml:"key"`
		Value string `xml:"value"`
	} `xml:"tagSet>item"`
	Devices []struct {
		Virtual string `xml:"virtualName"`
	} `xml:"blockDeviceMapping>item"`
}

func (a *AWS) Inventory(ctx context.Context, region, account string) ([]model.Document, error) {
	out := []model.Document{}
	token := ""
	for pages := 0; pages < 1000; pages++ {
		v := url.Values{"MaxResults": {"1000"}}
		if token != "" {
			v.Set("NextToken", token)
		}
		var r struct {
			Reservations []struct {
				Instances []instance `xml:"instancesSet>item"`
			} `xml:"reservationSet>item"`
			Next string `xml:"nextToken"`
		}
		if e := a.query(ctx, region, "DescribeInstances", v, &r); e != nil {
			return nil, e
		}
		for _, res := range r.Reservations {
			for _, i := range res.Instances {
				if i.State.Name == "terminated" {
					continue
				}
				tags := map[string]string{}
				managed := false
				ephemeral := false
				for _, t := range i.Tags {
					tags[t.Key] = t.Value
					if strings.Contains(t.Key, "autoscaling") || strings.Contains(t.Key, "eks") || strings.Contains(t.Key, "kubernetes") || strings.Contains(t.Key, "ecs") {
						managed = true
					}
				}
				for _, d := range i.Devices {
					if strings.HasPrefix(d.Virtual, "ephemeral") {
						ephemeral = true
					}
				}
				name := tags["Name"]
				if name == "" {
					name = i.ID
				}
				out = append(out, model.Document{"name": name, "provider": "AWS", "resource_type": "EC2", "provider_resource_id": i.ID, "account_id": account, "region": region, "zone": i.Placement.Zone, "instance_type": i.Type, "state": i.State.Name, "root_device_type": i.Root, "instance_store": ephemeral, "fleet_managed": managed || tags["finops:standalone"] != "true", "spot": i.Lifecycle == "spot", "runtime_stop_start_delegated": tags["finops:runtime-stop-start"] == "true", "configuration_authority": "UNKNOWN", "commitment_known": false, "uncovered_on_demand": false, "stable_network": tags["finops:stable-network"] == "true", "observation_days": 0, "environment": tags["finops:environment"], "owner": tags["finops:owner"], "tags": tags, "last_seen_at": model.Now(), "hourly_effective_cost": "0.000000000000", "monthly_effective_cost": "0.000000000000", "currency": "USD", "eligibility": "BLOCKED", "blockers": []string{"BLOCKED_INCOMPLETE_BILLING_OR_WORKLOAD_EVIDENCE"}})
			}
		}
		token = r.Next
		if token == "" {
			return out, nil
		}
	}
	return nil, errors.New("inventory pagination limit exceeded")
}
func (a *AWS) Describe(ctx context.Context, op model.Operation) (model.ProviderState, error) {
	var r struct {
		Reservations []struct {
			Instances []instance `xml:"instancesSet>item"`
		} `xml:"reservationSet>item"`
	}
	if e := a.query(ctx, op.Region, "DescribeInstances", url.Values{"InstanceId.1": {op.ProviderResourceID}}, &r); e != nil {
		return model.ProviderState{}, e
	}
	if len(r.Reservations) != 1 || len(r.Reservations[0].Instances) != 1 {
		return model.ProviderState{}, errors.New("exact instance not found")
	}
	s := r.Reservations[0].Instances[0].State.Name
	healthy := false
	if s == "running" {
		var checks struct {
			Items []struct {
				System struct {
					Status string `xml:"status"`
				} `xml:"systemStatus"`
				Instance struct {
					Status string `xml:"status"`
				} `xml:"instanceStatus"`
			} `xml:"instanceStatusSet>item"`
		}
		if e := a.query(ctx, op.Region, "DescribeInstanceStatus", url.Values{"InstanceId.1": {op.ProviderResourceID}, "IncludeAllInstances": {"true"}}, &checks); e != nil {
			return model.ProviderState{}, e
		}
		healthy = len(checks.Items) == 1 && checks.Items[0].System.Status == "ok" && checks.Items[0].Instance.Status == "ok"
	}
	return model.ProviderState{State: s, Healthy: healthy}, nil
}

// Preflight refreshes the mutation-sensitive facts from EC2 immediately before
// STOP. Explicit standalone attestation is required in addition to fleet-tag
// exclusion; unknown ownership never becomes eligibility by absence of a tag.
func (a *AWS) Preflight(ctx context.Context, op model.Operation, expected model.Document) error {
	var r struct {
		Reservations []struct {
			Instances []instance `xml:"instancesSet>item"`
		} `xml:"reservationSet>item"`
	}
	if e := a.query(ctx, op.Region, "DescribeInstances", url.Values{"InstanceId.1": {op.ProviderResourceID}}, &r); e != nil {
		return e
	}
	if len(r.Reservations) != 1 || len(r.Reservations[0].Instances) != 1 {
		return errors.New("instance identity uncertain")
	}
	i := r.Reservations[0].Instances[0]
	if i.ID != op.ProviderResourceID || i.Type != model.String(expected, "instance_type") || i.Root != "ebs" || i.Lifecycle == "spot" {
		return errors.New("instance configuration differs from approved safety envelope")
	}
	tags := map[string]string{}
	for _, tag := range i.Tags {
		tags[tag.Key] = tag.Value
		if strings.Contains(tag.Key, "autoscaling") || strings.Contains(tag.Key, "eks") || strings.Contains(tag.Key, "kubernetes") || strings.Contains(tag.Key, "ecs") {
			return errors.New("managed fleet membership detected")
		}
	}
	if tags["finops:environment"] != "NON_PRODUCTION" || tags["finops:runtime-stop-start"] != "true" || tags["finops:standalone"] != "true" || tags["finops:stable-network"] != "true" {
		return errors.New("live non-production, standalone, network or runtime delegation tags missing")
	}
	var types struct {
		Items []struct {
			Type  string `xml:"instanceType"`
			Store bool   `xml:"instanceStorageSupported"`
		} `xml:"instanceTypeSet>item"`
	}
	if e := a.query(ctx, op.Region, "DescribeInstanceTypes", url.Values{"InstanceType.1": {i.Type}}, &types); e != nil {
		return e
	}
	if len(types.Items) != 1 || types.Items[0].Type != i.Type || types.Items[0].Store {
		return errors.New("instance-store hardware is excluded")
	}
	return nil
}
func (a *AWS) Stop(ctx context.Context, op model.Operation) error {
	var r struct {
		Value bool `xml:"disableApiStop>value"`
	}
	if e := a.query(ctx, op.Region, "DescribeInstanceAttribute", url.Values{"InstanceId": {op.ProviderResourceID}, "Attribute": {"disableApiStop"}}, &r); e != nil {
		return e
	}
	if r.Value {
		return errors.New("stop protection enabled")
	}
	return a.query(ctx, op.Region, "StopInstances", url.Values{"InstanceId.1": {op.ProviderResourceID}, "Force": {"false"}, "Hibernate": {"false"}}, nil)
}
func (a *AWS) Start(ctx context.Context, op model.Operation) error {
	return a.query(ctx, op.Region, "StartInstances", url.Values{"InstanceId.1": {op.ProviderResourceID}}, nil)
}
