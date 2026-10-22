package provider

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"encoding/xml"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/network"
)

const networkPageLimit = 4 << 20
const networkRawLimit = 64 << 20
const networkReadLimit = 2048

type networkRead struct {
	a      *AWS
	scope  network.Scope
	frames []network.RawFrame
	bytes  int
	reads  int
	bound  map[[32]byte]bool
	role   string
}

func newNetworkRead(a *AWS, s network.Scope) (*networkRead, error) {
	if a == nil || a.cfg.Credentials == nil || network.ValidateScope(s) != nil {
		return nil, network.ErrEvidence
	}
	return &networkRead{a: a, scope: s, frames: []network.RawFrame{}, bound: map[[32]byte]bool{}}, nil
}
func (r *networkRead) raw() []byte {
	b, _ := json.Marshal(model.Document{"schema_version": "NETWORK_NATIVE_V1", "scope": r.scope, "frames": r.frames})
	return b
}
func (r *networkRead) retain(service, action, selector string, status int, body []byte) error {
	if len(body) > networkPageLimit || len(selector) > 64<<10 || r.bytes+len(body)+len(selector) > networkRawLimit {
		return network.ErrEvidence
	}
	r.bytes += len(body) + len(selector)
	r.frames = append(r.frames, network.RawFrame{Service: service, Action: action, Region: r.scope.Region, Selector: selector, StatusCode: status, Body: append([]byte{}, body...)})
	return nil
}
func (r *networkRead) signed(ctx context.Context, c aws.Credentials, service, action, body string) ([]byte, error) {
	h := r.a.client
	if h == nil {
		h = &http.Client{Timeout: 30 * time.Second}
	}
	safe := *h
	safe.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	for attempt := 0; attempt < 3; attempt++ {
		if ctx.Err() != nil || r.reads >= networkReadLimit {
			return nil, network.ErrEvidence
		}
		r.reads++
		req, e := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+service+"."+r.scope.Region+".amazonaws.com/", strings.NewReader(body))
		if e != nil {
			return nil, network.ErrEvidence
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Accept-Encoding", "identity")
		if v4.NewSigner().SignHTTP(ctx, c, req, network.BytesHash([]byte(body)), service, r.scope.Region, time.Now().UTC()) != nil {
			return nil, network.ErrEvidence
		}
		res, e := safe.Do(req)
		if e != nil {
			return nil, network.ErrEvidence
		}
		if enc := res.Header.Get("Content-Encoding"); enc != "" && enc != "identity" {
			res.Body.Close()
			return nil, network.ErrEvidence
		}
		raw, e := io.ReadAll(io.LimitReader(res.Body, networkPageLimit+1))
		res.Body.Close()
		if e != nil || len(raw) > networkPageLimit {
			return nil, network.ErrEvidence
		}
		if e = r.retain(service, action, body, res.StatusCode, raw); e != nil {
			return nil, e
		}
		if res.StatusCode == 200 {
			return raw, nil
		}
		var rejected struct {
			Errors []struct {
				Code string `xml:"Code"`
			} `xml:"Errors>Error"`
			Error struct {
				Code string `xml:"Code"`
			} `xml:"Error"`
		}
		_ = xml.Unmarshal(raw, &rejected)
		code := rejected.Error.Code
		if len(rejected.Errors) == 1 {
			code = rejected.Errors[0].Code
		}
		code = awsErrorCode(code)
		if attempt < 2 && (res.StatusCode == 429 || code == "Throttling" || code == "ThrottlingException" || code == "RequestLimitExceeded") {
			timer := time.NewTimer(time.Duration(attempt+1) * 100 * time.Millisecond)
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil, network.ErrEvidence
			case <-timer.C:
			}
			continue
		}
		return nil, &QueryRejection{Action: action, Code: code, StatusCode: res.StatusCode}
	}
	return nil, network.ErrEvidence
}
func (r *networkRead) identity(ctx context.Context, c aws.Credentials) error {
	key := sha256.Sum256([]byte(c.AccessKeyID + "\x00" + c.SecretAccessKey + "\x00" + c.SessionToken))
	if r.bound[key] {
		return nil
	}
	v := url.Values{"Action": {"GetCallerIdentity"}, "Version": {"2011-06-15"}}
	raw, e := r.signed(ctx, c, "sts", "GetCallerIdentity", v.Encode())
	if e != nil {
		return e
	}
	n, e := ebsTree(raw, "GetCallerIdentity")
	if e != nil {
		return network.ErrEvidence
	}
	n = n.get("GetCallerIdentityResult")
	if n == nil {
		return network.ErrEvidence
	}
	arn := n.value("Arn")
	prefix := "arn:aws:sts::" + r.scope.AccountID + ":assumed-role/"
	at := strings.LastIndexByte(arn, '/')
	if n.value("Account") != r.scope.AccountID || !strings.HasPrefix(arn, prefix) || at <= len(prefix) || at == len(arn)-1 || n.value("UserId") == "" {
		return network.ErrEvidence
	}
	role := arn[:at]
	if r.role != "" && r.role != role {
		return network.ErrEvidence
	}
	r.role = role
	r.bound[key] = true
	return nil
}

var networkActions = map[string]string{
	"DescribeVpcs": "ec2", "DescribeSubnets": "ec2", "DescribeAvailabilityZones": "ec2", "DescribeRouteTables": "ec2", "DescribeNatGateways": "ec2", "DescribeAddresses": "ec2", "DescribeInternetGateways": "ec2", "DescribeEgressOnlyInternetGateways": "ec2", "DescribeNetworkInterfaces": "ec2", "DescribeSecurityGroups": "ec2", "DescribeVpcEndpoints": "ec2", "DescribeVpcEndpointServices": "ec2", "DescribeVpcPeeringConnections": "ec2", "DescribeTransitGatewayAttachments": "ec2", "DescribeFlowLogs": "ec2", "DescribeLoadBalancers": "elasticloadbalancing", "GetMetricStatistics": "monitoring",
	"DescribePrefixLists": "ec2",
}

func (r *networkRead) query(ctx context.Context, action string, v url.Values) ([]byte, error) {
	service := networkActions[action]
	if service == "" {
		return nil, network.ErrEvidence
	}
	version := "2016-11-15"
	if service == "monitoring" {
		version = "2010-08-01"
	}
	if service == "elasticloadbalancing" {
		version = "2015-12-01"
	}
	v.Set("Action", action)
	v.Set("Version", version)
	c, e := r.a.cfg.Credentials.Retrieve(ctx)
	if e != nil || c.AccessKeyID == "" || c.SecretAccessKey == "" {
		return nil, network.ErrEvidence
	}
	if e = r.identity(ctx, c); e != nil {
		return nil, e
	}
	return r.signed(ctx, c, service, action, v.Encode())
}

// NetworkCaptureFrames rejects unbound/malformed captures and retains the exact
// successful and denied native read pages. It is evidence, never an authority.
func NetworkCaptureFrames(raw []byte) (network.Scope, []network.RawFrame, error) {
	var d struct {
		SchemaVersion string             `json:"schema_version"`
		Scope         network.Scope      `json:"scope"`
		Frames        []network.RawFrame `json:"frames"`
	}
	if len(raw) > networkRawLimit*2 {
		return d.Scope, nil, network.ErrEvidence
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(&d) != nil || dec.Decode(new(any)) != io.EOF || d.SchemaVersion != "NETWORK_NATIVE_V1" || network.ValidateScope(d.Scope) != nil || len(d.Frames) > networkReadLimit {
		return d.Scope, nil, network.ErrEvidence
	}
	for _, f := range d.Frames {
		if len(f.Body) > networkPageLimit || f.Region != d.Scope.Region || f.Action != "GetCallerIdentity" && networkActions[f.Action] != f.Service {
			return d.Scope, nil, network.ErrEvidence
		}
	}
	return d.Scope, d.Frames, nil
}
