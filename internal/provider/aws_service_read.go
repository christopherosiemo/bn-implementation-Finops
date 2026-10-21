package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/awsservice"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/lambdacost"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
)

type serviceRead struct {
	a            *AWS
	s            awsservice.Scope
	frames       []awsservice.Frame
	bound        map[string]bool
	role         string
	reads, bytes int
}

// Only metadata actions are routed by this reader. The customer IAM policy is
// independently read-only; neither arbitrary provider methods nor URLs enter it.
var serviceActions = map[string]string{
	"ListClusters": "ecs", "DescribeClusters": "ecs", "ListServices": "ecs", "DescribeServices": "ecs", "ListTasks": "ecs", "DescribeTasks": "ecs", "ListTaskDefinitions": "ecs", "DescribeTaskDefinition": "ecs", "ListContainerInstances": "ecs", "DescribeContainerInstances": "ecs", "DescribeCapacityProviders": "ecs", "ListTagsForResource": "ecs",
	"DescribeScalableTargets": "application-autoscaling", "DescribeScalingPolicies": "application-autoscaling", "DescribeScheduledActions": "application-autoscaling",
	"ListTables": "dynamodb", "DescribeTable": "dynamodb", "DescribeContinuousBackups": "dynamodb", "DescribeTimeToLive": "dynamodb", "ListBackups": "dynamodb", "DescribeTableReplicaAutoScaling": "dynamodb", "ListTagsOfResource": "dynamodb",
}

func newServiceRead(a *AWS, s awsservice.Scope) (*serviceRead, error) {
	if a == nil || a.cfg.Credentials == nil || a.cfg.Region != s.Region || awsservice.ValidateScope(s) != nil {
		return nil, awsservice.ErrEvidence
	}
	return &serviceRead{a: a, s: s, bound: map[string]bool{}, frames: []awsservice.Frame{}}, nil
}
func (r *serviceRead) retain(service, action, selector string, status int, body any) error {
	b, e := json.Marshal(body)
	if e != nil || len(b) > awsservice.MaxPageBytes || len(selector) > 64<<10 || r.bytes+len(b)+len(selector) > awsservice.MaxCaptureBytes {
		return awsservice.ErrEvidence
	}
	r.bytes += len(b) + len(selector)
	r.frames = append(r.frames, awsservice.Frame{Service: service, Action: action, Selector: selector, StatusCode: status, SanitizerVersion: "AWS_SERVICE_SECRET_MINIMIZATION_V1", Body: body})
	return nil
}
func (r *serviceRead) send(ctx context.Context, c aws.Credentials, service, method, path, body, target string) ([]byte, error) {
	if !awsservice.Contains([]string{"sts", "ecs", "eks", "elasticache", "dynamodb", "elasticloadbalancing", "application-autoscaling", "monitoring"}, service) || !strings.HasPrefix(path, "/") || strings.ContainsAny(path, "\r\n") {
		return nil, awsservice.ErrEvidence
	}
	client := r.a.client
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	safe := *client
	safe.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	for attempt := 0; attempt < 3; attempt++ {
		if ctx.Err() != nil || r.reads >= awsservice.MaxReads {
			return nil, awsservice.ErrEvidence
		}
		r.reads++
		req, e := http.NewRequestWithContext(ctx, method, "https://"+service+"."+r.s.Region+".amazonaws.com"+path, strings.NewReader(body))
		if e != nil {
			return nil, awsservice.ErrEvidence
		}
		req.Header.Set("Accept-Encoding", "identity")
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if target != "" {
			req.Header.Set("Content-Type", "application/x-amz-json-1.1")
			req.Header.Set("X-Amz-Target", target)
		}
		if service == "eks" {
			req.Header.Set("Content-Type", "application/json")
		}
		if service == "dynamodb" {
			req.Header.Set("Content-Type", "application/x-amz-json-1.0")
		}
		if v4.NewSigner().SignHTTP(ctx, c, req, awsservice.BytesHash([]byte(body)), service, r.s.Region, time.Now().UTC()) != nil {
			return nil, awsservice.ErrEvidence
		}
		res, e := safe.Do(req)
		if e != nil {
			return nil, awsservice.ErrEvidence
		}
		raw, e := io.ReadAll(io.LimitReader(res.Body, awsservice.MaxPageBytes+1))
		res.Body.Close()
		if e != nil || len(raw) > awsservice.MaxPageBytes || res.Header.Get("Content-Encoding") != "" && res.Header.Get("Content-Encoding") != "identity" {
			return nil, awsservice.ErrEvidence
		}
		if res.StatusCode == 200 {
			return raw, nil
		}
		code := res.Header.Get("x-amzn-ErrorType")
		var d model.Document
		if json.Unmarshal(raw, &d) == nil && code == "" {
			code = model.String(d, "__type")
		}
		var failure struct {
			Error struct {
				Code string `xml:"Code"`
			} `xml:"Error"`
		}
		if code == "" {
			_ = xml.Unmarshal(raw, &failure)
			code = failure.Error.Code
		}
		if at := strings.LastIndexAny(code, "#:"); at >= 0 {
			code = code[at+1:]
		}
		code = awsErrorCode(code)
		if attempt < 2 && (res.StatusCode == 429 || code == "Throttling" || code == "ThrottlingException" || code == "TooManyRequestsException" || code == "RequestLimitExceeded") {
			timer := time.NewTimer(time.Duration(attempt+1) * 100 * time.Millisecond)
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil, awsservice.ErrEvidence
			case <-timer.C:
			}
			continue
		}
		return nil, &QueryRejection{Action: path, Code: code, StatusCode: res.StatusCode}
	}
	return nil, awsservice.ErrEvidence
}
func (r *serviceRead) identity(ctx context.Context, c aws.Credentials) error {
	key := awsservice.BytesHash([]byte(c.AccessKeyID + "\x00" + c.SecretAccessKey + "\x00" + c.SessionToken))
	if r.bound[key] {
		return nil
	}
	raw, e := r.send(ctx, c, "sts", "POST", "/", "Action=GetCallerIdentity&Version=2011-06-15", "")
	if e != nil {
		return e
	}
	var x struct {
		Result struct{ Account, Arn, UserId string } `xml:"GetCallerIdentityResult"`
	}
	if rdsXML(raw, "GetCallerIdentityResponse", "GetCallerIdentityResult", "", &x) != nil || x.Result.Account != r.s.AccountID || !strings.HasPrefix(x.Result.Arn, "arn:aws:sts::"+r.s.AccountID+":assumed-role/") || x.Result.UserId == "" {
		return awsservice.ErrEvidence
	}
	at := strings.LastIndexByte(x.Result.Arn, '/')
	if at <= len("arn:aws:sts::"+r.s.AccountID+":assumed-role/") || at == len(x.Result.Arn)-1 || len(x.Result.Arn) > 2048 {
		return awsservice.ErrEvidence
	}
	role := x.Result.Arn[:at]
	if r.role != "" && role != r.role {
		return awsservice.ErrEvidence
	}
	r.role = role
	r.bound[key] = true
	return r.retain("sts", "GetCallerIdentity", "", 200, model.Document{"account_id": x.Result.Account, "arn": x.Result.Arn})
}
func (r *serviceRead) credentials(ctx context.Context) (aws.Credentials, error) {
	c, e := r.a.cfg.Credentials.Retrieve(ctx)
	if e != nil || c.AccessKeyID == "" || c.SecretAccessKey == "" {
		return c, awsservice.ErrEvidence
	}
	return c, r.identity(ctx, c)
}
func serviceSanitize(v any) any {
	switch d := v.(type) {
	case map[string]any:
		return serviceSanitizeMap(d)
	case model.Document:
		return serviceSanitizeMap(d)
	case []any:
		out := make([]any, len(d))
		for i, v := range d {
			out[i] = serviceSanitize(v)
		}
		return out
	default:
		return v
	}
}
func serviceSanitizeMap(d map[string]any) model.Document {
	out := model.Document{}
	for k, v := range d {
		switch strings.ToLower(k) {
		case "environment", "environmentfiles", "secrets", "secretoptions", "registrycredentials", "repositorycredentials", "credentialsspecs", "credentialspecs":
			count := 0
			if xs, ok := v.([]any); ok {
				count = len(xs)
			}
			out[k+"Metadata"] = model.Document{"present": v != nil, "entry_count": count, "values_redacted": true}
		case "command", "entrypoint", "options", "configurationvalues", "clientsecret", "password", "authtoken", "token", "secretaccesskey", "accesskeyid", "userdata", "description", "message", "reason", "statereason", "stoppedreason", "reasonphrase", "parametervalue":
			out[k+"Metadata"] = model.Document{"present": v != nil, "values_redacted": true}
		default:
			out[k] = serviceSanitize(v)
		}
	}
	return out
}
func (r *serviceRead) json(ctx context.Context, service, action, path string, p model.Document) (model.Document, error) {
	if service != "eks" && serviceActions[action] != service {
		return nil, awsservice.ErrEvidence
	}
	target := ""
	method := "POST"
	switch service {
	case "ecs":
		target = "AmazonEC2ContainerServiceV20141113." + action
	case "dynamodb":
		target = "DynamoDB_20120810." + action
	case "application-autoscaling":
		target = "AnyScaleFrontendService." + action
	case "eks":
		if !awsservice.Contains([]string{"ListClusters", "DescribeCluster", "ListNodegroups", "DescribeNodegroup", "ListFargateProfiles", "DescribeFargateProfile", "ListAddons", "DescribeAddon", "ListTagsForResource"}, action) {
			return nil, awsservice.ErrEvidence
		}
		method = "GET"
	default:
		return nil, awsservice.ErrEvidence
	}
	b, _ := json.Marshal(p)
	if method == "GET" {
		b = nil
	}
	c, e := r.credentials(ctx)
	if e != nil {
		return nil, e
	}
	raw, e := r.send(ctx, c, service, method, path, string(b), target)
	if e != nil {
		return nil, e
	}
	var doc map[string]any
	if lambdacost.DecodeJSON(raw, &doc) != nil {
		return nil, awsservice.ErrEvidence
	}
	if key := serviceIdentifierKey(service, action); key != "" {
		values, ok := doc[key].([]any)
		if !ok || len(values) > awsservice.MaxRows {
			return nil, awsservice.ErrEvidence
		}
		for _, v := range values {
			value, ok := v.(string)
			if !ok || value == "" || len(value) > 2048 {
				return nil, awsservice.ErrEvidence
			}
		}
	}
	san := serviceSanitize(doc)
	if e = r.retain(service, action, path+" "+string(b), 200, san); e != nil {
		return nil, e
	}
	return awsservice.Document(san), nil
}

// XML metadata is converted before retention; secret-bearing/free-form fields
// never enter the immutable archive, including error response messages.
func serviceXML(raw []byte, action string) (model.Document, error) {
	d := xml.NewDecoder(bytes.NewReader(raw))
	stack := []*rdsNode{}
	var root *rdsNode
	for {
		tok, e := d.Token()
		if e == io.EOF {
			break
		}
		if e != nil {
			return nil, awsservice.ErrEvidence
		}
		switch t := tok.(type) {
		case xml.StartElement:
			n := &rdsNode{name: t.Name.Local}
			if len(stack) == 0 {
				if root != nil || n.name != action+"Response" {
					return nil, awsservice.ErrEvidence
				}
				root = n
			} else {
				parent := stack[len(stack)-1]
				if parent.get(n.name) != nil && !awsservice.Contains([]string{"member", "CacheCluster", "ReplicationGroup", "ServerlessCache", "Tag", "Snapshot", "CacheNode", "Parameter", "CacheSubnetGroup", "CacheParameterGroup", "ServerlessCacheSnapshot", "LoadBalancerDescription", "InstanceState", "ListenerDescription", "NodeGroup", "NodeGroupMember", "CacheSecurityGroup", "SecurityGroupMembership"}, n.name) {
					return nil, awsservice.ErrEvidence
				}
				parent.children = append(parent.children, n)
			}
			stack = append(stack, n)
			if len(stack) > 64 {
				return nil, awsservice.ErrEvidence
			}
		case xml.EndElement:
			if len(stack) == 0 {
				return nil, awsservice.ErrEvidence
			}
			stack = stack[:len(stack)-1]
		case xml.CharData:
			if len(stack) > 0 {
				stack[len(stack)-1].text += string(t)
			} else if strings.TrimSpace(string(t)) != "" {
				return nil, awsservice.ErrEvidence
			}
		case xml.Directive:
			return nil, awsservice.ErrEvidence
		}
	}
	if root == nil {
		return nil, awsservice.ErrEvidence
	}
	var result *rdsNode
	for _, n := range root.children {
		if n.name == action+"Result" {
			if result != nil {
				return nil, awsservice.ErrEvidence
			}
			result = n
		}
	}
	if result == nil {
		return nil, awsservice.ErrEvidence
	}
	return awsservice.Document(serviceSanitize(serviceXMLValue(result))), nil
}
func serviceXMLValue(n *rdsNode) any {
	if len(n.children) == 0 {
		return strings.TrimSpace(n.text)
	}
	d := model.Document{}
	for _, c := range n.children {
		v := serviceXMLValue(c)
		if old, ok := d[c.name]; ok {
			if a, ok := old.([]any); ok {
				d[c.name] = append(a, v)
			} else {
				d[c.name] = []any{old, v}
			}
		} else if awsservice.Contains([]string{"member", "CacheCluster", "ReplicationGroup", "ServerlessCache", "Tag", "Snapshot", "CacheNode", "Parameter", "CacheSubnetGroup", "CacheParameterGroup", "ServerlessCacheSnapshot", "LoadBalancerDescription", "InstanceState", "ListenerDescription", "NodeGroup", "NodeGroupMember", "CacheSecurityGroup", "SecurityGroupMembership"}, c.name) {
			d[c.name] = []any{v}
		} else {
			d[c.name] = v
		}
	}
	return d
}
func (r *serviceRead) query(ctx context.Context, service, action, version string, p url.Values) (model.Document, error) {
	allowed := map[string][]string{"monitoring": {"GetMetricStatistics"}, "elasticache": {"DescribeReplicationGroups", "DescribeCacheClusters", "DescribeServerlessCaches", "DescribeCacheSubnetGroups", "DescribeCacheParameterGroups", "DescribeCacheParameters", "DescribeSnapshots", "DescribeServerlessCacheSnapshots", "ListTagsForResource"}, "elasticloadbalancing": {"DescribeLoadBalancers", "DescribeListeners", "DescribeRules", "DescribeTargetGroups", "DescribeTargetHealth", "DescribeLoadBalancerAttributes", "DescribeTargetGroupAttributes", "DescribeTags", "DescribeInstanceHealth", "DescribeLoadBalancerPolicies"}}
	if !awsservice.Contains(allowed[service], action) {
		return nil, awsservice.ErrEvidence
	}
	p.Set("Action", action)
	p.Set("Version", version)
	c, e := r.credentials(ctx)
	if e != nil {
		return nil, e
	}
	raw, e := r.send(ctx, c, service, "POST", "/", p.Encode(), "")
	if e != nil {
		return nil, e
	}
	doc, e := serviceXML(raw, action)
	if e != nil {
		return nil, e
	}
	if e = r.retain(service, action, p.Encode(), 200, doc); e != nil {
		return nil, e
	}
	return doc, nil
}
func serviceList(v any) []model.Document {
	if x, ok := v.(string); ok && x == "" {
		return []model.Document{}
	}
	d := awsservice.Document(v)
	for _, key := range []string{"member", "CacheCluster", "ReplicationGroup", "ServerlessCache", "Tag", "Snapshot", "CacheNode", "Parameter", "CacheSubnetGroup", "CacheParameterGroup", "ServerlessCacheSnapshot", "LoadBalancerDescription", "InstanceState", "ListenerDescription", "NodeGroup", "NodeGroupMember", "CacheSecurityGroup", "SecurityGroupMembership"} {
		if x, ok := d[key]; ok {
			return serviceList(x)
		}
	}
	rows := awsservice.Rows(v)
	if rows != nil {
		return rows
	}
	if len(d) > 0 {
		return []model.Document{d}
	}
	return []model.Document{}
}
func serviceStrings(v any) []string {
	if d := awsservice.Document(v); len(d) > 0 {
		if x, ok := d["member"]; ok {
			return serviceStrings(x)
		}
	}
	raw, _ := json.Marshal(v)
	out := []string{}
	_ = json.Unmarshal(raw, &out)
	return out
}
func serviceIdentifierKey(service, action string) string {
	if service == "ecs" {
		return map[string]string{"ListClusters": "clusterArns", "ListServices": "serviceArns", "ListTasks": "taskArns", "ListTaskDefinitions": "taskDefinitionArns", "ListContainerInstances": "containerInstanceArns"}[action]
	}
	if service == "eks" {
		return map[string]string{"ListClusters": "clusters", "ListNodegroups": "nodegroups", "ListFargateProfiles": "fargateProfileNames", "ListAddons": "addons"}[action]
	}
	if service == "dynamodb" && action == "ListTables" {
		return "TableNames"
	}
	return ""
}
