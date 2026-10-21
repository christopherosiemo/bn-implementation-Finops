package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

// This request is private coordinator input, never the public registration.
// ExternalIDConfigured means the approved private value was passed to NewAWS;
// successful assumption cannot prove that an administrator requires that value.
type AWSAccountProbeRequest struct {
	TenantID, AccountID, Region, ExpectedRoleARN string
	ExternalIDConfigured                         bool
}

type AWSAccountProbeResult struct {
	SchemaVersion    string                  `json:"schema_version"`
	ObservedAt       time.Time               `json:"observed_at"`
	ObservationBasis string                  `json:"observation_basis"`
	Fixture          bool                    `json:"fixture"`
	Identity         AWSAccountProbeIdentity `json:"identity"`
	Classes          []AWSAccountProbeClass  `json:"classes"`
}

type AWSAccountProbeIdentity struct {
	Status            string `json:"status"`
	ReasonCode        string `json:"reason_code"`
	ExpectedAccountID string `json:"expected_account_id"`
	ActualAccountID   string `json:"actual_account_id"`
	ConfiguredRoleARN string `json:"configured_role_arn"`
	CallerRoleARN     string `json:"caller_role_arn"`
	ExternalIDBound   bool   `json:"external_id_bound"`
}

type AWSAccountProbeOperation struct {
	Name              string `json:"name"`
	APIVersion        string `json:"api_version,omitempty"`
	Status            string `json:"status"`
	ReasonCode        string `json:"reason_code"`
	ProviderErrorCode string `json:"provider_error_code,omitempty"`
}

type AWSAccountProbeClass struct {
	Category          string                     `json:"category"`
	Status            string                     `json:"status"`
	ReasonCode        string                     `json:"reason_code"`
	ProviderErrorCode string                     `json:"provider_error_code,omitempty"`
	Operations        []AWSAccountProbeOperation `json:"operations"`
	InventoryComplete bool                       `json:"inventory_complete"`
	Limitations       []string                   `json:"limitations"`
}

var accountProbeRole = regexp.MustCompile(`^arn:aws:iam::([0-9]{12}):role/([A-Za-z0-9+=,.@_/-]+)$`)
var accountProbeAccount = regexp.MustCompile(`^[0-9]{12}$`)

var accountProbeCategories = []string{"EC2_ASG", "EBS", "RDS_AURORA", "ECS_FARGATE", "EKS", "LAMBDA", "S3", "ELASTICACHE", "DYNAMODB", "NETWORK_NAT", "PUBLIC_IPV4", "ELB", "COMMITMENTS"}

func accountProbeResult(req AWSAccountProbeRequest) AWSAccountProbeResult {
	identity := AWSAccountProbeIdentity{Status: "NOT_CONFIGURED", ReasonCode: "AWS_APPROVED_READ_BINDING_REQUIRED"}
	if accountProbeAccount.MatchString(req.AccountID) {
		identity.ExpectedAccountID = req.AccountID
	}
	if accountProbeRole.MatchString(req.ExpectedRoleARN) && len(req.ExpectedRoleARN) <= 2048 {
		identity.ConfiguredRoleARN = req.ExpectedRoleARN
	}
	out := AWSAccountProbeResult{SchemaVersion: "1", ObservedAt: time.Now().UTC(), ObservationBasis: "BOUNDED_NATIVE_READ_ACCESS_PROBE", Identity: identity, Classes: []AWSAccountProbeClass{}}
	for _, category := range accountProbeCategories {
		limitations := []string{"ACCESS_PROBE_ONLY_NOT_COMPLETE_INVENTORY", "NO_TELEMETRY_OR_RECOMMENDATION_AUTHORITY"}
		if category == "S3" {
			limitations = append(limitations, "GENERAL_PURPOSE_BUCKETS_ONLY_NO_OBJECT_READS")
		}
		if category == "COMMITMENTS" {
			limitations = append(limitations, "NO_PAYER_MEMBER_OR_PORTFOLIO_CLOSURE")
		}
		out.Classes = append(out.Classes, AWSAccountProbeClass{Category: category, Status: "NOT_CONFIGURED", ReasonCode: "AWS_IDENTITY_PREFLIGHT_REQUIRED", Operations: []AWSAccountProbeOperation{}, Limitations: limitations})
	}
	return out
}

func accountProbeRequestValid(req AWSAccountProbeRequest) bool {
	match := accountProbeRole.FindStringSubmatch(req.ExpectedRoleARN)
	return rdsPart.MatchString(req.TenantID) && accountProbeAccount.MatchString(req.AccountID) && validRegion(req.Region) && !strings.HasPrefix(req.Region, "cn-") && !strings.HasPrefix(req.Region, "us-gov-") && len(req.ExpectedRoleARN) <= 2048 && len(match) == 3 && match[1] == req.AccountID && !strings.HasSuffix(match[2], "/")
}

// AccountReadPreflight checks bounded metadata read availability, not inventory
// completeness. Empty successful pages prove access and never mean ABSENT.
// Only safe typed results escape this adapter; bodies and provider messages do not.
func (a *AWS) AccountReadPreflight(ctx context.Context, req AWSAccountProbeRequest) (AWSAccountProbeResult, error) {
	out := accountProbeResult(req)
	if !accountProbeRequestValid(req) || a == nil || a.cfg.Credentials == nil || a.cfg.Region != req.Region {
		out.Identity.Status, out.Identity.ReasonCode = "ERROR", "AWS_ACCOUNT_OR_REGION_BINDING_INVALID"
		return out, nil
	}
	if !req.ExternalIDConfigured {
		out.Identity.ReasonCode = "AWS_EXTERNAL_ID_BINDING_REQUIRED"
		return out, nil
	}
	creds, err := a.cfg.Credentials.Retrieve(ctx)
	if err != nil || creds.AccessKeyID == "" || creds.SecretAccessKey == "" || creds.SessionToken == "" || creds.CanExpire && !creds.Expires.After(time.Now().UTC()) {
		out.Identity.Status, out.Identity.ReasonCode = "ERROR", "AWS_READ_ROLE_ASSUMPTION_UNAVAILABLE"
		var coded interface{ ErrorCode() string }
		if errors.As(err, &coded) {
			op := accountProbeFailure("AssumeRole", &QueryRejection{Code: awsErrorCode(coded.ErrorCode())})
			if op.Status == "DENIED" {
				out.Identity.Status, out.Identity.ReasonCode = "DENIED", "AWS_READ_ROLE_ASSUMPTION_DENIED"
			}
		}
		return out, nil
	}
	reader := accountProbeReader{a: a, region: req.Region, creds: creds}
	identitySpec := accountReadProbe{name: "GetCallerIdentity", service: "sts", version: "2011-06-15", collection: "GetCallerIdentityResult"}
	raw, _, err := reader.read(ctx, identitySpec)
	if err != nil {
		op := accountProbeFailure("GetCallerIdentity", err)
		out.Identity.Status, out.Identity.ReasonCode = op.Status, "AWS_CALLER_IDENTITY_UNAVAILABLE"
		return out, nil
	}
	var identity struct {
		XMLName xml.Name
		Result  struct{ Account, Arn, UserId string } `xml:"GetCallerIdentityResult"`
	}
	if xml.Unmarshal(raw, &identity) != nil || identity.XMLName.Local != "GetCallerIdentityResponse" || !accountProbeAccount.MatchString(identity.Result.Account) || identity.Result.UserId == "" {
		out.Identity.Status, out.Identity.ReasonCode = "ERROR", "AWS_CALLER_IDENTITY_INVALID"
		return out, nil
	}
	out.Identity.ActualAccountID = identity.Result.Account
	role := req.ExpectedRoleARN[strings.LastIndexByte(req.ExpectedRoleARN, '/')+1:]
	prefix := "arn:aws:sts::" + req.AccountID + ":assumed-role/" + role + "/"
	if identity.Result.Account != req.AccountID || !strings.HasPrefix(identity.Result.Arn, prefix) || len(identity.Result.Arn) > 2048 || strings.TrimPrefix(identity.Result.Arn, prefix) == "" || strings.ContainsAny(strings.TrimPrefix(identity.Result.Arn, prefix), "/\r\n\t") {
		out.Identity.Status, out.Identity.ReasonCode = "ERROR", "AWS_CALLER_ACCOUNT_OR_ROLE_MISMATCH"
		return out, nil
	}
	out.Identity.Status, out.Identity.ReasonCode = "READY", "AWS_APPROVED_ASSUMED_READ_ROLE_OBSERVED"
	out.Identity.CallerRoleARN, out.Identity.ExternalIDBound = strings.TrimSuffix(prefix, "/"), true
	for i := range out.Classes {
		class := &out.Classes[i]
		for _, spec := range accountReadProbes(class.Category) {
			_, more, err := reader.read(ctx, spec)
			op := AWSAccountProbeOperation{Name: spec.name, APIVersion: spec.version, Status: "READY", ReasonCode: "AWS_BOUNDED_READ_ACCESS_OBSERVED"}
			if err != nil {
				op = accountProbeFailure(spec.name, err)
				op.APIVersion = spec.version
			} else if more {
				op.Status, op.ReasonCode = "PARTIAL", "AWS_READ_PROBE_PAGE_LIMIT_REACHED"
			}
			class.Operations = append(class.Operations, op)
		}
		accountProbeClassStatus(class)
	}
	return out, nil
}

// FixtureAWSAccountReadPreflight is explicit synthetic product data for local
// onboarding. It makes no assertion that customer AWS credentials were tested.
func FixtureAWSAccountReadPreflight(req AWSAccountProbeRequest) (AWSAccountProbeResult, error) {
	out := accountProbeResult(req)
	out.Fixture, out.ObservationBasis = true, "PROVIDER_SHAPED_SYNTHETIC_ACCESS_PROBE"
	if !accountProbeRequestValid(req) || !req.ExternalIDConfigured {
		return out, nil
	}
	out.Identity = AWSAccountProbeIdentity{Status: "READY", ReasonCode: "SYNTHETIC_APPROVED_READ_ROLE_EXAMPLE", ExpectedAccountID: req.AccountID, ActualAccountID: req.AccountID, ConfiguredRoleARN: req.ExpectedRoleARN, CallerRoleARN: "arn:aws:sts::" + req.AccountID + ":assumed-role/" + req.ExpectedRoleARN[strings.LastIndexByte(req.ExpectedRoleARN, '/')+1:], ExternalIDBound: true}
	for i := range out.Classes {
		class := &out.Classes[i]
		for n, spec := range accountReadProbes(class.Category) {
			op := AWSAccountProbeOperation{Name: spec.name, APIVersion: spec.version, Status: "READY", ReasonCode: "SYNTHETIC_READ_ACCESS_EXAMPLE"}
			if class.Category == "ELASTICACHE" || class.Category == "DYNAMODB" || class.Category == "S3" {
				op.Status, op.ReasonCode, op.ProviderErrorCode = "DENIED", "AWS_READ_PERMISSION_DENIED", "AccessDenied"
			} else if n == 0 && (class.Category == "RDS_AURORA" || class.Category == "LAMBDA" || class.Category == "ELB" || class.Category == "COMMITMENTS") {
				op.Status, op.ReasonCode = "PARTIAL", "AWS_READ_PROBE_PAGE_LIMIT_REACHED"
			}
			class.Operations = append(class.Operations, op)
		}
		accountProbeClassStatus(class)
		class.Limitations = append(class.Limitations, "SYNTHETIC_PROVIDER_DOUBLES_NOT_LIVE_AWS")
	}
	return out, nil
}

type accountReadProbe struct {
	name, service, version, collection, target, path string
	params                                           url.Values
	jsonBody                                         string
	jsonResponse                                     bool
}

func accountReadProbes(category string) []accountReadProbe {
	query := func(name, service, version, collection, key, value string) accountReadProbe {
		p := url.Values{}
		if key != "" {
			p.Set(key, value)
		}
		return accountReadProbe{name: name, service: service, version: version, collection: collection, params: p}
	}
	jsonProbe := func(name, service, target, collection, body string) accountReadProbe {
		return accountReadProbe{name: name, service: service, target: target, collection: collection, jsonBody: body, jsonResponse: true}
	}
	switch category {
	case "EC2_ASG":
		return []accountReadProbe{query("DescribeInstances", "ec2", "2016-11-15", "reservationSet", "MaxResults", "5"), query("DescribeAutoScalingGroups", "autoscaling", "2011-01-01", "AutoScalingGroups", "MaxRecords", "1")}
	case "EBS":
		v := query("DescribeSnapshots", "ec2", "2016-11-15", "snapshotSet", "MaxResults", "5")
		v.params.Set("Owner.1", "self")
		return []accountReadProbe{query("DescribeVolumes", "ec2", "2016-11-15", "volumeSet", "MaxResults", "5"), v}
	case "RDS_AURORA":
		return []accountReadProbe{query("DescribeDBInstances", "rds", "2014-10-31", "DBInstances", "MaxRecords", "20"), query("DescribeDBClusters", "rds", "2014-10-31", "DBClusters", "MaxRecords", "20")}
	case "ECS_FARGATE":
		return []accountReadProbe{jsonProbe("ListClusters", "ecs", "AmazonEC2ContainerServiceV20141113.ListClusters", "clusterArns", `{"maxResults":1}`), jsonProbe("ListTaskDefinitions", "ecs", "AmazonEC2ContainerServiceV20141113.ListTaskDefinitions", "taskDefinitionArns", `{"maxResults":1}`)}
	case "EKS":
		return []accountReadProbe{{name: "ListClusters", service: "eks", path: "/clusters?maxResults=1", collection: "clusters", jsonResponse: true}}
	case "LAMBDA":
		return []accountReadProbe{{name: "ListFunctions", service: "lambda", path: "/2015-03-31/functions/?MaxItems=1", collection: "Functions", jsonResponse: true}}
	case "S3":
		return []accountReadProbe{{name: "ListBuckets", service: "s3", collection: "Buckets", params: url.Values{"max-buckets": {"1"}}}}
	case "ELASTICACHE":
		return []accountReadProbe{query("DescribeCacheClusters", "elasticache", "2015-02-02", "CacheClusters", "MaxRecords", "20"), query("DescribeReplicationGroups", "elasticache", "2015-02-02", "ReplicationGroups", "MaxRecords", "20")}
	case "DYNAMODB":
		return []accountReadProbe{jsonProbe("ListTables", "dynamodb", "DynamoDB_20120810.ListTables", "TableNames", `{"Limit":1}`)}
	case "NETWORK_NAT":
		return []accountReadProbe{query("DescribeNatGateways", "ec2", "2016-11-15", "natGatewaySet", "MaxResults", "5"), query("DescribeRouteTables", "ec2", "2016-11-15", "routeTableSet", "MaxResults", "5")}
	case "PUBLIC_IPV4":
		return []accountReadProbe{query("DescribeAddresses", "ec2", "2016-11-15", "addressesSet", "", "")}
	case "ELB":
		v2 := query("DescribeLoadBalancers", "elasticloadbalancing", "2015-12-01", "LoadBalancers", "PageSize", "1")
		classic := query("DescribeLoadBalancers", "elasticloadbalancing", "2012-06-01", "LoadBalancerDescriptions", "PageSize", "1")
		return []accountReadProbe{v2, classic}
	case "COMMITMENTS":
		sp := jsonProbe("DescribeSavingsPlans", "savingsplans", "", "savingsPlans", `{"maxResults":1}`)
		sp.path = "/DescribeSavingsPlans"
		return []accountReadProbe{query("DescribeReservedInstances", "ec2", "2016-11-15", "reservedInstancesSet", "", ""), sp, query("DescribeReservedDBInstances", "rds", "2014-10-31", "ReservedDBInstances", "MaxRecords", "20")}
	}
	return nil
}

type accountProbeReader struct {
	a            *AWS
	region       string
	creds        aws.Credentials
	reads, bytes int
}

var errAccountProbeEvidence = errors.New("AWS_READ_PROBE_EVIDENCE_UNAVAILABLE")

func (r *accountProbeReader) read(ctx context.Context, spec accountReadProbe) ([]byte, bool, error) {
	region, host := r.region, spec.service+"."+r.region+".amazonaws.com"
	if spec.service == "savingsplans" {
		region, host = "us-east-1", "savingsplans.us-east-1.amazonaws.com"
	}
	path, body, method := spec.path, spec.jsonBody, http.MethodPost
	if path == "" {
		path = "/"
	}
	if spec.service == "eks" || spec.service == "lambda" {
		method = http.MethodGet
	}
	if spec.service == "s3" {
		method = http.MethodGet
		p := url.Values{"max-buckets": {"1"}, "bucket-region": {r.region}}
		path = "/?" + p.Encode()
	}
	if spec.version != "" {
		p := url.Values{"Action": {spec.name}, "Version": {spec.version}}
		for key, values := range spec.params {
			p[key] = append([]string{}, values...)
		}
		body = p.Encode()
	}
	client := r.a.client
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	safe := *client
	safe.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	for attempt := 0; attempt < 3; attempt++ {
		if ctx.Err() != nil || r.reads >= 96 || r.bytes >= 32<<20 {
			return nil, false, errAccountProbeEvidence
		}
		r.reads++
		request, err := http.NewRequestWithContext(ctx, method, "https://"+host+path, strings.NewReader(body))
		if err != nil {
			return nil, false, errAccountProbeEvidence
		}
		request.Header.Set("Accept-Encoding", "identity")
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if spec.jsonResponse {
			request.Header.Set("Content-Type", "application/json")
		}
		if spec.target != "" {
			request.Header.Set("X-Amz-Target", spec.target)
			request.Header.Set("Content-Type", "application/x-amz-json-1.1")
		}
		if spec.service == "dynamodb" {
			request.Header.Set("Content-Type", "application/x-amz-json-1.0")
		}
		if v4.NewSigner().SignHTTP(ctx, r.creds, request, rdsSHA([]byte(body)), spec.service, region, time.Now().UTC()) != nil {
			return nil, false, errAccountProbeEvidence
		}
		response, err := safe.Do(request)
		if err != nil {
			return nil, false, errAccountProbeEvidence
		}
		raw, err := io.ReadAll(io.LimitReader(response.Body, (4<<20)+1))
		response.Body.Close()
		r.bytes += len(raw)
		if err != nil || len(raw) > 4<<20 || r.bytes > 32<<20 || response.Header.Get("Content-Encoding") != "" && response.Header.Get("Content-Encoding") != "identity" {
			return nil, false, errAccountProbeEvidence
		}
		if response.StatusCode == 200 {
			more, ok := accountProbeResponse(spec, raw)
			if !ok {
				return nil, false, errAccountProbeEvidence
			}
			return raw, more, nil
		}
		code := response.Header.Get("x-amzn-ErrorType")
		var doc map[string]json.RawMessage
		if json.Unmarshal(raw, &doc) == nil {
			for _, key := range []string{"__type", "code", "Code"} {
				if code == "" {
					_ = json.Unmarshal(doc[key], &code)
				}
			}
		}
		if code == "" {
			var failure struct {
				Error  struct{ Code string }
				Errors []struct{ Code string } `xml:"Errors>Error"`
				Code   string
			}
			if xml.Unmarshal(raw, &failure) == nil {
				code = failure.Error.Code
				if code == "" && len(failure.Errors) > 0 {
					code = failure.Errors[0].Code
				}
				if code == "" {
					code = failure.Code
				}
			}
		}
		if at := strings.LastIndexAny(code, "#:"); at >= 0 {
			code = code[at+1:]
		}
		code = awsErrorCode(code)
		if attempt < 2 && (response.StatusCode == 429 || code == "Throttling" || code == "ThrottlingException" || code == "TooManyRequestsException" || code == "RequestLimitExceeded") {
			timer := time.NewTimer(time.Duration(attempt+1) * 100 * time.Millisecond)
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil, false, errAccountProbeEvidence
			case <-timer.C:
			}
			continue
		}
		return nil, false, &QueryRejection{Action: spec.name, Code: code, StatusCode: response.StatusCode}
	}
	return nil, false, errAccountProbeEvidence
}

func accountProbeResponse(spec accountReadProbe, raw []byte) (bool, bool) {
	if spec.jsonResponse {
		var doc map[string]json.RawMessage
		if json.Unmarshal(raw, &doc) != nil {
			return false, false
		}
		var rows []json.RawMessage
		if value, ok := doc[spec.collection]; !ok || json.Unmarshal(value, &rows) != nil || rows == nil {
			return false, false
		}
		for _, key := range []string{"nextToken", "NextToken", "NextMarker", "LastEvaluatedTableName"} {
			if value, ok := doc[key]; ok {
				var token string
				if json.Unmarshal(value, &token) != nil {
					return false, false
				}
				if token != "" {
					return true, true
				}
			}
		}
		return false, true
	}
	decoder := xml.NewDecoder(bytes.NewReader(raw))
	depth := 0
	root := ""
	found := false
	more := false
	stack := []string{}
	expectedDepth := 3
	if spec.service == "ec2" || spec.service == "s3" || spec.service == "sts" {
		expectedDepth = 2
	}
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return false, false
		}
		switch v := token.(type) {
		case xml.StartElement:
			depth++
			stack = append(stack, v.Name.Local)
			if depth == 1 {
				if root != "" {
					return false, false
				}
				root = v.Name.Local
			}
			atResult := depth == expectedDepth && (expectedDepth == 2 || stack[1] == spec.name+"Result")
			if v.Name.Local == spec.collection && atResult {
				if found {
					return false, false
				}
				found = true
			}
			if atResult && (v.Name.Local == "nextToken" || v.Name.Local == "NextToken" || v.Name.Local == "Marker" || v.Name.Local == "NextMarker" || v.Name.Local == "ContinuationToken") {
				var token string
				if decoder.DecodeElement(&token, &v) != nil {
					return false, false
				}
				depth--
				stack = stack[:len(stack)-1]
				more = more || token != ""
			}
		case xml.EndElement:
			depth--
			stack = stack[:len(stack)-1]
		case xml.CharData:
			if depth == 0 && strings.TrimSpace(string(v)) != "" {
				return false, false
			}
		}
	}
	want := spec.name + "Response"
	if spec.service == "s3" {
		want = "ListAllMyBucketsResult"
	}
	return more, root == want && found && depth == 0
}

func accountProbeFailure(name string, err error) AWSAccountProbeOperation {
	op := AWSAccountProbeOperation{Name: name, Status: "ERROR", ReasonCode: "AWS_READ_PROBE_UNAVAILABLE"}
	var rejection *QueryRejection
	if !errors.As(err, &rejection) {
		return op
	}
	op.ProviderErrorCode = awsErrorCode(rejection.Code)
	switch rejection.Code {
	case "AccessDenied", "AccessDeniedException", "UnauthorizedOperation", "UnauthorizedException", "AuthFailure", "AuthorizationError":
		op.Status, op.ReasonCode = "DENIED", "AWS_READ_PERMISSION_DENIED"
	case "UnknownOperationException", "UnsupportedOperation", "UnsupportedOperationException", "InvalidAction", "NotImplemented":
		op.Status, op.ReasonCode = "UNSUPPORTED", "AWS_READ_OPERATION_UNSUPPORTED"
	case "OptInRequired", "SubscriptionRequiredException":
		op.Status, op.ReasonCode = "NOT_CONFIGURED", "AWS_REGION_OR_SERVICE_NOT_CONFIGURED"
	default:
		if rejection.StatusCode == 403 {
			op.Status, op.ReasonCode = "DENIED", "AWS_READ_PERMISSION_DENIED"
		}
	}
	return op
}

func accountProbeClassStatus(class *AWSAccountProbeClass) {
	class.InventoryComplete = false
	if len(class.Operations) == 0 {
		class.Status, class.ReasonCode = "UNSUPPORTED", "AWS_CATEGORY_PROBE_UNSUPPORTED"
		return
	}
	states := map[string]bool{}
	for _, op := range class.Operations {
		states[op.Status] = true
		if op.ProviderErrorCode != "" {
			class.ProviderErrorCode = op.ProviderErrorCode
		}
	}
	status := "UNSUPPORTED"
	switch {
	case states["READY"] && len(states) == 1:
		status = "READY"
	case states["READY"] || states["PARTIAL"]:
		status = "PARTIAL"
	case states["ERROR"]:
		status = "ERROR"
	case states["DENIED"]:
		status = "DENIED"
	case states["NOT_CONFIGURED"]:
		status = "NOT_CONFIGURED"
	}
	class.Status = status
	switch status {
	case "READY":
		class.ReasonCode = "AWS_BOUNDED_READ_ACCESS_OBSERVED"
	case "PARTIAL":
		class.ReasonCode = "AWS_READ_ACCESS_PARTIAL"
	case "DENIED":
		class.ReasonCode = "AWS_READ_PERMISSION_DENIED"
	case "UNSUPPORTED":
		class.ReasonCode = "AWS_READ_OPERATION_UNSUPPORTED"
	case "NOT_CONFIGURED":
		class.ReasonCode = "AWS_REGION_OR_SERVICE_NOT_CONFIGURED"
	default:
		class.ReasonCode = "AWS_READ_PROBE_UNAVAILABLE"
	}
}
