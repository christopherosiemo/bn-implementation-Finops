package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
)

type accountPreflightTransport struct {
	account, role string
	calls         []string
	handle        func(*http.Request, string, url.Values) (string, int)
}

func (tr *accountPreflightTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	var raw []byte
	if req.Body != nil {
		raw, _ = io.ReadAll(req.Body)
	}
	values, _ := url.ParseQuery(string(raw))
	action := values.Get("Action")
	if action == "" {
		action = req.Header.Get("X-Amz-Target")
		if at := strings.LastIndexByte(action, '.'); at >= 0 {
			action = action[at+1:]
		}
	}
	if action == "" {
		switch {
		case req.URL.Host == "s3.eu-west-1.amazonaws.com":
			action = "ListBuckets"
		case strings.HasPrefix(req.URL.Path, "/2015-03-31/functions/"):
			action = "ListFunctions"
		case req.URL.Path == "/clusters":
			action = "ListClusters"
		case req.URL.Path == "/DescribeSavingsPlans":
			action = "DescribeSavingsPlans"
		}
	}
	tr.calls = append(tr.calls, req.URL.Host+":"+action)
	var body string
	status := 200
	if action == "GetCallerIdentity" {
		account, role := tr.account, tr.role
		if account == "" {
			account = "111122223333"
		}
		if role == "" {
			role = "read"
		}
		body = `<GetCallerIdentityResponse><GetCallerIdentityResult><Account>` + account + `</Account><Arn>arn:aws:sts::` + account + `:assumed-role/` + role + `/private-session-must-not-escape</Arn><UserId>private-id</UserId></GetCallerIdentityResult></GetCallerIdentityResponse>`
	} else if tr.handle != nil {
		body, status = tr.handle(req, action, values)
	} else {
		body = accountPreflightPage(req, action, values)
	}
	return &http.Response{StatusCode: status, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body)), Request: req}, nil
}

func accountPreflightPage(req *http.Request, action string, values url.Values) string {
	if req.URL.Host == "s3.eu-west-1.amazonaws.com" {
		return `<ListAllMyBucketsResult><Buckets/><Owner><ID>private-owner</ID></Owner></ListAllMyBucketsResult>`
	}
	if req.URL.Host == "lambda.eu-west-1.amazonaws.com" {
		return `{"Functions":[{"FunctionName":"private-name","Environment":{"Variables":{"PRIVATE_SECRET":"never-return-this-value"}}}]}`
	}
	if req.URL.Host == "eks.eu-west-1.amazonaws.com" {
		return `{"clusters":[]}`
	}
	if req.URL.Host == "ecs.eu-west-1.amazonaws.com" {
		if action == "ListTaskDefinitions" {
			return `{"taskDefinitionArns":[]}`
		}
		return `{"clusterArns":[]}`
	}
	if req.URL.Host == "dynamodb.eu-west-1.amazonaws.com" {
		return `{"TableNames":[]}`
	}
	if req.URL.Host == "savingsplans.us-east-1.amazonaws.com" {
		return `{"savingsPlans":[]}`
	}
	collection := map[string]string{"DescribeInstances": "reservationSet", "DescribeAutoScalingGroups": "AutoScalingGroups", "DescribeVolumes": "volumeSet", "DescribeSnapshots": "snapshotSet", "DescribeDBInstances": "DBInstances", "DescribeDBClusters": "DBClusters", "DescribeCacheClusters": "CacheClusters", "DescribeReplicationGroups": "ReplicationGroups", "DescribeNatGateways": "natGatewaySet", "DescribeRouteTables": "routeTableSet", "DescribeAddresses": "addressesSet", "DescribeReservedInstances": "reservedInstancesSet", "DescribeReservedDBInstances": "ReservedDBInstances", "DescribeLoadBalancers": "LoadBalancers"}[action]
	if action == "DescribeLoadBalancers" && values.Get("Version") == "2012-06-01" {
		collection = "LoadBalancerDescriptions"
	}
	if req.URL.Host == "ec2.eu-west-1.amazonaws.com" {
		return "<" + action + "Response><" + collection + "/></" + action + "Response>"
	}
	return "<" + action + "Response><" + action + "Result><" + collection + "/></" + action + "Result></" + action + "Response>"
}

func accountPreflightAWS(tr *accountPreflightTransport) *AWS {
	return &AWS{cfg: aws.Config{Region: "eu-west-1", Credentials: credentials.NewStaticCredentialsProvider("synthetic-read-key", "synthetic-read-secret", "synthetic-session-token")}, client: &http.Client{Transport: tr}}
}
func accountPreflightRequest() AWSAccountProbeRequest {
	return AWSAccountProbeRequest{TenantID: "tenant-a", AccountID: "111122223333", Region: "eu-west-1", ExpectedRoleARN: "arn:aws:iam::111122223333:role/path/read", ExternalIDConfigured: true}
}

func TestAWSAccountReadPreflightAllCategoriesSafeAndAccessOnly(t *testing.T) {
	tr := &accountPreflightTransport{}
	throttles := 0
	tr.handle = func(req *http.Request, action string, values url.Values) (string, int) {
		if !strings.HasPrefix(action, "Describe") && !strings.HasPrefix(action, "List") {
			t.Fatal("non-read AWS operation", action)
		}
		if req.URL.Host == "s3.eu-west-1.amazonaws.com" && (req.Method != http.MethodGet || req.URL.Query().Get("bucket-region") != "eu-west-1" || req.URL.Query().Get("max-buckets") != "1") {
			t.Fatal("S3 probe scope changed")
		}
		if action == "DescribeSnapshots" && values.Get("Owner.1") != "self" {
			t.Fatal("snapshot probe expanded beyond owned scope")
		}
		if action == "DescribeDBInstances" {
			return `<DescribeDBInstancesResponse><DescribeDBInstancesResult><DBInstances/><Marker>more</Marker></DescribeDBInstancesResult></DescribeDBInstancesResponse>`, 200
		}
		if req.URL.Host == "dynamodb.eu-west-1.amazonaws.com" {
			return `{"__type":"com.amazonaws#AccessDeniedException","message":"private-provider-message"}`, 403
		}
		if req.URL.Host == "elasticache.eu-west-1.amazonaws.com" {
			return `<ErrorResponse><Error><Code>UnsupportedOperation</Code><Message>private-provider-message</Message></Error></ErrorResponse>`, 400
		}
		if action == "DescribeNatGateways" && throttles == 0 {
			throttles++
			return `{"__type":"ThrottlingException"}`, 429
		}
		return accountPreflightPage(req, action, values), 200
	}
	out, e := accountPreflightAWS(tr).AccountReadPreflight(context.Background(), accountPreflightRequest())
	if e != nil || out.Identity.Status != "READY" || !out.Identity.ExternalIDBound || len(out.Classes) != 13 || out.Fixture {
		t.Fatal("identity or category access differs", e, out.Identity)
	}
	states := map[string]string{}
	for _, class := range out.Classes {
		states[class.Category] = class.Status
		if class.InventoryComplete || len(class.Operations) == 0 || len(class.Limitations) < 2 {
			t.Fatal("access became inventory authority")
		}
	}
	if states["EC2_ASG"] != "READY" || states["RDS_AURORA"] != "PARTIAL" || states["DYNAMODB"] != "DENIED" || states["ELASTICACHE"] != "UNSUPPORTED" || states["NETWORK_NAT"] != "READY" || throttles != 1 {
		t.Fatal("denied, paginated or throttled access lost", states)
	}
	raw, _ := json.Marshal(out)
	for _, secret := range []string{"synthetic-read-key", "synthetic-read-secret", "synthetic-session-token", "private-session", "private-id", "never-return-this-value", "private-provider-message", "private-name", "private-owner"} {
		if strings.Contains(string(raw), secret) {
			t.Fatal("sensitive native field escaped")
		}
	}
	if out.Identity.CallerRoleARN != "arn:aws:sts::111122223333:assumed-role/read" {
		t.Fatal("role display retained a session")
	}
}

func TestAWSAccountReadPreflightIdentityBindingFailsClosed(t *testing.T) {
	for _, scenario := range []string{"account", "role", "region", "external-id", "permanent-credentials", "invalid-role"} {
		t.Run(scenario, func(t *testing.T) {
			tr := &accountPreflightTransport{}
			a := accountPreflightAWS(tr)
			req := accountPreflightRequest()
			switch scenario {
			case "account":
				tr.account = "999900001111"
			case "role":
				tr.role = "other-read"
			case "region":
				req.Region = "us-east-1"
			case "external-id":
				req.ExternalIDConfigured = false
			case "permanent-credentials":
				a.cfg.Credentials = credentials.NewStaticCredentialsProvider("synthetic-key", "synthetic-secret", "")
			case "invalid-role":
				req.ExpectedRoleARN = "private-secret\nrole"
			}
			out, e := a.AccountReadPreflight(context.Background(), req)
			if e != nil || out.Identity.Status == "READY" || out.Identity.ExternalIDBound {
				t.Fatal("unproved identity accepted")
			}
			for _, call := range tr.calls {
				if !strings.Contains(call, "GetCallerIdentity") {
					t.Fatal("service call before identity proof")
				}
			}
			for _, class := range out.Classes {
				if class.Status != "NOT_CONFIGURED" || class.InventoryComplete || len(class.Operations) != 0 {
					t.Fatal("identity failure became observed inventory")
				}
			}
			raw, _ := json.Marshal(out)
			if strings.Contains(string(raw), "private-secret") {
				t.Fatal("invalid role leaked")
			}
		})
	}
}

func TestAWSAccountReadPreflightUsesApprovedAssumeRole(t *testing.T) {
	const external = "synthetic-approved-external-id-at-least-thirty-two"
	assumptions := 0
	sts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("Action") != "AssumeRole" || r.Form.Get("RoleArn") != "arn:aws:iam::111122223333:role/path/read" || r.Form.Get("ExternalId") != external {
			t.Error("private approved role/external ID not used")
			w.WriteHeader(400)
			return
		}
		assumptions++
		fmt.Fprintf(w, `<AssumeRoleResponse><AssumeRoleResult><Credentials><AccessKeyId>synthetic-assumed-key</AccessKeyId><SecretAccessKey>synthetic-assumed-secret</SecretAccessKey><SessionToken>synthetic-assumed-token</SessionToken><Expiration>%s</Expiration></Credentials><AssumedRoleUser><Arn>arn:aws:sts::111122223333:assumed-role/read/private-session</Arn><AssumedRoleId>private-id</AssumedRoleId></AssumedRoleUser></AssumeRoleResult></AssumeRoleResponse>`, time.Now().Add(time.Hour).UTC().Format(time.RFC3339))
	}))
	defer sts.Close()
	for key, value := range map[string]string{"AWS_ACCESS_KEY_ID": "synthetic-source", "AWS_SECRET_ACCESS_KEY": "synthetic-source-secret", "AWS_SESSION_TOKEN": "", "AWS_ROLE_ARN": "", "AWS_WEB_IDENTITY_TOKEN_FILE": "", "AWS_PROFILE": "", "AWS_ENDPOINT_URL_STS": sts.URL, "AWS_EC2_METADATA_DISABLED": "true"} {
		t.Setenv(key, value)
	}
	a, e := NewAWS(context.Background(), "eu-west-1", accountPreflightRequest().ExpectedRoleARN, external)
	if e != nil {
		t.Fatal(e)
	}
	a.client = &http.Client{Transport: &accountPreflightTransport{}}
	out, e := a.AccountReadPreflight(context.Background(), accountPreflightRequest())
	if e != nil || out.Identity.Status != "READY" || assumptions != 1 {
		t.Fatal("assumed identity was not independently observed", e, out.Identity, assumptions)
	}
}

func TestAWSAccountReadPreflightMalformedPagesAndClassifications(t *testing.T) {
	jsonSpec := accountReadProbe{collection: "clusters", jsonResponse: true}
	for _, body := range []string{`{}`, `{"clusters":null}`, `{"clusters":[],"nextToken":123}`, `{"clusters":[]}garbage`} {
		if _, ok := accountProbeResponse(jsonSpec, []byte(body)); ok {
			t.Fatal("malformed JSON page accepted")
		}
	}
	xmlSpec := accountReadProbe{name: "DescribeVolumes", service: "ec2", collection: "volumeSet"}
	for _, body := range []string{`<DescribeVolumesResponse/>`, `<WrongResponse><volumeSet/></WrongResponse>`, `<DescribeVolumesResponse><Wrong><volumeSet/></Wrong></DescribeVolumesResponse>`, `<DescribeVolumesResponse><volumeSet/></DescribeVolumesResponse><DescribeVolumesResponse><volumeSet/></DescribeVolumesResponse>`, `<DescribeVolumesResponse><volumeSet/></DescribeVolumesResponse>private`} {
		if _, ok := accountProbeResponse(xmlSpec, []byte(body)); ok {
			t.Fatal("malformed XML page accepted")
		}
	}
	for _, tc := range []struct{ code, status string }{{"AccessDenied", "DENIED"}, {"UnauthorizedOperation", "DENIED"}, {"UnknownOperationException", "UNSUPPORTED"}, {"OptInRequired", "NOT_CONFIGURED"}, {"ThrottlingException", "ERROR"}, {"ResourceNotFoundException", "ERROR"}} {
		op := accountProbeFailure("ListClusters", &QueryRejection{Action: "ListClusters", Code: tc.code, StatusCode: 400})
		if op.Status != tc.status {
			t.Fatal("native error changed meaning", tc.code, op.Status)
		}
	}
}

func TestFixtureAWSAccountReadPreflightLabelsMixedAccess(t *testing.T) {
	out, e := FixtureAWSAccountReadPreflight(accountPreflightRequest())
	if e != nil || !out.Fixture || out.ObservationBasis != "PROVIDER_SHAPED_SYNTHETIC_ACCESS_PROBE" || len(out.Classes) != 13 {
		t.Fatal("fixture source not explicit")
	}
	states := map[string]bool{}
	for _, class := range out.Classes {
		states[class.Status] = true
		if class.InventoryComplete {
			t.Fatal("fixture access became census")
		}
	}
	if !states["READY"] || !states["PARTIAL"] || !states["DENIED"] {
		t.Fatal("fixture hid realistic missing permissions")
	}
}
