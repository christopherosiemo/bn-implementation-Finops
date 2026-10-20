package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/lambdacost"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

var lambdaTestScope = lambdacost.Scope{TenantID: "tenant-lambda", AccountID: "111122223333", Region: "eu-west-1"}

const lambdaTestARN = "arn:aws:lambda:eu-west-1:111122223333:function:processor"

func lambdaTestAWS(t *testing.T, handler func(*http.Request, string) (string, int)) *AWS {
	t.Helper()
	return &AWS{cfg: aws.Config{Region: "eu-west-1", Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		return aws.Credentials{AccessKeyID: "fixture-read", SecretAccessKey: "fixture-secret", SessionToken: "fixture-session"}, nil
	})}, client: &http.Client{Transport: rdsTransport(func(r *http.Request) (*http.Response, error) {
		body := ""
		if r.Body != nil {
			raw, e := io.ReadAll(r.Body)
			if e != nil {
				t.Fatal(e)
			}
			body = string(raw)
		}
		if !strings.Contains(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256") {
			t.Fatal("unsigned native read")
		}
		out, status := handler(r, body)
		return &http.Response{StatusCode: status, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(out))}, nil
	})}}
}
func lambdaFixtureConfig(version string) model.Document {
	arn := lambdaTestARN
	if version != "$LATEST" {
		arn += ":" + version
	}
	return model.Document{"FunctionArn": arn, "FunctionName": "processor", "Version": version, "MemorySize": 2048, "Architectures": []string{"x86_64"}, "Runtime": "python3.13", "Handler": "main.handler", "PackageType": "Zip", "CodeSha256": "fixture-code-digest", "RevisionId": "fixture-config-" + version, "Timeout": 30, "EphemeralStorage": model.Document{"Size": 1024}, "State": "Active", "LastUpdateStatus": "Successful", "Role": "arn:aws:iam::111122223333:role/workload-only-metadata", "Environment": model.Document{"Variables": model.Document{"DATABASE_PASSWORD": "never-persist-this-secret"}}, "Layers": []model.Document{{"Arn": "arn:aws:lambda:eu-west-1:111122223333:layer:extension:1"}}, "LoggingConfig": model.Document{"LogGroup": "/aws/lambda/processor", "LogFormat": "Text"}}
}
func lambdaFixtureResponse(t *testing.T, r *http.Request, body string) (string, int) {
	t.Helper()
	if r.URL.Host == "sts.eu-west-1.amazonaws.com" {
		return rdsTestIdentity(), 200
	}
	var value any
	switch {
	case r.URL.Path == "/2015-03-31/functions/":
		value = model.Document{"Functions": []model.Document{lambdaFixtureConfig("$LATEST")}}
	case strings.HasSuffix(r.URL.Path, "/configuration"):
		version := r.URL.Query().Get("Qualifier")
		if version == "" {
			version = "$LATEST"
		}
		value = lambdaFixtureConfig(version)
	case strings.HasSuffix(r.URL.Path, "/versions"):
		value = model.Document{"Versions": []model.Document{lambdaFixtureConfig("$LATEST"), lambdaFixtureConfig("1"), lambdaFixtureConfig("2")}}
	case strings.HasSuffix(r.URL.Path, "/aliases"):
		value = model.Document{"Aliases": []model.Document{{"AliasArn": lambdaTestARN + ":live", "Name": "live", "FunctionVersion": "1", "RoutingConfig": model.Document{"AdditionalVersionWeights": model.Document{"2": 0.1}}, "RevisionId": "alias-epoch"}}}
	case strings.HasSuffix(r.URL.Path, "/provisioned-concurrency"):
		value = model.Document{"ProvisionedConcurrencyConfigs": []model.Document{{"FunctionArn": lambdaTestARN + ":live", "RequestedProvisionedConcurrentExecutions": 10, "AllocatedProvisionedConcurrentExecutions": 10, "Status": "READY"}}}
	case r.URL.Path == "/2015-03-31/event-source-mappings/":
		value = model.Document{"EventSourceMappings": []model.Document{{"UUID": "mapping", "FunctionArn": lambdaTestARN + ":live", "EventSourceArn": "arn:aws:sqs:eu-west-1:111122223333:queue", "BatchSize": 10, "State": "Enabled"}}}
	case strings.HasSuffix(r.URL.Path, "/event-invoke-config/list"):
		value = model.Document{"FunctionEventInvokeConfigs": []model.Document{{"FunctionArn": lambdaTestARN + ":live", "MaximumRetryAttempts": 2}}}
	case strings.HasSuffix(r.URL.Path, "/urls"):
		value = model.Document{"FunctionUrlConfigs": []model.Document{}}
	case strings.HasSuffix(r.URL.Path, "/concurrency"):
		value = model.Document{"ReservedConcurrentExecutions": 20}
	case strings.HasPrefix(r.URL.Path, "/2017-03-31/tags/"):
		value = model.Document{"Tags": model.Document{"Owner": "declared-team", "Environment": "non-production"}}
	case strings.HasSuffix(r.URL.Path, "/account-settings/"):
		value = model.Document{"AccountLimit": model.Document{"ConcurrentExecutions": 1000, "UnreservedConcurrentExecutions": 900}}
	default:
		t.Fatalf("unplanned Lambda read %s %s", r.URL, body)
	}
	raw, _ := json.Marshal(value)
	return string(raw), 200
}
func TestLambdaDiscoveryNativeMetadataAliasesAndSecretMinimization(t *testing.T) {
	reader := lambdaTestAWS(t, func(r *http.Request, b string) (string, int) { return lambdaFixtureResponse(t, r, b) })
	d, e := reader.LambdaDiscover(context.Background(), lambdaTestScope, lambdacost.DiscoverySelection{MaxFunctions: 1})
	if e != nil || !d.Complete || len(d.Functions) != 1 {
		t.Fatal(d, e)
	}
	config := lambdacost.Document(d.Functions[0]["lambda_configuration"])
	if model.Number(config, "memory_size_mb") != 2048 || len(lambdacost.Rows(config["versions"])) != 3 || model.Number(config, "reserved_concurrency") != 20 || len(lambdacost.Rows(config["provisioned_concurrency"])) != 1 || len(lambdacost.Rows(config["event_source_mappings"])) != 1 {
		t.Fatal(config)
	}
	aliases := lambdacost.Rows(config["aliases"])
	if len(aliases) != 1 || lambdacost.Document(aliases[0]["routing_weights"])["2"] == nil {
		t.Fatal("weighted routing lost", aliases)
	}
	env := lambdacost.Document(config["environment_metadata"])
	if !model.Bool(env, "values_redacted") || model.Number(env, "variable_count") != 1 || strings.Contains(string(d.Raw), "never-persist-this-secret") {
		t.Fatal("environment secret entered native evidence")
	}
	raw, _ := json.Marshal(d.Functions)
	if strings.Contains(string(raw), "never-persist-this-secret") {
		t.Fatal("environment value entered inventory")
	}
	filtered, err := reader.LambdaDiscover(context.Background(), lambdaTestScope, lambdacost.DiscoverySelection{MaxFunctions: 1, FunctionARN: lambdaTestARN + "-other"})
	if err != nil || len(filtered.Functions) != 0 {
		t.Fatal("unregistered function was published by source selector", err)
	}
}
func TestLambdaPaginationThrottlingDenialAndScopeFailures(t *testing.T) {
	calls := 0
	reader := lambdaTestAWS(t, func(r *http.Request, b string) (string, int) {
		if r.URL.Path == "/2015-03-31/functions/" {
			calls++
			if calls == 1 {
				return `{"__type":"TooManyRequestsException","message":"sensitive diagnostic"}`, 429
			}
			v := model.Document{"Functions": []model.Document{lambdaFixtureConfig("$LATEST")}, "NextMarker": "next-page"}
			raw, _ := json.Marshal(v)
			return string(raw), 200
		}
		if strings.HasSuffix(r.URL.Path, "/urls") {
			return `{"__type":"AccessDeniedException","message":"secret diagnostic"}`, 403
		}
		return lambdaFixtureResponse(t, r, b)
	})
	d, e := reader.LambdaDiscover(context.Background(), lambdaTestScope, lambdacost.DiscoverySelection{MaxFunctions: 1})
	if e != nil || d.Complete || d.NextMarker != "next-page" || calls != 2 || len(d.Functions) != 1 {
		t.Fatal(d, e, calls)
	}
	config := lambdacost.Document(d.Functions[0]["lambda_configuration"])
	if config["function_urls"] != nil || strings.Contains(string(d.Raw), "sensitive diagnostic") {
		t.Fatal("denied metadata became empty complete source")
	}
	for _, bad := range []lambdacost.Scope{{TenantID: "tenant-lambda", AccountID: "999999999999", Region: "eu-west-1"}, {TenantID: "tenant-lambda", AccountID: "111122223333", Region: "us-east-1"}} {
		if _, e = reader.LambdaDiscover(context.Background(), bad, lambdacost.DiscoverySelection{}); e == nil {
			t.Fatal("wrong native account/region accepted")
		}
	}
}
func TestLambdaMetricScopeNativePeriodsAndMissingRemainUnknown(t *testing.T) {
	start := time.Now().UTC().Truncate(time.Hour).Add(-3 * time.Hour)
	reader := lambdaTestAWS(t, func(r *http.Request, b string) (string, int) {
		if r.URL.Host == "sts.eu-west-1.amazonaws.com" {
			return rdsTestIdentity(), 200
		}
		v, _ := url.ParseQuery(b)
		if v.Get("Namespace") != "AWS/Lambda" || v.Get("Dimensions.member.2.Value") != "processor:live" || v.Get("Dimensions.member.3.Value") != "1" {
			t.Fatal("serving dimensions lost", v)
		}
		points := ""
		if v.Get("MetricName") == "Duration" {
			stat := v.Get("Statistics.member.1")
			points = fmt.Sprintf("<member><Timestamp>%s</Timestamp><%s>12.5</%s><SampleCount>2</SampleCount><Unit>Milliseconds</Unit></member>", start.Format(time.RFC3339), stat, stat)
		}
		return "<GetMetricStatisticsResponse><GetMetricStatisticsResult><Datapoints>" + points + "</Datapoints></GetMetricStatisticsResult></GetMetricStatisticsResponse>", 200
	})
	m, e := reader.LambdaMetrics(context.Background(), lambdaTestScope, lambdacost.MetricSelection{QualifiedARN: lambdaTestARN + ":live", Version: "1", Start: start, End: start.Add(time.Hour), PeriodSeconds: 3600})
	if e != nil || len(m.Rows) != 3 {
		t.Fatal(m, e)
	}
	for _, c := range m.Coverage {
		if c["metric"] == "Invocations" && (c["status"] != "GAPS" || model.Bool(c, "missing_is_zero")) {
			t.Fatal("missing invocation sample became zero", c)
		}
	}
	if _, e = reader.LambdaMetrics(context.Background(), lambdaTestScope, lambdacost.MetricSelection{QualifiedARN: lambdaTestARN + ":live", Version: "1", Start: start.Add(-20 * 24 * time.Hour), End: start, PeriodSeconds: 60}); e == nil {
		t.Fatal("expired minute resolution accepted")
	}
}
func TestLambdaCommissionedReportsAndProviderAdvice(t *testing.T) {
	at := time.Now().UTC().Truncate(time.Second).Add(-time.Hour)
	reader := lambdaTestAWS(t, func(r *http.Request, b string) (string, int) {
		if r.URL.Host == "sts.eu-west-1.amazonaws.com" {
			return rdsTestIdentity(), 200
		}
		if strings.HasPrefix(r.URL.Host, "logs.") {
			return fmt.Sprintf(`{"events":[{"eventId":"event","timestamp":%d,"logStreamName":"2026/10/20/[1]environment","message":"REPORT RequestId: fixture-report Duration: 12.4 ms Billed Duration: 113 ms Memory Size: 2048 MB Max Memory Used: 700 MB Init Duration: 100 ms"}]}`, at.UnixMilli()), 200
		}
		if strings.HasPrefix(r.URL.Host, "compute-optimizer.") {
			if !strings.Contains(b, "Unavailable") {
				t.Fatal("provider unavailable erased")
			}
			return `{"lambdaFunctionRecommendations":[{"accountId":"111122223333","functionArn":"` + lambdaTestARN + `","functionVersion":"1","finding":"Unavailable","findingReasonCodes":["Inconclusive"]}]}`, 200
		}
		t.Fatal("unexpected read")
		return "", 500
	})
	reg := lambdacost.Registration{ID: "reports", TenantID: lambdaTestScope.TenantID, Kind: lambdacost.ReportsKind, AccountID: lambdaTestScope.AccountID, Region: lambdaTestScope.Region, ReadRoleBindingID: "approved", FunctionARN: lambdaTestARN, Qualifier: "live", LogGroupARN: "arn:aws:logs:eu-west-1:111122223333:log-group:/aws/lambda/processor", LogGroupName: "/aws/lambda/processor", Format: "REPORT_TEXT", Version: 1, Enabled: true}
	reports, e := reader.LambdaReports(context.Background(), lambdaTestScope, reg, "1", at.Add(-time.Minute), at.Add(time.Minute), "")
	if e != nil || len(reports.Rows) != 1 || model.Bool(reports.Coverage, "invocation_census_complete") || model.String(reports.Rows[0], "billed_duration_ms") != "113" {
		t.Fatal(reports, e)
	}
	advice, _, e := reader.LambdaComputeOptimizer(context.Background(), lambdaTestScope, lambdaTestARN)
	if e != nil || len(lambdacost.Rows(advice["rows"])) != 1 {
		t.Fatal(advice, e)
	}
}
