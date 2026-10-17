package provider

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
)

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestLivePreflightRefreshesDelegationAndStorage(t *testing.T) {
	for _, tc := range []struct {
		name, environment, delegation, store string
		valid                                bool
	}{{"eligible", "NON_PRODUCTION", "true", "false", true}, {"production", "PRODUCTION", "true", "false", false}, {"revoked-delegation", "NON_PRODUCTION", "false", "false", false}, {"instance-store-hardware", "NON_PRODUCTION", "true", "true", false}} {
		t.Run(tc.name, func(t *testing.T) {
			client := &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
				body, _ := io.ReadAll(r.Body)
				v, _ := url.ParseQuery(string(body))
				response := ""
				switch v.Get("Action") {
				case "DescribeInstances":
					response = `<DescribeInstancesResponse><reservationSet><item><instancesSet><item><instanceId>i-pilot</instanceId><instanceType>m6i.large</instanceType><rootDeviceType>ebs</rootDeviceType><instanceState><name>running</name></instanceState><tagSet><item><key>finops:environment</key><value>` + tc.environment + `</value></item><item><key>finops:runtime-stop-start</key><value>` + tc.delegation + `</value></item><item><key>finops:standalone</key><value>true</value></item><item><key>finops:stable-network</key><value>true</value></item></tagSet></item></instancesSet></item></reservationSet></DescribeInstancesResponse>`
				case "DescribeInstanceTypes":
					response = `<DescribeInstanceTypesResponse><instanceTypeSet><item><instanceType>m6i.large</instanceType><instanceStorageSupported>` + tc.store + `</instanceStorageSupported></item></instanceTypeSet></DescribeInstanceTypesResponse>`
				default:
					t.Fatalf("unexpected mutating call: %s", v.Get("Action"))
				}
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(response)), Header: make(http.Header)}, nil
			})}
			a := &AWS{cfg: aws.Config{Region: "eu-west-1", Credentials: aws.NewCredentialsCache(credentials.NewStaticCredentialsProvider("fixture", "fixture", ""))}, client: client}
			e := a.Preflight(context.Background(), model.Operation{ProviderResourceID: "i-pilot", Region: "eu-west-1"}, model.Document{"instance_type": "m6i.large"})
			if (e == nil) != tc.valid {
				t.Fatalf("valid=%v, error=%v", tc.valid, e)
			}
		})
	}
}
func TestStopNeverForcesShutdown(t *testing.T) {
	calls := 0
	a := &AWS{cfg: aws.Config{Region: "eu-west-1", Credentials: aws.NewCredentialsCache(credentials.NewStaticCredentialsProvider("fixture", "fixture", ""))}, client: &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		calls++
		b, _ := io.ReadAll(r.Body)
		v, _ := url.ParseQuery(string(b))
		response := `<DescribeInstanceAttributeResponse><disableApiStop><value>false</value></disableApiStop></DescribeInstanceAttributeResponse>`
		if v.Get("Action") == "StopInstances" {
			if v.Get("Force") != "false" || v.Get("Hibernate") != "false" {
				t.Fatal("unsafe StopInstances parameters")
			}
			response = "<StopInstancesResponse/>"
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(response)), Header: make(http.Header)}, nil
	})}}
	if e := a.Stop(context.Background(), model.Operation{ProviderResourceID: "i-pilot", Region: "eu-west-1"}); e != nil {
		t.Fatal(e)
	}
	if calls != 2 {
		t.Fatal("stop protection precheck missing")
	}
}
