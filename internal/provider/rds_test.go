package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

var rdsTestScope = RDSScope{"tenant-rds", "111122223333", "eu-west-1"}

const rdsTestARN = "arn:aws:rds:eu-west-1:111122223333:db:primary"

type rdsTransport func(*http.Request) (*http.Response, error)

func (f rdsTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func rdsTestAWS(t *testing.T, handler func(*http.Request, string) (string, int)) *AWS {
	t.Helper()
	return &AWS{cfg: aws.Config{Region: rdsTestScope.Region, Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		return aws.Credentials{AccessKeyID: "offline-read", SecretAccessKey: "offline-secret", SessionToken: "offline-session"}, nil
	})}, client: &http.Client{Transport: rdsTransport(func(r *http.Request) (*http.Response, error) {
		b, e := io.ReadAll(r.Body)
		if e != nil {
			t.Fatal(e)
		}
		if !strings.Contains(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256") {
			t.Fatal("unsigned read")
		}
		body, status := handler(r, string(b))
		return &http.Response{StatusCode: status, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body))}, nil
	})}}
}
func rdsTestPage(action, collection, records, marker string) string {
	if marker != "" {
		marker = "<Marker>" + marker + "</Marker>"
	}
	return "<" + action + "Response><" + action + "Result><" + collection + ">" + records + "</" + collection + ">" + marker + "</" + action + "Result></" + action + "Response>"
}
func rdsTestIdentity() string {
	return "<GetCallerIdentityResponse><GetCallerIdentityResult><Account>111122223333</Account><Arn>arn:aws:sts::111122223333:assumed-role/readonly/session</Arn><UserId>FIXTURE:session</UserId></GetCallerIdentityResult></GetCallerIdentityResponse>"
}
func rdsTestInstance(extra string) string {
	return "<DBInstance><DBInstanceIdentifier>primary</DBInstanceIdentifier><DBInstanceArn>" + rdsTestARN + "</DBInstanceArn><DbiResourceId>db-NATIVEINCARNATION</DbiResourceId><DBInstanceClass>db.r6g.large</DBInstanceClass><Engine>postgres</Engine><EngineVersion>16.4</EngineVersion><LicenseModel>postgresql-license</LicenseModel><DBInstanceStatus>available</DBInstanceStatus><StorageType>gp3</StorageType><AllocatedStorage>100</AllocatedStorage><DBParameterGroups><DBParameterGroup><DBParameterGroupName>native-parameters</DBParameterGroupName><ParameterApplyStatus>in-sync</ParameterApplyStatus></DBParameterGroup></DBParameterGroups>" + extra + "</DBInstance>"
}
func rdsTestDefault(t *testing.T, r *http.Request, body string) (string, int) {
	t.Helper()
	v, _ := url.ParseQuery(body)
	switch v.Get("Action") {
	case "GetCallerIdentity":
		return rdsTestIdentity(), 200
	case "DescribeDBInstances":
		return rdsTestPage("DescribeDBInstances", "DBInstances", rdsTestInstance(""), ""), 200
	case "DescribeDBClusters":
		return rdsTestPage("DescribeDBClusters", "DBClusters", "", ""), 200
	case "DescribeReservedDBInstances":
		return rdsTestPage("DescribeReservedDBInstances", "ReservedDBInstances", "", ""), 200
	case "DescribeValidDBInstanceModifications":
		if v.Get("DBInstanceIdentifier") != rdsTestARN {
			t.Fatal("modification read lost exact native ARN")
		}
		return rdsTestModifications(""), 200
	}
	t.Fatalf("unplanned operation %s %s", r.URL, body)
	return "", 500
}
func TestRDSDiscoveryNativeScopePaginationAndUnknownFields(t *testing.T) {
	calls := 0
	a := rdsTestAWS(t, func(r *http.Request, b string) (string, int) {
		v, _ := url.ParseQuery(b)
		if v.Get("Action") == "DescribeDBInstances" {
			calls++
			if v.Get("Marker") == "" {
				return rdsTestPage("DescribeDBInstances", "DBInstances", rdsTestInstance("<UnprojectedSetting>preserved</UnprojectedSetting>"), "next"), 200
			}
			if v.Get("Marker") != "next" {
				t.Fatal("wrong native continuation")
			}
			return rdsTestPage("DescribeDBInstances", "DBInstances", "", ""), 200
		}
		return rdsTestDefault(t, r, b)
	})
	out, e := a.RDSDiscover(context.Background(), rdsTestScope)
	if e != nil || calls != 2 || len(out.Instances) != 1 || len(out.Callers) != 1 {
		t.Fatalf("native point read failed %v", e)
	}
	row := out.Instances[0]
	if row["multi_az"] != nil || row["iops"] != nil || model.String(row, "resource_id") != "db-NATIVEINCARNATION" {
		t.Fatal("unknown optional value fabricated or incarnation lost")
	}
	if !strings.Contains(string(out.Raw), "UnprojectedSetting") || strings.Contains(string(out.Raw), "offline-secret") || out.RawSHA256 != rdsSHA(out.Raw) {
		t.Fatal("raw/native or secret boundary lost")
	}
	pages, e := RDSCaptureFrames(out.Raw)
	if e != nil || len(pages) != 5 {
		t.Fatalf("exact frame closure %v %d", e, len(pages))
	}
	for _, bad := range []string{strings.Replace(rdsTestInstance(""), "111122223333", "999988887777", 1), rdsTestInstance("<DBInstanceArn>" + rdsTestARN + "</DBInstanceArn>")} {
		a := rdsTestAWS(t, func(r *http.Request, b string) (string, int) {
			v, _ := url.ParseQuery(b)
			if v.Get("Action") == "DescribeDBInstances" {
				return rdsTestPage("DescribeDBInstances", "DBInstances", bad, ""), 200
			}
			return rdsTestDefault(t, r, b)
		})
		if out, e := a.RDSDiscover(context.Background(), rdsTestScope); e == nil || len(out.Instances) != 0 || out.Raw != nil {
			t.Fatal("foreign or duplicate native identity accepted")
		}
	}
	for _, kind := range []string{"instance", "cluster"} {
		t.Run(kind+"_pending_modifications", func(t *testing.T) {
			for _, tc := range []struct {
				name, native     string
				unknown, invalid bool
			}{
				{name: "absent_unknown", unknown: true},
				{name: "explicit_empty", native: "<PendingModifiedValues/>"},
				{name: "native_nested", native: "<PendingModifiedValues><DBInstanceClass>db.r6g.xlarge</DBInstanceClass><UnprojectedSetting><Mode>native-only</Mode></UnprojectedSetting></PendingModifiedValues>"},
				{name: "duplicate_refused", native: "<PendingModifiedValues><DBInstanceClass>a</DBInstanceClass><DBInstanceClass>b</DBInstanceClass></PendingModifiedValues>", invalid: true},
				{name: "scalar_refused", native: "<PendingModifiedValues>unknown-format</PendingModifiedValues>", invalid: true},
			} {
				t.Run(tc.name, func(t *testing.T) {
					a := rdsTestAWS(t, func(r *http.Request, b string) (string, int) {
						v, _ := url.ParseQuery(b)
						if v.Get("Action") == "DescribeDBInstances" {
							row := ""
							if kind == "instance" {
								row = rdsTestInstance(tc.native)
							}
							return rdsTestPage("DescribeDBInstances", "DBInstances", row, ""), 200
						}
						if v.Get("Action") == "DescribeDBClusters" && kind == "cluster" {
							row := "<DBCluster><DBClusterArn>arn:aws:rds:eu-west-1:111122223333:cluster:primary</DBClusterArn><DBClusterIdentifier>primary</DBClusterIdentifier><DbClusterResourceId>cluster-NATIVEINCARNATION</DbClusterResourceId><Engine>aurora-postgresql</Engine><Status>available</Status>" + tc.native + "</DBCluster>"
							return rdsTestPage("DescribeDBClusters", "DBClusters", row, ""), 200
						}
						return rdsTestDefault(t, r, b)
					})
					got, err := a.RDSDiscover(context.Background(), rdsTestScope)
					if tc.invalid {
						if err == nil || got.Raw != nil || len(got.Instances)+len(got.Clusters) != 0 {
							t.Fatal("malformed pending values issued evidence")
						}
						return
					}
					if err != nil {
						t.Fatal(err)
					}
					rows := got.Instances
					if kind == "cluster" {
						rows = got.Clusters
					}
					if len(rows) != 1 {
						t.Fatal("native resource lost")
					}
					pending, ok := rows[0]["pending_modified_values"].(model.Document)
					if !ok || (pending == nil) != tc.unknown {
						t.Fatal("pending absence and explicit empty collapsed")
					}
					if tc.name == "explicit_empty" && len(pending) != 0 {
						t.Fatal("native empty became a pending change")
					}
					if tc.name == "native_nested" {
						p, _ := json.Marshal(pending)
						if len(pending) != 2 || !strings.Contains(string(p), "native-only") || !strings.Contains(string(p), "db.r6g.xlarge") {
							t.Fatal("complete native pending fields lost")
						}
						changed := strings.Replace(string(p), "db.r6g.xlarge", "db.r6g.2xlarge", 1)
						if rdsSHA(p) == rdsSHA([]byte(changed)) {
							t.Fatal("pending native correction did not change projected bytes")
						}
					}
					if model.String(rows[0], "status") != "available" || !strings.Contains(string(got.Raw), tc.native) {
						t.Fatal("pending projection rewrote native status/raw")
					}
					for _, flag := range []string{"ready", "execution_authorized", "configuration_authorized"} {
						if _, exists := rows[0][flag]; exists {
							t.Fatal("point pending read issued authority")
						}
					}
				})
			}
		})
	}
}
func TestRDSMetricsNativeSampleCountsDoNotFillMissingBins(t *testing.T) {
	end := time.Now().UTC().Truncate(time.Hour)
	start := end.Add(-2 * time.Hour)
	reads := 0
	a := rdsTestAWS(t, func(r *http.Request, b string) (string, int) {
		v, _ := url.ParseQuery(b)
		if v.Get("Action") == "GetMetricStatistics" {
			reads++
			if v.Get("Namespace") != "AWS/RDS" || v.Get("Dimensions.member.1.Value") != "primary" || v.Get("Statistics.member.2") != "SampleCount" {
				t.Fatal("native CW selector altered")
			}
			point := fmt.Sprintf("<member><Timestamp>%s</Timestamp><%s>0</%s><SampleCount>60.0</SampleCount><Unit>%s</Unit></member>", start.Format(time.RFC3339), v.Get("Statistics.member.1"), v.Get("Statistics.member.1"), v.Get("Unit"))
			return rdsTestPage("GetMetricStatistics", "Datapoints", point, ""), 200
		}
		return rdsTestDefault(t, r, b)
	})
	out, e := a.RDSMetrics(context.Background(), rdsTestScope, RDSMetricSelection{rdsTestARN, start, end, 3600})
	if e != nil || reads != len(rdsInstanceMetrics) || len(out.Metrics) != reads {
		t.Fatalf("native CW capture %v", e)
	}
	for _, row := range out.Metrics {
		if row["value"] != "0" || row["sample_count"] != int64(60) {
			t.Fatal("native zero/count changed")
		}
	}
	for _, c := range out.Coverage {
		if c["status"] == "NOT_APPLICABLE_NATIVE_PRIMARY" {
			continue
		}
		if c["missing_points"] != 1 || c["status"] != "INCOMPLETE_OR_UNKNOWN_SAMPLES" {
			t.Fatal("missing bin became observed zero")
		}
	}
}
func TestRDSParametersLiteralVersusFormulaAndPendingApply(t *testing.T) {
	for _, tc := range []struct {
		name, value, status string
		known               bool
	}{{"literal", "100", "in-sync", true}, {"formula", "LEAST({DBInstanceClassMemory/9531392},5000)", "in-sync", false}, {"pending", "100", "pending-reboot", false}} {
		t.Run(tc.name, func(t *testing.T) {
			a := rdsTestAWS(t, func(r *http.Request, b string) (string, int) {
				v, _ := url.ParseQuery(b)
				if v.Get("Action") == "DescribeDBParameters" {
					return rdsTestPage("DescribeDBParameters", "Parameters", "<Parameter><ParameterName>max_connections</ParameterName><ParameterValue>"+tc.value+"</ParameterValue><Source>user</Source><ApplyType>dynamic</ApplyType></Parameter>", ""), 200
				}
				body, status := rdsTestDefault(t, r, b)
				if v.Get("Action") == "DescribeDBInstances" {
					body = strings.ReplaceAll(body, "<ParameterApplyStatus>in-sync</ParameterApplyStatus>", "<ParameterApplyStatus>"+tc.status+"</ParameterApplyStatus>")
				}
				return body, status
			})
			out, e := a.RDSParameters(context.Background(), rdsTestScope, rdsTestARN)
			if e != nil || (out.ConnectionCapacity != nil) != tc.known {
				t.Fatalf("effective connection capacity %v %+v", e, out)
			}
			if model.String(out.Parameters[0], "value") != tc.value {
				t.Fatal("native formula/literal replaced")
			}
		})
	}
}

func TestRDSReplicaLagNativeSentinelStaysUnknown(t *testing.T) {
	end := time.Now().UTC().Truncate(time.Hour)
	start := end.Add(-time.Hour)
	a := rdsTestAWS(t, func(r *http.Request, b string) (string, int) {
		v, _ := url.ParseQuery(b)
		if v.Get("Action") == "DescribeDBInstances" {
			return rdsTestPage("DescribeDBInstances", "DBInstances", rdsTestInstance("<ReadReplicaSourceDBInstanceIdentifier>upstream</ReadReplicaSourceDBInstanceIdentifier>"), ""), 200
		}
		if v.Get("Action") == "GetMetricStatistics" {
			value := "0"
			if v.Get("MetricName") == "ReplicaLag" {
				value = "-1"
				if v.Get("Unit") != "Seconds" {
					t.Fatal("native replica unit changed")
				}
			}
			point := fmt.Sprintf("<member><Timestamp>%s</Timestamp><%s>%s</%s><SampleCount>60</SampleCount><Unit>%s</Unit></member>", start.Format(time.RFC3339), v.Get("Statistics.member.1"), value, v.Get("Statistics.member.1"), v.Get("Unit"))
			return rdsTestPage("GetMetricStatistics", "Datapoints", point, ""), 200
		}
		return rdsTestDefault(t, r, b)
	})
	out, e := a.RDSMetrics(context.Background(), rdsTestScope, RDSMetricSelection{rdsTestARN, start, end, 3600})
	if e != nil {
		t.Fatal(e)
	}
	found := false
	for _, v := range out.Metrics {
		if v["metric"] == "ReplicaLag" {
			found = true
			if v["value"] != nil || v["native_value"] != "-1" || v["unknown_reason"] != "NATIVE_REPLICA_LAG_UNAVAILABLE_SENTINEL" {
				t.Fatal("unknown native lag turned healthy")
			}
		}
	}
	if !found {
		t.Fatal("replica lag was not collected")
	}
}
