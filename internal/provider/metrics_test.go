package provider

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
)

type metricTestTransport func(*http.Request) (*http.Response, error)

func (f metricTestTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// The endpoint interception is private to this test. Production constructors
// expose no endpoint setting that can route signed AWS credentials elsewhere.
func metricsTestAWS(t *testing.T, handler http.HandlerFunc) *AWS {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	target, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: metricTestTransport(func(r *http.Request) (*http.Response, error) {
		copy := r.Clone(r.Context())
		copy.Host = r.URL.Host
		u := *r.URL
		u.Scheme, u.Host = target.Scheme, target.Host
		copy.URL = &u
		return http.DefaultTransport.RoundTrip(copy)
	})}
	return &AWS{cfg: aws.Config{Region: "eu-west-1", Credentials: aws.NewCredentialsCache(credentials.NewStaticCredentialsProvider("AKIDEXAMPLE", "fixture-not-a-real-secret", "fixture-session"))}, client: client}
}

func TestMetricsSignedHourlyRequestPreservesDecimalsAndMissingData(t *testing.T) {
	calls := 0
	a := metricsTestAWS(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		if err := r.ParseForm(); err != nil {
			t.Error(err)
			return
		}
		for key, expected := range map[string]string{"Action": "GetMetricStatistics", "Version": "2010-08-01", "Namespace": "AWS/EC2", "Period": "3600", "Statistics.member.1": "Maximum", "Dimensions.member.1.Name": "InstanceId", "Dimensions.member.1.Value": "i-0123456789abcdef0"} {
			if r.Form.Get(key) != expected {
				t.Errorf("%s = %q, want %q", key, r.Form.Get(key), expected)
			}
		}
		if r.Host != "monitoring.eu-west-1.amazonaws.com" || !strings.Contains(r.Header.Get("Authorization"), "/eu-west-1/monitoring/aws4_request") || r.Header.Get("X-Amz-Security-Token") != "fixture-session" || r.Header.Get("X-Amz-Date") == "" {
			t.Error("CloudWatch request was not signed for the configured regional service")
		}
		start, e1 := time.Parse(time.RFC3339, r.Form.Get("StartTime"))
		end, e2 := time.Parse(time.RFC3339, r.Form.Get("EndTime"))
		if e1 != nil || e2 != nil || end.Sub(start) != 14*24*time.Hour || end.Minute() != 0 || end.Second() != 0 {
			t.Error("invalid 14-day complete-hour window")
		}
		w.Header().Set("Content-Type", "text/xml")
		if r.Form.Get("MetricName") != "CPUUtilization" {
			fmt.Fprint(w, `<GetMetricStatisticsResponse><GetMetricStatisticsResult><Datapoints/></GetMetricStatisticsResult></GetMetricStatisticsResponse>`)
			return
		}
		if r.Form.Get("Unit") != "Percent" {
			t.Error("CPU unit not specified")
		}
		// Deliberately reverse order: CloudWatch does not promise chronological ordering.
		fmt.Fprintf(w, `<GetMetricStatisticsResponse xmlns="http://monitoring.amazonaws.com/doc/2010-08-01/"><GetMetricStatisticsResult><Datapoints><member><Timestamp>%s</Timestamp><Maximum>0.000000000000</Maximum><Unit>Percent</Unit></member><member><Timestamp>%s</Timestamp><Maximum>12.340000000001</Maximum><Unit>Percent</Unit></member></Datapoints></GetMetricStatisticsResult></GetMetricStatisticsResponse>`, start.Add(time.Hour).Format(time.RFC3339), start.Format(time.RFC3339))
	})
	rows, err := a.Metrics(context.Background(), "eu-west-1", "i-0123456789abcdef0")
	if err != nil {
		t.Fatal(err)
	}
	if calls != 3 || len(rows) != 2 {
		t.Fatalf("calls=%d, rows=%d; missing network data must stay absent", calls, len(rows))
	}
	if rows[0]["value"] != "12.340000000001" || rows[1]["value"] != "0.000000000000" {
		t.Fatalf("provider decimal strings lost: %#v", rows)
	}
	for _, row := range rows {
		if row["metric_name"] != "cpu_utilization" || row["statistic"] != "Maximum" {
			t.Fatalf("unexpected/fabricated observation: %#v", row)
		}
	}
}

func TestMetricsRejectsIncompleteObservationInsteadOfZero(t *testing.T) {
	a := metricsTestAWS(t, func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		fmt.Fprintf(w, `<GetMetricStatisticsResponse><GetMetricStatisticsResult><Datapoints><member><Timestamp>%s</Timestamp><Unit>Percent</Unit></member></Datapoints></GetMetricStatisticsResult></GetMetricStatisticsResponse>`, r.Form.Get("StartTime"))
	})
	if rows, err := a.Metrics(context.Background(), "eu-west-1", "i-0123456789abcdef0"); err == nil || rows != nil {
		t.Fatalf("incomplete metric accepted as usable data: rows=%#v err=%v", rows, err)
	}
}

func TestMetricsProviderFailureDoesNotBecomeEmptySuccess(t *testing.T) {
	a := metricsTestAWS(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `<ErrorResponse><Error><Code>AccessDenied</Code><Message>fixture failure</Message></Error></ErrorResponse>`)
	})
	_, err := a.Metrics(context.Background(), "eu-west-1", "i-0123456789abcdef0")
	if err == nil || !strings.Contains(err.Error(), "AccessDenied") {
		t.Fatalf("provider failure hidden: %v", err)
	}
}

func TestVolumesPaginatesAndPreservesAttachmentsWithoutInventingPrice(t *testing.T) {
	calls := 0
	a := metricsTestAWS(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		_ = r.ParseForm()
		if r.Form.Get("Action") != "DescribeVolumes" || !strings.Contains(r.Header.Get("Authorization"), "/eu-west-1/ec2/aws4_request") {
			t.Error("wrong operation or signing scope")
		}
		if calls == 1 {
			fmt.Fprint(w, `<DescribeVolumesResponse><volumeSet><item><volumeId>vol-0123456789abcdef0</volumeId><size>100</size><volumeType>gp3</volumeType><iops>3000</iops><throughput>125</throughput><availabilityZone>eu-west-1a</availabilityZone><status>in-use</status><encrypted>true</encrypted><attachmentSet><item><instanceId>i-0123456789abcdef0</instanceId><device>/dev/sda1</device><status>attached</status><deleteOnTermination>true</deleteOnTermination></item></attachmentSet></item></volumeSet><nextToken>next-page</nextToken></DescribeVolumesResponse>`)
			return
		}
		if r.Form.Get("NextToken") != "next-page" {
			t.Error("pagination token missing")
		}
		fmt.Fprint(w, `<DescribeVolumesResponse><volumeSet><item><volumeId>vol-0123456789abcdef1</volumeId><size>25</size><volumeType>gp2</volumeType><availabilityZone>eu-west-1b</availabilityZone><status>available</status></item></volumeSet></DescribeVolumesResponse>`)
	})
	rows, err := a.Volumes(context.Background(), "eu-west-1", "111122223333")
	if err != nil {
		t.Fatal(err)
	}
	if calls != 2 || len(rows) != 2 {
		t.Fatalf("pagination failed: calls=%d rows=%d", calls, len(rows))
	}
	if rows[0]["size_gib"] != "100" || rows[0]["encrypted"] != true || rows[0]["eligibility"] != "OBSERVE_ONLY" {
		t.Fatalf("volume facts lost: %#v", rows[0])
	}
	if _, found := rows[0]["hourly_effective_cost"]; found {
		t.Error("inventory invented a financial rate")
	}
	if len(rows[0]["attachments"].([]model.Document)) != 1 {
		t.Error("attachment topology missing")
	}
}
