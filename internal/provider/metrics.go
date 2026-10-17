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
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
)

var metricInstanceID = regexp.MustCompile(`^i-(?:[0-9a-f]{8}|[0-9a-f]{17})$`)
var metricNumber = regexp.MustCompile(`^[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?$`)
var metricAccountID = regexp.MustCompile(`^[0-9]{12}$`)

// Metrics reads 14 days of observations ending at the last complete UTC hour.
// Maximum is the maximum reported sample in each hour, not a forecast or a
// percentile. Missing datapoints remain absent; memory is never inferred.
func (a *AWS) Metrics(ctx context.Context, region, providerInstanceID string) ([]model.Document, error) {
	if !validRegion(region) || !metricInstanceID.MatchString(providerInstanceID) {
		return nil, errors.New("valid AWS region and EC2 instance ID required")
	}
	end := time.Now().UTC().Truncate(time.Hour)
	start := end.Add(-14 * 24 * time.Hour)
	metrics := []struct{ source, canonical, unit string }{
		{"CPUUtilization", "cpu_utilization", "Percent"},
		{"NetworkIn", "network_in", "Bytes"},
		{"NetworkOut", "network_out", "Bytes"},
	}
	rows := []model.Document{}
	for _, metric := range metrics {
		values := url.Values{
			"Namespace": {"AWS/EC2"}, "MetricName": {metric.source},
			"Dimensions.member.1.Name": {"InstanceId"}, "Dimensions.member.1.Value": {providerInstanceID},
			"StartTime": {start.Format(time.RFC3339)}, "EndTime": {end.Format(time.RFC3339)},
			"Period": {"3600"}, "Statistics.member.1": {"Maximum"}, "Unit": {metric.unit},
		}
		var response struct {
			Result struct {
				Datapoints []struct {
					Timestamp string `xml:"Timestamp"`
					Maximum   string `xml:"Maximum"`
					Unit      string `xml:"Unit"`
				} `xml:"Datapoints>member"`
			} `xml:"GetMetricStatisticsResult"`
		}
		if err := a.cloudWatchQuery(ctx, region, values, &response); err != nil {
			return nil, err
		}
		for _, point := range response.Result.Datapoints {
			at, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(point.Timestamp))
			if err != nil || at.Before(start) || !at.Before(end) {
				return nil, fmt.Errorf("CloudWatch %s returned an invalid observation timestamp", metric.source)
			}
			value := strings.TrimSpace(point.Maximum)
			if !metricNumber.MatchString(value) || point.Unit != metric.unit {
				return nil, fmt.Errorf("CloudWatch %s returned a missing/invalid maximum or unit", metric.source)
			}
			rows = append(rows, model.Document{
				"provider": "AWS", "region": region,
				"resource_id": providerInstanceID, "provider_resource_id": providerInstanceID,
				"metric_name": metric.canonical, "source_metric_name": metric.source,
				"source_time": at.UTC().Format(time.RFC3339Nano), "value": value,
				"unit": point.Unit, "statistic": "Maximum", "period_seconds": 3600,
			})
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		left, right := model.String(rows[i], "metric_name"), model.String(rows[j], "metric_name")
		if left != right {
			return left < right
		}
		return model.String(rows[i], "source_time") < model.String(rows[j], "source_time")
	})
	return rows, nil
}

// cloudWatchQuery deliberately has no endpoint environment override. Tests
// replace only the private HTTP transport; production always signs the regional
// AWS monitoring endpoint using the configured customer read-role identity.
func (a *AWS) cloudWatchQuery(ctx context.Context, region string, values url.Values, out any) error {
	values.Set("Action", "GetMetricStatistics")
	values.Set("Version", "2010-08-01")
	body := values.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://monitoring."+region+".amazonaws.com/", strings.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if a.cfg.Credentials == nil {
		return errors.New("CloudWatch customer credentials required")
	}
	creds, err := a.cfg.Credentials.Retrieve(ctx)
	if err != nil {
		return err
	}
	sum := sha256.Sum256([]byte(body))
	if err = v4.NewSigner().SignHTTP(ctx, creds, req, hex.EncodeToString(sum[:]), "monitoring", region, time.Now().UTC()); err != nil {
		return err
	}
	client := a.client
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 16<<20))
	if err != nil {
		return err
	}
	if res.StatusCode/100 != 2 {
		var failure struct {
			Error struct {
				Code string `xml:"Code"`
			} `xml:"Error"`
		}
		_ = xml.Unmarshal(raw, &failure)
		code := failure.Error.Code
		if code == "" {
			code = "ProviderError"
		}
		return fmt.Errorf("AWS GetMetricStatistics failed: %s (%d)", code, res.StatusCode)
	}
	return xml.Unmarshal(raw, out)
}

// Volumes discovers EBS inventory and attachment topology. Its data does not
// imply that retained volumes disappear, become free, or can be deleted.
func (a *AWS) Volumes(ctx context.Context, region, account string) ([]model.Document, error) {
	if !validRegion(region) || !metricAccountID.MatchString(account) {
		return nil, errors.New("valid AWS region and 12-digit account required")
	}
	rows := []model.Document{}
	token := ""
	for page := 0; page < 1000; page++ {
		values := url.Values{"MaxResults": {"500"}}
		if token != "" {
			values.Set("NextToken", token)
		}
		var response struct {
			Volumes []struct {
				ID          string `xml:"volumeId"`
				Type        string `xml:"volumeType"`
				Size        string `xml:"size"`
				IOPS        string `xml:"iops"`
				Throughput  string `xml:"throughput"`
				Zone        string `xml:"availabilityZone"`
				State       string `xml:"status"`
				Encrypted   bool   `xml:"encrypted"`
				Attachments []struct {
					Instance            string `xml:"instanceId"`
					Device              string `xml:"device"`
					State               string `xml:"status"`
					DeleteOnTermination bool   `xml:"deleteOnTermination"`
				} `xml:"attachmentSet>item"`
				Tags []struct {
					Key   string `xml:"key"`
					Value string `xml:"value"`
				} `xml:"tagSet>item"`
			} `xml:"volumeSet>item"`
			Next string `xml:"nextToken"`
		}
		if err := a.query(ctx, region, "DescribeVolumes", values, &response); err != nil {
			return nil, err
		}
		for _, volume := range response.Volumes {
			if volume.ID == "" {
				return nil, errors.New("EBS inventory returned missing volume identity")
			}
			attachments := []model.Document{}
			for _, attached := range volume.Attachments {
				attachments = append(attachments, model.Document{"provider_resource_id": attached.Instance, "device": attached.Device, "state": attached.State, "delete_on_termination": attached.DeleteOnTermination})
			}
			tags := map[string]string{}
			for _, tag := range volume.Tags {
				tags[tag.Key] = tag.Value
			}
			name := tags["Name"]
			if name == "" {
				name = volume.ID
			}
			row := model.Document{"name": name, "provider": "AWS", "resource_type": "EBS", "provider_resource_id": volume.ID, "account_id": account, "region": region, "zone": volume.Zone, "state": volume.State, "volume_type": volume.Type, "size_gib": volume.Size, "encrypted": volume.Encrypted, "attachments": attachments, "tags": tags, "configuration_authority": "UNKNOWN", "eligibility": "OBSERVE_ONLY", "last_seen_at": model.Now()}
			if volume.IOPS != "" {
				row["provisioned_iops"] = volume.IOPS
			}
			if volume.Throughput != "" {
				row["provisioned_throughput_mibps"] = volume.Throughput
			}
			rows = append(rows, row)
		}
		if response.Next == "" {
			return rows, nil
		}
		if response.Next == token {
			return nil, errors.New("EBS inventory repeated pagination token")
		}
		token = response.Next
	}
	return nil, errors.New("EBS inventory pagination limit exceeded")
}
