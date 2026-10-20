package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

func ebsHistoryFixture(t *testing.T, r *http.Request, body string, start time.Time, mutate func(string, model.Document) model.Document) (string, int) {
	t.Helper()
	target := r.Header.Get("X-Amz-Target")
	if target == "" {
		return ebsTestNative(t, r, body)
	}
	if target == "com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101.LookupEvents" {
		if r.URL.Host != "cloudtrail.eu-west-1.amazonaws.com" || r.Header.Get("Content-Type") != "application/x-amz-json-1.1" || !strings.Contains(r.Header.Get("Authorization"), "/eu-west-1/cloudtrail/aws4_request") {
			t.Fatal("CloudTrail native protocol mismatch")
		}
		var request model.Document
		if rdsJSON([]byte(body), &request) != nil || model.Number(request, "MaxResults") != 50 || request["EventCategory"] != nil {
			t.Fatal("CloudTrail bounded management selector missing")
		}
		attrs := ebsDocuments(request["LookupAttributes"])
		if len(attrs) != 1 || attrs[0]["AttributeKey"] != "EventSource" || attrs[0]["AttributeValue"] != "config.amazonaws.com" {
			t.Fatal("CloudTrail source filter differs")
		}
		first, fe := ebsConfigTime(request["StartTime"])
		last, le := ebsConfigTime(request["EndTime"])
		if fe != nil || le != nil || first.After(start) || last.Before(time.Now().UTC().Add(-time.Minute)) || !first.Before(last) {
			t.Fatal("CloudTrail window differs")
		}
		out := model.Document{"Events": []model.Document{}}
		if mutate != nil {
			out = mutate("LookupEvents", out)
		}
		raw, e := json.Marshal(out)
		if e != nil {
			t.Fatal(e)
		}
		return string(raw), 200
	}
	if r.URL.Host != "config.eu-west-1.amazonaws.com" || r.Header.Get("Content-Type") != "application/x-amz-json-1.1" || !strings.HasPrefix(target, "StarlingDoveService.") {
		t.Fatal("Config native protocol mismatch")
	}
	action := strings.TrimPrefix(target, "StarlingDoveService.")
	var p model.Document
	if json.Unmarshal([]byte(body), &p) != nil {
		t.Fatal("invalid Config request")
	}
	out := model.Document{}
	switch action {
	case "DescribeConfigurationRecorders":
		out["ConfigurationRecorders"] = []model.Document{{"name": "component-continuous", "roleARN": "arn:aws:iam::111122223333:role/recording", "recordingGroup": model.Document{"allSupported": false, "resourceTypes": []string{"AWS::EC2::Volume", "AWS::EC2::Instance"}}, "recordingMode": model.Document{"recordingFrequency": "CONTINUOUS"}}}
	case "DescribeConfigurationRecorderStatus":
		out["ConfigurationRecordersStatus"] = []model.Document{{"name": "component-continuous", "recording": true, "lastStartTime": start.Add(-24 * time.Hour).Unix(), "lastStatus": "Success"}}
	case "GetResourceConfigHistory":
		early := int64(p["earlierTime"].(float64))
		late := int64(p["laterTime"].(float64))
		if late-early > 7*24*3600 || late <= early {
			t.Fatal("unbounded native history query")
		}
		kind, id := model.String(p, "resourceType"), model.String(p, "resourceId")
		arnKind := "volume"
		if kind == "AWS::EC2::Instance" {
			arnKind = "instance"
		}
		at := early
		if model.String(p, "chronologicalOrder") == "Reverse" {
			at = late - 60
		}
		out["configurationItems"] = []model.Document{{"accountId": "111122223333", "awsRegion": "eu-west-1", "arn": "arn:aws:ec2:eu-west-1:111122223333:" + arnKind + "/" + id, "resourceId": id, "resourceType": kind, "configurationStateId": time.Unix(at, 0).UTC().Format(time.RFC3339), "configurationItemStatus": "OK", "configurationItemCaptureTime": at, "recordingFrequency": "CONTINUOUS", "configuration": `{"volumeId":"` + id + `","size":100,"volumeType":"gp2","attachments":[]}`}}
	default:
		t.Fatal("unexpected Config action", action)
	}
	if mutate != nil {
		out = mutate(action, out)
	}
	raw, e := json.Marshal(out)
	if e != nil {
		t.Fatal(e)
	}
	return string(raw), 200
}
func TestEBSConfigurationHistoryNativeProtocolBoundsAndRecordedBasis(t *testing.T) {
	end := time.Now().UTC().Truncate(24 * time.Hour)
	start := end.Add(-14 * 24 * time.Hour)
	a := rdsTestAWS(t, func(r *http.Request, b string) (string, int) { return ebsHistoryFixture(t, r, b, start, nil) })
	out, e := a.EBSConfigurationHistory(context.Background(), ebsTestScope, "AWS::EC2::Volume", ebsTestVolumeID, start, end)
	if e != nil || out.Baseline == nil || len(out.Items) != 2 || len(out.Recorders) != 1 || len(out.RecorderStatuses) != 1 {
		t.Fatal("native Config history unavailable", e)
	}
	if out.Basis != "AWS_CONFIG_RECORDED_CONFIGURATION_HISTORY" || out.Status != "RECORDED_HISTORY_REQUIRES_RECORDER_AND_CONFIGURATION_VALIDATION" || model.String(out.Baseline, "configurationItemStatus") != "OK" {
		t.Fatal("recorded history overclaimed")
	}
	pages, e := EBSCaptureFrames(out.Raw)
	if e != nil || len(pages) != 7 {
		t.Fatal("history raw/source closure differs", e, len(pages))
	}
	for _, p := range pages {
		if p.Service == "config" && p.Action == "GetResourceConfigHistory" && !strings.Contains(p.Selector, ebsTestVolumeID) {
			t.Fatal("history selector lost")
		}
	}
	control := out.RecorderControlHistory
	if model.String(control, "status") != "COMPLETE_ENUMERATION" || model.String(control, "account_id") != ebsTestScope.AccountID || model.String(control, "region") != ebsTestScope.Region || control["collected_at"] == nil || len(ebsDocuments(control["events"])) != 0 || !strings.Contains(strings.Join(model.Strings(control, "reason_codes"), " "), "EVENTUALLY_AVAILABLE") || out.RecorderStatuses[0]["lastStatus"] != "Success" {
		t.Fatal("native control audit/casing/basis missing")
	}
}

func ebsHistoryTrailEvent(name, id string, at time.Time, read bool) model.Document {
	native := model.Document{"eventVersion": "1.11", "eventID": id, "eventName": name, "eventTime": at.Format(time.RFC3339Nano), "eventSource": "config.amazonaws.com", "recipientAccountId": ebsTestScope.AccountID, "awsRegion": ebsTestScope.Region, "eventType": "AwsApiCall", "eventCategory": "Management", "managementEvent": true, "readOnly": read, "requestParameters": model.Document{"configurationRecorderName": "component-continuous"}}
	raw, _ := json.Marshal(native)
	return model.Document{"EventId": id, "EventName": name, "EventTime": json.Number(strconv.FormatInt(at.Unix(), 10)), "EventSource": "config.amazonaws.com", "ReadOnly": fmt.Sprint(read), "CloudTrailEvent": string(raw)}
}

func TestEBSConfigurationHistoryCloudTrailPagesAndRecorderChanges(t *testing.T) {
	end := time.Now().UTC().Truncate(24 * time.Hour)
	start := end.Add(-14 * 24 * time.Hour)
	for _, name := range []string{"DescribeConfigurationRecorders", "PutEvaluations", "PutExternalEvaluation", "StartConfigRulesEvaluation", "PutConfigurationRecorder", "DeleteConfigurationRecorder", "StartConfigurationRecorder", "StopConfigurationRecorder", "PutServiceLinkedConfigurationRecorder", "DeleteServiceLinkedConfigurationRecorder", "PutThirdPartyServiceLinkedConfigurationRecorder", "AssociateResourceTypes", "DisassociateResourceTypes", "FutureConfigManagementWrite"} {
		t.Run(name, func(t *testing.T) {
			calls := 0
			read := name == "DescribeConfigurationRecorders"
			unchanged := read || name == "PutEvaluations" || name == "PutExternalEvaluation" || name == "StartConfigRulesEvaluation"
			a := rdsTestAWS(t, func(r *http.Request, b string) (string, int) {
				return ebsHistoryFixture(t, r, b, start, func(action string, d model.Document) model.Document {
					if action == "LookupEvents" {
						calls++
						if calls == 1 {
							event := ebsHistoryTrailEvent(name, "00000000-0000-4000-8000-000000000001", start.Add(time.Hour), read)
							d["Events"] = []model.Document{event}
							d["NextToken"] = "page-two"
						} else {
							if !strings.Contains(b, `"NextToken":"page-two"`) {
								t.Fatal("pagination selector lost")
							}
						}
					}
					return d
				})
			})
			out, e := a.EBSConfigurationHistory(context.Background(), ebsTestScope, "AWS::EC2::Volume", ebsTestVolumeID, start, end)
			if e != nil || calls != 2 || model.String(out.RecorderControlHistory, "status") != "COMPLETE_ENUMERATION" || len(ebsDocuments(out.RecorderControlHistory["events"])) != 1 {
				t.Fatal("bounded native event enumeration failed", e, out.ReasonCodes)
			}
			if unchanged {
				if out.Status == "HISTORY_UNAVAILABLE" || len(ebsDocuments(out.RecorderControlHistory["relevant_changes"])) != 0 {
					t.Fatal("read-only/evaluation management event became recorder change")
				}
				if ebsDocuments(out.RecorderControlHistory["events"])[0]["read_only"] != read {
					t.Fatal("native write flag was relabeled read-only")
				}
			} else if out.Status != "HISTORY_UNAVAILABLE" || len(ebsDocuments(out.RecorderControlHistory["relevant_changes"])) != 1 {
				t.Fatal("recorder or unknown Config write promoted")
			}
			frames, e := EBSCaptureFrames(out.Raw)
			if e != nil {
				t.Fatal(e)
			}
			retained := 0
			for _, f := range frames {
				if f.Service == "cloudtrail" {
					retained++
					if f.Action != "LookupEvents" || !strings.Contains(f.Selector, "config.amazonaws.com") {
						t.Fatal("audit raw selector lost")
					}
				}
			}
			if retained != 2 {
				t.Fatal("audit raw pages missing")
			}
		})
	}
}

func TestEBSConfigurationHistoryCloudTrailUnavailableAndMalformed(t *testing.T) {
	end := time.Now().UTC().Truncate(24 * time.Hour)
	start := end.Add(-14 * 24 * time.Hour)
	for _, kind := range []string{"denied", "loop", "missing-events", "bad-token", "foreign", "wrong-region", "wrong-source", "wrong-time", "mismatched-id", "missing-management", "wrong-readonly", "invalid-inner-json", "disguised-recorder-write"} {
		t.Run(kind, func(t *testing.T) {
			a := rdsTestAWS(t, func(r *http.Request, b string) (string, int) {
				if kind == "denied" && strings.HasSuffix(r.Header.Get("X-Amz-Target"), ".LookupEvents") {
					return `{"__type":"AccessDeniedException"}`, 400
				}
				return ebsHistoryFixture(t, r, b, start, func(action string, d model.Document) model.Document {
					if action != "LookupEvents" {
						return d
					}
					if kind == "loop" {
						d["NextToken"] = "same"
						return d
					}
					if kind == "missing-events" {
						delete(d, "Events")
						return d
					}
					if kind == "bad-token" {
						d["NextToken"] = 12
						return d
					}
					event := ebsHistoryTrailEvent("DescribeConfigurationRecorders", "00000000-0000-4000-8000-000000000001", start.Add(time.Hour), true)
					var native model.Document
					_ = json.Unmarshal([]byte(model.String(event, "CloudTrailEvent")), &native)
					switch kind {
					case "foreign":
						native["recipientAccountId"] = "999988887777"
					case "wrong-region":
						native["awsRegion"] = "us-east-1"
					case "wrong-source":
						native["eventSource"] = "ec2.amazonaws.com"
					case "wrong-time":
						native["eventTime"] = end.Add(time.Hour).Format(time.RFC3339Nano)
					case "mismatched-id":
						native["eventID"] = "00000000-0000-4000-8000-000000000002"
					case "missing-management":
						delete(native, "managementEvent")
					case "wrong-readonly":
						native["readOnly"] = false
					case "disguised-recorder-write":
						native["eventName"] = "PutConfigurationRecorder"
						event["EventName"] = "PutConfigurationRecorder"
					}
					raw, _ := json.Marshal(native)
					event["CloudTrailEvent"] = string(raw)
					if kind == "invalid-inner-json" {
						event["CloudTrailEvent"] = "{"
					}
					d["Events"] = []model.Document{event}
					return d
				})
			})
			out, e := a.EBSConfigurationHistory(context.Background(), ebsTestScope, "AWS::EC2::Volume", ebsTestVolumeID, start, end)
			if e != nil || out.Status != "HISTORY_UNAVAILABLE" || model.String(out.RecorderControlHistory, "status") != "UNAVAILABLE" {
				t.Fatal("unknown/foreign/partial control audit promoted", e, kind)
			}
		})
	}
	oldStart := end.Add(-90 * 24 * time.Hour)
	a := rdsTestAWS(t, func(r *http.Request, b string) (string, int) {
		if strings.HasSuffix(r.Header.Get("X-Amz-Target"), ".LookupEvents") {
			t.Fatal("out-of-retention API call")
		}
		return ebsHistoryFixture(t, r, b, oldStart, nil)
	})
	out, e := a.EBSConfigurationHistory(context.Background(), ebsTestScope, "AWS::EC2::Volume", ebsTestVolumeID, oldStart, end)
	if e != nil || out.Status != "HISTORY_UNAVAILABLE" || model.String(out.RecorderControlHistory, "status") != "UNAVAILABLE" {
		t.Fatal("old baseline promoted", e)
	}
}
func TestEBSConfigurationHistoryForeignAndUnavailableRefused(t *testing.T) {
	end := time.Now().UTC().Truncate(24 * time.Hour)
	start := end.Add(-14 * 24 * time.Hour)
	for _, kind := range []string{"foreign", "no-baseline", "denied", "daily"} {
		t.Run(kind, func(t *testing.T) {
			a := rdsTestAWS(t, func(r *http.Request, b string) (string, int) {
				if kind == "denied" && strings.HasSuffix(r.Header.Get("X-Amz-Target"), "DescribeConfigurationRecorders") {
					return `{"__type":"NoAvailableConfigurationRecorderException"}`, 400
				}
				return ebsHistoryFixture(t, r, b, start, func(action string, d model.Document) model.Document {
					if action == "GetResourceConfigHistory" {
						rows := d["configurationItems"].([]model.Document)
						if kind == "foreign" {
							rows[0]["accountId"] = "999988887777"
						}
						if kind == "no-baseline" {
							d["configurationItems"] = []model.Document{}
						}
					}
					if kind == "daily" && action == "DescribeConfigurationRecorders" {
						d["ConfigurationRecorders"].([]model.Document)[0]["recordingMode"] = model.Document{"recordingFrequency": "DAILY"}
					}
					return d
				})
			})
			got, e := a.EBSConfigurationHistory(context.Background(), ebsTestScope, "AWS::EC2::Volume", ebsTestVolumeID, start, end)
			switch kind {
			case "foreign":
				if e == nil {
					t.Fatal("foreign history accepted")
				}
			case "no-baseline", "denied":
				if e != nil || got.Status != "HISTORY_UNAVAILABLE" || got.Baseline != nil {
					t.Fatal("missing native history promoted", e)
				}
			case "daily":
				if e != nil || got.Recorders[0]["recordingMode"].(map[string]any)["recordingFrequency"] != "DAILY" || got.Status == "COMPLETE" {
					t.Fatal("daily recorder promoted to continuous")
				}
			}
		})
	}
}
func TestEBSConfigurationHistoryRejectsPaginationLoopsAndUnsupportedTypes(t *testing.T) {
	end := time.Now().UTC().Truncate(24 * time.Hour)
	start := end.Add(-14 * 24 * time.Hour)
	a := rdsTestAWS(t, func(r *http.Request, b string) (string, int) {
		return ebsHistoryFixture(t, r, b, start, func(action string, d model.Document) model.Document {
			if action == "GetResourceConfigHistory" && strings.Contains(b, `"Forward"`) {
				d["nextToken"] = "loop"
			}
			return d
		})
	})
	if _, e := a.EBSConfigurationHistory(context.Background(), ebsTestScope, "AWS::EC2::Volume", ebsTestVolumeID, start, end); e == nil {
		t.Fatal("Config pagination loop accepted")
	}
	if _, e := a.EBSConfigurationHistory(context.Background(), ebsTestScope, "AWS::RDS::DBInstance", "db-other", start, end); e == nil {
		t.Fatal("out-of-scope history accepted")
	}
}
