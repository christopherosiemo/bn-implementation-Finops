package provider

import (
	"context"
	"encoding/json"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"math/big"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

type EBSConfigurationHistoryEvidence struct {
	EBSReadEvidence
	ResourceType           string           `json:"resource_type"`
	ResourceID             string           `json:"resource_id"`
	Start                  time.Time        `json:"start"`
	End                    time.Time        `json:"end"`
	Status                 string           `json:"status"`
	Basis                  string           `json:"basis"`
	Baseline               model.Document   `json:"baseline"`
	Items                  []model.Document `json:"items"`
	Recorders              []model.Document `json:"recorders"`
	RecorderStatuses       []model.Document `json:"recorder_statuses"`
	RecorderControlHistory model.Document   `json:"recorder_control_history"`
	ReasonCodes            []string         `json:"reason_codes"`
}

// Optional so an uncommissioned AWS Config reader cannot prevent current native
// inventory. CIs are provider-recorded states, not exact effective-change clocks.
type EBSHistoryReader interface {
	EBSConfigurationHistory(context.Context, EBSScope, string, string, time.Time, time.Time) (EBSConfigurationHistoryEvidence, error)
}

func (r *ebsRead) configRead(ctx context.Context, action string, p model.Document) (model.Document, error) {
	if action != "GetResourceConfigHistory" && action != "DescribeConfigurationRecorders" && action != "DescribeConfigurationRecorderStatus" {
		return nil, ErrEBSRead
	}
	raw, e := json.Marshal(p)
	if e != nil {
		return nil, ErrEBSRead
	}
	c, e := r.a.cfg.Credentials.Retrieve(ctx)
	if e != nil {
		return nil, ErrEBSRead
	}
	if e = r.identity(ctx, c); e != nil {
		return nil, e
	}
	body, e := r.signedBody(ctx, c, "config", action, string(raw), "StarlingDoveService."+action)
	if e != nil {
		return nil, e
	}
	if e = r.retain("config", action, string(raw), body); e != nil {
		return nil, e
	}
	var out model.Document
	if rdsJSON(body, &out) != nil {
		return nil, ErrEBSRead
	}
	out["raw_page_sha256"] = rdsSHA(body)
	return out, nil
}
func ebsConfigTime(v any) (time.Time, error) {
	n, ok := v.(json.Number)
	if !ok {
		return time.Time{}, ErrEBSRead
	}
	r, ok := new(big.Rat).SetString(n.String())
	if !ok || r.Sign() < 0 {
		return time.Time{}, ErrEBSRead
	}
	r.Mul(r, big.NewRat(1000000000, 1))
	if !r.IsInt() || !r.Num().IsInt64() {
		return time.Time{}, ErrEBSRead
	}
	return time.Unix(0, r.Num().Int64()).UTC(), nil
}
func ebsConfigItems(page model.Document, s EBSScope, kind, id string, early, late time.Time) ([]model.Document, error) {
	values, ok := page["configurationItems"].([]any)
	if !ok {
		return nil, ErrEBSRead
	}
	out := []model.Document{}
	arnKind := "volume"
	if kind == "AWS::EC2::Instance" {
		arnKind = "instance"
	}
	for _, v := range values {
		m, ok := v.(map[string]any)
		if !ok {
			return nil, ErrEBSRead
		}
		d := model.Document(m)
		at, e := ebsConfigTime(d["configurationItemCaptureTime"])
		if e != nil || at.Before(early) || at.After(late) || model.String(d, "accountId") != s.AccountID || model.String(d, "awsRegion") != s.Region || model.String(d, "resourceType") != kind || model.String(d, "resourceId") != id || model.String(d, "arn") != "arn:aws:ec2:"+s.Region+":"+s.AccountID+":"+arnKind+"/"+id || model.String(d, "configurationStateId") == "" {
			return nil, ErrEBSRead
		}
		raw := model.String(d, "configuration")
		var configuration model.Document
		if raw != "" && rdsJSON([]byte(raw), &configuration) != nil {
			return nil, ErrEBSRead
		}
		copy := ebsHistoryCopy(d)
		copy["configuration_decoded"] = configuration
		copy["capture_time"] = at
		copy["raw_page_sha256"] = page["raw_page_sha256"]
		out = append(out, copy)
	}
	return out, nil
}
func (a *AWS) EBSConfigurationHistory(ctx context.Context, s EBSScope, kind, id string, start, end time.Time) (EBSConfigurationHistoryEvidence, error) {
	out := EBSConfigurationHistoryEvidence{ResourceType: kind, ResourceID: id, Start: start, End: end, Status: "HISTORY_UNAVAILABLE", Basis: "AWS_CONFIG_RECORDED_CONFIGURATION_HISTORY", Items: []model.Document{}, ReasonCodes: []string{"RECORDED_CAPTURE_TIMES_ARE_NOT_EFFECTIVE_TRANSITION_TIMES"}}
	r, e := newEBSRead(a, s)
	if e != nil {
		return out, e
	}
	finish := func(err error) (EBSConfigurationHistoryEvidence, error) {
		out.EBSReadEvidence = r.evidence()
		return out, err
	}
	if kind != "AWS::EC2::Volume" && kind != "AWS::EC2::Instance" || kind == "AWS::EC2::Volume" && !ebsVolumeID.MatchString(id) || kind == "AWS::EC2::Instance" && !ebsInstanceID.MatchString(id) || start.IsZero() || !start.Before(end) || end.After(time.Now().UTC()) || end.Sub(start) > 90*24*time.Hour || start.Nanosecond() != 0 || end.Nanosecond() != 0 {
		return finish(ErrEBSRead)
	}
	for _, op := range []struct {
		action, key string
		target      *[]model.Document
	}{{"DescribeConfigurationRecorders", "ConfigurationRecorders", &out.Recorders}, {"DescribeConfigurationRecorderStatus", "ConfigurationRecordersStatus", &out.RecorderStatuses}} {
		page, err := r.configRead(ctx, op.action, model.Document{})
		if err != nil {
			out.ReasonCodes = append(out.ReasonCodes, "CONFIG_RECORDER_READ_UNAVAILABLE")
			return finish(nil)
		}
		rows, ok := page[op.key].([]any)
		if !ok {
			return finish(ErrEBSRead)
		}
		*op.target = []model.Document{}
		for _, v := range rows {
			d, ok := v.(map[string]any)
			if !ok {
				return finish(ErrEBSRead)
			}
			copy := ebsHistoryCopy(model.Document(d))
			copy["raw_page_sha256"] = page["raw_page_sha256"]
			*op.target = append(*op.target, copy)
		}
	}
	// AWS limits each call to seven days. Baseline search is explicitly bounded
	// to one year; an older or absent baseline remains unavailable.
	for later := start; out.Baseline == nil && later.After(start.Add(-365*24*time.Hour)); {
		earlier := later.Add(-7 * 24 * time.Hour)
		if earlier.Before(start.Add(-365 * 24 * time.Hour)) {
			earlier = start.Add(-365 * 24 * time.Hour)
		}
		page, err := r.configRead(ctx, "GetResourceConfigHistory", model.Document{"resourceType": kind, "resourceId": id, "earlierTime": earlier.Unix(), "laterTime": later.Unix(), "chronologicalOrder": "Reverse", "limit": 1})
		if err != nil {
			out.ReasonCodes = append(out.ReasonCodes, "CONFIG_BASELINE_READ_UNAVAILABLE")
			return finish(nil)
		}
		rows, err := ebsConfigItems(page, s, kind, id, earlier, later)
		if err != nil {
			return finish(err)
		}
		if len(rows) > 1 {
			return finish(ErrEBSRead)
		}
		if len(rows) == 1 {
			out.Baseline = rows[0]
		}
		later = earlier
	}
	if out.Baseline == nil {
		out.ReasonCodes = append(out.ReasonCodes, "CONFIG_BASELINE_NOT_FOUND_WITHIN_BOUNDED_YEAR")
		return finish(nil)
	}
	seen := map[string]string{}
	for early := start; early.Before(end); {
		late := early.Add(7 * 24 * time.Hour)
		if late.After(end) {
			late = end
		}
		token := ""
		tokens := map[string]bool{}
		for pageNumber := 0; pageNumber < 128; pageNumber++ {
			p := model.Document{"resourceType": kind, "resourceId": id, "earlierTime": early.Unix(), "laterTime": late.Unix(), "chronologicalOrder": "Forward", "limit": 100}
			if token != "" {
				p["nextToken"] = token
			}
			page, err := r.configRead(ctx, "GetResourceConfigHistory", p)
			if err != nil {
				out.ReasonCodes = append(out.ReasonCodes, "CONFIG_INTERVAL_READ_UNAVAILABLE")
				return finish(nil)
			}
			rows, err := ebsConfigItems(page, s, kind, id, early, late)
			if err != nil {
				return finish(err)
			}
			for _, row := range rows {
				key := model.String(row, "configurationStateId")
				stable := ebsHistoryCopy(row)
				delete(stable, "raw_page_sha256")
				hash := rdsSHA(mustEBSJSON(stable))
				if prior := seen[key]; prior != "" {
					if prior != hash {
						return finish(ErrEBSRead)
					}
					continue
				}
				seen[key] = hash
				out.Items = append(out.Items, row)
				if len(out.Items) > 4096 {
					return finish(ErrEBSRead)
				}
			}
			token = model.String(page, "nextToken")
			if token == "" {
				break
			}
			if len(token) > 8192 || tokens[token] || pageNumber == 127 {
				return finish(ErrEBSRead)
			}
			tokens[token] = true
		}
		early = late
	}
	sort.Slice(out.Items, func(i, j int) bool {
		return out.Items[i]["capture_time"].(time.Time).Before(out.Items[j]["capture_time"].(time.Time))
	})
	out.Status = "RECORDED_HISTORY_REQUIRES_RECORDER_AND_CONFIGURATION_VALIDATION"
	if len(out.Recorders) == 0 || len(out.RecorderStatuses) == 0 {
		out.Status = "HISTORY_UNAVAILABLE"
		out.ReasonCodes = append(out.ReasonCodes, "CONFIG_CONTINUOUS_RECORDER_NOT_OBSERVED")
	}
	baselineTime, err := time.Parse(time.RFC3339Nano, model.String(out.Baseline, "capture_time"))
	// capture_time is a time.Time before the evidence is JSON encoded.
	if at, ok := out.Baseline["capture_time"].(time.Time); ok {
		baselineTime, err = at, nil
	}
	if err != nil {
		return finish(ErrEBSRead)
	}
	if start.Before(baselineTime) {
		baselineTime = start
	}
	out.RecorderControlHistory = r.recorderControlHistory(ctx, baselineTime)
	if model.String(out.RecorderControlHistory, "status") != "COMPLETE_ENUMERATION" || len(ebsDocuments(out.RecorderControlHistory["relevant_changes"])) > 0 {
		out.Status = "HISTORY_UNAVAILABLE"
		out.ReasonCodes = append(out.ReasonCodes, "CONFIG_RECORDER_CONTROL_HISTORY_UNPROVEN_OR_CHANGED")
	}
	return finish(nil)
}
func mustEBSJSON(v any) []byte { raw, _ := json.Marshal(v); return raw }

func ebsHistoryCopy(d model.Document) model.Document {
	out := model.Document{}
	for k, v := range d {
		out[k] = v
	}
	return out
}

// Official protocol: https://raw.githubusercontent.com/aws/aws-sdk-js/master/apis/cloudtrail-2013-11-01.normal.json
// Bounds: https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_LookupEvents.html
// Event history is regional, account-scoped, management-only and retained 90d.
// COMPLETE_ENUMERATION describes this bounded paginated response, not a claim
// of immediate event visibility, effective transition clocks or action authority.
func (r *ebsRead) recorderControlHistory(ctx context.Context, start time.Time) model.Document {
	end := time.Now().UTC()
	retention := end.Add(-90 * 24 * time.Hour)
	out := model.Document{"basis": "AWS_CLOUDTRAIL_CONFIG_RECORDER_MANAGEMENT_EVENTS", "status": "UNAVAILABLE", "account_id": r.scope.AccountID, "region": r.scope.Region, "start": start, "end": end, "retention_start": retention, "event_source": "config.amazonaws.com", "events": []model.Document{}, "relevant_changes": []model.Document{}, "reason_codes": []string{"CLOUDTRAIL_EVENT_HISTORY_IS_EVENTUALLY_AVAILABLE_NOT_EFFECTIVE_TRANSITION_PROOF"}}
	defer func() { out["collected_at"] = time.Now().UTC() }()
	unavailable := func(reason string) model.Document {
		out["reason_codes"] = append(model.Strings(out, "reason_codes"), reason)
		return out
	}
	complete := func() model.Document {
		// The retention fence must still cover the first timestamp after I/O.
		currentRetention := time.Now().UTC().Add(-90 * 24 * time.Hour)
		out["retention_start"] = currentRetention
		if start.Before(currentRetention) {
			return unavailable("CLOUDTRAIL_90_DAY_RETENTION_DOES_NOT_COVER_BASELINE")
		}
		out["status"] = "COMPLETE_ENUMERATION"
		return out
	}
	if start.IsZero() || start.Before(retention) || !start.Before(end) {
		return unavailable("CLOUDTRAIL_90_DAY_RETENTION_DOES_NOT_COVER_BASELINE")
	}
	seconds := func(t time.Time) json.Number {
		return json.Number(strconv.FormatInt(t.Unix(), 10) + "." + strconv.FormatInt(int64(t.Nanosecond())+1000000000, 10)[1:])
	}
	seen, tokens := map[string]string{}, map[string]bool{}
	events, changes := []model.Document{}, []model.Document{}
	token := ""
	for pageNumber := 0; pageNumber < 128; pageNumber++ {
		p := model.Document{"LookupAttributes": []model.Document{{"AttributeKey": "EventSource", "AttributeValue": "config.amazonaws.com"}}, "StartTime": seconds(start), "EndTime": seconds(end), "MaxResults": 50}
		if token != "" {
			p["NextToken"] = token
		}
		selector, err := json.Marshal(p)
		if err != nil {
			return unavailable("CLOUDTRAIL_REQUEST_INVALID")
		}
		c, err := r.a.cfg.Credentials.Retrieve(ctx)
		if err != nil || r.identity(ctx, c) != nil {
			return unavailable("CLOUDTRAIL_CALLER_UNAVAILABLE")
		}
		raw, err := r.signedBody(ctx, c, "cloudtrail", "LookupEvents", string(selector), "com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101.LookupEvents")
		if err != nil {
			return unavailable("CLOUDTRAIL_LOOKUP_UNAVAILABLE")
		}
		if r.retain("cloudtrail", "LookupEvents", string(selector), raw) != nil {
			return unavailable("CLOUDTRAIL_RAW_BUDGET_UNAVAILABLE")
		}
		var page model.Document
		if rdsJSON(raw, &page) != nil {
			return unavailable("CLOUDTRAIL_PAGE_INVALID")
		}
		rows, ok := page["Events"].([]any)
		if !ok || len(rows) > 50 {
			return unavailable("CLOUDTRAIL_EVENTS_INVALID")
		}
		for _, v := range rows {
			m, ok := v.(map[string]any)
			if !ok {
				return unavailable("CLOUDTRAIL_EVENT_INVALID")
			}
			event, err := ebsRecorderControlEvent(model.Document(m), r.scope, start, end, rdsSHA(raw))
			if err != nil {
				return unavailable("CLOUDTRAIL_EVENT_SCOPE_OR_FIELDS_INVALID")
			}
			id, hash := model.String(event, "event_id"), rdsSHA(mustEBSJSON(event["native_event"]))
			if old := seen[id]; old != "" {
				if old != hash {
					return unavailable("CLOUDTRAIL_EVENT_ID_CONFLICT")
				}
				continue
			}
			seen[id] = hash
			events = append(events, event)
			out["events"] = events
			if ebsRecorderControlRelevant(model.String(event, "event_name"), event["read_only"] == true) {
				changes = append(changes, event)
				out["relevant_changes"] = changes
			}
			if len(events) > 4096 {
				return unavailable("CLOUDTRAIL_EVENT_COUNT_BOUND")
			}
		}
		value, present := page["NextToken"]
		if !present {
			return complete()
		}
		next, ok := value.(string)
		if !ok || strings.TrimSpace(next) != next || len(next) > 8192 {
			return unavailable("CLOUDTRAIL_NEXT_TOKEN_INVALID")
		}
		if next == "" {
			return complete()
		}
		if tokens[next] || pageNumber == 127 {
			return unavailable("CLOUDTRAIL_PAGINATION_INCOMPLETE")
		}
		tokens[next] = true
		token = next
	}
	return unavailable("CLOUDTRAIL_PAGINATION_INCOMPLETE")
}

func ebsRecorderControlEvent(outer model.Document, scope EBSScope, start, end time.Time, pageSHA string) (model.Document, error) {
	var native model.Document
	if rdsJSON([]byte(model.String(outer, "CloudTrailEvent")), &native) != nil {
		return nil, ErrEBSRead
	}
	id, name := model.String(outer, "EventId"), model.String(outer, "EventName")
	at, e := ebsConfigTime(outer["EventTime"])
	innerTime, ie := time.Parse(time.RFC3339Nano, model.String(native, "eventTime"))
	read, rok := native["readOnly"].(bool)
	management, mok := native["managementEvent"].(bool)
	version := model.String(native, "eventVersion")
	_, ve := strconv.Atoi(strings.TrimPrefix(version, "1."))
	recorderMutation := (strings.HasPrefix(name, "Put") || strings.HasPrefix(name, "Delete") || strings.HasPrefix(name, "Start") || strings.HasPrefix(name, "Stop")) && strings.Contains(name, "ConfigurationRecorder") || name == "AssociateResourceTypes" || name == "DisassociateResourceTypes"
	if !ebsTrailEventID.MatchString(id) || !ebsTrailEventName.MatchString(name) || e != nil || ie != nil || !at.Equal(innerTime) || at.Before(start) || at.After(end) || model.String(outer, "EventSource") != "config.amazonaws.com" || native["eventSource"] != "config.amazonaws.com" || native["eventID"] != id || native["eventName"] != name || native["recipientAccountId"] != scope.AccountID || native["awsRegion"] != scope.Region || !rok || !mok || !management || model.String(outer, "ReadOnly") != strconv.FormatBool(read) || native["eventCategory"] != "Management" || native["eventType"] != "AwsApiCall" && native["eventType"] != "AwsServiceEvent" || !strings.HasPrefix(version, "1.") || ve != nil || recorderMutation && read {
		return nil, ErrEBSRead
	}
	// Keep native readOnly unchanged even for the explicitly excluded evaluation
	// writes. Unknown writes remain potential recorder-control changes.
	return model.Document{"event_id": id, "event_name": name, "event_time": at, "account_id": scope.AccountID, "region": scope.Region, "management_event": management, "read_only": read, "request_parameters": native["requestParameters"], "native_event": native, "raw_page_sha256": pageSHA}, nil
}

func ebsRecorderControlRelevant(name string, readOnly bool) bool {
	if readOnly {
		return false
	}
	switch name {
	// These three operations deliver compliance evaluations or request an
	// evaluation of already-recorded state; they do not configure recording.
	// https://docs.aws.amazon.com/config/latest/APIReference/API_PutEvaluations.html
	// https://docs.aws.amazon.com/config/latest/APIReference/API_PutExternalEvaluation.html
	// https://docs.aws.amazon.com/config/latest/APIReference/API_StartConfigRulesEvaluation.html
	case "PutEvaluations", "PutExternalEvaluation", "StartConfigRulesEvaluation":
		return false
	default:
		return true
	}
}

var ebsTrailEventID = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
var ebsTrailEventName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]{0,127}$`)
