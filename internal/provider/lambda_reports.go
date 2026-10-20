package provider

import (
	"context"
	"encoding/json"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/lambdacost"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"strings"
	"time"
)

func (a *AWS) LambdaReports(ctx context.Context, s lambdacost.Scope, reg lambdacost.Registration, version string, start, end time.Time, nextToken string) (lambdacost.Reports, error) {
	out := lambdacost.Reports{Rows: []model.Document{}, Coverage: model.Document{}}
	r, e := newLambdaRead(a, s)
	if e != nil || lambdacost.ValidateRegistration(reg) != nil || reg.Kind != lambdacost.ReportsKind || reg.TenantID != s.TenantID || reg.AccountID != s.AccountID || reg.Region != s.Region || !reg.Enabled || start.IsZero() || !start.Before(end) || end.After(time.Now().UTC()) || end.Sub(start) > 90*24*time.Hour || len(nextToken) > 4096 {
		return out, lambdacost.ErrEvidence
	}
	_, q, e := lambdacost.FunctionARN(s, reg.FunctionARN+":"+version)
	if e != nil || q != version {
		return out, lambdacost.ErrEvidence
	}
	filter := "\"REPORT\" \"RequestId:\""
	if reg.Format == "PLATFORM_REPORT_JSON" {
		filter = "{ $.type = \"platform.report\" }"
	}
	seenTokens := map[string]bool{}
	seen := map[string]string{}
	rejected := 0
	complete := false
	token := nextToken
	for page := 0; page < 20; page++ {
		body := model.Document{"logGroupName": reg.LogGroupName, "startTime": start.UnixMilli(), "endTime": end.UnixMilli(), "filterPattern": filter, "limit": 500}
		if token != "" {
			body["nextToken"] = token
		}
		request, _ := json.Marshal(body)
		raw, e := r.signed(ctx, "POST", "logs", "/", "", string(request), "Logs_20140328.FilterLogEvents")
		if e != nil {
			return out, e
		}
		var doc model.Document
		if lambdacost.DecodeJSON(raw, &doc) != nil || doc["events"] == nil {
			return out, lambdacost.ErrEvidence
		}
		safeRows := []model.Document{}
		for _, event := range lambdacost.Rows(doc["events"]) {
			millis := model.Number(event, "timestamp")
			at := time.UnixMilli(millis)
			if at.Before(start) || !at.Before(end) {
				return out, lambdacost.ErrEvidence
			}
			stream := model.String(event, "logStreamName")
			message := model.String(event, "message")
			row, err := lambdacost.ParseReport(s, reg.FunctionARN+":"+reg.Qualifier, version, reg.Format, message, stream, model.String(event, "eventId"), at)
			if err != nil {
				rejected++
				continue
			}
			id := model.String(row, "log_event_id_hash")
			hash := lambdacost.Hash(row)
			if previous, exists := seen[id]; exists {
				if previous != hash {
					return out, lambdacost.ErrEvidence
				}
				continue
			}
			seen[id] = hash
			out.Rows = append(out.Rows, row)
			safeRows = append(safeRows, row)
			if len(out.Rows) > lambdacost.MaxRows {
				return out, lambdacost.ErrEvidence
			}
		}
		safe, _ := json.Marshal(model.Document{"records": safeRows, "rejected_records": rejected, "next_token_present": model.String(doc, "nextToken") != "", "query_start": start, "query_end": end, "source_registration_id": reg.ID, "source_registration_version": reg.Version, "sanitizer_version": "LAMBDA_REPORT_ALLOWLIST_V1"})
		if e = r.retain("FilterLogEvents", reg.LogGroupARN, "", 200, safe); e != nil {
			return out, e
		}
		token = model.String(doc, "nextToken")
		if token == "" {
			complete = true
			break
		}
		if len(token) > 4096 || seenTokens[token] {
			return out, lambdacost.ErrEvidence
		}
		seenTokens[token] = true
	}
	out.NextToken = token
	status := "BOUNDED_LOG_QUERY_INCOMPLETE"
	if complete {
		status = "COMPLETE_QUERY_NOT_COMPLETE_INVOCATION_CENSUS"
	}
	if rejected > 0 {
		status = "REJECTED_OR_UNBOUND_LOG_RECORDS"
	}
	out.Coverage = model.Document{"status": status, "query_complete": complete, "invocation_census_complete": false, "start": start, "end": end, "observed_records": len(out.Rows), "rejected_records": rejected, "missing_is_zero": false, "source_id": reg.ID, "source_version": reg.Version, "log_group_arn": reg.LogGroupARN, "format": reg.Format, "log_transport": "NATIVE_REGISTERED_CLOUDWATCH_FILTER_LOG_EVENTS", "unknown_causes": []string{"SYSTEM_LOG_DELIVERY_NOT_GUARANTEED", "CONFIGURATION_EPOCH_HISTORY_REQUIRED"}}
	out.Evidence = r.evidence()
	return out, nil
}

// No application log content is retained; this helper also makes the raw frame
// privacy contract testable without a provider or storage process.
func LambdaCaptureHasSecrets(raw []byte, secret string) bool {
	return secret != "" && strings.Contains(string(raw), secret)
}
