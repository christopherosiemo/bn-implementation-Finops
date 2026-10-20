package provider

import (
	"context"
	"encoding/json"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/lambdacost"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"math/big"
	"net/url"
	"strconv"
	"time"
)

type lambdaMetricSpec struct{ name, unit, stat string }

var lambdaMetricSpecs = []lambdaMetricSpec{{"Invocations", "Count", "Sum"}, {"Errors", "Count", "Sum"}, {"Throttles", "Count", "Sum"}, {"Duration", "Milliseconds", "Average"}, {"Duration", "Milliseconds", "Maximum"}, {"Duration", "Milliseconds", "Minimum"}, {"ConcurrentExecutions", "Count", "Maximum"}, {"ProvisionedConcurrentExecutions", "Count", "Maximum"}, {"ProvisionedConcurrencyInvocations", "Count", "Sum"}, {"ProvisionedConcurrencySpilloverInvocations", "Count", "Sum"}, {"ProvisionedConcurrencyUtilization", "None", "Maximum"}, {"ProvisionedConcurrencyUtilization", "None", "Average"}, {"IteratorAge", "Milliseconds", "Maximum"}, {"AsyncEventAge", "Milliseconds", "Maximum"}, {"AsyncEventsReceived", "Count", "Sum"}, {"AsyncEventsDropped", "Count", "Sum"}, {"DestinationDeliveryFailures", "Count", "Sum"}, {"DeadLetterErrors", "Count", "Sum"}}

func (a *AWS) LambdaMetrics(ctx context.Context, s lambdacost.Scope, sel lambdacost.MetricSelection) (lambdacost.Metrics, error) {
	out := lambdacost.Metrics{Selection: sel, Rows: []model.Document{}, Coverage: []model.Document{}}
	r, e := newLambdaRead(a, s)
	if e != nil {
		return out, e
	}
	base, q, e := lambdacost.FunctionARN(s, sel.QualifiedARN)
	if e != nil || sel.Version == "" || q == "" && sel.Version != "ALL" {
		return out, lambdacost.ErrEvidence
	}
	now := time.Now().UTC()
	p := sel.PeriodSeconds
	if p != 60 && p != 300 && p != 3600 || sel.Start.IsZero() || !sel.Start.Before(sel.End) || sel.End.After(now.Add(-20*time.Minute)) || sel.End.Sub(sel.Start) > 90*24*time.Hour || sel.Start.Unix()%int64(p) != 0 || sel.End.Unix()%int64(p) != 0 || p == 60 && sel.Start.Before(now.Add(-15*24*time.Hour)) || p == 300 && sel.Start.Before(now.Add(-63*24*time.Hour)) {
		return out, lambdacost.ErrEvidence
	}
	prefix := "arn:aws:lambda:" + s.Region + ":" + s.AccountID + ":function:"
	name := base[len(prefix):]
	resource := name + ":" + q
	expected := int(sel.End.Sub(sel.Start) / time.Second / time.Duration(p))
	for _, spec := range lambdaMetricSpecs {
		seen := map[int64]bool{}
		valid := 0
		failed := false
		for start := sel.Start; start.Before(sel.End); {
			end := start.Add(time.Duration(1440*p) * time.Second)
			if end.After(sel.End) {
				end = sel.End
			}
			values := url.Values{"Action": {"GetMetricStatistics"}, "Version": {"2010-08-01"}, "Namespace": {"AWS/Lambda"}, "MetricName": {spec.name}, "Dimensions.member.1.Name": {"FunctionName"}, "Dimensions.member.1.Value": {name}, "Dimensions.member.2.Name": {"Resource"}, "Dimensions.member.2.Value": {resource}, "StartTime": {start.Format(time.RFC3339)}, "EndTime": {end.Format(time.RFC3339)}, "Period": {strconv.Itoa(p)}, "Statistics.member.1": {spec.stat}, "Statistics.member.2": {"SampleCount"}, "Unit": {spec.unit}}
			dimensions := model.Document{"FunctionName": name, "Resource": resource}
			if q == "" {
				values.Del("Dimensions.member.2.Name")
				values.Del("Dimensions.member.2.Value")
				delete(dimensions, "Resource")
			}
			if q != "" && q != sel.Version {
				values.Set("Dimensions.member.3.Name", "ExecutedVersion")
				values.Set("Dimensions.member.3.Value", sel.Version)
				dimensions["ExecutedVersion"] = sel.Version
			}
			raw, e := r.signed(ctx, "POST", "monitoring", "/", "", values.Encode(), "")
			if e != nil {
				failed = true
				break
			}
			wrapped, _ := json.Marshal(model.Document{"native_xml": string(raw)})
			if r.retain("GetMetricStatistics", values.Encode(), "", 200, wrapped) != nil {
				return out, lambdacost.ErrEvidence
			}
			root, e := ebsTree(raw, "GetMetricStatistics")
			if e != nil {
				return out, lambdacost.ErrEvidence
			}
			result := root.get("GetMetricStatisticsResult")
			if result == nil || result.get("Datapoints") == nil {
				return out, lambdacost.ErrEvidence
			}
			for _, point := range result.list("Datapoints") {
				at, e := time.Parse(time.RFC3339Nano, point.value("Timestamp"))
				value := point.value(spec.stat)
				n, ok := new(big.Rat).SetString(value)
				if e != nil || at.Before(start) || !at.Before(end) || at.Unix()%int64(p) != 0 || seen[at.Unix()] || !ok || n.Sign() < 0 || point.value("Unit") != spec.unit {
					return out, lambdacost.ErrEvidence
				}
				seen[at.Unix()] = true
				var count any
				if point.get("SampleCount") != nil {
					c, ok := rdsMetricCount(point.value("SampleCount"))
					if !ok {
						return out, lambdacost.ErrEvidence
					}
					count = c
					if c > 0 {
						valid++
					}
				}
				out.Rows = append(out.Rows, model.Document{"metric": spec.name, "namespace": "AWS/Lambda", "statistic": spec.stat, "unit": spec.unit, "value": value, "source_time": at.UTC().Format(time.RFC3339Nano), "period_seconds": p, "sample_count": count, "dimensions": dimensions, "qualified_arn": sel.QualifiedARN, "version": sel.Version, "raw_page_sha256": lambdacost.BytesHash(wrapped)})
				if len(out.Rows) > 250000 {
					return out, lambdacost.ErrEvidence
				}
			}
			start = end
		}
		status := "GAPS"
		if failed {
			status = "UNAVAILABLE"
		} else if valid == expected {
			status = "COMPLETE_OBSERVED_BINS"
		}
		out.Coverage = append(out.Coverage, model.Document{"metric": spec.name, "statistic": spec.stat, "period_seconds": p, "expected_bins": expected, "observed_bins": len(seen), "positive_sample_count_bins": valid, "status": status, "missing_is_zero": false, "qualified_arn": sel.QualifiedARN, "version": sel.Version, "sparse_metric_semantics": "NO_EMISSION_IS_UNKNOWN_NOT_ZERO"})
	}
	out.Evidence = r.evidence()
	return out, nil
}

func (a *AWS) LambdaComputeOptimizer(ctx context.Context, s lambdacost.Scope, arn string) (model.Document, lambdacost.Evidence, error) {
	r, e := newLambdaRead(a, s)
	if e != nil {
		return nil, lambdacost.Evidence{}, e
	}
	base, _, e := lambdacost.FunctionARN(s, arn)
	if e != nil {
		return nil, lambdacost.Evidence{}, e
	}
	rows := []model.Document{}
	token := ""
	seen := map[string]bool{}
	for page := 0; page < 128; page++ {
		body := model.Document{"accountIds": []string{s.AccountID}, "functionArns": []string{base}, "filters": []model.Document{{"name": "Finding", "values": []string{"Optimized", "NotOptimized", "Unavailable"}}}, "maxResults": 100}
		if token != "" {
			body["nextToken"] = token
		}
		request, _ := json.Marshal(body)
		raw, e := r.signed(ctx, "POST", "compute-optimizer", "/", "", string(request), "ComputeOptimizerService.GetLambdaFunctionRecommendations")
		if e != nil {
			return nil, lambdacost.Evidence{}, e
		}
		var doc model.Document
		if lambdacost.DecodeJSON(raw, &doc) != nil || doc["lambdaFunctionRecommendations"] == nil || len(lambdacost.Rows(doc["errors"])) > 0 {
			return nil, lambdacost.Evidence{}, lambdacost.ErrEvidence
		}
		safe, _ := json.Marshal(lambdaSanitize(doc))
		if e = r.retain("GetLambdaFunctionRecommendations", string(request), "", 200, safe); e != nil {
			return nil, lambdacost.Evidence{}, e
		}
		for _, row := range lambdacost.Rows(doc["lambdaFunctionRecommendations"]) {
			b, _, err := lambdacost.FunctionARN(s, model.String(row, "functionArn"))
			if err != nil || b != base || model.String(row, "accountId") != s.AccountID {
				return nil, lambdacost.Evidence{}, lambdacost.ErrEvidence
			}
			rows = append(rows, row)
			if len(rows) > 1000 {
				return nil, lambdacost.Evidence{}, lambdacost.ErrEvidence
			}
		}
		token = model.String(doc, "nextToken")
		if token == "" {
			return model.Document{"status": "OPTIONAL_PROVIDER_ADVICE_NOT_CUSTOMER_PRICE", "rows": rows}, r.evidence(), nil
		}
		if seen[token] || len(token) > 4096 {
			return nil, lambdacost.Evidence{}, lambdacost.ErrEvidence
		}
		seen[token] = true
	}
	return nil, lambdacost.Evidence{}, lambdacost.ErrEvidence
}
