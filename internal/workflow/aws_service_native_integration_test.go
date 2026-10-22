package workflow

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/activity"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/auth"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/awsservice"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/native"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/provider"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/service"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/slo"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/source"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/telemetry"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/workload"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// One provider-shaped synthetic population traverses the normal registered
// collector, immutable/analytical storage, native CUR normalization, dedicated
// analyst/Python process and ordinary OIDC console. This is not live AWS proof.
func TestAWSServiceNativeFargatePositiveThroughActualPythonAndOIDC(t *testing.T) {
	if os.Getenv("AWS_SERVICE_TEST_STORAGE_ENABLED") != "true" {
		t.Skip("existing commissioned PostgreSQL/object/ClickHouse fixture required")
	}
	if os.Getenv("FINOPS_AWS_SERVICE_BROWSER") != "true" || os.Getenv("ECONOMICS_TEST_URL") == "" {
		t.Fatal("ordinary OIDC browser and actual private Python required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	admin, roles := schedulerTestDatabase(t)
	ingester := lambdaComponentRuntime(t, ctx, admin, "ingester", "finops_ingester")
	analyst := lambdaComponentRuntime(t, ctx, admin, "aws-service-assessor", "finops_service_analyst")
	const tenant = "tenant-demo"
	const account = "111122223333"
	const workloadID = "native-fargate-workload"
	const cluster = "arn:aws:ecs:eu-west-1:111122223333:cluster/orders"
	const arn = "arn:aws:ecs:eu-west-1:111122223333:service/orders/web"
	const definition = "arn:aws:ecs:eu-west-1:111122223333:task-definition/orders:7"
	tasks := []string{"arn:aws:ecs:eu-west-1:111122223333:task/orders/task-a", "arn:aws:ecs:eu-west-1:111122223333:task/orders/task-b"}
	end := time.Now().UTC().Truncate(24 * time.Hour)
	start := end.Add(-14 * 24 * time.Hour)
	reg := awsservice.Registration{ID: "native-fargate-source", TenantID: tenant, AccountID: account, Region: "eu-west-1", ReadRoleBindingID: "native-fargate-read", Version: 1, Enabled: true, ServiceFamilies: []string{"ECS"}, ScopeMode: "RESOURCE", RootResourceARNs: []string{cluster}}
	if e := roles["api"].Do(ctx, tenant, func(tx *store.Tx) error {
		if e := tx.Seed(ctx, true); e != nil {
			return e
		}
		if _, e := tx.Create(ctx, "workloads", model.Document{"id": workloadID, "name": "Native Fargate orders", "owner": "orders-team", "environment": "NON_PRODUCTION"}); e != nil {
			return e
		}
		yes := true
		p := workload.Profile{SchemaVersion: "1", Criticality: "NON_PRODUCTION", Statefulness: "STATELESS", Timezone: "UTC", MinReplicas: 2, MinZones: 1, Headroom: workload.Headroom{CPUFreePPM: 200000, MemoryFreePPM: 200000, ReserveAboveForecastPPM: 100000}, Saturation: workload.Saturation{CPUP99PPM: 800000, MemoryP99PPM: 800000}, RTOSeconds: 300, MaxSimultaneousChangePPM: 100000, VMCooldownSeconds: 86400, AWSService: &workload.AWSServiceLimits{BurstRequirementsKnown: &yes, AutoscalingReviewed: &yes}}
		if _, e := tx.WorkloadSafetyAppend(ctx, workloadID, 0, p); e != nil {
			return e
		}
		d := awsservice.Document(reg)
		d["kind"] = awsservice.NativeKind
		_, e := tx.SourceCreate(ctx, d)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	storage, e := native.StorageFromEnvironment(ctx, true)
	if e != nil {
		t.Fatal(e)
	}
	awsServicePositiveBilling(t, ctx, roles["api"], ingester, storage, tenant, tasks, start, end)
	sts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("Action") != "AssumeRole" {
			t.Error("unexpected STS mutation")
			w.WriteHeader(400)
			return
		}
		fmt.Fprintf(w, `<AssumeRoleResponse><AssumeRoleResult><Credentials><AccessKeyId>component-read</AccessKeyId><SecretAccessKey>component-secret</SecretAccessKey><SessionToken>component-session</SessionToken><Expiration>%s</Expiration></Credentials><AssumedRoleUser><Arn>arn:aws:sts::111122223333:assumed-role/read/component</Arn><AssumedRoleId>READ:component</AssumedRoleId></AssumedRoleUser></AssumeRoleResult></AssumeRoleResponse>`, time.Now().Add(time.Hour).UTC().Format(time.RFC3339))
	}))
	defer sts.Close()
	for key, value := range map[string]string{"AWS_ACCESS_KEY_ID": "synthetic-source", "AWS_SECRET_ACCESS_KEY": "synthetic-source-secret", "AWS_SESSION_TOKEN": "", "AWS_ROLE_ARN": "", "AWS_WEB_IDENTITY_TOKEN_FILE": "", "AWS_PROFILE": "", "AWS_ENDPOINT_URL_STS": sts.URL, "AWS_EC2_METADATA_DISABLED": "true"} {
		t.Setenv(key, value)
	}
	allowed := map[string]bool{}
	for _, endpoint := range []string{os.Getenv("OBJECT_ENDPOINT"), os.Getenv("CLICKHOUSE_URL"), os.Getenv("ECONOMICS_TEST_URL"), sts.URL, "http://keycloak:8080"} {
		u, _ := url.Parse(endpoint)
		allowed[u.Host] = true
	}
	original := http.DefaultTransport
	http.DefaultTransport = databaseFixtureTransport(func(req *http.Request) (*http.Response, error) {
		if allowed[req.URL.Host] || strings.HasPrefix(req.URL.Host, "127.0.0.1:") {
			return original.RoundTrip(req)
		}
		raw, _ := io.ReadAll(req.Body)
		p := awsservice.Document(json.RawMessage(raw))
		q, _ := url.ParseQuery(string(raw))
		action := req.Header.Get("X-Amz-Target")
		if at := strings.LastIndex(action, "."); at >= 0 {
			action = action[at+1:]
		}
		if action == "" {
			action = q.Get("Action")
		}
		var body []byte
		header := http.Header{"Content-Type": []string{"application/json"}}
		respond := func(d model.Document) { body, _ = json.Marshal(d) }
		if strings.HasPrefix(req.URL.Host, "sts.") {
			body = []byte(`<GetCallerIdentityResponse><GetCallerIdentityResult><Account>111122223333</Account><Arn>arn:aws:sts::111122223333:assumed-role/read/component</Arn><UserId>READ:component</UserId></GetCallerIdentityResult></GetCallerIdentityResponse>`)
		} else {
			switch action {
			case "ListClusters":
				respond(model.Document{"clusterArns": []string{cluster}})
			case "DescribeClusters":
				respond(model.Document{"clusters": []model.Document{{"clusterArn": cluster, "clusterName": "orders", "status": "ACTIVE", "capacityProviders": []string{}}}, "failures": []any{}})
			case "ListServices":
				respond(model.Document{"serviceArns": []string{arn}})
			case "DescribeServices":
				respond(model.Document{"services": []model.Document{{"serviceArn": arn, "clusterArn": cluster, "serviceName": "web", "taskDefinition": definition, "launchType": "FARGATE", "desiredCount": 2, "runningCount": 2, "pendingCount": 0, "status": "ACTIVE", "deployments": []model.Document{{"id": "ecs-svc/7", "rolloutState": "COMPLETED", "taskDefinition": definition, "createdAt": start.Add(-time.Hour).Unix()}}}}, "failures": []any{}})
			case "DescribeTaskDefinition":
				respond(model.Document{"taskDefinition": model.Document{"taskDefinitionArn": definition, "family": "orders", "revision": 7, "cpu": "1024", "memory": "2048", "networkMode": "awsvpc", "requiresCompatibilities": []string{"FARGATE"}, "runtimePlatform": model.Document{"cpuArchitecture": "X86_64", "operatingSystemFamily": "LINUX"}, "containerDefinitions": []model.Document{{"name": "app", "cpu": 128, "memoryReservation": 256}}}, "tags": []any{}})
			case "ListContainerInstances":
				respond(model.Document{"containerInstanceArns": []string{}})
			case "ListTasks":
				respond(model.Document{"taskArns": tasks})
			case "DescribeTasks":
				rows := []model.Document{}
				for _, task := range tasks {
					rows = append(rows, model.Document{"taskArn": task, "clusterArn": cluster, "group": "service:web", "taskDefinitionArn": definition, "launchType": "FARGATE", "capacityProviderName": "FARGATE", "startedAt": start.Add(-time.Hour).Unix(), "lastStatus": "RUNNING", "desiredStatus": "RUNNING", "cpu": "1024", "memory": "2048"})
				}
				respond(model.Document{"tasks": rows, "failures": []any{}})
			case "DescribeScalableTargets":
				respond(model.Document{"ScalableTargets": []any{}})
			case "DescribeScalingPolicies":
				respond(model.Document{"ScalingPolicies": []any{}})
			case "DescribeScheduledActions":
				respond(model.Document{"ScheduledActions": []any{}})
			case "GetMetricStatistics":
				name, stat := q.Get("MetricName"), q.Get("Statistics.member.1")
				value := "2"
				switch name {
				case "CPUUtilization", "TaskCpuUtilization":
					value = "30"
				case "MemoryUtilization", "TaskMemoryUtilization":
					value = "25"
				case "PendingTaskCount":
					value = "0"
				case "DeploymentCount":
					value = "1"
				}
				unit := "Count"
				if strings.Contains(name, "Utilization") {
					unit = "Percent"
				}
				left, _ := time.Parse(time.RFC3339, q.Get("StartTime"))
				right, _ := time.Parse(time.RFC3339, q.Get("EndTime"))
				var xml strings.Builder
				fmt.Fprintf(&xml, "<GetMetricStatisticsResponse><GetMetricStatisticsResult><Label>%s</Label><Datapoints>", name)
				for at := left; at.Before(right); at = at.Add(time.Hour) {
					fmt.Fprintf(&xml, "<member><Timestamp>%s</Timestamp><%s>%s</%s><SampleCount>60</SampleCount><Unit>%s</Unit></member>", at.Format(time.RFC3339), stat, value, stat, unit)
				}
				xml.WriteString("</Datapoints></GetMetricStatisticsResult></GetMetricStatisticsResponse>")
				body = []byte(xml.String())
			case "GetProducts":
				filters := awsservice.Rows(p["Filters"])
				if p["ServiceCode"] != "AmazonECS" || len(filters) != 1 {
					return nil, errors.New("unexpected pricing scope")
				}
				sku := model.String(filters[0], "Value")
				usage, unit := "EU-Fargate-vCPU-Hours", "vCPU-Hours"
				if sku == "FARGATE_MEMORY" {
					usage, unit = "EU-Fargate-GB-Hours", "GB-Hours"
				}
				product := model.Document{"product": model.Document{"sku": sku, "attributes": model.Document{"servicecode": "AmazonECS", "regionCode": "eu-west-1", "usagetype": usage, "operation": "FargateTask", "cpuArchitecture": "x86", "operatingSystem": "Linux"}}, "terms": model.Document{"OnDemand": model.Document{"term": model.Document{"effectiveDate": start.AddDate(-1, 0, 0).Format(time.RFC3339), "priceDimensions": model.Document{sku + ".RATE": model.Document{"rateCode": sku + ".RATE", "beginRange": "0", "endRange": "Inf", "unit": unit, "pricePerUnit": model.Document{"USD": "999.99"}}}}}}}
				encoded, _ := json.Marshal(product)
				respond(model.Document{"PriceList": []string{string(encoded)}})
			default:
				return nil, errors.New("unregistered native ECS request")
			}
		}
		return &http.Response{StatusCode: 200, Header: header, Body: io.NopCloser(bytes.NewReader(body)), ContentLength: int64(len(body)), Request: req}, nil
	})
	defer func() { http.DefaultTransport = original }()
	reader, e := provider.NewAWS(ctx, reg.Region, "arn:aws:iam::111122223333:role/read", "component-external-id-at-least-thirty-two")
	if e != nil {
		t.Fatal(e)
	}
	activities := &Activities{Store: ingester}
	for n := 0; n < 2; n++ {
		if e = SyncAWSServiceSource(ctx, activities, storage, reader, reg); e != nil {
			t.Fatal("registered native ECS sync", e)
		}
	}
	var resource, snapshot model.Document
	if e = roles["api"].Do(ctx, tenant, func(tx *store.Tx) error {
		var id string
		if e := tx.QueryRow(ctx, "SELECT id FROM entities WHERE tenant_id=$1 AND kind='resources' AND document->>'provider_resource_id'=$2", tenant, arn).Scan(&id); e != nil {
			return e
		}
		var e error
		resource, e = tx.Get(ctx, "resources", id)
		if e != nil {
			return e
		}
		resource["owner"], resource["workload_id"], resource["environment"], resource["configuration_authority"] = "orders-team", workloadID, "NON_PRODUCTION", "TERRAFORM"
		resource, e = tx.Update(ctx, "resources", id, model.Number(resource, "version"), resource)
		if e != nil {
			return e
		}
		snapshot, e = tx.AWSServiceEvidenceLatest(ctx, id)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	raw, e := storage.Read(ctx, tenant, awsservice.Document(snapshot["archive"]))
	if e != nil || awsservice.BytesHash(raw) != snapshot["content_hash"] {
		t.Fatal("independent native archive readback", e)
	}
	analyticsURL, e := url.Parse(storage.AnalyticsURL)
	if e != nil {
		t.Fatal(e)
	}
	query := analyticsURL.Query()
	query.Set("database", storage.Database)
	query.Set("query", "SELECT uniqExact(sample_id) FROM native_metric_samples WHERE tenant_id={tenant:String} AND resource_id={resource:String} AND metric!='AWS_SERVICE_CONFIGURATION' FORMAT TabSeparated")
	query.Set("param_tenant", tenant)
	query.Set("param_resource", model.String(resource, "id"))
	analyticsURL.RawQuery = query.Encode()
	request, e := http.NewRequestWithContext(ctx, http.MethodPost, analyticsURL.String(), nil)
	if e != nil {
		t.Fatal(e)
	}
	request.Header.Set("X-ClickHouse-User", storage.AnalyticsUser)
	request.Header.Set("X-ClickHouse-Key", storage.AnalyticsSecret)
	response, e := storage.Client.Do(request)
	if e != nil {
		t.Fatal(e)
	}
	body, e := io.ReadAll(io.LimitReader(response.Body, 1024))
	response.Body.Close()
	expected := model.Number(awsservice.Document(resource["aws_service_assessment_evidence"]), "metric_count")
	if e != nil || response.StatusCode != 200 || strings.TrimSpace(string(body)) != strconv.FormatInt(expected, 10) || expected == 0 {
		t.Fatal("independent native metric population differs")
	}
	awsServiceNativeHistoricalDemand(t, ctx, admin, roles["api"], storage, resource, start, end)
	awsServiceSLOMachine(t, ctx, admin, roles["api"], tenant, resource)
	awsServiceComponentBrowser(t, ctx, roles["api"], analyst, tenant, resource, nil, "", true)
}

// Reuse the commissioned native Prometheus reader: this endpoint supplies raw
// historical samples, not canonical projections or guarded minute receipts.
// The fixture labels synthetic history explicitly; no live customer history is
// claimed. Raw endpoint bodies and parsed samples traverse the real pipeline.
func awsServiceNativeHistoricalDemand(t *testing.T, ctx context.Context, admin, apiDB *store.Store, storage *native.Storage, resource model.Document, start, end time.Time) {
	t.Helper()
	readerDB := lambdaComponentRuntime(t, ctx, admin, "telemetry-reader", "finops_telemetry_reader")
	binding := telemetry.Binding{TenantID: model.String(resource, "tenant_id"), ResourceID: model.String(resource, "id"), WorkloadID: model.String(resource, "workload_id"), Provider: "AWS", ProviderResourceID: model.String(resource, "provider_resource_id"), AccountID: model.String(resource, "account_id"), Region: model.String(resource, "region")}
	c := telemetry.Connection{SchemaVersion: "1", ID: "native-fargate-history", Version: 1, Kind: "PROMETHEUS", ReadBindingID: "native-fargate-off-instance-collector", Enabled: true, Binding: binding}
	definitionByName := map[string]telemetry.Definition{}
	for _, metric := range []string{"ECSServiceConfiguration", "AcceptedWork", "CompletedWork", "RejectedWork", "Backlog", "InFlightWork"} {
		kind, name := "GAUGE", "finops_"+metric
		if awsservice.Contains([]string{"AcceptedWork", "CompletedWork", "RejectedWork"}, metric) {
			kind, name = "SUM", name+"_total"
		}
		d := telemetry.Definition{ID: metric, Version: "1", Metric: metric, Name: name, Unit: "Count", Type: kind, Monotonic: kind == "SUM", CadenceSeconds: 300, MaxGapSeconds: 300, Attributes: map[string]string{"service_arn": binding.ProviderResourceID}, EpochAttributes: map[string]string{"service_arn": binding.ProviderResourceID}, EpochMetric: "finops_service_collector_start_time_seconds"}
		c.Definitions = append(c.Definitions, d)
		definitionByName[name] = d
	}
	if e := apiDB.Do(ctx, binding.TenantID, func(tx *store.Tx) error { _, e := tx.TelemetryConnectionAppend(ctx, c.ID, 0, telemetry.Document(c)); return e }); e != nil {
		t.Fatal("commission native stable-service historical reader", e)
	}
	cfg := awsservice.Document(resource["aws_service_configuration"])
	labels := map[string]string{"service_arn": binding.ProviderResourceID, "cluster_arn": model.String(cfg, "clusterArn"), "task_definition_arn": model.String(cfg, "taskDefinition"), "cpu_units": "1024", "memory_mib": "2048", "desired_count": "2", "running_count": "2", "launch_type": "FARGATE", "capacity_provider": "FARGATE", "architecture": "X86_64", "deployment_id": "ecs-svc/7", "evidence_mode": "SYNTHETIC_PROVIDER_SHAPED_HISTORY"}
	prom := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/v1/metadata" {
			name := r.Form.Get("metric")
			kind := "gauge"
			if d, exists := definitionByName[name+"_total"]; exists && d.Type == "SUM" { kind = "counter" }
			_ = json.NewEncoder(w).Encode(model.Document{"status": "success", "data": model.Document{name: []model.Document{{"type": kind, "unit": "Count"}}}})
			return
		}
		if r.URL.Path != "/api/v1/query" { w.WriteHeader(404); return }
		name := strings.SplitN(r.Form.Get("query"), "{", 2)[0]
		if strings.Contains(name, "[") { name = strings.SplitN(name, "[", 2)[0] }
		d, known := definitionByName[name]
		if !known && name != "finops_service_collector_start_time_seconds" { t.Error("unregistered historical query"); w.WriteHeader(400); return }
		metricLabels := map[string]string{"__name__": name}
		for k, v := range labels { metricLabels[k] = v }
		values := []any{}
		for at := start.Add(-5*time.Minute); !at.After(end); at = at.Add(5*time.Minute) {
			value := "0"
			switch {
			case name == "finops_service_collector_start_time_seconds": value = strconv.FormatInt(start.Add(-time.Hour).Unix(), 10)
			case d.Metric == "ECSServiceConfiguration": value = "1"
			case d.Metric == "AcceptedWork" || d.Metric == "CompletedWork": value = strconv.FormatInt(int64(at.Sub(start.Add(-5*time.Minute))/(5*time.Minute))*100, 10)
			}
			values = append(values, []any{at.Unix(), value})
		}
		_ = json.NewEncoder(w).Encode(model.Document{"status": "success", "data": model.Document{"resultType": "matrix", "result": []model.Document{{"metric": metricLabels, "values": values}}}})
	}))
	defer prom.Close()
	batch, e := (telemetry.PromReader{URL: prom.URL, AllowHTTP: true, AllowPrivate: true}).Read(ctx, c, start, end)
	if e != nil || len(batch.Rejections) != 0 || len(batch.Warnings) != 0 { t.Fatal("native historical demand parse", e) }
	pipeline := native.Pipeline{Store: readerDB, Archive: storage.Archive, ReadObject: storage.Read, WriteFacts: storage.WriteFacts}
	receipt, replay, e := pipeline.Publish(ctx, c, batch, "native-fargate-historical-demand", start, end)
	if e != nil || replay { t.Fatal("native historical demand immutable/analytics publication", e) }
	if e = readerDB.Do(ctx, binding.TenantID, func(tx *store.Tx) error { var e error; receipt, e = tx.TelemetryReceipt(ctx, model.String(receipt, "id")); return e }); e != nil { t.Fatal(e) }
	back, e := pipeline.ReadBatch(ctx, binding.TenantID, receipt)
	if e != nil || telemetry.CanonicalHash(back) != telemetry.CanonicalHash(batch) || len(back.Samples) != len(batch.Samples) { t.Fatal("independent original historical batch readback", e) }
	u, e := url.Parse(storage.AnalyticsURL)
	if e != nil { t.Fatal(e) }
	query := u.Query()
	query.Set("database", storage.Database)
	query.Set("query", "SELECT uniqExact(sample_id) FROM native_metric_samples WHERE tenant_id={tenant:String} AND resource_id={resource:String} AND batch_id={batch:String} FORMAT TabSeparated")
	query.Set("param_tenant", binding.TenantID)
	query.Set("param_resource", binding.ResourceID)
	query.Set("param_batch", model.String(receipt, "batch_id"))
	u.RawQuery = query.Encode()
	request, e := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), nil)
	if e != nil { t.Fatal(e) }
	request.Header.Set("X-ClickHouse-User", storage.AnalyticsUser)
	request.Header.Set("X-ClickHouse-Key", storage.AnalyticsSecret)
	response, e := storage.Client.Do(request)
	if e != nil { t.Fatal(e) }
	count, readErr := io.ReadAll(io.LimitReader(response.Body, 1024))
	response.Body.Close()
	if readErr != nil || response.StatusCode != 200 || strings.TrimSpace(string(count)) != strconv.Itoa(len(batch.Samples)) { t.Fatal("independent historical native ClickHouse population differs") }
	if _, replay, e = pipeline.Publish(ctx, c, batch, "native-fargate-historical-demand", start, end); e != nil || !replay { t.Fatal("historical native replay changed population", e) }
}

func awsServicePositiveBilling(t *testing.T, ctx context.Context, apiDB, ingester *store.Store, storage *native.Storage, tenant string, tasks []string, start, end time.Time) {
	t.Helper()
	byMonth := map[string][]model.Document{}
	for at := start; at.Before(end); at = at.Add(time.Hour) {
		for n, task := range tasks {
			for _, part := range []struct{ sku, usage, unit, quantity, rate, cost string }{{"FARGATE_CPU", "EU-Fargate-vCPU-Hours", "vCPU-Hours", "1", "0.04", "0.04"}, {"FARGATE_MEMORY", "EU-Fargate-GB-Hours", "GB-Hours", "2", "0.004", "0.008"}} {
				tags, _ := json.Marshal(model.Document{"aws:ecs:clusterName": "orders", "aws:ecs:serviceName": "web"})
				month := at.Format("2006-01")
				byMonth[month] = append(byMonth[month], model.Document{"identity_line_item_id": fmt.Sprintf("fargate-%d-%s-%s", n, part.sku, at.Format("2006010215")), "line_item_usage_account_id": "111122223333", "line_item_resource_id": task, "line_item_currency_code": "GBP", "line_item_line_item_type": "Usage", "line_item_usage_type": part.usage, "line_item_usage_start_date": at.Format(time.RFC3339), "line_item_usage_end_date": at.Add(time.Hour).Format(time.RFC3339), "line_item_unblended_cost": part.cost, "line_item_net_unblended_cost": part.cost, "line_item_net_unblended_rate": part.rate, "line_item_usage_amount": part.quantity, "pricing_unit": part.unit, "pricing_term": "OnDemand", "pricing_rate_code": part.sku + ".RATE", "product_sku": part.sku, "line_item_operation": "FargateTask", "product_servicecode": "AmazonECS", "product_region_code": "eu-west-1", "product_cpu_architecture": "x86", "product_operating_system": "Linux", "resource_tags": string(tags), "bill_invoice_id": ""})
			}
		}
	}
	for month, rows := range byMonth {
		id := "fargate-cur-" + month + "-" + model.ID()
		d := source.FixtureRegistration(tenant, id)
		if e := apiDB.Do(ctx, tenant, func(tx *store.Tx) error { _, e := tx.SourceCreate(ctx, d); return e }); e != nil {
			t.Fatal(e)
		}
		reg, e := source.ParseRegistration(d)
		if e != nil {
			t.Fatal(e)
		}
		period, _ := time.Parse("2006-01", month)
		reader, e := source.NewFixtureReaderForBillingPeriod(reg, rows, period)
		if e != nil {
			t.Fatal(e)
		}
		now := time.Now().UTC()
		reader.Execution["ExecutionStatus"] = model.Document{"StatusCode": "DELIVERY_SUCCESS", "CreatedAt": now.Add(-time.Second).Format(time.RFC3339Nano)}
		reader.Invoices = []model.Document{}
		for key, object := range reader.Objects {
			object.LastModified = now.Add(-time.Second)
			reader.Objects[key] = object
		}
		normalizer := &service.API{Config: service.Config{EconomicsURL: os.Getenv("ECONOMICS_TEST_URL"), EconomicsToken: os.Getenv("ECONOMICS_TEST_TOKEN")}}
		pipeline := source.Pipeline{Store: ingester, ProviderFactory: func(context.Context, source.Registration) (source.Reader, error) { return reader, nil }, Normalize: normalizer.NormalizeTrustedSource, Persist: service.PersistEvidence, ArchiveObject: func(c context.Context, tenant, _, key string, body []byte) error {
			ref, e := storage.Archive(c, tenant, "wire", "fargate-billing-"+source.BytesHash([]byte(key)), body)
			if e != nil {
				return e
			}
			back, e := storage.Read(c, tenant, ref)
			if e != nil || !bytes.Equal(body, back) {
				return errors.New("native Fargate CUR readback differs")
			}
			return nil
		}}
		if e = pipeline.Sync(ctx, tenant, id); e != nil {
			t.Fatal("actual CUR/Python normalization", e)
		}
	}
}

func awsServicePositiveResult(t *testing.T, result model.Document) {
	t.Helper()
	economics := awsservice.Document(result["economics"])
	if result["model_kind"] != "AWS_SERVICE_ASSESSMENT_V1" || result["status"] != "RECOMMENDED" || result["recommendation_kind"] != "FARGATE_TASK_RIGHTSIZE" || result["read_only"] != true || result["execution_authorized"] != false || result["pre_execution_ready"] != false || result["verified_saving"] != nil || economics["currency"] != "GBP" || economics["current_window_cost"] != "32.256000000000" || economics["candidate_window_cost"] != "16.128000000000" || economics["estimated_window_saving"] != "16.128000000000" || economics["conditional_monthly_run_rate"] != nil {
		t.Fatal("native Fargate economics or read-only boundary differs", result["status"], result["blockers"], economics)
	}
}

func awsServiceSLOMachine(t *testing.T, ctx context.Context, admin, apiDB *store.Store, tenant string, resource model.Document) {
	t.Helper()
	machine := lambdaComponentRuntime(t, ctx, admin, "activity-ingress", "finops_activity")
	key, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	signer, e := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithHeader("kid", "fargate-slo"))
	if e != nil {
		t.Fatal(e)
	}
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "fargate-slo", Algorithm: "RS256", Use: "sig"}}})
	}))
	t.Cleanup(jwks.Close)
	const issuer = "https://native-fargate-machine.invalid"
	const audience = "finops-activity"
	var src slo.Source
	if e = apiDB.Do(ctx, tenant, func(tx *store.Tx) error {
		o := slo.Objective{SchemaVersion: "1", WorkloadID: model.String(resource, "workload_id"), Limits: slo.Limits{MaxErrorRatePPM: 0, MinAvailabilityPPM: 1000000, MaxP95LatencyMS: 200, MaxP99LatencyMS: 200, MinLatencySamples: 1}, EvaluationMinutes: 2, Availability: slo.Availability{Mode: "ALWAYS", Timezone: "UTC", Windows: []slo.Window{}}, Regression: slo.Regression{Enabled: false, MaxPercent: 15}}
		d, e := tx.SLOObjectiveAppend(ctx, o.WorkloadID, 0, slo.Document(o))
		if e != nil {
			return e
		}
		src, e = tx.SLORegister(ctx, slo.Source{SchemaVersion: "1", ID: "native-fargate-slo", ObjectiveID: model.String(d, "id"), WorkloadID: o.WorkloadID, ResourceID: model.String(resource, "id"), ProviderResourceID: model.String(resource, "provider_resource_id"), AccountID: "111122223333", Region: "eu-west-1", Issuer: issuer, Subject: "native-fargate-collector", Enabled: true})
		return e
	}); e != nil {
		t.Fatal(e)
	}
	validator, e := auth.NewMachine(ctx, issuer, audience, jwks.URL)
	if e != nil {
		t.Fatal(e)
	}
	server := httptest.NewServer(activity.NewServer(machine, validator, issuer).Handler())
	t.Cleanup(server.Close)
	access, e := jwt.Signed(signer).Claims(map[string]any{"iss": issuer, "aud": audience, "sub": src.Subject, "tenant_id": tenant, "exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Add(-time.Minute).Unix()}).Serialize()
	if e != nil {
		t.Fatal(e)
	}
	var previous time.Time
	var sequence int64
	submit := func() error {
		end := time.Now().UTC().Truncate(time.Minute)
		if end.Equal(previous) {
			return nil
		}
		sequence++
		upper := int64(100)
		interval := slo.Interval{SchemaVersion: "1", SourceID: src.ID, ObjectiveID: src.ObjectiveID, WorkloadID: src.WorkloadID, ResourceID: src.ResourceID, Sequence: sequence, IntervalStart: end.Add(-time.Minute), IntervalEnd: end, RequestCount: 100, AvailabilityGoodSeconds: 60, AvailabilityTotalSeconds: 60, Latency: slo.Histogram{Unit: "milliseconds", SampleCount: 100, Buckets: []slo.Bucket{{UpperBoundMS: &upper, Count: 100}, {UpperBoundMS: nil, Count: 0}}}}
		raw, _ := json.Marshal(interval)
		request, e := http.NewRequestWithContext(ctx, http.MethodPost, server.URL+"/v1/slo/intervals", bytes.NewReader(raw))
		if e != nil {
			return e
		}
		request.Header.Set("Authorization", "Bearer "+access)
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Idempotency-Key", fmt.Sprint(sequence))
		response, e := server.Client().Do(request)
		if e != nil {
			return e
		}
		response.Body.Close()
		if response.StatusCode != 201 {
			return errors.New("dedicated SLO ingress refused native service evidence")
		}
		previous = end
		return nil
	}
	if e = submit(); e != nil {
		t.Fatal(e)
	}
	done := make(chan struct{})
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop); <-done })
	go func() {
		defer close(done)
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-stop:
				return
			case <-ticker.C:
				if e := submit(); e != nil {
					if ctx.Err() == nil {
						t.Error(e)
					}
					return
				}
			}
		}
	}()
}

func awsServiceComponentBrowser(t *testing.T, ctx context.Context, apiDB, analyst *store.Store, tenant string, resource, policy model.Document, componentID string, positive bool) {
	t.Helper()
	binary := os.Getenv("FINOPS_AWS_SERVICE_ASSESSOR_BINARY")
	if binary != "/tmp/aws-service-finops" {
		t.Fatal("actual compiled AWS service analyst required")
	}
	info, e := os.Lstat(binary)
	if e != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode()&0111 == 0 {
		t.Fatal("AWS service executable unavailable")
	}
	log, e := os.OpenFile("/results/aws-service-analyst.log", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		t.Fatal(e)
	}
	defer log.Close()
	cmd := exec.CommandContext(ctx, binary, "--mode", "aws-service-assessor")
	cmd.Env = []string{"FIXTURE_MODE=true", "PORT=8098", "DATABASE_URL=" + analyst.Pool.Config().ConnConfig.ConnString(), "ECONOMICS_URL=" + os.Getenv("ECONOMICS_TEST_URL"), "ECONOMICS_TOKEN=" + os.Getenv("ECONOMICS_TEST_TOKEN")}
	for _, key := range []string{"OBJECT_REGION", "OBJECT_ENDPOINT", "OBJECT_BUCKET_RAW"} {
		cmd.Env = append(cmd.Env, key+"="+os.Getenv(key))
	}
	for _, pair := range [][2]string{{"OBJECT_ACCESS_KEY", "FINOPS_AWS_SERVICE_READER_ACCESS_KEY"}, {"OBJECT_SECRET_KEY", "FINOPS_AWS_SERVICE_READER_SECRET_KEY"}} {
		if os.Getenv(pair[1]) == "" {
			t.Fatal("version-only reader missing")
		}
		cmd.Env = append(cmd.Env, pair[0]+"="+os.Getenv(pair[1]))
	}
	cmd.Stdout, cmd.Stderr = log, log
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	defer func() {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		select {
		case e := <-done:
			if e != nil {
				t.Error("separate AWS service analyst failed", e)
			}
		case <-time.After(5 * time.Second):
			_ = cmd.Process.Kill()
			<-done
			t.Error("separate AWS service analyst shutdown")
		}
	}()
	validator, e := auth.New(ctx, "http://localhost:8081/realms/finops", "finops", "http://keycloak:8080/realms/finops/protocol/openid-connect/certs")
	if e != nil {
		t.Fatal(e)
	}
	listener, e := net.Listen("tcp", ":8097")
	if e != nil {
		t.Fatal(e)
	}
	server := &http.Server{Handler: (&service.API{Store: apiDB, Auth: validator, Config: service.Config{Fixture: true}}).Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 40 * time.Second, WriteTimeout: 40 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	apiDone := make(chan error, 1)
	go func() { apiDone <- server.Serve(listener) }()
	defer func() {
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
		if e := <-apiDone; e != nil && !errors.Is(e, http.ErrServerClosed) {
			t.Error(e)
		}
	}()
	ready := model.Document{"schema_version": "1", "tenant_id": tenant, "resource_ids": []string{model.String(resource, "id")}}
	raw, _ := json.Marshal(ready)
	readyPath, donePath := "/results/aws-service-native-ready.json", "/results/aws-service-native-browser-done.json"
	if positive {
		readyPath, donePath = "/results/aws-service-native-ready.json", "/results/aws-service-native-browser-done.json"
	}
	file, e := os.OpenFile(readyPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = file.Write(raw); e != nil {
		t.Fatal(e)
	}
	_ = file.Close()
	for {
		body, e := os.ReadFile(donePath)
		if e == nil {
			var proof struct {
				SchemaVersion, TenantID, ReadySHA256 string
				AssessmentIDs                        []string
			}
			var fields model.Document
			if json.Unmarshal(body, &fields) != nil {
				t.Fatal("browser proof invalid")
			}
			proof.SchemaVersion = model.String(fields, "schema_version")
			proof.TenantID = model.String(fields, "tenant_id")
			proof.ReadySHA256 = model.String(fields, "ready_sha256")
			proof.AssessmentIDs = model.Strings(fields, "assessment_ids")
			if proof.SchemaVersion != "1" || proof.TenantID != tenant || proof.ReadySHA256 != awsservice.BytesHash(raw) || len(proof.AssessmentIDs) != 1 || proof.AssessmentIDs[0] == componentID {
				t.Fatal("browser result reused component or wrong source")
			}
			if e = apiDB.Do(ctx, tenant, func(tx *store.Tx) error {
				record, e := tx.AWSServiceAssessmentGet(ctx, proof.AssessmentIDs[0])
				if e != nil {
					return e
				}
				if record["resource_id"] != resource["id"] || !positive && awsservice.Document(record["assessment"])["status"] != "BLOCKED" {
					return errors.New("independent browser stored result differs")
				}
				if positive {
					awsServicePositiveResult(t, awsservice.Document(record["assessment"]))
				}
				var actor string
				if e = tx.QueryRow(ctx, "SELECT created_by FROM aws_service_assessments WHERE tenant_id=$1 AND id=$2", tenant, record["id"]).Scan(&actor); e != nil {
					return e
				}
				if actor == "" || actor == "aws-service-component-verifier" {
					return errors.New("normal OIDC actor absent")
				}
				return nil
			}); e != nil {
				t.Fatal(e)
			}
			break
		}
		if !errors.Is(e, os.ErrNotExist) {
			t.Fatal(e)
		}
		select {
		case <-ctx.Done():
			t.Fatal("normal AWS service component browser deadline")
		case <-time.After(100 * time.Millisecond):
		}
	}
}
