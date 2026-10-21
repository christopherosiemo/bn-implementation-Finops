package workflow

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/activity"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/auth"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/lambdacost"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/native"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/provider"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/service"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/source"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/workload"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/jackc/pgx/v5"
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
)

// One connected COMPONENT chain, explicitly AWS-shaped transport doubles. The
// same collector snapshot reaches the actual API/analyst/Python and optional
// normal OIDC browser. Missing billing/performance history remains BLOCKED.
// This does not claim the separate positive financial/benchmark journey.
func TestLambdaNativeCollectorPersistedBlockedAssessmentThroughActualPython(t *testing.T) {
	lambdaNativeAssessmentJourney(t, false)
}

// The positive journey uses the same registered collector, actual billing
// ingestion, dedicated machine ingress and restricted analyst. Provider replies
// and customer benchmarks are synthetic; no live AWS acceptance is claimed.
func TestLambdaNativeCollectorPersistedPositiveMemoryThroughActualPython(t *testing.T) {
	lambdaNativeAssessmentJourney(t, true)
}

func lambdaNativeAssessmentJourney(t *testing.T, positive bool) {
	t.Helper()
	if os.Getenv("LAMBDA_TEST_STORAGE_ENABLED") != "true" {
		t.Skip("existing owned PostgreSQL/object/ClickHouse lab required")
	}
	if os.Getenv("ECONOMICS_TEST_URL") == "" || os.Getenv("ECONOMICS_TEST_TOKEN") == "" {
		t.Fatal("actual private Python required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	admin, roles := schedulerTestDatabase(t)
	tenant := "lambda-" + model.ID()
	if os.Getenv("FINOPS_LAMBDA_BROWSER") == "true" {
		tenant = "tenant-demo"
	}
	ingester := lambdaComponentRuntime(t, ctx, admin, "ingester", "finops_ingester")
	analyst := lambdaComponentRuntime(t, ctx, admin, "lambda-assessor", "finops_lambda_analyst")
	const arn = "arn:aws:lambda:eu-west-1:111122223333:function:component-processor"
	const resourceID = "lambda-component-resource"
	const workloadID = "lambda-component-workload"
	reg := lambdacost.Registration{ID: "lambda-component-reports", TenantID: tenant, Kind: lambdacost.ReportsKind, AccountID: "111122223333", Region: "eu-west-1", ReadRoleBindingID: "component-reader", FunctionARN: arn, Qualifier: "live", LogGroupARN: "arn:aws:logs:eu-west-1:111122223333:log-group:/aws/lambda/component-processor", LogGroupName: "/aws/lambda/component-processor", Format: "REPORT_TEXT", Version: 1, Enabled: true}
	nativeRegistration := lambdacost.Registration{ID: "lambda-component-native", TenantID: tenant, Kind: lambdacost.NativeKind, AccountID: reg.AccountID, Region: reg.Region, ReadRoleBindingID: reg.ReadRoleBindingID, FunctionARN: arn, Qualifier: "live", Version: 1, Enabled: true}
	end := time.Now().UTC().Truncate(24 * time.Hour)
	start := end.Add(-14 * 24 * time.Hour)
	if e := roles["api"].Do(ctx, tenant, func(tx *store.Tx) error {
		if e := tx.Seed(ctx, true); e != nil {
			return e
		}
		if _, e := tx.Create(ctx, "workloads", model.Document{"id": workloadID, "name": "Synthetic Lambda workload", "owner": "component-owner", "environment": "NON_PRODUCTION"}); e != nil {
			return e
		}
		p := workload.Profile{SchemaVersion: "1", Criticality: "NON_PRODUCTION", Statefulness: "STATELESS", Timezone: "UTC", MinReplicas: 1, MinZones: 1, Headroom: workload.Headroom{CPUFreePPM: 200000, MemoryFreePPM: 200000, ReserveAboveForecastPPM: 100000}, Saturation: workload.Saturation{CPUP99PPM: 800000, MemoryP99PPM: 800000}, RTOSeconds: 300, MaxSimultaneousChangePPM: 100000, VMCooldownSeconds: 86400}
		if _, e := tx.WorkloadSafetyAppend(ctx, workloadID, 0, p); e != nil {
			return e
		}
		if _, e := tx.Create(ctx, "resources", model.Document{"id": resourceID, "provider": "AWS", "resource_type": "LAMBDA_FUNCTION", "provider_resource_id": arn, "account_id": "111122223333", "region": "eu-west-1", "workload_id": workloadID, "owner": "component-owner", "environment": "NON_PRODUCTION", "configuration_authority": "TERRAFORM", "name": "Synthetic Lambda component"}); e != nil {
			return e
		}
		if _, e := tx.SourceCreate(ctx, lambdacost.Document(nativeRegistration)); e != nil {
			return e
		}
		_, e := tx.SourceCreate(ctx, lambdacost.Document(reg))
		return e
	}); e != nil {
		t.Fatal(e)
	}
	sts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("Action") != "AssumeRole" {
			w.WriteHeader(400)
			return
		}
		fmt.Fprintf(w, `<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><AssumeRoleResult><Credentials><AccessKeyId>component-read</AccessKeyId><SecretAccessKey>component-secret</SecretAccessKey><SessionToken>component-session</SessionToken><Expiration>%s</Expiration></Credentials><AssumedRoleUser><Arn>arn:aws:sts::111122223333:assumed-role/component-read/session</Arn><AssumedRoleId>COMPONENT:session</AssumedRoleId></AssumedRoleUser></AssumeRoleResult></AssumeRoleResponse>`, time.Now().UTC().Add(time.Hour).Format(time.RFC3339))
	}))
	defer sts.Close()
	for key, value := range map[string]string{"AWS_TENANT_ID": tenant, "AWS_ACCESS_KEY_ID": "component-source", "AWS_SECRET_ACCESS_KEY": "component-source-secret", "AWS_SESSION_TOKEN": "", "AWS_ROLE_ARN": "", "AWS_WEB_IDENTITY_TOKEN_FILE": "", "AWS_PROFILE": "", "AWS_ENDPOINT_URL_STS": sts.URL, "AWS_EC2_METADATA_DISABLED": "true"} {
		t.Setenv(key, value)
	}
	storage, e := native.StorageFromEnvironment(ctx, true)
	if e != nil {
		t.Fatal(e)
	}
	if positive {
		lambdaPositiveBilling(t, ctx, roles["api"], ingester, storage, tenant, arn, start, end)
	}
	original := http.DefaultTransport
	denied := false
	activeQualifier := "live"
	http.DefaultTransport = databaseFixtureTransport(func(r *http.Request) (*http.Response, error) {
		body := ""
		if r.Body != nil {
			raw, e := io.ReadAll(r.Body)
			if e != nil {
				return nil, e
			}
			body = string(raw)
		}
		host := r.URL.Host
		var out any
		var raw string
		switch {
		case host == "sts.eu-west-1.amazonaws.com":
			raw = `<GetCallerIdentityResponse><GetCallerIdentityResult><Account>111122223333</Account><Arn>arn:aws:sts::111122223333:assumed-role/component-read/session</Arn><UserId>COMPONENT:session</UserId></GetCallerIdentityResult></GetCallerIdentityResponse>`
		case host == "lambda.eu-west-1.amazonaws.com":
			if denied {
				return &http.Response{StatusCode: 403, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(`{"__type":"AccessDeniedException"}`))}, nil
			}
			configuration := func(version string) model.Document {
				a := arn
				if version != "$LATEST" {
					a += ":" + version
				}
				d := model.Document{"FunctionArn": a, "FunctionName": "component-processor", "Version": version, "MemorySize": 2048, "Architectures": []string{"x86_64"}, "Runtime": "python3.13", "PackageType": "Zip", "Handler": "main.handler", "CodeSha256": "synthetic-code", "RevisionId": "synthetic-config-" + version, "Timeout": 30, "State": "Active", "LastUpdateStatus": "Successful", "EphemeralStorage": model.Document{"Size": 512}, "Environment": model.Document{"Variables": model.Document{"SECRET": "SYNTHETIC_SECRET_MUST_NOT_PERSIST"}}, "LoggingConfig": model.Document{"LogGroup": reg.LogGroupName, "LogFormat": "Text"}}
				if positive {
					// Full native GETs positively observe an empty environment. The
					// sanitizer's presence/count alone cannot establish equivalence.
					d["CodeSha256"] = strings.Repeat("a", 64)
					d["LastModified"] = start.Add(-24 * time.Hour).Format(time.RFC3339Nano)
					d["RuntimeVersionConfig"] = model.Document{"RuntimeVersionArn": "arn:aws:lambda:eu-west-1::runtime:" + strings.Repeat("b", 64)}
					d["Environment"] = model.Document{"Variables": model.Document{}}
					d["VpcConfig"] = model.Document{"VpcId": "", "SubnetIds": []string{}, "SecurityGroupIds": []string{}, "Ipv6AllowedForDualStack": false}
					d["Layers"], d["FileSystemConfigs"] = []model.Document{}, []model.Document{}
					d["TracingConfig"], d["DeadLetterConfig"], d["SnapStart"] = model.Document{"Mode": "PassThrough"}, model.Document{}, model.Document{"ApplyOn": "None", "OptimizationStatus": "Off"}
					d["Role"] = "arn:aws:iam::111122223333:role/component-function-runtime"
					if version == "2" {
						d["MemorySize"] = 1536
					}
				}
				return d
			}
			switch {
			case r.URL.Path == "/2015-03-31/functions/":
				out = model.Document{"Functions": []model.Document{configuration("$LATEST")}}
			case strings.HasSuffix(r.URL.Path, "/configuration"):
				q := r.URL.Query().Get("Qualifier")
				if q == "" {
					q = "$LATEST"
				}
				out = configuration(q)
			case strings.HasSuffix(r.URL.Path, "/versions"):
				out = model.Document{"Versions": []model.Document{configuration("$LATEST"), configuration("1")}}
				if positive {
					out = model.Document{"Versions": []model.Document{configuration("$LATEST"), configuration("1"), configuration("2")}}
				}
			case strings.HasSuffix(r.URL.Path, "/aliases"):
				out = model.Document{"Aliases": []model.Document{{"AliasArn": arn + ":live", "Name": "live", "FunctionVersion": "1", "RevisionId": "synthetic-alias", "RoutingConfig": model.Document{}}}}
			case strings.HasSuffix(r.URL.Path, "/provisioned-concurrency"):
				out = model.Document{"ProvisionedConcurrencyConfigs": []model.Document{{"FunctionArn": arn + ":live", "RequestedProvisionedConcurrentExecutions": 2, "AllocatedProvisionedConcurrentExecutions": 2, "Status": "READY"}}}
				if positive {
					out = model.Document{"ProvisionedConcurrencyConfigs": []model.Document{}}
				}
			case strings.HasSuffix(r.URL.Path, "/event-source-mappings/"):
				out = model.Document{"EventSourceMappings": []model.Document{{"UUID": "synthetic-mapping", "FunctionArn": arn + ":live", "EventSourceArn": "arn:aws:sqs:eu-west-1:111122223333:component-work", "State": "Enabled", "BatchSize": 10}}}
			case strings.HasSuffix(r.URL.Path, "/event-invoke-config/list"):
				out = model.Document{"FunctionEventInvokeConfigs": []model.Document{}}
			case strings.HasSuffix(r.URL.Path, "/urls"):
				out = model.Document{"FunctionUrlConfigs": []model.Document{}}
			case strings.HasSuffix(r.URL.Path, "/concurrency"):
				out = model.Document{"ReservedConcurrentExecutions": 20}
			case strings.HasPrefix(r.URL.Path, "/2017-03-31/tags/"):
				out = model.Document{"Tags": model.Document{"Owner": "component-owner"}}
			case strings.HasSuffix(r.URL.Path, "/account-settings/"):
				out = model.Document{"AccountLimit": model.Document{"ConcurrentExecutions": 1000, "UnreservedConcurrentExecutions": 900}}
			default:
				return nil, errors.New("unplanned Lambda native operation")
			}
		case host == "monitoring.eu-west-1.amazonaws.com":
			v, _ := url.ParseQuery(body)
			start, _ := time.Parse(time.RFC3339, v.Get("StartTime"))
			stat := v.Get("Statistics.member.1")
			raw = fmt.Sprintf("<GetMetricStatisticsResponse><GetMetricStatisticsResult><Datapoints><member><Timestamp>%s</Timestamp><%s>1</%s><SampleCount>1</SampleCount><Unit>%s</Unit></member></Datapoints></GetMetricStatisticsResult></GetMetricStatisticsResponse>", start.Format(time.RFC3339), stat, stat, v.Get("Unit"))
			if positive {
				until, _ := time.Parse(time.RFC3339, v.Get("EndTime"))
				period, _ := strconv.Atoi(v.Get("Period"))
				var points strings.Builder
				metric := v.Get("MetricName")
				// Only explicitly observed bins are returned. Other signal types
				// retain their native absent/unknown state, not invented zeroes.
				if activeQualifier == "live" && (metric == "Invocations" || metric == "Errors" || metric == "Throttles" || metric == "ConcurrentExecutions" || metric == "Duration") {
					for at := start; at.Before(until); at = at.Add(time.Duration(period) * time.Second) {
						value := "0"
						if metric == "Invocations" && at.Hour() == 23 && at.Minute() == 0 {
							value = "10"
						} else if metric == "ConcurrentExecutions" {
							value = "1"
						} else if metric == "Duration" {
							value = "900"
						}
						fmt.Fprintf(&points, "<member><Timestamp>%s</Timestamp><%s>%s</%s><SampleCount>1</SampleCount><Unit>%s</Unit></member>", at.Format(time.RFC3339), stat, value, stat, v.Get("Unit"))
					}
				}
				raw = "<GetMetricStatisticsResponse><GetMetricStatisticsResult><Datapoints>" + points.String() + "</Datapoints></GetMetricStatisticsResult></GetMetricStatisticsResponse>"
			}
		case host == "logs.eu-west-1.amazonaws.com":
			at := time.Now().UTC().Truncate(24 * time.Hour).Add(-time.Hour)
			out = model.Document{"events": []model.Document{{"eventId": "component-report", "timestamp": at.UnixMilli(), "logStreamName": "2026/10/20/[1]environment", "message": "REPORT RequestId: component-report Duration: 12.4 ms Billed Duration: 113 ms Memory Size: 2048 MB Max Memory Used: 700 MB Init Duration: 100 ms"}}}
			if positive {
				events := []model.Document{}
				for day := start; day.Before(end); day = day.Add(24 * time.Hour) {
					for n := 0; n < 10; n++ {
						at := day.Add(23*time.Hour + time.Duration(n)*time.Second)
						id := "component-" + at.Format("20060102T150405")
						events = append(events, model.Document{"eventId": id, "timestamp": at.UnixMilli(), "logStreamName": at.Format("2006/01/02") + "/[1]environment", "message": "REPORT RequestId: " + id + " Duration: 900 ms Billed Duration: 1000 ms Memory Size: 2048 MB Max Memory Used: 700 MB Init Duration: 100 ms"})
					}
				}
				out = model.Document{"events": events}
			}
		case host == "api.pricing.us-east-1.amazonaws.com" && positive:
			request := model.Document{}
			_ = json.Unmarshal([]byte(body), &request)
			filters := lambdacost.Rows(request["Filters"])
			if len(filters) != 1 {
				return nil, errors.New("unregistered Lambda catalogue scope")
			}
			sku := model.String(filters[0], "Value")
			unit, usage := "Requests", "EUN1-Request"
			if sku == "SKU_compute" {
				unit, usage = "Lambda-GB-Second", "EUN1-Lambda-GB-Second"
			} else if sku != "SKU_request" {
				return nil, errors.New("unregistered Lambda SKU")
			}
			dimension := model.Document{"rateCode": sku + ".native", "beginRange": "0", "endRange": "Inf", "unit": unit, "appliesTo": []string{}, "pricePerUnit": model.Document{"USD": "99999"}}
			term := model.Document{"effectiveDate": "2026-01-01T00:00:00Z", "priceDimensions": model.Document{sku + ".native": dimension}}
			product := model.Document{"product": model.Document{"sku": sku, "attributes": model.Document{"regionCode": "eu-west-1", "servicecode": "AWSLambda", "usagetype": usage, "operation": "AWSLambda"}}, "publicationDate": "2026-01-01T00:00:00Z", "terms": model.Document{"OnDemand": model.Document{"native": term}}}
			encoded, _ := json.Marshal(product)
			out = model.Document{"PriceList": []string{string(encoded)}}
		default:
			if strings.HasSuffix(host, "amazonaws.com") {
				return nil, errors.New("unregistered AWS endpoint refused")
			}
			r.Body = io.NopCloser(strings.NewReader(body))
			return original.RoundTrip(r)
		}
		if out != nil {
			b, _ := json.Marshal(out)
			raw = string(b)
		}
		return &http.Response{StatusCode: 200, Header: http.Header{}, ContentLength: int64(len(raw)), Body: io.NopCloser(strings.NewReader(raw))}, nil
	})
	defer func() { http.DefaultTransport = original }()
	reader, e := provider.NewAWS(ctx, "eu-west-1", "arn:aws:iam::111122223333:role/component-read", "component-external-id-at-least-thirty-two")
	if e != nil {
		t.Fatal(e)
	}
	scope := lambdacost.Scope{TenantID: tenant, AccountID: "111122223333", Region: "eu-west-1"}
	discovery, e := reader.LambdaDiscover(ctx, scope, lambdacost.DiscoverySelection{MaxFunctions: 1})
	if e != nil || !discovery.Complete || len(discovery.Functions) != 1 {
		t.Fatal("native discovery", e)
	}
	if bytes.Contains(discovery.Raw, []byte("SYNTHETIC_SECRET_MUST_NOT_PERSIST")) {
		t.Fatal("native archive has environment value")
	}
	e = SyncLambdaNativeSource(ctx, &Activities{Store: ingester}, storage, reader, nativeRegistration, []lambdacost.Registration{reg}, LambdaCollectionOptions{ReportReader: func(context.Context, lambdacost.Registration) (LambdaNativeReader, error) { return reader, nil }})
	if e != nil {
		t.Fatal("native collector archive/analytics/publication", e)
	}
	var snapshot, resource model.Document
	if e = ingester.Do(ctx, tenant, func(tx *store.Tx) error {
		var e error
		snapshot, e = tx.LambdaEvidenceLatest(ctx, resourceID, "live")
		if e != nil {
			return e
		}
		resource, e = tx.Get(ctx, "resources", resourceID)
		if e != nil {
			return e
		}
		registered, e := tx.SourceGet(ctx, nativeRegistration.ID)
		if e != nil {
			return e
		}
		if registered["status"] != "HEALTHY" {
			return errors.New("registered native sync did not publish health")
		}
		return nil
	}); e != nil {
		t.Fatal("registered native serving snapshot not published", e)
	}
	if resource["id"] != resourceID || resource["workload_id"] != workloadID || resource["configuration_authority"] != "TERRAFORM" || len(lambdacost.Rows(resource["provider_relationships"])) != 1 {
		t.Fatal("native workload or authority lost")
	}
	raw, e := storage.Read(ctx, tenant, lambdacost.Document(snapshot["archive"]))
	if e != nil || lambdacost.BytesHash(raw) != snapshot["content_hash"] || bytes.Contains(raw, []byte("SYNTHETIC_SECRET_MUST_NOT_PERSIST")) {
		t.Fatal("immutable snapshot readback differs", e)
	}
	if e = roles["api"].Do(ctx, "foreign-"+tenant, func(tx *store.Tx) error { _, e := tx.LambdaEvidenceGet(ctx, model.String(snapshot, "id")); return e }); !errors.Is(e, pgx.ErrNoRows) {
		t.Fatal("cross-tenant native evidence visible", e)
	}
	denied = true
	if _, e = reader.LambdaDiscover(ctx, scope, lambdacost.DiscoverySelection{}); e == nil {
		t.Fatal("denied reads became complete inventory")
	}
	denied = false
	if positive {
		versions := map[string]model.Document{}
		for _, version := range []string{"1", "2"} {
			registration := nativeRegistration
			registration.ID, registration.Qualifier = nativeRegistration.ID+"-"+version, version
			if e = roles["api"].Do(ctx, tenant, func(tx *store.Tx) error { _, e := tx.SourceCreate(ctx, lambdacost.Document(registration)); return e }); e != nil {
				t.Fatal(e)
			}
			activeQualifier = version
			if e = SyncLambdaNativeSource(ctx, &Activities{Store: ingester}, storage, reader, registration, nil, LambdaCollectionOptions{}); e != nil {
				t.Fatal("native published configuration observation", e)
			}
			if e = ingester.Do(ctx, tenant, func(tx *store.Tx) error {
				var e error
				versions[version], e = tx.LambdaEvidenceLatest(ctx, resourceID, version)
				return e
			}); e != nil {
				t.Fatal(e)
			}
		}
		lambdaPositiveBenchmarks(t, ctx, admin, roles["api"], storage, tenant, resource, versions)
	}
	lambdaComponentAPI(t, ctx, admin, roles["api"], analyst, tenant, resource, snapshot, positive)
}

func lambdaPositiveBilling(t *testing.T, ctx context.Context, apiDB, ingester *store.Store, storage *native.Storage, tenant, arn string, start, end time.Time) {
	t.Helper()
	byMonth := map[string][]model.Document{}
	for day := start; day.Before(end); day = day.Add(24 * time.Hour) {
		at := day.Add(23 * time.Hour)
		for _, part := range []struct{ kind, usage, unit, quantity, rate, cost string }{{"request", "EUN1-Request", "Requests", "10", "0.0000002", "0.000002"}, {"compute", "EUN1-Lambda-GB-Second", "Lambda-GB-Second", "20", "0.00002", "0.0004"}} {
			key := day.Format("2006-01")
			byMonth[key] = append(byMonth[key], model.Document{"identity_line_item_id": "lambda-" + part.kind + "-" + day.Format("20060102"), "line_item_usage_account_id": "111122223333", "line_item_resource_id": arn, "line_item_currency_code": "GBP", "line_item_line_item_type": "Usage", "line_item_usage_start_date": at.Format(time.RFC3339), "line_item_usage_end_date": at.Add(time.Hour).Format(time.RFC3339), "line_item_unblended_cost": part.cost, "line_item_net_unblended_cost": part.cost, "line_item_net_unblended_rate": part.rate, "line_item_usage_amount": part.quantity, "pricing_unit": part.unit, "pricing_term": "OnDemand", "pricing_rate_code": "SKU_" + part.kind + ".native", "product_sku": "SKU_" + part.kind, "line_item_operation": "AWSLambda", "product_servicecode": "AWSLambda", "product_region_code": "eu-west-1", "bill_invoice_id": ""})
		}
	}
	for month, rows := range byMonth {
		id := "lambda-native-cur-" + month + "-" + model.ID()
		d := source.FixtureRegistration(tenant, id)
		if e := apiDB.Do(ctx, tenant, func(tx *store.Tx) error { _, e := tx.SourceCreate(ctx, d); return e }); e != nil {
			t.Fatal(e)
		}
		registration, e := source.ParseRegistration(d)
		if e != nil {
			t.Fatal(e)
		}
		period, _ := time.Parse("2006-01", month)
		reader, e := source.NewFixtureReaderForBillingPeriod(registration, rows, period)
		if e != nil {
			t.Fatal(e)
		}
		// An open native export is complete through observed usage, without an
		// invented issued invoice or a future delivery timestamp.
		now := time.Now().UTC()
		reader.Execution["ExecutionStatus"] = model.Document{"StatusCode": "DELIVERY_SUCCESS", "CreatedAt": now.Add(-time.Second).Format(time.RFC3339Nano)}
		reader.Invoices = []model.Document{}
		for key, object := range reader.Objects {
			object.LastModified = now.Add(-time.Second)
			reader.Objects[key] = object
		}
		normalizer := &service.API{Config: service.Config{EconomicsURL: os.Getenv("ECONOMICS_TEST_URL"), EconomicsToken: os.Getenv("ECONOMICS_TEST_TOKEN")}}
		pipeline := source.Pipeline{Store: ingester, ProviderFactory: func(context.Context, source.Registration) (source.Reader, error) { return reader, nil }, Normalize: normalizer.NormalizeTrustedSource, Persist: service.PersistEvidence, ArchiveObject: func(c context.Context, tenant, _, key string, raw []byte) error {
			ref, e := storage.Archive(c, tenant, "wire", "lambda-billing-"+source.BytesHash([]byte(key)), raw)
			if e != nil {
				return e
			}
			back, e := storage.Read(c, tenant, ref)
			if e != nil || !bytes.Equal(raw, back) {
				return errors.New("native billing archive readback differs")
			}
			return nil
		}}
		if e = pipeline.Sync(ctx, tenant, id); e != nil {
			t.Fatal("actual provider-shaped CUR pipeline", e)
		}
		if e = ingester.Do(ctx, tenant, func(tx *store.Tx) error {
			registration, e := tx.SourceGet(ctx, id)
			if e != nil {
				return e
			}
			if registration["status"] != "HEALTHY" {
				return errors.New("native billing source incomplete")
			}
			receipt, e := tx.SourceReceiptGet(ctx, model.String(registration, "latest_receipt_id"))
			if e != nil {
				return e
			}
			job, e := tx.Get(ctx, "ingestion_jobs", model.String(receipt, "ingestion_job_id"))
			if e != nil {
				return e
			}
			canonical := lambdacost.Document(job["canonical"])
			if len(lambdacost.Rows(canonical["records"])) != len(rows) {
				return errors.New("actual Python changed billing population")
			}
			return nil
		}); e != nil {
			t.Fatal(e)
		}
		endpoint, e := url.Parse(storage.AnalyticsURL)
		if e != nil {
			t.Fatal(e)
		}
		q := endpoint.Query()
		q.Set("database", storage.Database)
		q.Set("query", "SELECT uniqExact(tuple(source_version,source_record_id)) FROM billing_facts WHERE tenant_id={tenant:String} AND source_id={source:String} FORMAT TabSeparated")
		q.Set("param_tenant", tenant)
		q.Set("param_source", id)
		endpoint.RawQuery = q.Encode()
		request, e := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), nil)
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
		_ = response.Body.Close()
		if e != nil || response.StatusCode != 200 || strings.TrimSpace(string(body)) != strconv.Itoa(len(rows)) {
			t.Fatal("native CUR analytical population readback differs")
		}
	}
}

func lambdaPositiveBenchmarks(t *testing.T, ctx context.Context, admin, apiDB *store.Store, nativeArchive *native.Storage, tenant string, resource model.Document, versions map[string]model.Document) {
	t.Helper()
	machine := lambdaComponentRuntime(t, ctx, admin, "activity-ingress", "finops_activity")
	archive, e := activity.LambdaPerformanceStorageFromEnvironment(ctx, true)
	if e != nil {
		t.Fatal("commissioned dedicated benchmark storage required", e)
	}
	key, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	signer, e := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithHeader("kid", "lambda-benchmark"))
	if e != nil {
		t.Fatal(e)
	}
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "lambda-benchmark", Algorithm: "RS256", Use: "sig"}}})
	}))
	defer jwks.Close()
	const issuer = "https://lambda-benchmark.invalid/realms/finops"
	const audience = "finops-lambda-performance"
	const subject = "registered-lambda-benchmark"
	const sourceID = "lambda-positive-performance"
	if e = apiDB.Do(ctx, tenant, func(tx *store.Tx) error {
		_, e := tx.SourceCreate(ctx, model.Document{"id": sourceID, "kind": "AWS_LAMBDA_PERFORMANCE_CURVE_V1", "enabled": true, "issuer": issuer, "audience": audience, "subject": subject, "account_id": resource["account_id"], "region": resource["region"], "function_arn": resource["provider_resource_id"], "qualifier": "live"})
		return e
	}); e != nil {
		t.Fatal(e)
	}
	validator, e := auth.NewMachine(ctx, issuer, audience, jwks.URL)
	if e != nil {
		t.Fatal(e)
	}
	server := httptest.NewServer((&activity.Server{Store: machine, LambdaPerformance: &activity.LambdaPerformance{Auth: validator, Issuer: issuer, Audience: audience, Archive: archive}}).Handler())
	defer server.Close()
	token := func(aud string, roles []string) string {
		access, e := jwt.Signed(signer).Claims(map[string]any{"iss": issuer, "aud": aud, "sub": subject, "exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Add(-time.Minute).Unix(), "tenant_id": tenant, "realm_access": model.Document{"roles": roles}}).Serialize()
		if e != nil {
			t.Fatal(e)
		}
		return access
	}
	observed := map[string]model.Document{}
	for version, snapshot := range versions {
		raw, e := nativeArchive.Read(ctx, tenant, lambdacost.Document(snapshot["archive"]))
		if e != nil || lambdacost.BytesHash(raw) != snapshot["content_hash"] {
			t.Fatal("native configuration reference readback", e)
		}
		canonical := model.Document{}
		if json.Unmarshal(raw, &canonical) != nil {
			t.Fatal("native snapshot invalid")
		}
		observed[version] = lambdacost.Document(canonical["configuration"])
	}
	measurementStart := time.Now().UTC()
	select {
	case <-ctx.Done():
		t.Fatal("benchmark observation deadline")
	case <-time.After(2 * time.Second):
	}
	measurementEnd := time.Now().UTC()
	for index, version := range []string{"1", "2"} {
		configuration, snapshot := observed[version], versions[version]
		fingerprint, reasons := lambdacost.NonMemoryFingerprint(configuration)
		if len(reasons) > 0 {
			t.Fatal("native configuration comparability incomplete", reasons)
		}
		billed, total, duration, memory := "1000", "10000", "9000", "2048"
		if version == "2" {
			billed, total, duration, memory = "1100", "11000", "10000", "1536"
		}
		point := model.Document{"binding": model.Document{"tenant_id": tenant, "resource_id": resource["id"], "workload_id": resource["workload_id"], "provider": "AWS", "provider_resource_id": resource["provider_resource_id"], "account_id": resource["account_id"], "region": resource["region"]}, "qualifier": "live", "executed_version": version, "executed_target_arn": model.String(resource, "provider_resource_id") + ":" + version, "code_sha256": configuration["code_sha256"], "comparison_fingerprint": strings.Repeat("c", 64), "workload_definition_id": "completed-component-messages", "workload_definition_version": "1", "workload_mix_hash": strings.Repeat("d", 64), "load_profile_hash": strings.Repeat("e", 64), "architecture": "x86_64", "memory_size_mb": memory, "invocations": "10", "successful_work": "10", "errors": "0", "throttles": "0", "total_duration_ms": duration, "total_billed_duration_ms": total, "p95_duration_ms": billed, "p99_duration_ms": "1200", "max_memory_used_mb": "700", "peak_concurrent_executions": "10", "p95_application_latency_ms": "1500", "cold_start_p95_ms": "100", "measurement_start": measurementStart.Format(time.RFC3339Nano), "measurement_end": measurementEnd.Format(time.RFC3339Nano), "native_configuration_ref": model.Document{"snapshot_id": snapshot["id"], "content_hash": snapshot["content_hash"], "config_hash": snapshot["config_hash"]}, "configuration_epoch_hash": configuration["configuration_epoch_hash"], "non_memory_compatibility": model.Document{"definition_version": lambdacost.NonMemoryConfigurationVersion, "sha256": fingerprint, "dependency_manifest_sha256": strings.Repeat("f", 64)}}
		body, _ := json.Marshal(model.Document{"schema_version": "2", "source_id": sourceID, "source_version": 1, "sequence": strconv.Itoa(index + 1), "point": point})
		post := func(access, key string, raw []byte) (int, model.Document) {
			request, e := http.NewRequestWithContext(ctx, http.MethodPost, server.URL+"/v1/lambda-performance/batches", bytes.NewReader(raw))
			if e != nil {
				t.Fatal(e)
			}
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Authorization", "Bearer "+access)
			request.Header.Set("Idempotency-Key", key)
			response, e := server.Client().Do(request)
			if e != nil {
				t.Fatal(e)
			}
			defer response.Body.Close()
			d := model.Document{}
			if json.NewDecoder(io.LimitReader(response.Body, 16<<10)).Decode(&d) != nil {
				t.Fatal("benchmark response invalid")
			}
			return response.StatusCode, d
		}
		if index == 0 {
			if code, _ := post(token("finops", []string{"FINOPS_ADMIN"}), "lambda-console-refused", body); code != 401 {
				t.Fatal("console token manufactured benchmark", code)
			}
		}
		access, idempotency := token(audience, nil), "lambda-positive-benchmark-"+version
		code, receipt := post(access, idempotency, body)
		if code != 201 {
			t.Fatal("registered machine benchmark", code, receipt)
		}
		if code, replay := post(access, idempotency, body); code != 200 || replay["id"] != receipt["id"] {
			t.Fatal("benchmark replay changed")
		}
		conflict := bytes.Replace(body, []byte(`"successful_work":"10"`), []byte(`"successful_work":"9"`), 1)
		if code, _ := post(access, idempotency, conflict); code != 409 {
			t.Fatal("conflicting benchmark replay admitted", code)
		}
		if model.String(receipt, "received_at") == "" || receipt["schema_version"] != "2" || len(lambdacost.Document(receipt["analytics"])) == 0 || len(lambdacost.Document(receipt["archive"])) == 0 {
			t.Fatal("benchmark lost receipt/archive/analytics provenance")
		}
	}
}

func lambdaComponentRuntime(t *testing.T, ctx context.Context, admin *store.Store, mode, group string) *store.Store {
	t.Helper()
	login := "lambda_component_" + strings.ReplaceAll(model.ID(), "-", "")
	password := model.ID() + model.ID()
	marker := "owned-lambda-component:" + login
	if _, e := admin.Pool.Exec(ctx, "CREATE ROLE "+pgx.Identifier{login}.Sanitize()+" LOGIN PASSWORD '"+password+"' IN ROLE "+pgx.Identifier{group}.Sanitize()); e != nil {
		t.Fatal(e)
	}
	if _, e := admin.Pool.Exec(ctx, "COMMENT ON ROLE "+pgx.Identifier{login}.Sanitize()+" IS '"+marker+"'"); e != nil {
		t.Fatal(e)
	}
	u, e := url.Parse(admin.Pool.Config().ConnConfig.ConnString())
	if e != nil {
		t.Fatal(e)
	}
	u.User = url.UserPassword(login, password)
	db, e := store.OpenRuntime(ctx, u.String(), mode)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		db.Pool.Close()
		var actual string
		if e := admin.Pool.QueryRow(context.Background(), "SELECT coalesce(shobj_description(oid,'pg_authid'),'') FROM pg_roles WHERE rolname=$1", login).Scan(&actual); e != nil || actual != marker {
			t.Error("Lambda owned login changed")
			return
		}
		if _, e := admin.Pool.Exec(context.Background(), "DROP ROLE "+pgx.Identifier{login}.Sanitize()); e != nil {
			t.Error(e)
		}
	})
	return db
}

func lambdaComponentAPI(t *testing.T, ctx context.Context, admin, apiDB, analyst *store.Store, tenant string, resource, snapshot model.Document, positive bool) {
	t.Helper()
	key, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	signer, e := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithHeader("kid", "lambda-component"))
	if e != nil {
		t.Fatal(e)
	}
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "lambda-component", Algorithm: "RS256", Use: "sig"}}})
	}))
	defer jwks.Close()
	const issuer = "https://component-lambda.invalid/realms/finops"
	validator, e := auth.New(ctx, issuer, "finops", jwks.URL)
	if e != nil {
		t.Fatal(e)
	}
	token := func(tenant string) string {
		s, e := jwt.Signed(signer).Claims(map[string]any{"iss": issuer, "aud": "finops", "sub": "lambda-component-verifier", "exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Add(-time.Minute).Unix(), "tenant_id": tenant, "realm_access": model.Document{"roles": []string{"FINOPS_ADMIN"}}}).Serialize()
		if e != nil {
			t.Fatal(e)
		}
		return s
	}
	server := httptest.NewServer((&service.API{Store: apiDB, Auth: validator, Config: service.Config{Fixture: true}}).Handler())
	defer server.Close()
	request := func(method, path, access, idempotency string, body model.Document) (int, model.Document) {
		var b []byte
		if body != nil {
			b, _ = json.Marshal(body)
		}
		r, e := http.NewRequestWithContext(ctx, method, server.URL+"/v1/"+path, bytes.NewReader(b))
		if e != nil {
			t.Fatal(e)
		}
		if access != "" {
			r.Header.Set("Authorization", "Bearer "+access)
		}
		if method == "POST" {
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("If-Match", `"0"`)
			r.Header.Set("Idempotency-Key", idempotency)
		}
		res, e := server.Client().Do(r)
		if e != nil {
			t.Fatal(e)
		}
		defer res.Body.Close()
		d := model.Document{}
		if json.NewDecoder(io.LimitReader(res.Body, 8<<20)).Decode(&d) != nil {
			t.Fatal("bounded API response invalid")
		}
		return res.StatusCode, d
	}
	access := token(tenant)
	if code, _ := request("GET", "lambda-assessments", "", "", nil); code != 401 {
		t.Fatal("unauthenticated API admitted", code)
	}
	body := model.Document{"resource_id": resource["id"], "qualifier": "live"}
	if code, _ := request("POST", "lambda-assessments", token("foreign-"+tenant), "lambda-foreign-tenant", body); code != 404 {
		t.Fatal("cross-tenant request admitted", code)
	}
	declared := model.Document{"owner": "component-owner", "criticality": "NON_PRODUCTION", "timezone": "UTC", "configuration_authority": "TERRAFORM", "latency_sensitive": true, "latency_slo_ms": "200", "memory_headroom_fraction": "0.2", "max_error_rate": "0", "max_throttle_rate": "0", "available_concurrency": "20", "bursts_known": false}
	if positive {
		declared["latency_slo_ms"], declared["max_duration_ms"], declared["concurrency_headroom_fraction"], declared["bursts_known"] = "2000", "10000", "0.2", true
	}
	code, policy := request("POST", "lambda-policies", access, "native-component-policy", model.Document{"resource_id": resource["id"], "name": "Synthetic Lambda component requirements", "policy": declared})
	if code != 201 {
		t.Fatal("normal policy API", code, policy)
	}
	body["policy_id"] = policy["id"]
	code, queued := request("POST", "lambda-assessments", access, "native-component-assessment", body)
	if code != 202 {
		t.Fatal("IDs-only native assessment", code, queued)
	}
	code, replay := request("POST", "lambda-assessments", access, "native-component-assessment", body)
	if code != 202 || replay["id"] != queued["id"] {
		t.Fatal("native request replay differs")
	}
	if e = apiDB.Do(ctx, tenant, func(tx *store.Tx) error {
		var selected string
		if e := tx.QueryRow(ctx, "SELECT snapshot_id FROM lambda_assessments WHERE tenant_id=$1 AND id=$2", tenant, queued["id"]).Scan(&selected); e != nil {
			return e
		}
		if selected != snapshot["id"] {
			return errors.New("API selected synthetic replacement snapshot")
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	workerCtx, stop := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() {
		done <- service.RunLambdaAssessor(workerCtx, service.Config{Fixture: true, EconomicsURL: os.Getenv("ECONOMICS_TEST_URL"), EconomicsToken: os.Getenv("ECONOMICS_TEST_TOKEN")}, analyst)
	}()
	stopped := false
	stopWorker := func() {
		if stopped {
			return
		}
		stopped = true
		stop()
		select {
		case e := <-done:
			if e != nil {
				t.Error(e)
			}
		case <-time.After(5 * time.Second):
			t.Error("Lambda assessor shutdown")
		}
	}
	defer stopWorker()
	var stored model.Document
	for {
		code, stored = request("GET", "lambda-assessments/"+model.String(queued, "id"), access, "", nil)
		if code != 200 {
			t.Fatal("persisted assessment read", code, stored)
		}
		if stored["status"] == "BLOCKED" || positive && (stored["status"] == "ASSESSED" || stored["status"] == "FAILED") {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("native persisted actual-Python deadline")
		case <-time.After(150 * time.Millisecond):
		}
	}
	result := lambdacost.Document(stored["assessment"])
	if positive {
		if stored["status"] != "ASSESSED" || stored["current"] != true {
			t.Fatal("positive native result not current or assessed", stored["status"], stored["currentness_blockers"])
		}
		lambdaPositiveMemoryResult(t, result)
	} else if result["status"] != "BLOCKED" || result["verified_saving"] != nil || model.Bool(result, "execution_authorized") || len(model.Strings(result, "reason_codes")) == 0 || len(lambdacost.Rows(result["source_refs"])) == 0 {
		t.Fatal("native blocked result inflated or lost provenance", result)
	}
	if e = apiDB.Do(ctx, tenant, func(tx *store.Tx) error {
		var count int
		if e := tx.QueryRow(ctx, "SELECT count(*) FROM lambda_recommendation_publications WHERE tenant_id=$1 AND assessment_id=$2", tenant, queued["id"]).Scan(&count); e != nil {
			return e
		}
		if count != 1 {
			return errors.New("idempotent request produced duplicate analytical publications")
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	stopWorker()
	if os.Getenv("FINOPS_LAMBDA_BROWSER") == "true" {
		lambdaComponentBrowser(t, ctx, apiDB, analyst, tenant, resource, policy, model.String(queued, "id"), positive)
	}
}

func lambdaPositiveMemoryResult(t *testing.T, result model.Document) {
	t.Helper()
	if result["status"] != "RECOMMENDED" || result["verified_saving"] != nil || result["pre_execution_ready"] != false || result["execution_authorized"] != false || len(lambdacost.Rows(result["source_refs"])) == 0 || len(lambdacost.Rows(result["financial_references"])) == 0 {
		t.Fatal("native positive result lost financial provenance or gained execution authority", result["status"], result["reason_codes"])
	}
	var lower model.Document
	for _, candidate := range lambdacost.Rows(result["candidates"]) {
		if candidate["family"] == "MEMORY" && model.Number(candidate, "memory_size_mb") == 1536 {
			lower = candidate
		}
	}
	if lower == nil || lower["status"] != "RECOMMENDED" || lower["decision"] != "REDUCE_MEMORY" || lower["physical_status"] != "PASS" || lower["execution_authorized"] != false || lower["verified_saving"] != nil {
		t.Fatal("same native population did not justify lower memory", lower)
	}
	economics := lambdacost.Document(lower["economics"])
	if economics["estimated_window_saving"] != "0.000980000000" || economics["current_window_cost"] != "0.005628000000" || economics["candidate_window_cost"] != "0.004648000000" || economics["estimated_monthly_saving"] == nil || economics["estimated_annual_saving"] != nil {
		t.Fatal("customer net economics differ from preserved successful-work curve", economics)
	}
	if len(model.Strings(result, "economically_analysed_source_record_ids")) != 28 {
		t.Fatal("canonical hourly billing components missing or double counted")
	}
}

func lambdaComponentBrowser(t *testing.T, ctx context.Context, apiDB, analyst *store.Store, tenant string, resource, policy model.Document, componentID string, positive bool) {
	t.Helper()
	binary := os.Getenv("FINOPS_LAMBDA_ASSESSOR_BINARY")
	if binary != "/tmp/lambda-finops" {
		t.Fatal("actual compiled Lambda analyst required")
	}
	info, e := os.Lstat(binary)
	if e != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode()&0111 == 0 {
		t.Fatal("Lambda executable unavailable")
	}
	log, e := os.OpenFile("/results/lambda-analyst.log", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		t.Fatal(e)
	}
	defer log.Close()
	cmd := exec.CommandContext(ctx, binary, "--mode", "lambda-assessor")
	cmd.Env = []string{"FIXTURE_MODE=true", "PORT=8098", "DATABASE_URL=" + analyst.Pool.Config().ConnConfig.ConnString(), "ECONOMICS_URL=" + os.Getenv("ECONOMICS_TEST_URL"), "ECONOMICS_TOKEN=" + os.Getenv("ECONOMICS_TEST_TOKEN")}
	for _, key := range []string{"OBJECT_REGION", "OBJECT_ENDPOINT", "OBJECT_BUCKET_RAW"} {
		cmd.Env = append(cmd.Env, key+"="+os.Getenv(key))
	}
	for _, pair := range [][2]string{{"OBJECT_ACCESS_KEY", "FINOPS_LAMBDA_READER_ACCESS_KEY"}, {"OBJECT_SECRET_KEY", "FINOPS_LAMBDA_READER_SECRET_KEY"}} {
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
				t.Error("separate Lambda analyst failed", e)
			}
		case <-time.After(5 * time.Second):
			_ = cmd.Process.Kill()
			<-done
			t.Error("separate Lambda analyst shutdown")
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
	ready := model.Document{"schema_version": "1", "tenant_id": tenant, "resource_ids": []string{model.String(resource, "id")}, "policy_ids": []string{model.String(policy, "id")}, "qualifiers": []string{"live"}}
	raw, _ := json.Marshal(ready)
	readyPath, donePath := "/results/lambda-native-component-ready.json", "/results/lambda-native-component-browser-done.json"
	if positive {
		readyPath, donePath = "/results/lambda-native-positive-ready.json", "/results/lambda-native-positive-browser-done.json"
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
			if proof.SchemaVersion != "1" || proof.TenantID != tenant || proof.ReadySHA256 != lambdacost.BytesHash(raw) || len(proof.AssessmentIDs) != 1 || proof.AssessmentIDs[0] == componentID {
				t.Fatal("browser result reused component or wrong source")
			}
			if e = apiDB.Do(ctx, tenant, func(tx *store.Tx) error {
				record, e := tx.LambdaAssessmentGet(ctx, proof.AssessmentIDs[0])
				if e != nil {
					return e
				}
				if record["resource_id"] != resource["id"] || !positive && lambdacost.Document(record["assessment"])["status"] != "BLOCKED" {
					return errors.New("independent browser stored result differs")
				}
				if positive {
					lambdaPositiveMemoryResult(t, lambdacost.Document(record["assessment"]))
				}
				var actor string
				if e = tx.QueryRow(ctx, "SELECT created_by FROM lambda_assessments WHERE tenant_id=$1 AND id=$2", tenant, record["id"]).Scan(&actor); e != nil {
					return e
				}
				if actor == "" || actor == "lambda-component-verifier" {
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
			t.Fatal("normal Lambda component browser deadline")
		case <-time.After(100 * time.Millisecond):
		}
	}
}
