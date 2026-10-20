package workflow

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/auth"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/lambdacost"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/native"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/provider"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/service"
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
	original := http.DefaultTransport
	denied := false
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
				return model.Document{"FunctionArn": a, "FunctionName": "component-processor", "Version": version, "MemorySize": 2048, "Architectures": []string{"x86_64"}, "Runtime": "python3.13", "PackageType": "Zip", "Handler": "main.handler", "CodeSha256": "synthetic-code", "RevisionId": "synthetic-config-" + version, "Timeout": 30, "State": "Active", "LastUpdateStatus": "Successful", "EphemeralStorage": model.Document{"Size": 512}, "Environment": model.Document{"Variables": model.Document{"SECRET": "SYNTHETIC_SECRET_MUST_NOT_PERSIST"}}, "LoggingConfig": model.Document{"LogGroup": reg.LogGroupName, "LogFormat": "Text"}}
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
			case strings.HasSuffix(r.URL.Path, "/aliases"):
				out = model.Document{"Aliases": []model.Document{{"AliasArn": arn + ":live", "Name": "live", "FunctionVersion": "1", "RevisionId": "synthetic-alias", "RoutingConfig": model.Document{}}}}
			case strings.HasSuffix(r.URL.Path, "/provisioned-concurrency"):
				out = model.Document{"ProvisionedConcurrencyConfigs": []model.Document{{"FunctionArn": arn + ":live", "RequestedProvisionedConcurrentExecutions": 2, "AllocatedProvisionedConcurrentExecutions": 2, "Status": "READY"}}}
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
		case host == "logs.eu-west-1.amazonaws.com":
			at := time.Now().UTC().Truncate(24 * time.Hour).Add(-time.Hour)
			out = model.Document{"events": []model.Document{{"eventId": "component-report", "timestamp": at.UnixMilli(), "logStreamName": "2026/10/20/[1]environment", "message": "REPORT RequestId: component-report Duration: 12.4 ms Billed Duration: 113 ms Memory Size: 2048 MB Max Memory Used: 700 MB Init Duration: 100 ms"}}}
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
	lambdaComponentAPI(t, ctx, admin, roles["api"], analyst, tenant, resource, snapshot)
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

func lambdaComponentAPI(t *testing.T, ctx context.Context, admin, apiDB, analyst *store.Store, tenant string, resource, snapshot model.Document) {
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
	code, policy := request("POST", "lambda-policies", access, "native-component-policy", model.Document{"resource_id": resource["id"], "name": "Synthetic Lambda component requirements", "policy": model.Document{"owner": "component-owner", "criticality": "NON_PRODUCTION", "timezone": "UTC", "configuration_authority": "TERRAFORM", "latency_sensitive": true, "latency_slo_ms": "200", "memory_headroom_fraction": "0.2", "max_error_rate": "0", "max_throttle_rate": "0", "available_concurrency": "20", "bursts_known": false}})
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
		if stored["status"] == "BLOCKED" {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("native persisted actual-Python deadline")
		case <-time.After(150 * time.Millisecond):
		}
	}
	result := lambdacost.Document(stored["assessment"])
	if result["status"] != "BLOCKED" || result["verified_saving"] != nil || model.Bool(result, "execution_authorized") || len(model.Strings(result, "reason_codes")) == 0 || len(lambdacost.Rows(result["source_refs"])) == 0 {
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
		lambdaComponentBrowser(t, ctx, apiDB, analyst, tenant, resource, policy, model.String(queued, "id"))
	}
}

func lambdaComponentBrowser(t *testing.T, ctx context.Context, apiDB, analyst *store.Store, tenant string, resource, policy model.Document, componentID string) {
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
	file, e := os.OpenFile("/results/lambda-native-component-ready.json", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = file.Write(raw); e != nil {
		t.Fatal(e)
	}
	_ = file.Close()
	for {
		body, e := os.ReadFile("/results/lambda-native-component-browser-done.json")
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
				if record["resource_id"] != resource["id"] || lambdacost.Document(record["assessment"])["status"] != "BLOCKED" {
					return errors.New("independent browser stored result differs")
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
