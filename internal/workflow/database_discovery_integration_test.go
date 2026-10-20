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
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/auth"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/native"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/provider"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/service"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/telemetry"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/workload"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/jackc/pgx/v5"
)

type databaseFixtureTransport func(*http.Request) (*http.Response, error)

func (f databaseFixtureTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

const databaseFixtureARN = "arn:aws:rds:eu-west-1:111122223333:db:component-primary"

func databaseFixturePage(action, collection, body string) string {
	return "<" + action + "Response><" + action + "Result><" + collection + ">" + body + "</" + collection + "></" + action + "Result></" + action + "Response>"
}
func databaseFixtureInstance() string {
	return `<DBInstance><DBInstanceIdentifier>component-primary</DBInstanceIdentifier><DBInstanceArn>` + databaseFixtureARN + `</DBInstanceArn><DbiResourceId>db-COMPONENTINCARNATION</DbiResourceId><DBInstanceClass>db.r6g.large</DBInstanceClass><Engine>postgres</Engine><EngineVersion>16.4</EngineVersion><LicenseModel>postgresql-license</LicenseModel><DBInstanceStatus>available</DBInstanceStatus><StorageType>gp3</StorageType><AllocatedStorage>100</AllocatedStorage><MultiAZ>false</MultiAZ><DBParameterGroups><DBParameterGroup><DBParameterGroupName>component-parameters</DBParameterGroupName><ParameterApplyStatus>in-sync</ParameterApplyStatus></DBParameterGroup></DBParameterGroups></DBInstance>`
}

// The account, STS and native AWS responses below are COMPONENT transports, not
// AWS-origin authority. Actual SigV4/provider parsers, the separately logged-in
// ingester, forced-RLS SQL, versioned object write/readback and full ClickHouse
// payload population are exercised. Storage is the existing owned test lab.
func TestDatabaseNativeCollectorRestrictedPersistenceAndStorage(t *testing.T) {
	if os.Getenv("RDS_TEST_STORAGE_ENABLED") != "true" {
		t.Skip("existing owned PostgreSQL/versioned object/ClickHouse lab required")
	}
	admin, roles := schedulerTestDatabase(t)
	ctx, cancel := context.WithTimeout(context.Background(), 85*time.Second)
	defer cancel()
	tenant := "rds-" + model.ID()
	login := "rds_ingester_" + strings.ReplaceAll(model.ID(), "-", "")
	password := model.ID() + model.ID()
	marker := "owned-rds-collector:" + login
	if _, e := admin.Pool.Exec(ctx, "CREATE ROLE "+pgx.Identifier{login}.Sanitize()+" LOGIN PASSWORD '"+password+"' IN ROLE finops_ingester"); e != nil {
		t.Fatal(e)
	}
	if _, e := admin.Pool.Exec(ctx, "COMMENT ON ROLE "+pgx.Identifier{login}.Sanitize()+" IS '"+marker+"'"); e != nil {
		t.Fatal(e)
	}
	var ingester *store.Store
	t.Cleanup(func() {
		if ingester != nil {
			ingester.Pool.Close()
		}
		var actual string
		if e := admin.Pool.QueryRow(context.Background(), "SELECT coalesce(shobj_description(oid,'pg_authid'),'') FROM pg_roles WHERE rolname=$1", login).Scan(&actual); e != nil || actual != marker {
			t.Error("owned collector login marker changed")
			return
		}
		if _, e := admin.Pool.Exec(context.Background(), "DROP ROLE "+pgx.Identifier{login}.Sanitize()); e != nil {
			t.Error(e)
		}
	})
	dsn, e := url.Parse(admin.Pool.Config().ConnConfig.ConnString())
	if e != nil {
		t.Fatal(e)
	}
	dsn.User = url.UserPassword(login, password)
	ingester, e = store.OpenRuntime(ctx, dsn.String(), "ingester")
	if e != nil {
		t.Fatal(e)
	}
	var current, session string
	if e = ingester.Pool.QueryRow(ctx, "SELECT current_user,session_user").Scan(&current, &session); e != nil || current != "finops_ingester" || session != login {
		t.Fatal("collector did not use separate actual LOGIN/group", e)
	}
	resourceID, workloadID := "component-rds-resource", "component-rds-workload"
	if e = roles["api"].Do(ctx, tenant, func(tx *store.Tx) error {
		if e := tx.Seed(ctx, true); e != nil {
			return e
		}
		if _, e := tx.Create(ctx, "workloads", model.Document{"id": workloadID, "name": "Component declared database workload", "owner": "declared-fixture-owner"}); e != nil {
			return e
		}
		p := workload.Profile{SchemaVersion: "1", Criticality: "NON_PRODUCTION", Statefulness: "STATELESS", Timezone: "UTC", MinReplicas: 1, MinZones: 1, Headroom: workload.Headroom{CPUFreePPM: 300000, MemoryFreePPM: 300000, ReserveAboveForecastPPM: 300000}, Saturation: workload.Saturation{CPUP99PPM: 850000, MemoryP99PPM: 900000}, RTOSeconds: 900, MaxSimultaneousChangePPM: 100000, VMCooldownSeconds: 604800}
		if _, e := tx.WorkloadSafetyAppend(ctx, workloadID, 0, p); e != nil {
			return e
		}
		_, e := tx.Create(ctx, "resources", model.Document{"id": resourceID, "provider": "AWS", "account_id": "111122223333", "region": "eu-west-1", "provider_resource_id": databaseFixtureARN, "resource_type": "RDS_INSTANCE", "workload_id": workloadID, "owner": "declared-fixture-owner", "environment": "NON_PRODUCTION", "configuration_authority": "GITOPS", "database_configuration": model.Document{"class": "unknown-before-capture"}})
		return e
	}); e != nil {
		t.Fatal(e)
	}
	// A local STS endpoint supplies explicitly synthetic credentials only. The
	// production reader still pins every subsequent concrete identity/account.
	sts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("Action") != "AssumeRole" {
			t.Error("unexpected SDK operation")
			w.WriteHeader(400)
			return
		}
		fmt.Fprintf(w, `<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><AssumeRoleResult><Credentials><AccessKeyId>component-read</AccessKeyId><SecretAccessKey>component-secret</SecretAccessKey><SessionToken>component-session</SessionToken><Expiration>%s</Expiration></Credentials><AssumedRoleUser><Arn>arn:aws:sts::111122223333:assumed-role/component-read/session</Arn><AssumedRoleId>COMPONENT:session</AssumedRoleId></AssumedRoleUser></AssumeRoleResult></AssumeRoleResponse>`, time.Now().UTC().Add(time.Hour).Format(time.RFC3339))
	}))
	defer sts.Close()
	for k, v := range map[string]string{"AWS_TENANT_ID": tenant, "AWS_ACCESS_KEY_ID": "component-source", "AWS_SECRET_ACCESS_KEY": "component-source-secret", "AWS_SESSION_TOKEN": "", "AWS_ROLE_ARN": "", "AWS_WEB_IDENTITY_TOKEN_FILE": "", "AWS_PROFILE": "", "AWS_ENDPOINT_URL_STS": sts.URL, "AWS_EC2_METADATA_DISABLED": "true", "RDS_DATABASE_SAVINGS_PLAN_INVENTORY_ENABLED": "false", "RDS_COMPUTE_OPTIMIZER_ENABLED": "false"} {
		t.Setenv(k, v)
	}
	storage, e := native.StorageFromEnvironment(ctx, true)
	if e != nil {
		t.Fatal(e)
	}
	// Only exact provider endpoints are replaced. All other traffic must remain
	// inside the explicit pre-existing object/analytics/STS test endpoints.
	allowed := map[string]bool{}
	for _, endpoint := range []string{os.Getenv("OBJECT_ENDPOINT"), os.Getenv("CLICKHOUSE_URL"), sts.URL} {
		u, e := url.Parse(endpoint)
		if e != nil || u.Host == "" {
			t.Fatal("owned storage endpoint missing")
		}
		allowed[u.Host] = true
	}
	original := http.DefaultTransport
	var denied atomic.Bool
	http.DefaultTransport = databaseFixtureTransport(func(r *http.Request) (*http.Response, error) {
		host := r.URL.Host
		body := ""
		if host == "sts.eu-west-1.amazonaws.com" {
			body = `<GetCallerIdentityResponse><GetCallerIdentityResult><Account>111122223333</Account><Arn>arn:aws:sts::111122223333:assumed-role/component-read/session</Arn><UserId>COMPONENT:session</UserId></GetCallerIdentityResult></GetCallerIdentityResponse>`
		} else if host == "rds.eu-west-1.amazonaws.com" || host == "monitoring.eu-west-1.amazonaws.com" || host == "api.pricing.us-east-1.amazonaws.com" {
			if !strings.Contains(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256") {
				return nil, errors.New("component native read was unsigned")
			}
			raw, e := io.ReadAll(r.Body)
			if e != nil {
				return nil, e
			}
			v, _ := url.ParseQuery(string(raw))
			action := v.Get("Action")
			if denied.Load() && host == "rds.eu-west-1.amazonaws.com" {
				return &http.Response{StatusCode: 403, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(`<ErrorResponse><Error><Code>AccessDenied</Code></Error></ErrorResponse>`))}, nil
			}
			switch action {
			case "DescribeDBInstances":
				body = databaseFixturePage(action, "DBInstances", databaseFixtureInstance())
			case "DescribeDBClusters":
				body = databaseFixturePage(action, "DBClusters", "")
			case "DescribeReservedDBInstances":
				body = databaseFixturePage(action, "ReservedDBInstances", "")
			case "DescribeOrderableDBInstanceOptions":
				body = databaseFixturePage(action, "OrderableDBInstanceOptions", `<OrderableDBInstanceOption><Engine>postgres</Engine><EngineVersion>16.4</EngineVersion><LicenseModel>postgresql-license</LicenseModel><DBInstanceClass>db.r6g.large</DBInstanceClass><StorageType>gp3</StorageType><Vpc>true</Vpc><MultiAZCapable>true</MultiAZCapable></OrderableDBInstanceOption>`)
			case "DescribeDBParameters":
				body = databaseFixturePage(action, "Parameters", `<Parameter><ParameterName>max_connections</ParameterName><ParameterValue>400</ParameterValue><Source>user</Source><ApplyType>dynamic</ApplyType></Parameter>`)
			case "DescribeValidDBInstanceModifications":
				if v.Get("DBInstanceIdentifier") != databaseFixtureARN {
					return nil, errors.New("modification read lost native ARN")
				}
				body = databaseFixturePage(action, "ValidDBInstanceModificationsMessage", `<Storage><ValidStorageOptions><StorageType>gp3</StorageType><StorageSize><Range><From>100</From><To>16384</To><Step>1</Step></Range></StorageSize><ProvisionedIops><Range><From>1000</From><To>64000</To><Step>1000</Step></Range></ProvisionedIops><ProvisionedStorageThroughput><Range><From>125</From><To>1000</To><Step>125</Step></Range></ProvisionedStorageThroughput><IopsToStorageRatio><DoubleRange><From>0.5</From><To>500</To></DoubleRange></IopsToStorageRatio><StorageThroughputToIopsRatio><DoubleRange><From>0</From><To>0.25</To></DoubleRange></StorageThroughputToIopsRatio><SupportsStorageAutoscaling>true</SupportsStorageAutoscaling></ValidStorageOptions></Storage><ValidProcessorFeatures/>`)
			case "GetMetricStatistics":
				start, e := time.Parse(time.RFC3339, v.Get("StartTime"))
				if e != nil {
					return nil, e
				}
				end, e := time.Parse(time.RFC3339, v.Get("EndTime"))
				if e != nil {
					return nil, e
				}
				stat := v.Get("Statistics.member.1")
				var points strings.Builder
				for at := start; at.Before(end); at = at.Add(time.Hour) {
					fmt.Fprintf(&points, "<member><Timestamp>%s</Timestamp><%s>0</%s><SampleCount>60</SampleCount><Unit>%s</Unit></member>", at.Format(time.RFC3339), stat, stat, v.Get("Unit"))
				}
				body = databaseFixturePage(action, "Datapoints", points.String())
			default:
				if r.Header.Get("X-Amz-Target") != "AWSPriceListService.GetProducts" {
					return nil, errors.New("unexpected component provider operation")
				}
				product, _ := json.Marshal(model.Document{"product": model.Document{"sku": "component-capacity-only", "productFamily": "Database Instance", "attributes": map[string]string{"servicecode": "AmazonRDS", "instanceType": "db.r6g.large", "regionCode": "eu-west-1", "vcpu": "2", "memory": "16 GiB", "physicalProcessor": "AWS Graviton2", "processorArchitecture": "64-bit", "networkPerformance": "10 Gigabit"}}})
				response, _ := json.Marshal(model.Document{"PriceList": []string{string(product)}})
				body = string(response)
			}
		} else if allowed[host] {
			return original.RoundTrip(r)
		} else {
			return nil, errors.New("component collector refused unregistered network endpoint")
		}
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body))}, nil
	})
	defer func() { http.DefaultTransport = original }()
	aws, e := provider.NewAWS(ctx, "eu-west-1", "arn:aws:iam::111122223333:role/component-read", "component-external")
	if e != nil {
		t.Fatal(e)
	}
	a := &Activities{Config: service.Config{Fixture: true}}
	if e = ingester.Do(ctx, tenant, func(tx *store.Tx) error {
		return discoverRDSAccount(ctx, a, tx, aws, model.Document{"id": "component-cloud", "account_id": "111122223333", "region": "eu-west-1"})
	}); e != nil {
		t.Fatal(e)
	}
	var snapshot, resource model.Document
	if e = ingester.Do(ctx, tenant, func(tx *store.Tx) error {
		var e error
		resource, e = tx.Get(ctx, "resources", resourceID)
		if e != nil {
			return e
		}
		snapshot, e = tx.DatabaseEvidenceLatest(ctx, resourceID)
		return e
	}); e != nil {
		t.Fatal("collector failed to publish after real storage", e)
	}
	if resource["owner"] != "declared-fixture-owner" || resource["workload_id"] != workloadID || resource["configuration_authority"] != "GITOPS" {
		t.Fatal("native refresh replaced customer metadata")
	}
	ref, e := databaseDocument(snapshot["archive"])
	if e != nil {
		t.Fatal(e)
	}
	raw, e := storage.Read(ctx, tenant, ref)
	if e != nil {
		t.Fatal(e)
	}
	var canonical model.Document
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if decoder.Decode(&canonical) != nil {
		t.Fatal("stored canonical object invalid")
	}
	metrics := canonical["metrics"].([]any)
	if len(metrics) != 1 {
		t.Fatal("unexpected native resource population")
	}
	metricRaw, _ := json.Marshal(metrics[0])
	var metricEvidence provider.RDSMetricEvidence
	if json.Unmarshal(metricRaw, &metricEvidence) != nil {
		t.Fatal("stored metric wire invalid")
	}
	if metricEvidence.Selection.End.Sub(metricEvidence.Selection.Start) != 14*24*time.Hour || metricEvidence.Selection.End.Hour() != 0 || len(metricEvidence.Metrics) != 14*24*14 {
		t.Fatal("complete selected history was reduced")
	}
	observed, e := time.Parse(time.RFC3339Nano, model.String(snapshot, "observed_at"))
	if e != nil || !observed.Equal(metricEvidence.CollectedAt) || time.Since(observed) > time.Minute {
		t.Fatal("snapshot collection time was fabricated/renewed")
	}
	expected := map[string]telemetry.Sample{}
	batches, e := databaseMetricBatches(resource, metricEvidence)
	if e != nil {
		t.Fatal(e)
	}
	for _, batch := range batches {
		for _, s := range batch.Samples {
			expected[s.ID] = s
		}
	}
	endpoint, e := url.Parse(storage.AnalyticsURL)
	if e != nil {
		t.Fatal(e)
	}
	q := endpoint.Query()
	q.Set("database", storage.Database)
	q.Set("query", "SELECT sample_id,payload FROM native_metric_samples WHERE tenant_id={tenant:String} AND resource_id={resource:String} ORDER BY sample_id FORMAT JSONEachRow")
	q.Set("param_tenant", tenant)
	q.Set("param_resource", resourceID)
	endpoint.RawQuery = q.Encode()
	request, _ := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), nil)
	request.Header.Set("X-ClickHouse-User", storage.AnalyticsUser)
	request.Header.Set("X-ClickHouse-Key", storage.AnalyticsSecret)
	response, e := storage.Client.Do(request)
	if e != nil {
		t.Fatal(e)
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatal("actual scoped facts readback failed", response.StatusCode)
	}
	rows := json.NewDecoder(io.LimitReader(response.Body, 32<<20))
	seen := map[string]bool{}
	for {
		var row model.Document
		e := rows.Decode(&row)
		if e == io.EOF {
			break
		}
		if e != nil {
			t.Fatal(e)
		}
		id := model.String(row, "sample_id")
		var sample telemetry.Sample
		if json.Unmarshal([]byte(model.String(row, "payload")), &sample) != nil || seen[id] {
			t.Fatal("actual fact invalid/duplicated")
		}
		want, ok := expected[id]
		if !ok || telemetry.Hash(sample) != telemetry.Hash(want) || model.Number(sample.OriginalAttributes, "sample_count") != 60 {
			t.Fatal("full native fact payload/count differs")
		}
		seen[id] = true
	}
	if len(seen) != len(expected) || len(expected) != 14*24*14 {
		t.Fatal("actual ClickHouse population incomplete", len(seen), len(expected))
	}
	catalogs, e := databaseDocument(canonical["catalogs"])
	if e != nil {
		t.Fatal(e)
	}
	catalog, e := databaseDocument(catalogs[databaseFixtureARN])
	if e != nil {
		t.Fatal(e)
	}
	assetRef, e := databaseDocument(catalog["ebs_baseline_asset_ref"])
	asset := provider.RDSDocumentedIOBaselineAsset()
	if e != nil || model.String(assetRef, "bucket") == "" || model.String(assetRef, "key") == "" || model.String(assetRef, "version_id") == "" || model.String(assetRef, "body_sha256") != telemetry.BytesHash(asset) {
		t.Fatal("catalog documented baseline asset reference invalid")
	}
	assetCount := 0
	for _, v := range snapshot["source_refs"].([]any) {
		sourceRef, _ := databaseDocument(v)
		raw, e := storage.Read(ctx, tenant, sourceRef)
		if e != nil {
			t.Fatal(e)
		}
		if telemetry.Hash(sourceRef) == telemetry.Hash(assetRef) {
			if !bytes.Equal(raw, asset) || telemetry.BytesHash(raw) != model.String(assetRef, "body_sha256") {
				t.Fatal("archived documented baseline asset bytes differ")
			}
			assetCount++
			continue
		}
		if _, e = provider.RDSCaptureFrames(raw); e != nil {
			t.Fatal(e)
		}
	}
	if assetCount != 1 {
		t.Fatal("documented baseline asset reference missing or duplicated", assetCount)
	}
	if e = roles["api"].Do(ctx, tenant, func(tx *store.Tx) error {
		d := model.Clone(snapshot)
		d["id"] = model.ID()
		_, e := tx.DatabaseEvidenceAppend(ctx, d)
		return e
	}); e == nil {
		t.Fatal("API acquired native evidence issuance")
	}
	if e = ingester.Do(ctx, tenant, func(tx *store.Tx) error {
		_, e := tx.Exec(ctx, "UPDATE database_evidence_snapshots SET document='{}' WHERE tenant_id=$1 AND id=$2", tenant, snapshot["id"])
		return e
	}); e == nil {
		t.Fatal("issued snapshot mutable")
	}
	if e = ingester.Do(ctx, "foreign-"+tenant, func(tx *store.Tx) error { _, e := tx.DatabaseEvidenceGet(ctx, model.String(snapshot, "id")); return e }); !errors.Is(e, pgx.ErrNoRows) {
		t.Fatal("cross-tenant snapshot disclosed", e)
	}
	databaseCollectorBlockedAPI(t, ctx, admin, roles["api"], tenant, resourceID, model.String(snapshot, "id"), func(endpoint string) {
		u, e := url.Parse(endpoint)
		if e != nil || u.Host == "" {
			t.Fatal("component HTTP endpoint invalid")
		}
		allowed[u.Host] = true
	})
	denied.Store(true)
	if e = ingester.Do(ctx, tenant, func(tx *store.Tx) error {
		return discoverRDSAccount(ctx, a, tx, aws, model.Document{"id": "component-cloud", "account_id": "111122223333", "region": "eu-west-1"})
	}); e != nil {
		t.Fatal(e)
	}
	if e = ingester.Do(ctx, tenant, func(tx *store.Tx) error {
		q, e := tx.Get(ctx, "data_quality", "quality-rds-111122223333-eu-west-1")
		if e != nil {
			return e
		}
		if model.String(q, "status") != "DEGRADED" {
			return errors.New("provider refusal became successful empty inventory")
		}
		latest, e := tx.DatabaseEvidenceLatest(ctx, resourceID)
		if e == nil && latest["id"] != snapshot["id"] {
			return errors.New("provider refusal renewed advice")
		}
		return e
	}); e != nil {
		t.Fatal(e)
	}
}

// Reuses the captured native snapshot through the normal authenticated API and
// executable assessor entrypoint. Missing customer billing/SLO evidence must
// become a durable BLOCKED result; this fixture supplies no model response or
// invented customer rate. A restart processes a second legitimate request and
// cannot duplicate or rewrite the first analytical publication.
func databaseCollectorBlockedAPI(t *testing.T, ctx context.Context, admin, apiDB *store.Store, tenant, resourceID, snapshotID string, allowEndpoint func(string)) {
	t.Helper()
	login := "rds_analyst_" + strings.ReplaceAll(model.ID(), "-", "")
	password := model.ID() + model.ID()
	marker := "owned-rds-analyst:" + login
	if _, e := admin.Pool.Exec(ctx, "CREATE ROLE "+pgx.Identifier{login}.Sanitize()+" LOGIN PASSWORD '"+password+"' IN ROLE finops_database_analyst"); e != nil {
		t.Fatal(e)
	}
	if _, e := admin.Pool.Exec(ctx, "COMMENT ON ROLE "+pgx.Identifier{login}.Sanitize()+" IS '"+marker+"'"); e != nil {
		t.Fatal(e)
	}
	var analyst *store.Store
	t.Cleanup(func() {
		if analyst != nil {
			analyst.Pool.Close()
		}
		var actual string
		if e := admin.Pool.QueryRow(context.Background(), "SELECT coalesce(shobj_description(oid,'pg_authid'),'') FROM pg_roles WHERE rolname=$1", login).Scan(&actual); e != nil || actual != marker {
			t.Error("owned analyst login marker changed")
			return
		}
		if _, e := admin.Pool.Exec(context.Background(), "DROP ROLE "+pgx.Identifier{login}.Sanitize()); e != nil {
			t.Error(e)
		}
	})
	dsn, e := url.Parse(admin.Pool.Config().ConnConfig.ConnString())
	if e != nil {
		t.Fatal(e)
	}
	dsn.User = url.UserPassword(login, password)
	analyst, e = store.OpenRuntime(ctx, dsn.String(), "database-assessor")
	if e != nil {
		t.Fatal(e)
	}
	var current, session string
	if e = analyst.Pool.QueryRow(ctx, "SELECT current_user,session_user").Scan(&current, &session); e != nil || current != "finops_database_analyst" || session != login {
		t.Fatal("assessor did not use separately commissioned LOGIN/group", e)
	}
	key, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	signer, e := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithHeader("kid", "rds-component"))
	if e != nil {
		t.Fatal(e)
	}
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "rds-component", Algorithm: "RS256", Use: "sig"}}})
	}))
	defer jwks.Close()
	allowEndpoint(jwks.URL)
	const issuer = "https://component-rds.invalid/realms/finops"
	validator, e := auth.New(ctx, issuer, "finops", jwks.URL)
	if e != nil {
		t.Fatal(e)
	}
	token := func(tenant, role string) string {
		t.Helper()
		s, e := jwt.Signed(signer).Claims(map[string]any{"iss": issuer, "aud": "finops", "sub": "rds-component-" + role, "exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Add(-time.Minute).Unix(), "tenant_id": tenant, "realm_access": map[string]any{"roles": []string{role}}}).Serialize()
		if e != nil {
			t.Fatal(e)
		}
		return s
	}
	server := httptest.NewServer((&service.API{Store: apiDB, Auth: validator, Config: service.Config{Fixture: true}}).Handler())
	defer server.Close()
	allowEndpoint(server.URL)
	var modelCalls atomic.Int64
	// Any accidental request is a failure, never a fake successful model result.
	unavailableModel := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		modelCalls.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer unavailableModel.Close()
	allowEndpoint(unavailableModel.URL)
	access := token(tenant, "FINOPS_ADMIN")
	foreign := token("foreign-"+tenant, "FINOPS_ADMIN")
	viewer := token(tenant, "VIEWER")
	request := func(method, path, access, idempotency string, body model.Document) (int, model.Document) {
		t.Helper()
		var raw []byte
		if body != nil {
			var e error
			raw, e = json.Marshal(body)
			if e != nil {
				t.Fatal(e)
			}
		}
		r, e := http.NewRequestWithContext(ctx, method, server.URL+"/v1/"+path, bytes.NewReader(raw))
		if e != nil {
			t.Fatal(e)
		}
		if access != "" {
			r.Header.Set("Authorization", "Bearer "+access)
		}
		if method == http.MethodPost {
			r.Header.Set("If-Match", `"0"`)
			r.Header.Set("Idempotency-Key", idempotency)
			r.Header.Set("Content-Type", "application/json")
		}
		response, e := server.Client().Do(r)
		if e != nil {
			t.Fatal(e)
		}
		defer response.Body.Close()
		var d model.Document
		if json.NewDecoder(io.LimitReader(response.Body, 4<<20)).Decode(&d) != nil {
			t.Fatal("public API did not return bounded JSON")
		}
		return response.StatusCode, d
	}
	if code, _ := request(http.MethodGet, "database-assessments", "", "", nil); code != http.StatusUnauthorized {
		t.Fatal("unauthenticated assessment history admitted", code)
	}
	if code, _ := request(http.MethodPost, "database-assessments", viewer, "rds-viewer-must-not-queue", model.Document{"resource_id": resourceID}); code != http.StatusForbidden {
		t.Fatal("read-only actor queued assessment", code)
	}
	if code, _ := request(http.MethodPost, "database-assessments", access, "rds-authoritative-input-denied", model.Document{"resource_id": resourceID, "current_hourly_cost": "0"}); code != http.StatusUnprocessableEntity {
		t.Fatal("public authoritative price admitted", code)
	}
	queueKey := "rds-native-api-queue-" + model.ID()
	code, queued := request(http.MethodPost, "database-assessments", access, queueKey, model.Document{"resource_id": resourceID})
	if code != http.StatusAccepted || model.String(queued, "status") != "QUEUED" || model.String(queued, "id") == "" {
		t.Fatal("normal API failed to commit queue", code, model.String(queued, "status"))
	}
	id := model.String(queued, "id")
	code, replay := request(http.MethodPost, "database-assessments", access, queueKey, model.Document{"resource_id": resourceID})
	if code != http.StatusAccepted || replay["id"] != queued["id"] {
		t.Fatal("queue replay changed issued request")
	}
	var selectedSnapshot string
	if e = apiDB.Do(ctx, tenant, func(tx *store.Tx) error {
		return tx.QueryRow(ctx, "SELECT snapshot_id FROM database_assessments WHERE tenant_id=$1 AND id=$2", tenant, id).Scan(&selectedSnapshot)
	}); e != nil || selectedSnapshot != snapshotID {
		t.Fatal("queue selected other native snapshot", e)
	}
	run := func() func() {
		t.Helper()
		workerCtx, cancel := context.WithCancel(ctx)
		done := make(chan error, 1)
		go func() {
			done <- service.RunDatabaseAssessor(workerCtx, service.Config{Fixture: true, EconomicsURL: unavailableModel.URL, EconomicsToken: "component-unused-no-model-authority"}, analyst)
		}()
		stopped := false
		stop := func() {
			if stopped {
				return
			}
			stopped = true
			cancel()
			select {
			case e := <-done:
				if e != nil {
					t.Error("database assessor entrypoint failed", e)
				}
			case <-time.After(5 * time.Second):
				t.Error("database assessor failed to release owned work")
			}
		}
		t.Cleanup(stop)
		return stop
	}
	waitBlocked := func(id string) model.Document {
		t.Helper()
		deadline := time.Now().Add(15 * time.Second)
		for time.Now().Before(deadline) {
			code, d := request(http.MethodGet, "database-assessments/"+id, access, "", nil)
			if code != http.StatusOK {
				t.Fatal("assessment read failed", code)
			}
			if model.String(d, "status") == "BLOCKED" {
				return d
			}
			if model.String(d, "status") != "QUEUED" && model.String(d, "status") != "RUNNING" {
				t.Fatal("unexpected assessment state", model.String(d, "status"))
			}
			select {
			case <-ctx.Done():
				t.Fatal("connected assessment context expired")
			case <-time.After(100 * time.Millisecond):
			}
		}
		t.Fatal("assessor did not persist missing-evidence blocker")
		return nil
	}
	stop := run()
	defer stop()
	blocked := waitBlocked(id)
	stop()
	assessment, _ := databaseDocument(blocked["assessment"])
	proposal, _ := databaseDocument(assessment["proposal"])
	if model.String(assessment, "status") != "BLOCKED" || len(model.Strings(assessment, "blockers")) == 0 || proposal["executable"] != false || proposal["execution_authorized"] != false || assessment["verified_saving"] != nil {
		t.Fatal("missing evidence acquired success, savings or execution")
	}
	code, publication := request(http.MethodGet, "recommendations/database-"+id, access, "", nil)
	if code != http.StatusOK || model.String(publication, "status") != "BLOCKED" || publication["pre_execution_ready"] != false || publication["execution_authorized"] != false || publication["verified_saving"] != nil {
		t.Fatal("public publication lost read-only blockers", code)
	}
	if code, _ := request(http.MethodGet, "database-assessments/"+id, foreign, "", nil); code != http.StatusNotFound {
		t.Fatal("other tenant read assessment", code)
	}
	if code, _ := request(http.MethodGet, "recommendations/database-"+id, foreign, "", nil); code != http.StatusNotFound {
		t.Fatal("other tenant read publication", code)
	}
	if e = analyst.Do(ctx, tenant, func(tx *store.Tx) error {
		var permitted bool
		if e := tx.QueryRow(ctx, "SELECT has_table_privilege(current_user,'public.signed_plans','INSERT') OR has_table_privilege(current_user,'public.provider_operations','INSERT') OR has_table_privilege(current_user,'public.savings_ledger','INSERT')").Scan(&permitted); e != nil {
			return e
		}
		if permitted {
			return errors.New("database assessor acquired execution or verified savings write")
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	// A genuine new request exercises the same process after stopping/restarting;
	// the first request/publication remains byte-identical and appears in history.
	code, next := request(http.MethodPost, "database-assessments", access, "rds-native-api-after-restart", model.Document{"resource_id": resourceID})
	if code != http.StatusAccepted || next["id"] == id {
		t.Fatal("new request was not independently issued")
	}
	stopAgain := run()
	defer stopAgain()
	waitBlocked(model.String(next, "id"))
	stopAgain()
	code, retained := request(http.MethodGet, "database-assessments/"+id, access, "", nil)
	retainedAssessment, _ := databaseDocument(retained["assessment"])
	if code != http.StatusOK || telemetry.Hash(retainedAssessment) != telemetry.Hash(assessment) {
		t.Fatal("restart rewrote completed analytical result")
	}
	code, page := request(http.MethodGet, "database-assessments?resource_id="+url.QueryEscape(resourceID)+"&limit=100", access, "", nil)
	if code != http.StatusOK {
		t.Fatal("public durable history failed", code)
	}
	items, ok := page["items"].([]any)
	if !ok || len(items) != 2 {
		t.Fatal("history lost/repeated issued requests")
	}
	var count int
	if e = admin.Pool.QueryRow(ctx, "SELECT count(*) FROM database_recommendation_publications WHERE tenant_id=$1 AND resource_id=$2", tenant, resourceID).Scan(&count); e != nil || count != 2 {
		t.Fatal("restart duplicated/lost immutable publications", e)
	}
	if modelCalls.Load() != 0 {
		t.Fatal("blocked native assessment attempted numerical model without evidence")
	}
}
