package service

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/fleetassessmentworker"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/fleetbilling"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/fleetcapacity"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/fleetcapacityworker"
	g "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetgroup"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/native"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/source"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/telemetry"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type fleetCapacityCancelPopulation struct {
	reader fleetcapacityworker.PopulationReader
	cancel context.CancelFunc
	at     int32
	calls  atomic.Int32
}

// Failed analytics diagnostics remain private. The public lab receipt carries
// no query, metric payload, endpoint credential or arbitrary error text.
type fleetCapacityAnalyticsAudit struct{}

func (fleetCapacityAnalyticsAudit) RoundTrip(request *http.Request) (*http.Response, error) {
	response, e := http.DefaultTransport.RoundTrip(request)
	if e != nil || response.StatusCode == 200 || request.URL.Host != "clickhouse:8123" || !strings.HasPrefix(request.URL.Query().Get("query"), "INSERT INTO native_metric_") {
		return response, e
	}
	body, readError := io.ReadAll(io.LimitReader(response.Body, 16384))
	_ = response.Body.Close()
	response.Body = io.NopCloser(bytes.NewReader(body))
	response.ContentLength = int64(len(body))
	if readError == nil {
		diagnostic, _ := json.Marshal(model.Document{"schema_version": "1", "status": response.StatusCode, "private_analytics_response": string(body)})
		_ = os.WriteFile("/results/analytics-failure.private.json", diagnostic, 0600)
		code := regexp.MustCompile(`Code: [0-9]+`).Find(body)
		category := regexp.MustCompile(`\([A-Z][A-Z_]+\)`).FindAll(body, -1)
		label := "UNCLASSIFIED"
		if len(category) > 0 {
			label = string(category[len(category)-1])
		}
		fmt.Fprintln(os.Stderr, "private analytics failure", response.StatusCode, string(code), label)
	}
	return response, nil
}

func (r *fleetCapacityCancelPopulation) Read(ctx context.Context, in native.CapacityInputRequest) (native.CapacityPopulation, error) {
	if r.calls.Add(1) == r.at {
		r.cancel()
		return native.CapacityPopulation{}, context.Canceled
	}
	return r.reader.Read(ctx, in)
}

func fleetCapacityNativeLogin(t *testing.T, admin *store.Store, group, purpose string) *store.Store {
	t.Helper()
	ctx := context.Background()
	login, password := "capacity_native_"+strings.ReplaceAll(model.ID(), "-", ""), model.ID()
	if _, e := admin.Pool.Exec(ctx, "CREATE ROLE "+pgx.Identifier{login}.Sanitize()+" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '"+password+"' IN ROLE "+pgx.Identifier{group}.Sanitize()); e != nil {
		t.Fatal(e)
	}
	var db *store.Store
	t.Cleanup(func() {
		if db != nil {
			db.Pool.Close()
		}
		if _, e := admin.Pool.Exec(context.Background(), "DROP ROLE "+pgx.Identifier{login}.Sanitize()); e != nil {
			t.Error(e)
		}
	})
	c := admin.Pool.Config().ConnConfig
	dsn := url.URL{Scheme: "postgres", Host: net.JoinHostPort(c.Host, strconv.Itoa(int(c.Port))), Path: "/" + c.Database, User: url.UserPassword(login, password), RawQuery: "sslmode=disable"}
	var e error
	db, e = store.OpenRuntime(ctx, dsn.String(), purpose)
	if e != nil {
		t.Fatal(e)
	}
	return db
}

func TestFleetCapacityActualPrometheusAnalyticsPythonAPIAndWorker(t *testing.T) {
	if os.Getenv("FLEET_NATIVE_CAPACITY_LAB") != "ISOLATED_REAL_SERVICES_SYNTHETIC_HISTORY" {
		t.Skip("owned PG/MinIO/Prometheus/ClickHouse/Python lab required")
	}
	if os.Getenv("TEST_FLEET_HISTORY_S3_ENDPOINT") != "http://minio:9000" || os.Getenv("FLEET_CAPACITY_CLICKHOUSE_URL") != "http://clickhouse:8123" || os.Getenv("ECONOMICS_TEST_URL") != "http://economics:8000" {
		t.Fatal("fixed private service endpoints required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	seed := fleetCapacityReadPromSeed(t)
	fleetCapacityStartExporter(t)
	f, admin, evaluator, proposals := newFleetCapacityHTTPTest(t)
	transport := fleetCapacityNativeLogin(t, admin, "finops_telemetry_reader", "telemetry-reader")
	client := func(access, secret string) *s3.Client {
		return s3.NewFromConfig(aws.Config{Region: "eu-west-1", Credentials: credentials.NewStaticCredentialsProvider(access, secret, "")}, func(o *s3.Options) { o.BaseEndpoint = aws.String("http://minio:9000"); o.UsePathStyle = true })
	}
	archive := client(os.Getenv("TEST_FLEET_HISTORY_S3_ACCESS_KEY"), os.Getenv("TEST_FLEET_HISTORY_S3_SECRET_KEY"))
	readerClient := client(os.Getenv("TEST_FLEET_ASSESSMENT_READ_ACCESS_KEY"), os.Getenv("TEST_FLEET_ASSESSMENT_READ_SECRET_KEY"))
	bucket, owner := "native-capacity-"+strings.ReplaceAll(model.ID(), "-", ""), "owned-native-capacity:"+model.ID()
	if _, e := archive.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(bucket)}); e != nil {
		t.Fatal(e)
	}
	if _, e := archive.PutBucketTagging(ctx, &s3.PutBucketTaggingInput{Bucket: aws.String(bucket), Tagging: &types.Tagging{TagSet: []types.Tag{{Key: aws.String("finops-capacity-owner"), Value: aws.String(owner)}}}}); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		c, done := context.WithTimeout(context.Background(), 30*time.Second)
		defer done()
		tags, e := archive.GetBucketTagging(c, &s3.GetBucketTaggingInput{Bucket: aws.String(bucket)})
		owned := false
		if e == nil {
			for _, tag := range tags.TagSet {
				owned = owned || aws.ToString(tag.Key) == "finops-capacity-owner" && aws.ToString(tag.Value) == owner
			}
		}
		if !owned {
			t.Error("owned capacity archive cleanup refused")
			return
		}
		pages := s3.NewListObjectVersionsPaginator(archive, &s3.ListObjectVersionsInput{Bucket: aws.String(bucket)})
		for pages.HasMorePages() {
			p, e := pages.NextPage(c)
			if e != nil || len(p.Versions)+len(p.DeleteMarkers) > 1000 {
				t.Error("owned archive enumeration")
				return
			}
			objects := []types.ObjectIdentifier{}
			for _, v := range p.Versions {
				objects = append(objects, types.ObjectIdentifier{Key: v.Key, VersionId: v.VersionId})
			}
			for _, v := range p.DeleteMarkers {
				objects = append(objects, types.ObjectIdentifier{Key: v.Key, VersionId: v.VersionId})
			}
			if len(objects) > 0 {
				out, e := archive.DeleteObjects(c, &s3.DeleteObjectsInput{Bucket: aws.String(bucket), Delete: &types.Delete{Objects: objects, Quiet: aws.Bool(true)}})
				if e != nil || len(out.Errors) > 0 {
					t.Error("owned version cleanup")
					return
				}
			}
		}
		if _, e := archive.DeleteBucket(c, &s3.DeleteBucketInput{Bucket: aws.String(bucket)}); e != nil {
			t.Error(e)
		}
	})
	if _, e := archive.PutBucketVersioning(ctx, &s3.PutBucketVersioningInput{Bucket: aws.String(bucket), VersioningConfiguration: &types.VersioningConfiguration{Status: types.BucketVersioningStatusEnabled}}); e != nil {
		t.Fatal(e)
	}
	archived := 0
	put := func(captureCtx context.Context, key string, body []byte) model.Document {
		t.Helper()
		out, e := archive.PutObject(captureCtx, &s3.PutObjectInput{Bucket: aws.String(bucket), Key: aws.String(key), Body: bytes.NewReader(body)})
		if e != nil || aws.ToString(out.VersionId) == "" || aws.ToString(out.VersionId) == "null" {
			t.Fatal("capacity versioned archive", e)
		}
		back, e := archive.GetObject(captureCtx, &s3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String(key), VersionId: out.VersionId})
		if e != nil {
			t.Fatal(e)
		}
		got, e := io.ReadAll(io.LimitReader(back.Body, (128<<20)+1))
		_ = back.Body.Close()
		if e != nil || !bytes.Equal(got, body) || aws.ToString(back.VersionId) != aws.ToString(out.VersionId) {
			t.Fatal("capacity exact version readback")
		}
		archived++
		return model.Document{"bucket": bucket, "key": key, "version_id": aws.ToString(out.VersionId), "body_sha256": telemetry.BytesHash(body)}
	}
	var registration model.Document
	if e := f.roles["ingester"].Do(ctx, f.tenant, func(tx *store.Tx) error {
		var e error
		registration, e = tx.SourceGet(ctx, "assessment-native")
		return e
	}); e != nil {
		t.Fatal(e)
	}
	cfgHash := source.ConfigurationHash(registration)
	publishAt := func(captureCtx context.Context, kind string, d model.Document, raw []byte) {
		t.Helper()
		d = model.Clone(d)
		digest := telemetry.BytesHash(raw)
		prefix := "group-native/"
		if kind == "AWS_EC2_HARDWARE" {
			prefix = "hardware/" + model.String(sourceObject(d["binding"]), "resource_id") + "/"
		}
		ref := put(captureCtx, "tenant/"+f.tenant+"/"+prefix+digest+".bin", raw)
		id := "capacity-observation-" + model.ID()
		revision := "capacity-revision-" + source.Hash(model.Document{"kind": kind, "raw": digest})
		d["id"], d["kind"], d["source_id"], d["revision_id"], d["registration_version"], d["config_hash"], d["read_role_binding_id"], d["collected_at"], d["raw_object"] = id, kind, "assessment-native", revision, model.Number(registration, "version"), cfgHash, registration["read_role_binding_id"], time.Now().UTC(), ref
		if kind == "AWS_EC2_HARDWARE" {
			d["collected_at"] = sourceObject(d["native"])["collected_at"]
		}
		if e := f.roles["ingester"].Do(captureCtx, f.tenant, func(tx *store.Tx) error {
			rev := model.Document{"id": revision, "source_id": "assessment-native", "kind": kind, "revision_hash": source.Hash(model.Document{"kind": kind, "raw": digest}), "config_hash": cfgHash, "registration_version": model.Number(registration, "version"), "raw_object": ref, "observed_at": d["collected_at"]}
			if kind == "AWS_EC2_HARDWARE" {
				rev["resource_snapshot_hash"] = d["resource_snapshot_hash"]
			}
			if _, e := tx.SourceRevisionCreate(captureCtx, rev); e != nil {
				return e
			}
			_, e := tx.SourceReceiptCreate(captureCtx, d)
			return e
		}); e != nil {
			t.Fatal("capacity native ingester publication", kind, e)
		}
	}
	publish := func(kind string, d model.Document, raw []byte) { publishAt(ctx, kind, d, raw) }
	// The profile and actual inventory independently classify this fixture.
	profile := fleetCapacityFixtureProfile(telemetry.Binding{WorkloadID: "fixture-workload"}, time.Now().UTC(), false)
	if e := f.roles["api"].Do(ctx, f.tenant, func(tx *store.Tx) error {
		w, e := tx.Get(ctx, "workloads", "fixture-workload")
		if e != nil {
			return e
		}
		w["environment"] = "NON_PRODUCTION"
		if _, e = tx.Update(ctx, "workloads", "fixture-workload", model.Number(w, "version"), w); e != nil {
			return e
		}
		_, e = tx.WorkloadSafetyAppend(ctx, "fixture-workload", 1, profile)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	platform := f.token(f.tenant, "capacity-native-platform", "PLATFORM_ADMIN")
	auditor := f.token(f.tenant, "capacity-native-auditor", "AUDITOR")
	request := func(key, version string) model.Document {
		t.Helper()
		code, d, _ := f.request("workloads/fixture-workload/fleet-native-capacity-batches", `"`+version+`"`, key, platform, model.Document{"old_configuration_proposal_id": proposals[0], "candidate_configuration_proposal_id": proposals[1]})
		if code != 202 {
			t.Fatal("actual IDs-only capacity API", code, d)
		}
		return d
	}
	first := request("capacity-native-first", "2")
	var selection struct {
		Groups struct {
			Binding g.Binding `json:"binding"`
		} `json:"groups"`
	}
	raw, _ := json.Marshal(first["selection"])
	if json.Unmarshal(raw, &selection) != nil {
		t.Fatal("capacity server selection")
	}
	for _, s := range []struct {
		selection g.Selection
		ids       []string
		version   int
	}{{selection.Groups.Binding.Old, fleetCapacityPromInstances, 1}, {selection.Groups.Binding.Candidate, []string{}, 2}} {
		d, raw := nativeAssessmentMembership(s.selection, s.ids, s.version)
		publish("AWS_FLEET_MEMBERSHIP", d, raw)
	}
	templates, raw := fleetCapacityFixtureTemplates()
	publish("AWS_FLEET_LAUNCH_TEMPLATES", templates, raw)
	nativeStorage := &native.Storage{S3: archive, Bucket: bucket, Database: "finops", AnalyticsURL: "http://clickhouse:8123", AnalyticsUser: "finops", AnalyticsSecret: os.Getenv("FLEET_CAPACITY_CLICKHOUSE_PASSWORD"), Client: &http.Client{Timeout: 45 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect refused") }}}
	nativeStorage.Client.Transport = fleetCapacityAnalyticsAudit{}
	analyticsSQL := func(statement string) error {
		req, e := http.NewRequestWithContext(ctx, http.MethodPost, "http://clickhouse:8123/", strings.NewReader(statement))
		if e != nil {
			return e
		}
		req.Header.Set("X-ClickHouse-User", "finops")
		req.Header.Set("X-ClickHouse-Key", nativeStorage.AnalyticsSecret)
		response, e := nativeStorage.Client.Do(req)
		if e != nil {
			return e
		}
		defer response.Body.Close()
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		if response.StatusCode != 200 {
			return errors.New("isolated analytics SQL rejected")
		}
		return nil
	}
	ready := false
	for deadline := time.Now().Add(60 * time.Second); time.Now().Before(deadline); {
		if analyticsSQL("CREATE DATABASE IF NOT EXISTS finops") == nil {
			ready = true
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if !ready {
		t.Fatal("isolated ClickHouse not ready")
	}
	migration, e := os.ReadFile("../../config/clickhouse/001_facts.sql")
	if e != nil || len(migration) > 64<<10 {
		t.Fatal("canonical analytics migration unavailable", e)
	}
	for _, statement := range strings.Split(string(migration), ";") {
		if strings.TrimSpace(statement) != "" {
			if e := analyticsSQL(statement); e != nil {
				t.Fatal("canonical analytics migration", e)
			}
		}
	}
	pipeline := &native.Pipeline{Store: transport, Archive: nativeStorage.Archive, ReadObject: nativeStorage.Read, WriteFacts: nativeStorage.WriteFacts}
	bindings := map[string]native.ReadBinding{}
	inventories := map[string]model.Document{}
	sampleCount := 0
	for _, instance := range fleetCapacityPromInstances {
		resource := "actual-capacity-" + instance
		binding := telemetry.Binding{TenantID: f.tenant, ResourceID: resource, WorkloadID: "fixture-workload", Provider: "AWS", ProviderResourceID: instance, AccountID: nativeAssessmentAccount, Region: "eu-west-1"}
		connection := fleetCapacityFixtureConnection(binding)
		var inventory model.Document
		if e := f.roles["api"].Do(ctx, f.tenant, func(tx *store.Tx) error {
			var e error
			inventory, e = tx.Create(ctx, "resources", model.Document{"id": resource, "workload_id": "fixture-workload", "provider": "AWS", "provider_resource_id": instance, "account_id": nativeAssessmentAccount, "region": "eu-west-1", "instance_type": "m6i.xlarge", "environment": "NON_PRODUCTION"})
			if e != nil {
				return e
			}
			_, e = tx.TelemetryConnectionAppend(ctx, connection.ID, 0, telemetry.Document(connection))
			return e
		}); e != nil {
			t.Fatal(e)
		}
		inventories[instance] = inventory
		batch := fleetCapacityReadRealProm(t, connection, seed)
		receipt, replay, e := pipeline.Publish(ctx, connection, batch, "actual-prometheus-synthetic-history", seed.Start, seed.End)
		if e != nil || replay {
			t.Fatal("actual native archive/ClickHouse publication", e)
		}
		if model.String(receipt, "writer_role") != "finops_telemetry_reader" {
			t.Fatal("telemetry receipt issuer changed")
		}
		sampleCount += len(batch.Samples)
		bindings[connection.ReadBindingID] = native.ReadBinding{Binding: binding, Endpoint: "http://prometheus:9090", RequiredLabels: map[string]string{"instance": instance}}
	}
	refreshHardwareAt := func(captureCtx context.Context) {
		for _, instance := range fleetCapacityPromInstances {
			inventory := inventories[instance]
			binding := telemetry.Binding{TenantID: f.tenant, ResourceID: model.String(inventory, "id"), WorkloadID: "fixture-workload", Provider: "AWS", ProviderResourceID: instance, AccountID: nativeAssessmentAccount, Region: "eu-west-1"}
			hardware, raw := fleetCapacityFixtureHardware(t, instance, time.Now().UTC())
			publishAt(captureCtx, "AWS_EC2_HARDWARE", model.Document{"binding": binding, "resource_version": model.Number(inventory, "version"), "resource_snapshot_hash": telemetry.Hash(inventory), "inventory_snapshot": inventory, "candidate_types": []string{"m6i.large"}, "native": source.Object(hardware), "execution_authorized": false}, raw)
		}
	}
	refreshHardware := func() { refreshHardwareAt(ctx) }
	refreshHardware()
	readerToken := model.ID()
	nativeHandler := (&native.Server{Store: transport, Pipeline: pipeline, Fixture: true, ReaderToken: readerToken, Bindings: bindings}).Handler()
	server := httptest.NewServer(nativeHandler)
	defer server.Close()
	archiveReader, e := fleetassessmentworker.NewPinnedReader(readerClient, bucket, "")
	if e != nil {
		t.Fatal(e)
	}
	private := t.TempDir()
	secretFile := func(name, body string) string {
		p := filepath.Join(private, name)
		if e := os.WriteFile(p, []byte(body), 0444); e != nil {
			t.Fatal(e)
		}
		return p
	}
	modelToken := os.Getenv("TEST_FLEET_CAPACITY_MODEL_TOKEN")
	if len(modelToken) != 64 || modelToken == readerToken {
		t.Fatal("distinct private economics token required")
	}
	for _, token := range []string{"", "invalid-fixture-bearer"} {
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "http://economics:8000/v4/capacity", strings.NewReader("{}"))
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		response, e := nativeStorage.Client.Do(req)
		if e != nil {
			t.Fatal("actual economics authentication probe", e)
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		_ = response.Body.Close()
		if response.StatusCode != http.StatusUnauthorized {
			t.Fatal("economics accepted missing or wrong bearer", response.StatusCode)
		}
	}
	workerConfig := fleetcapacityworker.Config{Archive: fleetNativeWorkerConfig(f.tenant), ServiceMode: fleetcapacityworker.PrivateServices, ReaderURL: server.URL, ReaderTokenFile: secretFile("reader-token", readerToken), ModelURL: "http://economics:8000", ModelTokenFile: secretFile("model-token", modelToken)}
	workerConfig.Archive.ArchiveBucket = bucket
	workerConfig.Archive.ArchiveEndpoint = "http://minio:9000"
	population, calculator, closeDeps, e := fleetcapacityworker.OpenHTTPDependencies(ctx, workerConfig)
	if e != nil {
		t.Fatal("production capacity dependency construction", e)
	}
	defer closeDeps()
	newWorker := func(pop fleetcapacityworker.PopulationReader) *fleetcapacityworker.Worker {
		w, e := fleetcapacityworker.New(ctx, workerConfig, evaluator, archiveReader, pop, calculator)
		if e != nil {
			t.Fatal("production capacity worker construction", e)
		}
		return w
	}
	// Cancel before the second member: first publication must survive, then an
	// independently constructed worker resumes without rewriting that member.
	interrupted, stop := context.WithCancel(ctx)
	fault := &fleetCapacityCancelPopulation{reader: population, cancel: stop, at: 2}
	if _, e = newWorker(fault).Process(interrupted, model.String(first, "id")); e == nil {
		t.Fatal("interrupted capacity job unexpectedly completed")
	}
	processError := e
	stop()
	var before []model.Document
	if e = evaluator.Do(ctx, f.tenant, func(tx *store.Tx) error {
		var e error
		before, e = tx.FleetCapacityBatchMemberPage(ctx, model.String(first, "id"), "", 10)
		return e
	}); e != nil || len(before) != 1 {
		t.Fatal("completed first member was not durable", e, len(before), "process", processError, "population_calls", fault.calls.Load())
	}
	var issued model.Document
	var inputHash string
	if e = evaluator.Do(ctx, f.tenant, func(tx *store.Tx) error {
		var raw []byte
		if e := tx.QueryRow(ctx, `SELECT raw_document,input_snapshot_hash FROM public.fleet_native_capacity_members WHERE tenant_id=$1 AND id=$2`, f.tenant, before[0]["id"]).Scan(&raw, &inputHash); e != nil {
			return e
		}
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		return decoder.Decode(&issued)
	}); e != nil {
		t.Fatal(e)
	}
	if !model.Bool(issued, "model_evaluated") || model.String(issued, "input_kind") != "MODEL_REQUEST" || model.String(issued, "status") != "BLOCKED" || issued["model_evaluation"] == nil || issued["hardware"] == nil {
		t.Fatal("native SQL positive control requires actual calculated hardware/model evidence")
	}
	rollbackControl := errors.New("valid native member control rolled back")
	insertControl := func(d model.Document) error {
		raw, _ := json.Marshal(d)
		return evaluator.Do(ctx, f.tenant, func(tx *store.Tx) error {
			_, e := tx.Exec(ctx, `INSERT INTO public.fleet_native_capacity_members(tenant_id,id,request_id,instance_id,content_hash,input_snapshot_hash,document,raw_document) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT DO NOTHING`, f.tenant, d["id"], first["id"], d["instance_id"], fleetbilling.Hash(d), inputHash, raw, raw)
			if e != nil {
				return e
			}
			return rollbackControl
		})
	}
	if e := insertControl(model.Clone(issued)); !errors.Is(e, rollbackControl) {
		t.Fatal("valid actual native SQL control refused", e)
	}
	t.Log("Actual restricted native MODEL_REQUEST evaluated, persisted and SQL positive control accepted; member SHA256", fleetbilling.Hash(issued))
	negativeMutations := []func(model.Document){
		func(d model.Document) { d["execution_authorized"] = true },
		func(d model.Document) { d["verified_saving"] = "1" },
		func(d model.Document) { d["model_evaluated"] = false },
		func(d model.Document) {
			h := sourceObject(d["hardware"])
			h["receipt_id"] = "unissued-hardware"
			d["hardware"] = h
		},
		func(d model.Document) {
			c := sourceObject(d["candidate_template"])
			c["image_id"] = "ami-11111111111111111"
			d["candidate_template"] = c
		},
	}
	for i, mutate := range negativeMutations {
		d := model.Clone(issued)
		mutate(d)
		var failure *pgconn.PgError
		if e := insertControl(d); !errors.As(e, &failure) || failure.Code != "P0001" {
			t.Fatal("actual native SQL semantic negative did not reject", i, e)
		}
	}
	worker := newWorker(population)
	result, e := worker.Process(ctx, model.String(first, "id"))
	if e != nil || result.Members != 3 {
		t.Fatal("resumed production capacity job", e, result)
	}
	readMembers := func(id string) []fleetcapacity.MemberResult {
		t.Helper()
		code, page := fleetNativeHTTPGet(t, f, "fleet-native-capacity-batches/"+id+"/members?limit=2", auditor)
		if code != 200 || page["next_cursor"] == nil {
			t.Fatal("persisted capacity member pagination", code)
		}
		rows := []any{}
		for {
			rows = append(rows, page["items"].([]any)...)
			cursor := model.String(page, "next_cursor")
			if cursor == "" {
				break
			}
			code, page = fleetNativeHTTPGet(t, f, "fleet-native-capacity-batches/"+id+"/members?limit=2&cursor="+url.QueryEscape(cursor), auditor)
			if code != 200 {
				t.Fatal(code)
			}
		}
		out := []fleetcapacity.MemberResult{}
		for _, v := range rows {
			row := sourceObject(v)
			code, d := fleetNativeHTTPGet(t, f, "fleet-native-capacity-members/"+model.String(row, "id"), auditor)
			var member fleetcapacity.MemberResult
			raw, _ := json.Marshal(d["member"])
			if code != 200 || json.Unmarshal(raw, &member) != nil || model.String(d, "writer_role") != "finops_group_capacity" {
				t.Fatal("actual persistent capacity member", code)
			}
			out = append(out, member)
		}
		return out
	}
	members := readMembers(model.String(first, "id"))
	if len(members) != 3 {
		t.Fatal("original roster was truncated")
	}
	byInstance := map[string]fleetcapacity.MemberResult{}
	for _, m := range members {
		byInstance[m.InstanceID] = m
		if m.ExecutionAuthorized || m.GroupCapacityAuthorized || m.VerifiedSaving != nil || m.EstimatedSaving != nil || m.ChangePlanID != nil {
			t.Fatal("capacity calculation granted authority")
		}
	}
	healthy, high, missing := byInstance[fleetCapacityPromInstances[0]], byInstance[fleetCapacityPromInstances[1]], byInstance[fleetCapacityPromInstances[2]]
	if !healthy.ModelEvaluated || !high.ModelEvaluated || missing.ModelEvaluated || missing.CapacitySuitable != nil || healthy.CapacitySuitable == nil || *healthy.CapacitySuitable {
		t.Fatal("real native model/unknown classification differs")
	}
	if !strings.Contains(strings.Join(high.ReasonCodes, "|"), "MEMORY_P95_PLANNING_LIMIT") || !strings.Contains(strings.Join(healthy.ReasonCodes, "|"), "COMMITMENT_COMPATIBILITY_UNKNOWN_OR_FALSE") {
		t.Fatal("real physical pressure/unknown commitment lost")
	}
	if healthy.ModelEvaluation == nil || len(healthy.ModelEvaluation.Candidates) != 1 || len(healthy.ModelEvaluation.Candidates[0].Checks) != 5 {
		t.Fatal("actual healthy member omitted physical dimensions")
	}
	for _, check := range healthy.ModelEvaluation.Candidates[0].Checks {
		if model.String(check, "status") != "PASS" {
			t.Fatal("actual healthy member physical check failed", model.String(check, "dimension"))
		}
	}
	if model.String(healthy.ModelEvaluation.History, "status") == "INSUFFICIENT_OBSERVATION" || healthy.ModelEvaluation.Candidates[0].Economics.Status != "UNAVAILABLE" || healthy.ModelEvaluation.Candidates[0].Economics.EstimatedSaving != nil {
		t.Fatal("native member history/economics classification differs")
	}
	code, summary := fleetNativeHTTPGet(t, f, "fleet-native-capacity-batches/"+model.String(first, "id"), auditor)
	batchSummary := sourceObject(summary["batch"])
	if code != 200 || model.String(summary, "status") != "ASSESSED" || model.String(batchSummary, "coverage") != "PARTIAL" || model.String(batchSummary, "status") != "BLOCKED" || model.Bool(batchSummary, "group_capacity_authorized") || batchSummary["verified_saving"] != nil {
		t.Fatal("persistent capacity summary differs", code)
	}
	if code, reloaded := fleetNativeHTTPGet(t, f, "fleet-native-capacity-batches/"+model.String(first, "id"), auditor); code != 200 || fleetbilling.Hash(reloaded) != fleetbilling.Hash(summary) {
		t.Fatal("persistent capacity summary reload changed")
	}
	if replay, e := worker.Process(ctx, model.String(first, "id")); e != nil || !replay.Existing {
		t.Fatal("durable capacity batch replay", e)
	}
	var daemonProof *fleetCapacityDaemonProof
	if os.Getenv("FLEET_CAPACITY_DAEMON") == "ISOLATED_REAL_PROCESS_RESTART" {
		refreshHardware()
		daemonRequest := request("capacity-native-daemon", "2")
		daemonProof = fleetCapacityRunDaemonPhase(t, ctx, os.Getenv("FLEET_CAPACITY_RUN_ID"), f.tenant, evaluator, bucket, os.Getenv("TEST_FLEET_ASSESSMENT_READ_ACCESS_KEY"), os.Getenv("TEST_FLEET_ASSESSMENT_READ_SECRET_KEY"), readerToken, modelToken, nativeHandler, model.String(daemonRequest, "id"))
		if daemonProof == nil || !daemonProof.DistinctProcess || !daemonProof.OldAbsenceConfirmed {
			t.Fatal("actual daemon restart evidence unavailable")
		}
	}
	profile = fleetCapacityFixtureProfile(telemetry.Binding{WorkloadID: "fixture-workload"}, time.Now().UTC(), true)
	if e = f.roles["api"].Do(ctx, f.tenant, func(tx *store.Tx) error {
		_, e := tx.WorkloadSafetyAppend(ctx, "fixture-workload", 2, profile)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	fourfold := request("capacity-native-fourfold", "3")
	refreshHardware()
	if _, e = worker.Process(ctx, model.String(fourfold, "id")); e != nil {
		t.Fatal("declared demand batch", e)
	}
	four := readMembers(model.String(fourfold, "id"))
	found := false
	for _, m := range four {
		if m.InstanceID == fleetCapacityPromInstances[0] {
			found = strings.Contains(strings.Join(m.ReasonCodes, "|"), "CPU_FORECAST_RESERVE_INSUFFICIENT")
		}
	}
	if !found {
		t.Fatal("fourfold demand did not reject candidate CPU")
	}
	// Independent analytics readback checks actual persisted rows and exact raw
	// source counters, rather than a fixture acknowledgment callback.
	query := url.Values{"database": {"finops"}, "query": {"SELECT count() FROM native_metric_samples WHERE tenant_id='" + f.tenant + "' FORMAT TabSeparated"}}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "http://clickhouse:8123/?"+query.Encode(), nil)
	req.Header.Set("X-ClickHouse-User", "finops")
	req.Header.Set("X-ClickHouse-Key", os.Getenv("FLEET_CAPACITY_CLICKHOUSE_PASSWORD"))
	response, e := http.DefaultClient.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	analyticsBody, e := io.ReadAll(io.LimitReader(response.Body, 128))
	_ = response.Body.Close()
	count, _ := strconv.Atoi(strings.TrimSpace(string(analyticsBody)))
	if e != nil || response.StatusCode != 200 || count != sampleCount {
		t.Fatal("actual ClickHouse sample readback differs", count, sampleCount)
	}
	var issuedScope model.Document
	var scopeInputHash string
	if e = evaluator.Do(ctx, f.tenant, func(tx *store.Tx) error {
		var raw []byte
		if e := tx.QueryRow(ctx, `SELECT raw_document,input_snapshot_hash FROM public.fleet_native_capacity_scopes WHERE tenant_id=$1 AND request_id=$2`, f.tenant, fourfold["id"]).Scan(&raw, &scopeInputHash); e != nil {
			return e
		}
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		return decoder.Decode(&issuedScope)
	}); e != nil {
		t.Fatal(e)
	}
	insertScope := func(d model.Document) error {
		raw, _ := json.Marshal(d)
		return evaluator.Do(ctx, f.tenant, func(tx *store.Tx) error {
			_, e := tx.Exec(ctx, `INSERT INTO public.fleet_native_capacity_scopes(tenant_id,request_id,content_hash,input_snapshot_hash,document,raw_document) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING`, f.tenant, fourfold["id"], fleetbilling.Hash(d), scopeInputHash, raw, raw)
			if e != nil {
				return e
			}
			return rollbackControl
		})
	}
	if e := insertScope(model.Clone(issuedScope)); !errors.Is(e, rollbackControl) {
		t.Fatal("valid actual native scope SQL control", e)
	}
	for _, field := range []string{"instance_type", "image_id"} {
		d := model.Clone(issuedScope)
		candidate := sourceObject(d["candidate_template"])
		candidate[field] = map[string]string{"instance_type": "m6i.2xlarge", "image_id": "ami-11111111111111111"}[field]
		d["candidate_template"] = candidate
		scope := sourceObject(d["scope"])
		scope["snapshot_sha256"] = ""
		d["scope"] = scope
		scope["snapshot_sha256"] = fleetbilling.Hash(d)
		var failure *pgconn.PgError
		if e := insertScope(d); !errors.As(e, &failure) || failure.Code != "P0001" {
			t.Fatal("actual scope candidate semantic negative", field, e)
		}
	}
	// A real newly issued template response with unsupported effective CPU
	// options must preserve the full native roster and publish explicit gaps.
	_, supportedRaw := fleetCapacityFixtureTemplates()
	reader := bytes.NewReader(supportedRaw)
	var selectorSize uint32
	var bodySize uint64
	if binary.Read(reader, binary.BigEndian, &selectorSize) != nil {
		t.Fatal("template framing")
	}
	selectorBytes := make([]byte, selectorSize)
	if _, e = io.ReadFull(reader, selectorBytes); e != nil {
		t.Fatal(e)
	}
	if binary.Read(reader, binary.BigEndian, &bodySize) != nil {
		t.Fatal("template framing")
	}
	body := make([]byte, bodySize)
	if _, e = io.ReadFull(reader, body); e != nil || reader.Len() != 0 {
		t.Fatal("template framing")
	}
	selector, e := url.ParseQuery(string(selectorBytes))
	if e != nil {
		t.Fatal(e)
	}
	body = bytes.Replace(body, []byte("<instanceType>m6i.large</instanceType>"), []byte("<instanceType>m6i.large</instanceType><cpuOptions><coreCount>1</coreCount><threadsPerCore>1</threadsPerCore></cpuOptions>"), 1)
	unsupportedRaw := nativeAssessmentFrame(nativeAssessmentPage{selector, string(body)})
	publish("AWS_FLEET_LAUNCH_TEMPLATES", templates, unsupportedRaw)
	var movedFailure *pgconn.PgError
	if e := insertScope(model.Clone(issuedScope)); !errors.As(e, &movedFailure) || movedFailure.Code != "P0001" {
		t.Fatal("moved native template point did not invalidate old scope publication", e)
	}
	unsupported := request("capacity-native-unsupported-template", "3")
	if _, e = worker.Process(ctx, model.String(unsupported, "id")); e != nil {
		t.Fatal("unsupported effective template stalled roster", e)
	}
	for _, m := range readMembers(model.String(unsupported, "id")) {
		if m.ModelEvaluated || m.CapacitySuitable != nil || m.CandidateTemplate != nil {
			t.Fatal("unsupported raw template invented candidate capability")
		}
	}
	publish("AWS_FLEET_LAUNCH_TEMPLATES", templates, supportedRaw)
	// The browser reads the already persisted analytics archive. Its host may
	// retire Prometheus/ClickHouse only after this independent row-count proof.
	var browserProof *fleetCapacityBrowserProof
	if os.Getenv("FLEET_CAPACITY_BROWSER") == "ISOLATED_REAL_OIDC" {
		refreshNative := func(refreshCtx context.Context) {
			for _, group := range []struct {
				selection g.Selection
				ids       []string
				version   int
			}{{selection.Groups.Binding.Old, fleetCapacityPromInstances, 1}, {selection.Groups.Binding.Candidate, []string{}, 2}} {
				d, raw := nativeAssessmentMembership(group.selection, group.ids, group.version)
				publishAt(refreshCtx, "AWS_FLEET_MEMBERSHIP", d, raw)
			}
			_, raw := fleetCapacityFixtureTemplates()
			publishAt(refreshCtx, "AWS_FLEET_LAUNCH_TEMPLATES", templates, raw)
			refreshHardwareAt(refreshCtx)
			// Acknowledge only this completed real fixture capture cycle. Its
			// source/config/version must still be the issued selection; no clock
			// or receipt is rewritten to keep an expired source looking current.
			if e := f.roles["ingester"].Do(refreshCtx, f.tenant, func(tx *store.Tx) error {
				current, e := tx.SourceGet(refreshCtx, "assessment-native")
				if e != nil || !model.Bool(current, "enabled") || model.Bool(current, "revoked") || model.Number(current, "version") != model.Number(registration, "version") || source.ConfigurationHash(current) != cfgHash {
					return errors.New("captured fixture source configuration changed")
				}
				return tx.SourceCheckpointSet(refreshCtx, "assessment-native", "status", model.Document{"status": "HEALTHY", "config_hash": cfgHash, "last_sync_version": model.Number(current, "version"), "last_sync_at": time.Now().UTC().Format(time.RFC3339Nano)})
			}); e != nil {
				t.Fatal("actual native fixture capture acknowledgment", e)
			}
		}
		browserProof = fleetCapacityPositiveBrowserPhase(t, ctx, f, admin, proposals, model.String(first, "id"), fleetCapacityPromInstances[1], refreshNative)
		if browserProof == nil || !browserProof.ActualWorkerResult || !browserProof.PersistedReload {
			t.Fatal("actual calculated-member browser evidence unavailable")
		}
	}
	// Freeze an original roster, interrupt before its first member, revoke the
	// source, then resume. Every member remains present with an explicit gap.
	revoked := request("capacity-native-revoked", "3")
	interrupted, stop = context.WithCancel(ctx)
	fault = &fleetCapacityCancelPopulation{reader: population, cancel: stop, at: 1}
	if _, e = newWorker(fault).Process(interrupted, model.String(revoked, "id")); e == nil {
		t.Fatal("pre-member interruption absent")
	}
	stop()
	if e = f.roles["api"].Do(ctx, f.tenant, func(tx *store.Tx) error {
		_, e := tx.Exec(ctx, `UPDATE public.source_registrations SET document=document||'{"enabled":false,"revoked":true}'::jsonb WHERE tenant_id=$1 AND id='assessment-native'`, f.tenant)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	if _, e = worker.Process(ctx, model.String(revoked, "id")); e != nil {
		t.Fatal("historical roster gap completion after revocation", e)
	}
	for _, m := range readMembers(model.String(revoked, "id")) {
		if m.ModelEvaluated || m.CapacitySuitable != nil || !strings.Contains(strings.Join(m.ReasonCodes, "|"), "SCOPE_NOT_CURRENT") {
			t.Fatal("revocation erased member or fabricated model")
		}
	}
	if os.Getenv("FLEET_NATIVE_CAPACITY_WRITE_RESULT") == "1" {
		proof := model.Document{"schema_version": "1", "status": "PASS", "raw_transport": "PROVIDER_SHAPED_FIXTURE", "history": "SYNTHETIC_TSDB_BACKFILL", "history_days": 14, "cadence_seconds": 300, "complete_intervals_per_metric": 4032, "actual_prometheus": true, "actual_clickhouse": true, "actual_python": true, "model_authentication_enforced": true, "analytics_sample_count": sampleCount, "archived_native_readbacks": archived, "member_count": 3, "evaluated_member_count": 2, "low_utilization_physical_checks_pass": true, "memory95_rejected": true, "fourfold_demand_rejected": true, "missing_statistics_unknown": true, "resumed_publication": true, "revoked_source_roster_preserved": true, "unsupported_template_roster_preserved": true, "sql_guard_negatives": len(negativeMutations) + 3, "immutable_replay": true, "actual_daemon_restart": daemonProof != nil, "actual_real_oidc_browser": browserProof != nil, "group_capacity_authorized": false, "customer_execution_authorized": false, "verified_saving": nil, "fixture": true}
		raw, _ := json.Marshal(proof)
		if len(raw) > 4096 {
			t.Fatal("capacity proof bounds")
		}
		file, e := os.OpenFile("/results/result.json", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = file.Write(raw); e == nil {
			e = file.Sync()
		}
		closed := file.Close()
		if e != nil || closed != nil {
			t.Fatal("bounded capacity proof publication")
		}
	}
}
