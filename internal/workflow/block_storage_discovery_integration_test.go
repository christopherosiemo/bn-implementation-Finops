package workflow

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/native"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/provider"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/service"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/telemetry"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/workload"
	"github.com/jackc/pgx/v5"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const blockStorageFixtureVolume = "vol-0eb50000000000001"
const blockStorageFixtureInstance = "i-0eb50000000000001"

func blockStorageFixturePage(action, collection, body string) string {
	return "<" + action + "Response><requestId>component-ebs</requestId><" + collection + ">" + body + "</" + collection + "></" + action + "Response>"
}
func blockStorageFixtureNative(v url.Values) (string, error) {
	action := v.Get("Action")
	switch action {
	case "DescribeVolumes":
		return blockStorageFixturePage(action, "volumeSet", `<item><volumeId>`+blockStorageFixtureVolume+`</volumeId><size>100</size><availabilityZone>eu-west-1a</availabilityZone><status>in-use</status><createTime>2020-01-01T00:00:00Z</createTime><volumeType>gp3</volumeType><iops>3000</iops><throughput>125</throughput><encrypted>true</encrypted><multiAttachEnabled>false</multiAttachEnabled><attachmentSet><item><volumeId>`+blockStorageFixtureVolume+`</volumeId><instanceId>`+blockStorageFixtureInstance+`</instanceId><device>/dev/sda1</device><status>attached</status><attachTime>2020-01-01T00:00:00Z</attachTime><deleteOnTermination>true</deleteOnTermination></item></attachmentSet><tagSet/></item>`), nil
	case "DescribeSnapshots":
		return blockStorageFixturePage(action, "snapshotSet", ""), nil
	case "DescribeImages":
		return blockStorageFixturePage(action, "imagesSet", ""), nil
	case "DescribeFastSnapshotRestores":
		return blockStorageFixturePage(action, "fastSnapshotRestoreSet", ""), nil
	case "DescribeSnapshotTierStatus":
		return blockStorageFixturePage(action, "snapshotTierStatusSet", ""), nil
	case "DescribeLockedSnapshots":
		return blockStorageFixturePage(action, "snapshotSet", ""), nil
	case "DescribeVolumesModifications":
		return blockStorageFixturePage(action, "volumeModificationSet", ""), nil
	case "DescribeVolumeStatus":
		return blockStorageFixturePage(action, "volumeStatusSet", ""), nil
	case "DescribeInstances":
		if v.Get("InstanceId.1") != blockStorageFixtureInstance {
			return "", errors.New("component EBS attachment selector differs")
		}
		return blockStorageFixturePage(action, "reservationSet", `<item><ownerId>111122223333</ownerId><instancesSet><item><instanceId>`+blockStorageFixtureInstance+`</instanceId><instanceType>m6i.12xlarge</instanceType><rootDeviceName>/dev/sda1</rootDeviceName><rootDeviceType>ebs</rootDeviceType><ebsOptimized>true</ebsOptimized><monitoring><state>disabled</state></monitoring><placement><availabilityZone>eu-west-1a</availabilityZone></placement><blockDeviceMapping><item><deviceName>/dev/sda1</deviceName><ebs><volumeId>`+blockStorageFixtureVolume+`</volumeId><status>attached</status><deleteOnTermination>true</deleteOnTermination></ebs></item></blockDeviceMapping></item></instancesSet></item>`), nil
	case "DescribeInstanceTypes":
		return blockStorageFixturePage(action, "instanceTypeSet", `<item><instanceType>m6i.12xlarge</instanceType><currentGeneration>true</currentGeneration><hypervisor>nitro</hypervisor><ebsInfo><ebsOptimizedSupport>default</ebsOptimizedSupport><ebsOptimizedInfo><baselineBandwidthInMbps>15000</baselineBandwidthInMbps><baselineThroughputInMBps>1875</baselineThroughputInMBps><baselineIops>60000</baselineIops><maximumBandwidthInMbps>15000</maximumBandwidthInMbps><maximumThroughputInMBps>1875</maximumThroughputInMBps><maximumIops>60000</maximumIops></ebsOptimizedInfo></ebsInfo></item>`), nil
	case "GetMetricStatistics":
		start, e := time.Parse(time.RFC3339, v.Get("StartTime"))
		if e != nil {
			return "", e
		}
		end, e := time.Parse(time.RFC3339, v.Get("EndTime"))
		if e != nil {
			return "", e
		}
		period, e := strconv.Atoi(v.Get("Period"))
		if e != nil || period != 3600 {
			return "", errors.New("full EBS source period changed")
		}
		var rows strings.Builder
		stat := v.Get("Statistics.member.1")
		for at := start; at.Before(end); at = at.Add(time.Duration(period) * time.Second) {
			maximum := ""
			if v.Get("Statistics.member.3") == "Maximum" {
				maximum = "<Maximum>0</Maximum>"
			}
			count := 60
			if v.Get("Namespace") == "AWS/EC2" {
				count = 12
			}
			fmt.Fprintf(&rows, "<member><Timestamp>%s</Timestamp><%s>0</%s>%s<SampleCount>%d</SampleCount><Unit>%s</Unit></member>", at.Format(time.RFC3339), stat, stat, maximum, count, v.Get("Unit"))
		}
		return databaseFixturePage(action, "Datapoints", rows.String()), nil
	}
	return "", errors.New("unexpected EBS component operation")
}

// Native AWS/STS responses are explicit COMPONENT doubles. Actual SigV4,
// ordinary ingester LOGIN, SQL/RLS, immutable object write/readback and every
// full fourteen-day metric payload are exercised in the existing owned lab.
func TestBlockStorageNativeCollectorRestrictedPersistenceAndStorage(t *testing.T) {
	if os.Getenv("EBS_TEST_STORAGE_ENABLED") != "true" {
		t.Skip("existing owned PostgreSQL/versioned object/ClickHouse lab required")
	}
	admin, roles := schedulerTestDatabase(t)
	ctx, cancel := context.WithTimeout(context.Background(), 85*time.Second)
	defer cancel()
	tenant := "ebs-" + model.ID()
	login := "ebs_ingester_" + strings.ReplaceAll(model.ID(), "-", "")
	password := model.ID() + model.ID()
	marker := "owned-ebs-collector:" + login
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
			t.Error("owned EBS login marker differs")
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
		t.Fatal("actual EBS ingester identity differs", e)
	}
	resourceID, workloadID := "component-ebs-resource", "component-ebs-workload"
	if e = roles["api"].Do(ctx, tenant, func(tx *store.Tx) error {
		if e := tx.Seed(ctx, true); e != nil {
			return e
		}
		if _, e := tx.Create(ctx, "workloads", model.Document{"id": workloadID, "name": "Component EBS workload", "owner": "declared-owner"}); e != nil {
			return e
		}
		p := workload.Profile{SchemaVersion: "1", Criticality: "NON_PRODUCTION", Statefulness: "STATELESS", Timezone: "UTC", MinReplicas: 1, MinZones: 1, Headroom: workload.Headroom{CPUFreePPM: 300000, MemoryFreePPM: 300000, ReserveAboveForecastPPM: 300000}, Saturation: workload.Saturation{CPUP99PPM: 850000, MemoryP99PPM: 900000}, RTOSeconds: 900, MaxSimultaneousChangePPM: 100000, VMCooldownSeconds: 604800}
		if _, e := tx.WorkloadSafetyAppend(ctx, workloadID, 0, p); e != nil {
			return e
		}
		_, e := tx.Create(ctx, "resources", model.Document{"id": resourceID, "provider": "AWS", "account_id": "111122223333", "region": "eu-west-1", "provider_resource_id": blockStorageFixtureVolume, "resource_type": "EBS_VOLUME", "workload_id": workloadID, "owner": "declared-owner", "environment": "NON_PRODUCTION", "configuration_authority": "GITOPS", "storage_configuration": model.Document{}})
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
		fmt.Fprintf(w, `<AssumeRoleResponse><AssumeRoleResult><Credentials><AccessKeyId>component-ebs-read</AccessKeyId><SecretAccessKey>component-ebs-secret</SecretAccessKey><SessionToken>component-ebs-session</SessionToken><Expiration>%s</Expiration></Credentials><AssumedRoleUser><Arn>arn:aws:sts::111122223333:assumed-role/component-read/session</Arn><AssumedRoleId>COMPONENT:session</AssumedRoleId></AssumedRoleUser></AssumeRoleResult></AssumeRoleResponse>`, time.Now().UTC().Add(time.Hour).Format(time.RFC3339))
	}))
	defer sts.Close()
	for k, v := range map[string]string{"AWS_TENANT_ID": tenant, "AWS_ACCESS_KEY_ID": "component-source", "AWS_SECRET_ACCESS_KEY": "component-source-secret", "AWS_SESSION_TOKEN": "", "AWS_ROLE_ARN": "", "AWS_WEB_IDENTITY_TOKEN_FILE": "", "AWS_PROFILE": "", "AWS_ENDPOINT_URL_STS": sts.URL, "AWS_EC2_METADATA_DISABLED": "true"} {
		t.Setenv(k, v)
	}
	storage, e := native.StorageFromEnvironment(ctx, true)
	if e != nil {
		t.Fatal(e)
	}
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
		status := 200
		switch host {
		case "sts.eu-west-1.amazonaws.com":
			body = `<GetCallerIdentityResponse><GetCallerIdentityResult><Account>111122223333</Account><Arn>arn:aws:sts::111122223333:assumed-role/component-read/session</Arn><UserId>COMPONENT:session</UserId></GetCallerIdentityResult></GetCallerIdentityResponse>`
		case "ec2.eu-west-1.amazonaws.com", "monitoring.eu-west-1.amazonaws.com":
			if !strings.Contains(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256") {
				return nil, errors.New("unsigned EBS native request")
			}
			if denied.Load() {
				status = 403
				body = `<Response><Errors><Error><Code>UnauthorizedOperation</Code></Error></Errors></Response>`
				break
			}
			raw, e := io.ReadAll(r.Body)
			if e != nil {
				return nil, e
			}
			v, _ := url.ParseQuery(string(raw))
			body, e = blockStorageFixtureNative(v)
			if e != nil {
				return nil, e
			}
		case "config.eu-west-1.amazonaws.com":
			status = 400
			body = `{"__type":"NoAvailableConfigurationRecorderException"}`
		default:
			if allowed[host] {
				return original.RoundTrip(r)
			}
			return nil, errors.New("unregistered EBS component network endpoint")
		}
		return &http.Response{StatusCode: status, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body))}, nil
	})
	defer func() { http.DefaultTransport = original }()
	aws, e := provider.NewAWS(ctx, "eu-west-1", "arn:aws:iam::111122223333:role/component-read", "component-external")
	if e != nil {
		t.Fatal(e)
	}
	a := &Activities{Config: service.Config{Fixture: true}}
	capture := func() error {
		return ingester.Do(ctx, tenant, func(tx *store.Tx) error {
			return discoverBlockStorageAccount(ctx, a, tx, aws, model.Document{"id": "component-cloud", "account_id": "111122223333", "region": "eu-west-1"})
		})
	}
	if e = capture(); e != nil {
		t.Fatal(e)
	}
	var resource, snapshot model.Document
	if e = ingester.Do(ctx, tenant, func(tx *store.Tx) error {
		var e error
		resource, e = tx.Get(ctx, "resources", resourceID)
		if e != nil {
			return e
		}
		snapshot, e = tx.StorageEvidenceLatest(ctx, resourceID)
		return e
	}); e != nil {
		t.Fatal("EBS collector did not publish after storage", e)
	}
	if resource["owner"] != "declared-owner" || resource["workload_id"] != workloadID || resource["configuration_authority"] != "GITOPS" {
		t.Fatal("EBS refresh replaced reviewed metadata")
	}
	ref, _ := databaseDocument(snapshot["archive"])
	raw, e := storage.Read(ctx, tenant, ref)
	if e != nil {
		t.Fatal(e)
	}
	var object model.Document
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if d.Decode(&object) != nil {
		t.Fatal("invalid EBS canonical object")
	}
	metricRaw, _ := json.Marshal(object["metrics"].([]any)[0])
	var metrics provider.EBSMetricEvidence
	if json.Unmarshal(metricRaw, &metrics) != nil || metrics.Selection.End.Sub(metrics.Selection.Start) != 14*24*time.Hour || metrics.Selection.PeriodSeconds != 3600 || len(metrics.Metrics) != 19*14*24 {
		t.Fatal("EBS full native population reduced", len(metrics.Metrics))
	}
	batches, e := blockStorageMetricBatches(resource, metrics)
	if e != nil {
		t.Fatal(e)
	}
	count := 0
	for i, batch := range batches {
		batchID := "ebs-" + telemetry.Hash(model.Document{"resource": resourceID, "raw_sha256": metrics.RawSHA256, "chunk": i})
		endpoint, _ := url.Parse(storage.AnalyticsURL)
		q := endpoint.Query()
		q.Set("database", storage.Database)
		q.Set("query", "SELECT sample_id,payload FROM native_metric_samples WHERE tenant_id={tenant:String} AND batch_id={batch:String} ORDER BY sample_id FORMAT JSONEachRow")
		q.Set("param_tenant", tenant)
		q.Set("param_batch", batchID)
		endpoint.RawQuery = q.Encode()
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), nil)
		req.Header.Set("X-ClickHouse-User", storage.AnalyticsUser)
		req.Header.Set("X-ClickHouse-Key", storage.AnalyticsSecret)
		res, e := storage.Client.Do(req)
		if e != nil {
			t.Fatal(e)
		}
		if res.StatusCode != 200 {
			res.Body.Close()
			t.Fatal("actual EBS full payload read refused")
		}
		want := map[string]telemetry.Sample{}
		for _, s := range batch.Samples {
			want[s.ID] = s
		}
		seen := map[string]bool{}
		decoder := json.NewDecoder(io.LimitReader(res.Body, 16<<20))
		for {
			var row model.Document
			e := decoder.Decode(&row)
			if e == io.EOF {
				break
			}
			if e != nil {
				res.Body.Close()
				t.Fatal(e)
			}
			id := model.String(row, "sample_id")
			var actual telemetry.Sample
			if json.Unmarshal([]byte(model.String(row, "payload")), &actual) != nil || seen[id] || telemetry.Hash(actual) != telemetry.Hash(want[id]) {
				res.Body.Close()
				t.Fatal("actual EBS full fact differs")
			}
			seen[id] = true
		}
		res.Body.Close()
		if len(seen) != len(batch.Samples) {
			t.Fatal("missing EBS facts")
		}
		count += len(seen)
	}
	if count != len(metrics.Metrics) {
		t.Fatal("EBS payload population incomplete")
	}
	for _, v := range snapshot["source_refs"].([]any) {
		ref, _ := databaseDocument(v)
		body, e := storage.Read(ctx, tenant, ref)
		if e != nil {
			t.Fatal(e)
		}
		if model.String(ref, "body_sha256") == telemetry.BytesHash(provider.EBSCapabilityAsset()) {
			if !bytes.Equal(body, provider.EBSCapabilityAsset()) {
				t.Fatal("EBS capability asset differs")
			}
		} else if _, e = provider.EBSCaptureFrames(body); e != nil {
			t.Fatal(e)
		}
	}
	if e = roles["api"].Do(ctx, tenant, func(tx *store.Tx) error {
		copy := model.Clone(snapshot)
		copy["id"] = model.ID()
		_, e := tx.StorageEvidenceAppend(ctx, copy)
		return e
	}); e == nil {
		t.Fatal("API gained native EBS publication")
	}
	if e = ingester.Do(ctx, "foreign-"+tenant, func(tx *store.Tx) error { _, e := tx.StorageEvidenceGet(ctx, model.String(snapshot, "id")); return e }); !errors.Is(e, pgx.ErrNoRows) {
		t.Fatal("cross-tenant EBS evidence visible", e)
	}
	denied.Store(true)
	if e = capture(); e != nil {
		t.Fatal(e)
	}
	if e = ingester.Do(ctx, tenant, func(tx *store.Tx) error {
		q, e := tx.Get(ctx, "data_quality", "quality-ebs-111122223333-eu-west-1")
		if e != nil {
			return e
		}
		if model.String(q, "status") != "DEGRADED" {
			return errors.New("EBS refusal became empty success")
		}
		current, e := tx.StorageEvidenceLatest(ctx, resourceID)
		if e == nil && current["id"] != snapshot["id"] {
			return errors.New("EBS refusal renewed evidence")
		}
		return e
	}); e != nil {
		t.Fatal(e)
	}
}
