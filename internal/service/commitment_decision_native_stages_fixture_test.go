//go:build commitment_decision_native_integration

package service

// Provider-shaped response fixtures and synthetic Prometheus history below are
// reparsed and published by the ordinary production source/telemetry workers.
// They do not claim a live AWS observation or fourteen elapsed customer days.
import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	portfolio "github.com/christopherosiemo/bn-implementation-Finops/internal/commitmentportfolio"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/fleet"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/fleetassessmentworker"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/fleetcapacity"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/fleetcapacityworker"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/fleetdecisionworker"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/native"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/provider"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/source"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/telemetry"
	"github.com/jackc/pgx/v5"
)

type commitmentDecisionNativeStages struct {
	// The coordinator fills ownership only after its real attestor/archive path.
	// A provider membership point cannot manufacture an ownership interval.
	OwnershipScope                                                                  portfolio.DecisionOwnershipScope
	SourceID, WorkloadID, ResourceID, NativeID                                      string
	OldProposalID, CandidateProposalID, AssessmentRequestID, CapacityRequestID      string
	JointRequestID, JointDecisionID                                                 string
	HistoryRegistrationID, ASGARN, LaunchTemplateID, LaunchTemplateVersion, ImageID string
	SourceConfigurationSHA256                                                       string
	SafetyProfileVersion                                                            int64
	NativePins                                                                      []portfolio.Ref
	Refresh                                                                         func(context.Context) error
	Snapshot                                                                        func() commitmentDecisionNativeStages
}

type commitmentDecisionStageFleetReader struct{ oldName, candidateName, oldARN, candidateARN, instance string }

func (r commitmentDecisionStageFleetReader) FleetInventory(_ context.Context, region, account string, names []string) (provider.FleetInventoryEvidence, error) {
	if region != "eu-west-1" || account != nativeAssessmentAccount || len(names) < 1 || len(names) > 2 {
		return provider.FleetInventoryEvidence{}, errors.New("DECISION_STAGE_NATIVE_GROUP_SCOPE_DIFFERS")
	}
	ordered := append([]string{}, names...)
	sort.Strings(ordered)
	selector := url.Values{"Action": {"DescribeAutoScalingGroups"}, "Version": {"2011-01-01"}, "MaxRecords": {"100"}}
	body := "<DescribeAutoScalingGroupsResponse><DescribeAutoScalingGroupsResult><AutoScalingGroups>"
	for i, name := range ordered {
		if name != r.oldName && name != r.candidateName {
			return provider.FleetInventoryEvidence{}, errors.New("DECISION_STAGE_UNREGISTERED_GROUP")
		}
		selector.Set("AutoScalingGroupNames.member."+strconv.Itoa(i+1), name)
		count, version, arn, members := 0, 2, r.candidateARN, ""
		if name == r.oldName {
			count, version, arn = 1, 1, r.oldARN
			members = fmt.Sprintf("<member><InstanceId>%s</InstanceId><AvailabilityZone>eu-west-1a</AvailabilityZone><LifecycleState>InService</LifecycleState><HealthStatus>Healthy</HealthStatus><LaunchTemplate><LaunchTemplateId>%s</LaunchTemplateId><Version>1</Version></LaunchTemplate></member>", r.instance, nativeAssessmentTemplate)
		}
		body += fmt.Sprintf("<member><AutoScalingGroupName>%s</AutoScalingGroupName><AutoScalingGroupARN>%s</AutoScalingGroupARN><MinSize>%d</MinSize><MaxSize>%d</MaxSize><DesiredCapacity>%d</DesiredCapacity><DesiredCapacityType>units</DesiredCapacityType><AvailabilityZones><member>eu-west-1a</member></AvailabilityZones><VPCZoneIdentifier>subnet-0123456789abcdef0</VPCZoneIdentifier><CapacityRebalance>false</CapacityRebalance><NewInstancesProtectedFromScaleIn>false</NewInstancesProtectedFromScaleIn><LaunchTemplate><LaunchTemplateId>%s</LaunchTemplateId><Version>%d</Version></LaunchTemplate><Instances>%s</Instances></member>", name, arn, count, count, count, nativeAssessmentTemplate, version, members)
	}
	body += "</AutoScalingGroups></DescribeAutoScalingGroupsResult></DescribeAutoScalingGroupsResponse>"
	var parsed struct {
		Groups []provider.FleetGroup `xml:"DescribeAutoScalingGroupsResult>AutoScalingGroups>member"`
	}
	if xml.Unmarshal([]byte(body), &parsed) != nil {
		return provider.FleetInventoryEvidence{}, errors.New("DECISION_STAGE_GROUP_XML_INVALID")
	}
	for i := range parsed.Groups {
		if parsed.Groups[i].Members == nil {
			parsed.Groups[i].Members = []provider.FleetMember{}
		}
	}
	raw := nativeAssessmentFrame(nativeAssessmentPage{selector, body})
	return provider.FleetInventoryEvidence{SchemaVersion: "1", Provider: "AWS", Region: region, AccountID: account, CollectedAt: time.Now().UTC(), Raw: raw, RawSHA256: source.BytesHash(raw), Groups: parsed.Groups}, nil
}

func (r commitmentDecisionStageFleetReader) FleetTemplateVersions(_ context.Context, region, account string, requests []provider.FleetTemplateRequest) (provider.FleetTemplateEvidence, error) {
	if region != "eu-west-1" || account != nativeAssessmentAccount || len(requests) != 2 || requests[0].ID != nativeAssessmentTemplate || requests[0].Version != 1 || requests[1].ID != nativeAssessmentTemplate || requests[1].Version != 2 {
		return provider.FleetTemplateEvidence{}, errors.New("DECISION_STAGE_EXACT_TEMPLATE_SELECTORS_REQUIRED")
	}
	pages := []nativeAssessmentPage{}
	body := "<DescribeLaunchTemplateVersionsResponse><launchTemplateVersionSet>"
	for _, request := range requests {
		body += fmt.Sprintf(`<item><launchTemplateId>%s</launchTemplateId><versionNumber>%d</versionNumber><launchTemplateData><instanceType>m6i.large</instanceType><imageId>%s</imageId><placement><tenancy>default</tenancy></placement><blockDeviceMappingSet><item><deviceName>/dev/sda1</deviceName><ebs><volumeType>gp3</volumeType><volumeSize>64</volumeSize><iops>3000</iops><throughput>125</throughput><encrypted>true</encrypted><deleteOnTermination>true</deleteOnTermination></ebs></item></blockDeviceMappingSet></launchTemplateData></item>`, request.ID, request.Version, nativeAssessmentImage)
	}
	body += "</launchTemplateVersionSet></DescribeLaunchTemplateVersionsResponse>"
	pages = append(pages, nativeAssessmentPage{url.Values{"Action": {"DescribeLaunchTemplateVersions"}, "Version": {"2016-11-15"}, "MaxResults": {"100"}, "ResolveAlias": {"false"}, "LaunchTemplateId": {nativeAssessmentTemplate}, "LaunchTemplateVersion.1": {"1"}, "LaunchTemplateVersion.2": {"2"}}, body})
	var parsed struct {
		Templates []provider.FleetTemplateVersion `xml:"launchTemplateVersionSet>item"`
	}
	if xml.Unmarshal([]byte(body), &parsed) != nil {
		return provider.FleetTemplateEvidence{}, errors.New("DECISION_STAGE_TEMPLATE_XML_INVALID")
	}
	raw := nativeAssessmentFrame(pages...)
	return provider.FleetTemplateEvidence{SchemaVersion: "1", Provider: "AWS", Region: region, AccountID: account, CollectedAt: time.Now().UTC(), Raw: raw, RawSHA256: source.BytesHash(raw), Templates: parsed.Templates}, nil
}

func commitmentDecisionStageHardware(t *testing.T, instance string, now time.Time) (provider.HardwareEvidence, []byte) {
	t.Helper()
	pages := []nativeAssessmentPage{}
	for _, page := range fleetCapacityHardwarePages {
		selector, err := url.ParseQuery(page.selector)
		if err != nil {
			t.Fatal(err)
		}
		body := page.body
		volume := "vol-" + strings.TrimPrefix(instance, "i-")
		body = strings.ReplaceAll(strings.ReplaceAll(body, "i-0123456789abcdef0", instance), "vol-0123456789abcdef0", volume)
		switch selector.Get("Action") {
		case "DescribeInstances":
			selector.Set("InstanceId.1", instance)
			body = strings.ReplaceAll(body, "<instanceType>m6i.xlarge</instanceType>", "<instanceType>m6i.large</instanceType>")
			body = strings.ReplaceAll(body, "<imageId>"+nativeAssessmentImage+"</imageId>", "<imageId>"+nativeAssessmentImage+"</imageId><subnetId>subnet-0123456789abcdef0</subnetId><vpcId>vpc-0123456789abcdef0</vpcId>")
		case "DescribeInstanceTypes":
			selector.Del("InstanceType.2")
			at := strings.Index(body, "<item><instanceType>m6i.xlarge</instanceType>")
			end := strings.Index(body, "</instanceTypeSet>")
			if at < 0 || end < at {
				t.Fatal("fixed native type fixture order differs")
			}
			body = body[:at] + body[end:]
		case "DescribeInstanceTypeOfferings":
			selector.Del("Filter.1.Value.2")
			at := strings.Index(body, "<item><instanceType>m6i.xlarge</instanceType>")
			end := strings.Index(body, "</instanceTypeOfferingSet>")
			if at < 0 || end < at {
				t.Fatal("fixed native offering fixture order differs")
			}
			body = body[:at] + body[end:]
		case "DescribeVolumes":
			selector.Set("VolumeId.1", volume)
			body = strings.ReplaceAll(body, "<volumeType>gp3</volumeType>", "<volumeType>gp3</volumeType><size>64</size>")
		case "DescribeImages":
			body = strings.ReplaceAll(body, "<imageId>"+nativeAssessmentImage+"</imageId>", "<imageId>"+nativeAssessmentImage+"</imageId><platformDetails>Linux/UNIX</platformDetails><usageOperation>RunInstances</usageOperation><productCodes/>")
		}
		pages = append(pages, nativeAssessmentPage{selector, body})
	}
	raw := nativeAssessmentFrame(pages...)
	hardware, err := provider.ParseHardwareEvidence(raw, nativeAssessmentAccount, "eu-west-1", instance, []string{"m6i.large"}, now)
	if err != nil || provider.ValidateHardwareEvidence(hardware, instance, []string{"m6i.large"}) != nil {
		t.Fatal("current large native hardware did not reparse", err)
	}
	return hardware, raw
}

func commitmentDecisionIssueNativeStages(t *testing.T, ctx context.Context, f *mutationReplayFixture, admin *store.Store, sourceID, workloadID, resourceID, nativeID string, put func(context.Context, string, []byte) (model.Document, error), normalizerToken string) (commitmentDecisionNativeStages, error) {
	t.Helper()
	proof := commitmentDecisionNativeStages{SourceID: sourceID, WorkloadID: workloadID, ResourceID: resourceID, NativeID: nativeID, LaunchTemplateID: nativeAssessmentTemplate, LaunchTemplateVersion: "2", ImageID: nativeAssessmentImage, NativePins: []portfolio.Ref{}}
	if f == nil || admin == nil || put == nil || len(normalizerToken) < 32 || os.Getenv("TEST_FLEET_HISTORY_S3_ENDPOINT") != "http://minio:9000" || os.Getenv("FLEET_CAPACITY_CLICKHOUSE_URL") != "http://clickhouse:8123" {
		return proof, errors.New("DECISION_STAGE_FIXED_NATIVE_DEPENDENCIES_REQUIRED")
	}
	var registration, inventory model.Document
	if err := f.roles["api"].Do(ctx, f.tenant, func(tx *store.Tx) error {
		var err error
		registration, err = tx.SourceGet(ctx, sourceID)
		if err != nil {
			return err
		}
		inventory, err = tx.Get(ctx, "resources", resourceID)
		return err
	}); err != nil {
		return proof, err
	}
	if model.String(inventory, "workload_id") != workloadID || model.String(inventory, "provider_resource_id") != nativeID || model.String(inventory, "instance_type") != "m6i.large" || model.String(inventory, "environment") != "NON_PRODUCTION" {
		return proof, errors.New("DECISION_STAGE_ATTESTED_INVENTORY_DIFFERS")
	}
	proof.SourceConfigurationSHA256 = source.ConfigurationHash(registration)
	platform := f.token(f.tenant, "decision-native-platform", "PLATFORM_ADMIN")
	finance := f.token(f.tenant, "decision-native-finance", "FINANCE")
	activity := store.ActivitySource{ID: "decision-native-stage-activity", WorkloadID: workloadID, ResourceID: resourceID, ProviderResourceID: nativeID, AccountID: nativeAssessmentAccount, Region: "eu-west-1", Issuer: "https://native-stage-fixture.invalid", Subject: "independent-stage-activity", MetricDefinition: store.ActivityMetric{ID: "completed_orders", Version: "1", Unit: "completed_orders"}, Enabled: true}
	if err := f.roles["api"].Do(ctx, f.tenant, func(tx *store.Tx) error { _, err := tx.ActivityRegister(ctx, activity); return err }); err != nil {
		return proof, err
	}
	oldName, candidateName := "decision-native-original", "decision-native-current-baseline"
	oldARN := "arn:aws:autoscaling:eu-west-1:" + nativeAssessmentAccount + ":autoScalingGroup:04000000-0000-4000-8000-000000000001:autoScalingGroupName/" + oldName
	candidateARN := "arn:aws:autoscaling:eu-west-1:" + nativeAssessmentAccount + ":autoScalingGroup:04000000-0000-4000-8000-000000000002:autoScalingGroupName/" + candidateName
	proof.ASGARN = oldARN
	registrations := []string{}
	proposals := []string{}
	for index, name := range []string{oldName, candidateName} {
		arn := oldARN
		if index == 1 {
			arn = candidateARN
		}
		code, reg, _ := f.request("fleet-history-registrations", `"0"`, "decision-native-reg-"+name, platform, model.Document{"workload_id": workloadID, "fleet_id": name, "asg_arn": arn, "source_connection_id": sourceID, "cadence_seconds": 60, "max_gap_seconds": 120})
		if code != 201 {
			return proof, errors.New("DECISION_STAGE_HISTORY_REGISTRATION_REFUSED")
		}
		registrations = append(registrations, model.String(reg, "id"))
		code, definition, _ := f.request("fleet-demand-definitions", `"0"`, "decision-native-definition-"+name, platform, model.Document{"registration_id": reg["id"], "activity_source_id": activity.ID, "business_operation": "completed_order", "semantic_contract_id": "component-independent-completed-orders", "semantic_contract_hash": strings.Repeat("c", 64)})
		if code != 201 {
			return proof, errors.New("DECISION_STAGE_DEMAND_DEFINITION_REFUSED")
		}
		code, scope, _ := f.request("fleet-history-scopes", `"1"`, "decision-native-scope-"+name, platform, model.Document{"registration_id": reg["id"], "definition_id": definition["id"], "definition_version": 1})
		if code != 201 {
			return proof, errors.New("DECISION_STAGE_GROUP_SCOPE_REFUSED")
		}
		metadata := model.Document{"schema_version": "1", "authority": "TERRAFORM", "repository": model.Document{"url": "https://github.com/customer/stage-fixture.git", "ref": "main", "directory": "infra"}, "pipeline": model.Document{"system": "GITHUB_ACTIONS", "identity": model.Document{"issuer": "https://token.actions.githubusercontent.com", "audience": "finops-deployment-observer", "subject": "repo:customer/stage-fixture:ref:refs/heads/main", "pipeline_id": ".github/workflows/deploy.yml"}}, "terraform": model.Document{"workspace": "default", "state_lineage": "04000000-0000-4000-8000-000000000001", "asg_address": "aws_autoscaling_group." + []string{"original", "baseline"}[index], "launch_template_address": "aws_launch_template.current", "traffic": model.Document{"listener_rule_address": "aws_lb_listener_rule.current", "target_group_addresses": []string{"aws_lb_target_group.original", "aws_lb_target_group.baseline"}}}}
		base := "fleet-history-registrations/" + model.String(reg, "id")
		code, authority, _ := f.request(base+"/configuration-authorities", `"0"`, "decision-native-authority-"+name, platform, metadata)
		if code != 201 {
			return proof, errors.New("DECISION_STAGE_GROUP_AUTHORITY_REFUSED")
		}
		code, proposal, _ := f.request(base+"/configuration-proposals", `"1"`, "decision-native-proposal-"+name, platform, model.Document{"declaration_id": authority["id"], "scope_id": scope["id"]})
		if code != 201 {
			return proof, errors.New("DECISION_STAGE_GROUP_PROPOSAL_REFUSED")
		}
		proposals = append(proposals, model.String(proposal, "id"))
	}
	proof.HistoryRegistrationID, proof.OldProposalID, proof.CandidateProposalID = registrations[0], proposals[0], proposals[1]
	binding := telemetry.Binding{TenantID: f.tenant, ResourceID: resourceID, WorkloadID: workloadID, Provider: "AWS", ProviderResourceID: nativeID, AccountID: nativeAssessmentAccount, Region: "eu-west-1"}
	connection := fleetCapacityFixtureConnection(binding)
	if err := f.roles["api"].Do(ctx, f.tenant, func(tx *store.Tx) error {
		if _, err := tx.TelemetryConnectionAppend(ctx, connection.ID, 0, telemetry.Document(connection)); err != nil {
			return err
		}
		current, err := tx.WorkloadSafetyLatest(ctx, workloadID)
		if err == nil {
			proof.SafetyProfileVersion = model.Number(current, "version")
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		profile := fleetCapacityFixtureProfile(binding, time.Now().UTC(), false)
		_, err = tx.WorkloadSafetyAppend(ctx, workloadID, 0, profile)
		proof.SafetyProfileVersion = 1
		return err
	}); err != nil {
		return proof, err
	}
	if proof.SafetyProfileVersion < 1 {
		return proof, errors.New("DECISION_STAGE_CURRENT_SAFETY_PROFILE_REQUIRED")
	}
	reader := commitmentDecisionStageFleetReader{oldName: oldName, candidateName: candidateName, oldARN: oldARN, candidateARN: candidateARN, instance: nativeID}
	bucket := ""
	archive := func(c context.Context, tenant, id string, raw []byte) (model.Document, error) {
		ref, err := put(c, "tenant/"+tenant+"/fleet/"+id+"/"+source.BytesHash(raw)+".bin", raw)
		if err != nil {
			return nil, err
		}
		if bucket == "" {
			bucket = model.String(ref, "bucket")
		}
		if bucket == "" || model.String(ref, "bucket") != bucket || model.String(ref, "body_sha256") != source.BytesHash(raw) || model.String(ref, "version_id") == "" {
			return nil, errors.New("DECISION_STAGE_NATIVE_ARCHIVE_DIFFERS")
		}
		return ref, nil
	}
	factory := func(context.Context, source.Registration, string) (source.FleetReader, error) { return reader, nil }
	historyPipeline := source.FleetHistoryPipeline{Store: f.roles["ingester"], ReaderFactory: factory, Archive: archive}
	discovery := source.FleetPipeline{Store: f.roles["ingester"], ReaderFactory: factory, Archive: archive, DiscoveryBindings: map[string]source.FleetDiscoveryBinding{"decision-native-stage-groups": {SourceID: sourceID, Binding: fleet.Binding{TenantID: f.tenant, ResourceID: "decision-native-controller-point", WorkloadID: workloadID, Provider: "AWS", ProviderResourceID: oldName, AccountID: nativeAssessmentAccount, Region: "eu-west-1"}, OldASG: oldName, CandidateASG: candidateName}}}
	captureNative := func(c context.Context) error {
		for _, id := range registrations {
			if _, err := historyPipeline.Capture(c, f.tenant, id); err != nil {
				return err
			}
		}
		membership, err := discovery.Discover(c, f.tenant, "decision-native-stage-groups")
		if err != nil {
			return err
		}
		if _, err = discovery.CaptureTemplates(c, f.tenant, sourceID, model.String(membership, "id")); err != nil {
			return err
		}
		hardware, _ := commitmentDecisionStageHardware(t, nativeID, time.Now().UTC())
		pipeline := source.HardwarePipeline{Store: f.roles["ingester"], Targets: map[string]source.HardwareTarget{f.tenant + ":" + resourceID: {Binding: binding, SourceID: sourceID, CandidateTypes: []string{"m6i.large"}}}, ReaderFactory: func(context.Context, source.Registration, string) (source.HardwareReader, error) {
			return nativeHardwareFixtureReader{raw: hardware.Raw, now: hardware.CollectedAt}, nil
		}, Archive: func(c context.Context, tenant, resource string, raw []byte) (model.Document, error) {
			return put(c, "tenant/"+tenant+"/hardware/"+resource+"/"+source.BytesHash(raw)+".bin", raw)
		}}
		_, err = pipeline.Capture(c, f.tenant, resourceID)
		return err
	}
	if err := captureNative(ctx); err != nil {
		return proof, err
	}
	access, secret := os.Getenv("TEST_FLEET_HISTORY_S3_ACCESS_KEY"), os.Getenv("TEST_FLEET_HISTORY_S3_SECRET_KEY")
	chSecret := os.Getenv("FLEET_CAPACITY_CLICKHOUSE_PASSWORD")
	if access == "" || secret == "" || chSecret == "" {
		return proof, errors.New("DECISION_STAGE_PRIVATE_ARCHIVE_ANALYTICS_IDENTITY_REQUIRED")
	}
	s3client := s3.NewFromConfig(aws.Config{Region: "eu-west-1", Credentials: credentials.NewStaticCredentialsProvider(access, secret, "")}, func(options *s3.Options) {
		options.BaseEndpoint = aws.String("http://minio:9000")
		options.UsePathStyle = true
	})
	httpClient := &http.Client{Timeout: 45 * time.Second, Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	t.Cleanup(httpClient.CloseIdleConnections)
	storage := &native.Storage{S3: s3client, Bucket: bucket, Database: "finops", AnalyticsURL: "http://clickhouse:8123", AnalyticsUser: "finops", AnalyticsSecret: chSecret, Client: httpClient}
	sql := func(statement string) error {
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://clickhouse:8123/?database=finops", strings.NewReader(statement))
		if err != nil {
			return err
		}
		request.Header.Set("X-ClickHouse-User", "finops")
		request.Header.Set("X-ClickHouse-Key", chSecret)
		response, err := httpClient.Do(request)
		if err != nil {
			return err
		}
		defer response.Body.Close()
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		if response.StatusCode != 200 {
			return errors.New("DECISION_STAGE_OWNED_ANALYTICS_SCHEMA_REFUSED")
		}
		return nil
	}
	migration, err := os.ReadFile("../../config/clickhouse/001_facts.sql")
	if err != nil {
		return proof, err
	}
	for _, statement := range strings.Split(string(migration), ";") {
		if strings.TrimSpace(statement) != "" {
			if err = sql(statement); err != nil {
				return proof, err
			}
		}
	}
	transport := jointRuntime(t, admin, "finops_telemetry_reader", "telemetry-reader")
	nativePipeline := &native.Pipeline{Store: transport, Archive: func(c context.Context, tenant, kind, id string, raw []byte) (model.Document, error) {
		return put(c, "tenant/"+tenant+"/native/"+id+"/"+kind+"/"+source.BytesHash(raw)+".bin", raw)
	}, ReadObject: storage.Read, WriteFacts: func(c context.Context, tenant, batchID string, batch telemetry.Batch) (model.Document, error) {
		ref, err := storage.WriteFacts(c, tenant, batchID, batch)
		if err != nil {
			return nil, err
		}
		query := url.Values{"database": {"finops"}, "param_tenant": {tenant}, "param_batch": {batchID}, "param_hash": {telemetry.CanonicalHash(batch)}, "query": {"SELECT count() FROM native_metric_samples WHERE tenant_id={tenant:String} AND batch_id={batch:String} AND canonical_hash={hash:String} FORMAT TabSeparated"}}
		request, err := http.NewRequestWithContext(c, http.MethodPost, "http://clickhouse:8123/?"+query.Encode(), nil)
		if err != nil {
			return nil, err
		}
		request.Header.Set("X-ClickHouse-User", "finops")
		request.Header.Set("X-ClickHouse-Key", chSecret)
		response, err := httpClient.Do(request)
		if err != nil {
			return nil, err
		}
		raw, readErr := io.ReadAll(io.LimitReader(response.Body, 128))
		response.Body.Close()
		count, parseErr := strconv.Atoi(strings.TrimSpace(string(raw)))
		if readErr != nil || parseErr != nil || response.StatusCode != 200 || count != len(batch.Samples) {
			return nil, errors.New("DECISION_STAGE_EXACT_TELEMETRY_ANALYTICS_READBACK_REQUIRED")
		}
		return ref, nil
	}}
	prometheusEndpoint := ""
	publishTelemetry := func(c context.Context) error {
		base, start, end := fleetCapacityFixturePrometheus(t, connection, time.Now().UTC(), fleetCapacityFixtureOptions{CPU: "0.2", Memory: "0.2"})
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			recorder := httptest.NewRecorder()
			base.Config.Handler.ServeHTTP(recorder, r)
			for k, values := range recorder.Header() {
				for _, v := range values {
					w.Header().Add(k, v)
				}
			}
			w.WriteHeader(recorder.Code)
			_, _ = w.Write(bytes.ReplaceAll(recorder.Body.Bytes(), []byte("17179869184"), []byte("8589934592")))
		}))
		t.Cleanup(server.Close)
		if prometheusEndpoint == "" {
			prometheusEndpoint = server.URL
		}
		batch, err := (telemetry.PromReader{URL: server.URL, AllowHTTP: true, AllowPrivate: true}).Read(c, connection, start, end)
		if err != nil {
			return err
		}
		_, _, err = nativePipeline.Publish(c, connection, batch, "decision-stage-native-"+telemetry.CanonicalHash(batch), start, end)
		return err
	}
	if err = publishTelemetry(ctx); err != nil {
		return proof, err
	}
	readerToken := model.ID()
	nativeServer := httptest.NewServer((&native.Server{Store: transport, Pipeline: nativePipeline, Fixture: true, ReaderToken: readerToken, Bindings: map[string]native.ReadBinding{connection.ReadBindingID: {Binding: binding, Endpoint: prometheusEndpoint, RequiredLabels: map[string]string{"instance": nativeID}}}}).Handler())
	t.Cleanup(nativeServer.Close)
	private := t.TempDir()
	readerFile, modelFile := filepath.Join(private, "reader-token"), filepath.Join(private, "model-token")
	if os.WriteFile(readerFile, []byte(readerToken), 0444) != nil || os.WriteFile(modelFile, []byte(normalizerToken), 0444) != nil {
		return proof, errors.New("DECISION_STAGE_PRIVATE_TOKEN_FILES_REQUIRED")
	}
	config := fleetcapacityworker.Config{Archive: fleetNativeWorkerConfig(f.tenant), ServiceMode: fleetcapacityworker.PrivateServices, ReaderURL: nativeServer.URL, ReaderTokenFile: readerFile, ModelURL: "http://economics:8000", ModelTokenFile: modelFile}
	config.Archive.ArchiveBucket, config.Archive.ArchiveEndpoint = bucket, "http://minio:9000"
	population, calculator, closeDependencies, err := fleetcapacityworker.OpenHTTPDependencies(ctx, config)
	if err != nil {
		return proof, err
	}
	t.Cleanup(closeDependencies)
	pinned, err := fleetassessmentworker.NewPinnedReader(s3client, bucket, "")
	if err != nil {
		return proof, err
	}
	capacityDB := jointRuntime(t, admin, "finops_group_capacity", "group-capacity-evaluator")
	capacityWorker, err := fleetcapacityworker.New(ctx, config, capacityDB, pinned, population, calculator)
	if err != nil {
		return proof, err
	}
	assessor := jointRuntime(t, admin, "finops_group_assessor", "group-assessment-reader")
	assessmentConfig := fleetNativeWorkerConfig(f.tenant)
	assessmentConfig.ArchiveBucket, assessmentConfig.ArchiveEndpoint = bucket, "http://minio:9000"
	assessmentWorker, err := fleetassessmentworker.New(ctx, assessmentConfig, assessor, pinned)
	if err != nil {
		return proof, err
	}
	decisionDB := jointRuntime(t, admin, "finops_group_decision", "group-decision-reader", f.tenant)
	decisionWorker := fleetdecisionworker.Worker{Store: decisionDB, Tenant: f.tenant}
	issue := func(c context.Context) error {
		version := `"` + strconv.FormatInt(proof.SafetyProfileVersion, 10) + `"`
		body := model.Document{"old_configuration_proposal_id": proof.OldProposalID, "candidate_configuration_proposal_id": proof.CandidateProposalID}
		code, queued, _ := f.request("workloads/"+workloadID+"/fleet-native-capacity-batches", version, "decision-native-capacity-"+model.ID(), platform, body)
		if code != 202 {
			return errors.New("DECISION_STAGE_CAPACITY_QUEUE_REFUSED")
		}
		proof.CapacityRequestID = model.String(queued, "id")
		if result, err := capacityWorker.Process(c, proof.CapacityRequestID); err != nil || result.Members != 1 {
			return errors.New("DECISION_STAGE_SINGLE_MEMBER_CAPACITY_NOT_ISSUED")
		}
		var members []model.Document
		if err := capacityDB.Do(c, f.tenant, func(tx *store.Tx) error {
			var err error
			members, err = tx.FleetCapacityBatchMemberPage(c, proof.CapacityRequestID, "", 2)
			return err
		}); err != nil || len(members) != 1 {
			return errors.New("DECISION_STAGE_COMPLETE_CAPACITY_MEMBER_REQUIRED")
		}
		var member fleetcapacity.MemberResult
		if err := capacityDB.Do(c, f.tenant, func(tx *store.Tx) error {
			var raw []byte
			if err := tx.QueryRow(c, "SELECT raw_document FROM fleet_native_capacity_members WHERE tenant_id=$1 AND id=$2", f.tenant, members[0]["id"]).Scan(&raw); err != nil {
				return err
			}
			return json.Unmarshal(raw, &member)
		}); err != nil {
			return err
		}
		if !member.ModelEvaluated || member.InputKind != "CURRENT_CONFIGURATION_BASELINE_MODEL_REQUEST" || member.ModelEvaluation == nil || len(member.ModelEvaluation.Candidates) != 1 {
			return errors.New("DECISION_STAGE_ACTUAL_CURRENT_BASELINE_MODEL_REQUIRED")
		}
		for _, check := range member.ModelEvaluation.Candidates[0].Checks {
			if model.String(check, "status") != "PASS" {
				return errors.New("DECISION_STAGE_CURRENT_BASELINE_PHYSICAL_CHECK_FAILED")
			}
		}
		code, assessment, _ := f.request("workloads/"+workloadID+"/fleet-native-assessments", version, "decision-native-assessment-"+model.ID(), finance, body)
		if code != 202 {
			return errors.New("DECISION_STAGE_ASSESSMENT_QUEUE_REFUSED")
		}
		proof.AssessmentRequestID = model.String(assessment, "id")
		if _, err := assessmentWorker.Process(c, proof.AssessmentRequestID); err != nil {
			return err
		}
		code, joint, _ := f.request("workloads/"+workloadID+"/fleet-joint-decisions", version, "decision-native-joint-"+model.ID(), finance, model.Document{"assessment_request_id": proof.AssessmentRequestID, "capacity_batch_request_id": proof.CapacityRequestID})
		if code != 202 {
			return errors.New("DECISION_STAGE_JOINT_QUEUE_REFUSED")
		}
		proof.JointRequestID = model.String(joint, "id")
		issued, _, err := decisionWorker.Process(c, proof.JointRequestID)
		if err != nil {
			return err
		}
		decision := source.Object(issued["decision"])
		if model.String(issued, "status") != "ASSESSED" || model.String(decision, "physical_status") != "PASS" || len(source.Rows(decision["members"])) != 1 || model.Bool(decision, "execution_authorized") || model.Bool(decision, "group_capacity_authorized") || decision["verified_saving"] != nil {
			return errors.New("DECISION_STAGE_ISSUED_PHYSICAL_JOIN_REQUIRED")
		}
		scenario := source.Object(decision["scenario"])
		if model.String(scenario, "status") == "OBSERVED_CONDITIONAL" {
			return errors.New("DECISION_STAGE_BASELINE_CANNOT_ISSUE_FLEET_MONEY")
		}
		proof.JointDecisionID = model.String(decision, "id")
		proof.NativePins = []portfolio.Ref{{Kind: "FLEET_JOINT_DECISION", ID: proof.JointRequestID, SHA256: portfolio.Hash(decision)}}
		return nil
	}
	if err = issue(ctx); err != nil {
		return proof, err
	}
	proof.Refresh = func(c context.Context) error {
		if err := captureNative(c); err != nil {
			return err
		}
		if err := publishTelemetry(c); err != nil {
			return err
		}
		return issue(c)
	}
	proof.Snapshot = func() commitmentDecisionNativeStages { return proof }
	return proof, nil
}
