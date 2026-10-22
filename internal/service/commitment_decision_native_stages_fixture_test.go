//go:build commitment_decision_native_integration

package service

// Provider-shaped response fixtures and synthetic Prometheus history below are
// reparsed and published by the ordinary production source/telemetry workers.
// They do not claim a live AWS observation or fourteen elapsed customer days.
import (
	"bytes"
	"context"
	"encoding/binary"
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
	"github.com/christopherosiemo/bn-implementation-Finops/internal/fleetassessment"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/fleetassessmentworker"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/fleetbilling"
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

type commitmentDecisionStageFleetReader struct{ tenant, oldName, candidateName, oldARN, candidateARN, instance string }

func commitmentDecisionStageTemplate(candidate bool) (address, id string, version uint64) {
	if candidate {
		return "aws_launch_template.baseline", "lt-0d040000000000002", 2
	}
	return "aws_launch_template.original", nativeAssessmentTemplate, 1
}

func (r commitmentDecisionStageFleetReader) FleetInventory(_ context.Context, region, account string, names []string) (provider.FleetInventoryEvidence, error) {
	if r.tenant == "" || region != "eu-west-1" || account != nativeAssessmentAccount || len(names) < 1 || len(names) > 2 {
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
		_, templateID, version := commitmentDecisionStageTemplate(name == r.candidateName)
		count, arn, members := 0, r.candidateARN, ""
		if name == r.oldName {
			count, arn = 1, r.oldARN
			members = fmt.Sprintf("<member><InstanceId>%s</InstanceId><AvailabilityZone>eu-west-1a</AvailabilityZone><LifecycleState>InService</LifecycleState><HealthStatus>Healthy</HealthStatus><LaunchTemplate><LaunchTemplateId>%s</LaunchTemplateId><Version>%d</Version></LaunchTemplate></member>", r.instance, templateID, version)
		}
		body += fmt.Sprintf("<member><AutoScalingGroupName>%s</AutoScalingGroupName><AutoScalingGroupARN>%s</AutoScalingGroupARN><MinSize>%d</MinSize><MaxSize>%d</MaxSize><DesiredCapacity>%d</DesiredCapacity><DesiredCapacityType>units</DesiredCapacityType><AvailabilityZones><member>eu-west-1a</member></AvailabilityZones><VPCZoneIdentifier>subnet-0123456789abcdef0</VPCZoneIdentifier><CapacityRebalance>false</CapacityRebalance><NewInstancesProtectedFromScaleIn>false</NewInstancesProtectedFromScaleIn><Tags><member><Key>finops:tenant</Key><Value>%s</Value></member><member><Key>finops:environment</Key><Value>NON_PRODUCTION</Value></member></Tags><LaunchTemplate><LaunchTemplateId>%s</LaunchTemplateId><Version>%d</Version></LaunchTemplate><Instances>%s</Instances></member>", name, arn, count, count, count, r.tenant, templateID, version, members)
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
	if region != "eu-west-1" || account != nativeAssessmentAccount || len(requests) != 2 {
		return provider.FleetTemplateEvidence{}, errors.New("DECISION_STAGE_EXACT_TEMPLATE_SELECTORS_REQUIRED")
	}
	wanted := map[provider.FleetTemplateRequest]bool{}
	for _, candidate := range []bool{false, true} {
		_, id, version := commitmentDecisionStageTemplate(candidate)
		wanted[provider.FleetTemplateRequest{ID: id, Version: version}] = true
	}
	ordered := append([]provider.FleetTemplateRequest{}, requests...)
	for _, request := range ordered {
		if !wanted[request] {
			return provider.FleetTemplateEvidence{}, errors.New("DECISION_STAGE_EXACT_TEMPLATE_SELECTORS_REQUIRED")
		}
		delete(wanted, request)
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].ID < ordered[j].ID })
	pages := []nativeAssessmentPage{}
	templates := []provider.FleetTemplateVersion{}
	for _, request := range ordered {
		body := fmt.Sprintf(`<DescribeLaunchTemplateVersionsResponse><launchTemplateVersionSet><item><launchTemplateId>%s</launchTemplateId><launchTemplateName>decision-native-%s</launchTemplateName><versionNumber>%d</versionNumber><launchTemplateData><instanceType>m6i.large</instanceType><imageId>%s</imageId><placement><tenancy>default</tenancy></placement><blockDeviceMappingSet><item><deviceName>/dev/sda1</deviceName><ebs><volumeType>gp3</volumeType><volumeSize>64</volumeSize><iops>3000</iops><throughput>125</throughput><encrypted>true</encrypted><deleteOnTermination>true</deleteOnTermination></ebs></item></blockDeviceMappingSet></launchTemplateData></item></launchTemplateVersionSet></DescribeLaunchTemplateVersionsResponse>`, request.ID, request.ID, request.Version, nativeAssessmentImage)
		pages = append(pages, nativeAssessmentPage{url.Values{"Action": {"DescribeLaunchTemplateVersions"}, "Version": {"2016-11-15"}, "MaxResults": {"100"}, "ResolveAlias": {"false"}, "LaunchTemplateId": {request.ID}, "LaunchTemplateVersion.1": {strconv.FormatUint(request.Version, 10)}}, body})
		var parsed struct {
			Templates []provider.FleetTemplateVersion `xml:"launchTemplateVersionSet>item"`
		}
		if xml.Unmarshal([]byte(body), &parsed) != nil {
			return provider.FleetTemplateEvidence{}, errors.New("DECISION_STAGE_TEMPLATE_XML_INVALID")
		}
		templates = append(templates, parsed.Templates...)
	}
	raw := nativeAssessmentFrame(pages...)
	return provider.FleetTemplateEvidence{SchemaVersion: "1", Provider: "AWS", Region: region, AccountID: account, CollectedAt: time.Now().UTC(), Raw: raw, RawSHA256: source.BytesHash(raw), Templates: templates}, nil
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
		body = strings.ReplaceAll(strings.ReplaceAll(body, "<instanceId>i-0123456789abcdef0</instanceId>", "<instanceId>"+instance+"</instanceId>"), "vol-0123456789abcdef0", volume)
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

func TestCommitmentDecisionStageHardwarePreservesExactNativeSelectors(t *testing.T) {
	hardware, raw := commitmentDecisionStageHardware(t, decisionNativeID, time.Now().UTC())
	volume := "vol-" + strings.TrimPrefix(decisionNativeID, "i-")
	if hardware.Instance.ID != decisionNativeID || hardware.Instance.ImageID != nativeAssessmentImage || hardware.Image.ID != nativeAssessmentImage {
		t.Fatal("native instance/image binding changed during fixture substitution")
	}
	if len(hardware.Volumes) != 1 || hardware.Volumes[0].ID != volume || len(hardware.Volumes[0].Attachments) != 1 || hardware.Volumes[0].Attachments[0].InstanceID != decisionNativeID {
		t.Fatal("native volume/attachment binding differs")
	}
	for _, selector := range []string{"InstanceId.1=" + decisionNativeID, "ImageId.1=" + nativeAssessmentImage, "VolumeId.1=" + volume} {
		if !bytes.Contains(raw, []byte(selector)) {
			t.Fatal("exact native selector absent", selector)
		}
	}
	if bytes.Contains(raw, []byte("ami-"+strings.TrimPrefix(decisionNativeID, "i-"))) {
		t.Fatal("instance suffix was substituted into unrelated AMI identity")
	}
}

func TestCommitmentDecisionStageTemplatesPreserveDistinctNativeSelectors(t *testing.T) {
	oldAddress, oldID, oldVersion := commitmentDecisionStageTemplate(false)
	candidateAddress, candidateID, candidateVersion := commitmentDecisionStageTemplate(true)
	if oldAddress == candidateAddress || oldID == candidateID || oldID != nativeAssessmentTemplate || oldVersion != 1 || candidateVersion != 2 {
		t.Fatal("original and candidate declarative/native template identities must be distinct")
	}
	reader := commitmentDecisionStageFleetReader{tenant: "component-tenant", oldName: "original", candidateName: "baseline", oldARN: "original-arn", candidateARN: "baseline-arn", instance: decisionNativeID}
	inventory, err := reader.FleetInventory(context.Background(), "eu-west-1", nativeAssessmentAccount, []string{reader.oldName, reader.candidateName})
	if err != nil || len(inventory.Groups) != 2 {
		t.Fatal("native group fixture unavailable", err)
	}
	for _, group := range inventory.Groups {
		_, id, version := commitmentDecisionStageTemplate(group.Name == reader.candidateName)
		if group.LaunchTemplate.ID != id || group.LaunchTemplate.Version != strconv.FormatUint(version, 10) {
			t.Fatal("group points at a different native template")
		}
		if group.Name == reader.oldName && (len(group.Members) != 1 || group.Members[0].LaunchTemplate.ID != oldID || group.Members[0].LaunchTemplate.Version != "1") {
			t.Fatal("original member template was rewritten as the candidate")
		}
	}
	requests := []provider.FleetTemplateRequest{{ID: candidateID, Version: candidateVersion}, {ID: oldID, Version: oldVersion}}
	evidence, err := reader.FleetTemplateVersions(context.Background(), "eu-west-1", nativeAssessmentAccount, requests)
	if err != nil || len(evidence.Templates) != 2 || evidence.RawSHA256 != source.BytesHash(evidence.Raw) {
		t.Fatal("exact native template pair unavailable", err)
	}
	framed := bytes.NewReader(evidence.Raw)
	decoded := []provider.FleetTemplateVersion{}
	seen := map[string]bool{}
	for framed.Len() > 0 {
		var selectorSize uint32
		var bodySize uint64
		if binary.Read(framed, binary.BigEndian, &selectorSize) != nil || selectorSize == 0 || uint64(selectorSize) > uint64(framed.Len()) {
			t.Fatal("template selector frame invalid")
		}
		selectorRaw := make([]byte, selectorSize)
		_, _ = io.ReadFull(framed, selectorRaw)
		selector, err := url.ParseQuery(string(selectorRaw))
		if err != nil || binary.Read(framed, binary.BigEndian, &bodySize) != nil || bodySize == 0 || bodySize > uint64(framed.Len()) {
			t.Fatal("template response frame invalid")
		}
		body := make([]byte, int(bodySize))
		_, _ = io.ReadFull(framed, body)
		var response struct {
			XMLName xml.Name
			Items   []provider.FleetTemplateVersion `xml:"launchTemplateVersionSet>item"`
		}
		if xml.Unmarshal(body, &response) != nil || response.XMLName.Local != "DescribeLaunchTemplateVersionsResponse" || len(response.Items) != 1 {
			t.Fatal("template page must contain exactly its selected native identity")
		}
		item := response.Items[0]
		if seen[item.ID] || selector.Get("Action") != "DescribeLaunchTemplateVersions" || selector.Get("Version") != "2016-11-15" || selector.Get("MaxResults") != "100" || selector.Get("ResolveAlias") != "false" || selector.Get("LaunchTemplateId") != item.ID || selector.Get("LaunchTemplateVersion.1") != strconv.FormatUint(item.Version, 10) || selector.Get("LaunchTemplateVersion.2") != "" || item.Data.InstanceType != "m6i.large" || item.Data.ImageID != nativeAssessmentImage || len(item.Data.BlockDevices) != 1 || item.Data.BlockDevices[0].EBS == nil {
			t.Fatal("template raw selectors/data differ from exact original/candidate pins")
		}
		seen[item.ID] = true
		decoded = append(decoded, item)
	}
	if len(seen) != 2 || !seen[oldID] || !seen[candidateID] || portfolio.Hash(decoded) != portfolio.Hash(evidence.Templates) {
		t.Fatal("complete raw native template pair differs from typed projection")
	}
	if _, err := reader.FleetTemplateVersions(context.Background(), "eu-west-1", nativeAssessmentAccount, []provider.FleetTemplateRequest{{ID: oldID, Version: 1}, {ID: oldID, Version: 2}}); err == nil {
		t.Fatal("legacy single-template selector pair must refuse")
	}
}

// HTTP problem documents are diagnostic-only and remain in private test logs.
// The request helper returns an ETag as its third result, never a raw body.
func commitmentDecisionStageQueueRefused(code string, status int, problem model.Document) error {
	raw, _ := json.Marshal(problem)
	if len(raw) > 4096 {
		raw = raw[:4096]
	}
	return fmt.Errorf("%s: http_status=%d problem=%s", code, status, raw)
}

type commitmentDecisionStageAssessmentSnapshot struct {
	snapshot fleetbilling.GroupNativeSnapshot
}

func (r commitmentDecisionStageAssessmentSnapshot) ResolveGroupNative(_ context.Context, tenant, old, candidate string) (fleetbilling.GroupNativeSnapshot, error) {
	if r.snapshot.Selection.Binding.Old.Target.TenantID != tenant || r.snapshot.Selection.OldProposal.ID != old || r.snapshot.Selection.CandidateProposal.ID != candidate {
		return fleetbilling.GroupNativeSnapshot{}, errors.New("DECISION_STAGE_DIAGNOSTIC_SELECTION_DIFFERS")
	}
	return r.snapshot, nil
}

// Repeats only private read/pure gates after a refused real worker attempt.
// It cannot append, change a guard, or turn the failed attempt into evidence.
func commitmentDecisionStageAssessmentDiagnostic(ctx context.Context, db *store.Store, tenant, id string, archive fleetbilling.PinnedReader) string {
	var request, snapshot model.Document
	if err := db.Do(ctx, tenant, func(tx *store.Tx) error {
		var err error
		request, err = tx.FleetNativeAssessmentGet(ctx, id)
		return err
	}); err != nil {
		return "REQUEST_READ_FAILED"
	}
	decode := func(v any, out any) bool {
		raw, err := json.Marshal(v)
		if err != nil || len(raw) > 32<<20 {
			return false
		}
		d := json.NewDecoder(bytes.NewReader(raw))
		d.DisallowUnknownFields()
		d.UseNumber()
		return d.Decode(out) == nil && d.Decode(new(any)) == io.EOF
	}
	var selection fleetassessment.Selection
	if !decode(request["selection"], &selection) {
		return "SELECTION_STRICT_DECODE_FAILED"
	}
	if err := db.Do(ctx, tenant, func(tx *store.Tx) error {
		var err error
		snapshot, err = tx.FleetNativeAssessmentSnapshot(ctx, id)
		return err
	}); err != nil {
		return fmt.Sprintf("SNAPSHOT_READ_FAILED: population_limit=%t selection_current=%t evidence_changed=%t", errors.Is(err, store.ErrFleetNativeBounds), errors.Is(err, store.ErrFleetNativeCurrent), errors.Is(err, store.ErrFleetNativeEvidence))
	}
	var typed fleetbilling.GroupNativeSnapshot
	if !decode(snapshot, &typed) {
		return "SNAPSHOT_STRICT_DECODE_OR_32MIB_LIMIT_FAILED"
	}
	if fleetbilling.Hash(typed) != fleetbilling.Hash(snapshot) || fleetbilling.Hash(typed.Selection) != fleetbilling.Hash(selection.Groups) {
		return "SNAPSHOT_TYPED_HASH_OR_SELECTION_DIFFERS"
	}
	broker := fleetbilling.GroupNativeBroker{Repository: commitmentDecisionStageAssessmentSnapshot{snapshot: typed}, Archive: archive}
	prices, err := broker.Capture(ctx, tenant, selection.Groups.OldProposal.ID, selection.Groups.CandidateProposal.ID)
	if err != nil {
		return "BROKER_CAPTURE_DEPENDENCY_FAILED"
	}
	var documents []model.Document
	if err := db.Do(ctx, tenant, func(tx *store.Tx) error {
		var err error
		documents, err = tx.FleetNativeAssessmentMembers(ctx, id, snapshot)
		return err
	}); err != nil {
		return "MEMBERS_READ_FAILED"
	}
	allowed := map[string]bool{}
	for _, member := range prices.CurrentMemberIDs {
		allowed[member] = true
	}
	members := []fleetassessment.MemberAssessment{}
	for _, document := range documents {
		var member fleetassessment.MemberAssessment
		if !decode(document, &member) {
			return "MEMBER_STRICT_DECODE_FAILED"
		}
		if allowed[member.InstanceID] {
			members = append(members, member)
		}
	}
	_, buildErr := fleetassessment.Build(selection, prices, members, time.Now().UTC())
	// Broker reason codes are fixed enums; never reflect an arbitrary source value.
	reasons := []string{}
	for _, reason := range prices.ReasonCodes {
		if len(reason) <= 128 && strings.IndexFunc(reason, func(r rune) bool { return r != '_' && (r < 'A' || r > 'Z') && (r < '0' || r > '9') }) == -1 {
			reasons = append(reasons, reason)
		}
		if len(reasons) == 8 {
			break
		}
	}
	return fmt.Sprintf("READ_ONLY_GATES: broker_unavailable=%t reasons=%v build_failed=%t billing_receipts=%d", prices.Status == "UNAVAILABLE", reasons, buildErr != nil, len(typed.Billing))
}

func commitmentDecisionIssueNativeStages(t *testing.T, ctx context.Context, f *mutationReplayFixture, admin *store.Store, sourceID, workloadID, resourceID, nativeID string, put func(context.Context, string, []byte) (model.Document, error), normalizerToken string) (commitmentDecisionNativeStages, error) {
	t.Helper()
	_, candidateTemplate, candidateVersion := commitmentDecisionStageTemplate(true)
	proof := commitmentDecisionNativeStages{SourceID: sourceID, WorkloadID: workloadID, ResourceID: resourceID, NativeID: nativeID, LaunchTemplateID: candidateTemplate, LaunchTemplateVersion: strconv.FormatUint(candidateVersion, 10), ImageID: nativeAssessmentImage, NativePins: []portfolio.Ref{}}
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
		templateAddress, _, _ := commitmentDecisionStageTemplate(index == 1)
		metadata := model.Document{"schema_version": "1", "authority": "TERRAFORM", "repository": model.Document{"url": "https://github.com/customer/stage-fixture.git", "ref": "main", "directory": "infra"}, "pipeline": model.Document{"system": "GITHUB_ACTIONS", "identity": model.Document{"issuer": "https://token.actions.githubusercontent.com", "audience": "finops-deployment-observer", "subject": "repo:customer/stage-fixture:ref:refs/heads/main", "pipeline_id": ".github/workflows/deploy.yml"}}, "terraform": model.Document{"workspace": "default", "state_lineage": "04000000-0000-4000-8000-000000000001", "asg_address": "aws_autoscaling_group." + []string{"original", "baseline"}[index], "launch_template_address": templateAddress, "traffic": model.Document{"listener_rule_address": "aws_lb_listener_rule.current", "target_group_addresses": []string{"aws_lb_target_group.original", "aws_lb_target_group.baseline"}}}}
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
	reader := commitmentDecisionStageFleetReader{tenant: f.tenant, oldName: oldName, candidateName: candidateName, oldARN: oldARN, candidateARN: candidateARN, instance: nativeID}
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
	httpClient := commitmentDecisionAnalyticsClient(t)
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
		// Only the separately selected private component diagnostic exercises an
		// additional exact HTTP replay; the original full native journey is intact.
		replayChecked := t.Name() == "TestCommitmentDecisionNativeStagesDiagnostic"
		if replayChecked {
			replayed, err := storage.WriteFacts(c, tenant, batchID, batch)
			if err != nil || source.Hash(replayed) != source.Hash(ref) {
				return nil, errors.New("DECISION_STAGE_EXACT_TELEMETRY_ANALYTICS_REPLAY_REQUIRED")
			}
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
		if replayChecked {
			t.Logf("PRIVATE_ANALYTICS_FULL_POPULATION_REPLAY_PASS: samples=%d actual_rows=%d", len(batch.Samples), count)
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
			return commitmentDecisionStageQueueRefused("DECISION_STAGE_CAPACITY_QUEUE_REFUSED", code, queued)
		}
		proof.CapacityRequestID = model.String(queued, "id")
		result, err := capacityWorker.Process(c, proof.CapacityRequestID)
		if err != nil {
			return fmt.Errorf("DECISION_STAGE_CAPACITY_PROCESS_FAILED: %w", err)
		}
		if result.Members != 1 {
			return fmt.Errorf("DECISION_STAGE_SINGLE_MEMBER_CAPACITY_NOT_ISSUED: members=%d", result.Members)
		}
		var members []model.Document
		if err := capacityDB.Do(c, f.tenant, func(tx *store.Tx) error {
			var err error
			members, err = tx.FleetCapacityBatchMemberPage(c, proof.CapacityRequestID, "", 2)
			return err
		}); err != nil {
			return fmt.Errorf("DECISION_STAGE_CAPACITY_MEMBER_READ_FAILED: %w", err)
		}
		if len(members) != 1 {
			return fmt.Errorf("DECISION_STAGE_COMPLETE_CAPACITY_MEMBER_REQUIRED: members=%d", len(members))
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
			return fmt.Errorf("DECISION_STAGE_ACTUAL_CURRENT_BASELINE_MODEL_REQUIRED: evaluated=%t input_kind=%s status=%s reasons=%v", member.ModelEvaluated, member.InputKind, member.Status, member.ReasonCodes)
		}
		for index, check := range member.ModelEvaluation.Candidates[0].Checks {
			if model.String(check, "status") != "PASS" {
				// This model-only diagnostic stays in the private test log. Public
				// acceptance receipts never reflect this nested response/error.
				raw, _ := json.Marshal(check)
				if len(raw) > 4096 {
					raw = raw[:4096]
				}
				return fmt.Errorf("DECISION_STAGE_CURRENT_BASELINE_PHYSICAL_CHECK_FAILED: check_index=%d check=%s", index, raw)
			}
		}
		code, assessment, _ := f.request("workloads/"+workloadID+"/fleet-native-assessments", version, "decision-native-assessment-"+model.ID(), finance, body)
		if code != 202 {
			return commitmentDecisionStageQueueRefused("DECISION_STAGE_ASSESSMENT_QUEUE_REFUSED", code, assessment)
		}
		proof.AssessmentRequestID = model.String(assessment, "id")
		if _, err := assessmentWorker.Process(c, proof.AssessmentRequestID); err != nil {
			return fmt.Errorf("DECISION_STAGE_ASSESSMENT_PROCESS_FAILED: %w diagnostic=%s", err, commitmentDecisionStageAssessmentDiagnostic(c, assessor, f.tenant, proof.AssessmentRequestID, pinned))
		}
		code, joint, _ := f.request("workloads/"+workloadID+"/fleet-joint-decisions", version, "decision-native-joint-"+model.ID(), finance, model.Document{"assessment_request_id": proof.AssessmentRequestID, "capacity_batch_request_id": proof.CapacityRequestID})
		if code != 202 {
			return commitmentDecisionStageQueueRefused("DECISION_STAGE_JOINT_QUEUE_REFUSED", code, joint)
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
