//go:build commitment_decision_native_integration

package service

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/provider"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/source"
)

// Explicit deterministic signed-query RESPONSE transport. The production
// controller reparser repeats STS/account/pagination/member/group interpretation
// before real ingestion can issue a receipt. This is not a live AWS read.
type commitmentDecisionNativeControllerReader struct{ asgARN string }

func (r commitmentDecisionNativeControllerReader) ControllerDiscovery(ctx context.Context, region, account string, ids []string) (provider.ControllerDiscoveryEvidence, error) {
	var empty provider.ControllerDiscoveryEvidence
	if region != "eu-west-1" || account != nativeAssessmentAccount || len(ids) != 1 || ids[0] != decisionNativeID || !strings.Contains(r.asgARN, ":autoScalingGroupName/") {
		return empty, errors.New("DECISION_NATIVE_CONTROLLER_SCOPE")
	}
	started := time.Now().UTC()
	name := strings.SplitN(r.asgARN, ":autoScalingGroupName/", 2)[1]
	identity := `<GetCallerIdentityResponse><GetCallerIdentityResult><Account>` + account + `</Account><Arn>arn:aws:sts::` + account + `:assumed-role/fixture-controller-reader/finops-pilot</Arn><UserId>EXPLICIT_FIXTURE:finops-pilot</UserId></GetCallerIdentityResult></GetCallerIdentityResponse>`
	member := fmt.Sprintf(`<DescribeAutoScalingInstancesResponse><DescribeAutoScalingInstancesResult><AutoScalingInstances><member><InstanceId>%s</InstanceId><AutoScalingGroupName>%s</AutoScalingGroupName><AvailabilityZone>eu-west-1a</AvailabilityZone><LifecycleState>InService</LifecycleState><HealthStatus>Healthy</HealthStatus><ProtectedFromScaleIn>false</ProtectedFromScaleIn><LaunchTemplate><LaunchTemplateId>%s</LaunchTemplateId><Version>1</Version></LaunchTemplate></member></AutoScalingInstances></DescribeAutoScalingInstancesResult></DescribeAutoScalingInstancesResponse>`, ids[0], name, nativeAssessmentTemplate)
	group := fmt.Sprintf(`<DescribeAutoScalingGroupsResponse><DescribeAutoScalingGroupsResult><AutoScalingGroups><member><AutoScalingGroupName>%s</AutoScalingGroupName><AutoScalingGroupARN>%s</AutoScalingGroupARN><MinSize>1</MinSize><MaxSize>1</MaxSize><DesiredCapacity>1</DesiredCapacity><DesiredCapacityType>units</DesiredCapacityType><AvailabilityZones><member>eu-west-1a</member></AvailabilityZones><LaunchTemplate><LaunchTemplateId>%s</LaunchTemplateId><Version>1</Version></LaunchTemplate><Instances><member><InstanceId>%s</InstanceId><AvailabilityZone>eu-west-1a</AvailabilityZone><LifecycleState>InService</LifecycleState><HealthStatus>Healthy</HealthStatus><LaunchTemplate><LaunchTemplateId>%s</LaunchTemplateId><Version>1</Version></LaunchTemplate></member></Instances></member></AutoScalingGroups></DescribeAutoScalingGroupsResult></DescribeAutoScalingGroupsResponse>`, name, r.asgARN, nativeAssessmentTemplate, ids[0], nativeAssessmentTemplate)
	var parsed struct {
		Groups []provider.FleetGroup `xml:"DescribeAutoScalingGroupsResult>AutoScalingGroups>member"`
	}
	if xml.Unmarshal([]byte(group), &parsed) != nil || len(parsed.Groups) != 1 {
		return empty, errors.New("DECISION_NATIVE_CONTROLLER_XML")
	}
	raw := nativeAssessmentFrame(nativeAssessmentPage{url.Values{"Action": {"GetCallerIdentity"}, "Version": {"2011-06-15"}}, identity}, nativeAssessmentPage{url.Values{"Action": {"DescribeAutoScalingInstances"}, "Version": {"2011-01-01"}, "MaxRecords": {"50"}, "InstanceIds.member.1": {ids[0]}}, member}, nativeAssessmentPage{url.Values{"Action": {"DescribeAutoScalingGroups"}, "Version": {"2011-01-01"}, "MaxRecords": {"100"}, "IncludeInstances": {"true"}, "AutoScalingGroupNames.member.1": {name}}, group})
	zone, lifecycle, health, configuration := "eu-west-1a", "InService", "Healthy", ""
	protected := false
	template := parsed.Groups[0].Members[0].LaunchTemplate
	evidence := provider.ControllerDiscoveryEvidence{SchemaVersion: "1", Provider: "AWS", AccountID: account, Region: region, ObservationBasis: "BOUNDED_NON_ATOMIC_ASG_POINT_READ", StartedAt: started, CollectedAt: time.Now().UTC(), RegisteredInstanceIDs: append([]string{}, ids...), Memberships: []provider.ControllerMembership{{InstanceID: ids[0], Status: "ASG_MEMBER_OBSERVED", GroupName: &name, GroupARN: &r.asgARN, Zone: &zone, Lifecycle: &lifecycle, Health: &health, ProtectedFromScaleIn: &protected, LaunchTemplate: &template, LaunchConfigurationName: &configuration, RawPageSHA256: source.BytesHash([]byte(member)), ReasonCodes: []string{"OTHER_CONTROLLER_CLASSES_UNRESOLVED", "WARM_POOL_NOT_ENUMERATED"}}}, Groups: []provider.ControllerGroup{{Group: parsed.Groups[0], RawPageSHA256: source.BytesHash([]byte(group))}}, Callers: []provider.ControllerCaller{{AccountID: account, ARN: "arn:aws:sts::" + account + ":assumed-role/fixture-controller-reader/finops-pilot", UserID: "EXPLICIT_FIXTURE:finops-pilot", RawPageSHA256: source.BytesHash([]byte(identity))}}, UnsupportedControllerKinds: []string{"EKS", "ECS", "OTHER_CONTROLLERS"}, Raw: raw, RawSHA256: source.BytesHash(raw)}
	if err := provider.ValidateControllerDiscoveryEvidence(ctx, evidence, region, account, ids); err != nil {
		return empty, err
	}
	return evidence, nil
}

func commitmentDecisionNativeControllers(t *testing.T, ctx context.Context, f *mutationReplayFixture, asgARN string, put func(context.Context, string, []byte) (model.Document, error)) (func(context.Context) error, error) {
	t.Helper()
	const binding = "decision-native-controller"
	target := source.ControllerDiscoveryTarget{SourceID: decisionNativeSource, Binding: source.ControllerDiscoveryBinding{TenantID: f.tenant, WorkloadID: decisionNativeWorkload, Provider: "AWS", AccountID: nativeAssessmentAccount, Region: "eu-west-1"}, ResourceIDs: []string{decisionNativeResource}}
	pipeline := source.ControllerDiscoveryPipeline{Store: f.roles["ingester"], Bindings: map[string]source.ControllerDiscoveryTarget{binding: target}, ReaderFactory: func(context.Context, source.Registration, string) (source.ControllerDiscoveryReader, error) {
		return commitmentDecisionNativeControllerReader{asgARN: asgARN}, nil
	}, Archive: func(c context.Context, tenant, id string, raw []byte) (model.Document, error) {
		return put(c, "tenant/"+tenant+"/fleet/"+id+"/"+source.BytesHash(raw)+".bin", raw)
	}}
	if _, err := pipeline.Capture(ctx, f.tenant, binding); err != nil {
		return nil, err
	}
	return func(c context.Context) error { _, err := pipeline.CaptureIfDue(c, f.tenant, binding); return err }, nil
}
