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
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// PRIVATE_GUARD_COMPONENT: actual restricted ingester Capture/CaptureIfDue,
// source revisions and receipts, and actual SQL currentness reader. AWS XML
// and immutable object transport are explicit local doubles. No native cloud,
// optimization outcome, historical ownership or purchase acceptance is claimed.
const decisionControllerRenewalNativeID = "i-0c040000000000001"

type decisionControllerRenewalReader struct {
	asgARN  string
	calls   int
	maximum int
	grace   int
}

func (r *decisionControllerRenewalReader) ControllerDiscovery(ctx context.Context, region, account string, ids []string) (provider.ControllerDiscoveryEvidence, error) {
	var empty provider.ControllerDiscoveryEvidence
	if region != "eu-west-1" || account != nativeAssessmentAccount || len(ids) != 1 || ids[0] != decisionControllerRenewalNativeID || !strings.Contains(r.asgARN, ":autoScalingGroupName/") {
		return empty, errors.New("DECISION_NATIVE_CONTROLLER_SCOPE")
	}
	r.calls++
	started := time.Now().UTC()
	name := strings.SplitN(r.asgARN, ":autoScalingGroupName/", 2)[1]
	identity := `<GetCallerIdentityResponse><GetCallerIdentityResult><Account>` + account + `</Account><Arn>arn:aws:sts::` + account + `:assumed-role/fixture-controller-reader/finops-pilot</Arn><UserId>EXPLICIT_FIXTURE:finops-pilot</UserId></GetCallerIdentityResult></GetCallerIdentityResponse>`
	member := fmt.Sprintf(`<DescribeAutoScalingInstancesResponse><DescribeAutoScalingInstancesResult><AutoScalingInstances><member><InstanceId>%s</InstanceId><AutoScalingGroupName>%s</AutoScalingGroupName><AvailabilityZone>eu-west-1a</AvailabilityZone><LifecycleState>InService</LifecycleState><HealthStatus>Healthy</HealthStatus><ProtectedFromScaleIn>false</ProtectedFromScaleIn><LaunchTemplate><LaunchTemplateId>%s</LaunchTemplateId><Version>1</Version></LaunchTemplate></member></AutoScalingInstances></DescribeAutoScalingInstancesResult></DescribeAutoScalingInstancesResponse>`, ids[0], name, nativeAssessmentTemplate)
	group := fmt.Sprintf(`<DescribeAutoScalingGroupsResponse><DescribeAutoScalingGroupsResult><AutoScalingGroups><member><AutoScalingGroupName>%s</AutoScalingGroupName><AutoScalingGroupARN>%s</AutoScalingGroupARN><MinSize>1</MinSize><MaxSize>1</MaxSize><DesiredCapacity>1</DesiredCapacity><DesiredCapacityType>units</DesiredCapacityType><AvailabilityZones><member>eu-west-1a</member></AvailabilityZones><LaunchTemplate><LaunchTemplateId>%s</LaunchTemplateId><Version>1</Version></LaunchTemplate><Instances><member><InstanceId>%s</InstanceId><AvailabilityZone>eu-west-1a</AvailabilityZone><LifecycleState>InService</LifecycleState><HealthStatus>Healthy</HealthStatus><LaunchTemplate><LaunchTemplateId>%s</LaunchTemplateId><Version>1</Version></LaunchTemplate></member></Instances></member></AutoScalingGroups></DescribeAutoScalingGroupsResult></DescribeAutoScalingGroupsResponse>`, name, r.asgARN, nativeAssessmentTemplate, ids[0], nativeAssessmentTemplate)
	identity = strings.Replace(identity, "</GetCallerIdentityResponse>", fmt.Sprintf("<ResponseMetadata><RequestId>identity-%d</RequestId></ResponseMetadata></GetCallerIdentityResponse>", r.calls), 1)
	group = strings.Replace(group, "<MaxSize>1</MaxSize>", fmt.Sprintf("<MaxSize>%d</MaxSize>", r.maximum), 1)
	if r.grace != 0 {
		group = strings.Replace(group, "<MinSize>1</MinSize>", fmt.Sprintf("<MinSize>1</MinSize><HealthCheckGracePeriod>%d</HealthCheckGracePeriod>", r.grace), 1)
	}
	group = strings.Replace(group, "</DescribeAutoScalingGroupsResponse>", fmt.Sprintf("<ResponseMetadata><RequestId>group-%d</RequestId></ResponseMetadata></DescribeAutoScalingGroupsResponse>", r.calls), 1)
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

// One temporary EXECUTE grant exists only inside the operator-owned child
// transaction, then rolls back. Actual SESSION_USER/OID, analyst role and
// tenant binding remain those of the commissioned dedicated login. Public
// production policy/currentness paths gain no grant from this test.
func decisionControllerRenewalGuard(t *testing.T, ctx context.Context, admin, analyst *store.Store, tenant, sourceID, workload string, scope, policy, ref model.Document, mutate func(*store.Tx) error) (model.Document, error) {
	t.Helper()
	const signature = "public.commitment_controller_current(text,text,text,jsonb,jsonb,jsonb)"
	login := analyst.Pool.Config().ConnConfig.User
	var acl string
	var executable bool
	if admin.Pool.QueryRow(ctx, "SELECT coalesce(proacl::text,''),has_function_privilege($1,oid,'EXECUTE') FROM pg_proc WHERE oid=$2::regprocedure", login, signature).Scan(&acl, &executable) != nil || executable {
		t.Fatal("controller private helper ACL was already widened")
	}
	var expectedOID uint32
	if admin.Pool.QueryRow(ctx, "SELECT r.oid FROM pg_roles r JOIN commitment_portfolio_credentials c ON c.database_login=r.rolname AND c.role_oid=r.oid WHERE r.rolname=$1 AND c.tenant_id=$2", login, tenant).Scan(&expectedOID) != nil {
		t.Fatal("controller commissioned login/OID missing")
	}
	tx, e := admin.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback(context.Background())
	if _, e = tx.Exec(ctx, "SELECT set_config('app.tenant_id',$1,true)", tenant); e != nil {
		t.Fatal(e)
	}
	if mutate != nil {
		if _, e = tx.Exec(ctx, "SET LOCAL ROLE finops_api"); e != nil {
			t.Fatal(e)
		}
		if e = mutate(&store.Tx{Tx: tx, Tenant: tenant}); e != nil {
			t.Fatal("controller component mutation failed", e)
		}
		if _, e = tx.Exec(ctx, "RESET ROLE"); e != nil {
			t.Fatal(e)
		}
	}
	if _, e = tx.Exec(ctx, "GRANT EXECUTE ON FUNCTION "+signature+" TO finops_commitment_portfolio"); e != nil {
		t.Fatal(e)
	}
	if _, e = tx.Exec(ctx, "SET LOCAL SESSION AUTHORIZATION "+pgx.Identifier{login}.Sanitize()); e != nil {
		t.Fatal(e)
	}
	if _, e = tx.Exec(ctx, "SET LOCAL ROLE finops_commitment_portfolio"); e != nil {
		t.Fatal(e)
	}
	var session, role string
	var actualOID uint32
	var scoped bool
	if tx.QueryRow(ctx, "SELECT session_user,current_user,(SELECT oid FROM pg_roles WHERE rolname=session_user),public.commitment_portfolio_scope($1)", tenant).Scan(&session, &role, &actualOID, &scoped) != nil || session != login || role != "finops_commitment_portfolio" || actualOID != expectedOID || !scoped {
		t.Fatal("controller helper identity/OID/scope differs")
	}
	var raw []byte
	var original any
	if ref != nil {
		original = decision040JSON(t, ref)
	}
	readError := tx.QueryRow(ctx, "SELECT public.commitment_controller_current($1,$2,$3,$4::jsonb,$5::jsonb,$6::jsonb)", tenant, sourceID, workload, decision040JSON(t, scope), decision040JSON(t, policy), original).Scan(&raw)
	if e = tx.Rollback(ctx); e != nil {
		t.Fatal("controller private grant rollback failed", e)
	}
	var after string
	if admin.Pool.QueryRow(ctx, "SELECT coalesce(proacl::text,''),has_function_privilege($1,oid,'EXECUTE') FROM pg_proc WHERE oid=$2::regprocedure", login, signature).Scan(&after, &executable) != nil || after != acl || executable {
		t.Fatal("controller private helper ACL did not return to original denial")
	}
	value := model.Document{}
	if readError == nil {
		decision040Decode(t, raw, &value)
	}
	return value, readError
}

func TestCommitmentDecision040ControllerRoutineRenewal(t *testing.T) {
	f, admin, _, _ := newFleetNativeHTTPTest(t)
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	if e := admin.Migrate(ctx, "../../migrations"); e != nil {
		t.Fatal("controller component migrations failed", e)
	}
	analyst := commitmentPortfolioNativeRuntime(t, ctx, admin, f.tenant)
	const workload = "controller-renewal-component"
	const resource = "controller-renewal-resource"
	const sourceID = "controller-renewal-source"
	const bindingID = "controller-renewal-binding"
	registration := source.FixtureRegistration(f.tenant, sourceID)
	if e := f.roles["api"].Do(ctx, f.tenant, func(tx *store.Tx) error {
		if _, e := tx.Create(ctx, "workloads", model.Document{"id": workload, "owner": "component-owner", "environment": "NON_PRODUCTION"}); e != nil {
			return e
		}
		if _, e := tx.Create(ctx, "resources", model.Document{"id": resource, "resource_type": "EC2", "workload_id": workload, "provider": "AWS", "provider_resource_id": decisionControllerRenewalNativeID, "account_id": nativeAssessmentAccount, "region": "eu-west-1"}); e != nil {
			return e
		}
		_, e := tx.SourceCreate(ctx, registration)
		return e
	}); e != nil {
		t.Fatal("controller component registered scope failed", e)
	}
	// Explicit component source-health double; no billing/native-CUR claim.
	if e := f.roles["ingester"].Do(ctx, f.tenant, func(tx *store.Tx) error {
		return tx.SourceCheckpointSet(ctx, sourceID, "status", model.Document{"status": "HEALTHY", "config_hash": source.ConfigurationHash(registration), "last_sync_at": time.Now().UTC().Format(time.RFC3339Nano)})
	}); e != nil {
		t.Fatal(e)
	}
	asg := "arn:aws:autoscaling:eu-west-1:" + nativeAssessmentAccount + ":autoScalingGroup:component:autoScalingGroupName/fixed-one"
	reader := &decisionControllerRenewalReader{asgARN: asg, maximum: 1}
	target := source.ControllerDiscoveryTarget{SourceID: sourceID, Binding: source.ControllerDiscoveryBinding{TenantID: f.tenant, WorkloadID: workload, Provider: "AWS", AccountID: nativeAssessmentAccount, Region: "eu-west-1"}, ResourceIDs: []string{resource}}
	versions := 0
	pipeline := source.ControllerDiscoveryPipeline{Store: f.roles["ingester"], Bindings: map[string]source.ControllerDiscoveryTarget{bindingID: target}, ReaderFactory: func(context.Context, source.Registration, string) (source.ControllerDiscoveryReader, error) {
		return reader, nil
	}, Archive: func(_ context.Context, tenant, binding string, raw []byte) (model.Document, error) {
		versions++
		back := append([]byte{}, raw...)
		if source.BytesHash(back) != source.BytesHash(raw) {
			return nil, errors.New("component readback changed")
		}
		return model.Document{"bucket": "explicit-component-double", "key": "tenant/" + tenant + "/fleet/" + binding + "/controller.bin", "version_id": fmt.Sprintf("actual-double-version-%d", versions), "body_sha256": source.BytesHash(back)}, nil
	}}
	first, e := pipeline.CaptureIfDue(ctx, f.tenant, bindingID)
	if e != nil || reader.calls != 1 {
		t.Fatal("initial ordinary controller capture failed", e)
	}
	scope := model.Document{"resource_ids": []string{decisionControllerRenewalNativeID}}
	policy := model.Document{"account_id": nativeAssessmentAccount, "region": "eu-west-1", "asg_arn": asg}
	assertDenied := func() {
		t.Helper()
		e := analyst.Do(ctx, f.tenant, func(tx *store.Tx) error {
			_, e := tx.Exec(ctx, "SELECT public.commitment_controller_current($1,$2,$3,$4::jsonb,$5::jsonb,NULL)", f.tenant, sourceID, workload, decision040JSON(t, scope), decision040JSON(t, policy))
			return e
		})
		var pg *pgconn.PgError
		if !errors.As(e, &pg) || pg.Code != "42501" {
			t.Fatal("analyst directly executed owner-only controller currentness helper", e)
		}
	}
	assertDenied()
	selected, e := decisionControllerRenewalGuard(t, ctx, admin, analyst, f.tenant, sourceID, workload, scope, policy, nil, nil)
	if e != nil {
		t.Fatal("actual initial issued controller guard failed", e)
	}
	proof := source.Object(selected["proof"])
	original := source.Object(proof["original_ref"])
	if model.String(original, "id") != model.String(first, "id") {
		t.Fatal("initial guard selected unrelated evidence")
	}
	unchanged, e := pipeline.CaptureIfDue(ctx, f.tenant, bindingID)
	if e != nil || reader.calls != 1 || model.String(unchanged, "id") != model.String(first, "id") {
		t.Fatal("routine tick replaced a still-valid snapshot", e)
	}
	collected, e := time.Parse(time.RFC3339Nano, model.String(first, "collected_at"))
	if e != nil {
		t.Fatal(e)
	}
	wait := time.Until(collected.Add(90*time.Second + 100*time.Millisecond))
	if wait > 0 {
		timer := time.NewTimer(wait)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			t.Fatal("actual controller renewal wait exceeded component bound")
		case <-timer.C:
		}
	}
	renewed, e := pipeline.CaptureIfDue(ctx, f.tenant, bindingID)
	if e != nil || reader.calls != 2 || model.String(renewed, "id") == model.String(first, "id") {
		t.Fatal("ordinary actual ninety-second renewal did not reissue", e)
	}
	if source.Hash(first["raw_object"]) == source.Hash(renewed["raw_object"]) {
		t.Fatal("transport provenance did not vary in the renewal control")
	}
	if model.String(first, "controller_graph_sha256") == "" || model.String(first, "controller_graph_sha256") != model.String(renewed, "controller_graph_sha256") {
		t.Fatal("complete native graph was not retained across transport-only renewal")
	}
	selected, e = decisionControllerRenewalGuard(t, ctx, admin, analyst, f.tenant, sourceID, workload, scope, policy, original, nil)
	if e != nil {
		t.Fatal("same parsed native graph did not survive actual routine renewal", e)
	}
	proof = source.Object(selected["proof"])
	if source.Hash(proof["original_ref"]) != source.Hash(original) || model.String(source.Object(proof["latest_ref"]), "id") != model.String(renewed, "id") {
		t.Fatal("renewal rewrote original reference or skipped current evidence")
	}
	assertDenied()
	cases := []struct {
		name   string
		mutate func(*store.Tx) error
	}{
		{"roster-version", func(tx *store.Tx) error {
			r, e := tx.Get(ctx, "resources", resource)
			if e != nil {
				return e
			}
			r["name"] = "changed current inventory"
			_, e = tx.Update(ctx, "resources", resource, model.Number(r, "version"), r)
			return e
		}},
		{"source-version", func(tx *store.Tx) error {
			r, e := tx.SourceGet(ctx, sourceID)
			if e != nil {
				return e
			}
			_, e = tx.SourceUpdate(ctx, sourceID, model.Number(r, "version"), r)
			return e
		}},
		{"source-config", func(tx *store.Tx) error {
			r, e := tx.SourceGet(ctx, sourceID)
			if e != nil {
				return e
			}
			r["prefix"] = "other-approved-prefix/"
			_, e = tx.SourceUpdate(ctx, sourceID, model.Number(r, "version"), r)
			return e
		}},
		{"source-revoked", func(tx *store.Tx) error {
			r, e := tx.SourceGet(ctx, sourceID)
			if e != nil {
				return e
			}
			r["revoked"] = true
			_, e = tx.SourceUpdate(ctx, sourceID, model.Number(r, "version"), r)
			return e
		}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			_, e := decisionControllerRenewalGuard(t, ctx, admin, analyst, f.tenant, sourceID, workload, scope, policy, original, test.mutate)
			var pg *pgconn.PgError
			if !errors.As(e, &pg) || pg.Code != "P0001" {
				t.Fatal("changed current scope did not refuse", e)
			}
		})
	}
	reader.grace = 301
	if _, e = pipeline.Capture(ctx, f.tenant, bindingID); e != nil {
		t.Fatal("unprojected native configuration acquisition failed", e)
	}
	_, e = decisionControllerRenewalGuard(t, ctx, admin, analyst, f.tenant, sourceID, workload, scope, policy, original, nil)
	decision040ExpectedSQL(t, e, "optimization controller observation changed")
	reader.grace = 0
	if _, e = pipeline.Capture(ctx, f.tenant, bindingID); e != nil {
		t.Fatal("restored native configuration acquisition failed", e)
	}
	if _, e = decisionControllerRenewalGuard(t, ctx, admin, analyst, f.tenant, sourceID, workload, scope, policy, original, nil); e != nil {
		t.Fatal("identical real graph could not regain currentness", e)
	}
	reader.maximum = 2
	if _, e = pipeline.Capture(ctx, f.tenant, bindingID); e != nil {
		t.Fatal("changed native configuration acquisition failed", e)
	}
	_, e = decisionControllerRenewalGuard(t, ctx, admin, analyst, f.tenant, sourceID, workload, scope, policy, original, nil)
	decision040ExpectedSQL(t, e, "optimization controller observation changed")
	t.Log("PRIVATE_GUARD_COMPONENT actual routine90s renewal PASS; immutable original ref retained; source/config/roster/native change refusal; no public publisher or native authority claim")
}
