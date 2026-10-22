package source

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
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/fleet"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/provider"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestFleetReadFactoryRequiresExplicitTenantPayerMemberAndRegionBindings(t *testing.T) {
	r, _ := ParseRegistration(FixtureRegistration("tenant", "source"))
	r.UsageAccountIDs = append(r.UsageAccountIDs, "444455556666")
	bindings := map[string]AWSReadBinding{"fixture-payer": {TenantID: "tenant", PayerAccountID: r.PayerAccountID, AccountID: r.PayerAccountID, RoleARN: "arn:aws:iam::111122223333:role/read", ExternalID: strings.Repeat("x", 32), Region: "eu-west-1", MemberRoleBindings: map[string]string{"444455556666": "member"}}, "member": {TenantID: "tenant", PayerAccountID: r.PayerAccountID, AccountID: "444455556666", RoleARN: "arn:aws:iam::444455556666:role/read", ExternalID: strings.Repeat("y", 32), Region: "eu-west-1"}}
	encoded, _ := json.Marshal(bindings)
	parsed, e := ParseAWSBindings(string(encoded))
	if e != nil {
		t.Fatal(e)
	}
	if b, e := fleetReadBinding(parsed, r, "444455556666"); e != nil || b.AccountID != "444455556666" {
		t.Fatal("approved member unresolved", e)
	}
	for name, mutate := range map[string]func(*Registration, map[string]AWSReadBinding){"wrong tenant": func(r *Registration, b map[string]AWSReadBinding) { r.TenantID = "other" }, "wrong payer": func(r *Registration, b map[string]AWSReadBinding) { r.PayerAccountID = "999900001111" }, "unregistered member": func(r *Registration, b map[string]AWSReadBinding) { r.UsageAccountIDs = []string{r.PayerAccountID} }, "missing member role": func(r *Registration, b map[string]AWSReadBinding) { delete(b, "member") }, "wrong region": func(r *Registration, b map[string]AWSReadBinding) { r.Region = "us-east-1" }} {
		t.Run(name, func(t *testing.T) {
			copy := r
			raw, _ := json.Marshal(bindings)
			var b map[string]AWSReadBinding
			_ = json.Unmarshal(raw, &b)
			mutate(&copy, b)
			if _, e := fleetReadBinding(b, copy, "444455556666"); e == nil {
				t.Fatal("unapproved read binding selected")
			}
		})
	}
}

func TestFleetDiscoveryBindingsArePrivateExactReadScopes(t *testing.T) {
	p := sourceFleetPlan("tenant")
	b := map[string]FleetDiscoveryBinding{"approved": {SourceID: "source", Binding: p.Binding, OldASG: p.Old.ID, CandidateASG: p.Candidate.ID}}
	raw, _ := json.Marshal(b)
	if _, e := ParseFleetDiscoveryBindings(string(raw)); e != nil {
		t.Fatal(e)
	}
	for _, changed := range []string{strings.Replace(string(raw), `"eu-west-1"`, `"us-east-1"`, 1), strings.Replace(string(raw), `"old_asg":"asg-blue"`, `"old_asg":"different"`, 1), strings.Replace(string(raw), `"source_id":"source"`, `"source_id":"source","role_arn":"arn:aws:iam::111122223333:role/exec"`, 1), string(raw) + ` {}`} {
		if _, e := ParseFleetDiscoveryBindings(changed); e == nil {
			t.Fatal("invalid or credential-bearing discovery binding accepted")
		}
	}
}

func sourceFleetPlan(tenant string) fleet.Plan {
	return fleet.Plan{SchemaVersion: "4", Kind: fleet.Kind, ID: "parent", Binding: fleet.Binding{TenantID: tenant, ResourceID: "resource", WorkloadID: "workload", Provider: "AWS", ProviderResourceID: "asg-blue", AccountID: "111122223333", Region: "eu-west-1"}, Governance: fleet.Governance{RiskClass: "R2", ApproverRole: fleet.ApproverRole}, Old: fleet.Cohort{ID: "asg-blue", DesiredCount: 20, LaunchTemplateVersion: 1}, Candidate: fleet.Cohort{ID: "asg-green", LaunchTemplateVersion: 2}}
}
func nativeFleetGroup(p fleet.Plan, c fleet.Cohort, count int) provider.FleetGroup {
	minimum, desired, maximum := count, count, count
	disabled := false
	g := provider.FleetGroup{Name: c.ID, ARN: "arn:aws:autoscaling:eu-west-1:111122223333:autoScalingGroup:uuid:autoScalingGroupName/" + c.ID, Minimum: &minimum, Desired: &desired, Maximum: &maximum, LaunchTemplate: provider.FleetLaunchTemplate{ID: "lt-0123456789abcdef0", Version: fmt.Sprint(c.LaunchTemplateVersion)}, Zones: []string{"eu-west-1a", "eu-west-1b"}, Members: []provider.FleetMember{}, DesiredCapacityType: "units", CapacityRebalance: &disabled, NewInstancesProtectedFromScaleIn: &disabled}
	for _, s := range []string{"ReplaceUnhealthy", "AZRebalance", "InstanceRefresh", "ScheduledActions", "AlarmNotification"} {
		g.Suspended = append(g.Suspended, struct {
			Name string `xml:"ProcessName" json:"name"`
		}{s})
	}
	for key, value := range map[string]string{"finops:tenant": p.Binding.TenantID, "finops:environment": "NON_PRODUCTION", "finops:stateless": "true", "finops:fleet-rightsizing": "true", "finops:managed-by": "terraform"} {
		propagate := true
		g.Tags = append(g.Tags, provider.FleetTag{Key: key, Value: value, PropagateAtLaunch: &propagate})
	}
	sort.Slice(g.Tags, func(i, j int) bool { return g.Tags[i].Key < g.Tags[j].Key })
	for i := count; i > 0; i-- {
		g.Members = append(g.Members, provider.FleetMember{InstanceID: fmt.Sprintf("i-%017x", i), Zone: "eu-west-1a", Lifecycle: "InService", Health: "Healthy", LaunchTemplate: g.LaunchTemplate})
	}
	return g
}
func framedFleetEvidence(p fleet.Plan, groups []provider.FleetGroup, now time.Time) provider.FleetInventoryEvidence {
	sort.Slice(groups, func(i, j int) bool { return groups[i].Name < groups[j].Name })
	var response struct {
		XMLName xml.Name
		Result  struct {
			Groups []provider.FleetGroup `xml:"AutoScalingGroups>member"`
		} `xml:"DescribeAutoScalingGroupsResult"`
	}
	response.XMLName.Local = "DescribeAutoScalingGroupsResponse"
	response.Result.Groups = groups
	body, _ := xml.Marshal(response)
	v := url.Values{"Action": {"DescribeAutoScalingGroups"}, "Version": {"2011-01-01"}, "MaxRecords": {"100"}, "AutoScalingGroupNames.member.1": {"asg-blue"}, "AutoScalingGroupNames.member.2": {"asg-green"}}
	selector := v.Encode()
	var raw bytes.Buffer
	_ = binary.Write(&raw, binary.BigEndian, uint32(len(selector)))
	raw.WriteString(selector)
	_ = binary.Write(&raw, binary.BigEndian, uint64(len(body)))
	raw.Write(body)
	return provider.FleetInventoryEvidence{SchemaVersion: "1", Provider: "AWS", AccountID: p.Binding.AccountID, Region: p.Binding.Region, CollectedAt: now, RawSHA256: BytesHash(raw.Bytes()), Raw: raw.Bytes(), Groups: groups}
}
func TestFleetNativeRawBindingCountsAndControllerGuards(t *testing.T) {
	p := sourceFleetPlan("tenant")
	g := nativeFleetGroup(p, p.Old, 20)
	if ids, e := validateFleetGroup(g, p.Old, p.Binding, 20); e != nil || len(ids) != 20 || !sort.StringsAreSorted(ids) {
		t.Fatal("native members not sorted", e)
	}
	for name, mutate := range map[string]func(*provider.FleetGroup){"unknown counts": func(g *provider.FleetGroup) { g.Desired = nil }, "mixed controller": func(g *provider.FleetGroup) { g.MixedPolicy = &struct{}{} }, "unknown protection": func(g *provider.FleetGroup) { g.NewInstancesProtectedFromScaleIn = nil }, "unknown rebalance": func(g *provider.FleetGroup) { g.CapacityRebalance = nil }, "latest LT": func(g *provider.FleetGroup) { g.LaunchTemplate.Version = "$Latest" }, "member LT mismatch": func(g *provider.FleetGroup) { g.Members[0].LaunchTemplate.Version = "2" }, "not healthy": func(g *provider.FleetGroup) { g.Members[0].Health = "Unhealthy" }, "unknown lifecycle": func(g *provider.FleetGroup) { g.Members[0].Lifecycle = "" }, "duplicate member": func(g *provider.FleetGroup) { g.Members[0] = g.Members[1] }, "unsuspended replacement": func(g *provider.FleetGroup) { g.Suspended = g.Suspended[1:] }, "suspended launch": func(g *provider.FleetGroup) { g.Suspended[0].Name = "Launch" }, "nonpropagated tag": func(g *provider.FleetGroup) { no := false; g.Tags[0].PropagateAtLaunch = &no }, "duplicate tag": func(g *provider.FleetGroup) { g.Tags = append(g.Tags, g.Tags[0]) }, "count discrepancy": func(g *provider.FleetGroup) { g.Members = g.Members[:19] }} {
		t.Run(name, func(t *testing.T) {
			raw, _ := json.Marshal(g)
			var changed provider.FleetGroup
			_ = json.Unmarshal(raw, &changed)
			mutate(&changed)
			if _, e := validateFleetGroup(changed, p.Old, p.Binding, 20); e == nil {
				t.Fatal("unsafe native state accepted")
			}
		})
	}
	native := framedFleetEvidence(p, []provider.FleetGroup{g, nativeFleetGroup(p, p.Candidate, 0)}, time.Now().UTC())
	if _, e := fleetRawGroups(native, []string{p.Old.ID, p.Candidate.ID}); e != nil {
		t.Fatal(e)
	}
	native.Groups[0].Name = "different"
	if _, e := fleetRawGroups(native, []string{p.Old.ID, p.Candidate.ID}); e == nil {
		t.Fatal("typed groups not tied to raw pages")
	}
	native.RawSHA256 = strings.Repeat("0", 64)
	if _, e := fleetRawGroups(native, []string{p.Old.ID, p.Candidate.ID}); e == nil {
		t.Fatal("raw hash mismatch accepted")
	}
}

func TestFleetS3ArchivePinsVersionAndVerifiesReadback(t *testing.T) {
	for _, mode := range []string{"success", "no-version", "wrong-version", "altered-bytes"} {
		t.Run(mode, func(t *testing.T) {
			raw := []byte("exact native paginated response bytes")
			requests := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests++
				if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") {
					t.Error("archive request was not signed")
				}
				if !strings.HasPrefix(r.URL.Path, "/raw/tenant/tenant/fleet/parent/") {
					t.Error("archive tenant path lost")
				}
				if r.Method == "PUT" {
					body, _ := io.ReadAll(r.Body)
					if !bytes.Equal(body, raw) {
						t.Error("archive bytes changed")
					}
					if mode != "no-version" {
						w.Header().Set("X-Amz-Version-Id", "v1")
					}
					w.WriteHeader(200)
					return
				}
				if r.Method != "GET" || r.URL.Query().Get("versionId") != "v1" {
					t.Error("readback did not pin original version")
				}
				version := "v1"
				if mode == "wrong-version" {
					version = "v2"
				}
				w.Header().Set("X-Amz-Version-Id", version)
				if mode == "altered-bytes" {
					_, _ = w.Write([]byte("altered"))
				} else {
					_, _ = w.Write(raw)
				}
			}))
			defer server.Close()
			cfg := aws.Config{Region: "eu-west-1", Credentials: credentials.NewStaticCredentialsProvider("fixture", "fixture", ""), HTTPClient: server.Client()}
			client := s3.NewFromConfig(cfg, func(o *s3.Options) { o.BaseEndpoint = aws.String(server.URL); o.UsePathStyle = true })
			archive := FleetS3Archive{client, "raw"}
			ref, e := archive.Archive(context.Background(), "tenant", "parent", raw)
			if mode == "success" {
				if e != nil || requests != 2 || model.String(ref, "body_sha256") != BytesHash(raw) {
					t.Fatal("valid archive failed", e)
				}
			} else if e == nil {
				t.Fatal("unversioned or altered archive accepted")
			}
		})
	}
}

type fleetFixtureReader struct {
	evidence provider.FleetInventoryEvidence
}

func (r *fleetFixtureReader) FleetInventory(ctx context.Context, region, account string, names []string) (provider.FleetInventoryEvidence, error) {
	if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > 45*time.Second {
		return provider.FleetInventoryEvidence{}, errors.New("native reader has no bounded capture deadline")
	}
	if region != r.evidence.Region || account != r.evidence.AccountID || len(names) != 2 {
		return provider.FleetInventoryEvidence{}, errors.New("test requested wrong native scope")
	}
	return r.evidence, nil
}
func TestFleetMembershipFactoryPublishesOnlyAfterArchiveAndCurrentSource(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("disposable PostgreSQL required")
	}
	ctx := context.Background()
	admin, e := store.Open(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer admin.Pool.Close()
	if e = admin.Migrate(ctx, "../../migrations"); e != nil {
		t.Fatal(e)
	}
	cfg, e := pgxpool.ParseConfig(dsn)
	if e != nil {
		t.Fatal(e)
	}
	cfg.AfterConnect = func(ctx context.Context, c *pgx.Conn) error {
		_, e := c.Exec(ctx, "SET ROLE finops_ingester")
		return e
	}
	pool, e := pgxpool.NewWithConfig(ctx, cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer pool.Close()
	ingester := &store.Store{Pool: pool}
	for _, failure := range []string{"archive-failed", "archive-unversioned", "revoke-during-archive", "success", "discovery-blocked"} {
		t.Run(failure, func(t *testing.T) {
			tenant := "fleet-" + model.ID()
			registration := FixtureRegistration(tenant, "source")
			parent := sourceFleetPlan(tenant)
			now := time.Now().UTC()
			native := framedFleetEvidence(parent, []provider.FleetGroup{nativeFleetGroup(parent, parent.Old, 20), nativeFleetGroup(parent, parent.Candidate, 0)}, now)
			if failure == "discovery-blocked" {
				yes := true
				native.Groups[0].CapacityRebalance = &yes
				native = framedFleetEvidence(parent, native.Groups, now)
			}
			if e := admin.Do(ctx, tenant, func(tx *store.Tx) error {
				if _, e := tx.Exec(ctx, "SET LOCAL ROLE finops_api"); e != nil {
					return e
				}
				if _, e := tx.SourceCreate(ctx, registration); e != nil {
					return e
				}
				if failure == "discovery-blocked" {
					return nil
				}
				raw, _ := json.Marshal(parent)
				_, e := tx.Exec(ctx, "INSERT INTO fleet_plans(tenant_id,id,workload_id,content_hash,document) VALUES($1,$2,$3,$4,$5)", tenant, parent.ID, parent.Binding.WorkloadID, fleet.Digest(parent), raw)
				return e
			}); e != nil {
				t.Fatal(e)
			}
			archived := false
			pipeline := FleetPipeline{Store: ingester, Now: func() time.Time { return now }, ReaderFactory: func(_ context.Context, r Registration, account string) (FleetReader, error) {
				if r.TenantID != tenant || account != parent.Binding.AccountID {
					return nil, errors.New("reader credential binding escaped")
				}
				return &fleetFixtureReader{native}, nil
			}, Archive: func(_ context.Context, actualTenant, actualParent string, raw []byte) (model.Document, error) {
				if actualTenant != tenant || (actualParent != parent.ID && !(failure == "discovery-blocked" && strings.HasPrefix(actualParent, "discovery-"))) || !bytes.Equal(raw, native.Raw) {
					return nil, errors.New("archive scope or bytes changed")
				}
				if e := ingester.Do(ctx, tenant, func(tx *store.Tx) error {
					rs, e := tx.SourceReceiptList(ctx, "AWS_FLEET_MEMBERSHIP", "source")
					if e == nil && len(rs) != 0 {
						return errors.New("receipt published before archive")
					}
					return e
				}); e != nil {
					return nil, e
				}
				archived = true
				if failure == "archive-failed" {
					return nil, errors.New("fixture object unavailable")
				}
				version := "v1"
				if failure == "archive-unversioned" {
					version = "null"
				}
				if failure == "revoke-during-archive" {
					if e := admin.Do(ctx, tenant, func(tx *store.Tx) error {
						if _, e := tx.Exec(ctx, "SET LOCAL ROLE finops_api"); e != nil {
							return e
						}
						d, e := tx.SourceGet(ctx, "source")
						if e != nil {
							return e
						}
						d["enabled"] = false
						_, e = tx.SourceUpdate(ctx, "source", model.Number(d, "version"), d)
						return e
					}); e != nil {
						return nil, e
					}
				}
				return model.Document{"bucket": "raw", "key": "tenant/" + tenant + "/fleet/parent/raw.bin", "version_id": version, "body_sha256": BytesHash(raw)}, nil
			}}
			var result model.Document
			var err error
			if failure == "discovery-blocked" {
				pipeline.DiscoveryBindings = map[string]FleetDiscoveryBinding{"approved": {SourceID: "source", Binding: parent.Binding, OldASG: parent.Old.ID, CandidateASG: parent.Candidate.ID}}
				result, err = pipeline.Discover(ctx, tenant, "approved")
			} else {
				result, err = pipeline.Capture(ctx, tenant, "source", FleetCaptureTarget{ParentID: parent.ID, Position: "BASELINE"})
			}
			if !archived {
				t.Fatal("archive was not attempted")
			}
			if failure == "success" || failure == "discovery-blocked" {
				if err != nil || model.String(result, "kind") != "AWS_FLEET_MEMBERSHIP" || model.String(result, "writer_role") != "finops_ingester" || !sort.StringsAreSorted(model.Strings(result, "old_instance_ids")) {
					t.Fatal("trusted inventory receipt invalid", err, result)
				}
				if failure == "discovery-blocked" && (model.String(result, "position") != "DISCOVERY" || model.String(result, "status") != "OBSERVED_ONLY" || model.Bool(result, "execution_authorized") || len(model.Strings(result, "reason_codes")) == 0) {
					t.Fatal("read-only discovery promoted unsafe native state", result)
				}
			} else if err == nil {
				t.Fatal("failed or revoked capture published")
			}
			if e := ingester.Do(ctx, tenant, func(tx *store.Tx) error {
				rows, e := tx.SourceReceiptList(ctx, "AWS_FLEET_MEMBERSHIP", "source")
				if e != nil {
					return e
				}
				want := 0
				if failure == "success" || failure == "discovery-blocked" {
					want = 1
				}
				if len(rows) != want {
					return fmt.Errorf("receipt count=%d want=%d", len(rows), want)
				}
				billing, e := tx.SourceReceiptList(ctx, "AWS_CUR2", "source")
				if len(billing) != 0 {
					return errors.New("inventory became billing coverage")
				}
				if failure == "discovery-blocked" {
					var plans, children int
					if e := tx.QueryRow(ctx, "SELECT count(*) FROM fleet_plans WHERE tenant_id=$1", tenant).Scan(&plans); e != nil {
						return e
					}
					if e := tx.QueryRow(ctx, "SELECT count(*) FROM fleet_children WHERE tenant_id=$1", tenant).Scan(&children); e != nil {
						return e
					}
					if plans != 0 || children != 0 {
						return errors.New("discovery fabricated a parent or child")
					}
				}
				return e
			}); e != nil {
				t.Fatal(e)
			}
		})
	}
}
