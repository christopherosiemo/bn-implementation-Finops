package provider

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
)

const controllerFixtureAccount = "111122223333"
const controllerFixtureOne = "i-0123456789abcdef0"
const controllerFixtureTwo = "i-0123456789abcdef1"
const controllerFixtureAbsent = "i-0123456789abcdef2"

type controllerFixtureTransport func(*http.Request) (*http.Response, error)

func (f controllerFixtureTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type controllerFixtureCredentials struct {
	calls  int
	rotate bool
	failAt int
}

func (c *controllerFixtureCredentials) Retrieve(context.Context) (aws.Credentials, error) {
	c.calls++
	if c.failAt == c.calls {
		return aws.Credentials{}, errors.New("private diagnostic must not escape")
	}
	index := 1
	if c.rotate {
		index = c.calls
	}
	return aws.Credentials{AccessKeyID: fmt.Sprintf("offline-key-%d", index), SecretAccessKey: "offline-secret", SessionToken: fmt.Sprintf("offline-session-%d", index)}, nil
}

func controllerFixtureIdentity(account string) string {
	return `<GetCallerIdentityResponse><GetCallerIdentityResult><Account>` + account + `</Account><Arn>arn:aws:sts::` + account + `:assumed-role/registered-reader/session</Arn><UserId>OFFLINE:session</UserId></GetCallerIdentityResult></GetCallerIdentityResponse>`
}
func controllerFixtureInstance(id, group string) string {
	return `<member><InstanceId>` + id + `</InstanceId><AutoScalingGroupName>` + group + `</AutoScalingGroupName><AvailabilityZone>eu-west-1a</AvailabilityZone><HealthStatus>Healthy</HealthStatus><LifecycleState>InService</LifecycleState><ProtectedFromScaleIn>false</ProtectedFromScaleIn><LaunchTemplate><LaunchTemplateId>lt-0123456789abcdef0</LaunchTemplateId><Version>3</Version></LaunchTemplate></member>`
}
func controllerFixtureGroupMember(id string) string {
	return `<member><InstanceId>` + id + `</InstanceId><AvailabilityZone>eu-west-1a</AvailabilityZone><HealthStatus>Healthy</HealthStatus><LifecycleState>InService</LifecycleState><LaunchTemplate><LaunchTemplateId>lt-0123456789abcdef0</LaunchTemplateId><Version>3</Version></LaunchTemplate></member>`
}
func controllerFixtureGroup(name, account, members string) string {
	return `<member><AutoScalingGroupName>` + name + `</AutoScalingGroupName><AutoScalingGroupARN>arn:aws:autoscaling:eu-west-1:` + account + `:autoScalingGroup:fixture:autoScalingGroupName/` + name + `</AutoScalingGroupARN><MinSize>0</MinSize><DesiredCapacity>1</DesiredCapacity><MaxSize>3</MaxSize><AvailabilityZones><member>eu-west-1a</member></AvailabilityZones><Instances>` + members + `</Instances><MixedInstancesPolicy><InstancesDistribution><OnDemandPercentageAboveBaseCapacity>25</OnDemandPercentageAboveBaseCapacity></InstancesDistribution></MixedInstancesPolicy><UnprojectedNativeField>retained</UnprojectedNativeField></member>`
}
func controllerFixturePage(action, items, next string) string {
	collection := "AutoScalingInstances"
	if action == "DescribeAutoScalingGroups" {
		collection = "AutoScalingGroups"
	}
	if next != "" {
		next = "<NextToken>" + next + "</NextToken>"
	}
	return "<" + action + "Response><" + action + "Result><" + collection + ">" + items + "</" + collection + ">" + next + "</" + action + "Result></" + action + "Response>"
}
func controllerFixtureAWS(t *testing.T, c *controllerFixtureCredentials, respond func(string, url.Values) *http.Response) *AWS {
	t.Helper()
	lastIdentityKey := ""
	return &AWS{cfg: aws.Config{Region: "eu-west-1", Credentials: c}, client: &http.Client{Transport: controllerFixtureTransport(func(r *http.Request) (*http.Response, error) {
		if r.Method != "POST" || r.URL.Scheme != "https" || r.URL.Path != "/" || r.Header.Get("Accept-Encoding") != "identity" {
			t.Fatal("read transport changed")
		}
		body, e := io.ReadAll(r.Body)
		if e != nil {
			t.Fatal(e)
		}
		v, e := url.ParseQuery(string(body))
		if e != nil {
			t.Fatal(e)
		}
		action := v.Get("Action")
		service, version := "autoscaling", "2011-01-01"
		if action == "GetCallerIdentity" {
			service, version = "sts", "2011-06-15"
		} else if action != "DescribeAutoScalingInstances" && action != "DescribeAutoScalingGroups" {
			t.Fatal("unexpected or mutating action")
		}
		if r.URL.Host != service+".eu-west-1.amazonaws.com" || v.Get("Version") != version {
			t.Fatal("endpoint or query version changed")
		}
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 ") || !strings.Contains(auth, "/eu-west-1/"+service+"/aws4_request") || r.Header.Get("X-Amz-Security-Token") == "" {
			t.Fatal("native renewable signature missing")
		}
		key := strings.Split(strings.Split(auth, "Credential=")[1], "/")[0]
		if action == "GetCallerIdentity" {
			lastIdentityKey = key
		} else if lastIdentityKey != key {
			t.Fatal("ASG read used credentials not authenticated by STS")
		}
		return respond(action, v), nil
	})}}
}
func controllerFixtureResponse(body string) *http.Response {
	return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}
}

func TestControllerDiscoveryExactScopedPagesAndAbsence(t *testing.T) {
	c := &controllerFixtureCredentials{rotate: true}
	requests, identities := 0, 0
	a := controllerFixtureAWS(t, c, func(action string, v url.Values) *http.Response {
		if action == "GetCallerIdentity" {
			identities++
			return controllerFixtureResponse(controllerFixtureIdentity(controllerFixtureAccount))
		}
		requests++
		if action == "DescribeAutoScalingInstances" {
			if v.Get("InstanceIds.member.1") != controllerFixtureOne || v.Get("InstanceIds.member.2") != controllerFixtureTwo || v.Get("InstanceIds.member.3") != controllerFixtureAbsent || v.Get("MaxRecords") != "50" {
				t.Fatal("registered instance selectors changed")
			}
			if v.Get("NextToken") == "" {
				return controllerFixtureResponse(controllerFixturePage(action, controllerFixtureInstance(controllerFixtureOne, "blue"), "membership-2"))
			}
			return controllerFixtureResponse(controllerFixturePage(action, controllerFixtureInstance(controllerFixtureTwo, "green"), ""))
		}
		if v.Get("AutoScalingGroupNames.member.1") != "blue" || v.Get("AutoScalingGroupNames.member.2") != "green" || v.Get("IncludeInstances") != "true" || v.Get("MaxRecords") != "100" {
			t.Fatal("discovered group scope changed")
		}
		if v.Get("NextToken") == "" {
			return controllerFixtureResponse(controllerFixturePage(action, controllerFixtureGroup("blue", controllerFixtureAccount, controllerFixtureGroupMember(controllerFixtureOne)), "group-2"))
		}
		return controllerFixtureResponse(controllerFixturePage(action, controllerFixtureGroup("green", controllerFixtureAccount, controllerFixtureGroupMember(controllerFixtureTwo)), ""))
	})
	r, e := a.ControllerDiscovery(context.Background(), "eu-west-1", controllerFixtureAccount, []string{controllerFixtureAbsent, controllerFixtureTwo, controllerFixtureOne})
	if e != nil {
		t.Fatal(e)
	}
	if requests != 4 || identities != 4 || c.calls != 4 || len(r.Callers) != 4 || len(r.Groups) != 2 || len(r.Memberships) != 3 || r.Memberships[0].Status != "ASG_MEMBER_OBSERVED" || r.Memberships[2].Status != "NO_ASG_MEMBERSHIP_OBSERVED" || r.Memberships[2].GroupARN != nil || r.StartedAt.After(r.CollectedAt) || r.RawSHA256 != controllerSHA(r.Raw) {
		t.Fatal("complete scoped association or provenance lost")
	}
	frames := bytes.NewReader(r.Raw)
	count := 0
	for frames.Len() > 0 {
		var size uint32
		if binary.Read(frames, binary.BigEndian, &size) != nil {
			t.Fatal("bad selector frame")
		}
		selector := make([]byte, size)
		if _, e = io.ReadFull(frames, selector); e != nil {
			t.Fatal(e)
		}
		var length uint64
		if binary.Read(frames, binary.BigEndian, &length) != nil {
			t.Fatal("bad body frame")
		}
		body := make([]byte, length)
		if _, e = io.ReadFull(frames, body); e != nil {
			t.Fatal(e)
		}
		if !strings.Contains(string(selector), "Action=") || len(body) == 0 {
			t.Fatal("raw request scope missing")
		}
		count++
	}
	if count != 8 || !bytes.Contains(r.Raw, []byte("UnprojectedNativeField")) || bytes.Contains(r.Raw, []byte("offline-secret")) || bytes.Contains(r.Raw, []byte("offline-session")) {
		t.Fatal("complete native records or secret separation lost")
	}
	wire, e := json.Marshal(r)
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Contains(wire, []byte(`"unsupported_controller_kinds":["EKS","ECS","OTHER_CONTROLLERS"]`)) || bytes.Contains(wire, []byte(`"unmanaged"`)) || bytes.Contains(wire, []byte(`"complete":true`)) {
		t.Fatal("absence promoted to broader controller authority")
	}
}

func TestControllerDiscoveryEmptyAuthenticatedAssociationDoesNotEnumerateGroups(t *testing.T) {
	calls := 0
	c := &controllerFixtureCredentials{}
	a := controllerFixtureAWS(t, c, func(action string, v url.Values) *http.Response {
		calls++
		if action == "GetCallerIdentity" {
			return controllerFixtureResponse(controllerFixtureIdentity(controllerFixtureAccount))
		}
		if action != "DescribeAutoScalingInstances" {
			t.Fatal("empty name list became account-wide group enumeration")
		}
		return controllerFixtureResponse(controllerFixturePage(action, "", ""))
	})
	r, e := a.ControllerDiscovery(context.Background(), "eu-west-1", controllerFixtureAccount, []string{controllerFixtureOne})
	if e != nil || calls != 2 || len(r.Groups) != 0 || r.Memberships[0].Status != "NO_ASG_MEMBERSHIP_OBSERVED" || r.Memberships[0].ReasonCodes[0] != "EC2_EXISTENCE_NOT_PROVEN_BY_ASG_QUERY" {
		t.Fatal("bounded absence not explicit", e)
	}
}

func TestControllerDiscoveryBatchesRegisteredIDsAtFifty(t *testing.T) {
	ids := []string{}
	for i := 0; i < 51; i++ {
		ids = append(ids, fmt.Sprintf("i-%017x", i+1))
	}
	pages, sts := 0, 0
	a := controllerFixtureAWS(t, &controllerFixtureCredentials{}, func(action string, v url.Values) *http.Response {
		if action == "GetCallerIdentity" {
			sts++
			return controllerFixtureResponse(controllerFixtureIdentity(controllerFixtureAccount))
		}
		pages++
		if v.Get("InstanceIds.member.1") == "" || v.Get("InstanceIds.member.51") != "" {
			t.Fatal("unbounded or missing selectors")
		}
		return controllerFixtureResponse(controllerFixturePage(action, "", ""))
	})
	r, e := a.ControllerDiscovery(context.Background(), "eu-west-1", controllerFixtureAccount, ids)
	if e != nil || pages != 2 || sts != 1 || len(r.Memberships) != 51 {
		t.Fatal("registered batching or credential-local identity cache failed", e)
	}
}

func TestControllerDiscoveryFailsClosedOnNativeConflicts(t *testing.T) {
	for _, kind := range []string{"wrong-account", "missing-result", "missing-collection", "duplicate-result", "unexpected-collection-item", "duplicate-member", "unregistered-member", "missing-protection", "wrong-zone", "member-cycle", "missing-group", "wrong-group-account", "duplicate-group", "group-cycle", "moved-member", "absent-now-in-group", "different-template"} {
		t.Run(kind, func(t *testing.T) {
			a := controllerFixtureAWS(t, &controllerFixtureCredentials{}, func(action string, v url.Values) *http.Response {
				if action == "GetCallerIdentity" {
					account := controllerFixtureAccount
					if kind == "wrong-account" {
						account = "999900001111"
					}
					return controllerFixtureResponse(controllerFixtureIdentity(account))
				}
				items := controllerFixtureInstance(controllerFixtureOne, "blue")
				next := ""
				if action == "DescribeAutoScalingInstances" {
					switch kind {
					case "missing-result":
						return controllerFixtureResponse(`<DescribeAutoScalingInstancesResponse/>`)
					case "missing-collection":
						return controllerFixtureResponse(`<DescribeAutoScalingInstancesResponse><DescribeAutoScalingInstancesResult/></DescribeAutoScalingInstancesResponse>`)
					case "duplicate-result":
						return controllerFixtureResponse(`<DescribeAutoScalingInstancesResponse><DescribeAutoScalingInstancesResult><AutoScalingInstances/></DescribeAutoScalingInstancesResult><DescribeAutoScalingInstancesResult><AutoScalingInstances/></DescribeAutoScalingInstancesResult></DescribeAutoScalingInstancesResponse>`)
					case "unexpected-collection-item":
						items = `<wrong/>`
					case "duplicate-member":
						items += items
					case "unregistered-member":
						items = controllerFixtureInstance(controllerFixtureTwo, "blue")
					case "missing-protection":
						items = strings.Replace(items, "<ProtectedFromScaleIn>false</ProtectedFromScaleIn>", "", 1)
					case "wrong-zone":
						items = strings.ReplaceAll(items, "eu-west-1a", "us-east-1a")
					case "member-cycle":
						items = ""
						next = "cycle"
					}
					return controllerFixtureResponse(controllerFixturePage(action, items, next))
				}
				members := controllerFixtureGroupMember(controllerFixtureOne)
				account := controllerFixtureAccount
				switch kind {
				case "missing-group":
					members = ""
				case "wrong-group-account":
					account = "999900001111"
				case "moved-member":
					members = ""
				case "absent-now-in-group":
					members += controllerFixtureGroupMember(controllerFixtureAbsent)
				case "different-template":
					members = strings.ReplaceAll(members, "<Version>3</Version>", "<Version>4</Version>")
				}
				items = controllerFixtureGroup("blue", account, members)
				if kind == "missing-group" {
					items = ""
				}
				if kind == "duplicate-group" {
					items += items
				}
				if kind == "group-cycle" {
					items = ""
					next = "cycle"
				}
				return controllerFixtureResponse(controllerFixturePage(action, items, next))
			})
			r, e := a.ControllerDiscovery(context.Background(), "eu-west-1", controllerFixtureAccount, []string{controllerFixtureOne, controllerFixtureAbsent})
			if e == nil || r.Raw != nil || r.Memberships != nil {
				t.Fatal("partial or conflicting evidence escaped")
			}
		})
	}
}

type controllerNeverRead struct{ calls int }

func (r *controllerNeverRead) Read([]byte) (int, error) {
	r.calls++
	return 0, errors.New("should not read oversized declared body")
}
func (r *controllerNeverRead) Close() error { return nil }

func TestControllerDiscoveryBudgetsAndTransportRefusals(t *testing.T) {
	for _, kind := range []string{"redirect", "encoded", "declared-oversize", "provider-error", "page-budget", "credential-failure", "canceled"} {
		t.Run(kind, func(t *testing.T) {
			c := &controllerFixtureCredentials{}
			if kind == "credential-failure" {
				c.failAt = 2
			}
			calls := 0
			reader := &controllerNeverRead{}
			a := controllerFixtureAWS(t, c, func(action string, v url.Values) *http.Response {
				if action == "GetCallerIdentity" {
					return controllerFixtureResponse(controllerFixtureIdentity(controllerFixtureAccount))
				}
				calls++
				r := controllerFixtureResponse(controllerFixturePage(action, "", ""))
				switch kind {
				case "redirect":
					r.StatusCode = 302
					r.Header.Set("Location", "https://elsewhere.invalid/")
				case "encoded":
					r.Header.Set("Content-Encoding", "gzip")
				case "declared-oversize":
					r.ContentLength = controllerPageLimit + 1
					r.Body = reader
				case "provider-error":
					r.StatusCode = 403
				case "page-budget":
					r = controllerFixtureResponse(controllerFixturePage(action, "", fmt.Sprintf("page-%d", calls)))
				case "credential-failure":
					r = controllerFixtureResponse(controllerFixturePage(action, "", "next"))
				}
				return r
			})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if kind == "canceled" {
				cancel()
			}
			r, e := a.ControllerDiscovery(ctx, "eu-west-1", controllerFixtureAccount, []string{controllerFixtureOne})
			if e == nil || r.Raw != nil || reader.calls != 0 || calls > controllerReadLimit || strings.Contains(e.Error(), "private diagnostic") {
				t.Fatal("unsafe failure, pagination or transport budget")
			}
			if kind == "page-budget" && calls != controllerReadLimit {
				t.Fatal("global page budget changed")
			}
		})
	}
}

func TestControllerDiscoveryRejectsInvalidScopeBeforeAnyRead(t *testing.T) {
	a := controllerFixtureAWS(t, &controllerFixtureCredentials{}, func(string, url.Values) *http.Response { t.Fatal("invalid scope dispatched"); return nil })
	for _, scope := range []struct {
		region, account string
		ids             []string
	}{{"us-east-1", controllerFixtureAccount, []string{controllerFixtureOne}}, {"eu-west-1", "bad", []string{controllerFixtureOne}}, {"eu-west-1", controllerFixtureAccount, nil}, {"eu-west-1", controllerFixtureAccount, []string{controllerFixtureOne, controllerFixtureOne}}, {"eu-west-1", controllerFixtureAccount, []string{"i-not-native"}}, {"eu-west-1", controllerFixtureAccount, make([]string, 257)}} {
		if _, e := a.ControllerDiscovery(context.Background(), scope.region, scope.account, scope.ids); e == nil {
			t.Fatal("invalid native scope accepted")
		}
	}
}
