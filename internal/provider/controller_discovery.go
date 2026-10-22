package provider

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

const (
	controllerRawLimit  = 32 << 20
	controllerPageLimit = 16 << 20
	controllerReadLimit = 100
)

// ControllerDiscoveryEvidence is a bounded point-read of ASG associations only.
// Neither absence here nor group min=max=desired establishes that EKS, ECS or
// another controller is absent, or grants configuration/execution authority.
// Raw contains the fleet.go length-framed exact selectors and complete XML
// responses, including signed STS identity responses. Authorization headers and
// credentials are never retained. A publisher must archive/reparse these bytes.
type ControllerDiscoveryEvidence struct {
	SchemaVersion              string                 `json:"schema_version"`
	Provider                   string                 `json:"provider"`
	AccountID                  string                 `json:"account_id"`
	Region                     string                 `json:"region"`
	ObservationBasis           string                 `json:"observation_basis"`
	StartedAt                  time.Time              `json:"started_at"`
	CollectedAt                time.Time              `json:"collected_at"`
	RegisteredInstanceIDs      []string               `json:"registered_instance_ids"`
	Memberships                []ControllerMembership `json:"memberships"`
	Groups                     []ControllerGroup      `json:"groups"`
	Callers                    []ControllerCaller     `json:"callers"`
	UnsupportedControllerKinds []string               `json:"unsupported_controller_kinds"`
	RawSHA256                  string                 `json:"raw_sha256"`
	Raw                        []byte                 `json:"-"`
}

type ControllerCaller struct {
	AccountID     string `json:"account_id"`
	ARN           string `json:"arn"`
	UserID        string `json:"user_id"`
	RawPageSHA256 string `json:"raw_page_sha256"`
}

type ControllerMembership struct {
	InstanceID              string               `json:"instance_id"`
	Status                  string               `json:"status"` // ASG_MEMBER_OBSERVED | NO_ASG_MEMBERSHIP_OBSERVED
	GroupName               *string              `json:"group_name"`
	GroupARN                *string              `json:"group_arn"`
	Zone                    *string              `json:"zone"`
	Lifecycle               *string              `json:"lifecycle"`
	Health                  *string              `json:"health"`
	ProtectedFromScaleIn    *bool                `json:"protected_from_scale_in"`
	LaunchTemplate          *FleetLaunchTemplate `json:"launch_template"`
	LaunchConfigurationName *string              `json:"launch_configuration_name"`
	RawPageSHA256           string               `json:"raw_page_sha256"`
	ReasonCodes             []string             `json:"reason_codes"`
}

// Group is the existing fleet projection; the complete native record, including
// fields outside that projection, remains in its hash-pinned raw XML page.
// DescribeAutoScalingGroups does not enumerate warm-pool instances.
type ControllerGroup struct {
	Group         FleetGroup `json:"group"`
	RawPageSHA256 string     `json:"raw_page_sha256"`
}

type controllerInstance struct {
	ID            string              `xml:"InstanceId"`
	Group         string              `xml:"AutoScalingGroupName"`
	Zone          string              `xml:"AvailabilityZone"`
	Lifecycle     string              `xml:"LifecycleState"`
	Health        string              `xml:"HealthStatus"`
	Protected     *bool               `xml:"ProtectedFromScaleIn"`
	Template      FleetLaunchTemplate `xml:"LaunchTemplate"`
	Configuration string              `xml:"LaunchConfigurationName"`
}

type controllerRead struct {
	a                     *AWS
	region, account, role string
	raw                   bytes.Buffer
	reads                 int
	bound                 map[[32]byte]bool
	callers               []ControllerCaller
}

func controllerSHA(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func controllerZone(zone, region string) bool {
	if !strings.HasPrefix(zone, region) || len(zone) <= len(region) || len(zone) > 255 {
		return false
	}
	for _, c := range zone[len(region):] {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return zone[len(region)] == '-' || zone[len(region)] >= 'a' && zone[len(region)] <= 'z'
}

func (r *controllerRead) retain(values url.Values, body []byte) error {
	selector := values.Encode()
	if len(selector) > 64<<10 || r.raw.Len()+12+len(selector)+len(body) > controllerRawLimit {
		return errors.New("CONTROLLER_DISCOVERY_RAW_LIMIT")
	}
	_ = binary.Write(&r.raw, binary.BigEndian, uint32(len(selector)))
	r.raw.WriteString(selector)
	_ = binary.Write(&r.raw, binary.BigEndian, uint64(len(body)))
	r.raw.Write(body)
	return nil
}

// Same renewable-credential SigV4 and no-redirect read transport as fleetRead.
// This separate helper is needed because fleetRead fixes its action and obtains
// credentials internally; here STS and the ASG request must use the SAME snapshot.
func (r *controllerRead) signed(ctx context.Context, service string, values url.Values, credentials aws.Credentials, limit int64) ([]byte, error) {
	selector := values.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+service+"."+r.region+".amazonaws.com/", strings.NewReader(selector))
	if err != nil {
		return nil, errors.New("CONTROLLER_DISCOVERY_REQUEST_INVALID")
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept-Encoding", "identity")
	if err = v4.NewSigner().SignHTTP(ctx, credentials, request, controllerSHA([]byte(selector)), service, r.region, time.Now()); err != nil {
		return nil, errors.New("CONTROLLER_DISCOVERY_SIGNING_UNAVAILABLE")
	}
	client := *r.a.client
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := client.Do(request)
	if err != nil {
		return nil, errors.New("CONTROLLER_DISCOVERY_READ_UNAVAILABLE")
	}
	defer response.Body.Close()
	if encoding := response.Header.Get("Content-Encoding"); encoding != "" && encoding != "identity" {
		return nil, errors.New("CONTROLLER_DISCOVERY_ENCODING_UNSUPPORTED")
	}
	remaining := int64(controllerRawLimit - r.raw.Len() - 12 - len(selector))
	if remaining < limit {
		limit = remaining
	}
	if limit < 0 || response.ContentLength > limit {
		return nil, errors.New("CONTROLLER_DISCOVERY_RAW_LIMIT")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil || int64(len(body)) > limit {
		return nil, errors.New("CONTROLLER_DISCOVERY_RAW_LIMIT")
	}
	if response.StatusCode != http.StatusOK {
		return nil, &QueryRejection{Action: values.Get("Action"), Code: "ProviderRejected", StatusCode: response.StatusCode}
	}
	return body, nil
}

func (r *controllerRead) read(ctx context.Context, action string, values url.Values) ([]byte, error) {
	if ctx.Err() != nil {
		return nil, errors.New("CONTROLLER_DISCOVERY_READ_UNAVAILABLE")
	}
	if r.reads >= controllerReadLimit {
		return nil, errors.New("CONTROLLER_DISCOVERY_PAGE_LIMIT")
	}
	r.reads++
	if action != "DescribeAutoScalingInstances" && action != "DescribeAutoScalingGroups" {
		return nil, errors.New("CONTROLLER_DISCOVERY_ACTION_INVALID")
	}
	credentials, err := r.a.cfg.Credentials.Retrieve(ctx)
	if err != nil || credentials.AccessKeyID == "" || credentials.SecretAccessKey == "" {
		return nil, errors.New("CONTROLLER_DISCOVERY_IDENTITY_UNAVAILABLE")
	}
	// Internal only: no credential-derived fingerprint is exposed or archived.
	key := sha256.Sum256([]byte(credentials.AccessKeyID + "\x00" + credentials.SecretAccessKey + "\x00" + credentials.SessionToken))
	if !r.bound[key] {
		identitySelector := url.Values{"Action": {"GetCallerIdentity"}, "Version": {"2011-06-15"}}
		body, e := r.signed(ctx, "sts", identitySelector, credentials, 64<<10)
		if e != nil {
			return nil, e
		}
		var identity struct {
			Result struct {
				Account string `xml:"Account"`
				ARN     string `xml:"Arn"`
				UserID  string `xml:"UserId"`
			} `xml:"GetCallerIdentityResult"`
		}
		if controllerXML(body, "GetCallerIdentityResponse", "GetCallerIdentityResult", "", &identity) != nil || identity.Result.Account != r.account || !strings.HasPrefix(identity.Result.ARN, "arn:aws:sts::"+r.account+":assumed-role/") || len(identity.Result.ARN) > 2048 || identity.Result.UserID == "" || len(identity.Result.UserID) > 256 {
			return nil, errors.New("CONTROLLER_DISCOVERY_ACCOUNT_BINDING_MISMATCH")
		}
		slash := strings.LastIndexByte(identity.Result.ARN, '/')
		prefix := "arn:aws:sts::" + r.account + ":assumed-role/"
		if slash <= len(prefix) || slash == len(identity.Result.ARN)-1 {
			return nil, errors.New("CONTROLLER_DISCOVERY_ACCOUNT_BINDING_MISMATCH")
		}
		role := identity.Result.ARN[:slash]
		if r.role != "" && r.role != role {
			return nil, errors.New("CONTROLLER_DISCOVERY_ROLE_CHANGED")
		}
		r.role = role
		if e = r.retain(identitySelector, body); e != nil {
			return nil, e
		}
		r.callers = append(r.callers, ControllerCaller{r.account, identity.Result.ARN, identity.Result.UserID, controllerSHA(body)})
		r.bound[key] = true
	}
	values.Set("Action", action)
	values.Set("Version", "2011-01-01")
	body, err := r.signed(ctx, "autoscaling", values, credentials, controllerPageLimit)
	if err != nil {
		return nil, err
	}
	if err = r.retain(values, body); err != nil {
		return nil, err
	}
	return body, nil
}

// Require the actual result and collection containers before interpreting an
// empty page as absence. Duplicate singleton elements and XML directives fail.
func controllerXML(body []byte, root, result, collection string, out any) error {
	d := xml.NewDecoder(bytes.NewReader(body))
	path := []string{}
	counts := map[string]int{}
	fields := map[int]map[string]bool{}
	for {
		token, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return errors.New("CONTROLLER_DISCOVERY_XML_INVALID")
		}
		switch t := token.(type) {
		case xml.StartElement:
			path = append(path, t.Name.Local)
			if len(path) > 64 {
				return errors.New("CONTROLLER_DISCOVERY_XML_INVALID")
			}
			key := strings.Join(path, "/")
			if len(path) == 1 && t.Name.Local != root {
				return errors.New("CONTROLLER_DISCOVERY_XML_INVALID")
			}
			if collection != "" && len(path) == 4 && path[2] == collection && t.Name.Local != "member" {
				return errors.New("CONTROLLER_DISCOVERY_XML_INVALID")
			}
			if len(path) == 4 && path[2] == collection && t.Name.Local == "member" || collection == "AutoScalingGroups" && len(path) == 6 && path[4] == "Instances" && t.Name.Local == "member" {
				fields[len(path)] = map[string]bool{}
			}
			if seen := fields[len(path)-1]; seen != nil {
				if seen[t.Name.Local] {
					return errors.New("CONTROLLER_DISCOVERY_XML_INVALID")
				}
				seen[t.Name.Local] = true
			}
			if key == root || key == root+"/"+result || collection != "" && key == root+"/"+result+"/"+collection || key == root+"/"+result+"/NextToken" || collection == "" && len(path) == 3 {
				counts[key]++
				if counts[key] > 1 {
					return errors.New("CONTROLLER_DISCOVERY_XML_INVALID")
				}
			}
		case xml.EndElement:
			delete(fields, len(path))
			path = path[:len(path)-1]
		case xml.CharData:
			if len(path) == 0 && strings.TrimSpace(string(t)) != "" {
				return errors.New("CONTROLLER_DISCOVERY_XML_INVALID")
			}
		case xml.Directive:
			return errors.New("CONTROLLER_DISCOVERY_XML_INVALID")
		}
	}
	if counts[root] != 1 || counts[root+"/"+result] != 1 || collection != "" && counts[root+"/"+result+"/"+collection] != 1 {
		return errors.New("CONTROLLER_DISCOVERY_XML_INVALID")
	}
	return xml.Unmarshal(body, out)
}

// ControllerDiscovery never enumerates an unregistered account fleet. AWS
// silently omits nonexistent IDs, so NO_ASG_MEMBERSHIP_OBSERVED does not prove
// EC2 existence or absence of another controller. Successful pages are not an
// atomic snapshot; inconsistent association/group reads fail closed.
// API contracts: docs.aws.amazon.com/autoscaling/ec2/APIReference/
// API_DescribeAutoScalingInstances.html and API_DescribeAutoScalingGroups.html.
func (a *AWS) ControllerDiscovery(ctx context.Context, region, account string, instanceIDs []string) (ControllerDiscoveryEvidence, error) {
	var zero ControllerDiscoveryEvidence
	if a == nil || a.client == nil || a.cfg.Credentials == nil || region != "eu-west-1" || !fleetAccount.MatchString(account) || len(instanceIDs) < 1 || len(instanceIDs) > 256 {
		return zero, errors.New("CONTROLLER_DISCOVERY_SCOPE_INVALID")
	}
	ids := append([]string{}, instanceIDs...)
	sort.Strings(ids)
	for i, id := range ids {
		if !fleetInstance.MatchString(id) || i > 0 && id == ids[i-1] {
			return zero, errors.New("CONTROLLER_DISCOVERY_SCOPE_INVALID")
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	r := controllerRead{a: a, region: region, account: account, bound: map[[32]byte]bool{}, callers: []ControllerCaller{}}
	out := ControllerDiscoveryEvidence{SchemaVersion: "1", Provider: "AWS", AccountID: account, Region: region, ObservationBasis: "BOUNDED_NON_ATOMIC_ASG_POINT_READ", StartedAt: time.Now().UTC(), RegisteredInstanceIDs: ids, Memberships: []ControllerMembership{}, Groups: []ControllerGroup{}, UnsupportedControllerKinds: []string{"EKS", "ECS", "OTHER_CONTROLLERS"}}
	found := map[string]controllerInstance{}
	memberPages := map[string]string{}
	absentPages := map[string]string{}
	names := map[string]bool{}
	for start := 0; start < len(ids); start += 50 {
		end := start + 50
		if end > len(ids) {
			end = len(ids)
		}
		wanted := map[string]bool{}
		values := url.Values{"MaxRecords": {"50"}}
		for i, id := range ids[start:end] {
			wanted[id] = true
			values.Set(fmt.Sprintf("InstanceIds.member.%d", i+1), id)
		}
		tokens := map[string]bool{}
		for {
			body, err := r.read(ctx, "DescribeAutoScalingInstances", values)
			if err != nil {
				return zero, err
			}
			var response struct {
				Result struct {
					Items []controllerInstance `xml:"AutoScalingInstances>member"`
					Next  string               `xml:"NextToken"`
				} `xml:"DescribeAutoScalingInstancesResult"`
			}
			if controllerXML(body, "DescribeAutoScalingInstancesResponse", "DescribeAutoScalingInstancesResult", "AutoScalingInstances", &response) != nil {
				return zero, errors.New("CONTROLLER_DISCOVERY_MEMBERSHIP_INVALID")
			}
			for _, m := range response.Result.Items {
				if !wanted[m.ID] || found[m.ID].ID != "" || !fleetGroupName.MatchString(m.Group) || !controllerZone(m.Zone, region) || m.Health == "" || len(m.Health) > 32 || m.Lifecycle == "" || len(m.Lifecycle) > 64 || m.Protected == nil || len(m.Configuration) > 255 {
					return zero, errors.New("CONTROLLER_DISCOVERY_MEMBERSHIP_INVALID")
				}
				found[m.ID] = m
				memberPages[m.ID] = controllerSHA(body)
				names[m.Group] = true
			}
			if response.Result.Next == "" {
				// The final page hash is a locator, not a completeness assertion:
				// reparse the entire framed request chain to authenticate absence.
				for id := range wanted {
					if found[id].ID == "" {
						absentPages[id] = controllerSHA(body)
					}
				}
				break
			}
			if len(response.Result.Next) > 2048 || tokens[response.Result.Next] {
				return zero, errors.New("CONTROLLER_DISCOVERY_PAGINATION_CONFLICT")
			}
			tokens[response.Result.Next] = true
			values.Set("NextToken", response.Result.Next)
		}
	}
	orderedNames := []string{}
	for name := range names {
		orderedNames = append(orderedNames, name)
	}
	sort.Strings(orderedNames)
	groups := map[string]FleetGroup{}
	groupMembers := map[string]string{}
	memberCount := 0
	for start := 0; start < len(orderedNames); start += 50 {
		end := start + 50
		if end > len(orderedNames) {
			end = len(orderedNames)
		}
		wanted := map[string]bool{}
		values := url.Values{"MaxRecords": {"100"}, "IncludeInstances": {"true"}}
		for i, name := range orderedNames[start:end] {
			wanted[name] = true
			values.Set(fmt.Sprintf("AutoScalingGroupNames.member.%d", i+1), name)
		}
		tokens := map[string]bool{}
		for {
			body, err := r.read(ctx, "DescribeAutoScalingGroups", values)
			if err != nil {
				return zero, err
			}
			var response struct {
				Result struct {
					Items []FleetGroup `xml:"AutoScalingGroups>member"`
					Next  string       `xml:"NextToken"`
				} `xml:"DescribeAutoScalingGroupsResult"`
			}
			if controllerXML(body, "DescribeAutoScalingGroupsResponse", "DescribeAutoScalingGroupsResult", "AutoScalingGroups", &response) != nil {
				return zero, errors.New("CONTROLLER_DISCOVERY_GROUP_INVALID")
			}
			for _, g := range response.Result.Items {
				prefix := "arn:aws:autoscaling:" + region + ":" + account + ":autoScalingGroup:"
				if !wanted[g.Name] || groups[g.Name].Name != "" || !strings.HasPrefix(g.ARN, prefix) || !strings.HasSuffix(g.ARN, ":autoScalingGroupName/"+g.Name) || g.Minimum == nil || g.Desired == nil || g.Maximum == nil || *g.Minimum < 0 || *g.Desired < *g.Minimum || *g.Maximum < *g.Desired || len(g.Zones) == 0 {
					return zero, errors.New("CONTROLLER_DISCOVERY_GROUP_INVALID")
				}
				zones := map[string]bool{}
				for _, zone := range g.Zones {
					if !controllerZone(zone, region) || zones[zone] {
						return zero, errors.New("CONTROLLER_DISCOVERY_GROUP_INVALID")
					}
					zones[zone] = true
				}
				for _, m := range g.Members {
					memberCount++
					if memberCount > 100000 || !fleetInstance.MatchString(m.InstanceID) || groupMembers[m.InstanceID] != "" || !zones[m.Zone] || m.Health == "" || m.Lifecycle == "" {
						return zero, errors.New("CONTROLLER_DISCOVERY_GROUP_INVALID")
					}
					groupMembers[m.InstanceID] = g.Name
				}
				if g.Members == nil {
					g.Members = []FleetMember{}
				}
				groups[g.Name] = g
				out.Groups = append(out.Groups, ControllerGroup{g, controllerSHA(body)})
			}
			if response.Result.Next == "" {
				for name := range wanted {
					if groups[name].Name == "" {
						return zero, errors.New("CONTROLLER_DISCOVERY_GROUP_NOT_OBSERVED")
					}
				}
				break
			}
			if len(response.Result.Next) > 2048 || tokens[response.Result.Next] {
				return zero, errors.New("CONTROLLER_DISCOVERY_PAGINATION_CONFLICT")
			}
			tokens[response.Result.Next] = true
			values.Set("NextToken", response.Result.Next)
		}
	}
	for _, id := range ids {
		m, ok := found[id]
		if !ok {
			if groupMembers[id] != "" {
				return zero, errors.New("CONTROLLER_DISCOVERY_POINT_CONFLICT")
			}
			out.Memberships = append(out.Memberships, ControllerMembership{InstanceID: id, Status: "NO_ASG_MEMBERSHIP_OBSERVED", RawPageSHA256: absentPages[id], ReasonCodes: []string{"EC2_EXISTENCE_NOT_PROVEN_BY_ASG_QUERY", "OTHER_CONTROLLER_CLASSES_UNRESOLVED"}})
			continue
		}
		if groupMembers[id] != m.Group {
			return zero, errors.New("CONTROLLER_DISCOVERY_POINT_CONFLICT")
		}
		for _, gm := range groups[m.Group].Members {
			if gm.InstanceID == id && (gm.Zone != m.Zone || gm.Health != m.Health || gm.Lifecycle != m.Lifecycle || gm.LaunchTemplate != m.Template) {
				return zero, errors.New("CONTROLLER_DISCOVERY_POINT_CONFLICT")
			}
		}
		g := groups[m.Group]
		out.Memberships = append(out.Memberships, ControllerMembership{InstanceID: id, Status: "ASG_MEMBER_OBSERVED", GroupName: &m.Group, GroupARN: &g.ARN, Zone: &m.Zone, Lifecycle: &m.Lifecycle, Health: &m.Health, ProtectedFromScaleIn: m.Protected, LaunchTemplate: &m.Template, LaunchConfigurationName: &m.Configuration, RawPageSHA256: memberPages[id], ReasonCodes: []string{"OTHER_CONTROLLER_CLASSES_UNRESOLVED", "WARM_POOL_NOT_ENUMERATED"}})
	}
	sort.Slice(out.Groups, func(i, j int) bool { return out.Groups[i].Group.Name < out.Groups[j].Group.Name })
	out.Callers = r.callers
	out.Raw = append([]byte{}, r.raw.Bytes()...)
	out.RawSHA256 = controllerSHA(out.Raw)
	out.CollectedAt = time.Now().UTC()
	if ctx.Err() != nil {
		return zero, errors.New("CONTROLLER_DISCOVERY_READ_UNAVAILABLE")
	}
	return out, nil
}
