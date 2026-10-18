package source

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/fleet"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/provider"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/jackc/pgx/v5"
)

type FleetReader interface {
	FleetInventory(context.Context, string, string, []string) (provider.FleetInventoryEvidence, error)
}
type FleetCaptureTarget struct{ ParentID, ChildID, Position string }
type FleetPipeline struct {
	DiscoveryBindings map[string]FleetDiscoveryBinding
	Store             *store.Store
	ReaderFactory     func(context.Context, Registration, string) (FleetReader, error)
	Archive           func(context.Context, string, string, []byte) (model.Document, error)
	Now               func() time.Time
}

// FleetAWSFactory resolves credentials exclusively from the ingester's approved
// configuration. Neither the parent nor the registration supplies a role ARN.
func FleetAWSFactory(encoded string) (func(context.Context, Registration, string) (FleetReader, error), error) {
	bindings, e := ParseAWSBindings(encoded)
	if e != nil {
		return nil, e
	}
	return func(ctx context.Context, r Registration, account string) (FleetReader, error) {
		b, e := fleetReadBinding(bindings, r, account)
		if e != nil {
			return nil, e
		}
		return provider.NewAWS(ctx, b.Region, b.RoleARN, b.ExternalID)
	}, nil
}
func fleetReadBinding(bindings map[string]AWSReadBinding, r Registration, account string) (AWSReadBinding, error) {
	b, ok := bindings[r.ReadRoleBindingID]
	approved := account == r.PayerAccountID
	for _, id := range r.UsageAccountIDs {
		approved = approved || id == account
	}
	if !ok || !approved || b.TenantID != r.TenantID || b.PayerAccountID != r.PayerAccountID || b.Region != r.Region {
		return AWSReadBinding{}, errors.New("FLEET_READ_BINDING_NOT_CONFIGURED")
	}
	if b.AccountID != account {
		id := b.MemberRoleBindings[account]
		b, ok = bindings[id]
	}
	if !ok || b.TenantID != r.TenantID || b.PayerAccountID != r.PayerAccountID || b.AccountID != account || b.Region != "eu-west-1" {
		return AWSReadBinding{}, errors.New("FLEET_READ_BINDING_NOT_CONFIGURED")
	}
	return b, nil
}

var fleetObjectPart = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
var fleetTemplateID = regexp.MustCompile(`^lt-(?:[a-f0-9]{8}|[a-f0-9]{17})$`)
var fleetInstanceID = regexp.MustCompile(`^i-(?:[a-f0-9]{8}|[a-f0-9]{17})$`)

func fleetRawGroups(e provider.FleetInventoryEvidence, names []string) ([]provider.FleetGroup, error) {
	if len(e.Raw) == 0 || len(e.Raw) > 32<<20 || BytesHash(e.Raw) != e.RawSHA256 {
		return nil, errors.New("FLEET_NATIVE_RAW_HASH_MISMATCH")
	}
	r := bytes.NewReader(e.Raw)
	groups := []provider.FleetGroup{}
	next := ""
	pages := 0
	for r.Len() > 0 {
		var selectorLength uint32
		if binary.Read(r, binary.BigEndian, &selectorLength) != nil || selectorLength == 0 || selectorLength > 65536 || uint64(selectorLength) > uint64(r.Len()) {
			return nil, errors.New("FLEET_NATIVE_RAW_INVALID")
		}
		selector := make([]byte, selectorLength)
		_, _ = io.ReadFull(r, selector)
		v, err := url.ParseQuery(string(selector))
		if err != nil || v.Get("Action") != "DescribeAutoScalingGroups" || v.Get("Version") != "2011-01-01" || v.Get("MaxRecords") != "100" || v.Get("NextToken") != next {
			return nil, errors.New("FLEET_NATIVE_SELECTOR_MISMATCH")
		}
		ordered := append([]string{}, names...)
		sort.Strings(ordered)
		for i, name := range ordered {
			if v.Get("AutoScalingGroupNames.member."+strconv.Itoa(i+1)) != name {
				return nil, errors.New("FLEET_NATIVE_SELECTOR_MISMATCH")
			}
		}
		for key, values := range v {
			if len(values) != 1 {
				return nil, errors.New("FLEET_NATIVE_SELECTOR_MISMATCH")
			}
			if key != "Action" && key != "Version" && key != "MaxRecords" && key != "NextToken" && key != "AutoScalingGroupNames.member.1" && key != "AutoScalingGroupNames.member.2" {
				return nil, errors.New("FLEET_NATIVE_SELECTOR_MISMATCH")
			}
		}
		var size uint64
		if binary.Read(r, binary.BigEndian, &size) != nil || size == 0 || size > 16<<20 || size > uint64(r.Len()) {
			return nil, errors.New("FLEET_NATIVE_RAW_INVALID")
		}
		body := make([]byte, int(size))
		_, _ = io.ReadFull(r, body)
		var response struct {
			XMLName xml.Name
			Result  struct {
				Groups []provider.FleetGroup `xml:"AutoScalingGroups>member"`
				Next   string                `xml:"NextToken"`
			} `xml:"DescribeAutoScalingGroupsResult"`
		}
		if xml.Unmarshal(body, &response) != nil || response.XMLName.Local != "DescribeAutoScalingGroupsResponse" {
			return nil, errors.New("FLEET_NATIVE_RAW_INVALID")
		}
		for _, g := range response.Result.Groups {
			if g.Members == nil {
				g.Members = []provider.FleetMember{}
			}
			groups = append(groups, g)
		}
		next = response.Result.Next
		pages++
		if pages > 100 || next == "" && r.Len() > 0 {
			return nil, errors.New("FLEET_NATIVE_RAW_INVALID")
		}
	}
	if pages == 0 || next != "" {
		return nil, errors.New("FLEET_NATIVE_RAW_INVALID")
	}
	sort.Slice(groups, func(i, j int) bool { return groups[i].Name < groups[j].Name })
	if Hash(groups) != Hash(e.Groups) {
		return nil, errors.New("FLEET_NATIVE_TYPED_RAW_MISMATCH")
	}
	return groups, nil
}
func validateFleetGroup(g provider.FleetGroup, c fleet.Cohort, b fleet.Binding, expected int) ([]string, error) {
	prefix := "arn:aws:autoscaling:" + b.Region + ":" + b.AccountID + ":autoScalingGroup:"
	if g.Name != c.ID || !strings.HasPrefix(g.ARN, prefix) || !strings.HasSuffix(g.ARN, ":autoScalingGroupName/"+g.Name) || g.Minimum == nil || g.Desired == nil || g.Maximum == nil || *g.Minimum != expected || *g.Desired != expected || *g.Maximum != expected || len(g.Members) != expected || expected < 0 || expected > 256 {
		return nil, errors.New("FLEET_NATIVE_COUNTS_OR_BINDING_MISMATCH")
	}
	version, e := strconv.ParseUint(g.LaunchTemplate.Version, 10, 64)
	if e != nil || version != c.LaunchTemplateVersion || !fleetTemplateID.MatchString(g.LaunchTemplate.ID) || g.MixedPolicy != nil || g.DesiredCapacityType != "units" || g.CapacityRebalance == nil || *g.CapacityRebalance || g.NewInstancesProtectedFromScaleIn == nil || *g.NewInstancesProtectedFromScaleIn {
		return nil, errors.New("FLEET_NATIVE_CONFIGURATION_UNSAFE_OR_UNKNOWN")
	}
	suspended := map[string]bool{}
	for _, s := range g.Suspended {
		if suspended[s.Name] || s.Name == "Launch" || s.Name == "Terminate" {
			return nil, errors.New("FLEET_NATIVE_SCALING_COLLISION")
		}
		suspended[s.Name] = true
	}
	for _, name := range []string{"ReplaceUnhealthy", "AZRebalance", "InstanceRefresh", "ScheduledActions", "AlarmNotification"} {
		if !suspended[name] {
			return nil, errors.New("FLEET_NATIVE_SCALING_COLLISION")
		}
	}
	tags := map[string]string{}
	for _, tag := range g.Tags {
		if _, seen := tags[tag.Key]; seen {
			return nil, errors.New("FLEET_NATIVE_TAG_CONFLICT")
		}
		tags[tag.Key] = tag.Value
		if strings.HasPrefix(tag.Key, "finops:") && (tag.PropagateAtLaunch == nil || !*tag.PropagateAtLaunch) {
			return nil, errors.New("FLEET_NATIVE_SCOPE_TAGS_REQUIRED")
		}
	}
	for key, want := range map[string]string{"finops:tenant": b.TenantID, "finops:environment": "NON_PRODUCTION", "finops:stateless": "true", "finops:fleet-rightsizing": "true", "finops:managed-by": "terraform"} {
		if tags[key] != want {
			return nil, errors.New("FLEET_NATIVE_SCOPE_TAGS_REQUIRED")
		}
	}
	zones := map[string]bool{}
	for _, zone := range g.Zones {
		if !strings.HasPrefix(zone, b.Region) || zones[zone] {
			return nil, errors.New("FLEET_NATIVE_ZONE_MISMATCH")
		}
		zones[zone] = true
	}
	if len(zones) == 0 {
		return nil, errors.New("FLEET_NATIVE_ZONE_MISMATCH")
	}
	ids := []string{}
	seen := map[string]bool{}
	for _, m := range g.Members {
		if !fleetInstanceID.MatchString(m.InstanceID) || seen[m.InstanceID] || !zones[m.Zone] || m.Lifecycle != "InService" || m.Health != "Healthy" || m.LaunchTemplate != g.LaunchTemplate {
			return nil, errors.New("FLEET_NATIVE_MEMBER_NOT_HEALTHY_PINNED")
		}
		seen[m.InstanceID] = true
		ids = append(ids, m.InstanceID)
	}
	sort.Strings(ids)
	return ids, nil
}

// Capture is an ingester-only inventory factory. Position is BASELINE, BEFORE
// or AFTER a stored signed child. A receipt asserts native membership only; it
// asserts no billing coverage, SLO health, instance type, or storage safety.
func (p *FleetPipeline) Capture(ctx context.Context, tenant, sourceID string, target FleetCaptureTarget) (model.Document, error) {
	if p.Store == nil || p.ReaderFactory == nil || p.Archive == nil {
		return nil, errors.New("FLEET_PIPELINE_DEPENDENCIES_REQUIRED")
	}
	now := time.Now().UTC()
	if p.Now != nil {
		now = p.Now().UTC()
	}
	var registration model.Document
	var parent fleet.Plan
	var child fleet.ChildEnvelope
	if e := p.Store.Do(ctx, tenant, func(tx *store.Tx) error {
		var e error
		registration, e = tx.SourceGet(ctx, sourceID)
		if e != nil {
			return e
		}
		parent, e = tx.FleetTypedPlan(ctx, target.ParentID)
		if e != nil {
			return e
		}
		if target.ChildID != "" {
			child, e = tx.FleetChild(ctx, target.ChildID)
		}
		return e
	}); e != nil {
		return nil, e
	}
	r, e := ParseRegistration(registration)
	if e != nil {
		return nil, e
	}
	if !r.Enabled || model.Bool(registration, "revoked") || r.TenantID != tenant || parent.Binding.TenantID != tenant || fleet.ValidateBinding(parent.Binding) != nil || parent.Old.ID != parent.Binding.ProviderResourceID || parent.Old.ID == parent.Candidate.ID {
		return nil, errors.New("FLEET_CAPTURE_SCOPE_INVALID")
	}
	approved := r.PayerAccountID == parent.Binding.AccountID
	for _, id := range r.UsageAccountIDs {
		approved = approved || id == parent.Binding.AccountID
	}
	if !approved {
		return nil, errors.New("FLEET_CAPTURE_ACCOUNT_NOT_REGISTERED")
	}
	oldCount, greenCount := parent.Old.DesiredCount, 0
	if target.Position == "BASELINE" {
		if target.ChildID != "" {
			return nil, errors.New("FLEET_CAPTURE_POSITION_INVALID")
		}
	} else if target.Position == "BEFORE" || target.Position == "AFTER" {
		if target.ChildID == "" || child.Plan.ParentID != parent.ID || child.Plan.Binding != parent.Binding {
			return nil, errors.New("FLEET_CAPTURE_CHILD_BINDING_INVALID")
		}
		tr := child.Plan.Transition
		if target.Position == "BEFORE" {
			oldCount, greenCount = tr.OldBefore, tr.CandidateBefore
		} else {
			oldCount, greenCount = tr.OldAfter, tr.CandidateAfter
		}
	} else {
		return nil, errors.New("FLEET_CAPTURE_POSITION_INVALID")
	}
	reader, e := p.ReaderFactory(ctx, r, parent.Binding.AccountID)
	if e != nil {
		return nil, e
	}
	readContext, cancelRead := context.WithTimeout(ctx, 45*time.Second)
	native, e := reader.FleetInventory(readContext, parent.Binding.Region, parent.Binding.AccountID, []string{parent.Old.ID, parent.Candidate.ID})
	cancelRead()
	if e != nil {
		return nil, e
	}
	if p.Now != nil {
		now = p.Now().UTC()
	} else {
		now = time.Now().UTC()
	}
	if native.SchemaVersion != "1" || native.Provider != "AWS" || native.AccountID != parent.Binding.AccountID || native.Region != parent.Binding.Region || native.CollectedAt.Before(now.Add(-time.Minute)) || native.CollectedAt.After(now.Add(5*time.Second)) {
		return nil, errors.New("FLEET_NATIVE_OBSERVATION_STALE_OR_WRONG_SCOPE")
	}
	groups, e := fleetRawGroups(native, []string{parent.Old.ID, parent.Candidate.ID})
	if e != nil {
		return nil, e
	}
	if len(groups) != 2 {
		return nil, errors.New("FLEET_NATIVE_GROUPS_INCOMPLETE")
	}
	var oldIDs, greenIDs []string
	seen := map[string]bool{}
	for _, g := range groups {
		if seen[g.Name] {
			return nil, errors.New("FLEET_NATIVE_GROUP_DUPLICATE")
		}
		seen[g.Name] = true
		switch g.Name {
		case parent.Old.ID:
			oldIDs, e = validateFleetGroup(g, parent.Old, parent.Binding, oldCount)
		case parent.Candidate.ID:
			greenIDs, e = validateFleetGroup(g, parent.Candidate, parent.Binding, greenCount)
		default:
			e = errors.New("FLEET_NATIVE_GROUP_NOT_SELECTED")
		}
		if e != nil {
			return nil, e
		}
	}
	for _, a := range oldIDs {
		for _, b := range greenIDs {
			if a == b {
				return nil, errors.New("FLEET_NATIVE_MEMBER_CROSS_COHORT")
			}
		}
	}
	ref, e := p.Archive(ctx, tenant, parent.ID, native.Raw)
	if e != nil {
		return nil, e
	}
	if model.String(ref, "bucket") == "" || !strings.HasPrefix(model.String(ref, "key"), "tenant/"+tenant+"/fleet/") || strings.Contains(model.String(ref, "key"), "..") || model.String(ref, "version_id") == "" || model.String(ref, "version_id") == "null" || model.String(ref, "body_sha256") != native.RawSHA256 {
		return nil, errors.New("FLEET_VERSIONED_RAW_ARCHIVE_REQUIRED")
	}
	config := ConfigurationHash(registration)
	revisionHash := Hash(model.Document{"kind": "AWS_FLEET_MEMBERSHIP", "source_id": sourceID, "registration_version": r.Version, "config_hash": config, "raw_sha256": native.RawSHA256})
	revisionID := "fleet-rev-" + revisionHash
	d := model.Document{"id": "fleet-" + Hash(model.Document{"revision": revisionID, "parent_id": parent.ID, "child_id": target.ChildID, "position": target.Position, "collected_at": native.CollectedAt}), "source_id": sourceID, "revision_id": revisionID, "kind": "AWS_FLEET_MEMBERSHIP", "binding": Object(parent.Binding), "parent_id": parent.ID, "child_id": target.ChildID, "child_sha256": fleet.Digest(child.Plan), "position": target.Position, "old_asg": parent.Old.ID, "candidate_asg": parent.Candidate.ID, "old_instance_ids": oldIDs, "candidate_instance_ids": greenIDs, "groups": groups, "collected_at": native.CollectedAt, "raw_object": ref, "registration_version": r.Version, "read_role_binding_id": r.ReadRoleBindingID, "config_hash": config}
	encoded, _ := json.Marshal(d)
	if len(encoded) > 128<<10 {
		return nil, errors.New("FLEET_MEMBERSHIP_METADATA_LIMIT")
	}
	var result model.Document
	e = p.Store.Do(ctx, tenant, func(tx *store.Tx) error {
		if _, err := tx.Exec(ctx, "SELECT fleet_source_current_lock($1,$2)", tenant, sourceID); err != nil {
			return err
		}
		active, err := tx.SourceGet(ctx, sourceID)
		if err != nil {
			return err
		}
		if !model.Bool(active, "enabled") || model.Bool(active, "revoked") || model.Number(active, "version") != r.Version || ConfigurationHash(active) != config {
			return errors.New("FLEET_SOURCE_CHANGED_DURING_CAPTURE")
		}
		if old, err := tx.SourceReceiptGet(ctx, model.String(d, "id")); err == nil {
			if model.String(old, "revision_id") != revisionID {
				return errors.New("FLEET_RECEIPT_REPLAY_CONFLICT")
			}
			result = old
			return nil
		} else if err != pgx.ErrNoRows {
			return err
		}
		if _, err := tx.SourceRevisionGet(ctx, revisionID); err == pgx.ErrNoRows {
			if _, err = tx.SourceRevisionCreate(ctx, model.Document{"id": revisionID, "source_id": sourceID, "kind": "AWS_FLEET_MEMBERSHIP", "registration_version": r.Version, "revision_hash": revisionHash, "config_hash": config, "raw_object": ref, "observed_at": native.CollectedAt}); err != nil {
				return err
			}
		} else if err != nil {
			return err
		}
		if _, err := tx.SourceReceiptCreate(ctx, d); err != nil {
			return err
		}
		result, err = tx.SourceReceiptGet(ctx, model.String(d, "id"))
		return err
	})
	return result, e
}

type FleetS3Client interface {
	PutObject(context.Context, *s3.PutObjectInput, ...func(*s3.Options)) (*s3.PutObjectOutput, error)
	GetObject(context.Context, *s3.GetObjectInput, ...func(*s3.Options)) (*s3.GetObjectOutput, error)
}
type FleetS3Archive struct {
	Client FleetS3Client
	Bucket string
}

func (s *FleetS3Archive) Archive(ctx context.Context, tenant, parent string, raw []byte) (model.Document, error) {
	if s.Client == nil || !bucketPattern.MatchString(s.Bucket) || !fleetObjectPart.MatchString(tenant) || !fleetObjectPart.MatchString(parent) || len(raw) == 0 || len(raw) > 32<<20 {
		return nil, errors.New("FLEET_ARCHIVE_SCOPE_INVALID")
	}
	digest := BytesHash(raw)
	key := "tenant/" + tenant + "/fleet/" + parent + "/" + digest + ".bin"
	sum := sha256.Sum256(raw)
	put, e := s.Client.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(s.Bucket), Key: aws.String(key), Body: bytes.NewReader(raw), ContentType: aws.String("application/octet-stream"), ChecksumSHA256: aws.String(base64.StdEncoding.EncodeToString(sum[:]))})
	if e != nil {
		return nil, errors.New("FLEET_RAW_ARCHIVE_FAILED")
	}
	if put == nil {
		return nil, errors.New("FLEET_RAW_ARCHIVE_FAILED")
	}
	version := aws.ToString(put.VersionId)
	if version == "" || version == "null" {
		return nil, errors.New("FLEET_RAW_VERSION_REQUIRED")
	}
	get, e := s.Client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(s.Bucket), Key: aws.String(key), VersionId: aws.String(version)})
	if e != nil {
		return nil, errors.New("FLEET_RAW_READBACK_FAILED")
	}
	if get == nil || get.Body == nil {
		return nil, errors.New("FLEET_RAW_READBACK_FAILED")
	}
	defer get.Body.Close()
	read, e := io.ReadAll(io.LimitReader(get.Body, (32<<20)+1))
	if e != nil || len(read) > 32<<20 || aws.ToString(get.VersionId) != version || BytesHash(read) != digest {
		return nil, errors.New("FLEET_RAW_READBACK_MISMATCH")
	}
	return model.Document{"bucket": s.Bucket, "key": key, "version_id": version, "body_sha256": digest}, nil
}
