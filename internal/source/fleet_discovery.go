package source

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/fleet"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/provider"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/jackc/pgx/v5"
)

// Discovery targets are selected from ingester-only operator configuration.
// They select read scope; they are not plans, approvals, observed state or prices.
type FleetDiscoveryBinding struct {
	SourceID     string        `json:"source_id"`
	Binding      fleet.Binding `json:"binding"`
	OldASG       string        `json:"old_asg"`
	CandidateASG string        `json:"candidate_asg"`
}

func ParseFleetDiscoveryBindings(encoded string) (map[string]FleetDiscoveryBinding, error) {
	bindings := map[string]FleetDiscoveryBinding{}
	if strings.TrimSpace(encoded) == "" {
		return bindings, nil
	}
	decoder := json.NewDecoder(strings.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if len(encoded) > 1<<20 || decoder.Decode(&bindings) != nil || decoder.Decode(new(any)) != io.EOF {
		return nil, errors.New("FLEET_DISCOVERY_BINDINGS_INVALID")
	}
	for id, b := range bindings {
		if !fleetObjectPart.MatchString(id) || b.SourceID == "" || fleet.ValidateBinding(b.Binding) != nil || b.OldASG != b.Binding.ProviderResourceID || b.CandidateASG == "" || b.CandidateASG == b.OldASG || len(b.OldASG) > 255 || len(b.CandidateASG) > 255 || strings.ContainsAny(b.OldASG+b.CandidateASG, "\r\n\x00") {
			return nil, errors.New("FLEET_DISCOVERY_BINDINGS_INVALID")
		}
	}
	return bindings, nil
}

// Discover archives authentic native inventory before any FleetPlan exists.
// A changing/unhealthy controller can be observed with explicit blockers. Its
// DISCOVERY position is never accepted as post-apply health by SQL013.
func (p *FleetPipeline) Discover(ctx context.Context, tenant, bindingID string) (model.Document, error) {
	target, ok := p.DiscoveryBindings[bindingID]
	if !ok || target.Binding.TenantID != tenant || p.Store == nil || p.ReaderFactory == nil || p.Archive == nil {
		return nil, errors.New("FLEET_DISCOVERY_BINDING_NOT_CONFIGURED")
	}
	var registration model.Document
	resourceObserved := false
	if e := p.Store.Do(ctx, tenant, func(tx *store.Tx) error {
		var e error
		registration, e = tx.SourceGet(ctx, target.SourceID)
		if e != nil {
			return e
		}
		resource, e := tx.Get(ctx, "resources", target.Binding.ResourceID)
		if e == pgx.ErrNoRows {
			return nil
		}
		if e != nil {
			return e
		}
		resourceObserved = true
		for key, want := range map[string]string{"workload_id": target.Binding.WorkloadID, "provider": target.Binding.Provider, "provider_resource_id": target.OldASG, "account_id": target.Binding.AccountID, "region": target.Binding.Region} {
			if model.String(resource, key) != want {
				return errors.New("FLEET_DISCOVERY_RESOURCE_BINDING_CHANGED")
			}
		}
		return nil
	}); e != nil {
		return nil, e
	}
	r, e := ParseRegistration(registration)
	if e != nil {
		return nil, e
	}
	if !r.Enabled || model.Bool(registration, "revoked") || r.TenantID != tenant {
		return nil, errors.New("FLEET_DISCOVERY_SOURCE_DISABLED")
	}
	approved := r.PayerAccountID == target.Binding.AccountID
	for _, id := range r.UsageAccountIDs {
		approved = approved || id == target.Binding.AccountID
	}
	if !approved {
		return nil, errors.New("FLEET_DISCOVERY_ACCOUNT_NOT_REGISTERED")
	}
	reader, e := p.ReaderFactory(ctx, r, target.Binding.AccountID)
	if e != nil {
		return nil, e
	}
	readContext, cancel := context.WithTimeout(ctx, 45*time.Second)
	native, e := reader.FleetInventory(readContext, target.Binding.Region, target.Binding.AccountID, []string{target.OldASG, target.CandidateASG})
	cancel()
	if e != nil {
		return nil, e
	}
	now := time.Now().UTC()
	if p.Now != nil {
		now = p.Now().UTC()
	}
	if native.SchemaVersion != "1" || native.Provider != "AWS" || native.AccountID != target.Binding.AccountID || native.Region != target.Binding.Region || native.CollectedAt.Before(now.Add(-time.Minute)) || native.CollectedAt.After(now.Add(5*time.Second)) {
		return nil, errors.New("FLEET_NATIVE_OBSERVATION_STALE_OR_WRONG_SCOPE")
	}
	groups, e := fleetRawGroups(native, []string{target.OldASG, target.CandidateASG})
	if e != nil {
		return nil, e
	}
	if len(groups) != 2 {
		return nil, errors.New("FLEET_DISCOVERY_GROUPS_INCOMPLETE")
	}
	seenGroups, seenInstances := map[string]bool{}, map[string]bool{}
	ids := map[string][]string{}
	reasons := []string{}
	for _, g := range groups {
		if seenGroups[g.Name] || g.Name != target.OldASG && g.Name != target.CandidateASG || !strings.HasPrefix(g.ARN, "arn:aws:autoscaling:"+target.Binding.Region+":"+target.Binding.AccountID+":autoScalingGroup:") || !strings.HasSuffix(g.ARN, ":autoScalingGroupName/"+g.Name) || g.Desired == nil || g.Minimum == nil || g.Maximum == nil || *g.Minimum < 0 || *g.Desired < *g.Minimum || *g.Maximum < *g.Desired || len(g.Members) > 256 {
			return nil, errors.New("FLEET_DISCOVERY_NATIVE_BINDING_INVALID")
		}
		seenGroups[g.Name] = true
		tags := map[string]string{}
		for _, tag := range g.Tags {
			if _, duplicate := tags[tag.Key]; duplicate {
				return nil, errors.New("FLEET_NATIVE_TAG_CONFLICT")
			}
			tags[tag.Key] = tag.Value
		}
		if tags["finops:tenant"] != tenant || tags["finops:environment"] != "NON_PRODUCTION" {
			return nil, errors.New("FLEET_DISCOVERY_NATIVE_TENANT_ENVIRONMENT_MISMATCH")
		}
		ids[g.Name] = []string{}
		for _, m := range g.Members {
			if !fleetInstanceID.MatchString(m.InstanceID) || seenInstances[m.InstanceID] {
				return nil, errors.New("FLEET_DISCOVERY_MEMBER_BINDING_INVALID")
			}
			seenInstances[m.InstanceID] = true
			ids[g.Name] = append(ids[g.Name], m.InstanceID)
		}
		sort.Strings(ids[g.Name])
		version, err := strconv.ParseUint(g.LaunchTemplate.Version, 10, 64)
		if err != nil || version < 1 {
			return nil, errors.New("FLEET_DISCOVERY_NUMERIC_LT_VERSION_REQUIRED")
		}
		if _, err := validateFleetGroup(g, fleet.Cohort{ID: g.Name, LaunchTemplateVersion: version}, target.Binding, *g.Desired); err != nil {
			reasons = append(reasons, g.Name+":"+err.Error())
		}
		if g.Name == target.CandidateASG && *g.Desired != 0 {
			reasons = append(reasons, "CANDIDATE_NOT_EMPTY")
		}
	}
	if !resourceObserved {
		reasons = append(reasons, "RESOURCE_MAPPING_REQUIRED")
	}
	sort.Strings(reasons)
	config := ConfigurationHash(registration)
	discoveryHash := Hash(target)
	archiveID := "discovery-" + discoveryHash
	ref, e := p.Archive(ctx, tenant, archiveID, native.Raw)
	if e != nil {
		return nil, e
	}
	if model.String(ref, "bucket") == "" || !strings.HasPrefix(model.String(ref, "key"), "tenant/"+tenant+"/fleet/") || strings.Contains(model.String(ref, "key"), "..") || model.String(ref, "version_id") == "" || model.String(ref, "version_id") == "null" || model.String(ref, "body_sha256") != native.RawSHA256 {
		return nil, errors.New("FLEET_VERSIONED_RAW_ARCHIVE_REQUIRED")
	}
	revisionHash := Hash(model.Document{"kind": "AWS_FLEET_MEMBERSHIP", "source_id": r.ID, "registration_version": r.Version, "config_hash": config, "discovery_binding_hash": discoveryHash, "raw_sha256": native.RawSHA256})
	revisionID := "fleet-rev-" + revisionHash
	d := model.Document{"id": "fleet-" + Hash(model.Document{"revision_id": revisionID, "collected_at": native.CollectedAt}), "kind": "AWS_FLEET_MEMBERSHIP", "source_id": r.ID, "revision_id": revisionID, "position": "DISCOVERY", "binding": Object(target.Binding), "discovery_binding_id": bindingID, "discovery_binding_hash": discoveryHash, "old_asg": target.OldASG, "candidate_asg": target.CandidateASG, "old_instance_ids": ids[target.OldASG], "candidate_instance_ids": ids[target.CandidateASG], "groups": groups, "collected_at": native.CollectedAt, "raw_object": ref, "registration_version": r.Version, "read_role_binding_id": r.ReadRoleBindingID, "config_hash": config, "status": "OBSERVED_ONLY", "execution_authorized": false, "reason_codes": reasons}
	raw, _ := json.Marshal(d)
	if len(raw) > 128<<10 {
		return nil, errors.New("FLEET_MEMBERSHIP_METADATA_LIMIT")
	}
	var out model.Document
	e = p.Store.Do(ctx, tenant, func(tx *store.Tx) error {
		if current, ok := p.DiscoveryBindings[bindingID]; !ok || Hash(current) != discoveryHash {
			return errors.New("FLEET_DISCOVERY_BINDING_CHANGED")
		}
		if _, e := tx.Exec(ctx, "SELECT fleet_source_current_lock($1,$2)", tenant, r.ID); e != nil {
			return e
		}
		active, e := tx.SourceGet(ctx, r.ID)
		if e != nil {
			return e
		}
		if !model.Bool(active, "enabled") || model.Bool(active, "revoked") || model.Number(active, "version") != r.Version || ConfigurationHash(active) != config {
			return errors.New("FLEET_SOURCE_CHANGED_DURING_CAPTURE")
		}
		if existing, e := tx.SourceReceiptGet(ctx, model.String(d, "id")); e == nil {
			out = existing
			return nil
		} else if e != pgx.ErrNoRows {
			return e
		}
		if _, e := tx.SourceRevisionGet(ctx, revisionID); e == pgx.ErrNoRows {
			if _, e = tx.SourceRevisionCreate(ctx, model.Document{"id": revisionID, "source_id": r.ID, "kind": "AWS_FLEET_MEMBERSHIP", "registration_version": r.Version, "revision_hash": revisionHash, "config_hash": config, "discovery_binding_hash": discoveryHash, "raw_object": ref, "observed_at": native.CollectedAt}); e != nil {
				return e
			}
		} else if e != nil {
			return e
		}
		if _, e := tx.SourceReceiptCreate(ctx, d); e != nil {
			return e
		}
		out, e = tx.SourceReceiptGet(ctx, model.String(d, "id"))
		return e
	})
	return out, e
}

// Compile-time assertion keeps native inventory transport descriptive.
var _ FleetReader = (*provider.AWS)(nil)
