package source

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"net/url"
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

type FleetTemplateReader interface {
	FleetTemplateVersions(context.Context, string, string, []provider.FleetTemplateRequest) (provider.FleetTemplateEvidence, error)
}

func fleetTemplateRaw(e provider.FleetTemplateEvidence, requests []provider.FleetTemplateRequest) ([]provider.FleetTemplateVersion, error) {
	if len(e.Raw) == 0 || len(e.Raw) > 32<<20 || BytesHash(e.Raw) != e.RawSHA256 {
		return nil, errors.New("FLEET_TEMPLATE_RAW_HASH_MISMATCH")
	}
	wanted := map[string][]uint64{}
	for _, request := range requests {
		wanted[request.ID] = append(wanted[request.ID], request.Version)
	}
	for id := range wanted {
		sort.Slice(wanted[id], func(i, j int) bool { return wanted[id][i] < wanted[id][j] })
	}
	r := bytes.NewReader(e.Raw)
	next, done := map[string]string{}, map[string]bool{}
	seen := map[string]bool{}
	templates := []provider.FleetTemplateVersion{}
	pages := 0
	for r.Len() > 0 {
		var length uint32
		if binary.Read(r, binary.BigEndian, &length) != nil || length == 0 || length > 65536 || uint64(length) > uint64(r.Len()) {
			return nil, errors.New("FLEET_TEMPLATE_RAW_INVALID")
		}
		selector := make([]byte, length)
		_, _ = io.ReadFull(r, selector)
		v, err := url.ParseQuery(string(selector))
		id := v.Get("LaunchTemplateId")
		versions, known := wanted[id]
		if err != nil || !known || done[id] || v.Get("Action") != "DescribeLaunchTemplateVersions" || v.Get("Version") != "2016-11-15" || v.Get("ResolveAlias") != "false" || v.Get("MaxResults") != "100" || v.Get("NextToken") != next[id] {
			return nil, errors.New("FLEET_TEMPLATE_SELECTOR_MISMATCH")
		}
		for i, version := range versions {
			if v.Get("LaunchTemplateVersion."+strconv.Itoa(i+1)) != strconv.FormatUint(version, 10) {
				return nil, errors.New("FLEET_TEMPLATE_SELECTOR_MISMATCH")
			}
		}
		for key, values := range v {
			if len(values) != 1 {
				return nil, errors.New("FLEET_TEMPLATE_SELECTOR_MISMATCH")
			}
			if key == "Action" || key == "Version" || key == "LaunchTemplateId" || key == "ResolveAlias" || key == "MaxResults" || key == "NextToken" {
				continue
			}
			number, err := strconv.Atoi(strings.TrimPrefix(key, "LaunchTemplateVersion."))
			if !strings.HasPrefix(key, "LaunchTemplateVersion.") || err != nil || number < 1 || number > len(versions) {
				return nil, errors.New("FLEET_TEMPLATE_SELECTOR_MISMATCH")
			}
		}
		var size uint64
		if binary.Read(r, binary.BigEndian, &size) != nil || size == 0 || size > 16<<20 || size > uint64(r.Len()) {
			return nil, errors.New("FLEET_TEMPLATE_RAW_INVALID")
		}
		body := make([]byte, int(size))
		_, _ = io.ReadFull(r, body)
		var response struct {
			XMLName   xml.Name
			Templates []provider.FleetTemplateVersion `xml:"launchTemplateVersionSet>item"`
			Next      string                          `xml:"nextToken"`
		}
		if xml.Unmarshal(body, &response) != nil || response.XMLName.Local != "DescribeLaunchTemplateVersionsResponse" {
			return nil, errors.New("FLEET_TEMPLATE_RAW_INVALID")
		}
		for _, template := range response.Templates {
			key := template.ID + ":" + strconv.FormatUint(template.Version, 10)
			allowed := false
			for _, version := range versions {
				allowed = allowed || template.Version == version
			}
			if template.ID != id || !allowed || seen[key] || template.Data.InstanceRequirements || template.Data.InstanceType == "" || !strings.HasPrefix(template.Data.ImageID, "ami-") {
				return nil, errors.New("FLEET_TEMPLATE_NATIVE_IDENTITY_MISMATCH")
			}
			seen[key] = true
			templates = append(templates, template)
		}
		next[id] = response.Next
		done[id] = response.Next == ""
		pages++
		if pages > 3200 {
			return nil, errors.New("FLEET_TEMPLATE_RAW_INVALID")
		}
	}
	if len(templates) != len(requests) {
		return nil, errors.New("FLEET_TEMPLATE_NATIVE_VERSION_MISSING")
	}
	for id := range wanted {
		if !done[id] {
			return nil, errors.New("FLEET_TEMPLATE_NATIVE_VERSION_MISSING")
		}
	}
	sort.Slice(templates, func(i, j int) bool {
		if templates[i].ID == templates[j].ID {
			return templates[i].Version < templates[j].Version
		}
		return templates[i].ID < templates[j].ID
	})
	if Hash(templates) != Hash(e.Templates) {
		return nil, errors.New("FLEET_TEMPLATE_TYPED_RAW_MISMATCH")
	}
	return templates, nil
}

// CaptureTemplates adds hardware configuration facts to a prior native
// membership receipt. It neither changes that immutable receipt nor treats AMI
// defaults or actual attached volumes as observed. No synthetic plan is needed.
func (p *FleetPipeline) CaptureTemplates(ctx context.Context, tenant, sourceID, membershipID string) (model.Document, error) {
	if p.Store == nil || p.ReaderFactory == nil || p.Archive == nil {
		return nil, errors.New("FLEET_PIPELINE_DEPENDENCIES_REQUIRED")
	}
	var registration, membership model.Document
	if e := p.Store.Do(ctx, tenant, func(tx *store.Tx) error {
		var e error
		registration, e = tx.SourceGet(ctx, sourceID)
		if e != nil {
			return e
		}
		membership, e = tx.SourceReceiptGet(ctx, membershipID)
		return e
	}); e != nil {
		return nil, e
	}
	r, e := ParseRegistration(registration)
	if e != nil {
		return nil, e
	}
	config := ConfigurationHash(registration)
	var binding fleet.Binding
	raw, _ := json.Marshal(membership["binding"])
	if json.Unmarshal(raw, &binding) != nil || fleet.ValidateBinding(binding) != nil || binding.TenantID != tenant || membership["kind"] != "AWS_FLEET_MEMBERSHIP" || model.String(membership, "writer_role") != "finops_ingester" || model.String(membership, "source_id") != sourceID || model.Number(membership, "registration_version") != r.Version || model.String(membership, "config_hash") != config || !r.Enabled || model.Bool(registration, "revoked") {
		return nil, errors.New("FLEET_TEMPLATE_MEMBERSHIP_SOURCE_INVALID")
	}
	approved := r.PayerAccountID == binding.AccountID
	for _, account := range r.UsageAccountIDs {
		approved = approved || account == binding.AccountID
	}
	if !approved {
		return nil, errors.New("FLEET_TEMPLATE_ACCOUNT_NOT_REGISTERED")
	}
	groups := []provider.FleetGroup{}
	raw, _ = json.Marshal(membership["groups"])
	if json.Unmarshal(raw, &groups) != nil || len(groups) != 2 {
		return nil, errors.New("FLEET_TEMPLATE_MEMBERSHIP_GROUPS_INVALID")
	}
	seenGroups := map[string]bool{}
	seen := map[string]bool{}
	requests := []provider.FleetTemplateRequest{}
	for _, g := range groups {
		version, e := strconv.ParseUint(g.LaunchTemplate.Version, 10, 64)
		if e != nil || version < 1 || !fleetTemplateID.MatchString(g.LaunchTemplate.ID) || seenGroups[g.Name] || g.Name != model.String(membership, "old_asg") && g.Name != model.String(membership, "candidate_asg") {
			return nil, errors.New("FLEET_TEMPLATE_MEMBERSHIP_PIN_INVALID")
		}
		seenGroups[g.Name] = true
		key := g.LaunchTemplate.ID + ":" + g.LaunchTemplate.Version
		if !seen[key] {
			requests = append(requests, provider.FleetTemplateRequest{ID: g.LaunchTemplate.ID, Version: version})
			seen[key] = true
		}
	}
	sort.Slice(requests, func(i, j int) bool {
		if requests[i].ID == requests[j].ID {
			return requests[i].Version < requests[j].Version
		}
		return requests[i].ID < requests[j].ID
	})
	reader, e := p.ReaderFactory(ctx, r, binding.AccountID)
	if e != nil {
		return nil, e
	}
	typed, ok := reader.(FleetTemplateReader)
	if !ok {
		return nil, errors.New("FLEET_TEMPLATE_READER_REQUIRED")
	}
	readContext, cancel := context.WithTimeout(ctx, 45*time.Second)
	native, e := typed.FleetTemplateVersions(readContext, binding.Region, binding.AccountID, requests)
	cancel()
	if e != nil {
		return nil, e
	}
	now := time.Now().UTC()
	if p.Now != nil {
		now = p.Now().UTC()
	}
	if native.SchemaVersion != "1" || native.Provider != "AWS" || native.Region != binding.Region || native.AccountID != binding.AccountID || native.CollectedAt.Before(now.Add(-time.Minute)) || native.CollectedAt.After(now.Add(5*time.Second)) {
		return nil, errors.New("FLEET_TEMPLATE_OBSERVATION_STALE_OR_WRONG_SCOPE")
	}
	templates, e := fleetTemplateRaw(native, requests)
	if e != nil {
		return nil, e
	}
	ref, e := p.Archive(ctx, tenant, "templates-"+Hash(requests), native.Raw)
	if e != nil {
		return nil, e
	}
	if model.String(ref, "bucket") == "" || !strings.HasPrefix(model.String(ref, "key"), "tenant/"+tenant+"/fleet/") || strings.Contains(model.String(ref, "key"), "..") || model.String(ref, "version_id") == "" || model.String(ref, "version_id") == "null" || model.String(ref, "body_sha256") != native.RawSHA256 {
		return nil, errors.New("FLEET_VERSIONED_RAW_ARCHIVE_REQUIRED")
	}
	revisionHash := Hash(model.Document{"kind": "AWS_FLEET_LAUNCH_TEMPLATES", "source_id": sourceID, "registration_version": r.Version, "config_hash": config, "membership_receipt_id": membershipID, "raw_sha256": native.RawSHA256})
	revisionID := "fleet-lt-rev-" + revisionHash
	d := model.Document{"id": "fleet-lt-" + Hash(model.Document{"revision_id": revisionID, "collected_at": native.CollectedAt}), "kind": "AWS_FLEET_LAUNCH_TEMPLATES", "source_id": sourceID, "revision_id": revisionID, "binding": Object(binding), "membership_receipt_id": membershipID, "requests": requests, "templates": templates, "raw_object": ref, "collected_at": native.CollectedAt, "registration_version": r.Version, "read_role_binding_id": r.ReadRoleBindingID, "config_hash": config, "status": "OBSERVED_ONLY", "execution_authorized": false, "storage_status": "UNKNOWN_REQUIRES_AMI_AND_ATTACHMENTS", "reason_codes": []string{"AMI_STORAGE_UNOBSERVED", "INSTANCE_ATTACHMENTS_UNOBSERVED"}}
	encoded, _ := json.Marshal(d)
	if len(encoded) > 128<<10 {
		return nil, errors.New("FLEET_TEMPLATE_METADATA_LIMIT")
	}
	var result model.Document
	e = p.Store.Do(ctx, tenant, func(tx *store.Tx) error {
		if _, e := tx.Exec(ctx, "SELECT fleet_source_current_lock($1,$2)", tenant, sourceID); e != nil {
			return e
		}
		active, e := tx.SourceGet(ctx, sourceID)
		if e != nil {
			return e
		}
		if !model.Bool(active, "enabled") || model.Bool(active, "revoked") || model.Number(active, "version") != r.Version || ConfigurationHash(active) != config {
			return errors.New("FLEET_SOURCE_CHANGED_DURING_CAPTURE")
		}
		if old, e := tx.SourceReceiptGet(ctx, model.String(d, "id")); e == nil {
			result = old
			return nil
		} else if e != pgx.ErrNoRows {
			return e
		}
		if _, e := tx.SourceRevisionGet(ctx, revisionID); e == pgx.ErrNoRows {
			if _, e = tx.SourceRevisionCreate(ctx, model.Document{"id": revisionID, "source_id": sourceID, "kind": "AWS_FLEET_LAUNCH_TEMPLATES", "registration_version": r.Version, "revision_hash": revisionHash, "config_hash": config, "membership_receipt_id": membershipID, "raw_object": ref, "observed_at": native.CollectedAt}); e != nil {
				return e
			}
		} else if e != nil {
			return e
		}
		if _, e := tx.SourceReceiptCreate(ctx, d); e != nil {
			return e
		}
		result, e = tx.SourceReceiptGet(ctx, model.String(d, "id"))
		return e
	})
	return result, e
}
