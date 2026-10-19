package fleetbilling

// This adapter is separate from the legacy resource-bound broker. A group is
// selected by real025/027 references, never by an invented inventory resource.
// All inputs are private repository selections; none is an evidence upload DTO.
import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/evidence"
	g "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetgroup"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/provider"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/source"
)

const GroupNativePriceKind = "AWS_GROUP_HISTORICAL_ACCOUNT_RATES"

var groupNativeInstance = regexp.MustCompile(`^i-(?:[a-f0-9]{8}|[a-f0-9]{17})$`)
var groupNativeID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)

type GroupSelection struct {
	OldProposal       g.SnapshotRef `json:"old_configuration_proposal"`
	CandidateProposal g.SnapshotRef `json:"candidate_configuration_proposal"`
	Binding           g.Binding     `json:"binding"`
}

func ValidateGroupSelection(s GroupSelection) error {
	if g.ValidateBinding(s.Binding) != nil || !groupNativeID.MatchString(s.OldProposal.ID) || !groupNativeID.MatchString(s.CandidateProposal.ID) || s.OldProposal.ID == s.CandidateProposal.ID || !reasonHash(s.OldProposal.SHA256) || !reasonHash(s.CandidateProposal.SHA256) {
		return errors.New("GROUP_NATIVE_SELECTION_INVALID")
	}
	return nil
}
func reasonHash(s string) bool {
	return len(s) == 64 && strings.IndexFunc(s, func(r rune) bool { return !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') }) < 0
}

type GroupNativeReceipt struct {
	Receipt  model.Document `json:"receipt"`
	Revision model.Document `json:"revision"`
}
type GroupNativeBillingRevision struct {
	Receipt  model.Document `json:"receipt"`
	Revision model.Document `json:"revision"`
	Job      model.Document `json:"job"`
	// Resolved from the current exact-period source checkpoint under the shared
	// sync guard. A receipt's own presence cannot prove that it is the head.
	CurrentReceiptID string `json:"current_receipt_id"`
}
type GroupNativeSnapshot struct {
	Selection       GroupSelection               `json:"selection"`
	Registrations   map[string]model.Document    `json:"registrations"`
	Memberships     []GroupNativeReceipt         `json:"memberships"`
	Templates       []GroupNativeReceipt         `json:"templates"`
	Hardware        []GroupNativeReceipt         `json:"hardware"`
	BillingSourceID string                       `json:"billing_source_id"`
	Commitment      model.Document               `json:"commitment"`
	Billing         []GroupNativeBillingRevision `json:"billing"`
}
type GroupNativeRepository interface {
	// Resolve must hold/recheck current025/027 bindings and native source heads.
	// A future publisher must repeat this check under its publication locks.
	ResolveGroupNative(context.Context, string, string, string) (GroupNativeSnapshot, error)
}
type GroupNativeBroker struct {
	Repository GroupNativeRepository
	Archive    PinnedReader
	Now        func() time.Time
}
type GroupNativePin struct {
	ReceiptID         string `json:"receipt_id"`
	RevisionID        string `json:"revision_id"`
	ReceiptSHA256     string `json:"receipt_sha256"`
	RawSHA256         string `json:"raw_sha256"`
	ReceiptVersionID  string `json:"receipt_version_id"`
	RevisionVersionID string `json:"revision_version_id"`
}
type GroupNativeEvidence struct {
	SchemaVersion       string           `json:"schema_version"`
	ID                  string           `json:"id"`
	Kind                string           `json:"kind"`
	Selection           GroupSelection   `json:"selection"`
	SnapshotSHA256      string           `json:"snapshot_sha256"`
	SourcePins          []GroupNativePin `json:"source_pins"`
	BillingSourceRefs   []SourceRef      `json:"billing_source_refs"`
	Baseline            Period           `json:"baseline"`
	BaselineScopeBasis  string           `json:"baseline_scope_basis"`
	BillingLagSeconds   int64            `json:"billing_lag_seconds"`
	CurrentMemberIDs    []string         `json:"current_member_ids"`
	Old                 Rate             `json:"old"`
	Candidate           Rate             `json:"candidate"`
	EconomicScopeSHA256 string           `json:"economic_scope_sha256"`
	ObservedAt          time.Time        `json:"observed_at"`
	ValidUntil          time.Time        `json:"valid_until"`
	Status              string           `json:"status"`
	ReasonCodes         []string         `json:"reason_codes"`
	ExecutionAuthorized bool             `json:"execution_authorized"`
	VerifiedSaving      *string          `json:"verified_saving"`
	HardSpendCap        bool             `json:"hard_spend_cap"`
}

func groupSource(reg model.Document, tenant, account, region string, now time.Time) error {
	approved := model.String(reg, "payer_account_id") == account
	for _, id := range model.Strings(reg, "usage_account_ids") {
		approved = approved || id == account
	}
	if model.String(reg, "tenant_id") != tenant || model.String(reg, "kind") != "AWS_CUR2" || !model.Bool(reg, "enabled") || model.Bool(reg, "revoked") || model.String(reg, "status") != "HEALTHY" || !approved || model.String(reg, "region") != region || !fresh(stamp(reg, "last_sync_at"), now, 5*time.Minute) {
		return errors.New("GROUP_PRICE_SOURCE_NOT_CURRENT")
	}
	return nil
}
func groupReceipt(pin GroupNativeReceipt, reg model.Document, kind string, now time.Time) error {
	d, r := pin.Receipt, pin.Revision
	ref, revRef := object(d["raw_object"]), object(r["raw_object"])
	if model.String(d, "kind") != kind || model.String(d, "writer_role") != "finops_ingester" || model.String(r, "writer_role") != "finops_ingester" || model.String(r, "kind") != kind || model.String(d, "id") == "" || model.String(r, "id") != model.String(d, "revision_id") || model.String(d, "source_id") != model.String(reg, "id") || model.String(r, "source_id") != model.String(reg, "id") || model.String(d, "config_hash") != source.ConfigurationHash(reg) || model.String(r, "config_hash") != source.ConfigurationHash(reg) || model.Number(d, "registration_version") != model.Number(reg, "version") || model.Number(r, "registration_version") != model.Number(reg, "version") || model.String(d, "read_role_binding_id") != model.String(reg, "read_role_binding_id") || model.String(reg, "read_role_binding_id") == "" || !fresh(stamp(d, "collected_at"), now, 5*time.Minute) {
		return errors.New("GROUP_PRICE_NATIVE_REVISION_NOT_CURRENT")
	}
	for _, key := range []string{"bucket", "key", "body_sha256"} {
		if model.String(ref, key) == "" || model.String(ref, key) != model.String(revRef, key) {
			return errors.New("GROUP_PRICE_NATIVE_REVISION_OBJECT_MISMATCH")
		}
	}
	if model.String(revRef, "version_id") == "" || model.String(revRef, "version_id") == "null" {
		return errors.New("GROUP_PRICE_NATIVE_REVISION_OBJECT_MISMATCH")
	}
	return nil
}
func (b *GroupNativeBroker) read(ctx context.Context, tenant string, pin GroupNativeReceipt) ([]byte, error) {
	ref := object(pin.Receipt["raw_object"])
	key := model.String(ref, "key")
	version := model.String(ref, "version_id")
	if model.String(ref, "bucket") == "" || version == "" || version == "null" || !strings.HasPrefix(key, "tenant/"+tenant+"/") || strings.ContainsAny(key, "\\\x00\r\n") || strings.Contains(key, "..") || !reasonHash(model.String(ref, "body_sha256")) {
		return nil, errors.New("GROUP_PRICE_PINNED_ARCHIVE_REQUIRED")
	}
	got, err := b.Archive.ReadPinned(ctx, tenant, ref)
	if err != nil {
		return nil, errors.New("GROUP_PRICE_ARCHIVE_UNAVAILABLE")
	}
	if got.Bucket != model.String(ref, "bucket") || got.Key != key || got.VersionID != version || len(got.Body) == 0 || len(got.Body) > 32<<20 || BytesHash(got.Body) != model.String(ref, "body_sha256") {
		return nil, errors.New("GROUP_PRICE_ARCHIVE_READBACK_MISMATCH")
	}
	return got.Body, nil
}

// Each receipt is one exact registered ASG capture, as produced by025. No
// representative instance or legacy resource-shaped group binding is accepted.
func parseRegisteredGroup(d model.Document, raw []byte, s g.Selection) (nativeGroup, error) {
	fail := func() (nativeGroup, error) {
		return nativeGroup{}, errors.New("GROUP_PRICE_MEMBERSHIP_BINDING_INVALID")
	}
	if model.String(d, "history_registration_id") != s.Registration.ID || model.Number(d, "history_registration_version") != s.Registration.Version || model.String(d, "history_registration_hash") != s.Registration.SHA256 || BytesHash(raw) != model.String(object(d["raw_object"]), "body_sha256") {
		return fail()
	}
	binding := object(d["binding"])
	want := model.Document{"tenant_id": s.Target.TenantID, "workload_id": s.Target.WorkloadID, "provider": s.Target.Provider, "account_id": s.Target.AccountID, "region": s.Target.Region}
	if Hash(binding) != Hash(want) {
		return fail()
	}
	parts := strings.SplitN(s.Target.ASGARN, ":autoScalingGroupName/", 2)
	if len(parts) != 2 {
		return fail()
	}
	name := parts[1]
	pages, e := nativePages(raw)
	if e != nil {
		return fail()
	}
	groups := []provider.FleetGroup{}
	subnets := []string{}
	next := ""
	for n, p := range pages {
		v := p.selector
		if v.Get("Action") != "DescribeAutoScalingGroups" || v.Get("Version") != "2011-01-01" || v.Get("MaxRecords") != "100" || v.Get("NextToken") != next || v.Get("AutoScalingGroupNames.member.1") != name || !exactKeys(v, "Action", "Version", "MaxRecords", "NextToken", "AutoScalingGroupNames.member.1") {
			return fail()
		}
		var response struct {
			XMLName xml.Name
			Result  struct {
				Groups []provider.FleetGroup `xml:"AutoScalingGroups>member"`
				Next   string                `xml:"NextToken"`
			} `xml:"DescribeAutoScalingGroupsResult"`
		}
		if xml.Unmarshal(p.body, &response) != nil || response.XMLName.Local != "DescribeAutoScalingGroupsResponse" {
			return fail()
		}
		var extra struct {
			Groups []struct {
				Name, ARN string
				Subnets   string `xml:"VPCZoneIdentifier"`
			} `xml:"DescribeAutoScalingGroupsResult>AutoScalingGroups>member"`
		}
		if xml.Unmarshal(p.body, &extra) != nil {
			return fail()
		}
		for _, x := range extra.Groups {
			subnets = append(subnets, strings.Split(x.Subnets, ",")...)
		}
		groups = append(groups, response.Result.Groups...)
		next = response.Result.Next
		if next == "" && n != len(pages)-1 {
			return fail()
		}
	}
	if next != "" || len(groups) != 1 || len(subnets) == 0 || len(subnets) > 16 {
		return fail()
	}
	group := groups[0]
	if group.Members == nil {
		group.Members = []provider.FleetMember{}
	}
	if Hash([]provider.FleetGroup{group}) != Hash(d["groups"]) || group.ARN != s.Target.ASGARN || group.Name != name || group.Desired == nil || *group.Desired != len(group.Members) || len(group.Members) > 256 || group.MixedPolicy != nil || group.LaunchTemplate.ID == "" {
		return fail()
	}
	version, e := strconv.ParseUint(group.LaunchTemplate.Version, 10, 64)
	if e != nil || version == 0 {
		return fail()
	}
	seen := map[string]bool{}
	for _, member := range group.Members {
		if !groupNativeInstance.MatchString(member.InstanceID) || seen[member.InstanceID] || member.LaunchTemplate.ID != group.LaunchTemplate.ID || member.LaunchTemplate.Version != group.LaunchTemplate.Version {
			return fail()
		}
		seen[member.InstanceID] = true
	}
	seen = map[string]bool{}
	for _, subnet := range subnets {
		if !subnetPattern.MatchString(subnet) || seen[subnet] {
			return fail()
		}
		seen[subnet] = true
	}
	sort.Strings(subnets)
	return nativeGroup{group, subnets}, nil
}

func (b *GroupNativeBroker) Capture(ctx context.Context, tenant, oldProposal, candidateProposal string) (GroupNativeEvidence, error) {
	out := GroupNativeEvidence{SchemaVersion: "1", Kind: GroupNativePriceKind, SourcePins: []GroupNativePin{}, BillingSourceRefs: []SourceRef{}, CurrentMemberIDs: []string{}, BaselineScopeBasis: BaselineScopeBasis, Status: "UNAVAILABLE", ReasonCodes: []string{"EXECUTION_AUTHORITY_NOT_GRANTED", "NO_PROVIDER_FUTURE_PRICE_GUARANTEE", "WORKLOAD_ATTRIBUTION_NOT_PROVEN"}}
	if b.Repository == nil || b.Archive == nil || tenant == "" || oldProposal == "" || candidateProposal == "" {
		return out, errors.New("GROUP_PRICE_PRIVATE_DEPENDENCIES_REQUIRED")
	}
	now := time.Now().UTC()
	if b.Now != nil {
		now = b.Now().UTC()
	}
	out.ObservedAt = now
	s, e := b.Repository.ResolveGroupNative(ctx, tenant, oldProposal, candidateProposal)
	if e != nil {
		return out, e
	}
	out.Selection = s.Selection
	fail := func(code string) (GroupNativeEvidence, error) {
		if !reasonCodePattern.MatchString(code) {
			code = "GROUP_PRICE_EVIDENCE_INVALID"
		}
		out.ReasonCodes = append([]string{code}, out.ReasonCodes...)
		// A failed currentness/readback gate cannot leave plausible monetary
		// fields in an otherwise unavailable public analytical projection.
		out.Old = Rate{}
		out.Candidate = Rate{}
		return out, nil
	}
	if ValidateGroupSelection(s.Selection) != nil || s.Selection.OldProposal.ID != oldProposal || s.Selection.CandidateProposal.ID != candidateProposal || s.Selection.Binding.Old.Target.TenantID != tenant {
		return fail("GROUP_PRICE_SELECTION_CHANGED")
	}
	encoded, err := json.Marshal(s)
	if err != nil || len(encoded) > 32<<20 {
		return fail("GROUP_PRICE_SNAPSHOT_LIMIT")
	}
	out.SnapshotSHA256 = Hash(s)
	if len(s.Registrations) > 4 || len(s.Memberships) != 2 || len(s.Templates) < 1 || len(s.Templates) > 2 || len(s.Hardware) > 512 || len(s.Billing) < 1 || len(s.Billing) > 24 {
		return fail("GROUP_PRICE_POPULATION_LIMIT")
	}
	target := s.Selection.Binding.Old.Target
	for id, reg := range s.Registrations {
		if model.String(reg, "id") != id {
			return fail("GROUP_PRICE_REGISTRATION_ID_MISMATCH")
		}
		if e = groupSource(reg, tenant, target.AccountID, target.Region, now); e != nil {
			return fail(e.Error())
		}
	}
	for _, selection := range []g.Selection{s.Selection.Binding.Old, s.Selection.Binding.Candidate} {
		reg := s.Registrations[selection.SourceID]
		if model.Number(reg, "version") != selection.SourceRegistrationVersion || source.ConfigurationHash(reg) != selection.SourceConfigSHA256 {
			return fail("GROUP_PRICE_SELECTION_SOURCE_CHANGED")
		}
	}
	reg := s.Registrations[s.BillingSourceID]
	if reg == nil {
		return fail("GROUP_PRICE_BILLING_SOURCE_REQUIRED")
	}
	commitment := s.Commitment
	scope := object(commitment["commitment_scope"])
	if model.String(commitment, "kind") != "AWS_COMMITMENT" || model.String(commitment, "writer_role") != "finops_ingester" || model.String(commitment, "source_id") != s.BillingSourceID || model.String(commitment, "config_hash") != source.ConfigurationHash(reg) || !fresh(stamp(scope, "observed_at"), now, 5*time.Minute) || evidence.ValidateCommitmentScopeV3(scope, model.Document{"payer_account_id": reg["payer_account_id"], "account_id": target.AccountID}) != nil {
		return fail("GROUP_PRICE_CURRENT_COMMITMENT_REQUIRED")
	}
	groups := map[string]nativeGroup{}
	templates := map[string]NativeTemplate{}
	machines := map[string]NativeMachine{}
	pins := append(append(append([]GroupNativeReceipt{}, s.Memberships...), s.Templates...), s.Hardware...)
	rawBudget := 0
	seenPins := map[string]bool{}
	for _, pin := range pins {
		d := pin.Receipt
		registration := s.Registrations[model.String(d, "source_id")]
		if seenPins[model.String(d, "id")] {
			return fail("GROUP_PRICE_NATIVE_RECEIPT_DUPLICATE")
		}
		seenPins[model.String(d, "id")] = true
		if e = groupReceipt(pin, registration, model.String(d, "kind"), now); e != nil {
			return fail(e.Error())
		}
		raw, err := b.read(ctx, tenant, pin)
		if err != nil {
			return fail(err.Error())
		}
		rawBudget += len(raw)
		// A fresh capture may archive the same bytes in a second object version
		// while retaining the original data revision. Authenticate both pins;
		// neither matching hashes nor a repeated key can replace version readback.
		receiptVersion := model.String(object(d["raw_object"]), "version_id")
		revisionVersion := model.String(object(pin.Revision["raw_object"]), "version_id")
		if receiptVersion != revisionVersion {
			revisionRaw, readErr := b.read(ctx, tenant, GroupNativeReceipt{Receipt: model.Document{"raw_object": pin.Revision["raw_object"]}})
			if readErr != nil || !bytes.Equal(raw, revisionRaw) {
				return fail("GROUP_PRICE_LINKED_REVISION_READBACK_MISMATCH")
			}
			rawBudget += len(revisionRaw)
		}
		if rawBudget > 128<<20 {
			return fail("GROUP_PRICE_RAW_BUDGET_LIMIT")
		}
		out.SourcePins = append(out.SourcePins, GroupNativePin{ReceiptID: model.String(d, "id"), RevisionID: model.String(d, "revision_id"), ReceiptSHA256: Hash(d), RawSHA256: BytesHash(raw), ReceiptVersionID: receiptVersion, RevisionVersionID: revisionVersion})
		switch model.String(d, "kind") {
		case "AWS_FLEET_MEMBERSHIP":
			var selected *g.Selection
			for _, selection := range []g.Selection{s.Selection.Binding.Old, s.Selection.Binding.Candidate} {
				if model.String(d, "history_registration_id") == selection.Registration.ID {
					x := selection
					selected = &x
				}
			}
			if selected == nil || model.String(d, "source_id") != selected.SourceID || groups[selected.Target.ASGARN].Name != "" {
				return fail("GROUP_PRICE_MEMBERSHIP_SCOPE_INVALID")
			}
			parsed, err := parseRegisteredGroup(d, raw, *selected)
			if err != nil {
				return fail(err.Error())
			}
			groups[selected.Target.ASGARN] = parsed
		case "AWS_FLEET_LAUNCH_TEMPLATES":
			parsed, err := parseTemplates(d, raw)
			if err != nil {
				return fail(err.Error())
			}
			for key, value := range parsed {
				if previous, exists := templates[key]; exists && previous != value {
					return fail("GROUP_PRICE_TEMPLATE_AMBIGUOUS")
				}
				templates[key] = value
			}
		case "AWS_EC2_HARDWARE":
			binding := object(d["binding"])
			if model.String(binding, "tenant_id") != tenant || model.String(binding, "workload_id") != target.WorkloadID || model.String(binding, "provider") != "AWS" {
				return fail("GROUP_PRICE_MACHINE_SCOPE_INVALID")
			}
			m, err := parseHardware(d, raw, target.AccountID, target.Region)
			if err != nil {
				return fail(err.Error())
			}
			if _, exists := machines[m.InstanceID]; exists {
				return fail("GROUP_PRICE_MACHINE_DUPLICATE")
			}
			machines[m.InstanceID] = m
		default:
			return fail("GROUP_PRICE_NATIVE_KIND_INVALID")
		}
	}
	old, candidate := groups[s.Selection.Binding.Old.Target.ASGARN], groups[s.Selection.Binding.Candidate.Target.ASGARN]
	if old.Name == "" || candidate.Name == "" || len(old.Members) == 0 {
		return fail("GROUP_PRICE_CURRENT_MEMBERS_REQUIRED")
	}
	// Population comes from the complete authenticated membership point. A
	// later missing hardware receipt must not shrink capacity coverage to just
	// the members whose dimension checks happened to pass first.
	for _, member := range old.Members {
		out.CurrentMemberIDs = append(out.CurrentMemberIDs, member.InstanceID)
	}
	sort.Strings(out.CurrentMemberIDs)
	oldTemplate, ok := templates[old.LaunchTemplate.ID+":"+old.LaunchTemplate.Version]
	if !ok {
		return fail("GROUP_PRICE_OLD_TEMPLATE_REQUIRED")
	}
	candidateTemplate, ok := templates[candidate.LaunchTemplate.ID+":"+candidate.LaunchTemplate.Version]
	if !ok {
		return fail("GROUP_PRICE_CANDIDATE_TEMPLATE_REQUIRED")
	}
	oldMachines := []NativeMachine{}
	for _, member := range old.Members {
		m, ok := machines[member.InstanceID]
		if !ok || !machineMatches(m, oldTemplate) || !inSubnets(m.SubnetID, old.Subnets) {
			return fail("GROUP_PRICE_OLD_MEMBER_DIMENSIONS_REQUIRED")
		}
		oldMachines = append(oldMachines, m)
	}
	candidates := []NativeMachine{}
	for _, m := range machines {
		if machineMatches(m, candidateTemplate) && inSubnets(m.SubnetID, candidate.Subnets) {
			candidates = append(candidates, m)
		}
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].InstanceID < candidates[j].InstanceID })
	if len(candidates) == 0 {
		return fail("GROUP_PRICE_CANDIDATE_NATIVE_DIMENSIONS_REQUIRED")
	}
	end := time.Time{}
	for _, r := range s.Billing {
		p := object(r.Receipt["source_proof"])
		if stamp(p, "period_end").After(end) && !stamp(p, "period_end").After(now) {
			end = stamp(p, "period_end")
		}
	}
	end = end.UTC().Truncate(24 * time.Hour)
	if end.IsZero() || now.Sub(end) > 48*time.Hour {
		return fail("GROUP_PRICE_LATEST_COMPLETE_BILLING_REQUIRED")
	}
	out.Baseline = Period{end.AddDate(0, 0, -14), end}
	out.BillingLagSeconds = int64(now.Sub(end).Seconds())
	out.ValidUntil = minTime(now.Add(24*time.Hour), end.Add(48*time.Hour))
	billing := append([]GroupNativeBillingRevision{}, s.Billing...)
	sort.Slice(billing, func(i, j int) bool {
		return stamp(object(billing[i].Receipt["source_proof"]), "period_start").Before(stamp(object(billing[j].Receipt["source_proof"]), "period_start"))
	})
	records := []model.Document{}
	currency := ""
	cursor := out.Baseline.Start
	periods := map[string]bool{}
	for _, r := range billing {
		d := r.Receipt
		p := object(d["source_proof"])
		left, right := stamp(p, "period_start"), stamp(p, "period_end")
		if !left.Before(end) || !right.After(out.Baseline.Start) {
			continue
		}
		if r.CurrentReceiptID != model.String(d, "id") || r.CurrentReceiptID == "" || periods[model.String(p, "billing_period_start")] {
			return fail("GROUP_PRICE_BILLING_HEAD_AMBIGUOUS")
		}
		periods[model.String(p, "billing_period_start")] = true
		if e = validateJob(reg, d, r.Revision, r.Job, tenant); e != nil {
			return fail(e.Error())
		}
		if model.String(d, "source_id") != s.BillingSourceID || model.String(d, "config_hash") != source.ConfigurationHash(reg) || model.String(r.Revision, "id") != model.String(d, "revision_id") {
			return fail("GROUP_PRICE_BILLING_REVISION_SCOPE_INVALID")
		}
		if left.After(cursor) {
			return fail("GROUP_PRICE_BILLING_PERIOD_GAP")
		}
		if right.After(cursor) {
			cursor = right
		}
		if currency == "" {
			currency = model.String(p, "currency")
		}
		if currency == "" || currency != model.String(p, "currency") {
			return fail("GROUP_PRICE_CURRENCY_SCOPE_AMBIGUOUS")
		}
		approved := false
		for _, account := range model.Strings(p, "usage_account_ids") {
			approved = approved || account == target.AccountID
		}
		if !approved {
			return fail("GROUP_PRICE_BILLING_ACCOUNT_SCOPE_UNPROVEN")
		}
		proof := model.Clone(p)
		proof["usage_account_id"] = target.AccountID
		if e = evidence.ValidateSourceProofV3(proof, model.Document{"payer_account_id": reg["payer_account_id"], "account_id": target.AccountID, "region": target.Region, "currency": currency, "invoice_entity": p["invoice_entity"]}, maxTime(left, out.Baseline.Start), minTime(right, end), false); e != nil {
			return fail(e.Error())
		}
		records = append(records, rows(object(r.Job["raw"])["records"])...)
		if len(records) > 100000 {
			return fail("GROUP_PRICE_BILLING_ROW_LIMIT")
		}
		out.BillingSourceRefs = append(out.BillingSourceRefs, SourceRef{model.String(d, "id"), model.String(d, "revision_id"), model.String(r.Job, "id"), model.String(d, "raw_hash"), model.String(d, "canonical_hash"), left, right})
	}
	if cursor.Before(end) {
		return fail("GROUP_PRICE_BILLING_PERIOD_GAP")
	}
	if e = portfolioSafe(records, out.Baseline); e != nil {
		return fail(e.Error())
	}
	out.EconomicScopeSHA256 = economicHash(records, out.Baseline)
	// An exact current-type baseline has no counterfactual configuration-price
	// claim. Preserve actual population/native/CUR closure and repeat final
	// currentness below, but do not manufacture conditional fleet economics.
	currentBaseline := len(oldMachines) > 0
	for _, machine := range oldMachines {
		currentBaseline = currentBaseline && machine.InstanceType == candidateTemplate.InstanceType
	}
	if !currentBaseline {
		out.Old, e = summarizeRates(records, oldMachines, oldTemplate, out.Baseline, target.AccountID, target.Region, currency, true)
		if e != nil {
			return fail(e.Error())
		}
		for _, m := range candidates {
			// Require one complete latest day for the native witness as well. A
			// duplicate or overlapping witness row cannot inflate observed costs or
			// masquerade as additional rate support.
			rate, err := summarizeRates(records, []NativeMachine{m}, candidateTemplate, Period{end.Add(-24 * time.Hour), end}, target.AccountID, target.Region, currency, true)
			if err != nil {
				if err.Error() == "PRICE_CANDIDATE_ACCOUNT_RATE_UNAVAILABLE" {
					continue
				}
				return fail(err.Error())
			}
			if out.Candidate.ObservedHourlyRate != nil && (Hash(out.Candidate.Dimensions) != Hash(rate.Dimensions) || *out.Candidate.ObservedHourlyRate != *rate.ObservedHourlyRate) {
				return fail("GROUP_PRICE_CANDIDATE_ACCOUNT_RATE_AMBIGUOUS")
			}
			out.Candidate = rate
		}
		if out.Candidate.ObservedHourlyRate == nil {
			return fail("GROUP_PRICE_CANDIDATE_ACCOUNT_RATE_REQUIRED")
		}
	}
	latest, err := b.Repository.ResolveGroupNative(ctx, tenant, oldProposal, candidateProposal)
	if err != nil {
		return fail("GROUP_PRICE_FINAL_CURRENTNESS_UNAVAILABLE")
	}
	if Hash(latest) != out.SnapshotSHA256 {
		return fail("GROUP_PRICE_SELECTION_OR_SOURCE_CHANGED")
	}
	finalNow := time.Now().UTC()
	if b.Now != nil {
		finalNow = b.Now().UTC()
	}
	for _, r := range latest.Registrations {
		if groupSource(r, tenant, target.AccountID, target.Region, finalNow) != nil {
			return fail("GROUP_PRICE_SOURCE_EXPIRED_DURING_CAPTURE")
		}
	}
	for _, pin := range pins {
		if groupReceipt(pin, latest.Registrations[model.String(pin.Receipt, "source_id")], model.String(pin.Receipt, "kind"), finalNow) != nil {
			return fail("GROUP_PRICE_NATIVE_EVIDENCE_EXPIRED_DURING_CAPTURE")
		}
	}
	if !fresh(stamp(object(latest.Commitment["commitment_scope"]), "observed_at"), finalNow, 5*time.Minute) {
		return fail("GROUP_PRICE_COMMITMENT_EXPIRED_DURING_CAPTURE")
	}
	if !out.ValidUntil.After(finalNow) {
		return fail("GROUP_PRICE_BILLING_EXPIRED_DURING_CAPTURE")
	}
	if currentBaseline {
		return fail("CURRENT_CONFIGURATION_BASELINE_NO_COUNTERFACTUAL_ECONOMICS")
	}
	out.Status = "OBSERVED_CONDITIONAL"
	out.ID = "group-native-rate-" + Hash(out)
	return out, nil
}
