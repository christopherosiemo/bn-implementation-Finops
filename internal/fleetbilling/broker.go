package fleetbilling

import (
	"context"
	"errors"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/evidence"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/fleet"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/source"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
)

type PinnedReader interface {
	ReadPinned(context.Context, string, model.Document) (PinnedObject, error)
}

// Metadata must be the read response's observed identity/version, not echoed
// request values. A future S3 adapter must use GetObjectVersion and return its
// response VersionId. This package does not install a credentialed adapter.
type PinnedObject struct {
	Bucket, Key, VersionID string
	Body                   []byte
}
type Broker struct {
	Store   *store.Store
	Archive PinnedReader
	Targets map[string]Target
	Now     func() time.Time
}

func (b *Broker) now() time.Time {
	if b.Now != nil {
		return b.Now().UTC()
	}
	return time.Now().UTC()
}

type resolved struct {
	registration, membership, templates, commitment model.Document
	inventory                                       model.Document
	hardware                                        []model.Document
	billing                                         []model.Document
	jobs                                            map[string]model.Document
}

func newestMatching(all []model.Document, match func(model.Document) bool) model.Document {
	for n := len(all) - 1; n >= 0; n-- {
		if match(all[n]) {
			return all[n]
		}
	}
	return nil
}
func currentGate(r, c model.Document, target Target, now time.Time) error {
	if model.String(r, "id") != target.SourceID || model.String(r, "tenant_id") != target.Binding.TenantID || model.String(r, "kind") != "AWS_CUR2" || !model.Bool(r, "enabled") || model.Bool(r, "revoked") || model.String(r, "status") != "HEALTHY" || model.String(r, "region") != "eu-west-1" || !fresh(stamp(r, "last_sync_at"), now, 5*time.Minute) {
		return errors.New("PRICE_SOURCE_AUTHORITY_UNAVAILABLE")
	}
	config := source.ConfigurationHash(r)
	scope := object(c["commitment_scope"])
	if model.String(c, "kind") != "AWS_COMMITMENT" || model.String(c, "writer_role") != "finops_ingester" || model.String(c, "source_id") != target.SourceID || model.String(c, "config_hash") != config || !fresh(stamp(scope, "observed_at"), now, 5*time.Minute) {
		return errors.New("PRICE_CURRENT_COMMITMENT_REQUIRED")
	}
	return evidence.ValidateCommitmentScopeV3(scope, model.Document{"payer_account_id": r["payer_account_id"], "account_id": target.Binding.AccountID})
}
func load(ctx context.Context, tx *store.Tx, target Target, now time.Time) (resolved, error) {
	out := resolved{jobs: map[string]model.Document{}}
	// Source sync publishes multiple immutable monthly revisions in separate
	// transactions. HEALTHY can still describe the previous completed sync while
	// that publication is in progress. Hold a shared snapshot guard until this
	// transaction ends; do not wait for or observe an incomplete source sync.
	var stable bool
	if e := tx.QueryRow(ctx, "SELECT pg_try_advisory_xact_lock_shared(hashtextextended($1,0))", tx.Tenant+":trusted-source:"+target.SourceID).Scan(&stable); e != nil {
		return out, e
	}
	if !stable {
		return out, errors.New("PRICE_SOURCE_SYNC_IN_PROGRESS")
	}
	resource, e := tx.Get(ctx, "resources", target.Binding.ResourceID)
	if e != nil {
		return out, e
	}
	for key, want := range map[string]string{"workload_id": target.Binding.WorkloadID, "provider": target.Binding.Provider, "provider_resource_id": target.Binding.ProviderResourceID, "account_id": target.Binding.AccountID, "region": target.Binding.Region, "environment": "NON_PRODUCTION"} {
		if model.String(resource, key) != want {
			return out, errors.New("PRICE_CURRENT_RESOURCE_BINDING_INVALID")
		}
	}
	out.inventory = resource
	r, e := tx.SourceGet(ctx, target.SourceID)
	if e != nil {
		return out, e
	}
	out.registration = r
	all, e := tx.SourceReceiptList(ctx, "", target.SourceID)
	if e != nil {
		return out, e
	}
	out.commitment = newestMatching(all, func(d model.Document) bool { return model.String(d, "kind") == "AWS_COMMITMENT" })
	if e = currentGate(r, out.commitment, target, now); e != nil {
		return out, e
	}
	cfg := source.ConfigurationHash(r)
	match := func(d model.Document) bool {
		return model.String(d, "writer_role") == "finops_ingester" && model.String(d, "config_hash") == cfg && Hash(d["binding"]) == Hash(target.Binding)
	}
	out.membership = newestMatching(all, func(d model.Document) bool {
		return model.String(d, "kind") == "AWS_FLEET_MEMBERSHIP" && match(d) && model.String(d, "old_asg") == target.OldASG && model.String(d, "candidate_asg") == target.CandidateASG
	})
	if out.membership == nil || !fresh(stamp(out.membership, "collected_at"), now, 5*time.Minute) {
		return out, errors.New("PRICE_CURRENT_MEMBERSHIP_REQUIRED")
	}
	out.templates = newestMatching(all, func(d model.Document) bool {
		return model.String(d, "kind") == "AWS_FLEET_LAUNCH_TEMPLATES" && match(d) && model.String(d, "membership_receipt_id") == model.String(out.membership, "id")
	})
	if out.templates == nil || !fresh(stamp(out.templates, "collected_at"), now, 5*time.Minute) {
		return out, errors.New("PRICE_CURRENT_TEMPLATE_REQUIRED")
	}
	latestHardware := map[string]model.Document{}
	periods := map[string]model.Document{}
	for _, d := range all {
		if model.String(d, "writer_role") != "finops_ingester" || model.String(d, "config_hash") != cfg {
			continue
		}
		switch model.String(d, "kind") {
		case "AWS_EC2_HARDWARE":
			binding := object(d["binding"])
			if model.String(binding, "tenant_id") == tx.Tenant && model.String(binding, "account_id") == target.Binding.AccountID && model.String(binding, "region") == target.Binding.Region {
				latestHardware[model.String(binding, "provider_resource_id")] = d
			}
		case "AWS_CUR2":
			p := object(d["source_proof"])
			periods[model.String(p, "billing_period_start")] = d
		}
	}
	for _, d := range latestHardware {
		if fresh(stamp(d, "collected_at"), now, 5*time.Minute) {
			out.hardware = append(out.hardware, d)
		}
	}
	sort.Slice(out.hardware, func(i, j int) bool { return model.String(out.hardware[i], "id") < model.String(out.hardware[j], "id") })
	for _, d := range periods {
		job, e := tx.Get(ctx, "ingestion_jobs", model.String(d, "ingestion_job_id"))
		if e != nil {
			return out, e
		}
		rev, e := tx.SourceRevisionGet(ctx, model.String(d, "revision_id"))
		if e != nil {
			return out, e
		}
		if e = validateJob(r, d, rev, job, tx.Tenant); e != nil {
			return out, e
		}
		out.billing = append(out.billing, d)
		out.jobs[model.String(d, "id")] = job
	}
	sort.Slice(out.billing, func(i, j int) bool {
		return model.String(object(out.billing[i]["source_proof"]), "billing_period_start") < model.String(object(out.billing[j]["source_proof"]), "billing_period_start")
	})
	return out, nil
}
func validateJob(reg, receipt, rev, job model.Document, tenant string) error {
	if model.String(receipt, "tenant_id") != tenant || model.String(receipt, "kind") != "AWS_CUR2" || model.String(receipt, "registration_id") != model.String(reg, "id") || model.String(receipt, "writer_role") != "finops_ingester" || model.String(rev, "writer_role") != "finops_ingester" || model.String(rev, "source_id") != model.String(reg, "id") || model.String(job, "status") != "PERSISTED" || model.String(job, "source_provenance") != "AWS_CUR2_AUTHENTICATED" || model.String(job, "source_registration_id") != model.String(reg, "id") || model.String(job, "source_receipt_id") != model.String(receipt, "id") || model.String(job, "source_revision_id") != model.String(receipt, "revision_id") || model.String(receipt, "raw_hash") != Hash(job["raw"]) || model.String(receipt, "canonical_hash") != Hash(job["canonical"]) || model.String(rev, "raw_hash") != Hash(job["raw"]) || model.String(rev, "canonical_hash") != Hash(job["canonical"]) || model.String(rev, "config_hash") != source.ConfigurationHash(reg) {
		return errors.New("PRICE_BILLING_RECEIPT_BINDING_INVALID")
	}
	raw, can := object(job["raw"]), object(job["canonical"])
	native, canonical := rows(raw["records"]), rows(can["records"])
	if len(native) == 0 || len(native) != len(canonical) || model.String(raw, "source_id") != model.String(reg, "id") || model.String(raw, "source_version") != model.String(receipt, "source_version") {
		return errors.New("PRICE_CANONICAL_SOURCE_BINDING_INVALID")
	}
	byID := map[string]model.Document{}
	for _, r := range native {
		id := rawString(r, "identity_line_item_id")
		if id == "" || byID[id] != nil || rawString(r, "bill_payer_account_id") != model.String(reg, "payer_account_id") {
			return errors.New("PRICE_NATIVE_RECORD_ID_INVALID")
		}
		byID[id] = r
	}
	if model.Number(object(receipt["source_proof"]), "row_count") != int64(len(native)) {
		return errors.New("PRICE_NATIVE_RECORD_COUNT_MISMATCH")
	}
	seen := map[string]bool{}
	for _, c := range canonical {
		id := model.String(c, "x_SourceRecordId")
		r := byID[id]
		if r == nil || seen[id] || Hash(c["x_ProviderFields"]) != Hash(r) || model.String(c, "x_SourceId") != model.String(reg, "id") || model.String(c, "x_SourceVersion") != model.String(raw, "source_version") {
			return errors.New("PRICE_CANONICAL_NATIVE_TAMPERED")
		}
		seen[id] = true
		for canonicalKey, nativeKey := range map[string]string{"SubAccountId": "line_item_usage_account_id", "ResourceId": "line_item_resource_id", "RegionId": "product_region_code", "BillingCurrency": "line_item_currency_code", "BillingAccountId": "bill_payer_account_id"} {
			if model.String(c, canonicalKey) != rawString(r, nativeKey) {
				return errors.New("PRICE_CANONICAL_NATIVE_TAMPERED")
			}
		}
		if stamp(c, "ChargePeriodStart").IsZero() || !stamp(c, "ChargePeriodStart").Equal(stamp(r, "line_item_usage_start_date")) || !stamp(c, "ChargePeriodEnd").Equal(stamp(r, "line_item_usage_end_date")) {
			return errors.New("PRICE_CANONICAL_NATIVE_TAMPERED")
		}
		billed, e := decimal(model.String(c, "BilledCost"))
		nativeText := rawString(r, "line_item_net_unblended_cost")
		if nativeText == "" {
			nativeText = rawString(r, "line_item_unblended_cost")
		}
		nativeCost, e2 := decimal(nativeText)
		if e != nil || e2 != nil || billed.Cmp(nativeCost) != 0 {
			return errors.New("PRICE_CANONICAL_NATIVE_TAMPERED")
		}
	}
	return nil
}
func (b *Broker) read(ctx context.Context, target Target, d model.Document) ([]byte, error) {
	ref := object(d["raw_object"])
	key := model.String(ref, "key")
	if model.String(ref, "bucket") == "" || model.String(ref, "version_id") == "" || model.String(ref, "version_id") == "null" || !strings.HasPrefix(key, "tenant/"+target.Binding.TenantID+"/") || strings.ContainsAny(key, "\\\x00") || strings.Contains(key, "..") || len(model.String(ref, "body_sha256")) != 64 {
		return nil, errors.New("PRICE_PINNED_NATIVE_ARCHIVE_REQUIRED")
	}
	read, e := b.Archive.ReadPinned(ctx, target.Binding.TenantID, ref)
	if e != nil {
		return nil, e
	}
	if read.Bucket != model.String(ref, "bucket") || read.Key != key || read.VersionID != model.String(ref, "version_id") {
		return nil, errors.New("PRICE_NATIVE_ARCHIVE_VERSION_MISMATCH")
	}
	raw := read.Body
	if BytesHash(raw) != model.String(ref, "body_sha256") {
		return nil, errors.New("PRICE_NATIVE_ARCHIVE_HASH_MISMATCH")
	}
	return raw, nil
}

// Capture resolves all evidence server-side. Even READY is a conditional
// historical account rate, not permission to execute or a verified benefit.
func (b *Broker) Capture(ctx context.Context, tenant, resource string, programDuration time.Duration) (Evidence, error) {
	target, ok := b.Targets[tenant+":"+resource]
	if !ok || target.Binding.TenantID != tenant || target.Binding.ResourceID != resource || target.OldASG != target.Binding.ProviderResourceID || target.OldASG == target.CandidateASG || fleet.ValidateBinding(target.Binding) != nil || b.Store == nil || b.Archive == nil {
		return Evidence{}, errors.New("PRICE_APPROVED_TARGET_REQUIRED")
	}
	now := b.now()
	out := Evidence{SchemaVersion: "1", Kind: Kind, Binding: target.Binding, SourceConnectionID: target.SourceID, BillingSourceRefs: []SourceRef{}, HardwareReceiptIDs: []string{}, BaselineDays: 14, BaselineScopeBasis: BaselineScopeBasis, ObservedAt: now, ReasonCodes: []string{}}
	if programDuration <= 0 || programDuration > 24*time.Hour {
		return out, errors.New("PRICE_PROGRAM_DURATION_INVALID")
	}
	var s resolved
	e := b.Store.Do(ctx, tenant, func(tx *store.Tx) error { var e error; s, e = load(ctx, tx, target, now); return e })
	if e != nil {
		return captureFailure(out, e)
	}
	out.SourceConfigHash = source.ConfigurationHash(s.registration)
	out.SourceConfiguration = configuration(s.registration)
	out.MembershipReceiptID = model.String(s.membership, "id")
	out.LaunchTemplatesReceiptID = model.String(s.templates, "id")
	out.CommitmentReceiptID = model.String(s.commitment, "id")
	membershipRaw, e := b.read(ctx, target, s.membership)
	if e != nil {
		return unavailable(out, e.Error()), nil
	}
	old, candidate, e := parseMembership(s.membership, membershipRaw, target)
	if e != nil {
		return unavailable(out, e.Error()), nil
	}
	templateRaw, e := b.read(ctx, target, s.templates)
	if e != nil {
		return unavailable(out, e.Error()), nil
	}
	templates, e := parseTemplates(s.templates, templateRaw)
	if e != nil {
		return unavailable(out, e.Error()), nil
	}
	oldT, ok1 := templates[old.LaunchTemplate.ID+":"+old.LaunchTemplate.Version]
	candidateT, ok2 := templates[candidate.LaunchTemplate.ID+":"+candidate.LaunchTemplate.Version]
	if !ok1 || !ok2 {
		return unavailable(out, "PRICE_MEMBERSHIP_TEMPLATE_PIN_MISMATCH"), nil
	}
	machines := map[string]NativeMachine{}
	for _, d := range s.hardware {
		raw, e := b.read(ctx, target, d)
		if e != nil {
			return unavailable(out, e.Error()), nil
		}
		m, e := parseHardware(d, raw, target.Binding.AccountID, target.Binding.Region)
		if e != nil {
			continue
		}
		machines[m.InstanceID] = m
	}
	oldMachines := []NativeMachine{}
	for _, member := range old.Members {
		m, ok := machines[member.InstanceID]
		if !ok || !machineMatches(m, oldT) || !inSubnets(m.SubnetID, old.Subnets) || member.LaunchTemplate.ID != oldT.ID || member.LaunchTemplate.Version != strconv.FormatUint(oldT.Version, 10) {
			return unavailable(out, "PRICE_OLD_MEMBER_NATIVE_DIMENSIONS_UNAVAILABLE"), nil
		}
		oldMachines = append(oldMachines, m)
		out.HardwareReceiptIDs = append(out.HardwareReceiptIDs, m.HardwareReceiptID)
	}
	candidateMachines := []NativeMachine{}
	for _, m := range machines {
		if machineMatches(m, candidateT) && inSubnets(m.SubnetID, candidate.Subnets) {
			candidateMachines = append(candidateMachines, m)
		}
	}
	sort.Slice(candidateMachines, func(i, j int) bool { return candidateMachines[i].InstanceID < candidateMachines[j].InstanceID })
	if len(candidateMachines) == 0 {
		return unavailable(out, "PRICE_CANDIDATE_NATIVE_DIMENSIONS_UNAVAILABLE"), nil
	}
	end := time.Time{}
	for _, receipt := range s.billing {
		p := object(receipt["source_proof"])
		if t := stamp(p, "period_end"); t.After(end) && !t.After(now) {
			end = t
		}
	}
	end = end.UTC().Truncate(24 * time.Hour)
	if end.IsZero() || now.Sub(end) > 48*time.Hour {
		return unavailable(out, "PRICE_LATEST_COMPLETE_BILLING_UNAVAILABLE"), nil
	}
	out.Baseline = Period{end.AddDate(0, 0, -14), end}
	out.BillingLagSeconds = int64(now.Sub(end).Seconds())
	out.ValidUntil = now.Add(24 * time.Hour)
	if last := end.Add(48 * time.Hour); last.Before(out.ValidUntil) {
		out.ValidUntil = last
	}
	if out.ValidUntil.Before(now.Add(programDuration)) {
		return unavailable(out, "PRICE_EVIDENCE_HORIZON_SHORTER_THAN_PROGRAM"), nil
	}
	records := []model.Document{}
	cursor := out.Baseline.Start
	currency := ""
	for _, receipt := range s.billing {
		p := object(receipt["source_proof"])
		left, right := stamp(p, "period_start"), stamp(p, "period_end")
		if !left.Before(end) || !right.After(out.Baseline.Start) {
			continue
		}
		if left.After(cursor) {
			return unavailable(out, "PRICE_BILLING_PERIOD_GAP"), nil
		}
		if right.After(cursor) {
			cursor = right
		}
		if currency == "" {
			currency = model.String(p, "currency")
		}
		if currency == "" || model.String(p, "currency") != currency {
			return unavailable(out, "PRICE_CURRENCY_SCOPE_AMBIGUOUS"), nil
		}
		if known := model.String(s.inventory, "currency"); known != "" && known != currency {
			return unavailable(out, "PRICE_RESOURCE_CURRENCY_MISMATCH"), nil
		}
		approved := false
		for _, account := range model.Strings(p, "usage_account_ids") {
			approved = approved || account == target.Binding.AccountID
		}
		if !approved {
			return unavailable(out, "PRICE_BILLING_ACCOUNT_SCOPE_UNPROVEN"), nil
		}
		binding := model.Document{"payer_account_id": s.registration["payer_account_id"], "account_id": target.Binding.AccountID, "region": target.Binding.Region, "currency": currency, "invoice_entity": p["invoice_entity"]}
		proof := model.Clone(p)
		proof["usage_account_id"] = target.Binding.AccountID
		if e = evidence.ValidateSourceProofV3(proof, binding, maxTime(left, out.Baseline.Start), minTime(right, end), false); e != nil {
			return unavailable(out, e.Error()), nil
		}
		job := s.jobs[model.String(receipt, "id")]
		for _, r := range rows(object(job["raw"])["records"]) {
			records = append(records, r)
		}
		out.BillingSourceRefs = append(out.BillingSourceRefs, SourceRef{model.String(receipt, "id"), model.String(receipt, "revision_id"), model.String(job, "id"), model.String(receipt, "raw_hash"), model.String(receipt, "canonical_hash"), left, right})
	}
	if cursor.Before(end) {
		return unavailable(out, "PRICE_BILLING_PERIOD_GAP"), nil
	}
	out.EconomicScopeHash = economicHash(records, out.Baseline)
	if e = portfolioSafe(records, out.Baseline); e != nil {
		return unavailable(out, e.Error()), nil
	}
	out.Old, e = summarizeRates(records, oldMachines, oldT, out.Baseline, target.Binding.AccountID, target.Binding.Region, currency, true)
	if e != nil {
		return unavailable(out, e.Error()), nil
	}
	candidatePeriod := Period{end.AddDate(0, 0, -1), end}
	var candidateErr error
	for _, m := range candidateMachines {
		rate, e := summarizeRates(records, []NativeMachine{m}, candidateT, candidatePeriod, target.Binding.AccountID, target.Binding.Region, currency, false)
		if e != nil {
			if e.Error() != "PRICE_CANDIDATE_ACCOUNT_RATE_UNAVAILABLE" {
				return unavailable(out, e.Error()), nil
			}
			candidateErr = e
			continue
		}
		if out.Candidate.ObservedHourlyRate != nil && (Hash(out.Candidate.Dimensions) != Hash(rate.Dimensions) || *out.Candidate.ObservedHourlyRate != *rate.ObservedHourlyRate) {
			return unavailable(out, "PRICE_CANDIDATE_NATIVE_RATE_AMBIGUOUS"), nil
		}
		out.Candidate = rate
		out.HardwareReceiptIDs = append(out.HardwareReceiptIDs, m.HardwareReceiptID)
	}
	if out.Candidate.ObservedHourlyRate == nil {
		if candidateErr == nil {
			candidateErr = errors.New("PRICE_CANDIDATE_ACCOUNT_RATE_UNAVAILABLE")
		}
		return unavailable(out, candidateErr.Error()), nil
	}
	sort.Strings(out.HardwareReceiptIDs)
	unique := []string{}
	for _, id := range out.HardwareReceiptIDs {
		if len(unique) == 0 || unique[len(unique)-1] != id {
			unique = append(unique, id)
		}
	}
	out.HardwareReceiptIDs = unique
	// Re-read current authority after external object I/O. Publication and source
	// revocation share the dependency guard; no stale capture can race a revoke.
	e = b.Store.Do(ctx, tenant, func(tx *store.Tx) error {
		if _, e := tx.Exec(ctx, "SELECT fleet_billing_source_lock($1,$2)", tenant, target.SourceID); e != nil {
			return e
		}
		current, e := load(ctx, tx, target, b.now())
		if e != nil {
			return e
		}
		if resolutionHash(current) != resolutionHash(s) {
			return errors.New("PRICE_AUTHORITY_CHANGED_DURING_CAPTURE")
		}
		if out.ValidUntil.Before(b.now().Add(programDuration)) {
			return errors.New("PRICE_EVIDENCE_HORIZON_SHORTER_THAN_PROGRAM")
		}
		out.Status = "READY"
		out.ReasonCodes = []string{"CONDITIONAL_HISTORICAL_ACCOUNT_RATE", "EXECUTION_AUTHORITY_NOT_GRANTED", "NO_PROVIDER_FUTURE_PRICE_GUARANTEE", "WORKLOAD_ATTRIBUTION_NOT_PROVEN"}
		out.ID = "fleet-price-" + Hash(out)
		return insert(ctx, tx, out)
	})
	if e != nil {
		return captureFailure(out, e)
	}
	return out, nil
}
func captureFailure(out Evidence, e error) (Evidence, error) {
	if reasonCodePattern.MatchString(e.Error()) {
		return unavailable(out, e.Error()), nil
	}
	return unavailable(out, "PRICE_EVIDENCE_UNAVAILABLE"), e
}
func resolutionHash(s resolved) string {
	return Hash(model.Document{"registration_config": source.ConfigurationHash(s.registration), "inventory": s.inventory, "membership": s.membership["id"], "templates": s.templates["id"], "hardware": s.hardware, "billing": s.billing, "commitment": s.commitment["id"]})
}
func configuration(d model.Document) model.Document {
	out := model.Document{}
	for _, k := range []string{"kind", "payer_account_id", "usage_account_ids", "region", "export_arn", "bucket", "bucket_owner", "prefix", "read_role_binding_id"} {
		out[k] = d[k]
	}
	ids := append([]string{}, model.Strings(d, "usage_account_ids")...)
	sort.Strings(ids)
	out["usage_account_ids"] = ids
	return out
}
func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
func maxTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}
