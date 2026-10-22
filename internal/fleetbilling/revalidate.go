package fleetbilling

import (
	"context"
	"errors"
	"sort"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/evidence"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/source"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
)

// Revalidate loads the issued immutable ID, not caller-provided prices. The
// original validity horizon is never extended. Current native source and payer
// commitment authority must still be fresh even when the snapshot is hours old.
// A successful result remains private evidence, not dispatch permission.
func (b *Broker) Revalidate(ctx context.Context, tenant, id string, programEnd time.Time) error {
	if b.Store == nil || b.Archive == nil {
		return errors.New("PRICE_BROKER_DEPENDENCIES_REQUIRED")
	}
	now := b.now()
	var issued Evidence
	var current resolved
	var pinnedTemplates, pinnedMembership model.Document
	pinnedHardware := []model.Document{}
	err := b.Store.Do(ctx, tenant, func(tx *store.Tx) error {
		var e error
		issued, e = Get(ctx, tx, id)
		if e != nil {
			return e
		}
		target, ok := b.Targets[tenant+":"+issued.Binding.ResourceID]
		if !ok || target.Binding != issued.Binding || issued.SourceConnectionID != target.SourceID {
			return errors.New("PRICE_APPROVED_TARGET_CHANGED")
		}
		if issued.Status != "READY" || issued.ExecutionAuthorized || issued.HardSpendCap || issued.VerifiedSaving != nil || !programEnd.After(now) || programEnd.After(issued.ValidUntil) || issued.ObservedAt.After(now.Add(30*time.Second)) {
			return errors.New("PRICE_EVIDENCE_EXPIRED_OR_UNSAFE")
		}
		current, e = load(ctx, tx, target, now)
		if e != nil {
			return e
		}
		if source.ConfigurationHash(current.registration) != issued.SourceConfigHash {
			return errors.New("PRICE_SOURCE_CONFIGURATION_CHANGED")
		}
		if known := model.String(current.inventory, "currency"); known != "" && (issued.Old.Dimensions == nil || issued.Old.Dimensions.Currency != known) {
			return errors.New("PRICE_RESOURCE_CURRENCY_MISMATCH")
		}
		pinnedTemplates, e = tx.SourceReceiptGet(ctx, issued.LaunchTemplatesReceiptID)
		if e != nil {
			return e
		}
		pinnedMembership, e = tx.SourceReceiptGet(ctx, issued.MembershipReceiptID)
		if e != nil {
			return e
		}
		for _, id := range issued.HardwareReceiptIDs {
			d, e := tx.SourceReceiptGet(ctx, id)
			if e != nil {
				return e
			}
			pinnedHardware = append(pinnedHardware, d)
		}
		return nil
	})
	if err != nil {
		return err
	}
	target := b.Targets[tenant+":"+issued.Binding.ResourceID]
	raw, e := b.read(ctx, target, current.membership)
	if e != nil {
		return e
	}
	old, candidate, e := parseMembership(current.membership, raw, target)
	if e != nil {
		return e
	}
	ids := []string{}
	for _, m := range old.Members {
		ids = append(ids, m.InstanceID)
	}
	sort.Strings(ids)
	if Hash(ids) != issued.Old.MemberIDsHash {
		return errors.New("PRICE_CURRENT_MEMBERS_CHANGED")
	}
	raw, e = b.read(ctx, target, pinnedMembership)
	if e != nil {
		return e
	}
	previousOld, previousCandidate, e := parseMembership(pinnedMembership, raw, target)
	if e != nil {
		return e
	}
	if Hash(old.Subnets) != Hash(previousOld.Subnets) || Hash(candidate.Subnets) != Hash(previousCandidate.Subnets) {
		return errors.New("PRICE_NATIVE_TARGET_NETWORK_CHANGED")
	}
	raw, e = b.read(ctx, target, current.templates)
	if e != nil {
		return e
	}
	templates, e := parseTemplates(current.templates, raw)
	if e != nil {
		return e
	}
	raw, e = b.read(ctx, target, pinnedTemplates)
	if e != nil {
		return e
	}
	oldTemplates, e := parseTemplates(pinnedTemplates, raw)
	if e != nil {
		return e
	}
	if Hash(templates) != Hash(oldTemplates) {
		return errors.New("PRICE_NATIVE_TEMPLATE_CHANGED")
	}
	live := map[string]NativeMachine{}
	for _, d := range current.hardware {
		raw, e := b.read(ctx, target, d)
		if e != nil {
			return e
		}
		machine, e := parseHardware(d, raw, target.Binding.AccountID, target.Binding.Region)
		if e == nil {
			live[machine.InstanceID] = machine
		}
	}
	for _, d := range pinnedHardware {
		raw, e := b.read(ctx, target, d)
		if e != nil {
			return e
		}
		previous, e := parseHardware(d, raw, target.Binding.AccountID, target.Binding.Region)
		if e != nil {
			return e
		}
		actual, ok := live[previous.InstanceID]
		previous.HardwareReceiptID = ""
		actual.HardwareReceiptID = ""
		if !ok || actual != previous {
			return errors.New("PRICE_NATIVE_MACHINE_CHANGED_OR_STALE")
		}
	}
	records := []model.Document{}
	if issued.Old.Dimensions == nil {
		return errors.New("PRICE_IMMUTABLE_DIMENSIONS_REQUIRED")
	}
	if err := checkBillingScope(current, issued.Baseline, target, issued.Old.Dimensions.Currency); err != nil {
		return err
	}
	for _, r := range current.billing {
		p := object(r["source_proof"])
		if stamp(p, "period_start").Before(issued.Baseline.End) && stamp(p, "period_end").After(issued.Baseline.Start) {
			records = append(records, rows(object(current.jobs[model.String(r, "id")]["raw"])["records"])...)
		}
	}
	if economicHash(records, issued.Baseline) != issued.EconomicScopeHash {
		return errors.New("PRICE_PAYER_ECONOMIC_SCOPE_CHANGED")
	}
	if e = portfolioSafe(records, issued.Baseline); e != nil {
		return e
	}
	// Serialize the final authority check with source revocation. No price row is
	// mutated or renewed, and no provider/executor action is performed here.
	return b.Store.Do(ctx, tenant, func(tx *store.Tx) error {
		if _, e := tx.Exec(ctx, "SELECT fleet_billing_source_lock($1,$2)", tenant, target.SourceID); e != nil {
			return e
		}
		finalNow := b.now()
		if !programEnd.After(finalNow) || !issued.ValidUntil.After(finalNow) || programEnd.After(issued.ValidUntil) {
			return errors.New("PRICE_EVIDENCE_EXPIRED_OR_UNSAFE")
		}
		latest, e := load(ctx, tx, target, finalNow)
		if e != nil {
			return e
		}
		if resolutionHash(latest) != resolutionHash(current) {
			return errors.New("PRICE_AUTHORITY_CHANGED_DURING_VALIDATION")
		}
		finalNow = b.now()
		if !programEnd.After(finalNow) || !issued.ValidUntil.After(finalNow) || programEnd.After(issued.ValidUntil) {
			return errors.New("PRICE_EVIDENCE_EXPIRED_OR_UNSAFE")
		}
		return nil
	})
}

func checkBillingScope(s resolved, period Period, target Target, currency string) error {
	cursor := period.Start
	for _, receipt := range s.billing {
		p := object(receipt["source_proof"])
		left, right := stamp(p, "period_start"), stamp(p, "period_end")
		if !left.Before(period.End) || !right.After(period.Start) {
			continue
		}
		if left.After(cursor) {
			return errors.New("PRICE_BILLING_PERIOD_GAP")
		}
		if right.After(cursor) {
			cursor = right
		}
		if model.String(p, "currency") != currency {
			return errors.New("PRICE_CURRENCY_SCOPE_AMBIGUOUS")
		}
		approved := false
		for _, id := range model.Strings(p, "usage_account_ids") {
			approved = approved || id == target.Binding.AccountID
		}
		if !approved {
			return errors.New("PRICE_BILLING_ACCOUNT_SCOPE_UNPROVEN")
		}
		binding := model.Document{"payer_account_id": s.registration["payer_account_id"], "account_id": target.Binding.AccountID, "region": target.Binding.Region, "currency": currency, "invoice_entity": p["invoice_entity"]}
		proof := model.Clone(p)
		proof["usage_account_id"] = target.Binding.AccountID
		if e := evidence.ValidateSourceProofV3(proof, binding, maxTime(left, period.Start), minTime(right, period.End), false); e != nil {
			return e
		}
	}
	if cursor.Before(period.End) {
		return errors.New("PRICE_BILLING_PERIOD_GAP")
	}
	return nil
}
