package commitmentportfolio

import (
	"math/big"
	"regexp"
	"sort"
)

var resultDecimal = regexp.MustCompile(`^-?(0|[1-9][0-9]{0,25})(\.[0-9]{1,12})?$`)

func numberValue(p *string, signed, fraction bool) (*big.Rat, error) {
	if p == nil {
		return nil, nil
	}
	if !resultDecimal.MatchString(*p) {
		return nil, ErrEvidence
	}
	r, okay := new(big.Rat).SetString(*p)
	if !okay || !signed && r.Sign() < 0 || fraction && (r.Sign() < 0 || r.Cmp(big.NewRat(1, 1)) > 0) {
		return nil, ErrEvidence
	}
	return r, nil
}
func reasonList(values []string) bool {
	if values == nil || len(values) > 256 {
		return false
	}
	for _, v := range values {
		if v == "" || len(v) > 1024 {
			return false
		}
	}
	return true
}
func sameAmount(a, b *string) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	x, e := numberValue(a, true, false)
	if e != nil {
		return false
	}
	y, e := numberValue(b, true, false)
	return e == nil && x.Cmp(y) == 0
}
func summedAmount(values []*string) (*string, error) {
	r := new(big.Rat)
	for _, v := range values {
		if v == nil {
			return nil, nil
		}
		n, e := numberValue(v, true, false)
		if e != nil {
			return nil, e
		}
		r.Add(r, n)
	}
	s := r.FloatString(12)
	if _, e := numberValue(&s, true, false); e != nil {
		return nil, e
	}
	return &s, nil
}
func partitionKey(class string, currency *string, account string, region, family *string) string {
	return Hash([]any{class, currency, account, region, family})
}
func validateAnalysis(in Input, out Analysis) error {
	if out.SchemaVersion != "1" || out.RequestID != in.RequestID || Hash(out.Selection) != Hash(in.Selection) || Hash(out.InputRefs) != Hash(in.InputRefs) || !out.ObservedAt.Equal(in.ObservedAt) || out.InventoryStatus != in.InventoryStatus || out.BillingStatus != in.BillingStatus || out.RecommendationStatus != "BLOCKED" || out.RecommendationAuthorized || out.PurchaseAuthorized || out.ExecutionAuthorized || out.ExpectedSavings != nil || out.EstimatedSaving != nil || out.VerifiedSaving != nil || out.Positions == nil || out.Partitions == nil || out.UnmatchedBilling == nil || len(out.Positions) != len(in.Positions) || len(out.OptimizationOrder) != 5 || !reasonList(out.ReasonCodes) || !shaPattern.MatchString(out.ID) {
		return ErrEvidence
	}
	identity := out
	identity.ID = ""
	if Hash(identity) != out.ID {
		return ErrEvidence
	}
	groups := map[string][]PositionAnalysis{}
	known := map[string]bool{}
	for i, p := range out.Positions {
		if Hash(p.Position) != Hash(in.Positions[i]) || p.Coverage != nil || p.EffectiveDiscount != nil || p.BreakEvenUtilization != nil || p.RemainingValue != nil || p.CashRequirement != nil || p.ExpectedUtilization != nil || p.ConfidenceInterval != nil || p.Status != "OBSERVED_PARTIAL" && p.Status != "UNKNOWN" || !reasonList(p.ReasonCodes) {
			return ErrEvidence
		}
		for _, v := range []*string{p.ObservedAllocatedCost, p.ObservedCommittedCost, p.ObservedUsedCommitment, p.ObservedUnusedCommitment, p.DownsideIfZeroUsageObservedWindow} {
			if _, e := numberValue(v, false, false); e != nil {
				return e
			}
		}
		if _, e := numberValue(p.ObservedBilledCost, true, false); e != nil {
			return e
		}
		if _, e := numberValue(p.Utilization, false, true); e != nil {
			return e
		}
		if p.Expiry.WithinDays != 30 || p.Expiry.Status != "ACTIVE" && p.Expiry.Status != "EXPIRED" && p.Expiry.Status != "NOT_STARTED" && p.Expiry.Status != "UNKNOWN" {
			return ErrEvidence
		}
		if _, e := numberValue(p.Expiry.RemainingSeconds, false, false); e != nil {
			return e
		}
		if p.Expiry.Status == "UNKNOWN" && (p.Expiry.RemainingSeconds != nil || p.Expiry.ExpiresWithinWindow != nil) {
			return ErrEvidence
		}
		if p.AllocatedCostBasis != nil && !allocationBasis(*p.AllocatedCostBasis) || p.ObservedAllocatedCost != nil && p.AllocatedCostBasis == nil || p.CommitmentCostBasis != "NATIVE_SP_HOURLY_TOTAL_AND_USED_COMMITMENT" && p.CommitmentCostBasis != "UNAVAILABLE" {
			return ErrEvidence
		}
		if p.CommitmentCostBasis == "UNAVAILABLE" && (p.ObservedCommittedCost != nil || p.ObservedUsedCommitment != nil || p.ObservedUnusedCommitment != nil || p.Utilization != nil || p.DownsideIfZeroUsageObservedWindow != nil) {
			return ErrEvidence
		}
		if p.ObservedCommittedCost != nil {
			total, _ := numberValue(p.ObservedCommittedCost, false, false)
			used, _ := numberValue(p.ObservedUsedCommitment, false, false)
			unused, _ := numberValue(p.ObservedUnusedCommitment, false, false)
			if used == nil || unused == nil || used.Cmp(total) > 0 || new(big.Rat).Add(used, unused).Cmp(total) != 0 || !sameAmount(p.DownsideIfZeroUsageObservedWindow, p.ObservedCommittedCost) || total.Sign() == 0 && p.Utilization != nil {
				return ErrEvidence
			}
		}
		key := partitionKey(p.Position.Class, p.Position.Currency, p.Position.AccountID, p.Position.Region, p.Position.InstanceFamily)
		groups[key] = append(groups[key], p)
		known[p.Position.ID] = true
	}
	if len(out.Partitions) != len(groups) {
		return ErrEvidence
	}
	seen := map[string]bool{}
	for _, p := range out.Partitions {
		key := partitionKey(p.Class, p.Currency, p.AccountID, p.Region, p.InstanceFamily)
		members, okay := groups[key]
		if !okay || seen[key] || p.PositionIDs == nil || p.PositionShares == nil || p.ExpiringPositionIDs == nil || p.PositionCount != len(members) || p.HourlyCommitmentRateUnit != "currency/hour" || p.ConcentrationBasis != "NATIVE_HOURLY_COMMITMENT_RATE" {
			return ErrEvidence
		}
		seen[key] = true
		expected := []string{}
		expires := []string{}
		for _, m := range members {
			expected = append(expected, m.Position.ID)
			if m.Expiry.ExpiresWithinWindow != nil && *m.Expiry.ExpiresWithinWindow {
				expires = append(expires, m.Position.ID)
			}
		}
		sort.Strings(expected)
		sort.Strings(expires)
		if Hash(expected) != Hash(p.PositionIDs) || Hash(expires) != Hash(p.ExpiringPositionIDs) || len(p.PositionShares) != len(expected) {
			return ErrEvidence
		}
		for i, s := range p.PositionShares {
			if s.PositionID != expected[i] {
				return ErrEvidence
			}
			if _, e := numberValue(s.Share, false, true); e != nil {
				return e
			}
			if p.HourlyCommitmentRate == nil && s.Share != nil {
				return ErrEvidence
			}
		}
		fields := []func(PositionAnalysis) *string{func(v PositionAnalysis) *string { return v.ObservedBilledCost }, func(v PositionAnalysis) *string { return v.ObservedCommittedCost }, func(v PositionAnalysis) *string { return v.ObservedUsedCommitment }, func(v PositionAnalysis) *string { return v.ObservedUnusedCommitment }}
		actual := []*string{p.ObservedBilledCost, p.ObservedCommittedCost, p.ObservedUsedCommitment, p.ObservedUnusedCommitment}
		for i, get := range fields {
			values := []*string{}
			for _, m := range members {
				values = append(values, get(m))
			}
			expected, e := summedAmount(values)
			if e != nil || !sameAmount(expected, actual[i]) {
				return ErrEvidence
			}
		}
		if _, e := numberValue(p.Utilization, false, true); e != nil {
			return e
		}
		if _, e := numberValue(p.HourlyCommitmentRate, false, false); e != nil {
			return e
		}
	}
	stages := []string{"REMOVE_IDLE", "SCHEDULE", "RIGHTSIZE", "AUTOSCALE", "RECALCULATE_STABLE_DEMAND"}
	for i, s := range out.OptimizationOrder {
		if s.Stage != stages[i] || s.Status != "BLOCKED" || s.DecisionRef != nil || s.OutcomeRef != nil || s.ScopeSHA256 != nil || !reasonList(s.ReasonCodes) {
			return ErrEvidence
		}
	}
	unmatched := map[string][]BillingLine{}
	for _, line := range in.Billing {
		if !known[line.CommitmentID] {
			key := Hash([]string{line.CommitmentID, line.AccountID, line.Currency})
			unmatched[key] = append(unmatched[key], line)
		}
	}
	if len(out.UnmatchedBilling) != len(unmatched) {
		return ErrEvidence
	}
	seen = map[string]bool{}
	for _, u := range out.UnmatchedBilling {
		key := Hash([]string{u.CommitmentID, u.AccountID, u.Currency})
		lines, okay := unmatched[key]
		if !okay || seen[key] || u.LineIDs == nil || len(u.LineIDs) != len(lines) || Hash(u.ReasonCodes) != Hash([]string{"COMMITMENT_NOT_IN_SELECTED_NATIVE_POINT"}) {
			return ErrEvidence
		}
		seen[key] = true
		ids := []string{}
		for _, line := range lines {
			ids = append(ids, line.ID)
		}
		sort.Strings(ids)
		if Hash(ids) != Hash(u.LineIDs) {
			return ErrEvidence
		}
		if _, e := numberValue(u.ObservedBilledCost, true, false); e != nil {
			return e
		}
		if in.BillingStatus != "COMPLETE_OBSERVED_WINDOW" && u.ObservedBilledCost != nil {
			return ErrEvidence
		}
	}
	return nil
}
func allocationBasis(s string) bool {
	return s == "NET_SP_EFFECTIVE" || s == "SP_EFFECTIVE" || s == "NET_RI_EFFECTIVE" || s == "RI_EFFECTIVE"
}
