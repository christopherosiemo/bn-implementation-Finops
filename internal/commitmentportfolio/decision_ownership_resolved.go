package commitmentportfolio

import "time"

// DecisionResolvedOwnership is a private normalized view over an actual issued
// live-journal OR historical-archive aggregate. The SQL resolver authenticates
// the exact immutable Reference and repeats source/key/current-scope checks.
// Constructing this Go value or satisfying its hashes does not authenticate it.
// ObservedAt is the resolver's current authority-check time; the immutable
// aggregate retains its original capture/assessment timestamps separately.
type DecisionResolvedOwnership struct {
	Scope            DecisionOwnershipScope             `json:"scope"`
	ScopeSHA256      string                             `json:"scope_sha256"`
	Period           Period                             `json:"period"`
	Basis            string                             `json:"basis"`
	Reference        Ref                                `json:"reference"`
	InputRefs        []Ref                              `json:"input_refs"`
	ObservedAt       time.Time                          `json:"observed_at"`
	RegistrationPins []DecisionOwnershipRegistrationPin `json:"registration_pins"`
}

func validateResolvedDecisionOwnership(value DecisionResolvedOwnership, scope DecisionOwnershipScope, period Period, now time.Time) error {
	if !ownershipScope(scope) || Hash(value.Scope) != Hash(scope) || value.ScopeSHA256 != Hash(scope) || !ownershipPeriod(value.Period) || value.Period.Start.After(period.Start) || value.Period.End.Before(period.End) || !ownershipRef(value.Reference, "HISTORICAL_OWNERSHIP") || value.Basis != DecisionOwnershipBasis && value.Basis != DecisionOwnershipArchiveBasis || !ownershipUTC(value.ObservedAt) || value.ObservedAt.After(now) || now.Sub(value.ObservedAt) > 5*time.Minute || value.InputRefs == nil || len(value.InputRefs) > 128 || len(value.RegistrationPins) < 2 || len(value.RegistrationPins) > 128 {
		return ErrDecisionOwnershipEvidence
	}
	seen := map[string]bool{}
	for _, pin := range value.RegistrationPins {
		if !idPattern.MatchString(pin.ID) || pin.Revision < 1 || !shaPattern.MatchString(pin.SHA256) || seen[pin.ID] {
			return ErrDecisionOwnershipEvidence
		}
		seen[pin.ID] = true
	}
	refs, err := decisionRefs(value.InputRefs)
	if err != nil || Hash(refs) != Hash(value.InputRefs) {
		return ErrDecisionOwnershipEvidence
	}
	return nil
}
