// Package fleetassessment describes group-bound observations and conditional
// rate comparisons. It does not issue capacity, execution or savings authority.
package fleetassessment

import (
	"encoding/json"
	"errors"
	"math/big"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/fleetbilling"
	g "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetgroup"
)

const ScenarioBasis = "LIKE_FOR_LIKE_CURRENT_MEMBER_COUNT"

var number = regexp.MustCompile(`^(0|[1-9][0-9]{0,25})(\.[0-9]{1,12})?$`)
var hash = regexp.MustCompile(`^[a-f0-9]{64}$`)

type Selection struct {
	Groups        fleetbilling.GroupSelection `json:"groups"`
	SafetyProfile g.VersionedRef              `json:"safety_profile"`
}

// A member reference must be independently resolved from its real inventory
// mapping and immutable017 result. One result cannot stand in for a whole ASG.
type MemberAssessment struct {
	InstanceID        string `json:"instance_id"`
	ResourceID        string `json:"resource_id"`
	ResultID          string `json:"result_id"`
	ResultSHA256      string `json:"result_sha256"`
	HardwareReceiptID string `json:"hardware_receipt_id"`
	Status            string `json:"status"`
	DemandMeaning     string `json:"demand_meaning"`
}
type CapacityCoverage struct {
	Status                         string             `json:"status"`
	Members                        []MemberAssessment `json:"members"`
	MissingInstanceIDs             []string           `json:"missing_instance_ids"`
	HistoricalMembership           string             `json:"historical_membership"`
	GroupCapacityAuthorized        bool               `json:"group_capacity_authorized"`
	CompletedBusinessWorkPreserved *bool              `json:"completed_business_work_preserved"`
}
type HourlyScenario struct {
	Status                  string   `json:"status"`
	Basis                   string   `json:"basis"`
	RateBasis               string   `json:"rate_basis"`
	Currency                *string  `json:"currency"`
	MemberCount             int      `json:"member_count"`
	OldHourlyRate           *string  `json:"old_hourly_rate"`
	CandidateHourlyRate     *string  `json:"candidate_hourly_rate"`
	OldHourlyCompute        *string  `json:"old_hourly_compute"`
	CandidateHourlyCompute  *string  `json:"candidate_hourly_compute"`
	HourlyComputeDifference *string  `json:"hourly_compute_difference"`
	ContractedAvoidableCost *string  `json:"contracted_avoidable_cost"`
	EstimatedSaving         *string  `json:"estimated_saving"`
	VerifiedSaving          *string  `json:"verified_saving"`
	HardSpendCap            bool     `json:"hard_spend_cap"`
	ExcludedCosts           []string `json:"excluded_costs"`
}
type Assessment struct {
	SchemaVersion       string                           `json:"schema_version"`
	ID                  string                           `json:"id"`
	Selection           Selection                        `json:"selection"`
	ObservedAt          time.Time                        `json:"observed_at"`
	NativeRates         fleetbilling.GroupNativeEvidence `json:"native_rates"`
	Capacity            CapacityCoverage                 `json:"capacity"`
	Scenario            HourlyScenario                   `json:"scenario"`
	Status              string                           `json:"status"`
	ReasonCodes         []string                         `json:"reason_codes"`
	ExecutionAuthorized bool                             `json:"execution_authorized"`
	ChangePlanID        *string                          `json:"change_plan_id"`
	VerifiedSaving      *string                          `json:"verified_saving"`
}

func exact(n *big.Rat) (string, error) {
	d := new(big.Int).Set(n.Denom())
	two, five := big.NewInt(2), big.NewInt(5)
	a, b := 0, 0
	for new(big.Int).Mod(d, two).Sign() == 0 {
		d.Div(d, two)
		a++
	}
	for new(big.Int).Mod(d, five).Sign() == 0 {
		d.Div(d, five)
		b++
	}
	if d.Cmp(big.NewInt(1)) != 0 || max(a, b) > 12 {
		return "", errors.New("GROUP_SCENARIO_DECIMAL_UNAVAILABLE")
	}
	s := n.FloatString(max(a, b))
	if strings.Contains(s, ".") {
		s = strings.TrimRight(strings.TrimRight(s, "0"), ".")
	}
	if len(strings.TrimPrefix(strings.SplitN(s, ".", 2)[0], "-")) > 26 {
		return "", errors.New("GROUP_SCENARIO_DECIMAL_OVERFLOW")
	}
	return s, nil
}
func rate(text *string) (*big.Rat, error) {
	if text == nil || !number.MatchString(*text) {
		return nil, errors.New("GROUP_SCENARIO_RATE_UNAVAILABLE")
	}
	v, ok := new(big.Rat).SetString(*text)
	if !ok || v.Sign() <= 0 {
		return nil, errors.New("GROUP_SCENARIO_RATE_UNAVAILABLE")
	}
	return v, nil
}
func pointer(s string) *string { return &s }

// Build consumes a privately issued broker result, not caller monetary inputs.
// Selection/currentness and each member-result mapping require repository
// validation before publication; this pure function cannot authenticate origin.
func Build(selection Selection, prices fleetbilling.GroupNativeEvidence, members []MemberAssessment, now time.Time) (Assessment, error) {
	out := Assessment{SchemaVersion: "1", Selection: selection, ObservedAt: now.UTC(), NativeRates: prices, Status: "BLOCKED", ReasonCodes: []string{"EXECUTION_AUTHORITY_NOT_GRANTED", "GROUP_HISTORICAL_INTERVAL_OWNERSHIP_UNPROVEN", "CONFIGURATION_AUTHORITY_NOT_ATTESTED", "GROUP_CAPACITY_AUTHORITY_UNAVAILABLE"}, Capacity: CapacityCoverage{Status: "UNAVAILABLE", Members: []MemberAssessment{}, MissingInstanceIDs: []string{}, HistoricalMembership: "INTERVAL_OWNERSHIP_UNPROVEN"}, Scenario: HourlyScenario{Status: "UNAVAILABLE", Basis: ScenarioBasis, RateBasis: fleetbilling.RateBasis, ExcludedCosts: []string{"EBS", "NETWORK", "IP_ADDRESSES", "SHARED_FEES", "COMMITMENTS", "MIGRATION_AND_OVERLAP", "TAX"}}}
	if fleetbilling.ValidateGroupSelection(selection.Groups) != nil || selection.SafetyProfile.ID == "" || selection.SafetyProfile.Version < 1 || !hash.MatchString(selection.SafetyProfile.SHA256) || g.Digest(selection.Groups) != g.Digest(prices.Selection) || prices.SchemaVersion != "1" || prices.Kind != fleetbilling.GroupNativePriceKind || prices.ExecutionAuthorized || prices.HardSpendCap || prices.VerifiedSaving != nil || prices.ObservedAt.IsZero() || prices.ObservedAt.After(now.Add(5*time.Second)) || prices.ObservedAt.Before(now.Add(-2*time.Minute)) || len(members) > 256 {
		return out, errors.New("GROUP_ASSESSMENT_BINDING_INVALID")
	}
	allowed := map[string]bool{}
	for _, id := range prices.CurrentMemberIDs {
		if id == "" || allowed[id] {
			return out, errors.New("GROUP_ASSESSMENT_MEMBERS_INVALID")
		}
		allowed[id] = true
	}
	seen := map[string]bool{}
	results := map[string]bool{}
	resources := map[string]bool{}
	hardware := map[string]bool{}
	for _, m := range members {
		if !allowed[m.InstanceID] || seen[m.InstanceID] || m.ResourceID == "" || resources[m.ResourceID] || m.ResultID == "" || results[m.ResultID] || !hash.MatchString(m.ResultSHA256) || m.HardwareReceiptID == "" || hardware[m.HardwareReceiptID] || (m.Status != "BLOCKED" && m.Status != "INSUFFICIENT_OBSERVATION") || (m.DemandMeaning != "REQUEST_THROUGHPUT_PROXY" && m.DemandMeaning != "LEGACY_UNPROVEN_PROXY" && m.DemandMeaning != "UNAVAILABLE") {
			return out, errors.New("GROUP_ASSESSMENT_MEMBER_RESULT_INVALID")
		}
		seen[m.InstanceID] = true
		results[m.ResultID] = true
		resources[m.ResourceID] = true
		hardware[m.HardwareReceiptID] = true
		out.Capacity.Members = append(out.Capacity.Members, m)
	}
	sort.Slice(out.Capacity.Members, func(i, j int) bool { return out.Capacity.Members[i].InstanceID < out.Capacity.Members[j].InstanceID })
	for id := range allowed {
		if !seen[id] {
			out.Capacity.MissingInstanceIDs = append(out.Capacity.MissingInstanceIDs, id)
		}
	}
	sort.Strings(out.Capacity.MissingInstanceIDs)
	if len(members) > 0 {
		out.Capacity.Status = "PARTIAL"
		if len(out.Capacity.MissingInstanceIDs) == 0 {
			out.Capacity.Status = "CURRENT_MEMBER_RESULTS_OBSERVED"
		}
	}
	if prices.Status == "OBSERVED_CONDITIONAL" {
		copy := prices
		copy.ID = ""
		if prices.ID != "group-native-rate-"+fleetbilling.Hash(copy) || !prices.ValidUntil.After(now) || len(allowed) == 0 || len(allowed) > 256 || prices.Old.MemberCount != len(allowed) || prices.Old.Dimensions == nil || prices.Candidate.Dimensions == nil || prices.Old.Dimensions.Currency != prices.Candidate.Dimensions.Currency || !regexp.MustCompile(`^[A-Z]{3}$`).MatchString(prices.Old.Dimensions.Currency) || prices.Old.RateBasis != fleetbilling.RateBasis || prices.Candidate.RateBasis != fleetbilling.RateBasis {
			return out, errors.New("GROUP_ASSESSMENT_RATE_RECEIPT_INVALID")
		}
		ids := append([]string{}, prices.CurrentMemberIDs...)
		sort.Strings(ids)
		if prices.Old.MemberIDsHash != fleetbilling.Hash(ids) || prices.Baseline.End.Sub(prices.Baseline.Start) != 14*24*time.Hour || !prices.Baseline.End.Equal(prices.Baseline.End.UTC().Truncate(24*time.Hour)) || prices.Baseline.End.After(prices.ObservedAt) || prices.ObservedAt.Sub(prices.Baseline.End) > 48*time.Hour || prices.ValidUntil.After(prices.ObservedAt.Add(24*time.Hour)) || prices.BaselineScopeBasis != fleetbilling.BaselineScopeBasis || !hash.MatchString(prices.SnapshotSHA256) || len(prices.SourcePins) == 0 || len(prices.BillingSourceRefs) == 0 {
			return out, errors.New("GROUP_ASSESSMENT_NATIVE_SCOPE_INVALID")
		}
		for _, r := range []fleetbilling.Rate{prices.Old, prices.Candidate} {
			d := r.Dimensions
			if d.AccountID != selection.Groups.Binding.Old.Target.AccountID || d.Region != selection.Groups.Binding.Old.Target.Region || d.InstanceType == "" || d.InstanceType != r.InstanceType || d.OperatingSystem != "Linux" || d.Tenancy != "Shared" || d.LicenseModel != "No License required" || d.PreinstalledSoftware != "NA" || d.Operation != "RunInstances" || d.Unit != "Hrs" || (d.CostBasis != "UNBLENDED" && d.CostBasis != "NET_UNBLENDED") || d.SKU == "" || d.UsageType == "" || r.SampleCount < 1 {
				return out, errors.New("GROUP_ASSESSMENT_NATIVE_DIMENSIONS_INVALID")
			}
			if _, e := rate(r.ObservedComputeCost); e != nil {
				return out, e
			}
			if _, e := rate(r.UsageHours); e != nil {
				return out, e
			}
		}
		old, e := rate(prices.Old.ObservedHourlyRate)
		if e != nil {
			return out, e
		}
		candidate, e := rate(prices.Candidate.ObservedHourlyRate)
		if e != nil {
			return out, e
		}
		n := new(big.Rat).SetInt64(int64(len(allowed)))
		oldTotal, e := exact(new(big.Rat).Mul(old, n))
		if e != nil {
			return out, e
		}
		candidateTotal, e := exact(new(big.Rat).Mul(candidate, n))
		if e != nil {
			return out, e
		}
		difference, e := exact(new(big.Rat).Mul(new(big.Rat).Sub(old, candidate), n))
		if e != nil {
			return out, e
		}
		out.Scenario.Status = "OBSERVED_CONDITIONAL"
		out.Scenario.MemberCount = len(allowed)
		out.Scenario.Currency = pointer(prices.Old.Dimensions.Currency)
		out.Scenario.OldHourlyRate = pointer(*prices.Old.ObservedHourlyRate)
		out.Scenario.CandidateHourlyRate = pointer(*prices.Candidate.ObservedHourlyRate)
		out.Scenario.OldHourlyCompute = pointer(oldTotal)
		out.Scenario.CandidateHourlyCompute = pointer(candidateTotal)
		out.Scenario.HourlyComputeDifference = pointer(difference)
	} else if prices.Status != "UNAVAILABLE" {
		return out, errors.New("GROUP_ASSESSMENT_RATE_STATUS_INVALID")
	}
	// Freeze a deep copy: subsequent repository/caller map or pointer mutations
	// must not alter an already returned analytical document or its ID.
	raw, e := json.Marshal(out)
	if e != nil {
		return out, e
	}
	var frozen Assessment
	if e = json.Unmarshal(raw, &frozen); e != nil {
		return out, e
	}
	frozen.ID = "group-native-assessment-" + g.Digest(frozen)
	return frozen, nil
}
