// Package allocation computes a current-ownership view of observed BilledCost.
// It neither changes native billing nor proves historical ownership, finality,
// avoidable expenditure or savings. Source authenticity belongs to its broker.
package allocation

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"regexp"
	"sort"
	"strings"
)

const MaxRecords = 5000
const MaxAllocations = 25000
const Basis = "CURRENT_OWNERSHIP_VIEW"

var identifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)
var currency = regexp.MustCompile(`^[A-Z]{3}$`)
var decimal = regexp.MustCompile(`^-?(0|[1-9][0-9]{0,25})(\.[0-9]{1,12})?$`)

type Recipient struct {
	WorkloadID string `json:"workload_id"`
	WeightPPM  int64  `json:"weight_ppm"`
}
type Rule struct {
	ResourceIDs []string    `json:"resource_ids"`
	Recipients  []Recipient `json:"recipients"`
}
type Policy struct {
	SchemaVersion string `json:"schema_version"`
	Name          string `json:"name"`
	Rules         []Rule `json:"rules"`
}
type Resource struct {
	ID, Provider, AccountID, Region, ProviderResourceID, WorkloadID string
	Version                                                         int64
}
type Record struct {
	ID                 string  `json:"record_id"`
	SourceID           string  `json:"source_id"`
	SourceVersion      string  `json:"source_version"`
	Provider           string  `json:"provider"`
	AccountID          string  `json:"account_id"`
	Region             string  `json:"region"`
	ProviderResourceID string  `json:"provider_resource_id"`
	Currency           string  `json:"currency"`
	BilledCost         *string `json:"observed_billed_cost"`
}
type Line struct {
	RecordID            string  `json:"record_id"`
	SourceID            string  `json:"source_id"`
	SourceVersion       string  `json:"source_version"`
	ResourceID          *string `json:"resource_id"`
	ProviderResourceID  string  `json:"provider_resource_id"`
	WorkloadID          *string `json:"workload_id"`
	Currency            string  `json:"currency"`
	AllocatedBilledCost *string `json:"allocated_billed_cost"`
	Method              string  `json:"method"`
	ReasonCode          string  `json:"reason_code"`
}
type Total struct {
	Currency            string  `json:"currency"`
	ObservedBilledTotal *string `json:"observed_billed_total"`
	KnownBilledSubtotal string  `json:"known_billed_subtotal"`
	AllocatedSubtotal   string  `json:"allocated_subtotal"`
	UnallocatedSubtotal string  `json:"unallocated_subtotal"`
	UnknownRecordCount  int     `json:"unknown_record_count"`
}
type Result struct {
	SchemaVersion       string   `json:"schema_version"`
	Basis               string   `json:"basis"`
	Status              string   `json:"status"`
	ReasonCodes         []string `json:"reason_codes"`
	RecordCount         int      `json:"record_count"`
	Lines               []Line   `json:"lines"`
	ObservedRecords     []Record `json:"observed_records"`
	Totals              []Total  `json:"totals"`
	ExecutionAuthorized bool     `json:"execution_authorized"`
	VerifiedSaving      *string  `json:"verified_saving"`
}

func Digest(v any) string {
	raw, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
func validID(value string) bool { return identifier.MatchString(value) }

func ValidatePolicy(p Policy) error {
	if p.SchemaVersion != "1" || strings.TrimSpace(p.Name) == "" || len([]rune(p.Name)) > 80 || p.Rules == nil || len(p.Rules) > 100 {
		return errors.New("ALLOCATION_POLICY_INVALID")
	}
	seen, count := map[string]bool{}, 0
	for _, rule := range p.Rules {
		if len(rule.ResourceIDs) == 0 || len(rule.ResourceIDs) > 256 || len(rule.Recipients) == 0 || len(rule.Recipients) > 100 {
			return errors.New("ALLOCATION_RULE_INVALID")
		}
		for _, id := range rule.ResourceIDs {
			if !validID(id) || seen[id] {
				return errors.New("ALLOCATION_RESOURCE_SELECTOR_OVERLAP_OR_INVALID")
			}
			seen[id] = true
			count++
		}
		if count > 1024 {
			return errors.New("ALLOCATION_POLICY_RESOURCE_LIMIT")
		}
		weights, recipients := int64(0), map[string]bool{}
		for _, target := range rule.Recipients {
			if !validID(target.WorkloadID) || target.WeightPPM < 1 || target.WeightPPM > 1000000 || recipients[target.WorkloadID] {
				return errors.New("ALLOCATION_RECIPIENT_INVALID")
			}
			weights += target.WeightPPM
			recipients[target.WorkloadID] = true
		}
		if weights != 1000000 {
			return errors.New("ALLOCATION_WEIGHTS_MUST_SUM_ONE_MILLION")
		}
	}
	return nil
}

func parseUnits(value string) (*big.Int, error) {
	if !decimal.MatchString(value) {
		return nil, errors.New("ALLOCATION_DECIMAL_38_12_REQUIRED")
	}
	negative := strings.HasPrefix(value, "-")
	value = strings.TrimPrefix(value, "-")
	parts := strings.SplitN(value, ".", 2)
	fraction := ""
	if len(parts) == 2 {
		fraction = parts[1]
	}
	n, ok := new(big.Int).SetString(parts[0]+fraction+strings.Repeat("0", 12-len(fraction)), 10)
	if !ok {
		return nil, errors.New("ALLOCATION_DECIMAL_38_12_REQUIRED")
	}
	if negative {
		n.Neg(n)
	}
	return n, nil
}
func formatUnits(n *big.Int) (string, error) {
	a := new(big.Int).Abs(n).String()
	if len(a) > 38 {
		return "", errors.New("ALLOCATION_DECIMAL_TOTAL_OVERFLOW")
	}
	if len(a) < 13 {
		a = strings.Repeat("0", 13-len(a)) + a
	}
	sign := ""
	if n.Sign() < 0 {
		sign = "-"
	}
	return sign + a[:len(a)-12] + "." + a[len(a)-12:], nil
}
func str(value string) *string { return &value }
func resourceKey(provider, account, region, id string) string {
	return Digest([]string{provider, account, region, id})
}

type share struct {
	id                string
	amount, remainder *big.Int
}

func split(n *big.Int, recipients []Recipient) []share {
	abs, denominator := new(big.Int).Abs(n), big.NewInt(1000000)
	left := new(big.Int).Set(abs)
	out := make([]share, 0, len(recipients))
	for _, target := range recipients {
		q, r := new(big.Int), new(big.Int)
		q.QuoRem(new(big.Int).Mul(abs, big.NewInt(target.WeightPPM)), denominator, r)
		left.Sub(left, q)
		out = append(out, share{target.WorkloadID, q, r})
	}
	sort.Slice(out, func(i, j int) bool {
		if c := out[i].remainder.Cmp(out[j].remainder); c != 0 {
			return c > 0
		}
		return out[i].id < out[j].id
	})
	for i := int64(0); i < left.Int64(); i++ {
		out[i].amount.Add(out[i].amount, big.NewInt(1))
	}
	if n.Sign() < 0 {
		for i := range out {
			out[i].amount.Neg(out[i].amount)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].id < out[j].id })
	return out
}

// Evaluate conserves every known source amount, including negative credits.
// Unknown costs remain null. A policy may reassign current analytical ownership,
// but this result is never historical workload or verification evidence.
func Evaluate(p Policy, records []Record, resources []Resource, workloads []string) (Result, error) {
	out := Result{SchemaVersion: "1", Basis: Basis, Status: "ALLOCATED_OBSERVATIONS", ReasonCodes: []string{"PROVISIONAL_ALLOCATION_ONLY", "HISTORICAL_OWNERSHIP_NOT_ASSERTED", "VERIFIED_SAVINGS_NOT_ASSERTED"}, Lines: []Line{}, ObservedRecords: []Record{}, Totals: []Total{}, RecordCount: len(records)}
	if err := ValidatePolicy(p); err != nil {
		return out, err
	}
	if len(records) > MaxRecords {
		return out, errors.New("ALLOCATION_RECORD_LIMIT")
	}
	knownWorkloads := map[string]bool{}
	for _, id := range workloads {
		if !validID(id) || knownWorkloads[id] {
			return out, errors.New("ALLOCATION_WORKLOAD_CATALOG_INVALID")
		}
		knownWorkloads[id] = true
	}
	byKey, byID := map[string]Resource{}, map[string]Resource{}
	for _, r := range resources {
		key := resourceKey(r.Provider, r.AccountID, r.Region, r.ProviderResourceID)
		if !validID(r.ID) || r.Provider == "" || r.AccountID == "" || r.ProviderResourceID == "" || r.Version < 1 || byKey[key].ID != "" || byID[r.ID].ID != "" {
			return out, errors.New("ALLOCATION_RESOURCE_CATALOG_INVALID")
		}
		if r.WorkloadID != "" && !knownWorkloads[r.WorkloadID] {
			return out, errors.New("ALLOCATION_RESOURCE_OWNER_UNKNOWN")
		}
		// An absent region cannot establish a regional provider identity, even
		// when both inventory and billing happen to omit it. Global resources
		// need a later explicit identity-scope contract; never fill this gap.
		if r.Region != "" {
			byKey[key] = r
		}
		byID[r.ID] = r
	}
	rules := map[string][]Recipient{}
	for _, rule := range p.Rules {
		for _, id := range rule.ResourceIDs {
			if byID[id].ID == "" {
				return out, errors.New("ALLOCATION_POLICY_RESOURCE_NOT_FOUND")
			}
			rules[id] = rule.Recipients
		}
		for _, target := range rule.Recipients {
			if !knownWorkloads[target.WorkloadID] {
				return out, errors.New("ALLOCATION_POLICY_WORKLOAD_NOT_FOUND")
			}
		}
	}
	type accumulator struct {
		known, allocated, unallocated *big.Int
		unknown                       int
	}
	totals := map[string]*accumulator{}
	seen := map[string]bool{}
	for _, record := range records {
		if record.ID == "" || record.SourceID == "" || record.SourceVersion == "" || record.Provider == "" || record.AccountID == "" || !currency.MatchString(record.Currency) {
			return out, errors.New("ALLOCATION_RECORD_BINDING_INVALID")
		}
		id := Digest([]string{record.SourceID, record.SourceVersion, record.ID})
		if seen[id] {
			return out, errors.New("ALLOCATION_DUPLICATE_SOURCE_RECORD")
		}
		seen[id] = true
		t := totals[record.Currency]
		if t == nil {
			t = &accumulator{new(big.Int), new(big.Int), new(big.Int), 0}
			totals[record.Currency] = t
		}
		r := byKey[resourceKey(record.Provider, record.AccountID, record.Region, record.ProviderResourceID)]
		out.ObservedRecords = append(out.ObservedRecords, record)
		line := Line{RecordID: record.ID, SourceID: record.SourceID, SourceVersion: record.SourceVersion, ProviderResourceID: record.ProviderResourceID, Currency: record.Currency, Method: "UNALLOCATED", ReasonCode: "RESOURCE_OWNER_UNAVAILABLE"}
		if r.ID != "" {
			line.ResourceID = str(r.ID)
		}
		if record.BilledCost == nil {
			t.unknown++
			line.ReasonCode = "BILLED_COST_UNAVAILABLE"
			out.Lines = append(out.Lines, line)
			if len(out.Lines) > MaxAllocations {
				return out, errors.New("ALLOCATION_OUTPUT_LIMIT")
			}
			continue
		}
		n, err := parseUnits(*record.BilledCost)
		if err != nil {
			return out, err
		}
		t.known.Add(t.known, n)
		targets := rules[r.ID]
		method := "POLICY_FIXED_SHARE"
		if len(targets) == 0 && r.WorkloadID != "" {
			targets = []Recipient{{r.WorkloadID, 1000000}}
			method = "CURRENT_RESOURCE_OWNER"
		}
		if len(targets) == 0 {
			amount, err := formatUnits(n)
			if err != nil {
				return out, err
			}
			line.AllocatedBilledCost = str(amount)
			t.unallocated.Add(t.unallocated, n)
			out.Lines = append(out.Lines, line)
			if len(out.Lines) > MaxAllocations {
				return out, errors.New("ALLOCATION_OUTPUT_LIMIT")
			}
			continue
		}
		for _, part := range split(n, targets) {
			derived := line
			derived.WorkloadID = str(part.id)
			derived.Method = method
			derived.ReasonCode = "CURRENT_POLICY_MAPPING"
			amount, err := formatUnits(part.amount)
			if err != nil {
				return out, err
			}
			derived.AllocatedBilledCost = str(amount)
			out.Lines = append(out.Lines, derived)
			t.allocated.Add(t.allocated, part.amount)
		}
		if len(out.Lines) > MaxAllocations {
			return out, errors.New("ALLOCATION_OUTPUT_LIMIT")
		}
	}
	for code, t := range totals {
		if new(big.Int).Add(t.allocated, t.unallocated).Cmp(t.known) != 0 {
			return out, errors.New("ALLOCATION_CONSERVATION_FAILED")
		}
		known, err := formatUnits(t.known)
		if err != nil {
			return out, err
		}
		allocated, err := formatUnits(t.allocated)
		if err != nil {
			return out, err
		}
		unallocated, err := formatUnits(t.unallocated)
		if err != nil {
			return out, err
		}
		total := Total{Currency: code, KnownBilledSubtotal: known, AllocatedSubtotal: allocated, UnallocatedSubtotal: unallocated, UnknownRecordCount: t.unknown}
		if t.unknown == 0 {
			total.ObservedBilledTotal = str(known)
		} else {
			out.Status = "PARTIAL_OBSERVATIONS"
		}
		out.Totals = append(out.Totals, total)
	}
	if len(records) == 0 {
		out.Status = "NO_OBSERVATIONS"
		out.ReasonCodes = append(out.ReasonCodes, "BILLING_OBSERVATIONS_UNAVAILABLE")
	}
	sort.Slice(out.Totals, func(i, j int) bool { return out.Totals[i].Currency < out.Totals[j].Currency })
	return out, nil
}
