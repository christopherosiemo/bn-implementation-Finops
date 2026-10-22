// Package commitmentportfolio analyses issued observations. These types carry
// no provider purchase, signing, execution or financial-ledger capability.
package commitmentportfolio

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"
)

type Ref struct {
	Kind   string `json:"kind"`
	ID     string `json:"id"`
	SHA256 string `json:"sha256"`
}
type Period struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}
type Selection struct {
	SourceID            string   `json:"source_id"`
	CommitmentReceiptID string   `json:"commitment_receipt_id"`
	BillingReceiptIDs   []string `json:"billing_receipt_ids"`
	Period              Period   `json:"period"`
}
type RIRecurringCharge struct {
	Amount    *string `json:"amount"`
	Frequency *string `json:"frequency"`
}
type ReservedInstanceTerms struct {
	OfferingClass      *string             `json:"offering_class"`
	OfferingType       *string             `json:"offering_type"`
	Scope              *string             `json:"scope"`
	DurationSeconds    *string             `json:"duration_seconds"`
	CurrencyCode       *string             `json:"currency_code"`
	FixedPrice         *string             `json:"fixed_price"`
	UsagePrice         *string             `json:"usage_price"`
	InstanceCount      *string             `json:"instance_count"`
	InstanceType       *string             `json:"instance_type"`
	InstanceTenancy    *string             `json:"instance_tenancy"`
	ProductDescription *string             `json:"product_description"`
	AvailabilityZone   *string             `json:"availability_zone"`
	AvailabilityZoneID *string             `json:"availability_zone_id"`
	RecurringCharges   []RIRecurringCharge `json:"recurring_charges"`
}
type Position struct {
	ReservedInstanceTerms *ReservedInstanceTerms `json:"reserved_instance_terms"`
	ID                    string                 `json:"id"`
	AccountID             string                 `json:"account_id"`
	Class                 string                 `json:"class"`
	State                 string                 `json:"state"`
	Region                *string                `json:"region"`
	InstanceFamily        *string                `json:"instance_family"`
	Currency              *string                `json:"currency"`
	Start                 *time.Time             `json:"start"`
	End                   *time.Time             `json:"end"`
	TermSeconds           *string                `json:"term_seconds"`
	HourlyCommitment      *string                `json:"hourly_commitment"`
	UpfrontAmount         *string                `json:"upfront_amount"`
	RecurringAmount       *string                `json:"recurring_amount"`
	RecurringAmountUnit   string                 `json:"recurring_amount_unit"`
	PaymentOption         *string                `json:"payment_option"`
	NativeRef             Ref                    `json:"native_ref"`
	ReasonCodes           []string               `json:"reason_codes"`
}

// BillingLine is derived from a re-read issued CUR revision. No public route
// accepts it. Total/used commitment retain the provider's per-hour fee basis.
type BillingLine struct {
	ID                 string  `json:"id"`
	CommitmentID       string  `json:"commitment_id"`
	AccountID          string  `json:"account_id"`
	Currency           string  `json:"currency"`
	Kind               string  `json:"kind"`
	Period             Period  `json:"period"`
	BilledCost         string  `json:"billed_cost"`
	AllocatedCost      *string `json:"allocated_cost"`
	AllocatedCostBasis *string `json:"allocated_cost_basis"`
	TotalCommitment    *string `json:"total_commitment"`
	UsedCommitment     *string `json:"used_commitment"`
	NativeRef          Ref     `json:"native_ref"`
}
type OptimizationStage struct {
	Stage       string   `json:"stage"`
	Status      string   `json:"status"`
	DecisionRef *Ref     `json:"decision_ref"`
	OutcomeRef  *Ref     `json:"outcome_ref"`
	ScopeSHA256 *string  `json:"scope_sha256"`
	ReasonCodes []string `json:"reason_codes"`
}
type Input struct {
	SchemaVersion     string              `json:"schema_version"`
	RequestID         string              `json:"request_id"`
	TenantID          string              `json:"tenant_id"`
	PayerAccountID    string              `json:"payer_account_id"`
	UsageAccountIDs   []string            `json:"usage_account_ids"`
	Selection         Selection           `json:"selection"`
	InputRefs         []Ref               `json:"input_refs"`
	InventoryStatus   string              `json:"inventory_status"`
	Positions         []Position          `json:"positions"`
	Billing           []BillingLine       `json:"billing"`
	BillingStatus     string              `json:"billing_status"`
	OptimizationOrder []OptimizationStage `json:"optimization_order"`
	ObservedAt        time.Time           `json:"observed_at"`
}
type Expiry struct {
	Status              string  `json:"status"`
	RemainingSeconds    *string `json:"remaining_seconds"`
	WithinDays          int     `json:"within_days"`
	ExpiresWithinWindow *bool   `json:"expires_within_window"`
}
type PositionShare struct {
	PositionID string  `json:"position_id"`
	Share      *string `json:"share"`
}
type PositionAnalysis struct {
	Expiry                            Expiry   `json:"expiry"`
	Position                          Position `json:"position"`
	ObservedBilledCost                *string  `json:"observed_billed_cost"`
	ObservedAllocatedCost             *string  `json:"observed_allocated_cost"`
	AllocatedCostBasis                *string  `json:"allocated_cost_basis"`
	CommitmentCostBasis               string   `json:"commitment_cost_basis"`
	ObservedCommittedCost             *string  `json:"observed_committed_cost"`
	ObservedUsedCommitment            *string  `json:"observed_used_commitment"`
	ObservedUnusedCommitment          *string  `json:"observed_unused_commitment"`
	Utilization                       *string  `json:"utilization"`
	Coverage                          *string  `json:"coverage"`
	EffectiveDiscount                 *string  `json:"effective_discount"`
	DownsideIfZeroUsageObservedWindow *string  `json:"downside_if_zero_usage_observed_window"`
	BreakEvenUtilization              *string  `json:"break_even_utilization"`
	RemainingValue                    *string  `json:"remaining_value"`
	CashRequirement                   *string  `json:"cash_requirement"`
	ExpectedUtilization               *string  `json:"expected_utilization"`
	ConfidenceInterval                *string  `json:"confidence_interval"`
	Status                            string   `json:"status"`
	ReasonCodes                       []string `json:"reason_codes"`
}
type Partition struct {
	Class                    string          `json:"class"`
	Currency                 *string         `json:"currency"`
	AccountID                string          `json:"account_id"`
	Region                   *string         `json:"region"`
	InstanceFamily           *string         `json:"instance_family"`
	PositionIDs              []string        `json:"position_ids"`
	PositionCount            int             `json:"position_count"`
	ObservedCommittedCost    *string         `json:"observed_committed_cost"`
	ObservedUsedCommitment   *string         `json:"observed_used_commitment"`
	ObservedUnusedCommitment *string         `json:"observed_unused_commitment"`
	Utilization              *string         `json:"utilization"`
	ExpiringPositionIDs      []string        `json:"expiring_position_ids"`
	HourlyCommitmentRate     *string         `json:"hourly_commitment_rate"`
	HourlyCommitmentRateUnit string          `json:"hourly_commitment_rate_unit"`
	PositionShares           []PositionShare `json:"position_shares"`
	ConcentrationBasis       string          `json:"concentration_basis"`
	// No total combines currencies or assumes cross-class reallocation.
	ObservedBilledCost *string `json:"observed_billed_cost"`
}
type UnmatchedBilling struct {
	CommitmentID       string   `json:"commitment_id"`
	AccountID          string   `json:"account_id"`
	Currency           string   `json:"currency"`
	LineIDs            []string `json:"line_ids"`
	ObservedBilledCost *string  `json:"observed_billed_cost"`
	ReasonCodes        []string `json:"reason_codes"`
}
type Analysis struct {
	UnmatchedBilling         []UnmatchedBilling  `json:"unmatched_billing"`
	SchemaVersion            string              `json:"schema_version"`
	ID                       string              `json:"id"`
	RequestID                string              `json:"request_id"`
	Selection                Selection           `json:"selection"`
	InputRefs                []Ref               `json:"input_refs"`
	ObservedAt               time.Time           `json:"observed_at"`
	InventoryStatus          string              `json:"inventory_status"`
	BillingStatus            string              `json:"billing_status"`
	Positions                []PositionAnalysis  `json:"positions"`
	Partitions               []Partition         `json:"partitions"`
	OptimizationOrder        []OptimizationStage `json:"optimization_order"`
	RecommendationStatus     string              `json:"recommendation_status"`
	ReasonCodes              []string            `json:"reason_codes"`
	ExpectedSavings          *string             `json:"expected_savings"`
	EstimatedSaving          *string             `json:"estimated_saving"`
	VerifiedSaving           *string             `json:"verified_saving"`
	RecommendationAuthorized bool                `json:"recommendation_authorized"`
	PurchaseAuthorized       bool                `json:"purchase_authorized"`
	ExecutionAuthorized      bool                `json:"execution_authorized"`
}

func Hash(v any) string {
	b, _ := json.Marshal(v)
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var value any
	if d.Decode(&value) == nil {
		b, _ = json.Marshal(value)
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

type Refusal struct {
	ReasonCode string    `json:"reason_code"`
	ObservedAt time.Time `json:"observed_at"`
}
type Record struct {
	ID                  string    `json:"id"`
	Version             int       `json:"version"`
	CreatorID           string    `json:"creator_id"`
	Status              string    `json:"status"`
	Selection           Selection `json:"selection"`
	InputRefs           []Ref     `json:"input_refs"`
	Analysis            *Analysis `json:"analysis"`
	Refusal             *Refusal  `json:"refusal"`
	CreatedAt           time.Time `json:"created_at"`
	ExecutionAuthorized bool      `json:"execution_authorized"`
	VerifiedSaving      *string   `json:"verified_saving"`
}
