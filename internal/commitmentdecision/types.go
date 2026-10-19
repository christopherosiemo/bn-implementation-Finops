// Package commitmentdecision evaluates server-resolved purchasing advice.
// Neither a recommendation nor its Finance approval grants purchase or
// execution authority. Existing portfolio records and signatures stay intact.
package commitmentdecision

import (
	"time"

	portfolio "github.com/christopherosiemo/bn-implementation-Finops/internal/commitmentportfolio"
)

type Ref = portfolio.Ref
type Period = portfolio.Period

// Selection is the complete public body. Workload identity comes from the
// scoped route. Amounts, trust flags, outcome labels and forecasts are not input.
type Selection struct {
	PortfolioAnalysisRequestID   string `json:"portfolio_analysis_request_id"`
	OfferReceiptID               string `json:"offer_receipt_id"`
	PostOptimizationAssessmentID string `json:"post_optimization_assessment_id"`
	ForecastID                   string `json:"forecast_id"`
}

type Dimensions struct {
	AccountID          string  `json:"account_id"`
	ServiceCode        string  `json:"service_code"`
	ProductType        string  `json:"product_type"`
	UsageType          string  `json:"usage_type"`
	Operation          string  `json:"operation"`
	Region             string  `json:"region"`
	InstanceType       *string `json:"instance_type"`
	InstanceFamily     *string `json:"instance_family"`
	ProductDescription *string `json:"product_description"`
	Tenancy            *string `json:"tenancy"`
	Unit               string  `json:"unit"`
	Currency           string  `json:"currency"`
}

// Hour is a complete eligible CUR population selected from issued revisions.
// Covered and actual OnDemand usage are kept distinct. RI-discounted rows,
// credits and fee/negation lines do not become uncovered usage quantities.
type UsageHour struct {
	ID                     string     `json:"id"`
	Period                 Period     `json:"period"`
	Dimensions             Dimensions `json:"dimensions"`
	Kind                   string     `json:"kind"`
	CommitmentID           *string    `json:"commitment_id"`
	UsageAmount            string     `json:"usage_amount"`
	BilledCost             string     `json:"billed_cost"`
	OnDemandEquivalentCost *string    `json:"on_demand_equivalent_cost"`
	OnDemandBasis          string     `json:"on_demand_basis"`
	AllocatedCost          *string    `json:"allocated_cost"`
	AllocatedCostBasis     *string    `json:"allocated_cost_basis"`
	ContractRate           *string    `json:"contract_rate"`
	NativeRef              Ref        `json:"native_ref"`
}

// ContractRate comes from DescribeSavingsPlanRates for an existing plan.
// It cannot stand in for a new offer or forward account PAYG agreement.
type ContractRate struct {
	PlanID     string     `json:"plan_id"`
	Dimensions Dimensions `json:"dimensions"`
	Rate       string     `json:"rate"`
	NativeRef  Ref        `json:"native_ref"`
}

type OfferRate struct {
	Dimensions Dimensions `json:"dimensions"`
	Rate       string     `json:"rate"`
	NativeRef  Ref        `json:"native_ref"`
}

type Offer struct {
	ID              string      `json:"id"`
	Class           string      `json:"class"`
	Currency        string      `json:"currency"`
	PaymentOption   string      `json:"payment_option"`
	DurationSeconds string      `json:"duration_seconds"`
	EffectivePeriod Period      `json:"effective_period"`
	Rates           []OfferRate `json:"rates"`
	NativeRef       Ref         `json:"native_ref"`
}

// PAYGBasis is derived server-side from actual ordinary Usage net cost divided
// by its native usage quantity. It is current observed account pricing, not a
// forward contract or a public tariff. Its source rows remain individually pinned.
type PAYGBasis struct {
	Dimensions     Dimensions `json:"dimensions"`
	ObservedPeriod Period     `json:"observed_period"`
	Rate           string     `json:"rate"`
	Basis          string     `json:"basis"`
	SourceLineIDs  []string   `json:"source_line_ids"`
	NativeRefs     []Ref      `json:"native_refs"`
}

type Scope struct {
	TenantID            string   `json:"tenant_id"`
	WorkloadID          string   `json:"workload_id"`
	PayerAccountID      string   `json:"payer_account_id"`
	UsageAccountIDs     []string `json:"usage_account_ids"`
	ResourceIDs         []string `json:"resource_ids"`
	Class               string   `json:"class"`
	Currency            string   `json:"currency"`
	ConfigurationSHA256 string   `json:"configuration_sha256"`
	OwnershipRef        Ref      `json:"ownership_ref"`
	HistoryPeriod       Period   `json:"history_period"`
	ProjectionPeriod    Period   `json:"projection_period"`
	SHA256              string   `json:"sha256"`
}

// All five stages are required, ordered and bound to the exact scope. Only a
// server-issued assessment can establish evidenced no-change/inapplicability;
// a customer declaration or a blocked candidate is insufficient.
type OptimizationStage struct {
	Stage       string    `json:"stage"`
	Disposition string    `json:"disposition"`
	DecisionRef Ref       `json:"decision_ref"`
	OutcomeRef  Ref       `json:"outcome_ref"`
	ScopeSHA256 string    `json:"scope_sha256"`
	CompletedAt time.Time `json:"completed_at"`
	ReasonCodes []string  `json:"reason_codes"`
}

type ForecastHour struct {
	Period        Period     `json:"period"`
	Dimensions    Dimensions `json:"dimensions"`
	ExpectedUsage string     `json:"expected_usage"`
	LowerUsage    string     `json:"lower_usage"`
	UpperUsage    string     `json:"upper_usage"`
}

type Calibration struct {
	Method           string `json:"method"`
	ModelVersion     string `json:"model_version"`
	ModelSHA256      string `json:"model_sha256"`
	TrainingPeriod   Period `json:"training_period"`
	HoldoutPeriod    Period `json:"holdout_period"`
	SampleCount      int    `json:"sample_count"`
	NominalCoverage  string `json:"nominal_coverage"`
	ObservedCoverage string `json:"observed_coverage"`
	ScopeSHA256      string `json:"scope_sha256"`
	NativeRef        Ref    `json:"native_ref"`
}

type Forecast struct {
	ID             string         `json:"id"`
	ScopeSHA256    string         `json:"scope_sha256"`
	RecalculatedAt time.Time      `json:"recalculated_at"`
	Hours          []ForecastHour `json:"hours"`
	Calibration    *Calibration   `json:"calibration"`
	NativeRef      Ref            `json:"native_ref"`
}

// Input is private resolver output, never a public JSON body. Hashes provide
// consistency; issuer authentication, historical ownership and publication
// currentness must be rechecked against persisted sources by the resolver.
type Input struct {
	SchemaVersion     string              `json:"schema_version"`
	RequestID         string              `json:"request_id"`
	Selection         Selection           `json:"selection"`
	Scope             Scope               `json:"scope"`
	Portfolio         portfolio.Analysis  `json:"portfolio"`
	UsageStatus       string              `json:"usage_status"`
	Usage             []UsageHour         `json:"usage"`
	ContractRates     []ContractRate      `json:"contract_rates"`
	Offer             *Offer              `json:"offer"`
	PAYGBasis         []PAYGBasis         `json:"payg_basis"`
	OptimizationOrder []OptimizationStage `json:"optimization_order"`
	Forecast          *Forecast           `json:"forecast"`
	InputRefs         []Ref               `json:"input_refs"`
	ObservedAt        time.Time           `json:"observed_at"`
}

type Metric struct {
	Status      string   `json:"status"`
	Value       *string  `json:"value"`
	Unit        string   `json:"unit"`
	Currency    *string  `json:"currency"`
	Basis       string   `json:"basis"`
	Period      Period   `json:"period"`
	ReasonCodes []string `json:"reason_codes"`
	InputRefs   []Ref    `json:"input_refs"`
}

type Confidence struct {
	Status               string   `json:"status"`
	LowerExpectedSavings *string  `json:"lower_expected_savings"`
	UpperExpectedSavings *string  `json:"upper_expected_savings"`
	Coverage             *string  `json:"coverage"`
	Method               *string  `json:"method"`
	CalibrationRef       *Ref     `json:"calibration_ref"`
	ReasonCodes          []string `json:"reason_codes"`
}

type PriceChangeStress struct {
	Status                        string   `json:"status"`
	Assumption                    string   `json:"assumption"`
	BreakEvenPAYGRateDropFraction *string  `json:"break_even_payg_rate_drop_fraction"`
	ZeroUsageLoss                 Metric   `json:"zero_usage_loss"`
	ReasonCodes                   []string `json:"reason_codes"`
}

type Decision struct {
	SchemaVersion             string              `json:"schema_version"`
	ID                        string              `json:"id"`
	RequestID                 string              `json:"request_id"`
	Selection                 Selection           `json:"selection"`
	Scope                     Scope               `json:"scope"`
	InputRefs                 []Ref               `json:"input_refs"`
	Status                    string              `json:"status"`
	ObservedCoverage          Metric              `json:"observed_coverage"`
	ObservedEffectiveDiscount Metric              `json:"observed_effective_discount"`
	ObservedUnusedExposure    Metric              `json:"observed_unused_exposure"`
	ExpectedUtilization       Metric              `json:"expected_utilization"`
	BreakEvenUtilization      Metric              `json:"break_even_utilization"`
	ExpectedSavings           Metric              `json:"expected_savings"`
	DownsideExposure          Metric              `json:"downside_exposure"`
	CashRequirement           Metric              `json:"cash_requirement"`
	ForwardPriceAssumption    string              `json:"forward_price_assumption"`
	PriceChangeStress         PriceChangeStress   `json:"price_change_stress"`
	Confidence                Confidence          `json:"confidence"`
	OptimizationOrder         []OptimizationStage `json:"optimization_order"`
	ReasonCodes               []string            `json:"reason_codes"`
	ObservedAt                time.Time           `json:"observed_at"`
	FinanceApprovalRequired   bool                `json:"finance_approval_required"`
	PurchaseAuthorized        bool                `json:"purchase_authorized"`
	ExecutionAuthorized       bool                `json:"execution_authorized"`
	VerifiedSaving            *string             `json:"verified_saving"`
}
