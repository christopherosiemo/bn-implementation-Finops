// Package commitmentportfolio evaluates server-resolved purchasing advice.
// Neither a recommendation nor its Finance approval grants purchase or
// execution authority. Existing portfolio records and signatures stay intact.
package commitmentportfolio

import "time"

// DecisionSelection is the complete public body. Workload identity comes from the
// scoped route. Amounts, trust flags, outcome labels and forecasts are not input.
type DecisionSelection struct {
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
	BilledCostBasis        string     `json:"billed_cost_basis"`
	NetUsageCost           *string    `json:"net_usage_cost"`
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
	ID               string `json:"id"`
	NativeOfferingID string `json:"native_offering_id"`
	Class            string `json:"class"`
	Currency         string `json:"currency"`
	PaymentOption    string `json:"payment_option"`
	DurationSeconds  string `json:"duration_seconds"`
	// Local read freshness at calculation/review time. AWS does not supply a
	// quote expiry here; future pricing is provisional and purchase is disabled.
	ValidityBasis   string      `json:"validity_basis"`
	EffectivePeriod Period      `json:"effective_period"`
	Rates           []OfferRate `json:"rates"`
	NativeRef       Ref         `json:"native_ref"`
}

const DecisionOfferValidityBasis = "LOCAL_READ_FRESHNESS_POLICY_NOT_PROVIDER_QUOTE_EXPIRY"

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

type DecisionScope struct {
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
type PostOptimizationStage struct {
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
	Target              string `json:"target"`
	HorizonHours        int    `json:"horizon_hours"`
	BacktestOriginCount int    `json:"backtest_origin_count"`
	Method              string `json:"method"`
	ModelVersion        string `json:"model_version"`
	ModelSHA256         string `json:"model_sha256"`
	TrainingPeriod      Period `json:"training_period"`
	HoldoutPeriod       Period `json:"holdout_period"`
	SampleCount         int    `json:"sample_count"`
	NominalCoverage     string `json:"nominal_coverage"`
	ObservedCoverage    string `json:"observed_coverage"`
	ScopeSHA256         string `json:"scope_sha256"`
	NativeRef           Ref    `json:"native_ref"`
}

type DecisionForecast struct {
	ID             string         `json:"id"`
	ScopeSHA256    string         `json:"scope_sha256"`
	RecalculatedAt time.Time      `json:"recalculated_at"`
	Hours          []ForecastHour `json:"hours"`
	Calibration    *Calibration   `json:"calibration"`
	NativeRef      Ref            `json:"native_ref"`
}

// DecisionInput is private resolver output, never a public JSON body. Hashes provide
// consistency; issuer authentication, historical ownership and publication
// currentness must be rechecked against persisted sources by the resolver.
type DecisionInput struct {
	SchemaVersion       string                  `json:"schema_version"`
	RequestID           string                  `json:"request_id"`
	Selection           DecisionSelection       `json:"selection"`
	Scope               DecisionScope           `json:"scope"`
	Portfolio           Analysis                `json:"portfolio"`
	UsageStatus         string                  `json:"usage_status"`
	Usage               []UsageHour             `json:"usage"`
	ContractRates       []ContractRate          `json:"contract_rates"`
	ContractRateStatus  string                  `json:"contract_rate_status"`
	ContractRatePlanIDs []string                `json:"contract_rate_plan_ids"`
	ContractRateRefs    []Ref                   `json:"contract_rate_refs"`
	Offer               *Offer                  `json:"offer"`
	PAYGBasis           []PAYGBasis             `json:"payg_basis"`
	OptimizationOrder   []PostOptimizationStage `json:"optimization_order"`
	Forecast            *DecisionForecast       `json:"forecast"`
	InputRefs           []Ref                   `json:"input_refs"`
	ObservedAt          time.Time               `json:"observed_at"`
	ReasonCodes         []string                `json:"reason_codes"`
}

type DecisionMetric struct {
	Status      string   `json:"status"`
	Value       *string  `json:"value"`
	Unit        string   `json:"unit"`
	Currency    *string  `json:"currency"`
	Basis       string   `json:"basis"`
	Period      Period   `json:"period"`
	ReasonCodes []string `json:"reason_codes"`
	InputRefs   []Ref    `json:"input_refs"`
}

type DecisionConfidence struct {
	Status               string   `json:"status"`
	LowerExpectedSavings *string  `json:"lower_expected_savings"`
	UpperExpectedSavings *string  `json:"upper_expected_savings"`
	Coverage             *string  `json:"coverage"`
	Method               *string  `json:"method"`
	CalibrationRef       *Ref     `json:"calibration_ref"`
	ReasonCodes          []string `json:"reason_codes"`
}

type PriceChangeStress struct {
	Status                        string         `json:"status"`
	Assumption                    string         `json:"assumption"`
	BreakEvenPAYGRateDropFraction *string        `json:"break_even_payg_rate_drop_fraction"`
	ZeroUsageLoss                 DecisionMetric `json:"zero_usage_loss"`
	ReasonCodes                   []string       `json:"reason_codes"`
}

type Decision struct {
	SchemaVersion                  string                  `json:"schema_version"`
	ID                             string                  `json:"id"`
	RequestID                      string                  `json:"request_id"`
	Selection                      DecisionSelection       `json:"selection"`
	Scope                          DecisionScope           `json:"scope"`
	InputRefs                      []Ref                   `json:"input_refs"`
	Status                         string                  `json:"status"`
	ObservedCoverage               DecisionMetric          `json:"observed_coverage"`
	ComputationPolicy              string                  `json:"computation_policy"`
	ProposedHourlyCommitment       DecisionMetric          `json:"proposed_hourly_commitment"`
	ProposedTermObligation         DecisionMetric          `json:"proposed_term_obligation"`
	ObservedEffectiveDiscount      DecisionMetric          `json:"observed_effective_discount"`
	ObservedUnusedExposure         DecisionMetric          `json:"observed_unused_exposure"`
	ExpectedUtilization            DecisionMetric          `json:"expected_utilization"`
	BreakEvenUtilization           DecisionMetric          `json:"break_even_utilization"`
	ExpectedSavings                DecisionMetric          `json:"expected_savings"`
	DownsideExposure               DecisionMetric          `json:"downside_exposure"`
	CashRequirement                DecisionMetric          `json:"cash_requirement"`
	RemainingContractualObligation DecisionMetric          `json:"remaining_contractual_obligation"`
	PaidUnamortizedValue           DecisionMetric          `json:"paid_unamortized_value"`
	ForwardPriceAssumption         string                  `json:"forward_price_assumption"`
	PriceChangeStress              PriceChangeStress       `json:"price_change_stress"`
	Confidence                     DecisionConfidence      `json:"confidence"`
	OptimizationOrder              []PostOptimizationStage `json:"optimization_order"`
	ReasonCodes                    []string                `json:"reason_codes"`
	ObservedAt                     time.Time               `json:"observed_at"`
	FinanceApprovalRequired        bool                    `json:"finance_approval_required"`
	PurchaseAuthorized             bool                    `json:"purchase_authorized"`
	ExecutionAuthorized            bool                    `json:"execution_authorized"`
	VerifiedSaving                 *string                 `json:"verified_saving"`
}

// FinanceReview projects the existing approvals entity with a new typed
// target. It records review only and cannot feed a change plan or purchase.
type DecisionFinanceReview struct {
	ID                  string    `json:"id"`
	ActorID             string    `json:"actor_id"`
	DecisionID          string    `json:"decision_id"`
	DecisionSHA256      string    `json:"decision_sha256"`
	InputSHA256         string    `json:"input_sha256"`
	ApprovedAt          time.Time `json:"approved_at"`
	ApprovalScope       string    `json:"approval_scope"`
	PurchaseAuthorized  bool      `json:"purchase_authorized"`
	ExecutionAuthorized bool      `json:"execution_authorized"`
}

type DecisionSummary struct {
	ID                       string   `json:"id"`
	Status                   string   `json:"status"`
	Currency                 string   `json:"currency"`
	ProposedHourlyCommitment *string  `json:"proposed_hourly_commitment"`
	ExpectedSavings          *string  `json:"expected_savings"`
	ReasonCodes              []string `json:"reason_codes"`
	FinanceStatus            string   `json:"finance_status"`
}

type DecisionRecord struct {
	ID                  string                 `json:"id"`
	Version             int64                  `json:"version"`
	WorkloadID          string                 `json:"workload_id"`
	CreatorID           string                 `json:"creator_id"`
	Status              string                 `json:"status"`
	Selection           DecisionSelection      `json:"selection"`
	InputRefs           []Ref                  `json:"input_refs"`
	InputSHA256         *string                `json:"input_sha256"`
	DecisionSHA256      *string                `json:"decision_sha256"`
	Decision            *Decision              `json:"decision"`
	DecisionSummary     *DecisionSummary       `json:"decision_summary"`
	Refusal             *Refusal               `json:"refusal"`
	FinanceReview       *DecisionFinanceReview `json:"finance_review"`
	CanFinanceReview    bool                   `json:"can_finance_review"`
	ReviewReasonCodes   []string               `json:"review_reason_codes"`
	CreatedAt           time.Time              `json:"created_at"`
	ExecutionAuthorized bool                   `json:"execution_authorized"`
	VerifiedSaving      *string                `json:"verified_saving"`
}

type DecisionInputChoice struct {
	ID          string   `json:"id"`
	Kind        string   `json:"kind"`
	Label       string   `json:"label"`
	Status      string   `json:"status"`
	ScopeSHA256 *string  `json:"scope_sha256"`
	Period      *Period  `json:"period"`
	InputRefs   []Ref    `json:"input_refs"`
	ReasonCodes []string `json:"reason_codes"`
}

type DecisionPreparationSelection struct {
	PortfolioAnalysisRequestID string `json:"portfolio_analysis_request_id"`
	OfferReceiptID             string `json:"offer_receipt_id"`
}

type DecisionPreparationRecord struct {
	ID                           string                       `json:"id"`
	Version                      int64                        `json:"version"`
	WorkloadID                   string                       `json:"workload_id"`
	CreatorID                    string                       `json:"creator_id"`
	Status                       string                       `json:"status"`
	Selection                    DecisionPreparationSelection `json:"selection"`
	PostOptimizationAssessmentID *string                      `json:"post_optimization_assessment_id"`
	ForecastID                   *string                      `json:"forecast_id"`
	InputRefs                    []Ref                        `json:"input_refs"`
	ReasonCodes                  []string                     `json:"reason_codes"`
	CreatedAt                    time.Time                    `json:"created_at"`
	ExecutionAuthorized          bool                         `json:"execution_authorized"`
	VerifiedSaving               *string                      `json:"verified_saving"`
}

// Numerical producer output has no invented issuer references. The private
// Go worker publishes the calibration and forecast as separate immutable
// payloads, then attaches their actual persisted IDs and content hashes.
type DecisionForecastProduction struct {
	SchemaVersion  string               `json:"schema_version"`
	ID             string               `json:"id"`
	RequestID      string               `json:"request_id"`
	ScopeSHA256    string               `json:"scope_sha256"`
	RecalculatedAt time.Time            `json:"recalculated_at"`
	Status         string               `json:"status"`
	Hours          []ForecastHour       `json:"hours"`
	Calibration    *ProducedCalibration `json:"calibration"`
	ReasonCodes    []string             `json:"reason_codes"`
	InputRefs      []Ref                `json:"input_refs"`
}

type ProducedCalibration struct {
	Target              string `json:"target"`
	HorizonHours        int    `json:"horizon_hours"`
	BacktestOriginCount int    `json:"backtest_origin_count"`
	Method              string `json:"method"`
	ModelVersion        string `json:"model_version"`
	ModelSHA256         string `json:"model_sha256"`
	TrainingPeriod      Period `json:"training_period"`
	HoldoutPeriod       Period `json:"holdout_period"`
	SampleCount         int    `json:"sample_count"`
	NominalCoverage     string `json:"nominal_coverage"`
	ObservedCoverage    string `json:"observed_coverage"`
	ScopeSHA256         string `json:"scope_sha256"`
}

type DecisionHistoryHour struct {
	Period              Period     `json:"period"`
	Dimensions          Dimensions `json:"dimensions"`
	UsageAmount         string     `json:"usage_amount"`
	ConfigurationSHA256 string     `json:"configuration_sha256"`
	NativeRef           Ref        `json:"native_ref"`
}

type DecisionForecastRequest struct {
	SchemaVersion     string                  `json:"schema_version"`
	RequestID         string                  `json:"request_id"`
	Scope             DecisionScope           `json:"scope"`
	ObservedAt        time.Time               `json:"observed_at"`
	OptimizationOrder []PostOptimizationStage `json:"optimization_order"`
	InputRefs         []Ref                   `json:"input_refs"`
	History           []DecisionHistoryHour   `json:"history"`
}
