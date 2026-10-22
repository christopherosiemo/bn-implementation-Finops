// Package fleetbilling issues private, conditional historical account-rate
// evidence. It grants no execution, future price guarantee or savings claim.
package fleetbilling

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/fleet"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
)

const Kind = "AWS_FLEET_BILLING_PRICE"
const RateBasis = "HISTORICAL_ACCOUNT_RATE_ESTIMATE"
const BaselineScopeBasis = "CURRENT_MEMBERS_NATIVE_BILLING_HISTORY"

// Target is server-owned configuration. No price, native dimension, source
// receipt or observation window can be supplied through an action request.
type Target struct {
	Binding      fleet.Binding `json:"binding"`
	SourceID     string        `json:"source_id"`
	OldASG       string        `json:"old_asg"`
	CandidateASG string        `json:"candidate_asg"`
}
type Period struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}
type SourceRef struct {
	ReceiptID      string    `json:"receipt_id"`
	RevisionID     string    `json:"revision_id"`
	IngestionJobID string    `json:"ingestion_job_id"`
	RawHash        string    `json:"raw_hash"`
	CanonicalHash  string    `json:"canonical_hash"`
	PeriodStart    time.Time `json:"period_start"`
	PeriodEnd      time.Time `json:"period_end"`
}
type Dimensions struct {
	AccountID            string `json:"account_id"`
	Region               string `json:"region"`
	Currency             string `json:"currency"`
	InstanceType         string `json:"instance_type"`
	OperatingSystem      string `json:"operating_system"`
	Tenancy              string `json:"tenancy"`
	LicenseModel         string `json:"license_model"`
	PreinstalledSoftware string `json:"preinstalled_software"`
	SKU                  string `json:"sku"`
	Operation            string `json:"operation"`
	UsageType            string `json:"usage_type"`
	Unit                 string `json:"unit"`
	CostBasis            string `json:"cost_basis"`
}
type Rate struct {
	InstanceType        string      `json:"instance_type"`
	Dimensions          *Dimensions `json:"rate_dimensions"`
	ObservedHourlyRate  *string     `json:"observed_hourly_rate"`
	UsageHours          *string     `json:"usage_hours"`
	ObservedComputeCost *string     `json:"observed_current_member_compute_cost"`
	SampleCount         int         `json:"sample_count"`
	LatestUsageEnd      *time.Time  `json:"latest_usage_end"`
	RateBasis           string      `json:"rate_basis"`
	MemberCount         int         `json:"member_count"`
	MemberIDsHash       string      `json:"member_ids_hash"`
}
type Evidence struct {
	SchemaVersion            string         `json:"schema_version"`
	ID                       string         `json:"id"`
	Kind                     string         `json:"kind"`
	Binding                  fleet.Binding  `json:"binding"`
	SourceConnectionID       string         `json:"source_connection_id"`
	SourceConfigHash         string         `json:"source_config_hash"`
	SourceConfiguration      model.Document `json:"source_configuration"`
	MembershipReceiptID      string         `json:"membership_receipt_id"`
	LaunchTemplatesReceiptID string         `json:"launch_templates_receipt_id"`
	HardwareReceiptIDs       []string       `json:"hardware_receipt_ids"`
	BillingSourceRefs        []SourceRef    `json:"billing_source_refs"`
	CommitmentReceiptID      string         `json:"commitment_receipt_id"`
	Baseline                 Period         `json:"baseline"`
	BaselineDays             int            `json:"baseline_days"`
	BaselineScopeBasis       string         `json:"baseline_scope_basis"`
	BillingLagSeconds        int64          `json:"billing_lag_seconds"`
	Old                      Rate           `json:"old"`
	Candidate                Rate           `json:"candidate"`
	EconomicScopeHash        string         `json:"economic_scope_hash"`
	Status                   string         `json:"status"`
	ReasonCodes              []string       `json:"reason_codes"`
	ObservedAt               time.Time      `json:"observed_at"`
	ValidUntil               time.Time      `json:"valid_until"`
	ExecutionAuthorized      bool           `json:"execution_authorized"`
	VerifiedSaving           *string        `json:"verified_saving"`
	HardSpendCap             bool           `json:"hard_spend_cap"`
}

func Hash(v any) string {
	b, _ := json.Marshal(v)
	// Struct field order and a persisted JSON object's sorted keys must name
	// the same content. Keep native JSON numbers exact during canonicalization.
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.UseNumber()
	var canonical any
	if decoder.Decode(&canonical) == nil {
		b, _ = json.Marshal(canonical)
	}
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}
func rawHash(v []byte) string { s := sha256.Sum256(v); return hex.EncodeToString(s[:]) }
func object(v any) model.Document {
	b, _ := json.Marshal(v)
	d := model.Document{}
	_ = json.Unmarshal(b, &d)
	return d
}
func rows(v any) []model.Document {
	b, _ := json.Marshal(v)
	d := []model.Document{}
	_ = json.Unmarshal(b, &d)
	return d
}
func decode(v any, d any) error {
	b, e := json.Marshal(v)
	if e != nil {
		return e
	}
	return json.Unmarshal(b, d)
}
func stamp(d model.Document, k string) time.Time {
	t, _ := time.Parse(time.RFC3339Nano, model.String(d, k))
	return t
}
