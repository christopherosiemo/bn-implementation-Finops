package commitmentportfolio

import (
	"encoding/json"
	"errors"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/source"
)

var ErrEvidence = errors.New("COMMITMENT_PORTFOLIO_ISSUED_EVIDENCE_INVALID")
var decimalPattern = regexp.MustCompile(`^-?(0|[1-9][0-9]{0,29})(\.[0-9]{1,18})?$`)
var accountPattern = regexp.MustCompile(`^[0-9]{12}$`)
var shaPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

type BillingRevision struct {
	Receipt          model.Document `json:"receipt"`
	Revision         model.Document `json:"revision"`
	Job              model.Document `json:"job"`
	CurrentReceiptID string         `json:"current_receipt_id"`
}

// Resolved is selected by the database resolver under graph/source locks. This
// is not an API body. Its field checks do not authenticate an uploaded copy.
type Resolved struct {
	TenantID  string `json:"tenant_id"`
	RequestID string `json:"-"`
	// Decision-only immutable reconstruction anchor, restored from the actual
	// selected039 analysis after SQL authenticates the current financial heads.
	// This is not a source-currentness timestamp and cannot enter through JSON.
	DecisionSnapshotObservedAt time.Time         `json:"-"`
	Selection                  Selection         `json:"selection"`
	Registration               model.Document    `json:"registration"`
	Checkpoint                 model.Document    `json:"checkpoint"`
	Commitment                 model.Document    `json:"commitment"`
	Billing                    []BillingRevision `json:"billing"`
}

func document(v any) model.Document {
	raw, _ := json.Marshal(v)
	var out model.Document
	_ = json.Unmarshal(raw, &out)
	return out
}
func documents(v any) []model.Document {
	raw, _ := json.Marshal(v)
	var out []model.Document
	_ = json.Unmarshal(raw, &out)
	return out
}
func stringValue(v any) string { s, _ := v.(string); return s }
func first(d model.Document, names ...string) string {
	for _, n := range names {
		if s := stringValue(d[n]); s != "" {
			return s
		}
	}
	return ""
}
func nullable(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
func date(s string) *time.Time {
	t, e := time.Parse(time.RFC3339Nano, s)
	if e != nil {
		return nil
	}
	t = t.UTC()
	return &t
}
func decimalValue(s string) (*string, error) {
	if s == "" {
		return nil, nil
	}
	if !decimalPattern.MatchString(s) || strings.HasPrefix(s, "-") {
		return nil, ErrEvidence
	}
	return &s, nil
}
func ref(kind string, d model.Document) Ref { return Ref{kind, model.String(d, "id"), Hash(d)} }
func Prepare(r Resolved, now time.Time) (Input, error) {
	out := Input{SchemaVersion: "1", TenantID: r.TenantID, RequestID: r.RequestID, Selection: r.Selection, InputRefs: []Ref{}, UsageAccountIDs: []string{}, Positions: []Position{}, Billing: []BillingLine{}, OptimizationOrder: []OptimizationStage{}, ObservedAt: now.UTC(), InventoryStatus: "UNAVAILABLE", BillingStatus: "UNAVAILABLE"}
	if ValidateSelection(r.Selection, now) != nil {
		return Input{}, ErrEvidence
	}
	reg, c := r.Registration, r.Commitment
	observed := date(model.String(c, "observed_at"))
	if r.TenantID == "" || r.RequestID == "" || r.Selection.SourceID != model.String(reg, "id") || source.ValidateRegistration(reg) != nil || model.String(reg, "tenant_id") != r.TenantID || !model.Bool(reg, "enabled") || model.Bool(reg, "revoked") || model.String(reg, "status") != "HEALTHY" || model.String(c, "id") != r.Selection.CommitmentReceiptID || model.String(c, "source_id") != r.Selection.SourceID || model.String(c, "kind") != "AWS_COMMITMENT" || model.String(c, "writer_role") != "finops_ingester" || model.String(c, "tenant_id") != r.TenantID || model.String(c, "config_hash") != source.ConfigurationHash(reg) || model.String(r.Checkpoint, "commitment_receipt_id") != model.String(c, "id") || observed == nil || observed.Before(now.Add(-5*time.Minute)) || observed.After(now.Add(5*time.Second)) {
		return Input{}, ErrEvidence
	}
	scope := document(c["commitment_scope"])
	if model.String(scope, "receipt_id") != model.String(c, "id") || model.String(scope, "payer_account_id") != model.String(reg, "payer_account_id") || model.String(scope, "scope") != "PAYER_ALL_LINKED_ACCOUNTS_ALL_REGIONS" || source.Hash(scope) != model.String(c, "native_hash") {
		return Input{}, ErrEvidence
	}
	out.PayerAccountID = model.String(scope, "payer_account_id")
	nativeRef := ref("AWS_COMMITMENT", c)
	out.InputRefs = append(out.InputRefs, nativeRef)
	complete := model.Bool(scope, "complete")
	out.InventoryStatus = "PARTIAL"
	if complete {
		out.InventoryStatus = "COMPLETE_POINT_IN_TIME"
	}
	accounts := map[string]bool{}
	for _, a := range model.Strings(scope, "usage_account_ids") {
		if !accountPattern.MatchString(a) || accounts[a] {
			return Input{}, ErrEvidence
		}
		accounts[a] = true
	}
	if !accounts[out.PayerAccountID] {
		return Input{}, ErrEvidence
	}
	for account := range accounts {
		out.UsageAccountIDs = append(out.UsageAccountIDs, account)
	}
	sort.Strings(out.UsageAccountIDs)
	if complete {
		for _, a := range model.Strings(reg, "usage_account_ids") {
			if !accounts[a] {
				return Input{}, ErrEvidence
			}
		}
		if !accounts[out.PayerAccountID] {
			return Input{}, ErrEvidence
		}
		if _, ok := scope["reserved_instance_count"]; !ok {
			return Input{}, ErrEvidence
		}
		if _, ok := scope["savings_plan_count"]; !ok {
			return Input{}, ErrEvidence
		}
	}
	snapshots := documents(scope["native_snapshots"])
	seen := map[string]bool{}
	riCount, spCount := 0, 0
	for _, snapshot := range snapshots {
		account := model.String(snapshot, "account_id")
		if !accounts[account] || seen[account] {
			return Input{}, ErrEvidence
		}
		seen[account] = true
		for _, ri := range documents(snapshot["reserved_instances"]) {
			id := model.String(ri, "id")
			if id == "" || len(id) > 128 {
				return Input{}, ErrEvidence
			}
			riCount++
			// Existing issuer projects only these four fields. Extra field presence may
			// not turn this receipt into a classified/priced RI or a term schedule.
			position, e := reservedInstancePosition(ri, account, nativeRef)
			if e != nil {
				return Input{}, e
			}
			out.Positions = append(out.Positions, position)
		}
		for _, sp := range documents(snapshot["savings_plans"]) {
			id := first(sp, "SavingsPlanArn", "savingsPlanArn")
			if id == "" || !strings.Contains(id, ":"+account+":savingsplan/") {
				return Input{}, ErrEvidence
			}
			spCount++
			class := map[string]string{"Compute": "COMPUTE_SAVINGS_PLAN", "EC2Instance": "EC2_INSTANCE_SAVINGS_PLAN", "SageMaker": "SAGEMAKER_SAVINGS_PLAN", "Database": "DATABASE_SAVINGS_PLAN"}[first(sp, "SavingsPlanType", "savingsPlanType")]
			reasons := []string{}
			if class == "" {
				class = "UNSUPPORTED_SAVINGS_PLAN"
				reasons = append(reasons, "SAVINGS_PLAN_CLASS_UNSUPPORTED")
			}
			currency := first(sp, "Currency", "currency")
			if currency != "" && !regexp.MustCompile(`^[A-Z]{3}$`).MatchString(currency) {
				return Input{}, ErrEvidence
			}
			hourly, e := decimalValue(first(sp, "Commitment", "commitment"))
			if e != nil {
				return Input{}, e
			}
			upfront, e := decimalValue(first(sp, "UpfrontPaymentAmount", "upfrontPaymentAmount"))
			if e != nil {
				return Input{}, e
			}
			recurring, e := decimalValue(first(sp, "RecurringPaymentAmount", "recurringPaymentAmount"))
			if e != nil {
				return Input{}, e
			}
			p := Position{ID: id, AccountID: account, Class: class, State: first(sp, "State", "state"), Region: nullable(first(sp, "Region", "region")), InstanceFamily: nullable(first(sp, "Ec2InstanceFamily", "ec2InstanceFamily")), Currency: nullable(currency), Start: date(first(sp, "Start", "start")), End: date(first(sp, "End", "end")), HourlyCommitment: hourly, UpfrontAmount: upfront, RecurringAmount: recurring, RecurringAmountUnit: "PROVIDER_FIELD_UNIT_UNVERIFIED", PaymentOption: nullable(first(sp, "PaymentOption", "paymentOption")), NativeRef: nativeRef, ReasonCodes: reasons}
			if p.Start != nil && p.End != nil && p.End.After(*p.Start) && p.End.Sub(*p.Start)%time.Second == 0 {
				p.TermSeconds = nullable(strconv.FormatInt(int64(p.End.Sub(*p.Start)/time.Second), 10))
			}
			out.Positions = append(out.Positions, p)
		}
	}
	if complete && (len(seen) != len(accounts) || int64(riCount) != model.Number(scope, "reserved_instance_count") || int64(spCount) != model.Number(scope, "savings_plan_count")) {
		return Input{}, ErrEvidence
	}
	if len(out.Positions) > 2000 {
		return Input{}, ErrEvidence
	}
	sort.Slice(out.Positions, func(i, j int) bool { return out.Positions[i].ID < out.Positions[j].ID })
	for i := 1; i < len(out.Positions); i++ {
		if out.Positions[i-1].ID == out.Positions[i].ID {
			return Input{}, ErrEvidence
		}
	}
	if len(r.Selection.BillingReceiptIDs) != len(r.Billing) || len(r.Billing) > 24 {
		return Input{}, ErrEvidence
	}
	if len(r.Billing) > 0 {
		out.BillingStatus = "PARTIAL"
	}
	wanted := map[string]bool{}
	for _, id := range r.Selection.BillingReceiptIDs {
		if id == "" || wanted[id] {
			return Input{}, ErrEvidence
		}
		wanted[id] = true
	}
	rows := 0
	periods := []Period{}
	proofComplete := complete
	for _, b := range r.Billing {
		receipt, revision, job := b.Receipt, b.Revision, b.Job
		id := model.String(receipt, "id")
		if !wanted[id] || id != b.CurrentReceiptID || model.String(receipt, "tenant_id") != r.TenantID || model.String(receipt, "kind") != "AWS_CUR2" || model.String(receipt, "writer_role") != "finops_ingester" || model.String(receipt, "source_id") != r.Selection.SourceID || model.String(receipt, "config_hash") != source.ConfigurationHash(reg) || model.String(revision, "writer_role") != "finops_ingester" || model.String(revision, "id") != model.String(receipt, "revision_id") || model.String(revision, "source_id") != r.Selection.SourceID || model.String(job, "status") != "PERSISTED" || model.String(job, "source_provenance") != "AWS_CUR2_AUTHENTICATED" || model.String(job, "source_receipt_id") != id || model.String(job, "source_revision_id") != model.String(revision, "id") || source.Hash(job["raw"]) != model.String(receipt, "raw_hash") || source.Hash(job["canonical"]) != model.String(receipt, "canonical_hash") {
			return Input{}, ErrEvidence
		}
		delete(wanted, id)
		billingRef := ref("AWS_CUR2", receipt)
		out.InputRefs = append(out.InputRefs, billingRef)
		proof := document(receipt["source_proof"])
		left, right := date(model.String(proof, "period_start")), date(model.String(proof, "period_end"))
		proofAccounts := map[string]bool{}
		for _, a := range model.Strings(proof, "usage_account_ids") {
			proofAccounts[a] = true
		}
		if len(proofAccounts) != len(accounts) {
			proofComplete = false
		}
		for a := range accounts {
			if !proofAccounts[a] {
				proofComplete = false
			}
		}
		if left == nil || right == nil || !left.Before(*right) || model.String(proof, "payer_account_id") != out.PayerAccountID || model.String(proof, "receipt_id") != id || model.String(proof, "revision_id") != model.String(revision, "id") || !shaPattern.MatchString(model.String(proof, "manifest_hash")) || (model.String(proof, "state") != "COMPLETE" && model.String(proof, "state") != "FINAL") || model.Number(proof, "object_count") <= 0 || model.Number(proof, "object_count") != model.Number(proof, "verified_object_count") || model.Number(proof, "row_count") != model.Number(proof, "verified_row_count") {
			return Input{}, ErrEvidence
		}
		periods = append(periods, Period{*left, *right})
		canonical := document(job["canonical"])
		nativeRows := documents(document(job["raw"])["records"])
		canonicalRows := documents(canonical["records"])
		if len(nativeRows) != len(canonicalRows) || int64(len(nativeRows)) != model.Number(proof, "row_count") {
			return Input{}, ErrEvidence
		}
		nativeByID := map[string]model.Document{}
		for _, raw := range nativeRows {
			key := first(raw, "identity_line_item_id", "identity/LineItemId")
			if key == "" || nativeByID[key] != nil {
				return Input{}, ErrEvidence
			}
			nativeByID[key] = raw
		}
		for _, row := range documents(canonical["records"]) {
			rows++
			if rows > 100000 {
				return Input{}, ErrEvidence
			}
			raw := document(row["x_ProviderFields"])
			commitment := first(raw, "savings_plan_savings_plan_a_r_n", "savings_plan_savings_plan_arn", "savingsPlan/SavingsPlanARN")
			reserved := first(raw, "reservation_reservation_a_r_n", "reservation_reservation_arn", "reservation/ReservationARN")
			if commitment != "" && reserved != "" && commitment != reserved {
				return Input{}, ErrEvidence
			}
			if commitment == "" {
				commitment = reserved
			}
			if commitment == "" {
				continue
			}
			commitment = selectedCommitmentIdentity(commitment, out.Positions)
			key := first(row, "x_SourceRecordId")
			if nativeByID[key] == nil || Hash(raw) != Hash(nativeByID[key]) || first(raw, "bill_payer_account_id", "bill/PayerAccountId") != out.PayerAccountID || !accounts[first(raw, "line_item_usage_account_id", "lineItem/UsageAccountId")] {
				return Input{}, ErrEvidence
			}
			start, end := date(first(raw, "line_item_usage_start_date", "lineItem/UsageStartDate")), date(first(raw, "line_item_usage_end_date", "lineItem/UsageEndDate"))
			if start == nil || end == nil {
				return Input{}, ErrEvidence
			}
			if !start.Before(r.Selection.Period.End) || !end.After(r.Selection.Period.Start) {
				continue
			}
			if start.Before(r.Selection.Period.Start) || end.After(r.Selection.Period.End) {
				return Input{}, ErrEvidence
			}
			allocated, basis, e := nativeAllocatedCost(raw)
			if e != nil {
				return Input{}, e
			}
			total, e := decimalValue(first(raw, "savings_plan_total_commitment_to_date", "savingsPlan/TotalCommitmentToDate"))
			if e != nil {
				return Input{}, e
			}
			used, e := decimalValue(first(raw, "savings_plan_used_commitment", "savingsPlan/UsedCommitment"))
			if e != nil {
				return Input{}, e
			}
			out.Billing = append(out.Billing, BillingLine{ID: key, CommitmentID: commitment, AccountID: first(raw, "line_item_usage_account_id", "lineItem/UsageAccountId"), Currency: first(raw, "line_item_currency_code", "lineItem/CurrencyCode"), Kind: first(raw, "line_item_line_item_type", "lineItem/LineItemType"), Period: Period{*start, *end}, BilledCost: first(raw, "line_item_net_unblended_cost", "lineItem/NetUnblendedCost", "line_item_unblended_cost", "lineItem/UnblendedCost"), AllocatedCost: allocated, AllocatedCostBasis: basis, TotalCommitment: total, UsedCommitment: used, NativeRef: billingRef})
		}
	}
	sort.Slice(periods, func(i, j int) bool { return periods[i].Start.Before(periods[j].Start) })
	cursor := r.Selection.Period.Start
	for _, p := range periods {
		if p.End.Before(cursor) || p.End.Equal(cursor) {
			continue
		}
		if p.Start.After(cursor) {
			proofComplete = false
		}
		cursor = p.End
	}
	if len(periods) > 0 && proofComplete && !cursor.Before(r.Selection.Period.End) {
		out.BillingStatus = "COMPLETE_OBSERVED_WINDOW"
	}
	return out, nil
}
