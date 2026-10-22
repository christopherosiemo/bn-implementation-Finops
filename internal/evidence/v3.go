package evidence

import (
	"encoding/json"
	"errors"
	"math"
	"math/big"
	"regexp"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
)

var v3Hash = regexp.MustCompile(`^[a-fA-F0-9]{64}$`)
var v3Decimal = regexp.MustCompile(`^-?[0-9]+(?:\.[0-9]{1,12})?$`)

func V3Binding(tenant string, resource model.Document, payer, entity, currency string) model.Document {
	b := Binding(tenant, resource, currency)
	b["payer_account_id"], b["invoice_entity"] = payer, entity
	return b
}

func SameBindingV3(a, b model.Document) bool {
	return SameBinding(a, b) && model.String(a, "payer_account_id") != "" && model.String(a, "payer_account_id") == model.String(b, "payer_account_id") && model.String(a, "invoice_entity") != "" && model.String(a, "invoice_entity") == model.String(b, "invoice_entity")
}

func countV3(value any) (int64, bool) {
	switch n := value.(type) {
	case int:
		return int64(n), n >= 0
	case int64:
		return n, n >= 0
	case float64:
		return int64(n), n >= 0 && n <= 9007199254740991 && math.Trunc(n) == n
	case json.Number:
		number, err := n.Int64()
		return number, err == nil && number >= 0
	default:
		return 0, false
	}
}

// ValidateSourceProofV3 checks resolved receipt structure, not authenticity.
// Callers must first load the receipt from the ingester-only source tables;
// never pass an API request's proof object as authority.
func ValidateSourceProofV3(proof, binding model.Document, start, end time.Time, final bool) error {
	for _, key := range []string{"receipt_id", "revision_id", "manifest_hash"} {
		if model.String(proof, key) == "" {
			return errors.New("SOURCE_RECEIPT_REQUIRED")
		}
	}
	if !v3Hash.MatchString(model.String(proof, "manifest_hash")) {
		return errors.New("SOURCE_MANIFEST_HASH_INVALID")
	}
	for key, target := range map[string]string{"payer_account_id": "payer_account_id", "usage_account_id": "account_id", "region": "region", "currency": "currency", "invoice_entity": "invoice_entity"} {
		if model.String(proof, key) == "" || model.String(proof, key) != model.String(binding, target) {
			return errors.New("SOURCE_SCOPE_MISMATCH")
		}
	}
	state := model.String(proof, "state")
	if state != "FINAL" && (final || state != "COMPLETE") {
		return errors.New("SOURCE_NOT_COMPLETE_OR_FINAL")
	}
	left, e1 := time.Parse(time.RFC3339Nano, model.String(proof, "period_start"))
	right, e2 := time.Parse(time.RFC3339Nano, model.String(proof, "period_end"))
	if e1 != nil || e2 != nil || !start.Before(end) || start.Before(left) || end.After(right) {
		return errors.New("SOURCE_PERIOD_NOT_COVERED")
	}
	objects, ok1 := countV3(proof["object_count"])
	verifiedObjects, ok2 := countV3(proof["verified_object_count"])
	rows, ok3 := countV3(proof["row_count"])
	verifiedRows, ok4 := countV3(proof["verified_row_count"])
	if !ok1 || !ok2 || !ok3 || !ok4 || objects == 0 || objects != verifiedObjects || rows != verifiedRows {
		return errors.New("SOURCE_EXPORT_PARTIAL")
	}
	return nil
}

func ValidateCommitmentScopeV3(proof, binding model.Document) error {
	if model.String(proof, "receipt_id") == "" || model.String(proof, "payer_account_id") != model.String(binding, "payer_account_id") || model.String(proof, "scope") != "PAYER_ALL_LINKED_ACCOUNTS_ALL_REGIONS" || !model.Bool(proof, "complete") {
		return errors.New("COMMITMENT_SCOPE_INCOMPLETE")
	}
	found := false
	seen := map[string]bool{}
	for _, account := range model.Strings(proof, "usage_account_ids") {
		if seen[account] {
			return errors.New("COMMITMENT_SCOPE_INCOMPLETE")
		}
		seen[account] = true
		found = found || account == model.String(binding, "account_id")
	}
	ri, ok1 := countV3(proof["reserved_instance_count"])
	sp, ok2 := countV3(proof["savings_plan_count"])
	if !found || !ok1 || !ok2 {
		return errors.New("COMMITMENT_SCOPE_INCOMPLETE")
	}
	if ri != 0 || sp != 0 {
		return errors.New("COMMITMENT_COVERED_OR_PORTFOLIO_MODEL_REQUIRED")
	}
	return nil
}

// NativePricingBasisV3 returns original CUR pricing, never supplied ContractedCost.
func NativePricingBasisV3(raw model.Document) (string, string, error) {
	for _, pair := range []struct{ basis, snake, slash string }{
		{"NET_UNBLENDED", "line_item_net_unblended_cost", "lineItem/NetUnblendedCost"},
		{"UNBLENDED", "line_item_unblended_cost", "lineItem/UnblendedCost"},
	} {
		value := model.String(raw, pair.snake)
		if value == "" {
			value = model.String(raw, pair.slash)
		}
		if value != "" {
			if !v3Decimal.MatchString(value) {
				return "", "", errors.New("NATIVE_COST_DECIMAL_INVALID")
			}
			number, ok := new(big.Rat).SetString(value)
			limit := new(big.Int).Exp(big.NewInt(10), big.NewInt(26), nil)
			if !ok || new(big.Rat).Abs(number).Cmp(new(big.Rat).SetInt(limit)) >= 0 {
				return "", "", errors.New("NATIVE_COST_DECIMAL_INVALID")
			}
			return pair.basis, value, nil
		}
	}
	return "", "", errors.New("NATIVE_UNBLENDED_COST_REQUIRED")
}

// SourceV3 resolves one immutable revision. Multi-revision snapshots call this
// for each receipt and retain each row's source ID/version, plus source_proofs.
func SourceV3(job, resource model.Document, tenant string) (model.Document, []model.Document, error) {
	binding, records, err := Source(job, resource, tenant)
	if err != nil {
		return nil, nil, err
	}
	proof := Object(job["source_proof"])
	if model.String(job, "source_receipt_id") == "" || model.String(job, "source_receipt_id") != model.String(proof, "receipt_id") {
		return nil, nil, errors.New("RESOLVED_SOURCE_RECEIPT_REQUIRED")
	}
	if model.String(proof, "source_id") != model.String(job, "source_id") || model.String(proof, "source_version") != model.String(Object(job["raw"]), "source_version") {
		return nil, nil, errors.New("SOURCE_RECEIPT_REVISION_MISMATCH")
	}
	binding = V3Binding(tenant, resource, model.String(proof, "payer_account_id"), model.String(proof, "invoice_entity"), model.String(binding, "currency"))
	left, e1 := time.Parse(time.RFC3339Nano, model.String(proof, "period_start"))
	right, e2 := time.Parse(time.RFC3339Nano, model.String(proof, "period_end"))
	if e1 != nil || e2 != nil {
		return nil, nil, errors.New("SOURCE_PERIOD_INVALID")
	}
	if err = ValidateSourceProofV3(proof, binding, left, right, false); err != nil {
		return nil, nil, err
	}
	for _, row := range records {
		if model.String(row, "BillingAccountId") != model.String(binding, "payer_account_id") || model.String(row, "InvoiceIssuerName") != model.String(binding, "invoice_entity") {
			return nil, nil, errors.New("SOURCE_PAYER_ENTITY_MISMATCH")
		}
		basis, value, e := NativePricingBasisV3(Object(row["x_ProviderFields"]))
		if e != nil {
			return nil, nil, e
		}
		native, ok1 := new(big.Rat).SetString(value)
		canonical, ok2 := new(big.Rat).SetString(model.String(row, "x_NativeComputeCost"))
		if !ok1 || !ok2 || native.Cmp(canonical) != 0 || model.String(row, "x_PricingBasis") != basis {
			return nil, nil, errors.New("NATIVE_CANONICAL_PRICE_MISMATCH")
		}
	}
	return binding, records, nil
}
