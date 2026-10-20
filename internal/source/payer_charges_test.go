package source

import (
	"testing"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
)

func TestNativePayerChargesRetainResourceLessFeesAndCredits(t *testing.T) {
	r, _ := fixture(t)
	for _, kind := range []string{"Fee", "RIFee", "SavingsPlanRecurringFee", "SavingsPlanUpfrontFee", "Credit", "Refund", "Tax"} {
		t.Run(kind, func(t *testing.T) {
			row := model.Clone(FixtureBillingRows(r, "i-original")[0])
			row["identity_line_item_id"], row["line_item_line_item_type"] = "payer-charge", kind
			row["line_item_usage_account_id"], row["line_item_resource_id"] = "", ""
			row["line_item_unblended_cost"] = "2.125"
			if kind == "Credit" || kind == "Refund" {
				row["line_item_unblended_cost"] = "-2.125"
			}
			reader, err := NewFixtureReader(r, []model.Document{row})
			if err != nil {
				t.Fatal(err)
			}
			name, err := ValidateExecution(r, reader.Execution)
			if err != nil {
				t.Fatal(err)
			}
			key := reader.ManifestKeys[0]
			manifest, err := ParseManifest(r, name, model.String(reader.Execution, "ExecutionId"), key, reader.Objects[key].Data)
			if err != nil {
				t.Fatal(err)
			}
			rows, err := ParseGzipCSV(reader.Objects[manifest.Keys[0]].Data)
			if err != nil || len(rows) != 1 {
				t.Fatal("native CSV row lost", err)
			}
			if err = ValidateRows(r, manifest, rows); err != nil {
				t.Fatal("payer-level charge rejected", err)
			}
			if !PayerScopedNonResourceCharge(rows[0], r.PayerAccountID) || model.String(rows[0], "line_item_unblended_cost") != model.String(row, "line_item_unblended_cost") || model.String(rows[0], "line_item_resource_id") != "" {
				t.Fatal("payer charge was assigned to a resource or its signed amount changed")
			}
			filtered := model.Clone(reader.Execution)
			export := Object(filtered["Export"])
			query := Object(export["DataQuery"])
			query["QueryStatement"] = "SELECT * FROM COST_AND_USAGE_REPORT WHERE line_item_line_item_type='Fee'"
			export["DataQuery"], filtered["Export"] = query, export
			if _, err = ValidateExecution(r, filtered); err == nil {
				t.Fatal("payer-charge shape authorized a filtered export")
			}
		})
	}
}

func TestNativePayerChargeExceptionCannotAdmitUsageOrCrossScope(t *testing.T) {
	r, reader := fixture(t)
	name, err := ValidateExecution(r, reader.Execution)
	if err != nil {
		t.Fatal(err)
	}
	key := reader.ManifestKeys[0]
	manifest, err := ParseManifest(r, name, model.String(reader.Execution, "ExecutionId"), key, reader.Objects[key].Data)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseGzipCSV(reader.Objects[manifest.Keys[0]].Data)
	if err != nil || len(parsed) == 0 {
		t.Fatal(err)
	}
	base := model.Clone(parsed[0])
	base["line_item_line_item_type"], base["line_item_usage_account_id"], base["line_item_resource_id"] = "Fee", "", ""
	if err = ValidateRows(r, manifest, []model.Document{base}); err != nil {
		t.Fatal("positive control is not a valid native payer charge", err)
	}
	for _, name := range []string{"usage", "resource-bound", "wrong-payer", "invalid-account", "missing-account-field", "missing-resource-field"} {
		t.Run(name, func(t *testing.T) {
			row := model.Clone(base)
			switch name {
			case "usage":
				row["line_item_line_item_type"] = "Usage"
			case "resource-bound":
				row["line_item_resource_id"] = "i-unowned"
			case "wrong-payer":
				row["bill_payer_account_id"] = "444455556666"
			case "invalid-account":
				row["line_item_usage_account_id"] = "not-an-account"
			case "missing-account-field":
				delete(row, "line_item_usage_account_id")
			case "missing-resource-field":
				delete(row, "line_item_resource_id")
			}
			if PayerScopedNonResourceCharge(row, r.PayerAccountID) || ValidateRows(r, manifest, []model.Document{row}) == nil {
				t.Fatal("invalid row passed payer-only exception")
			}
		})
	}
}
