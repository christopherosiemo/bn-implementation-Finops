package evidence

import (
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"testing"
	"time"
)

func sourceFixture() (model.Document, model.Document) {
	r := model.Document{"id": "resource", "provider_resource_id": "i-0123456789abcdef0", "account_id": "111122223333", "region": "eu-west-1"}
	row := model.Document{"ResourceId": r["provider_resource_id"], "SubAccountId": r["account_id"], "RegionId": r["region"], "BillingCurrency": "GBP", "x_SourceId": "source", "x_SourceVersion": "v2", "ChargePeriodStart": "2026-09-01T00:00:00Z", "ChargePeriodEnd": "2026-09-01T01:00:00Z"}
	return r, model.Document{"id": "job", "status": "PERSISTED", "source_id": "source", "raw": model.Document{"source_id": "source", "source_version": "v2"}, "canonical": model.Document{"records": []model.Document{row}}}
}
func TestSourceRequiresPersistedExactProviderAndVersionBinding(t *testing.T) {
	r, j := sourceFixture()
	b, rows, e := Source(j, r, "tenant")
	if e != nil || len(rows) != 1 || model.String(b, "tenant_id") != "tenant" {
		t.Fatalf("validsource:%v", e)
	}
	for _, field := range []string{"ResourceId", "SubAccountId", "RegionId", "BillingCurrency", "x_SourceId", "x_SourceVersion"} {
		t.Run(field, func(t *testing.T) {
			changed := model.Clone(j)
			can := Object(changed["canonical"])
			rr := Rows(can["records"])
			rr[0][field] = "wrong"
			if field == "BillingCurrency" {
				rr[0][field] = ""
			}
			can["records"] = rr
			changed["canonical"] = can
			if _, _, e := Source(changed, r, "tenant"); e == nil {
				t.Fatal("mismatched source accepted")
			}
		})
	}
	j["status"] = "PENDING"
	if _, _, e := Source(j, r, "tenant"); e == nil {
		t.Fatal("unpersisted source accepted")
	}
	r, j = sourceFixture()
	r["currency"] = "USD"
	if _, _, e := Source(j, r, "tenant"); e == nil {
		t.Fatal("source changed a known nativecurrency")
	}
}
func TestWorkloadSamplesBoundToTargetAndPeriod(t *testing.T) {
	r, _ := sourceFixture()
	binding := Binding("tenant", r, "GBP")
	start := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	sample := model.Clone(binding)
	delete(sample, "currency")
	sample["start"], sample["end"], sample["source_record_id"], sample["units"] = start.Format(time.RFC3339), start.Add(time.Hour).Format(time.RFC3339), "work-1", "0"
	if _, e := Samples(binding, []model.Document{sample}, start, start.Add(time.Hour)); e != nil {
		t.Fatal(e)
	}
	sample["account_id"] = "444455556666"
	if _, e := Samples(binding, []model.Document{sample}, start, start.Add(time.Hour)); e == nil {
		t.Fatal("cross-accountworkload accepted")
	}
}
func TestFixtureFinancialClockPreservesDayWorkAndSingleOwnedWindow(t *testing.T) {
	r, _ := sourceFixture()
	raw, b, binding := Fixture("tenant", r)
	if len(Rows(raw["records"])) != 336 || len(Rows(b["workload_samples"])) != 336 {
		t.Fatal("baseline incomplete")
	}
	post, snapshot := FixtureMeasurement(binding, []model.Document{{"execution_id": "actual", "stopped_at": "2026-10-17T12:00:00Z", "running_at": "2026-10-17T12:00:08Z"}})
	zero := 0
	for _, row := range Rows(post["records"]) {
		if model.String(row, "line_item_unblended_cost") == "0.000000000000" {
			zero++
		}
	}
	if zero != 43 || len(Rows(post["records"])) != 1344 {
		t.Fatalf("attributed quarters=%d", zero)
	}
	clock := Object(snapshot["financial_clock"])
	m := Rows(clock["owned_interval_mappings"])
	if len(m) != 1 || model.String(m[0], "execution_id") != "actual" {
		t.Fatal("logical interval lacks actualreceipt")
	}
}
