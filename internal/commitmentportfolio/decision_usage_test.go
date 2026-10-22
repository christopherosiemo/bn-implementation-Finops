package commitmentportfolio

import (
	"testing"
	"time"
)

func decisionUsageSample(id string, end time.Time, quantity string, net *string) UsageHour {
	return UsageHour{ID: id, Period: Period{Start: end.Add(-time.Hour), End: end}, Dimensions: Dimensions{AccountID: "111122223333", ServiceCode: "AmazonEC2", ProductType: "EC2", UsageType: "BoxUsage:m6i.large", Operation: "RunInstances", Region: "eu-west-1", Unit: "Hrs", Currency: "USD"}, Kind: "Usage", UsageAmount: quantity, NetUsageCost: net, NativeRef: Ref{Kind: "AWS_CUR2", ID: "receipt", SHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}
}
func decisionString(s string) *string { return &s }

func TestDecisionNativeNetBasisNeverUsesGrossPublicOrOlderMissingNet(t *testing.T) {
	end := time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC)
	old := decisionUsageSample("old", end.Add(-time.Hour), "1", decisionString("0.2"))
	current := decisionUsageSample("current", end, "1", nil)
	current.BilledCost = "999"
	current.OnDemandEquivalentCost = decisionString("999")
	if got := decisionPAYGBasis([]UsageHour{old, current}); len(got) != 0 {
		t.Fatal("missing current native net cost borrowed a historical/gross/public rate", got)
	}
	current.NetUsageCost = decisionString("0")
	got := decisionPAYGBasis([]UsageHour{old, current})
	if len(got) != 1 || got[0].Rate != "0.000000000000" || len(got[0].SourceLineIDs) != 1 || got[0].SourceLineIDs[0] != "current" {
		t.Fatal("explicit current native zero was not retained separately", got)
	}
}

func TestDecisionNativeNetBasisPartitionsExactScopeAndRefusesHiddenPrecision(t *testing.T) {
	end := time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC)
	first := decisionUsageSample("first", end, "2", decisionString("0.4"))
	second := decisionUsageSample("second", end, "3", decisionString("0.6"))
	foreign := decisionUsageSample("foreign", end, "1", decisionString("6"))
	foreign.Dimensions.Currency = "EUR"
	got := decisionPAYGBasis([]UsageHour{second, foreign, first})
	if len(got) != 2 {
		t.Fatal("currencies combined or exact same-SKU rows not grouped", got)
	}
	for _, rate := range got {
		if rate.Dimensions.Currency == "USD" && (rate.Rate != "0.200000000000" || len(rate.SourceLineIDs) != 2) {
			t.Fatal("native net quantity denominator changed", rate)
		}
	}
	recurring := decisionUsageSample("recurring", end, "3", decisionString("1"))
	if got := decisionPAYGBasis([]UsageHour{recurring}); len(got) != 0 {
		t.Fatal("repeating decimal was silently rounded into an authoritative rate", got)
	}
	negative := decisionUsageSample("negative", end, "1", decisionString("-1"))
	if got := decisionPAYGBasis([]UsageHour{negative}); len(got) != 0 {
		t.Fatal("credit became a usable future net rate", got)
	}
	covered := decisionUsageSample("covered", end, "1", decisionString("0.01"))
	covered.Kind = "SavingsPlanCoveredUsage"
	if got := decisionPAYGBasis([]UsageHour{covered}); len(got) != 0 {
		t.Fatal("covered usage became uncovered PAYG", got)
	}
}
