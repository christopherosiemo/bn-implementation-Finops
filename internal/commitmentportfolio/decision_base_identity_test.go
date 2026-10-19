package commitmentportfolio

import (
	"encoding/json"
	"testing"
	"time"
)

func TestDecisionBaseRestoresOnlySelectedIssuedPortfolioIdentity(t *testing.T) {
	selection, err := json.Marshal(DecisionPreparationSelection{PortfolioAnalysisRequestID: "issued039", OfferReceiptID: "issued-offer"})
	if err != nil {
		t.Fatal(err)
	}
	issuedAt := time.Date(2026, 10, 19, 12, 0, 0, 123456789, time.UTC)
	original := decisionBase{Selection: selection, Portfolio: Analysis{RequestID: "issued039", ObservedAt: issuedAt}, PortfolioInputs: Resolved{RequestID: "must-not-survive-json", DecisionSnapshotObservedAt: issuedAt}}
	raw, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	var decoded decisionBase
	if err = decodeDecisionPrivate(raw, &decoded, 32768); err != nil {
		t.Fatal(err)
	}
	if decoded.PortfolioInputs.RequestID != "" || !decoded.PortfolioInputs.DecisionSnapshotObservedAt.IsZero() {
		t.Fatal("private resolved identity or snapshot anchor unexpectedly serialized")
	}
	if err = restoreDecisionPortfolioRequestID(&decoded); err != nil || decoded.PortfolioInputs.RequestID != "issued039" || !decoded.PortfolioInputs.DecisionSnapshotObservedAt.Equal(issuedAt) {
		t.Fatal("selected issued analysis identity/anchor was not restored", err)
	}
	for _, identity := range []string{"", "other-issued039"} {
		bad := original
		bad.Portfolio.RequestID = identity
		bad.PortfolioInputs.RequestID = ""
		bad.PortfolioInputs.DecisionSnapshotObservedAt = time.Time{}
		if restoreDecisionPortfolioRequestID(&bad) == nil || bad.PortfolioInputs.RequestID != "" || !bad.PortfolioInputs.DecisionSnapshotObservedAt.IsZero() {
			t.Fatal("unselected portfolio identity supplied private authority")
		}
	}
	missing := original
	missing.Portfolio.ObservedAt = time.Time{}
	missing.PortfolioInputs = Resolved{}
	if restoreDecisionPortfolioRequestID(&missing) == nil || missing.PortfolioInputs.RequestID != "" || !missing.PortfolioInputs.DecisionSnapshotObservedAt.IsZero() {
		t.Fatal("an issued identity without its real observation instant acquired an anchor")
	}
}
