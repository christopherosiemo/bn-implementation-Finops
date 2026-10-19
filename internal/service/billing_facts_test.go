package service

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
)

func TestJointDecisionBillingFactProjectionPreservesExactCorrections(t *testing.T) {
	for _, amount := range []string{"0.2", "0", "-0.000000000001"} {
		r := model.Document{"x_SourceRecordId": "hourly-row", "x_SourceVersion": "version", "ChargePeriodStart": "2026-10-01T01:00:00Z", "ResourceId": "instance", "BillingCurrency": "USD", "BilledCost": amount}
		facts, e := billingFactRows("tenant", "source", model.Document{"records": []model.Document{r}})
		if e != nil || len(facts) != 1 || facts[0]["billed_cost"] != amount || facts[0]["effective_cost"] != nil || facts[0]["source_record_id"] != "hourly-row" || facts[0]["source_version"] != "version" {
			t.Fatal("canonical cost projection changed", e)
		}
		var payload model.Document
		if e = json.Unmarshal([]byte(model.String(facts[0], "payload")), &payload); e != nil || payload["BilledCost"] != amount {
			t.Fatal("exact source payload lost", e)
		}
	}
	for _, field := range []string{"x_SourceRecordId", "x_SourceVersion", "ChargePeriodStart", "BilledCost"} {
		r := model.Document{"x_SourceRecordId": "row", "x_SourceVersion": "version", "ChargePeriodStart": "2026-10-01T00:00:00Z", "BilledCost": "1"}
		delete(r, field)
		if _, e := billingFactRows("tenant", "source", model.Document{"records": []model.Document{r}}); e == nil {
			t.Fatal("incomplete canonical identity accepted", field)
		}
	}
}

func TestJointDecisionBillingFactPublisherUsesActualCanonicalClickHousePath(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != "POST" || r.URL.Query().Get("query") != "INSERT INTO billing_facts FORMAT JSONEachRow" || r.URL.Query().Get("database") != "owned" || r.Header.Get("X-ClickHouse-User") != "fixture" || r.Header.Get("X-ClickHouse-Key") != "fixture-secret" || r.URL.Query().Get("insert_deduplication_token") == "" {
			t.Error("canonical publication boundary changed")
		}
		raw, _ := io.ReadAll(io.LimitReader(r.Body, 8192))
		if !strings.Contains(string(raw), `"billed_cost":"0.2"`) {
			t.Error("exact canonical amount not transmitted")
		}
		w.WriteHeader(200)
	}))
	defer server.Close()
	t.Setenv("CLICKHOUSE_URL", server.URL)
	t.Setenv("CLICKHOUSE_DATABASE", "owned")
	t.Setenv("CLICKHOUSE_USER", "fixture")
	t.Setenv("CLICKHOUSE_PASSWORD", "fixture-secret")
	t.Setenv("OBJECT_ENDPOINT", "must-not-be-read")
	e := persistBillingFacts(context.Background(), "tenant", "source", model.Document{"records": []model.Document{{"x_SourceRecordId": "row", "x_SourceVersion": "version", "ChargePeriodStart": "2026-10-01T00:00:00Z", "BilledCost": "0.2"}}})
	if e != nil || calls != 1 {
		t.Fatal("actual canonical insertion missing", e, calls)
	}
}
