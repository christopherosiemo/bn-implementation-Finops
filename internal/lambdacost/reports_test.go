package lambdacost

import (
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"strings"
	"testing"
	"time"
)

func TestLambdaReportMemoryBilledDurationAndVersionBinding(t *testing.T) {
	scope := Scope{"tenant-lambda", "111122223333", "eu-west-1"}
	arn := "arn:aws:lambda:eu-west-1:111122223333:function:processor:live"
	at := time.Now().UTC().Truncate(time.Second)
	text := "REPORT RequestId: 6d68ca91-49c9-448d-89b8-7ca3e6dc66aa Duration: 10.40 ms Billed Duration: 111 ms Memory Size: 2048 MB Max Memory Used: 700 MB Init Duration: 100.10 ms"
	row, e := ParseReport(scope, arn, "1", "REPORT_TEXT", text, "2026/10/20/[1]environment", "event", at)
	if e != nil || row["duration_ms"] != "10.40" || row["billed_duration_ms"] != "111" || row["init_duration_ms"] != "100.10" || row["memory_semantics"] != "EXECUTION_ENVIRONMENT_HIGH_WATER_MARK" {
		t.Fatal(row, e)
	}
	if strings.Contains(Hash(row), "6d68ca91") || row["request_id"] != nil {
		t.Fatal("raw request identity persisted")
	}
	for name, change := range map[string]func() error{"wrong-version": func() error {
		_, e := ParseReport(scope, arn, "2", "REPORT_TEXT", text, "2026/10/20/[1]environment", "event", at)
		return e
	}, "application": func() error {
		_, e := ParseReport(scope, arn, "1", "REPORT_TEXT", "secret application log", "2026/10/20/[1]environment", "event", at)
		return e
	}, "wrong-account": func() error {
		bad := scope
		bad.AccountID = "999999999999"
		_, e := ParseReport(bad, arn, "1", "REPORT_TEXT", text, "2026/10/20/[1]environment", "event", at)
		return e
	}, "memory-overflow": func() error {
		_, e := ParseReport(scope, arn, "1", "REPORT_TEXT", strings.Replace(text, "700 MB", "3000 MB", 1), "2026/10/20/[1]environment", "event", at)
		return e
	}} {
		t.Run(name, func(t *testing.T) {
			if change() == nil {
				t.Fatal("untrusted report accepted")
			}
		})
	}
	jsonReport := `{"time":"` + at.Format(time.RFC3339Nano) + `","type":"platform.report","record":{"requestId":"fixture-request","metrics":{"durationMs":10.4,"billedDurationMs":111,"memorySizeMB":2048,"maxMemoryUsedMB":700,"initDurationMs":100.1},"status":"success"}}`
	row, e = ParseReport(scope, arn, "1", "PLATFORM_REPORT_JSON", jsonReport, "2026/10/20/[1]environment", "event-json", at)
	if e != nil || row["billed_duration_ms"] != "111" {
		t.Fatal(row, e)
	}
}
func TestLambdaRegistrationAndDuplicateJSONFailClosed(t *testing.T) {
	r := model.Document{"id": "reports", "tenant_id": "tenant", "kind": ReportsKind, "account_id": "111122223333", "region": "eu-west-1", "function_arn": "arn:aws:lambda:eu-west-1:111122223333:function:processor", "qualifier": "live", "read_role_binding_id": "registered", "version": 1, "enabled": true, "log_group_name": "/aws/lambda/processor", "log_group_arn": "arn:aws:logs:eu-west-1:111122223333:log-group:/aws/lambda/processor", "format": "REPORT_TEXT"}
	if ValidateRegistration(r) != nil {
		t.Fatal("valid registration rejected")
	}
	r["log_group_arn"] = "arn:aws:logs:eu-west-1:999999999999:log-group:/aws/lambda/processor"
	if ValidateRegistration(r) == nil {
		t.Fatal("foreign log group accepted")
	}
	var doc model.Document
	for _, raw := range []string{`{"memory":128,"memory":2048}`, `{"ok":1} {"secret":2}`, `{"nested":{"x":1,"x":2}}`} {
		if DecodeJSON([]byte(raw), &doc) == nil {
			t.Fatal("ambiguous JSON accepted", raw)
		}
	}
	if Model(model.Document{"MemorySize": 32768}) != "EVENT_CAPABILITY_UNSUPPORTED" || Model(model.Document{"CapacityProviderConfig": model.Document{"x": true}}) != "EVENT_MANAGED_INSTANCES" || Model(model.Document{"DurableConfig": model.Document{"x": true}}) != "EVENT_DURABLE" {
		t.Fatal("execution model conflated")
	}
}
