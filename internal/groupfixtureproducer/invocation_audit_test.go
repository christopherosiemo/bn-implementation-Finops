package groupfixtureproducer

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNativeInvocationAuditRetainsAttemptsAndRejectsTornEvidence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "invocations.jsonl")
	line := `{"operation":"apply","started_at":"2026-10-19T00:00:00Z"}`
	if err := os.WriteFile(path, []byte(line+"\n"+line+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	audit, err := readInvocationAudit(path)
	if err != nil || audit.Total != 2 || audit.Counts["apply"] != 2 || len(audit.SHA256) != 64 {
		t.Fatal("invocation attempts were not retained", err)
	}
	for _, raw := range []string{"", line, `{"operation":"shell","started_at":"2026-10-19T00:00:00Z"}` + "\n", `{"operation":"apply","started_at":"not-a-time"}` + "\n", line + "\n{broken\n"} {
		if err = os.WriteFile(path, []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err = readInvocationAudit(path); err == nil {
			t.Fatal("unknown or torn native audit accepted")
		}
	}
}
