package fleet

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFleetOfflineCheckerRunsExactSignedArtifactsWithoutApply(t *testing.T) {
	now := time.Now().UTC()
	p := fixturePlan(now)
	c := terraformChild(p, 1, now)
	plan := terraformFixture(p, c)
	raw, _ := json.Marshal(plan)
	c.PlanJSONSHA256 = BytesDigest(raw)
	private := ed25519.NewKeyFromSeed(make([]byte, 32))
	parent, e := Sign(p, []Approval{{"approval", "tenant", "approver", ApproverRole, Digest(p), now}}, private, now)
	if e != nil {
		t.Fatal(e)
	}
	child, e := SignChild(c, parent, private, now)
	if e != nil {
		t.Fatal(e)
	}
	dir := t.TempDir()
	files := map[string][]byte{"plan-json": raw, "saved-plan": []byte("binary-plan"), "public-key": []byte(base64.StdEncoding.EncodeToString(private.Public().(ed25519.PublicKey)))}
	files["parent"], _ = json.Marshal(parent)
	files["child"], _ = json.Marshal(child)
	files["provenance"], _ = json.Marshal(c.IaC)
	args := []string{"run", "./cmd/check-workload-plan"}
	for _, name := range []string{"parent", "child", "plan-json", "saved-plan", "provenance", "public-key"} {
		path := filepath.Join(dir, name)
		if e = os.WriteFile(path, files[name], 0600); e != nil {
			t.Fatal(e)
		}
		args = append(args, "--"+name, path)
	}
	args = append(args, "--tenant", p.Binding.TenantID, "--workload", p.Binding.WorkloadID, "--resource", p.Binding.ResourceID, "--provider-resource", p.Binding.ProviderResourceID, "--account", p.Binding.AccountID, "--region", p.Binding.Region)
	command := exec.Command("go", args...)
	output, e := command.CombinedOutput()
	if e != nil {
		t.Fatal("offline signed checker failed", e, string(output))
	}
	var result map[string]any
	if e = json.Unmarshal(output, &result); e != nil || result["applied"] != false || result["status"] != "OFFLINE_REVIEW_PASSED" {
		t.Fatal("offline review claimed apply", string(output), e)
	}
	if e = os.WriteFile(filepath.Join(dir, "saved-plan"), []byte("tampered binary"), 0600); e != nil {
		t.Fatal(e)
	}
	rejected, e := exec.Command("go", args...).CombinedOutput()
	if e == nil || !strings.Contains(string(rejected), "FLEET_SAVED_PLAN_DIGEST_MISMATCH") {
		t.Fatal("CLI accepted a changed binary", string(rejected), e)
	}
}
