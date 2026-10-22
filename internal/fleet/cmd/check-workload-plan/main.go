// This command reviews already-created customer-pipeline artifacts offline.
// It never runs Terraform, authenticates to a cloud or dispatches an apply.
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/fleet"
)

func readJSON(path string, out any) error {
	f, e := os.Open(path)
	if e != nil {
		return fmt.Errorf("required artifact could not be opened")
	}
	defer f.Close()
	d := json.NewDecoder(f)
	d.DisallowUnknownFields()
	if e := d.Decode(out); e != nil {
		return e
	}
	if d.Decode(new(any)) != io.EOF {
		return fmt.Errorf("artifact contains trailing JSON")
	}
	return nil
}
func run(args []string) error {
	f := flag.NewFlagSet("check-workload-plan", flag.ContinueOnError)
	names := []string{"parent", "child", "plan-json", "saved-plan", "provenance", "public-key", "tenant", "workload", "resource", "provider-resource", "account", "region"}
	values := map[string]*string{}
	for _, name := range names {
		values[name] = f.String(name, "", "required offline review input")
	}
	seen := map[string]bool{}
	for i := 0; i < len(args); i += 2 {
		if i+1 >= len(args) || !strings.HasPrefix(args[i], "--") || strings.HasPrefix(args[i+1], "--") || seen[args[i]] {
			return fmt.Errorf("invalid or duplicate offline review option")
		}
		seen[args[i]] = true
	}
	if e := f.Parse(args); e != nil {
		return e
	}
	if f.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments")
	}
	for _, name := range names {
		if *values[name] == "" {
			return fmt.Errorf("--%s is required", name)
		}
	}
	var parent fleet.Envelope
	var child fleet.ChildEnvelope
	var provenance fleet.IaCBinding
	if e := readJSON(*values["parent"], &parent); e != nil {
		return e
	}
	if e := readJSON(*values["child"], &child); e != nil {
		return e
	}
	if e := readJSON(*values["provenance"], &provenance); e != nil {
		return e
	}
	publicRaw, e := os.ReadFile(*values["public-key"])
	if e != nil {
		return fmt.Errorf("public verification key could not be read")
	}
	key, e := base64.StdEncoding.DecodeString(strings.TrimSpace(string(publicRaw)))
	if e != nil || len(key) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid Ed25519 public verification key")
	}
	expected := fleet.Binding{TenantID: *values["tenant"], WorkloadID: *values["workload"], ResourceID: *values["resource"], Provider: "AWS", ProviderResourceID: *values["provider-resource"], AccountID: *values["account"], Region: *values["region"]}
	now := time.Now().UTC()
	if e = fleet.VerifyChild(child, parent, ed25519.PublicKey(key), expected, now); e != nil {
		return e
	}
	raw, e := os.ReadFile(*values["plan-json"])
	if e != nil {
		return fmt.Errorf("Terraform JSON artifact could not be read")
	}
	binary, e := os.ReadFile(*values["saved-plan"])
	if e != nil {
		return fmt.Errorf("saved Terraform binary artifact could not be read")
	}
	review, e := fleet.ValidateTerraformPlan(raw, binary, child.Plan, parent.Plan, provenance, now)
	if e != nil {
		return e
	}
	output, e := json.Marshal(map[string]any{"status": "OFFLINE_REVIEW_PASSED", "account": expected.AccountID, "region": expected.Region, "review": review, "applied": false, "note": "Artifact checks only. Pipeline provenance and live acceptance remain separate requirements."})
	if e != nil {
		return e
	}
	fmt.Println(string(output))
	return nil
}
func main() {
	if e := run(os.Args[1:]); e != nil {
		fmt.Fprintln(os.Stderr, "Workload plan rejected:", e)
		os.Exit(1)
	}
}
