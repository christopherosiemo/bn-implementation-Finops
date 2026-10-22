package source

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
)

func fixture(t *testing.T) (Registration, *FixtureReader) {
	t.Helper()
	r, e := ParseRegistration(FixtureRegistration("tenant", "source"))
	if e != nil {
		t.Fatal(e)
	}
	f, e := NewFixtureReader(r, nil)
	if e != nil {
		t.Fatal(e)
	}
	return r, f
}

func TestHistoricalExportAndWriterBoundary(t *testing.T) {
	r, f := fixture(t)
	if _, e := ValidateExecution(r, f.Execution); e != nil {
		t.Fatal(e)
	}
	if e := ValidateWriterPolicy(r, FixtureBucketPolicy(r)); e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{"filtered query", "wrong destination", "daily aggregation", "nonversioned bucket", "missing explicit deny", "other export allowed"} {
		t.Run(name, func(t *testing.T) {
			d := model.Clone(f.Execution)
			bucket := FixtureBucketPolicy(r)
			switch name {
			case "filtered query":
				Object(d["Export"])
				export := Object(d["Export"])
				query := Object(export["DataQuery"])
				query["QueryStatement"] = "SELECT * FROM COST_AND_USAGE_REPORT WHERE line_item_usage_account_id='111122223333'"
				export["DataQuery"] = query
				d["Export"] = export
			case "wrong destination":
				export := Object(d["Export"])
				dest := Object(Object(export["DestinationConfigurations"])["S3Destination"])
				dest["S3Bucket"] = "other-bucket"
				export["DestinationConfigurations"] = model.Document{"S3Destination": dest}
				d["Export"] = export
			case "daily aggregation":
				export := Object(d["Export"])
				query := Object(export["DataQuery"])
				query["TableConfigurations"] = model.Document{"COST_AND_USAGE_REPORT": model.Document{"TIME_GRANULARITY": "DAILY", "INCLUDE_RESOURCES": "TRUE"}}
				export["DataQuery"] = query
				d["Export"] = export
			case "nonversioned bucket":
				bucket["versioning"] = "Suspended"
			case "missing explicit deny":
				policy := Object(bucket["policy"])
				policy["Statement"] = Rows(policy["Statement"])[:1]
				bucket["policy"] = policy
			case "other export allowed":
				policy := Object(bucket["policy"])
				statements := Rows(policy["Statement"])
				kept := []model.Document{}
				for _, s := range statements {
					if model.String(Object(Object(s["Condition"])["StringNotEqualsIfExists"]), "aws:SourceArn") == "" {
						kept = append(kept, s)
					}
				}
				policy["Statement"] = kept
				bucket["policy"] = policy
			}
			_, execErr := ValidateExecution(r, d)
			policyErr := ValidateWriterPolicy(r, bucket)
			if execErr == nil && policyErr == nil {
				t.Fatal("invalid authority accepted")
			}
		})
	}
}

func TestManifestAndRowsRejectOmissionsAndCrossBindings(t *testing.T) {
	r, f := fixture(t)
	name, _ := ValidateExecution(r, f.Execution)
	key := f.ManifestKeys[0]
	manifest, e := ParseManifest(r, name, model.String(f.Execution, "ExecutionId"), key, f.Objects[key].Data)
	if e != nil {
		t.Fatal(e)
	}
	all := []model.Document{}
	for _, k := range manifest.Keys {
		rows, e := ParseGzipCSV(f.Objects[k].Data)
		if e != nil {
			t.Fatal(e)
		}
		all = append(all, rows...)
	}
	if len(all) != 710 {
		t.Fatalf("expected full delivery excluding actual stop hours, got %d", len(all))
	}
	if e = ValidateRows(r, manifest, all); e != nil {
		t.Fatal(e)
	}
	for _, bad := range []model.Document{{"reportKeys": []string{manifest.Keys[0], manifest.Keys[0]}}, {"reportKeys": []string{"another-prefix/data.csv.gz"}}, {"reportKeys": []string{}}, {"reportKeys": []string{strings.ReplaceAll(manifest.Keys[0], "fixture-delivery", "different-execution")}}} {
		if _, e := ParseManifest(r, name, "fixture-delivery", key, []byte(marshal(bad))); e == nil {
			t.Fatal("unsafe manifest accepted")
		}
	}
	duplicate := append([]model.Document{}, all...)
	duplicate = append(duplicate, model.Clone(all[0]))
	if e := ValidateRows(r, manifest, duplicate); e == nil {
		t.Fatal("duplicate source records accepted")
	}
	wrong := []model.Document{model.Clone(all[0])}
	wrong[0]["bill_payer_account_id"] = "444455556666"
	if e := ValidateRows(r, manifest, wrong); e == nil {
		t.Fatal("wrong payer accepted")
	}
	wrong = []model.Document{model.Clone(all[0])}
	wrong[0]["bill_billing_period_end_date"] = "2026-11-01T00:00:00Z"
	if e := ValidateRows(r, manifest, wrong); e == nil {
		t.Fatal("wrong native billing period accepted")
	}
	if _, e := ParseGzipCSV([]byte("plain csv pretending to be gzip")); e == nil {
		t.Fatal("uncompressed object accepted")
	}
	if _, e := f.BillingObject(context.Background(), r.Bucket, manifest.Keys[0], "different-version"); e == nil {
		t.Fatal("fixture must enforce pinned versions")
	}
}

func TestReadBindingsCannotCrossTenantsOrAccounts(t *testing.T) {
	r, _ := fixture(t)
	b := model.Document{"payer": model.Document{"tenant_id": "tenant", "payer_account_id": r.PayerAccountID, "role_arn": "arn:aws:iam::111122223333:role/billing-reader", "external_id": strings.Repeat("x", 32), "region": r.Region}}
	factory, e := AWSFactory(marshal(b))
	if e != nil {
		t.Fatal(e)
	}
	r.ReadRoleBindingID = "payer"
	r.TenantID = "other"
	if _, e = factory(context.Background(), r); e == nil {
		t.Fatal("cross tenant binding accepted")
	}
	Object(b["payer"])
	payer := Object(b["payer"])
	payer["role_arn"] = "arn:aws:iam::444455556666:role/reader"
	b["payer"] = payer
	if _, e = AWSFactory(marshal(b)); e == nil {
		t.Fatal("role account differs from approved account")
	}
	d := FixtureRegistration("tenant", "source")
	hash := ConfigurationHash(d)
	d["version"], d["sync_requested"], d["status"] = 2, true, "SYNC_QUEUED"
	if ConfigurationHash(d) != hash {
		t.Fatal("sync controls invalidated immutable configuration")
	}
	d["bucket"] = "different-bucket"
	if ConfigurationHash(d) == hash {
		t.Fatal("source location missing from config hash")
	}
}

func TestProviderExecutionCannotAttestFutureHistory(t *testing.T) {
	_, f := fixture(t)
	now := time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC)
	if e := ValidateExecutionTime(f.Execution, now); e != nil {
		t.Fatal(e)
	}
	for _, field := range []string{"CreatedAt", "CompletedAt", "LastUpdatedAt"} {
		d := model.Clone(f.Execution)
		status := Object(d["ExecutionStatus"])
		status[field] = now.Add(time.Minute).Format(time.RFC3339)
		d["ExecutionStatus"] = status
		if e := ValidateExecutionTime(d, now); e == nil {
			t.Fatalf("future %s accepted", field)
		}
	}
}

func marshal(v any) string { b, _ := json.Marshal(v); return string(b) }
