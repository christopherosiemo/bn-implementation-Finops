package fleetbilling

import (
	"strings"
	"testing"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/source"
)

func TestCurrentSourceAndCompletePayerCommitmentsAreIndependentFreshGates(t *testing.T) {
	now := time.Now().UTC()
	target := testTarget()
	reg := model.Document{"id": "source", "tenant_id": "tenant", "kind": "AWS_CUR2", "enabled": true, "status": "HEALTHY", "last_sync_at": now.Format(time.RFC3339Nano), "payer_account_id": account, "usage_account_ids": []string{account}, "region": "eu-west-1"}
	scope := model.Document{"receipt_id": "commitment", "payer_account_id": account, "usage_account_ids": []string{account}, "scope": "PAYER_ALL_LINKED_ACCOUNTS_ALL_REGIONS", "complete": true, "reserved_instance_count": 0, "savings_plan_count": 0, "observed_at": now.Format(time.RFC3339Nano)}
	commit := model.Document{"id": "commitment", "kind": "AWS_COMMITMENT", "writer_role": "finops_ingester", "source_id": "source", "config_hash": source.ConfigurationHash(reg), "commitment_scope": scope}
	if e := currentGate(reg, commit, target, now); e != nil {
		t.Fatal(e)
	}
	cases := map[string]func(model.Document, model.Document){"stale writer boundary": func(r, c model.Document) { r["last_sync_at"] = now.Add(-6 * time.Minute).Format(time.RFC3339Nano) }, "revoked source": func(r, c model.Document) { r["enabled"] = false }, "future native scope": func(r, c model.Document) {
		objectScope := object(c["commitment_scope"])
		objectScope["observed_at"] = now.Add(time.Minute).Format(time.RFC3339Nano)
		c["commitment_scope"] = objectScope
	}, "new reservation": func(r, c model.Document) {
		s := object(c["commitment_scope"])
		s["reserved_instance_count"] = 1
		c["commitment_scope"] = s
	}, "incomplete portfolio": func(r, c model.Document) {
		s := object(c["commitment_scope"])
		s["complete"] = false
		c["commitment_scope"] = s
	}, "other payer": func(r, c model.Document) {
		s := object(c["commitment_scope"])
		s["payer_account_id"] = "999900001111"
		c["commitment_scope"] = s
	}, "missing member": func(r, c model.Document) {
		s := object(c["commitment_scope"])
		s["usage_account_ids"] = []string{"444455556666"}
		c["commitment_scope"] = s
	}, "configuration changed": func(r, c model.Document) { r["read_role_binding_id"] = "different-private-binding" }, "uploaded issuer": func(r, c model.Document) { c["writer_role"] = "finops_api" }, "stale commitment": func(r, c model.Document) {
		s := object(c["commitment_scope"])
		s["observed_at"] = now.Add(-6 * time.Minute).Format(time.RFC3339Nano)
		c["commitment_scope"] = s
	}}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			r, c := model.Clone(reg), model.Clone(commit)
			mutate(r, c)
			if e := currentGate(r, c, target, now); e == nil {
				t.Fatal("current authority blocker bypassed")
			}
		})
	}
}
func TestCanonicalSourceCopiesCannotReplaceIssuedNativeMoney(t *testing.T) {
	now := time.Now().UTC()
	reg := model.Document{"id": "source", "payer_account_id": account, "usage_account_ids": []string{account}}
	r := usage(oldInstance, "m6i.xlarge", "SKU", "4.8", "0.2", now.Add(-24*time.Hour), now)
	raw := model.Document{"source_id": "source", "source_version": "version", "records": []model.Document{r}}
	c := model.Document{"x_SourceId": "source", "x_SourceVersion": "version", "x_SourceRecordId": r["identity_line_item_id"], "x_ProviderFields": r, "BillingAccountId": account, "SubAccountId": account, "ResourceId": oldInstance, "RegionId": "eu-west-1", "BillingCurrency": "USD", "ChargePeriodStart": r["line_item_usage_start_date"], "ChargePeriodEnd": r["line_item_usage_end_date"], "BilledCost": "4.8"}
	can := model.Document{"records": []model.Document{c}}
	job := model.Document{"status": "PERSISTED", "source_provenance": "AWS_CUR2_AUTHENTICATED", "source_registration_id": "source", "source_receipt_id": "receipt", "source_revision_id": "revision", "raw": raw, "canonical": can}
	receipt := model.Document{"id": "receipt", "tenant_id": "tenant", "kind": "AWS_CUR2", "writer_role": "finops_ingester", "registration_id": "source", "source_id": "source", "revision_id": "revision", "source_version": "version", "raw_hash": Hash(raw), "canonical_hash": Hash(can), "source_proof": model.Document{"row_count": 1}}
	rev := model.Document{"id": "revision", "source_id": "source", "writer_role": "finops_ingester", "config_hash": source.ConfigurationHash(reg), "raw_hash": Hash(raw), "canonical_hash": Hash(can)}
	if e := validateJob(reg, receipt, rev, job, "tenant"); e != nil {
		t.Fatal(e)
	}
	for _, field := range []string{"BilledCost", "BillingCurrency", "RegionId", "SubAccountId", "ResourceId", "x_SourceVersion"} {
		t.Run(field, func(t *testing.T) {
			j := model.Clone(job)
			cc := rows(object(j["canonical"])["records"])
			cc[0][field] = "tampered"
			j["canonical"] = model.Document{"records": cc}
			rc, rv := model.Clone(receipt), model.Clone(rev)
			rc["canonical_hash"] = Hash(j["canonical"])
			rv["canonical_hash"] = Hash(j["canonical"])
			if e := validateJob(reg, rc, rv, j, "tenant"); e == nil {
				t.Fatal("self-consistent canonical replacement accepted over native row")
			}
		})
	}
	receipt["canonical_hash"] = strings.Repeat("a", 64)
	if e := validateJob(reg, receipt, rev, job, "tenant"); e == nil {
		t.Fatal("wrong immutable canonical hash accepted")
	}
}

func TestLatestBillingAuthorityCannotBePartialOrLoseFrozenWindow(t *testing.T) {
	end := time.Now().UTC().Truncate(24 * time.Hour)
	p := Period{end.AddDate(0, 0, -14), end}
	proof := model.Document{"receipt_id": "receipt", "revision_id": "revision", "manifest_hash": strings.Repeat("a", 64), "payer_account_id": account, "usage_account_ids": []string{account}, "region": "eu-west-1", "currency": "USD", "invoice_entity": "AWS EMEA", "state": "COMPLETE", "object_count": 1, "verified_object_count": 1, "row_count": 14, "verified_row_count": 14, "period_start": p.Start.Format(time.RFC3339), "period_end": p.End.Format(time.RFC3339)}
	snapshot := resolved{registration: model.Document{"payer_account_id": account}, billing: []model.Document{{"source_proof": proof}}}
	if e := checkBillingScope(snapshot, p, testTarget(), "USD"); e != nil {
		t.Fatal(e)
	}
	for name, mutate := range map[string]func(model.Document){"partial": func(p model.Document) { p["state"] = "PARTIAL" }, "row omitted": func(p model.Document) { p["verified_row_count"] = 13 }, "lost last day": func(p model.Document) { p["period_end"] = end.Add(-24 * time.Hour).Format(time.RFC3339) }, "wrong currency": func(p model.Document) { p["currency"] = "GBP" }, "wrong member": func(p model.Document) { p["usage_account_ids"] = []string{"444455556666"} }} {
		t.Run(name, func(t *testing.T) {
			p2 := model.Clone(proof)
			mutate(p2)
			s := snapshot
			s.billing = []model.Document{{"source_proof": p2}}
			if e := checkBillingScope(s, p, testTarget(), "USD"); e == nil {
				t.Fatal("new incomplete authority reused old complete scope")
			}
		})
	}
}
