package service

import (
	"context"
	"errors"
	"sort"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/activity"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/evidence"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/source"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
)

func rejectSubmittedAuthority(in model.Document) error {
	allowed := map[string]bool{"schema_version": true, "resource_id": true, "source_connection_id": true, "schedule_id": true, "measurement_id": true, "start": true, "end": true}
	for k := range in {
		if !allowed[k] {
			return problem(422, "SERVER_SELECTED_EVIDENCE_REQUIRED", "version 3 accepts resource and observation windows; evidence authority is selected server-side")
		}
	}
	for _, k := range []string{"workload_samples", "billing_records", "invoice", "invoices", "invoice_scope_records", "source_proof", "commitment_scope", "coverage", "billing_observations", "owned_intervals", "financial_clock", "amount", "total", "proof_set_id", "ingestion_job_id"} {
		if _, ok := in[k]; ok {
			return problem(422, "SERVER_SELECTED_EVIDENCE_REQUIRED", "version 3 selects immutable receipts server-side")
		}
	}
	return nil
}

// The database only permits the ingester to issue source receipts. A provenance
// string in an entity, an S3 version, or a caller-supplied proof is insufficient.
func holdTrustedSourceSnapshot(ctx context.Context, t *store.Tx, connection string) error {
	if connection == "" {
		return errors.New("TRUSTED_SOURCE_REQUIRED")
	}
	var stable bool
	if err := t.QueryRow(ctx, "SELECT pg_try_advisory_xact_lock_shared(hashtextextended($1,0))", t.Tenant+":trusted-source:"+connection).Scan(&stable); err != nil {
		return err
	}
	if !stable {
		return errors.New("SOURCE_SYNC_IN_PROGRESS")
	}
	return nil
}

func trustedJob(ctx context.Context, t *store.Tx, job, res model.Document) (model.Document, error) {
	if model.String(job, "status") != "PERSISTED" || model.String(job, "source_provenance") != "AWS_CUR2_AUTHENTICATED" {
		return nil, errors.New("TRUSTED_SOURCE_REQUIRED")
	}
	receipt, e := t.SourceReceiptGet(ctx, model.String(job, "source_receipt_id"))
	if e != nil {
		return nil, errors.New("TRUSTED_SOURCE_REQUIRED")
	}
	if model.String(receipt, "writer_role") != "finops_ingester" {
		return nil, errors.New("TRUSTED_RECEIPT_ISSUER_INVALID")
	}
	if e = holdTrustedSourceSnapshot(ctx, t, model.String(receipt, "registration_id")); e != nil {
		return nil, e
	}
	registration, e := t.SourceGet(ctx, model.String(receipt, "registration_id"))
	if e != nil {
		return nil, e
	}
	if !model.Bool(registration, "enabled") {
		return nil, errors.New("SOURCE_REVOKED")
	}
	// A retained issued receipt is historical evidence. A failed or ambiguous
	// current delivery cannot silently reuse it for a new financial authority.
	// Existing owned restoration does not call this STOP/verification gate.
	if model.String(registration, "status") != "HEALTHY" {
		return nil, errors.New("SOURCE_AUTHORITY_UNAVAILABLE")
	}
	if model.String(receipt, "config_hash") != source.ConfigurationHash(registration) {
		return nil, errors.New("SOURCE_CONFIGURATION_CHANGED")
	}
	if model.String(receipt, "kind") != "AWS_CUR2" || model.String(receipt, "ingestion_job_id") != model.String(job, "id") || model.String(receipt, "revision_id") != model.String(job, "source_revision_id") || model.String(receipt, "raw_hash") != evidence.Hash(job["raw"]) || model.String(receipt, "canonical_hash") != evidence.Hash(job["canonical"]) {
		return nil, errors.New("SOURCE_RECEIPT_BINDING_INVALID")
	}
	revision, e := t.SourceRevisionGet(ctx, model.String(receipt, "revision_id"))
	if e != nil {
		return nil, e
	}
	if model.String(revision, "source_id") != model.String(registration, "id") {
		return nil, errors.New("SOURCE_REVISION_BINDING_INVALID")
	}
	if model.String(registration, "region") != model.String(res, "region") || model.String(res, "region") != "eu-west-1" {
		return nil, errors.New("SOURCE_REGION_INVALID")
	}
	found := false
	for _, id := range model.Strings(registration, "usage_account_ids") {
		if id == model.String(res, "account_id") {
			found = true
		}
	}
	if !found {
		return nil, errors.New("SOURCE_ACCOUNT_INVALID")
	}
	for _, k := range []string{"payer_account_id", "region", "export_arn", "bucket", "bucket_owner", "prefix"} {
		if model.String(receipt, k) != "" && model.String(receipt, k) != model.String(registration, k) {
			return nil, errors.New("SOURCE_CONFIGURATION_CHANGED")
		}
	}
	return receipt, nil
}

func currentSourceGate(ctx context.Context, t *store.Tx, connection string, binding model.Document, now time.Time) (model.Document, error) {
	if e := holdTrustedSourceSnapshot(ctx, t, connection); e != nil {
		return nil, e
	}
	registration, e := t.SourceGet(ctx, connection)
	if e != nil {
		return nil, e
	}
	if !model.Bool(registration, "enabled") {
		return nil, errors.New("SOURCE_REVOKED")
	}
	synced, e := time.Parse(time.RFC3339Nano, model.String(registration, "last_sync_at"))
	if e != nil || synced.After(now.Add(30*time.Second)) || now.Sub(synced) > 5*time.Minute || model.String(registration, "status") != "HEALTHY" {
		return nil, errors.New("SOURCE_AUTHORITY_STALE_OR_UNAVAILABLE")
	}
	receipts, e := t.SourceReceiptList(ctx, "AWS_COMMITMENT", connection)
	if e != nil {
		return nil, e
	}
	if len(receipts) == 0 {
		return nil, errors.New("COMMITMENT_SCOPE_INCOMPLETE")
	}
	receipt := receipts[len(receipts)-1]
	receipt, e = t.SourceReceiptGet(ctx, model.String(receipt, "id"))
	if e != nil {
		return nil, e
	}
	if model.String(receipt, "writer_role") != "finops_ingester" || model.String(receipt, "source_id") != connection || model.String(receipt, "kind") != "AWS_COMMITMENT" {
		return nil, errors.New("TRUSTED_COMMITMENT_ISSUER_INVALID")
	}
	if model.String(receipt, "config_hash") != source.ConfigurationHash(registration) {
		return nil, errors.New("COMMITMENT_SCOPE_INCOMPLETE")
	}
	scope := evidence.Object(receipt["commitment_scope"])
	observed, e := time.Parse(time.RFC3339Nano, model.String(scope, "observed_at"))
	if e != nil || observed.After(now.Add(30*time.Second)) || now.Sub(observed) > 5*time.Minute {
		return nil, errors.New("COMMITMENT_EVIDENCE_STALE")
	}
	if e = evidence.ValidateCommitmentScopeV3(scope, binding); e != nil {
		return nil, e
	}
	return scope, nil
}

func selectedTrustedSource(ctx context.Context, t *store.Tx, connection string, res model.Document) (model.Document, model.Document, error) {
	receipts, e := t.SourceReceiptList(ctx, "AWS_CUR2", connection)
	if e != nil {
		return nil, nil, e
	}
	if connection == "" || len(receipts) == 0 {
		return nil, nil, errors.New("TRUSTED_SOURCE_REQUIRED")
	}
	// Corrections are authoritative even if they invalidate an earlier claim.
	receipt := receipts[len(receipts)-1]
	job, e := t.Get(ctx, "ingestion_jobs", model.String(receipt, "ingestion_job_id"))
	if e != nil {
		return nil, nil, e
	}
	receipt, e = trustedJob(ctx, t, job, res)
	return job, receipt, e
}

func trustedActivityGate(ctx context.Context, t *store.Tx, res model.Document, now time.Time) error {
	latest, e := t.ActivityLatest(ctx, model.String(res, "id"))
	if e != nil {
		return errors.New("TRUSTED_WORKLOAD_SOURCE_REQUIRED")
	}
	state := activity.FreshActivity(now, latest, 2*time.Minute)
	if state.Status != "CLEAR" {
		return errors.New(state.ReasonCode)
	}
	return nil
}

func trustedWorkload(ctx context.Context, t *store.Tx, res, w model.Document) (model.Document, error) {
	if e := trustedActivityGate(ctx, t, res, time.Now()); e != nil {
		return nil, e
	}
	latest, e := t.ActivityLatest(ctx, model.String(res, "id"))
	if e != nil {
		return nil, e
	}
	d := evidence.Object(latest)
	w = model.Clone(w)
	for _, k := range []string{"incident", "deployment", "job"} {
		w[k] = d[k]
	}
	w["signals_at"] = d["received_at"]
	return w, nil
}

func (a *API) trustedSnapshot(ctx context.Context, t *store.Tx, in, res model.Document) (model.Document, error) {
	if e := rejectSubmittedAuthority(in); e != nil {
		return nil, e
	}
	start, e := inputTime(in, "start")
	if e != nil {
		return nil, e
	}
	end, e := inputTime(in, "end")
	if e != nil {
		return nil, e
	}
	if !start.Before(end) || end.After(a.now()) {
		return nil, errors.New("EVIDENCE_WINDOW_INVALID")
	}
	connection := model.String(in, "source_connection_id")
	receipts, e := periodReceipts(ctx, t, connection, start, end)
	if e != nil {
		return nil, e
	}
	var binding model.Document
	records, proofs, refs, scope, invoices := []model.Document{}, []model.Document{}, []model.Document{}, []model.Document{}, []model.Document{}
	fullScope := []model.Document{}
	var firstJob, firstReceipt model.Document
	seenInvoices := map[string]bool{}
	for _, receipt := range receipts {
		job, err := t.Get(ctx, "ingestion_jobs", model.String(receipt, "ingestion_job_id"))
		if err != nil {
			return nil, err
		}
		if _, err = trustedJob(ctx, t, job, res); err != nil {
			return nil, err
		}
		proof := evidence.Object(receipt["source_proof"])
		current, rows, err := evidence.Source(job, res, t.Tenant)
		if err != nil {
			return nil, err
		}
		entity := ""
		for _, row := range rows {
			v := model.String(row, "InvoiceIssuerName")
			if v == "" || entity != "" && v != entity {
				return nil, errors.New("SOURCE_ENTITY_AMBIGUOUS")
			}
			entity = v
		}
		current["payer_account_id"], current["invoice_entity"] = proof["payer_account_id"], entity
		proof["usage_account_id"], proof["region"], proof["currency"], proof["invoice_entity"] = res["account_id"], res["region"], current["currency"], entity
		proof["source_id"], proof["source_version"] = job["source_id"], evidence.Object(job["raw"])["source_version"]
		job["source_proof"] = proof
		current, rows, err = evidence.SourceV3(job, res, t.Tenant)
		if err != nil {
			return nil, err
		}
		if binding == nil {
			binding = current
			firstJob, firstReceipt = job, receipt
		} else if !evidence.SameBindingV3(binding, current) {
			return nil, errors.New("SOURCE_SCOPE_MISMATCH")
		}
		rows, err = evidence.PeriodRecords(rows, start, end)
		if err != nil {
			return nil, err
		}
		records = append(records, rows...)
		proofs = append(proofs, proof)
		ref := evidence.SourceReference(job, current)
		ref["source_receipt_id"], ref["source_revision_id"] = receipt["id"], receipt["revision_id"]
		refs = append(refs, ref)
		for _, row := range evidence.Rows(evidence.Object(job["canonical"])["records"]) {
			fullScope = append(fullScope, row)
			if model.String(row, "BillingAccountId") == model.String(binding, "payer_account_id") && model.String(row, "InvoiceIssuerName") == model.String(binding, "invoice_entity") && model.String(row, "BillingCurrency") == model.String(binding, "currency") {
				scope = append(scope, row)
			}
		}
		for _, invoice := range evidence.Rows(receipt["invoices"]) {
			native := evidence.Object(invoice["native"])
			id := model.String(native, "InvoiceId")
			if id != "" && !seenInvoices[id] && model.String(evidence.Object(native["BaseCurrencyAmount"]), "CurrencyCode") == model.String(binding, "currency") && model.String(evidence.Object(native["Entity"]), "InvoicingEntity") == model.String(binding, "invoice_entity") {
				invoices = append(invoices, invoice)
				seenInvoices[id] = true
			}
		}
	}
	samples, e := t.ActivitySamples(ctx, model.String(res, "id"), start, end)
	if e != nil {
		return nil, e
	}
	commitment, e := currentSourceGate(ctx, t, connection, binding, a.now())
	if e != nil {
		return nil, e
	}
	snapshot := model.Document{"schema_version": "3", "id": model.ID(), "resource_id": res["id"], "binding": binding, "source_connection_id": connection, "ingestion_job_id": firstJob["id"], "source_id": firstJob["source_id"], "source_version": evidence.Object(firstJob["raw"])["source_version"], "source_hash": evidence.Hash(firstJob["raw"]), "canonical_hash": evidence.Hash(firstJob["canonical"]), "source_receipt_id": firstReceipt["id"], "source_revision_id": firstReceipt["revision_id"], "source_proof": proofs[0], "source_proofs": proofs, "commitment_scope": commitment, "billing_records": records, "workload_samples": samples, "start": start.Format(time.RFC3339Nano), "end": end.Format(time.RFC3339Nano), "source_refs": refs, "invoices": invoices, "invoice_scope_records": scope}
	snapshot["source_scope_records"] = fullScope
	return snapshot, nil
}

func periodReceipts(ctx context.Context, t *store.Tx, connection string, start, end time.Time) ([]model.Document, error) {
	if connection == "" {
		return nil, errors.New("TRUSTED_SOURCE_REQUIRED")
	}
	receipts, e := t.SourceReceiptList(ctx, "AWS_CUR2", connection)
	if e != nil {
		return nil, e
	}
	latest := map[string]model.Document{}
	for _, r := range receipts {
		proof := evidence.Object(r["source_proof"])
		key := model.String(proof, "billing_period_start")
		if key == "" {
			key = model.String(proof, "period_start")
		}
		latest[key] = r
	}
	out := []model.Document{}
	for _, r := range latest {
		proof := evidence.Object(r["source_proof"])
		s, e1 := time.Parse(time.RFC3339Nano, model.String(proof, "period_start"))
		e, e2 := time.Parse(time.RFC3339Nano, model.String(proof, "period_end"))
		if e1 == nil && e2 == nil && s.Before(end) && e.After(start) {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return model.String(evidence.Object(out[i]["source_proof"]), "period_start") < model.String(evidence.Object(out[j]["source_proof"]), "period_start")
	})
	if len(out) == 0 {
		return nil, errors.New("TRUSTED_SOURCE_PERIOD_REQUIRED")
	}
	return out, nil
}

func validateSnapshotSources(ctx context.Context, t *store.Tx, snapshot, res model.Document) error {
	refs := evidence.Rows(snapshot["source_refs"])
	if len(refs) == 0 {
		return errors.New("SOURCE_RECEIPT_REQUIRED")
	}
	start, e := inputTime(snapshot, "start")
	if e != nil {
		return e
	}
	end, e := inputTime(snapshot, "end")
	if e != nil {
		return e
	}
	binding := evidence.Object(snapshot["binding"])
	selected, full, invoiceScope, proofs, invoiceReceipts := []model.Document{}, []model.Document{}, []model.Document{}, []model.Document{}, []model.Document{}
	seenInvoices := map[string]bool{}
	for _, ref := range refs {
		job, e := t.Get(ctx, "ingestion_jobs", model.String(ref, "ingestion_job_id"))
		if e != nil {
			return e
		}
		receipt, e := trustedJob(ctx, t, job, res)
		if e != nil {
			return e
		}
		if model.String(receipt, "id") != model.String(ref, "source_receipt_id") || model.String(receipt, "revision_id") != model.String(ref, "source_revision_id") || evidence.Hash(job["raw"]) != model.String(ref, "source_hash") || evidence.Hash(job["canonical"]) != model.String(ref, "canonical_hash") {
			return errors.New("BASELINE_SOURCE_CHANGED")
		}
		rows := evidence.Rows(evidence.Object(job["canonical"])["records"])
		full = append(full, rows...)
		target := []model.Document{}
		for _, r := range rows {
			if model.String(r, "ResourceId") == model.String(res, "provider_resource_id") {
				target = append(target, r)
			}
			if model.String(r, "BillingAccountId") == model.String(binding, "payer_account_id") && model.String(r, "InvoiceIssuerName") == model.String(binding, "invoice_entity") && model.String(r, "BillingCurrency") == model.String(binding, "currency") {
				invoiceScope = append(invoiceScope, r)
			}
		}
		target, e = evidence.PeriodRecords(target, start, end)
		if e != nil {
			return e
		}
		selected = append(selected, target...)
		proof := evidence.Object(receipt["source_proof"])
		proof["usage_account_id"], proof["region"], proof["currency"], proof["invoice_entity"] = res["account_id"], res["region"], binding["currency"], binding["invoice_entity"]
		proof["source_id"], proof["source_version"] = job["source_id"], evidence.Object(job["raw"])["source_version"]
		proofs = append(proofs, proof)
		for _, wrapper := range evidence.Rows(receipt["invoices"]) {
			native := evidence.Object(wrapper["native"])
			id := model.String(native, "InvoiceId")
			if id != "" && !seenInvoices[id] && model.String(evidence.Object(native["BaseCurrencyAmount"]), "CurrencyCode") == model.String(binding, "currency") && model.String(evidence.Object(native["Entity"]), "InvoicingEntity") == model.String(binding, "invoice_entity") {
				invoiceReceipts = append(invoiceReceipts, wrapper)
				seenInvoices[id] = true
			}
		}
		all, e := t.SourceReceiptList(ctx, "AWS_CUR2", model.String(receipt, "source_id"))
		if e != nil {
			return e
		}
		period := model.String(evidence.Object(receipt["source_proof"]), "billing_period_start")
		for n := len(all) - 1; n >= 0; n-- {
			if model.String(evidence.Object(all[n]["source_proof"]), "billing_period_start") == period {
				if model.String(all[n], "id") != model.String(receipt, "id") {
					if model.String(snapshot, "baseline_id") != "" {
						return errors.New("SOURCE_REVISION_SUPERSEDED")
					}
					current, e := t.Get(ctx, "ingestion_jobs", model.String(all[n], "ingestion_job_id"))
					if e != nil {
						return e
					}
					if _, e = trustedJob(ctx, t, current, res); e != nil {
						return e
					}
					start, e1 := inputTime(snapshot, "start")
					end, e2 := inputTime(snapshot, "end")
					if e1 != nil || e2 != nil {
						return errors.New("SOURCE_PERIOD_INVALID")
					}
					if baselineEconomicHash(job, res, start, end) != baselineEconomicHash(current, res, start, end) {
						return errors.New("BASELINE_ECONOMICS_CORRECTED")
					}
				}
				break
			}
		}
	}
	if documentRowsHash(selected) != documentRowsHash(evidence.Rows(snapshot["billing_records"])) || documentRowsHash(full) != documentRowsHash(evidence.Rows(snapshot["source_scope_records"])) || documentRowsHash(invoiceScope) != documentRowsHash(evidence.Rows(snapshot["invoice_scope_records"])) || documentRowsHash(proofs) != documentRowsHash(evidence.Rows(snapshot["source_proofs"])) || documentRowsHash(invoiceReceipts) != documentRowsHash(evidence.Rows(snapshot["invoices"])) {
		return errors.New("SNAPSHOT_SOURCE_RECORDS_CHANGED")
	}
	samples, e := t.ActivitySamples(ctx, model.String(res, "id"), start, end)
	if e != nil {
		return e
	}
	if documentRowsHash(samples) != documentRowsHash(evidence.Rows(snapshot["workload_samples"])) {
		return errors.New("SNAPSHOT_ACTIVITY_RECEIPTS_CHANGED")
	}
	scope := evidence.Object(snapshot["commitment_scope"])
	commitment, e := t.SourceReceiptGet(ctx, model.String(scope, "receipt_id"))
	if e != nil {
		return e
	}
	if model.String(commitment, "kind") != "AWS_COMMITMENT" || model.String(commitment, "writer_role") != "finops_ingester" || evidence.Hash(commitment["commitment_scope"]) != evidence.Hash(scope) {
		return errors.New("SNAPSHOT_COMMITMENT_RECEIPT_CHANGED")
	}
	return nil
}

func documentRowsHash(rows []model.Document) string {
	hashes := make([]string, 0, len(rows))
	for _, row := range rows {
		hashes = append(hashes, evidence.Hash(row))
	}
	sort.Strings(hashes)
	return evidence.Hash(hashes)
}

// Daily export refreshes and invoice metadata alone do not rewrite a frozen
// baseline. A change to its actual native economics invalidates new stops and
// claims until an explicitly sealed replacement resolves the correction.
func baselineEconomicHash(job, res model.Document, start, end time.Time) string {
	fingerprints := []string{}
	for _, r := range evidence.Rows(evidence.Object(job["canonical"])["records"]) {
		// A payer-wide correction may introduce historical commitments or credits
		// in another member/region. Those affect the target's avoidable-price proof
		// even when its own compute rows and today's commitment counts stay equal.
		s, e1 := time.Parse(time.RFC3339Nano, model.String(r, "ChargePeriodStart"))
		e, e2 := time.Parse(time.RFC3339Nano, model.String(r, "ChargePeriodEnd"))
		if e1 != nil || e2 != nil || !s.Before(end) || !e.After(start) {
			continue
		}
		d := model.Document{}
		for _, k := range []string{"ResourceId", "SubAccountId", "RegionId", "BillingCurrency", "BillingAccountId", "InvoiceIssuerName", "ServiceName", "BilledCost", "ChargePeriodStart", "ChargePeriodEnd", "x_PricingBasis", "x_NativeComputeCost"} {
			d[k] = r[k]
		}
		raw := evidence.Object(r["x_ProviderFields"])
		for _, k := range []string{"product_product_family", "product/productFamily", "line_item_line_item_type", "lineItem/LineItemType", "pricing_term", "pricing/term", "line_item_usage_type", "lineItem/UsageType", "line_item_operation", "lineItem/Operation", "reservation_reservation_a_r_n", "reservation/ReservationARN", "savings_plan_savings_plan_a_r_n", "savingsPlan/SavingsPlanARN"} {
			d[k] = raw[k]
		}
		fingerprints = append(fingerprints, evidence.Hash(d))
	}
	sort.Strings(fingerprints)
	return evidence.Hash(fingerprints)
}

func (a *API) createTrustedBaseline(ctx context.Context, t *store.Tx, in model.Document) (model.Document, error) {
	res, e := t.Get(ctx, "resources", model.String(in, "resource_id"))
	if e != nil {
		return nil, e
	}
	b, e := a.trustedSnapshot(ctx, t, in, res)
	if e != nil {
		return nil, evidenceProblem(e)
	}
	schedule, e := t.Get(ctx, "schedules", model.String(in, "schedule_id"))
	if e != nil {
		return nil, e
	}
	if model.String(schedule, "workload_id") != model.String(res, "workload_id") {
		return nil, errors.New("WORKLOAD_BINDING_INVALID")
	}
	b["schedule"], b["schedule_id"], b["activation_at"], b["evidence_as_of"] = schedule, schedule["id"], a.now().Format(time.RFC3339Nano), a.now().Format(time.RFC3339Nano)
	proof, e := t.EvidenceCreate(ctx, "proof_set", model.Document{"schema_version": "3", "resource_id": res["id"], "baseline_id": b["id"], "binding": b["binding"], "source_receipt_id": b["source_receipt_id"], "source_refs": b["source_refs"], "activity_hash": evidence.Hash(b["workload_samples"])})
	if e != nil {
		return nil, e
	}
	b["proof_set_id"] = proof["id"]
	result, e := a.economics(ctx, "v3/evaluate", baselineInput(b))
	if e != nil {
		return nil, e
	}
	b["evaluation"] = result
	if !model.Bool(result, "pre_execution_ready") {
		return nil, problem(422, model.String(result, "reason_code"), "trusted baseline evidence is incomplete")
	}
	b, e = t.EvidenceCreate(ctx, "baseline", b)
	if e == nil {
		e = t.Audit(ctx, "evidence-engine", "baseline.sealed", model.String(b, "id"), model.Document{"source_receipt_id": b["source_receipt_id"], "resource_id": res["id"]})
	}
	return b, e
}

func (a *API) createTrustedMeasurement(ctx context.Context, t *store.Tx, in model.Document) (model.Document, error) {
	m, e := t.EvidenceGet(ctx, "measurement", model.String(in, "measurement_id"))
	if e != nil {
		return nil, e
	}
	b, e := t.EvidenceGet(ctx, "baseline", model.String(m, "baseline_id"))
	if e != nil {
		return nil, e
	}
	if model.String(b, "schema_version") != "3" {
		return nil, errors.New("EVIDENCE_V3_REQUIRED")
	}
	res, e := t.Get(ctx, "resources", model.String(m, "resource_id"))
	if e != nil {
		return nil, e
	}
	snapshot, e := a.trustedSnapshot(ctx, t, in, res)
	if e != nil {
		return nil, evidenceProblem(e)
	}
	if !evidence.SameBindingV3(evidence.Object(snapshot["binding"]), evidence.Object(b["binding"])) {
		return nil, errors.New("MEASUREMENT_BINDING_INVALID")
	}
	start, e := inputTime(snapshot, "start")
	if e != nil {
		return nil, e
	}
	activation, e := inputTime(m, "activation_at")
	if e != nil {
		return nil, e
	}
	if start.Before(activation) {
		return nil, errors.New("MEASUREMENT_WINDOW_INVALID")
	}
	snapshot["baseline_id"], snapshot["measurement_id"] = b["id"], m["id"]
	snapshot["evidence_as_of"] = a.now().Format(time.RFC3339Nano)
	// Coverage and absence are derived by the evaluator from the complete pinned
	// revision and executor-owned intervals, never a caller's zero-cost samples.
	return t.EvidenceCreate(ctx, "measurement_snapshot", snapshot)
}

func sealProofSet(ctx context.Context, t *store.Tx, b, res model.Document, now time.Time, readiness model.Document) (model.Document, error) {
	job, receipt, e := selectedTrustedSource(ctx, t, model.String(b, "source_connection_id"), res)
	if e != nil {
		return nil, e
	}
	_ = job
	scope, e := currentSourceGate(ctx, t, model.String(b, "source_connection_id"), evidence.Object(b["binding"]), now)
	if e != nil {
		return nil, e
	}
	if e = trustedActivityGate(ctx, t, res, now); e != nil {
		return nil, e
	}
	latest, e := t.ActivityLatest(ctx, model.String(res, "id"))
	if e != nil {
		return nil, e
	}
	d := model.Document{"schema_version": "3", "resource_id": res["id"], "baseline_id": b["id"], "binding": b["binding"], "source_receipt_id": receipt["id"], "activity_receipt": latest, "commitment_scope": scope, "checked_at": now.UTC().Format(time.RFC3339Nano)}
	review, e := currentDependencyReview(ctx, t, model.String(res, "id"), "", "", time.Now())
	if e != nil {
		return nil, e
	}
	d["dependency_review_id"], d["dependency_graph_hash"] = review["id"], review["graph_hash"]
	for _, key := range []string{"slo_objective_id", "slo_objective_version", "slo_objective_hash", "slo_evaluation_id", "slo_evaluation_hash"} {
		d[key] = readiness[key]
	}
	return t.EvidenceCreate(ctx, "proof_set", d)
}

func proofPlanCheck(ctx context.Context, t *store.Tx, p model.Plan, b, res, ready model.Document) error {
	if p.ProofSetID == "" || p.ProofSetID != model.String(ready, "proof_set_id") {
		return errors.New("PROOF_SET_REQUIRED")
	}
	proof, e := t.EvidenceGet(ctx, "proof_set", p.ProofSetID)
	if e != nil {
		return e
	}
	if model.String(proof, "baseline_id") != p.BaselineID || model.String(proof, "resource_id") != model.String(res, "id") || !evidence.SameBindingV3(evidence.Object(proof["binding"]), evidence.Object(b["binding"])) {
		return errors.New("PROOF_SET_BINDING_INVALID")
	}
	if model.String(proof, "dependency_review_id") != p.DependencyReviewID || model.String(proof, "dependency_graph_hash") != p.DependencyGraphHash {
		return errors.New("DEPENDENCY_PROOF_SET_INVALID")
	}
	if model.String(proof, "slo_objective_id") != p.SLOObjectiveID || model.Number(proof, "slo_objective_version") != p.SLOObjectiveVersion || model.String(proof, "slo_objective_hash") != p.SLOObjectiveHash || model.String(proof, "slo_evaluation_id") != p.SLOEvaluationID || model.String(proof, "slo_evaluation_hash") != p.SLOEvaluationHash {
		return errors.New("SLO_PROOF_SET_INVALID")
	}
	_, receipt, e := selectedTrustedSource(ctx, t, model.String(b, "source_connection_id"), res)
	if e != nil {
		return e
	}
	if model.String(receipt, "id") != model.String(proof, "source_receipt_id") {
		return errors.New("PROOF_SET_SUPERSEDED")
	}
	if _, e = currentSourceGate(ctx, t, model.String(b, "source_connection_id"), evidence.Object(b["binding"]), time.Now()); e != nil {
		return e
	}
	if e = trustedActivityGate(ctx, t, res, time.Now()); e != nil {
		return e
	}
	return nil
}
