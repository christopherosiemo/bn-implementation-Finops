package service

import (
	"context"
	"encoding/json"
	"errors"
	"math/big"
	"sort"
	"strings"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/awsservice"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/evidence"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/source"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/jackc/pgx/v5"
)

const commissioningEvidenceLimit = 10000

func commissioningKnownOwner(owner string) bool {
	switch strings.ToUpper(strings.TrimSpace(owner)) {
	case "", "UNKNOWN", "UNOWNED", "NONE", "NULL":
		return false
	}
	return true
}
func commissioningAccountCharge(record model.Document, account string) bool {
	return model.String(record, "SubAccountId") == account || databaseBillingPayerCharge(record, account)
}
func commissioningPercent(amount, denominator *big.Rat, complete bool) any {
	if !complete || amount == nil || denominator == nil || denominator.Sign() <= 0 {
		return nil
	}
	return databaseCoverageAmount(new(big.Rat).Mul(new(big.Rat).Quo(amount, denominator), big.NewRat(100, 1)))
}
func commissioningMoney(value any) (*big.Rat, bool) {
	text, ok := value.(string)
	if !ok || !databaseCoverageDecimal.MatchString(text) {
		return nil, false
	}
	n, ok := new(big.Rat).SetString(text)
	return n, ok
}
func commissioningDimension(key, status string, reasons, remediation []string, details model.Document, affected any) model.Document {
	if reasons == nil {
		reasons = []string{}
	}
	if remediation == nil {
		remediation = []string{}
	}
	if affected == nil {
		affected = []model.Document{}
	}
	return model.Document{"key": key, "status": status, "reason_codes": databaseSortedReasons(reasons), "remediation": remediation, "affected_spend": affected, "details": details}
}
func commissioningAffected(coverage model.Document, key string) any {
	out := []model.Document{}
	for _, row := range storageRows(coverage["currencies"]) {
		value, ok := row[key].(string)
		if !ok || row["currency"] == nil {
			return nil
		}
		out = append(out, model.Document{"currency": row["currency"], "amount": value})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// Four exclusive positive-charge partitions reconcile to detected spend.
// Workload allocation and ownership are overlapping overlays, never extra cost.
func commissioningCoverageProjection(input model.Document, account, region string) model.Document {
	out := []model.Document{}
	complete := true
	reasons := append([]string{}, model.Strings(input, "blockers")...)
	for _, group := range storageRows(input["groups"]) {
		row := model.Document{"currency": group["currency"], "denominator_complete": false, "percentages": model.Document{"analysed": nil, "observation_only": nil, "blocked": nil, "unsupported": nil, "unallocated": nil}}
		for _, key := range []string{"detected_spend", "analysed_spend", "observation_only_spend", "blocked_spend", "unsupported_spend", "unallocated_spend", "unowned_spend", "credits", "net_spend"} {
			row[key] = group[key]
		}
		denominator, ok := commissioningMoney(group["detected_spend"])
		trusted := ok && denominator.Sign() >= 0 && model.Bool(group, "complete") && databaseCoverageCurrency.MatchString(model.String(group, "currency"))
		sum := new(big.Rat)
		parts := map[string]*big.Rat{}
		for _, key := range []string{"analysed", "observation_only", "blocked", "unsupported", "unallocated"} {
			value, valid := commissioningMoney(group[key+"_spend"])
			if !valid || value.Sign() < 0 {
				trusted = false
				if !valid {
					row[key+"_spend"] = nil
				}
			} else {
				parts[key] = value
				if key != "unallocated" {
					sum.Add(sum, value)
				}
			}
		}
		credits, creditsOK := commissioningMoney(group["credits"])
		net, netOK := commissioningMoney(group["net_spend"])
		if !creditsOK || !netOK || credits.Sign() > 0 {
			trusted = false
		} else if ok && new(big.Rat).Add(denominator, credits).Cmp(net) != 0 {
			trusted = false
			reasons = append(reasons, "COMMISSIONING_CREDITS_DO_NOT_RECONCILE")
		}
		if ok && sum.Cmp(denominator) != 0 {
			trusted = false
			reasons = append(reasons, "COMMISSIONING_COVERAGE_PARTITIONS_DO_NOT_RECONCILE")
		}
		if ok && parts["unallocated"] != nil && parts["unallocated"].Cmp(denominator) > 0 {
			trusted = false
			reasons = append(reasons, "COMMISSIONING_ALLOCATION_OVERLAY_INVALID")
		}
		row["denominator_complete"] = trusted
		percentages := storageObject(row["percentages"])
		for key, value := range parts {
			percentages[key] = commissioningPercent(value, denominator, trusted)
		}
		row["percentages"] = percentages
		if !trusted {
			complete = false
		}
		out = append(out, row)
	}
	if len(out) == 0 {
		complete = false
	}
	if !complete {
		reasons = append(reasons, "COMMISSIONING_TRUSTED_SPEND_DENOMINATOR_UNAVAILABLE")
	}
	return model.Document{"scope": model.Document{"account_id": account, "inventory_region": region, "financial_regions": "ALL_REGIONS_INCLUDING_GLOBAL", "allocation_basis": "EXACT_CANONICAL_RESOURCE_WORKLOAD_MAPPING", "allocation_overlay": "OVERLAPS_FOUR_EXCLUSIVE_PARTITIONS_DO_NOT_ADD"}, "period": input["period"], "currencies": out, "complete": complete, "reason_codes": databaseSortedReasons(reasons), "service_groups": input["service_groups"]}
}

func commissioningReadDocuments(ctx context.Context, tx *store.Tx, query string, args ...any) ([]model.Document, error) {
	rows, e := tx.Query(ctx, query, args...)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []model.Document{}
	for rows.Next() {
		var raw []byte
		if e = rows.Scan(&raw); e != nil {
			return nil, e
		}
		var d model.Document
		if e = json.Unmarshal(raw, &d); e != nil {
			return nil, e
		}
		out = append(out, d)
		if len(out) > commissioningEvidenceLimit {
			return nil, errors.New("COMMISSIONING_EVIDENCE_BOUND")
		}
	}
	return out, rows.Err()
}
func commissioningSourceInAccount(d model.Document, account string) bool {
	return d["account_id"] == account || d["payer_account_id"] == account || awsservice.Contains(model.Strings(d, "usage_account_ids"), account)
}
func commissioningFresh(value any, now time.Time, maxAge time.Duration) bool {
	text, ok := value.(string)
	if !ok {
		return false
	}
	at, e := time.Parse(time.RFC3339Nano, text)
	return e == nil && !at.After(now.Add(time.Minute)) && now.Sub(at) <= maxAge
}

// CommissioningEvidence is a persisted-evidence read broker for the ingestion
// identity. It performs no provider calls, public-price lookup or mutation.
// Provider first-page access is reported separately by the preflight reader.
func (a *API) CommissioningEvidence(ctx context.Context, tx *store.Tx, accountID, region string, now time.Time) (model.Document, error) {
	if now.IsZero() || region != "eu-west-1" || awsservice.ValidateScope(awsservice.Scope{TenantID: tx.Tenant, AccountID: accountID, Region: region}) != nil {
		return nil, errors.New("COMMISSIONING_EVIDENCE_SCOPE_INVALID")
	}
	snapshotAPI := *a
	snapshotAPI.Clock = func() time.Time { return now.UTC() }
	// Reporting uses hash-only authority brokers even when a component caller
	// omitted process-role configuration; it never reads raw declarations.
	snapshotAPI.Config.Role = "commissioning"
	resources, e := commissioningReadDocuments(ctx, tx, `SELECT r.document||jsonb_build_object('id',r.id,'version',r.version,'workload_exists',EXISTS(SELECT FROM entities w WHERE w.tenant_id=r.tenant_id AND w.kind='workloads' AND w.id=r.document->>'workload_id')) FROM entities r WHERE r.tenant_id=$1 AND r.kind='resources' AND r.document->>'provider'='AWS' AND r.document->>'account_id'=$2 ORDER BY r.id LIMIT $3`, tx.Tenant, accountID, commissioningEvidenceLimit+1)
	if e != nil {
		return nil, e
	}
	sourceRows, e := commissioningReadDocuments(ctx, tx, `SELECT jsonb_build_object('id',id) FROM source_registrations WHERE tenant_id=$1 AND (document->>'account_id'=$2 OR document->>'payer_account_id'=$2 OR document->'usage_account_ids' ? $2) ORDER BY id LIMIT 257`, tx.Tenant, accountID)
	if e != nil {
		return nil, e
	}
	if len(sourceRows) > 256 {
		return nil, errors.New("COMMISSIONING_SOURCE_BOUND")
	}
	sources := []model.Document{}
	for _, s := range sourceRows {
		d, e := tx.SourceGet(ctx, model.String(s, "id"))
		if e != nil {
			return nil, e
		}
		if commissioningSourceInAccount(d, accountID) {
			sources = append(sources, d)
		}
	}
	rawCoverage, e := snapshotAPI.databaseCoverageScoped(ctx, tx, accountID, region)
	if e != nil {
		return nil, e
	}
	coverage := commissioningCoverageProjection(rawCoverage, accountID, region)
	billing, billingDim, commitments, commitmentDim, refs, e := commissioningBilling(ctx, tx, sources, rawCoverage, coverage, accountID, now)
	if e != nil {
		return nil, e
	}
	for _, r := range resources {
		if databaseResource(r) || r["service_family"] == "ELASTICACHE" || r["service_family"] == "DYNAMODB" {
			commitmentDim["status"], commitments["status"] = "PARTIAL", "PARTIAL"
			codes := append(model.Strings(commitmentDim, "reason_codes"), "SERVICE_SPECIFIC_COMMITMENT_SCOPE_NOT_ESTABLISHED")
			commitmentDim["reason_codes"], commitments["reason_codes"] = databaseSortedReasons(codes), databaseSortedReasons(codes)
		}
	}
	ownership, ownershipDim, mappingDim := commissioningOwnership(resources, coverage)
	authority, authorityDim, e := commissioningAuthority(ctx, tx, resources, now)
	if e != nil {
		return nil, e
	}
	telemetry, metricsDim, e := commissioningTelemetry(ctx, tx, resources, sources, accountID, region, now)
	if e != nil {
		return nil, e
	}
	refs = append(refs, storageRows(telemetry["evidence_refs"])...)
	recommendationStatus := "NOT_CONFIGURED"
	recommendationReasons := []string{"COMMISSIONING_NO_CURRENT_ECONOMIC_ASSESSMENT"}
	hasAnalysis := false
	allAnalysed := len(storageRows(coverage["currencies"])) > 0 && model.Bool(coverage, "complete")
	for _, row := range storageRows(coverage["currencies"]) {
		n, ok := new(big.Rat).SetString(model.String(row, "analysed_spend"))
		if ok && n.Sign() > 0 {
			hasAnalysis = true
		}
		if !ok || model.String(row, "analysed_spend") != model.String(row, "detected_spend") {
			allAnalysed = false
		}
	}
	if hasAnalysis {
		recommendationStatus = "PARTIAL"
		recommendationReasons = []string{"COMMISSIONING_ECONOMIC_ASSESSMENTS_COVER_SELECTED_CHARGES_ONLY"}
	}
	if allAnalysed && hasAnalysis {
		recommendationStatus = "READY"
		recommendationReasons = []string{}
	}
	currentness, e := snapshotAPI.commissioningRecommendationCurrentness(ctx,tx,accountID,region)
	if e != nil { return nil,e }
	coverage["recommendation_currentness"] = currentness
	currentnessCounts := storageObject(currentness["assumption_context_counts"])
	if model.Number(currentnessCounts,"STALE")>0 || model.Number(currentnessCounts,"BLOCKED")>0 || !model.Bool(currentness,"complete") {
		recommendationStatus="PARTIAL"
		recommendationReasons=append(recommendationReasons,"COMMISSIONING_RECOMMENDATIONS_REQUIRE_REANALYSIS")
		for reason := range storageObject(currentness["reason_counts"]) { recommendationReasons=append(recommendationReasons,reason) }
	}
	coverageDim := commissioningDimension("RECOMMENDATION_COVERAGE", recommendationStatus, recommendationReasons, []string{"Resolve the listed evidence gaps and run existing read-only assessments; no execution role is required."}, coverage, commissioningAffected(coverage, "blocked_spend"))
	qualityReasons := append([]string{}, model.Strings(coverage, "reason_codes")...)
	for _, s := range sources {
		if !model.Bool(s, "enabled") || model.Bool(s, "revoked") {
			qualityReasons = append(qualityReasons, "COMMISSIONING_SOURCE_REVOKED")
		} else if s["status"] != "HEALTHY" {
			qualityReasons = append(qualityReasons, "COMMISSIONING_SOURCE_NOT_HEALTHY")
		}
	}
	if len(resources) == 0 {
		qualityReasons = append(qualityReasons, "COMMISSIONING_NO_PERSISTED_INVENTORY")
	}
	if metricsDim["status"] != "READY" {
		qualityReasons = append(qualityReasons, "COMMISSIONING_REQUIRED_TELEMETRY_NOT_ESTABLISHED")
	}
	qualityStatus := "READY"
	if len(qualityReasons) > 0 {
		qualityStatus = "PARTIAL"
	}
	qualityDim := commissioningDimension("DATA_QUALITY", qualityStatus, qualityReasons, []string{"Synchronize commissioned sources and inspect missing, stale, denied or incomplete evidence; absence is never zero."}, model.Document{"source_count": len(sources), "resource_count": len(resources), "denominator_complete": coverage["complete"], "missing_is_zero": false}, nil)
	return model.Document{"schema_version": "1", "account_id": accountID, "region": region, "checked_at": now.UTC().Format(time.RFC3339Nano), "dimensions": []model.Document{billingDim, metricsDim, ownershipDim, mappingDim, authorityDim, commitmentDim, coverageDim, qualityDim}, "billing": billing, "telemetry": telemetry, "ownership": ownership, "configuration_authority": authority, "commitments": commitments, "coverage": coverage, "coverage_scope": coverage["scope"], "evidence_refs": refs, "execution_authorized": false, "verified_saving": nil}, nil
}

func commissioningBilling(ctx context.Context, tx *store.Tx, sources []model.Document, rawCoverage, coverage model.Document, account string, now time.Time) (model.Document, model.Document, model.Document, model.Document, []model.Document, error) {
	details := []model.Document{}
	refs := storageRows(rawCoverage["source_refs"])
	reasons := []string{}
	commitReasons := []string{}
	commitRows := []model.Document{}
	completeCommitments := true
	for _, registration := range sources {
		if registration["kind"] != "AWS_CUR2" {
			continue
		}
		d := model.Document{"source_id": registration["id"], "source_version": registration["version"], "payer_account_id": registration["payer_account_id"], "usage_account_ids": registration["usage_account_ids"], "region": registration["region"], "bucket": registration["bucket"], "prefix": registration["prefix"], "status": registration["status"], "reason_code": registration["reason_code"], "last_sync_at": registration["last_sync_at"], "oldest_usable_history": nil, "latest_persisted_delivery_at": nil, "export_finality": nil, "invoice_finality": "UNAVAILABLE", "reconciliation_status": "NOT_EVALUATED", "reconciliation": []model.Document{}, "native_invoice_count": nil, "invoices": []model.Document{}}
		if !model.Bool(registration, "enabled") || model.Bool(registration, "revoked") || registration["status"] != "HEALTHY" {
			reasons = append(reasons, "BILLING_SOURCE_NOT_CURRENT")
		}
		if !commissioningFresh(registration["last_sync_at"], now, 48*time.Hour) {
			reasons = append(reasons, "BILLING_DELIVERY_STALE_OR_UNAVAILABLE")
		}
		var oldest *string
		if e := tx.QueryRow(ctx, `SELECT min(r.document->'source_proof'->>'period_start') FROM source_receipts r JOIN source_checkpoints c ON c.tenant_id=r.tenant_id AND c.source_id=r.source_id AND c.document->>'receipt_id'=r.id WHERE r.tenant_id=$1 AND r.source_id=$2 AND r.kind='AWS_CUR2' AND starts_with(c.checkpoint_key,$3)`, tx.Tenant, registration["id"], "month:"+source.ConfigurationHash(registration)+":").Scan(&oldest); e != nil {
			return nil, nil, nil, nil, nil, e
		}
		if oldest != nil {
			if _, e := time.Parse(time.RFC3339Nano, *oldest); e == nil {
				d["oldest_usable_history"] = *oldest
			}
		}
		if id := model.String(registration, "latest_receipt_id"); id != "" {
			receipt, e := tx.SourceReceiptGet(ctx, id)
			if e != nil && !errors.Is(e, pgx.ErrNoRows) {
				return nil, nil, nil, nil, nil, e
			}
			if receipt != nil && receipt["source_id"] == registration["id"] && receipt["kind"] == "AWS_CUR2" && receipt["config_hash"] == source.ConfigurationHash(registration) {
				d["latest_persisted_delivery_at"] = receipt["created_at"]
				d["latest_native_execution_at"] = receipt["execution_created_at"]
				d["export_finality"] = storageObject(receipt["source_proof"])["state"]
				invoices, invoiceStatus := commissioningInvoiceMetadata(receipt, model.String(registration, "payer_account_id"), now)
				d["invoices"], d["native_invoice_count"], d["invoice_finality"] = invoices, len(invoices), invoiceStatus
				if jobID := model.String(receipt, "ingestion_job_id"); jobID != "" {
					job, err := tx.Get(ctx, "ingestion_jobs", jobID)
					if err != nil && !errors.Is(err, pgx.ErrNoRows) {
						return nil, nil, nil, nil, nil, err
					}
					canonical := storageObject(job["canonical"])
					if job != nil && evidence.Hash(canonical) == receipt["canonical_hash"] {
						metadata := []model.Document{}
						for currency, value := range storageObject(canonical["reconciliation"]) {
							if !databaseCoverageCurrency.MatchString(currency) {
								continue
							}
							r := storageObject(value)
							ratio := r["ratio"]
							if ratio != nil {
								if n, ok := commissioningMoney(ratio); !ok || n.Sign() < 0 || n.Cmp(big.NewRat(1, 1)) > 0 {
									ratio = nil
								}
							}
							variance := r["variance"]
							if variance != nil {
								if _, ok := commissioningMoney(variance); !ok {
									variance = nil
								}
							}
							metadata = append(metadata, model.Document{"currency": currency, "status": r["status"], "ratio": ratio, "variance": variance, "basis": "PERSISTED_NATIVE_SOURCE_NORMALIZATION", "scope": "EXPORT_CURRENCY_SCOPE_NOT_REVALIDATED_AS_INVOICE_ENTITY_SCOPE", "ingestion_job_id": jobID, "source_receipt_id": receipt["id"], "canonical_hash": receipt["canonical_hash"]})
						}
						d["reconciliation"] = metadata
						sort.Slice(metadata, func(i, j int) bool {
							return model.String(metadata[i], "currency") < model.String(metadata[j], "currency")
						})
						if len(metadata) > 0 {
							d["reconciliation_status"] = "PERSISTED_RESULT_AVAILABLE_INVOICE_SCOPE_NOT_EVALUATED"
						}
					}
				}
			}
		}
		details = append(details, d)
		commitment := model.Document{"source_id": registration["id"], "payer_account_id": registration["payer_account_id"], "status": "NOT_CONFIGURED", "scope": nil, "observed_at": nil, "savings_plan_count": nil, "service_specific_exposure": "NOT_ESTABLISHED_BY_SHARED_SP_RECEIPT"}
		if id := model.String(registration, "commitment_receipt_id"); id != "" {
			receipt, e := tx.SourceReceiptGet(ctx, id)
			if e != nil && !errors.Is(e, pgx.ErrNoRows) {
				return nil, nil, nil, nil, nil, e
			}
			scope := storageObject(receipt["commitment_scope"])
			if receipt != nil && receipt["kind"] == "AWS_COMMITMENT" && receipt["source_id"] == registration["id"] && receipt["config_hash"] == source.ConfigurationHash(registration) {
				commitment["receipt_id"], commitment["scope"], commitment["observed_at"], commitment["savings_plan_count"] = receipt["id"], scope["scope"], scope["observed_at"], scope["savings_plan_count"]
				commitment["status"] = "PARTIAL"
				if lambdaCommitmentClosure(registration, receipt, now) {
					commitment["status"] = "READY"
				}
				refs = append(refs, model.Document{"kind": "AWS_COMMITMENT", "id": receipt["id"], "sha256": evidence.Hash(receipt)})
			}
		}
		if commitment["status"] != "READY" {
			completeCommitments = false
			commitReasons = append(commitReasons, "COMMITMENT_PAYER_SCOPE_OR_MARGINAL_EXPOSURE_UNRESOLVED")
		}
		commitRows = append(commitRows, commitment)
	}
	status := "READY"
	if len(details) == 0 {
		status = "NOT_CONFIGURED"
		reasons = append(reasons, "BILLING_NOT_READY_NO_REGISTERED_CUR2_EXPORT")
	}
	if len(details) > 0 && (!model.Bool(coverage, "complete") || len(reasons) > 0) {
		status = "PARTIAL"
		reasons = append(reasons, "BILLING_NOT_READY_TRUSTED_CURRENT_WINDOW_UNAVAILABLE")
	}
	billing := model.Document{"status": status, "sources": details, "canonical_observations": rawCoverage["billing_metadata"], "period": coverage["period"], "denominator_complete": coverage["complete"], "pricing_fallback": "NONE", "baseline_completeness": "MUST_BE_EVALUATED_FROM_ACTUAL_BASELINE_OBSERVATIONS", "reason_codes": databaseSortedReasons(reasons)}
	dim := commissioningDimension("BILLING", status, reasons, []string{"Commission or synchronize the approved unfiltered hourly resource-level CUR 2.0 export, inspect delivery integrity and collect genuine history; public prices do not replace missing billing."}, billing, nil)
	commitStatus := "READY"
	if len(commitRows) == 0 {
		commitStatus = "NOT_CONFIGURED"
		commitReasons = append(commitReasons, "COMMITMENT_EVIDENCE_NOT_CONFIGURED")
	} else if !completeCommitments {
		commitStatus = "PARTIAL"
	}
	commitments := model.Document{"status": commitStatus, "sources": commitRows, "scope_note": "Shared Savings Plan/RI scope receipts do not establish every service-specific reservation or Database Savings Plan exposure.", "reason_codes": databaseSortedReasons(commitReasons)}
	commitDim := commissioningDimension("COMMITMENT_EVIDENCE", commitStatus, commitReasons, []string{"Synchronize native payer/member commitment evidence; unresolved fixed obligations block numerical avoidable-cost estimates, without requiring purchasing authority."}, commitments, nil)
	return billing, dim, commitments, commitDim, refs, nil
}

func commissioningOwnership(resources []model.Document, coverage model.Document) (model.Document, model.Document, model.Document) {
	unknownOwner, unmapped := 0, 0
	for _, r := range resources {
		if !commissioningKnownOwner(model.String(r, "owner")) {
			unknownOwner++
		}
		if !model.Bool(r, "workload_exists") {
			unmapped++
		}
	}
	details := model.Document{"resource_count": len(resources), "unknown_owner_count": unknownOwner, "unmapped_workload_count": unmapped, "basis": "PERSISTED_RESOURCE_AND_EXISTING_TENANT_WORKLOAD_IDENTITY", "inferred_ownership": false}
	status, ms := "READY", "READY"
	ownerReasons, mappingReasons := []string{}, []string{}
	if len(resources) == 0 {
		status, ms = "NOT_CONFIGURED", "NOT_CONFIGURED"
		ownerReasons = append(ownerReasons, "OWNERSHIP_INVENTORY_UNAVAILABLE")
		mappingReasons = append(mappingReasons, "WORKLOAD_MAPPING_INVENTORY_UNAVAILABLE")
	}
	if unknownOwner > 0 {
		status = "PARTIAL"
		ownerReasons = append(ownerReasons, "RESOURCE_OWNER_UNKNOWN")
	}
	if unmapped > 0 {
		ms = "PARTIAL"
		mappingReasons = append(mappingReasons, "RESOURCE_WORKLOAD_MAPPING_UNRESOLVED")
	}
	return details, commissioningDimension("OWNERSHIP", status, ownerReasons, []string{"Assign evidenced resource ownership through the normal workload/inventory flow; unowned spend remains in coverage."}, details, commissioningAffected(coverage, "unowned_spend")), commissioningDimension("WORKLOAD_MAPPING", ms, mappingReasons, []string{"Bind exact resource identities to existing tenant workloads; names and bucket tags alone do not establish allocation."}, details, commissioningAffected(coverage, "unallocated_spend"))
}

func commissioningInvoiceMetadata(receipt model.Document, payer string, now time.Time) ([]model.Document, string) {
	out := []model.Document{}
	seen := map[string]bool{}
	allIssued := true
	for _, wrapper := range storageRows(receipt["invoices"]) {
		n := storageObject(wrapper["native"])
		id := model.String(n, "InvoiceId")
		amount := storageObject(n["BaseCurrencyAmount"])
		entity := storageObject(n["Entity"])
		nativeStatus := model.String(n, "TaxAuthorityStatus")
		status := nativeStatus
		if id == "" || seen[id] || n["AccountId"] != payer || !databaseCoverageCurrency.MatchString(model.String(amount, "CurrencyCode")) || model.String(entity, "InvoicingEntity") == "" {
			status = "SCOPE_OR_IDENTITY_AMBIGUOUS"
		}
		seen[id] = true
		issued, e := time.Parse(time.RFC3339Nano, model.String(n, "IssuedDate"))
		if e != nil || issued.After(now) {
			status = "ISSUANCE_NOT_ESTABLISHED"
		}
		if status != "ISSUED" {
			allIssued = false
		}
		out = append(out, model.Document{"invoice_id": id, "receipt_id": wrapper["receipt_id"], "payer_account_id": n["AccountId"], "entity": entity["InvoicingEntity"], "currency": amount["CurrencyCode"], "invoice_type": n["InvoiceType"], "native_status": nativeStatus, "status": status, "issued_at": n["IssuedDate"], "billing_period": n["BillingPeriod"], "source_receipt_id": receipt["id"], "source_hash": evidence.Hash(wrapper), "post_issuance_corrections_possible": true})
	}
	sort.Slice(out, func(i, j int) bool { return model.String(out[i], "invoice_id") < model.String(out[j], "invoice_id") })
	if len(out) == 0 {
		return out, "UNAVAILABLE"
	}
	if allIssued {
		return out, "NATIVE_ISSUED_EVIDENCE_NOT_BILLING_FINALITY"
	}
	return out, "NON_FINAL_CANCELLED_OR_AMBIGUOUS"
}

func commissioningAuthority(ctx context.Context, tx *store.Tx, resources []model.Document, now time.Time) (model.Document, model.Document, error) {
	counts := map[string]int{"TERRAFORM": 0, "CLOUDFORMATION": 0, "KUBERNETES": 0, "CLOUD_API": 0, "MANUAL": 0, "UNKNOWN": 0}
	byID := map[string]model.Document{}
	for _, r := range resources {
		byID[model.String(r, "id")] = r
		kind := model.String(r, "configuration_authority")
		if _, ok := counts[kind]; !ok {
			kind = "UNKNOWN"
		}
		counts[kind]++
	}
	authorities := []model.Document{}
	if len(resources) > 0 {
		ids := make([]string, 0, len(byID))
		for id := range byID {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		var e error
		authorities, e = commissioningReadDocuments(ctx, tx, `SELECT commissioning_configuration_authority_metadata($1::text,$2::text[])`, firstResourceAccount(resources), ids)
		if e != nil {
			return nil, nil, e
		}
	}
	declarations := map[string]model.Document{}
	for _, a := range authorities {
		binding := storageObject(a["binding"])
		if r := byID[model.String(binding, "resource_id")]; r != nil && binding["provider_resource_id"] == r["provider_resource_id"] && binding["account_id"] == r["account_id"] && binding["region"] == r["region"] {
			declarations[model.String(r, "id")] = a
		}
	}
	localArtifacts := 0
	for id, a := range declarations {
		var present bool
		e := tx.QueryRow(ctx, `SELECT EXISTS(SELECT FROM configuration_artifact_receipts p JOIN configuration_artifact_registrations g ON g.tenant_id=p.tenant_id AND g.id=p.document->>'registration_id' AND g.version=(p.document->>'registration_version')::bigint WHERE p.tenant_id=$1 AND g.resource_id=$2 AND g.authority_id=$3 AND p.observed_at<=$4 AND p.expires_at>$4 AND p.document->>'status'='OBSERVED' AND NOT EXISTS(SELECT FROM configuration_artifact_revocations v WHERE v.tenant_id=g.tenant_id AND v.registration_id=g.id AND v.registration_version=g.version) AND NOT EXISTS(SELECT FROM configuration_artifact_registrations newer WHERE newer.tenant_id=g.tenant_id AND newer.id=g.id AND newer.version>g.version))`, tx.Tenant, id, a["id"], now).Scan(&present)
		if e != nil {
			return nil, nil, e
		}
		if present {
			localArtifacts++
		}
	}
	reasons := []string{}
	status := "READY"
	if len(resources) == 0 {
		status = "NOT_CONFIGURED"
		reasons = append(reasons, "CONFIGURATION_AUTHORITY_INVENTORY_UNAVAILABLE")
	}
	if counts["UNKNOWN"] > 0 {
		status = "PARTIAL"
		reasons = append(reasons, "CONFIGURATION_AUTHORITY_UNKNOWN_OBSERVE_ALLOWED")
	}
	if counts["TERRAFORM"]+counts["CLOUDFORMATION"]+counts["KUBERNETES"] > 0 {
		status = "PARTIAL"
		reasons = append(reasons, "IAC_REMOTE_SOURCE_RESOLVABILITY_UNVERIFIED")
	}
	details := model.Document{"classifications": counts, "current_identity_bound_declarations": len(declarations), "unexpired_local_artifact_receipts": localArtifacts, "remote_repository_resolvable": nil, "observe_allowed": true, "autonomous_declarative_mutation_allowed": false, "reason_codes": reasons}
	return details, commissioningDimension("CONFIGURATION_AUTHORITY", status, reasons, []string{"Classify configuration ownership and commission the existing exact repository/artifact reader. Local artifact observation does not prove remote Git HEAD; Observe/Recommend does not require mutation permissions."}, details, nil), nil
}
func firstResourceAccount(resources []model.Document) string {
	if len(resources) > 0 {
		return model.String(resources[0], "account_id")
	}
	return ""
}

var commissioningMetricAliases = map[string][]string{
	"cpu": {"cpu_utilization", "CPUUtilization"}, "memory": {"memory_utilization", "memory_used_percent", "mem_used_percent"}, "network": {"network_receive", "network_transmit", "network_bytes", "NetworkIn", "NetworkOut"}, "storage": {"disk_iops", "disk_read_iops", "disk_write_iops", "storage_io"},
	"freeable_memory": {"freeable_memory", "FreeableMemory"}, "connections": {"connections", "DatabaseConnections"}, "iops": {"read_iops", "write_iops", "ReadIOPS", "WriteIOPS"}, "latency": {"read_latency", "write_latency", "ReadLatency", "WriteLatency"}, "throughput": {"read_throughput", "write_throughput", "VolumeReadBytes", "VolumeWriteBytes"}, "queue_burst": {"queue_depth", "DiskQueueDepth", "VolumeQueueLength", "BurstBalance"},
	"invocations": {"invocations", "Invocations"}, "duration": {"duration", "Duration"}, "errors": {"errors", "Errors"}, "throttles": {"throttles", "Throttles"}, "nat_metrics": {"BytesInFromSource", "BytesInFromDestination", "bytes_in_from_source", "bytes_in_from_destination"},
}

func commissioningTelemetryClass(r model.Document) string {
	switch model.String(r, "resource_type") {
	case "EC2":
		return "EC2"
	case "RDS_INSTANCE", "RDS_CLUSTER":
		return "RDS"
	case "EBS_VOLUME":
		return "EBS"
	case "LAMBDA_FUNCTION", "LAMBDA":
		return "LAMBDA"
	case "S3_BUCKET":
		return "S3"
	case "NAT_GATEWAY":
		return "NETWORK"
	case "ECS_SERVICE":
		return "ECS"
	}
	return model.String(r, "service_family")
}
func commissioningRequiredMetrics(class string) []string {
	switch class {
	case "EC2":
		return []string{"cpu", "memory", "network", "storage"}
	case "RDS":
		return []string{"cpu", "freeable_memory", "connections", "iops", "latency"}
	case "EBS":
		return []string{"iops", "throughput", "queue_burst"}
	case "LAMBDA":
		return []string{"invocations", "duration", "errors", "throttles"}
	case "NETWORK":
		return []string{"nat_metrics"}
	case "ECS":
		return []string{"cpu", "memory", "network", "storage"}
	case "ELASTICACHE":
		return []string{"cpu", "memory", "connections"}
	case "DYNAMODB":
		return []string{"consumed_reads", "consumed_writes", "throttles"}
	}
	return []string{}
}
func commissioningHistoryDays(_ model.Document, profile model.Document, workload ...model.Document) int {
	if model.Bool(profile, "high_seasonality") {
		return 90
	}
	if len(workload) == 1 && profile["criticality"] == "NON_PRODUCTION" && workload[0]["environment"] == "NON_PRODUCTION" {
		return 14
	}
	return 30
}
func commissioningMetricReady(results []model.Document, key string) bool {
	paired := map[string][]string{"network": {"network_receive", "network_transmit"}, "iops": {"read_iops", "write_iops"}, "throughput": {"read_throughput", "write_throughput"}, "latency": {"read_latency", "write_latency"}, "nat_metrics": {"bytes_in_from_source", "bytes_in_from_destination"}}
	if required, ok := paired[key]; ok {
		for _, part := range required {
			if !commissioningMetricReady(results, part) {
				return false
			}
		}
		return true
	}
	aliases := commissioningMetricAliases[key]
	if len(aliases) == 0 {
		aliases = []string{key}
	}
	for _, metric := range results {
		if awsservice.Contains(aliases, model.String(metric, "metric")) && metric["status"] == "READY" && model.Number(metric, "coverage_ppm") == 1000000 && model.Number(metric, "observed_samples") > 0 && model.Number(metric, "unknown_duration_ns") == 0 && model.String(metric, "unit") != "" {
			return true
		}
	}
	return false
}
func commissioningTelemetry(ctx context.Context, tx *store.Tx, resources, sources []model.Document, account, region string, now time.Time) (model.Document, model.Document, error) {
	evaluations, e := commissioningReadDocuments(ctx, tx, `SELECT jsonb_build_object('resource_id',c.config->'binding'->>'resource_id','connection_id',c.id,'config_hash',c.config_hash,'evaluation',e.document) FROM telemetry_connections c JOIN telemetry_source_revisions v ON v.tenant_id=c.tenant_id AND v.connection_id=c.id AND v.connection_version=c.version LEFT JOIN LATERAL(SELECT document FROM telemetry_evaluations e WHERE e.tenant_id=c.tenant_id AND e.connection_id=c.id AND e.revision_id=v.id ORDER BY created_at DESC,id DESC LIMIT 1)e ON true WHERE c.tenant_id=$1 AND c.config->'binding'->>'account_id'=$2 AND c.config->'binding'->>'region'=$3 AND c.config->'enabled'='true'::jsonb AND NOT EXISTS(SELECT FROM telemetry_connections n WHERE n.tenant_id=c.tenant_id AND n.id=c.id AND n.version>c.version) AND NOT EXISTS(SELECT FROM telemetry_source_revocations x WHERE x.tenant_id=v.tenant_id AND x.revision_id=v.id) ORDER BY c.id LIMIT 257`, tx.Tenant, account, region)
	if e != nil {
		return nil, nil, e
	}
	if len(evaluations) > 256 {
		return nil, nil, errors.New("COMMISSIONING_TELEMETRY_CONNECTION_BOUND")
	}
	byResource := map[string][]model.Document{}
	evaluationRefs := []model.Document{}
	for _, d := range evaluations {
		result := storageObject(d["evaluation"])
		ids := model.Strings(result, "receipt_ids")
		seen := map[string]bool{}
		for _, id := range ids {
			seen[id] = true
		}
		if len(ids) == 0 || len(ids) > 400 || len(seen) != len(ids) || result["config_hash"] != d["config_hash"] {
			continue
		}
		var count int
		e = tx.QueryRow(ctx, `SELECT count(*) FROM telemetry_receipts p JOIN entities r ON r.tenant_id=p.tenant_id AND r.id=$4 AND r.kind='resources' WHERE p.tenant_id=$1 AND p.id=ANY($2::text[]) AND p.connection_id=$3 AND p.document->'binding'=jsonb_build_object('tenant_id',r.tenant_id,'resource_id',r.id,'workload_id',r.document->>'workload_id','provider',r.document->>'provider','provider_resource_id',r.document->>'provider_resource_id','account_id',r.document->>'account_id','region',r.document->>'region')`, tx.Tenant, ids, d["connection_id"], d["resource_id"]).Scan(&count)
		if e != nil {
			return nil, nil, e
		}
		if count != len(ids) {
			continue
		}
		eval := storageObject(result["evaluation"])
		if eval["status"] != "READY" || !commissioningFresh(eval["evaluated_at"], now, 48*time.Hour) || !commissioningFresh(eval["end"], now, 48*time.Hour) {
			continue
		}
		byResource[model.String(d, "resource_id")] = append(byResource[model.String(d, "resource_id")], eval)
		evaluationRefs = append(evaluationRefs, model.Document{"kind": "PERSISTED_TELEMETRY_EVALUATION", "id": result["id"], "connection_id": d["connection_id"], "config_hash": d["config_hash"], "sha256": evidence.Hash(result), "receipt_ids": ids})
	}
	type metricGroup struct {
		resources, ready int
		metricReady      map[string]int
		reasons          []string
		required         []string
	}
	groups := map[string]*metricGroup{}
	profiles := map[string]model.Document{}
	workloads := map[string]model.Document{}
	for _, r := range resources {
		if r["region"] != region {
			continue
		}
		class := commissioningTelemetryClass(r)
		if class == "" {
			class = "UNSUPPORTED"
		}
		g := groups[class]
		if g == nil {
			g = &metricGroup{metricReady: map[string]int{}, required: commissioningRequiredMetrics(class), reasons: []string{}}
			groups[class] = g
		}
		g.resources++
		wid := model.String(r, "workload_id")
		profile, known := profiles[wid]
		if !known && wid != "" {
			profile, e = tx.WorkloadSafetyLatest(ctx, wid)
			if e != nil && !errors.Is(e, pgx.ErrNoRows) {
				return nil, nil, e
			}
			profiles[wid] = profile
		}
		workload, known := workloads[wid]
		if !known && wid != "" {
			workload, e = tx.Get(ctx, "workloads", wid)
			if e != nil && !errors.Is(e, pgx.ErrNoRows) {
				return nil, nil, e
			}
			workloads[wid] = workload
		}
		days := commissioningHistoryDays(r, profile, workload)
		metrics := []model.Document{}
		for _, eval := range byResource[model.String(r, "id")] {
			if model.Number(eval, "history_days") >= int64(days) {
				left, e1 := time.Parse(time.RFC3339Nano, model.String(eval, "start"))
				right, e2 := time.Parse(time.RFC3339Nano, model.String(eval, "end"))
				if e1 == nil && e2 == nil && !left.After(right.Add(-time.Duration(days)*24*time.Hour)) {
					metrics = append(metrics, storageRows(eval["metrics"])...)
				}
			}
		}
		ready := len(g.required) > 0
		for _, key := range g.required {
			if commissioningMetricReady(metrics, key) {
				g.metricReady[key]++
			} else {
				ready = false
				g.reasons = append(g.reasons, "METRIC_OR_COMPLETE_HISTORY_UNAVAILABLE:"+key)
			}
		}
		if class == "RDS" {
			cfg := storageObject(r["database_configuration"])
			lagApplicable := model.String(cfg, "read_replica_source_identifier") != "" || strings.HasPrefix(model.String(cfg, "engine"), "aurora") || r["resource_type"] == "RDS_CLUSTER"
			lagKnownNotApplicable := r["resource_type"] == "RDS_INSTANCE" && model.String(cfg, "engine") != "" && cfg["cluster_identifier"] == "" && cfg["read_replica_source_identifier"] == "" && !lagApplicable
			if !lagKnownNotApplicable && !commissioningMetricReady(metrics, "replica_lag") {
				ready = false
				g.reasons = append(g.reasons, "RDS_REPLICATION_LAG_OR_NATIVE_APPLICABILITY_UNPROVEN")
			}
			if cfg["engine"] == nil {
				ready = false
				g.reasons = append(g.reasons, "RDS_ENGINE_SPECIFIC_TELEMETRY_APPLICABILITY_UNKNOWN")
			}
			g.reasons = append(g.reasons, model.Strings(r, "blockers")...)
		}
		if class == "ECS" {
			ready = false
			g.reasons = append(g.reasons, "ECS_HISTORICAL_DEMAND_REQUIRES_CURRENT_SERVICE_ASSESSMENT")
		}
		if class == "S3" {
			ready = false
			g.reasons = append(g.reasons, "S3_POPULATION_AND_ACCESS_CURRENTNESS_REQUIRES_EXISTING_ASSESSOR")
		}
		if class == "LAMBDA" {
			ready = false
			g.reasons = append(g.reasons, "LAMBDA_REPORT_AND_NATIVE_BENCHMARK_COMPARABILITY_REQUIRES_EXISTING_ASSESSOR")
		}
		if class == "NETWORK" {
			ready = false
			g.reasons = append(g.reasons, "FLOW_LOG_POPULATION_CURRENTNESS_REQUIRES_EXISTING_ASSESSOR")
		}
		if ready {
			g.ready++
		}
	}
	classes := []string{}
	for class := range groups {
		classes = append(classes, class)
	}
	sort.Strings(classes)
	out := []model.Document{}
	allReady := len(classes) > 0
	allReasons := []string{}
	for _, class := range classes {
		g := groups[class]
		metrics := []model.Document{}
		for _, key := range g.required {
			status := "NOT_CONFIGURED"
			if g.metricReady[key] > 0 {
				status = "PARTIAL"
			}
			if g.metricReady[key] == g.resources {
				status = "READY"
			}
			metrics = append(metrics, model.Document{"metric": key, "status": status, "resources_with_complete_evidence": g.metricReady[key], "resource_count": g.resources})
		}
		status := "PARTIAL"
		if g.ready == g.resources {
			status = "READY"
		} else {
			allReady = false
		}
		out = append(out, model.Document{"resource_class": class, "status": status, "resource_count": g.resources, "resources_ready": g.ready, "metrics": metrics, "reason_codes": databaseSortedReasons(g.reasons), "history_policy": "14_NON_PRODUCTION_30_PRODUCTION_90_SEASONAL_COMPLETE_DAYS", "native_snapshot_alone_is_metric_coverage": false})
		allReasons = append(allReasons, g.reasons...)
	}
	nativeSources := []model.Document{}
	for _, s := range sources {
		kind := model.String(s, "kind")
		if kind == "AWS_LAMBDA_REPORTS_V1" || kind == "AWS_LAMBDA_PERFORMANCE_CURVE_V1" || kind == "AWS_S3_INVENTORY" || kind == "AWS_S3_ANALYTICS" || strings.Contains(kind, "FLOW") {
			nativeSources = append(nativeSources, model.Document{"source_id": s["id"], "kind": kind, "status": s["status"], "reason_code": s["reason_code"], "last_sync_at": s["last_sync_at"], "scope_current": model.Bool(s, "enabled") && !model.Bool(s, "revoked") && s["region"] == region})
		}
	}
	status := "PARTIAL"
	if allReady {
		status = "READY"
	}
	if len(classes) == 0 {
		status = "NOT_CONFIGURED"
		allReasons = append(allReasons, "TELEMETRY_INVENTORY_OR_INDEPENDENT_OBSERVATIONS_UNAVAILABLE")
	}
	details := model.Document{"status": status, "classes": out, "registered_native_sources": nativeSources, "current_telemetry_connection_count": len(evaluations), "evidence_refs": evaluationRefs, "missing_is_zero": false, "native_per_metric_coverage": "UNAVAILABLE_UNTIL_CURRENT_HISTORY_EVALUATION_OR_CLASS_ASSESSMENT", "reason_codes": databaseSortedReasons(allReasons)}
	remediation := []string{"Commission missing approved metric sources, including independent memory telemetry; synchronize and evaluate actual historical receipts. Do not enable paid telemetry or infer missing samples merely to pass preflight.", "Use the existing class assessor for native REPORT, Inventory, access and Flow Log population/comparability gates."}
	for _, class := range classes {
		if class == "ECS" {
			remediation = append(remediation, "Run the existing ECS service assessor with a current registered historical-demand receipt and compatible serving epochs. Generic metric coverage alone does not establish service-history readiness.")
		}
	}
	return details, commissioningDimension("METRICS", status, allReasons, remediation, details, nil), nil
}
