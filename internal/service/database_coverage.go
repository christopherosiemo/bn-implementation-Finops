package service

import (
	"context"
	"encoding/json"
	"errors"
	"math/big"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/evidence"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/source"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/jackc/pgx/v5"
)

const databaseCoverageLimit = 100000

var databaseCoverageDecimal = regexp.MustCompile(`^-?(0|[1-9][0-9]{0,25})(\.[0-9]{1,12})?$`)
var databaseCoverageCurrency = regexp.MustCompile(`^[A-Z]{3}$`)

// databaseBillingMonth reuses the allocation broker's native receipt selection
// and trust gates, before allocation's separate 5,000-row presentation limit.
// It returns one current authenticated export revision, never revision history
// or caller-provided financial rows. Its independent domain bound is 100,000.
func (a *API) databaseBillingMonth(ctx context.Context, tx *store.Tx, sourceID string, start time.Time) (model.Document, []model.Document, error) {
	if sourceID == "" || start.Location() != time.UTC || start.Day() != 1 || start.Hour() != 0 || start.Minute() != 0 || start.Second() != 0 || start.Nanosecond() != 0 {
		return nil, nil, errors.New("DATABASE_BILLING_MONTH_REQUIRED")
	}
	if err := holdTrustedSourceSnapshot(ctx, tx, sourceID); err != nil {
		return nil, nil, err
	}
	registration, err := tx.SourceGet(ctx, sourceID)
	if err != nil {
		return nil, nil, err
	}
	nativeRegistration, err := source.ParseRegistration(registration)
	if err != nil || model.String(registration, "status") != "HEALTHY" || !model.Bool(registration, "enabled") {
		return nil, nil, errors.New("DATABASE_BILLING_SOURCE_UNAVAILABLE")
	}
	// Bound the legacy receipt enumerator before calling it; no unbounded
	// archive history is materialized merely to find one latest month head.
	var receiptCount int
	if err = tx.QueryRow(ctx, `SELECT count(*) FROM (SELECT 1 FROM source_receipts WHERE tenant_id=$1 AND source_id=$2 AND kind='AWS_CUR2' LIMIT $3) bounded`, tx.Tenant, sourceID, databaseCoverageLimit+1).Scan(&receiptCount); err != nil {
		return nil, nil, err
	}
	if receiptCount > databaseCoverageLimit {
		return nil, nil, errors.New("DATABASE_BILLING_RECEIPT_LIMIT")
	}
	heads, err := periodReceipts(ctx, tx, sourceID, start, start.AddDate(0, 1, 0))
	if err != nil {
		return nil, nil, err
	}
	var selected model.Document
	for _, head := range heads {
		if model.String(evidence.Object(head["source_proof"]), "billing_period_start") == start.Format(time.RFC3339) {
			if selected != nil {
				return nil, nil, errors.New("DATABASE_BILLING_MONTH_AMBIGUOUS")
			}
			selected = head
		}
	}
	if selected == nil {
		return nil, nil, errors.New("DATABASE_BILLING_MONTH_UNAVAILABLE")
	}
	job, err := tx.Get(ctx, "ingestion_jobs", model.String(selected, "ingestion_job_id"))
	if err != nil {
		return nil, nil, err
	}
	accounts := model.Strings(registration, "usage_account_ids")
	if len(accounts) == 0 {
		return nil, nil, errors.New("DATABASE_BILLING_SCOPE_UNAVAILABLE")
	}
	validated, err := trustedJob(ctx, tx, job, model.Document{"account_id": accounts[0], "region": registration["region"]})
	if err != nil || model.String(validated, "id") != model.String(selected, "id") {
		return nil, nil, errors.New("DATABASE_BILLING_RECEIPT_INVALID")
	}
	raw, canonical := evidence.Object(job["raw"]), evidence.Object(job["canonical"])
	if _, err = source.ValidateExecution(nativeRegistration, evidence.Object(raw["provider_execution"])); err != nil {
		return nil, nil, errors.New("DATABASE_BILLING_UNFILTERED_NATIVE_EXPORT_REQUIRED")
	}
	id, version := model.String(raw, "source_id"), model.String(raw, "source_version")
	if id == "" || version == "" || model.String(job, "source_id") != id {
		return nil, nil, errors.New("DATABASE_BILLING_SOURCE_IDENTITY_INVALID")
	}
	encoded, err := json.Marshal(canonical["records"])
	if err != nil || len(encoded) > 64<<20 {
		return nil, nil, errors.New("DATABASE_BILLING_RECORD_BYTES_LIMIT")
	}
	var records []model.Document
	decoder := json.NewDecoder(strings.NewReader(string(encoded)))
	decoder.UseNumber()
	if err = decoder.Decode(&records); err != nil || records == nil {
		return nil, nil, errors.New("DATABASE_BILLING_RECORDS_INVALID")
	}
	if len(records) > databaseCoverageLimit {
		return nil, nil, errors.New("DATABASE_BILLING_RECORD_LIMIT")
	}
	payer := model.String(registration, "payer_account_id")
	allowed := map[string]bool{}
	for _, account := range accounts {
		allowed[account] = true
	}
	seen := map[string]bool{}
	for _, record := range records {
		recordID := model.String(record, "x_SourceRecordId")
		if recordID == "" || seen[recordID] || model.String(record, "x_SourceId") != id || model.String(record, "x_SourceVersion") != version || model.String(record, "BillingAccountId") != payer || (!allowed[model.String(record, "SubAccountId")] && !databaseBillingPayerCharge(record, payer)) {
			return nil, nil, errors.New("DATABASE_BILLING_CANONICAL_BINDING_INVALID")
		}
		seen[recordID] = true
		if cost := record["BilledCost"]; cost != nil {
			text, ok := cost.(string)
			if !ok || !databaseCoverageDecimal.MatchString(text) {
				return nil, nil, errors.New("DATABASE_BILLING_DECIMAL_STRING_REQUIRED")
			}
		}
	}
	proof := evidence.Object(selected["source_proof"])
	if model.String(proof, "payer_account_id") != payer || model.String(proof, "billing_period_start") != start.Format(time.RFC3339) || model.String(proof, "billing_period_end") != start.AddDate(0, 1, 0).Format(time.RFC3339) || model.Number(proof, "row_count") != int64(len(records)) || model.Number(proof, "verified_row_count") != int64(len(records)) || model.Number(proof, "object_count") < 1 || model.Number(proof, "object_count") != model.Number(proof, "verified_object_count") {
		return nil, nil, errors.New("DATABASE_BILLING_EXPORT_INCOMPLETE")
	}
	ref := model.Document{"kind": "AWS_CUR2_CONNECTION", "source_connection_id": sourceID, "source_receipt_id": selected["id"], "source_revision_id": selected["revision_id"], "ingestion_job_id": job["id"], "source_id": id, "source_version": version, "raw_hash": evidence.Hash(raw), "canonical_hash": evidence.Hash(canonical), "payer_account_id": payer, "billing_period_start": start.Format(time.RFC3339), "source_proof": proof, "coverage": "AUTHENTICATED_EXPORT_REVISION"}
	return ref, records, nil
}

type databaseCoverageTotals struct {
	values   map[string]*big.Rat
	known    bool
	complete bool
}

func newDatabaseCoverageTotals() *databaseCoverageTotals {
	group := &databaseCoverageTotals{values: map[string]*big.Rat{}, known: true, complete: true}
	for _, key := range []string{"detected_spend", "analysed_spend", "observation_only_spend", "blocked_spend", "unsupported_spend", "credits", "net_spend"} {
		group.values[key] = new(big.Rat)
	}
	return group
}

func databaseCoverageAmount(value *big.Rat) string {
	text := strings.TrimRight(strings.TrimRight(value.FloatString(12), "0"), ".")
	if text == "" || text == "-0" {
		return "0"
	}
	return text
}

type databaseCoveragePublication struct {
	status, currency string
	current          bool
	hourly           *big.Rat
	assessment       model.Document
	economicLines    map[string]bool
}

// Coverage is a financial observation, not an execution gate or savings claim.
// Positive charges are the denominator; credits never shrink that denominator.
func (a *API) databaseCoverage(ctx context.Context, tx *store.Tx) (model.Document, error) {
	now := a.now()
	end := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	start := time.Date(end.Year(), end.Month(), 1, 0, 0, 0, 0, time.UTC)
	if start.Equal(end) {
		start = start.AddDate(0, -1, 0)
	}
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock_shared(hashtextextended($1,0))", tx.Tenant+":dependency-graph"); err != nil {
		return nil, err
	}
	blockers := map[string]bool{}
	incomplete := false
	mark := func(code string) { blockers[code] = true; incomplete = true }
	// Inventory is used only for exact native ID/account/region attribution;
	// every unowned or resourceless charge still enters the denominator.
	rows, err := tx.Query(ctx, `SELECT id,document FROM entities WHERE tenant_id=$1 AND kind='resources' AND document->>'provider'='AWS' ORDER BY id LIMIT $2`, tx.Tenant, databaseCoverageLimit+1)
	if err != nil {
		return nil, err
	}
	resources := map[string]model.Document{}
	count := 0
	for rows.Next() {
		var id string
		var raw []byte
		if err = rows.Scan(&id, &raw); err != nil {
			break
		}
		count++
		if count > databaseCoverageLimit {
			err = errors.New("DATABASE_COVERAGE_RESOURCE_LIMIT")
			break
		}
		var resource model.Document
		if err = json.Unmarshal(raw, &resource); err != nil {
			break
		}
		resource["id"] = id
		// Only exact immutable aliases from authenticated native discovery qualify.
		// Names, suffixes and inferred identifiers never establish attribution.
		aliases := map[string]bool{model.String(resource, "provider_resource_id"): true}
		if databaseResource(resource) {
			configuration := evidence.Object(resource["database_configuration"])
			aliases[model.String(configuration, "arn")] = true
			aliases[model.String(configuration, "resource_id")] = true
		}
		for alias := range aliases {
			if alias == "" {
				continue
			}
			key := model.String(resource, "account_id") + "\x00" + model.String(resource, "region") + "\x00" + alias
			if previous, exists := resources[key]; exists && (previous == nil || model.String(previous, "id") != id) {
				resources[key] = nil
				mark("DATABASE_COVERAGE_RESOURCE_BINDING_AMBIGUOUS")
			} else {
				resources[key] = resource
			}
		}
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return nil, err
	}
	publications := map[string]databaseCoveragePublication{}
	rows, err = tx.Query(ctx, `SELECT a.resource_id,a.document,p.document,p.currency,p.current_hourly_cost::text
 FROM (SELECT DISTINCT ON(resource_id) * FROM database_assessments WHERE tenant_id=$1 ORDER BY resource_id,created_at DESC,id DESC) a
 LEFT JOIN database_recommendation_publications p ON p.tenant_id=a.tenant_id AND p.assessment_id=a.id ORDER BY a.resource_id LIMIT $2`, tx.Tenant, databaseCoverageLimit+1)
	if err != nil {
		return nil, err
	}
	type publicationRow struct {
		resource            string
		record, publication []byte
		currency, hourly    *string
	}
	persisted := []publicationRow{}
	for rows.Next() {
		var row publicationRow
		if err = rows.Scan(&row.resource, &row.record, &row.publication, &row.currency, &row.hourly); err != nil {
			break
		}
		persisted = append(persisted, row)
		if len(persisted) > databaseCoverageLimit {
			err = errors.New("DATABASE_COVERAGE_ASSESSMENT_LIMIT")
			break
		}
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return nil, err
	}
	for _, row := range persisted {
		var record model.Document
		if err = json.Unmarshal(row.record, &record); err != nil {
			return nil, err
		}
		publication := databaseCoveragePublication{status: model.String(record, "status"), assessment: evidence.Object(record["assessment"])}
		if len(row.publication) > 0 {
			current, currentErr := a.databaseAssessmentCurrent(ctx, tx, record)
			if currentErr != nil {
				if ctx.Err() != nil {
					return nil, ctx.Err()
				}
				if strings.HasPrefix(currentErr.Error(), "SOURCE_") || strings.HasPrefix(currentErr.Error(), "TRUSTED_") || strings.HasPrefix(currentErr.Error(), "DATABASE_") {
					mark("DATABASE_COVERAGE_ASSESSMENT_NOT_CURRENT")
				} else {
					return nil, currentErr
				}
			}
			publication.current = model.Bool(current, "current")
			if row.currency != nil {
				publication.currency = *row.currency
			}
			if row.hourly != nil && databaseCoverageDecimal.MatchString(*row.hourly) {
				publication.hourly, _ = new(big.Rat).SetString(*row.hourly)
			}
		}
		publication.economicLines = databaseCoverageEconomicLines(publication.assessment)
		publications[row.resource] = publication
	}
	storagePublications, storageErr := a.storageCoveragePublications(ctx, tx)
	if storageErr != nil {
		return nil, storageErr
	}
	for id, publication := range storagePublications {
		publications[id] = publication
	}
	rows, err = tx.Query(ctx, `SELECT id FROM source_registrations WHERE tenant_id=$1 AND kind='AWS_CUR2' ORDER BY id LIMIT $2`, tx.Tenant, databaseCoverageLimit+1)
	if err != nil {
		return nil, err
	}
	sourceIDs := []string{}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			break
		}
		sourceIDs = append(sourceIDs, id)
		if len(sourceIDs) > databaseCoverageLimit {
			err = errors.New("DATABASE_COVERAGE_SOURCE_LIMIT")
			break
		}
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return nil, err
	}
	type month struct {
		ref     model.Document
		records []model.Document
		payer   string
	}
	months := []month{}
	payers := map[string]int{}
	totalRows := 0
	for _, id := range sourceIDs {
		ref, records, e := a.databaseBillingMonth(ctx, tx, id, start)
		if e != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			// Data-domain absence is visible as incomplete, never silently omitted.
			if strings.HasPrefix(e.Error(), "DATABASE_") || strings.HasPrefix(e.Error(), "ALLOCATION_") || strings.HasPrefix(e.Error(), "SOURCE_") || strings.HasPrefix(e.Error(), "TRUSTED_") || errors.Is(e, pgx.ErrNoRows) {
				mark("DATABASE_COVERAGE_SOURCE_UNAVAILABLE")
				continue
			}
			return nil, e
		}
		totalRows += len(records)
		if totalRows > databaseCoverageLimit {
			return nil, errors.New("DATABASE_COVERAGE_RECORD_LIMIT")
		}
		payer := model.String(ref, "payer_account_id")
		payers[payer]++
		months = append(months, month{ref, records, payer})
	}
	groups := map[string]*databaseCoverageTotals{}
	groupFor := func(currency string) *databaseCoverageTotals {
		if groups[currency] == nil {
			groups[currency] = newDatabaseCoverageTotals()
		}
		return groups[currency]
	}
	if len(months) == 0 {
		mark("DATABASE_COVERAGE_BILLING_UNAVAILABLE")
	}
	ec2 := map[string]model.Document{}
	for _, selected := range months {
		if payers[selected.payer] != 1 {
			mark("DATABASE_COVERAGE_PAYER_MONTH_AMBIGUOUS")
			continue
		}
		proof := evidence.Object(selected.ref["source_proof"])
		left, e1 := time.Parse(time.RFC3339Nano, model.String(proof, "period_start"))
		right, e2 := time.Parse(time.RFC3339Nano, model.String(proof, "period_end"))
		complete := e1 == nil && e2 == nil && !left.After(start) && !right.Before(end) && (model.String(proof, "state") == "COMPLETE" || model.String(proof, "state") == "FINAL")
		if !complete {
			mark("DATABASE_COVERAGE_BILLING_WINDOW_INCOMPLETE")
		}
		for _, record := range selected.records {
			at, e1 := time.Parse(time.RFC3339Nano, model.String(record, "ChargePeriodStart"))
			until, e2 := time.Parse(time.RFC3339Nano, model.String(record, "ChargePeriodEnd"))
			currency := model.String(record, "BillingCurrency")
			if !databaseCoverageCurrency.MatchString(currency) {
				currency = ""
				mark("DATABASE_COVERAGE_CURRENCY_UNAVAILABLE")
			}
			group := groupFor(currency)
			if e1 != nil || e2 != nil || !at.Before(until) {
				group.known = false
				mark("DATABASE_COVERAGE_CHARGE_WINDOW_INVALID")
				continue
			}
			if at.Before(start) || !at.Before(end) {
				continue
			}
			if !complete || until.After(end) {
				group.complete = false
				mark("DATABASE_COVERAGE_BILLING_WINDOW_INCOMPLETE")
			}
			costText, ok := record["BilledCost"].(string)
			cost, valid := new(big.Rat).SetString(costText)
			if !ok || !valid || !databaseCoverageDecimal.MatchString(costText) || currency == "" {
				group.known = false
				mark("DATABASE_COVERAGE_BILLED_COST_UNAVAILABLE")
				continue
			}
			group.values["net_spend"].Add(group.values["net_spend"], cost)
			if cost.Sign() < 0 {
				group.values["credits"].Add(group.values["credits"], cost)
				continue
			}
			if cost.Sign() == 0 {
				continue
			}
			group.values["detected_spend"].Add(group.values["detected_spend"], cost)
			key := model.String(record, "SubAccountId") + "\x00" + model.String(record, "RegionId") + "\x00" + model.String(record, "ResourceId")
			resource := resources[key]
			category := "unsupported_spend"
			if resource != nil && (databaseResource(resource) || storageResource(resource)) {
				category = "observation_only_spend"
				publication := publications[model.String(resource, "id")]
				if publication.status == "BLOCKED" || model.String(publication.assessment, "status") == "BLOCKED" {
					category = "blocked_spend"
				} else if publication.current && publication.hourly != nil && publication.hourly.Sign() >= 0 && publication.currency == currency && (model.String(publication.assessment, "status") == "RECOMMENDED" || model.String(publication.assessment, "status") == "NO_CHANGE") {
					economics := evidence.Object(publication.assessment["economics"])
					price, ok := new(big.Rat).SetString(model.String(economics, "current_hourly_cost"))
					if ok && model.String(economics, "currency") == currency && price.Cmp(publication.hourly) == 0 && publication.economicLines[databaseCoverageLineKey(selected.ref, model.String(record, "x_SourceRecordId"))] {
						category = "analysed_spend"
					}
				}
				if storageResource(resource) && model.String(resource, "resource_type") == "EBS_VOLUME" {
					switch model.String(evidence.Object(resource["storage_configuration"]), "volume_type") {
					case "gp2", "gp3", "io1", "io2":
					default:
						category = "unsupported_spend"
					}
				}
			} else if resource != nil && model.String(resource, "resource_type") == "EC2" {
				id := model.String(resource, "id")
				baseline, seen := ec2[id]
				if !seen {
					baseline, err = databaseCoverageEC2Baseline(ctx, tx, resource, now)
					if err != nil {
						return nil, err
					}
					ec2[id] = baseline
				}
				if baseline != nil {
					binding := evidence.Object(baseline["binding"])
					bs, e1 := time.Parse(time.RFC3339Nano, model.String(baseline, "start"))
					be, e2 := time.Parse(time.RFC3339Nano, model.String(baseline, "end"))
					if e1 == nil && e2 == nil && !at.Before(bs) && !until.After(be) && model.String(binding, "currency") == currency {
						category = "analysed_spend"
					}
				}
			} else if model.String(record, "ServiceName") == "AmazonRDS" || model.String(evidence.Object(record["x_ProviderFields"]), "product_servicecode") == "AmazonRDS" {
				category = "observation_only_spend"
			} else if component, _, _ := storageChargeKind(evidence.Object(record["x_ProviderFields"])); component != "" {
				category = "observation_only_spend"
			}
			group.values[category].Add(group.values[category], cost)
		}
	}
	if len(groups) == 0 {
		unknown := groupFor("")
		unknown.known = false
		unknown.complete = false
	}
	currencies := make([]string, 0, len(groups))
	for currency := range groups {
		currencies = append(currencies, currency)
	}
	sort.Strings(currencies)
	out := []model.Document{}
	for _, currency := range currencies {
		group := groups[currency]
		row := model.Document{"currency": nullableDatabaseString(currency), "basis": "POSITIVE_BILLED_CHARGES", "complete": group.complete && group.known && !incomplete, "analysed_percent": nil}
		for key, value := range group.values {
			if group.known {
				row[key] = databaseCoverageAmount(value)
			} else {
				row[key] = nil
			}
		}
		if model.Bool(row, "complete") && group.values["detected_spend"].Sign() > 0 {
			ratio := new(big.Rat).Quo(group.values["analysed_spend"], group.values["detected_spend"])
			ratio.Mul(ratio, big.NewRat(100, 1))
			row["analysed_percent"] = databaseCoverageAmount(ratio)
		}
		out = append(out, row)
	}
	codes := make([]string, 0, len(blockers))
	for code := range blockers {
		codes = append(codes, code)
	}
	sort.Strings(codes)
	return model.Document{"period": model.Document{"start": start.Format(time.RFC3339), "end": end.Format(time.RFC3339)}, "groups": out, "blockers": codes}, nil
}

// Only an actually issued, unexpired v3 readiness with accepted financial
// evaluation and revalidated native source closure counts as analysed EC2.
// CPU observations, fixture/customer-import baselines and resource price fields
// cannot satisfy this branch. It performs no HTTP/economics call or mutation.
func databaseCoverageEC2Baseline(ctx context.Context, tx *store.Tx, resource model.Document, now time.Time) (model.Document, error) {
	var raw []byte
	err := tx.QueryRow(ctx, `SELECT document FROM readiness_evidence WHERE tenant_id=$1 AND kind='readiness' AND resource_id=$2 ORDER BY created_at DESC,id DESC LIMIT 1`, tx.Tenant, resource["id"]).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var ready model.Document
	if err = json.Unmarshal(raw, &ready); err != nil {
		return nil, err
	}
	expires, e1 := time.Parse(time.RFC3339Nano, model.String(ready, "expires_at"))
	checked, e2 := time.Parse(time.RFC3339Nano, model.String(ready, "checked_at"))
	if !model.Bool(ready, "pre_execution_ready") || model.String(ready, "status") != "READY" || e1 != nil || e2 != nil || !expires.After(now) || checked.After(now) || now.Sub(checked) > 5*time.Minute {
		return nil, nil
	}
	baseline, err := tx.EvidenceGet(ctx, "baseline", model.String(ready, "baseline_id"))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if model.String(baseline, "schema_version") != "3" || !model.Bool(evidence.Object(baseline["evaluation"]), "pre_execution_ready") || !evidence.SameBinding(evidence.Object(baseline["binding"]), evidence.Binding(tx.Tenant, resource, model.String(evidence.Object(baseline["binding"]), "currency"))) {
		return nil, nil
	}
	if err = validateSnapshotSources(ctx, tx, baseline, resource); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if strings.HasPrefix(err.Error(), "SOURCE_") || strings.HasPrefix(err.Error(), "BASELINE_") || strings.HasPrefix(err.Error(), "TRUSTED_") || strings.HasPrefix(err.Error(), "COMMITMENT_") {
			return nil, nil
		}
		return nil, err
	}
	return baseline, nil
}

// The financial resolver selects these IDs from the same authenticated canonical
// document that produced the economic inputs. A resource-level price or a bare
// completeness flag never labels every unrelated charge as economically analysed.
func databaseCoverageLineKey(ref model.Document, id string) string {
	return model.String(ref, "source_connection_id") + "\x00" + model.String(ref, "source_receipt_id") + "\x00" + model.String(ref, "ingestion_job_id") + "\x00" + model.String(ref, "canonical_hash") + "\x00" + id
}
func databaseCoverageEconomicLines(assessment model.Document) map[string]bool {
	out := map[string]bool{}
	count := 0
	for _, ref := range evidence.Rows(assessment["source_refs"]) {
		if model.String(ref, "kind") != "AWS_CUR2_CONNECTION" {
			continue
		}
		if model.String(ref, "source_connection_id") == "" || model.String(ref, "source_receipt_id") == "" || model.String(ref, "ingestion_job_id") == "" || len(model.String(ref, "canonical_hash")) != 64 {
			continue
		}
		raw, err := json.Marshal(ref["economic_record_ids"])
		if err != nil {
			return map[string]bool{}
		}
		var ids []string
		if json.Unmarshal(raw, &ids) != nil || len(ids) == 0 {
			return map[string]bool{}
		}
		seen := map[string]bool{}
		for _, id := range ids {
			count++
			if id == "" || seen[id] || count > databaseCoverageLimit {
				return map[string]bool{}
			}
			seen[id] = true
			out[databaseCoverageLineKey(ref, id)] = true
		}
	}
	return out
}

// A native payer charge can have no usage account or resource. This exception
// is not a wildcard for unmatched usage: the original unfiltered export and
// exact native payer/type/resource fields have already been authenticated.
func databaseBillingPayerCharge(record model.Document, payer string) bool {
	if payer == "" || model.String(record, "BillingAccountId") != payer || model.String(record, "SubAccountId") != "" || model.String(record, "ResourceId") != "" {
		return false
	}
	return source.PayerScopedNonResourceCharge(evidence.Object(record["x_ProviderFields"]), payer)
}
