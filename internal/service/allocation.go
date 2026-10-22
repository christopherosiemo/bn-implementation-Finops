package service

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/allocation"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/auth"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/evidence"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/jackc/pgx/v5"
)

type allocationSelection struct {
	PolicyID string `json:"policy_id"`
	Source   struct {
		Kind               string `json:"kind"`
		IngestionJobID     string `json:"ingestion_job_id,omitempty"`
		SourceConnectionID string `json:"source_connection_id,omitempty"`
		BillingPeriodStart string `json:"billing_period_start,omitempty"`
	} `json:"source"`
}

func allocationRole(i auth.Identity, write bool) error {
	if write {
		return requireRole(i, "FINOPS_ADMIN", "FINANCE")
	}
	return requireRole(i, "FINOPS_ADMIN", "FINANCE", "AUDITOR")
}

func (a *API) allocationGet(ctx context.Context, tx *store.Tx, i auth.Identity, r *http.Request) (any, bool, error) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/v1/"), "/")
	if parts[0] != "allocation-policies" && parts[0] != "allocation-reports" && parts[0] != "allocation-sources" {
		return nil, false, nil
	}
	if err := allocationRole(i, false); err != nil {
		return nil, true, err
	}
	if len(parts) == 1 {
		after, limit, err := nativeCursor(r, i.Tenant, parts[0], "")
		if err != nil {
			return nil, true, err
		}
		if parts[0] == "allocation-sources" {
			rows, e := tx.Query(ctx, `SELECT id,coalesce(document->>'status',''),document->>'source_provenance',coalesce(document->>'source_id',''),coalesce(document->'raw'->>'source_version',''),created_at FROM entities WHERE tenant_id=$1 AND kind='ingestion_jobs' AND document->>'source_provenance' IN ('CUSTOMER_IMPORT','DETERMINISTIC_FIXTURE') AND ($2='' OR (created_at,id)<(SELECT created_at,id FROM entities WHERE tenant_id=$1 AND kind='ingestion_jobs' AND id=$2)) ORDER BY created_at DESC,id DESC LIMIT $3`, i.Tenant, after, limit+1)
			if e != nil {
				return nil, true, e
			}
			defer rows.Close()
			items := []model.Document{}
			for rows.Next() {
				var id, status, provenance, sourceID, version string
				var created time.Time
				if e = rows.Scan(&id, &status, &provenance, &sourceID, &version, &created); e != nil {
					return nil, true, e
				}
				items = append(items, model.Document{"id": id, "status": status, "provenance": provenance, "source_id": sourceID, "source_version": version, "created_at": created.UTC().Format(time.RFC3339Nano), "coverage": "UNKNOWN", "execution_authorized": false, "verified_saving": nil})
			}
			return nativePage(items, limit, i.Tenant, parts[0], ""), true, rows.Err()
		}
		var rows []model.Document
		if parts[0] == "allocation-policies" {
			rows, err = tx.AllocationPolicyPage(ctx, after, limit+1)
		} else {
			rows, err = tx.AllocationReportPage(ctx, after, limit+1)
		}
		if err != nil {
			return nil, true, err
		}
		out := nativePage(rows, limit, i.Tenant, parts[0], "")
		if parts[0] == "allocation-policies" {
			latest, e := tx.AllocationPolicyLatest(ctx)
			if e != nil && e != pgx.ErrNoRows {
				return nil, true, e
			}
			out["latest"], out["version"] = latest, model.Number(latest, "version")
		}
		return out, true, nil
	}
	if parts[0] == "allocation-policies" && len(parts) == 2 {
		d, e := tx.AllocationPolicyGet(ctx, parts[1])
		return d, true, e
	}
	if parts[0] == "allocation-reports" && len(parts) >= 2 && len(parts) <= 3 {
		report, err := tx.AllocationReportGet(ctx, parts[1])
		if err != nil {
			return nil, true, err
		}
		if len(parts) == 2 {
			return report, true, nil
		}
		if parts[2] != "lines" && parts[2] != "observations" {
			return nil, true, problem(404, "NOT_FOUND", "allocation collection not found")
		}
		after, limit, err := nativeCursor(r, i.Tenant, "allocation-"+parts[2], parts[1])
		if err != nil {
			return nil, true, err
		}
		rows, err := tx.AllocationReportRowPage(ctx, parts[1], parts[2], after, limit+1)
		return nativePage(rows, limit, i.Tenant, "allocation-"+parts[2], parts[1]), true, err
	}
	return nil, true, problem(404, "NOT_FOUND", "allocation resource not found")
}

func (a *API) allocationMutate(ctx context.Context, tx *store.Tx, i auth.Identity, r *http.Request, in model.Document, parts []string) (model.Document, int, bool, error) {
	if parts[0] != "allocation-policies" && parts[0] != "allocation-reports" {
		return nil, 0, false, nil
	}
	if err := allocationRole(i, true); err != nil {
		return nil, 0, true, err
	}
	if len(parts) != 1 {
		return nil, 0, true, problem(404, "NOT_FOUND", "allocation mutation not found")
	}
	// Serialize CAS, source selection and current mapping with ownership changes.
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", i.Tenant+":dependency-graph"); err != nil {
		return nil, 0, true, err
	}
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", i.Tenant+":allocation-policy"); err != nil {
		return nil, 0, true, err
	}
	latest, err := tx.AllocationPolicyLatest(ctx)
	if err != nil && err != pgx.ErrNoRows {
		return nil, 0, true, err
	}
	if latest == nil {
		latest = model.Document{"version": int64(0)}
	}
	if err = match(r, latest); err != nil {
		return nil, 0, true, err
	}
	var out model.Document
	if parts[0] == "allocation-policies" {
		var p allocation.Policy
		if err = telemetryStrict(in, &p); err == nil {
			err = allocation.ValidatePolicy(p)
		}
		if err != nil {
			return nil, 0, true, problem(422, "ALLOCATION_POLICY_INVALID", "use version 1 resource selectors and workload weights summing to 1000000")
		}
		out, err = tx.AllocationPolicyAppend(ctx, model.Number(latest, "version"), i.Subject, p)
	} else {
		var selection allocationSelection
		if err = telemetryStrict(in, &selection); err != nil || selection.PolicyID == "" {
			return nil, 0, true, problem(422, "ALLOCATION_SELECTION_INVALID", "select an immutable policy and persisted source; amounts, records and authority are server-selected")
		}
		if model.String(latest, "id") != selection.PolicyID {
			return nil, 0, true, store.ErrConflict
		}
		var src model.Document
		var rows []allocation.Record
		src, rows, err = a.allocationSource(ctx, tx, selection)
		if err == nil {
			out, err = tx.AllocationReportCreate(ctx, selection.PolicyID, i.Subject, src, rows)
		}
	}
	if err != nil {
		if strings.HasPrefix(err.Error(), "ALLOCATION_") {
			err = problem(422, err.Error(), "allocation source, mapping or precision is unavailable; no report was published")
		}
		return nil, 0, true, err
	}
	if err = tx.Audit(ctx, i.Subject, parts[0]+".created", model.String(out, "id"), model.Document{"id": out["id"], "version": out["version"], "input_hash": out["input_hash"], "hash": out["hash"], "execution_authorized": false}); err != nil {
		return nil, 0, true, err
	}
	return out, 201, true, nil
}

// The selection is never a new financial authority. Native reports consume one
// current complete export revision for an exact month, never sum revision history.
// Public uploads remain explicitly customer-reported with unknown coverage.
func (a *API) allocationSource(ctx context.Context, tx *store.Tx, s allocationSelection) (model.Document, []allocation.Record, error) {
	var job model.Document
	src := model.Document{"kind": s.Source.Kind, "coverage": "UNKNOWN", "finality": "UNPROVEN", "execution_authorized": false, "verified_saving": nil}
	if s.Source.Kind == "CUSTOMER_IMPORT" {
		if s.Source.IngestionJobID == "" || s.Source.SourceConnectionID != "" || s.Source.BillingPeriodStart != "" {
			return nil, nil, errors.New("ALLOCATION_SOURCE_SELECTION_INVALID")
		}
		var err error
		job, err = tx.Get(ctx, "ingestion_jobs", s.Source.IngestionJobID)
		if err != nil {
			return nil, nil, err
		}
		provenance := model.String(job, "source_provenance")
		if provenance != "CUSTOMER_IMPORT" && !(a.Config.Fixture && provenance == "DETERMINISTIC_FIXTURE") {
			return nil, nil, errors.New("ALLOCATION_CUSTOMER_IMPORT_REQUIRED")
		}
		src["provenance"], src["reason_code"] = provenance, "CUSTOMER_REPORTED_COVERAGE_UNKNOWN"
		if provenance == "DETERMINISTIC_FIXTURE" {
			src["kind"], src["reason_code"] = "DETERMINISTIC_FIXTURE", "FIXTURE_DATA_ONLY"
		}
	} else if s.Source.Kind == "AWS_CUR2_CONNECTION" {
		if s.Source.SourceConnectionID == "" || s.Source.IngestionJobID != "" {
			return nil, nil, errors.New("ALLOCATION_SOURCE_SELECTION_INVALID")
		}
		// Sync owns this key exclusively until publication/checkpoints complete.
		// A shared transaction lock freezes the selected month head without
		// waiting for network ingestion while holding the inventory graph lock.
		var stable bool
		if err := tx.QueryRow(ctx, "SELECT pg_try_advisory_xact_lock_shared(hashtextextended($1,0))", tx.Tenant+":trusted-source:"+s.Source.SourceConnectionID).Scan(&stable); err != nil {
			return nil, nil, err
		}
		if !stable {
			return nil, nil, errors.New("ALLOCATION_SOURCE_SYNC_IN_PROGRESS")
		}
		start, err := time.Parse(time.RFC3339Nano, s.Source.BillingPeriodStart)
		if err != nil || start.Format(time.RFC3339) != s.Source.BillingPeriodStart || start.Location() != time.UTC || start.Day() != 1 || start.Hour() != 0 || start.Minute() != 0 || start.Second() != 0 || start.Nanosecond() != 0 {
			return nil, nil, errors.New("ALLOCATION_BILLING_MONTH_REQUIRED")
		}
		var sourceID string
		if err = tx.QueryRow(ctx, "SELECT id FROM source_registrations WHERE tenant_id=$1 AND id=$2 FOR SHARE", tx.Tenant, s.Source.SourceConnectionID).Scan(&sourceID); err != nil {
			return nil, nil, err
		}
		registration, err := tx.SourceGet(ctx, sourceID)
		if err != nil {
			return nil, nil, err
		}
		if model.String(registration, "status") != "HEALTHY" {
			return nil, nil, errors.New("ALLOCATION_NATIVE_SOURCE_NOT_HEALTHY")
		}
		receipts, err := periodReceipts(ctx, tx, sourceID, start, start.AddDate(0, 1, 0))
		if err != nil {
			return nil, nil, errors.New("ALLOCATION_NATIVE_PERIOD_UNAVAILABLE")
		}
		var selected model.Document
		for _, receipt := range receipts {
			p := evidence.Object(receipt["source_proof"])
			if model.String(p, "billing_period_start") == s.Source.BillingPeriodStart {
				if selected != nil {
					return nil, nil, errors.New("ALLOCATION_NATIVE_PERIOD_AMBIGUOUS")
				}
				selected = receipt
			}
		}
		if selected == nil {
			return nil, nil, errors.New("ALLOCATION_NATIVE_PERIOD_UNAVAILABLE")
		}
		job, err = tx.Get(ctx, "ingestion_jobs", model.String(selected, "ingestion_job_id"))
		if err != nil {
			return nil, nil, err
		}
		accounts := model.Strings(registration, "usage_account_ids")
		if len(accounts) == 0 {
			return nil, nil, errors.New("ALLOCATION_NATIVE_SCOPE_UNAVAILABLE")
		}
		// Reuse receipt issuer/hash/revision/current-registration validation. This
		// synthetic selector tests registration scope, never asserts a resource fact.
		validated, err := trustedJob(ctx, tx, job, model.Document{"region": registration["region"], "account_id": accounts[0]})
		if err != nil || model.String(validated, "id") != model.String(selected, "id") {
			return nil, nil, errors.New("ALLOCATION_NATIVE_RECEIPT_INVALID")
		}
		src["coverage"], src["provenance"], src["reason_code"] = "AUTHENTICATED_EXPORT_REVISION", "AWS_CUR2_AUTHENTICATED", "PROVISIONAL_NATIVE_BILLED_COST"
		src["source_connection_id"], src["source_receipt_id"], src["source_revision_id"] = sourceID, selected["id"], selected["revision_id"]
		src["billing_period_start"], src["payer_account_id"], src["source_proof_hash"] = s.Source.BillingPeriodStart, registration["payer_account_id"], evidence.Hash(selected["source_proof"])
	} else {
		return nil, nil, errors.New("ALLOCATION_SOURCE_KIND_UNSUPPORTED")
	}
	if model.String(job, "status") != "PERSISTED" {
		return nil, nil, errors.New("ALLOCATION_PERSISTED_SOURCE_REQUIRED")
	}
	raw, canonical := evidence.Object(job["raw"]), evidence.Object(job["canonical"])
	id, version := model.String(raw, "source_id"), model.String(raw, "source_version")
	if id == "" || version == "" || model.String(job, "source_id") != id {
		return nil, nil, errors.New("ALLOCATION_SOURCE_IDENTITY_INVALID")
	}
	encoded, encodeErr := json.Marshal(canonical["records"])
	var nativeRows []model.Document
	if encodeErr != nil || json.Unmarshal(encoded, &nativeRows) != nil || nativeRows == nil {
		return nil, nil, errors.New("ALLOCATION_CANONICAL_RECORDS_INVALID")
	}
	if len(nativeRows) > allocation.MaxRecords {
		return nil, nil, errors.New("ALLOCATION_RECORD_LIMIT")
	}
	rows := make([]allocation.Record, 0, len(nativeRows))
	for _, row := range nativeRows {
		if model.String(row, "x_SourceId") != id || model.String(row, "x_SourceVersion") != version {
			return nil, nil, errors.New("ALLOCATION_CANONICAL_SOURCE_MISMATCH")
		}
		if s.Source.Kind == "AWS_CUR2_CONNECTION" && model.String(row, "BillingAccountId") != model.String(src, "payer_account_id") {
			return nil, nil, errors.New("ALLOCATION_NATIVE_PAYER_MISMATCH")
		}
		var cost *string
		if value, exists := row["BilledCost"]; exists && value != nil {
			amount, ok := value.(string)
			if !ok {
				return nil, nil, errors.New("ALLOCATION_DECIMAL_STRING_REQUIRED")
			}
			cost = &amount
		}
		rows = append(rows, allocation.Record{ID: model.String(row, "x_SourceRecordId"), SourceID: id, SourceVersion: version, Provider: "AWS", AccountID: model.String(row, "SubAccountId"), Region: model.String(row, "RegionId"), ProviderResourceID: model.String(row, "ResourceId"), Currency: model.String(row, "BillingCurrency"), BilledCost: cost})
	}
	src["ingestion_job_id"], src["source_id"], src["source_version"] = job["id"], id, version
	src["raw_hash"], src["canonical_hash"] = evidence.Hash(raw), evidence.Hash(canonical)
	return src, rows, nil
}
