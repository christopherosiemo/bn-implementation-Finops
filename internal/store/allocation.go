package store

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/allocation"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/jackc/pgx/v5"
)

var ErrAllocationInvalid = errors.New("ALLOCATION_METADATA_OR_CURSOR_INVALID")

func sortAllocationCatalog(resources []allocation.Resource, workloads []string, mapping model.Document) {
	sort.Slice(resources, func(i, j int) bool { return resources[i].ID < resources[j].ID })
	sort.Strings(workloads)
	rows := mapping["resources"].([]model.Document)
	sort.Slice(rows, func(i, j int) bool { return model.String(rows[i], "id") < model.String(rows[j], "id") })
	mapping["resources"], mapping["workloads"] = rows, workloads
}

func (t *Tx) allocationLock(ctx context.Context) error {
	_, err := t.Exec(ctx, "SELECT allocation_lock($1)", t.Tenant)
	return err
}
func (t *Tx) allocationHash(ctx context.Context, value any) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	var hash string
	err = t.QueryRow(ctx, "SELECT allocation_json_hash($1::jsonb)", raw).Scan(&hash)
	return hash, err
}
func (t *Tx) AllocationPolicyLatest(ctx context.Context) (model.Document, error) {
	return t.sourceOne(ctx, "SELECT document FROM allocation_policy_revisions WHERE tenant_id=$1 ORDER BY version DESC LIMIT 1", t.Tenant)
}
func (t *Tx) AllocationPolicyGet(ctx context.Context, id string) (model.Document, error) {
	return t.sourceOne(ctx, "SELECT document FROM allocation_policy_revisions WHERE tenant_id=$1 AND id=$2", t.Tenant, id)
}
func (t *Tx) AllocationPolicyPage(ctx context.Context, after string, limit int) ([]model.Document, error) {
	if limit < 1 || limit > 101 {
		return nil, ErrAllocationInvalid
	}
	return t.sourceRows(ctx, "SELECT document FROM allocation_policy_revisions WHERE tenant_id=$1 AND ($2='' OR (created_at,id)<(SELECT created_at,id FROM allocation_policy_revisions WHERE tenant_id=$1 AND id=$2)) ORDER BY created_at DESC,id DESC LIMIT $3", t.Tenant, after, limit)
}
func (t *Tx) allocationCatalog(ctx context.Context) ([]allocation.Resource, []string, model.Document, error) {
	raw, err := t.List(ctx, "resources")
	if err != nil {
		return nil, nil, nil, err
	}
	workloads, err := t.List(ctx, "workloads")
	if err != nil {
		return nil, nil, nil, err
	}
	if len(raw) > 10000 || len(workloads) > 10000 {
		return nil, nil, nil, errors.New("ALLOCATION_CATALOG_LIMIT")
	}
	resources, ids := []allocation.Resource{}, []string{}
	mapping := model.Document{"resources": []model.Document{}, "workloads": []string{}}
	for _, d := range raw {
		r := allocation.Resource{ID: model.String(d, "id"), Provider: model.String(d, "provider"), AccountID: model.String(d, "account_id"), Region: model.String(d, "region"), ProviderResourceID: model.String(d, "provider_resource_id"), WorkloadID: model.String(d, "workload_id"), Version: model.Number(d, "version")}
		resources = append(resources, r)
		mapping["resources"] = append(mapping["resources"].([]model.Document), model.Document{"id": r.ID, "provider": r.Provider, "account_id": r.AccountID, "region": r.Region, "provider_resource_id": r.ProviderResourceID, "workload_id": r.WorkloadID, "version": r.Version})
	}
	for _, d := range workloads {
		ids = append(ids, model.String(d, "id"))
	}
	// Engine/resource iteration does not affect attribution, but the immutable
	// snapshot has a deterministic order independent of inventory creation time.
	sortAllocationCatalog(resources, ids, mapping)
	return resources, ids, mapping, nil
}
func (t *Tx) AllocationPolicyAppend(ctx context.Context, expected int64, actor string, p allocation.Policy) (model.Document, error) {
	if expected < 0 || expected == math.MaxInt64 || actor == "" || len(actor) > 512 {
		return nil, ErrAllocationInvalid
	}
	if err := t.allocationLock(ctx); err != nil {
		return nil, err
	}
	latest, err := t.AllocationPolicyLatest(ctx)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	if model.Number(latest, "version") != expected {
		return nil, ErrConflict
	}
	resources, workloads, _, err := t.allocationCatalog(ctx)
	if err != nil {
		return nil, err
	}
	if _, err = allocation.Evaluate(p, nil, resources, workloads); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	hash, err := t.allocationHash(ctx, p)
	if err != nil {
		return nil, err
	}
	return t.sourceOne(ctx, "INSERT INTO allocation_policy_revisions(tenant_id,id,version,content_hash,definition,created_by) VALUES($1,$2,$3,$4,$5,$6) RETURNING document", t.Tenant, model.ID(), expected+1, hash, raw, actor)
}

var allocationSourceKeys = map[string]bool{
	"kind": true, "coverage": true, "finality": true, "execution_authorized": true, "verified_saving": true, "provenance": true, "reason_code": true,
	"source_connection_id": true, "source_receipt_id": true, "source_revision_id": true, "billing_period_start": true, "payer_account_id": true,
	"source_proof_hash": true, "ingestion_job_id": true, "source_id": true, "source_version": true, "raw_hash": true, "canonical_hash": true,
}

var allocationSourceHash = regexp.MustCompile(`^[a-f0-9]{64}$`)
var allocationPayerID = regexp.MustCompile(`^[0-9]{12}$`)
var allocationNativeSourceKeys = []string{"source_connection_id", "source_receipt_id", "source_revision_id", "billing_period_start", "payer_account_id", "source_proof_hash"}

func validateAllocationSource(d model.Document) error {
	if d == nil || (model.String(d, "kind") != "CUSTOMER_IMPORT" && model.String(d, "kind") != "DETERMINISTIC_FIXTURE" && model.String(d, "kind") != "AWS_CUR2_CONNECTION") || (model.String(d, "coverage") != "UNKNOWN" && model.String(d, "coverage") != "AUTHENTICATED_EXPORT_REVISION") || model.String(d, "finality") != "UNPROVEN" || d["execution_authorized"] != false || d["verified_saving"] != nil {
		return ErrAllocationInvalid
	}
	if _, present := d["verified_saving"]; !present {
		return ErrAllocationInvalid
	}
	for k, v := range d {
		if !allocationSourceKeys[k] {
			return ErrAllocationInvalid
		}
		if k != "execution_authorized" && k != "verified_saving" {
			text, ok := v.(string)
			if !ok || strings.TrimSpace(text) == "" || len(text) > 512 {
				return ErrAllocationInvalid
			}
		}
	}
	for _, k := range []string{"provenance", "reason_code", "ingestion_job_id", "source_id", "source_version", "raw_hash", "canonical_hash"} {
		if _, ok := d[k].(string); !ok || model.String(d, k) == "" {
			return ErrAllocationInvalid
		}
	}
	for _, k := range []string{"raw_hash", "canonical_hash"} {
		if !allocationSourceHash.MatchString(model.String(d, k)) {
			return ErrAllocationInvalid
		}
	}
	switch model.String(d, "kind") {
	case "CUSTOMER_IMPORT", "DETERMINISTIC_FIXTURE":
		if model.String(d, "provenance") != model.String(d, "kind") || model.String(d, "coverage") != "UNKNOWN" {
			return ErrAllocationInvalid
		}
		for _, k := range allocationNativeSourceKeys {
			if _, exists := d[k]; exists {
				return ErrAllocationInvalid
			}
		}
	case "AWS_CUR2_CONNECTION":
		if model.String(d, "provenance") != "AWS_CUR2_AUTHENTICATED" || model.String(d, "coverage") != "AUTHENTICATED_EXPORT_REVISION" || model.String(d, "source_id") != model.String(d, "source_connection_id") {
			return ErrAllocationInvalid
		}
		for _, k := range allocationNativeSourceKeys {
			if _, ok := d[k].(string); !ok || model.String(d, k) == "" {
				return ErrAllocationInvalid
			}
		}
		month := model.String(d, "billing_period_start")
		start, e := time.Parse(time.RFC3339, month)
		if e != nil || start.Format("2006-01-02T15:04:05Z") != month || start.Day() != 1 || start.Hour() != 0 || start.Minute() != 0 || start.Second() != 0 || !allocationPayerID.MatchString(model.String(d, "payer_account_id")) || !allocationSourceHash.MatchString(model.String(d, "source_proof_hash")) {
			return ErrAllocationInvalid
		}
	}
	raw, err := json.Marshal(d)
	if err != nil || len(raw) > 65536 {
		return ErrAllocationInvalid
	}
	return nil
}

// The API selects source facts before calling this method. The source label is
// contextual metadata only; it never creates provider/finality/claim authority.
func (t *Tx) AllocationReportCreate(ctx context.Context, policyID, actor string, source model.Document, records []allocation.Record) (model.Document, error) {
	if actor == "" || len(actor) > 512 || len(records) > allocation.MaxRecords {
		return nil, ErrAllocationInvalid
	}
	if err := validateAllocationSource(source); err != nil {
		return nil, err
	}
	for _, record := range records {
		if record.SourceID != model.String(source, "source_id") || record.SourceVersion != model.String(source, "source_version") {
			return nil, ErrAllocationInvalid
		}
	}
	if err := t.allocationLock(ctx); err != nil {
		return nil, err
	}
	policy, err := t.AllocationPolicyGet(ctx, policyID)
	if err != nil {
		return nil, err
	}
	current, err := t.AllocationPolicyLatest(ctx)
	if err != nil {
		return nil, err
	}
	if model.String(current, "id") != policyID {
		return nil, ErrConflict
	}
	var definition allocation.Policy
	raw, err := json.Marshal(policy["definition"])
	if err != nil || json.Unmarshal(raw, &definition) != nil {
		return nil, ErrAllocationInvalid
	}
	resources, workloads, mapping, err := t.allocationCatalog(ctx)
	if err != nil {
		return nil, err
	}
	if records == nil {
		records = []allocation.Record{}
	}
	result, err := allocation.Evaluate(definition, records, resources, workloads)
	if err != nil {
		return nil, err
	}
	mappingHash, err := t.allocationHash(ctx, mapping)
	if err != nil {
		return nil, err
	}
	inputHash, err := t.allocationHash(ctx, model.Document{"tenant_id": t.Tenant, "policy_id": policyID, "policy_hash": policy["hash"], "source": source, "mapping_hash": mappingHash, "records": records})
	if err != nil {
		return nil, err
	}
	resultHash, err := t.allocationHash(ctx, result)
	if err != nil {
		return nil, err
	}
	id := model.ID()
	d := model.Document{"id": id, "version": 1, "schema_version": "1", "status": result.Status, "basis": result.Basis, "reason_codes": result.ReasonCodes, "policy_id": policyID, "source": source, "mapping_hash": mappingHash, "input_hash": inputHash, "result_hash": resultHash, "record_count": result.RecordCount, "line_count": len(result.Lines), "totals": result.Totals, "execution_authorized": false, "verified_saving": nil}
	raw, err = json.Marshal(d)
	if err != nil {
		return nil, err
	}
	mapRaw, err := json.Marshal(mapping)
	if err != nil {
		return nil, err
	}
	if _, err = t.Exec(ctx, "INSERT INTO allocation_reports(tenant_id,id,policy_id,record_count,line_count,mapping_snapshot,document,created_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8)", t.Tenant, id, policyID, len(records), len(result.Lines), mapRaw, raw, actor); err != nil {
		return nil, err
	}
	ordinals := map[string]int{}
	// Bound transport batches without weakening any per-row trigger or the final
	// independent seal. Avoid a network round trip for each of 30,000 rows.
	batch := &pgx.Batch{}
	flush := func() error {
		if batch.Len() == 0 {
			return nil
		}
		err := t.SendBatch(ctx, batch).Close()
		batch = &pgx.Batch{}
		return err
	}
	for i, r := range result.ObservedRecords {
		raw, _ = json.Marshal(r)
		batch.Queue("INSERT INTO allocation_observations(tenant_id,report_id,ordinal,source_id,source_version,record_id,currency,observed_amount,document) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)", t.Tenant, id, i+1, r.SourceID, r.SourceVersion, r.ID, r.Currency, r.BilledCost, raw)
		if batch.Len() == 256 {
			if err = flush(); err != nil {
				return nil, err
			}
		}
		ordinals[allocation.Digest([]string{r.SourceID, r.SourceVersion, r.ID})] = i + 1
	}
	if err = flush(); err != nil {
		return nil, err
	}
	for i, line := range result.Lines {
		raw, _ = json.Marshal(line)
		batch.Queue("INSERT INTO allocation_lines(tenant_id,report_id,ordinal,observation_ordinal,currency,allocated_amount,document) VALUES($1,$2,$3,$4,$5,$6,$7)", t.Tenant, id, i+1, ordinals[allocation.Digest([]string{line.SourceID, line.SourceVersion, line.RecordID})], line.Currency, line.AllocatedBilledCost, raw)
		if batch.Len() == 256 {
			if err = flush(); err != nil {
				return nil, err
			}
		}
	}
	if err = flush(); err != nil {
		return nil, err
	}
	if _, err = t.Exec(ctx, "INSERT INTO allocation_report_seals(tenant_id,report_id) VALUES($1,$2)", t.Tenant, id); err != nil {
		return nil, err
	}
	return t.AllocationReportGet(ctx, id)
}
func (t *Tx) AllocationReportGet(ctx context.Context, id string) (model.Document, error) {
	return t.sourceOne(ctx, "SELECT report.document FROM allocation_reports report JOIN allocation_report_seals seal ON seal.tenant_id=report.tenant_id AND seal.report_id=report.id WHERE report.tenant_id=$1 AND report.id=$2", t.Tenant, id)
}
func (t *Tx) AllocationReportPage(ctx context.Context, after string, limit int) ([]model.Document, error) {
	if limit < 1 || limit > 101 {
		return nil, ErrAllocationInvalid
	}
	return t.sourceRows(ctx, "SELECT report.document FROM allocation_reports report JOIN allocation_report_seals seal ON seal.tenant_id=report.tenant_id AND seal.report_id=report.id WHERE report.tenant_id=$1 AND ($2='' OR (report.created_at,report.id)<(SELECT created_at,id FROM allocation_reports WHERE tenant_id=$1 AND id=$2)) ORDER BY report.created_at DESC,report.id DESC LIMIT $3", t.Tenant, after, limit)
}
func (t *Tx) AllocationReportRowPage(ctx context.Context, reportID, kind, after string, limit int) ([]model.Document, error) {
	ordinal := int64(0)
	if after != "" {
		var err error
		ordinal, err = strconv.ParseInt(after, 10, 32)
		if err != nil || ordinal < 1 || strconv.FormatInt(ordinal, 10) != after {
			return nil, ErrAllocationInvalid
		}
	}
	if limit < 1 || limit > 101 || (kind != "lines" && kind != "observations") {
		return nil, ErrAllocationInvalid
	}
	if _, err := t.AllocationReportGet(ctx, reportID); err != nil {
		return nil, err
	}
	table := "allocation_" + kind // The two-value allowlist above is mandatory.
	return t.sourceRows(ctx, "SELECT entry.document||jsonb_build_object('id',entry.ordinal::text) FROM "+table+" entry WHERE entry.tenant_id=$1 AND entry.report_id=$2 AND entry.ordinal>$3 ORDER BY entry.ordinal LIMIT $4", t.Tenant, reportID, ordinal, limit)
}
