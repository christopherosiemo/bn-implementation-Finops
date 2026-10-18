package source

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/provider"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/jackc/pgx/v5"
	"sort"
	"strings"
	"time"
)

func (p *Pipeline) now() time.Time {
	if p.Now != nil {
		return p.Now().UTC()
	}
	return time.Now().UTC()
}
func (p *Pipeline) do(ctx context.Context, tenant string, f func(*store.Tx) error) error {
	return p.Store.Do(ctx, tenant, f)
}
func (p *Pipeline) status(ctx context.Context, tenant, id string, d model.Document) error {
	return p.do(ctx, tenant, func(t *store.Tx) error { return t.SourceCheckpointSet(ctx, id, "status", d) })
}
func (p *Pipeline) Tick(ctx context.Context, tenant string) error {
	var sources []model.Document
	if e := p.do(ctx, tenant, func(t *store.Tx) error { var e error; sources, e = t.SourceList(ctx); return e }); e != nil {
		return e
	}
	var first error
	for _, d := range sources {
		if model.String(d, "kind") != "AWS_CUR2" || !model.Bool(d, "enabled") || model.Bool(d, "revoked") {
			continue
		}
		last, _ := time.Parse(time.RFC3339Nano, model.String(d, "last_sync_at"))
		if !last.IsZero() && p.now().Sub(last) < time.Minute && (!model.Bool(d, "sync_requested") || model.Number(d, "last_sync_version") >= model.Number(d, "version")) {
			continue
		}
		if e := p.Sync(ctx, tenant, model.String(d, "id")); e != nil && first == nil {
			first = e
		}
	}
	return first
}
func (p *Pipeline) Sync(ctx context.Context, tenant, id string) (err error) {
	if p.Store == nil || p.ProviderFactory == nil || p.Normalize == nil || p.Persist == nil || p.ArchiveObject == nil {
		return errors.New("SOURCE_PIPELINE_DEPENDENCIES_REQUIRED")
	}
	lock, e := p.Store.Pool.Acquire(ctx)
	if e != nil {
		return e
	}
	defer lock.Release()
	var held bool
	if e = lock.QueryRow(ctx, "SELECT pg_try_advisory_lock(hashtextextended($1,0))", tenant+":trusted-source:"+id).Scan(&held); e != nil {
		return e
	}
	if !held {
		return nil
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_, _ = lock.Exec(cleanup, "SELECT pg_advisory_unlock(hashtextextended($1,0))", tenant+":trusted-source:"+id)
	}()
	var registration model.Document
	if e = p.do(ctx, tenant, func(t *store.Tx) error { var e error; registration, e = t.SourceGet(ctx, id); return e }); e != nil {
		return e
	}
	r, e := ParseRegistration(registration)
	if e != nil {
		return e
	}
	if !r.Enabled || model.Bool(registration, "revoked") {
		return errors.New("SOURCE_DISABLED")
	}
	configHash := ConfigurationHash(registration)
	status := model.Document{"last_sync_at": p.now().Format(time.RFC3339Nano), "last_sync_version": r.Version, "config_hash": configHash, "status": "DEGRADED", "reason_code": "SOURCE_SYNC_FAILED"}
	defer func() {
		if err != nil {
			status["reason_code"] = safeReason(err)
		}
		status["last_sync_at"] = p.now().Format(time.RFC3339Nano)
		if statusErr := p.status(ctx, tenant, id, status); err == nil {
			err = statusErr
		}
	}()
	reader, e := p.ProviderFactory(ctx, r)
	if e != nil {
		return e
	}
	bucket, e := reader.BillingBucket(ctx, r.Bucket)
	if e != nil {
		return e
	}
	if e = ValidateWriterPolicy(r, bucket); e != nil {
		return e
	}
	commitment, e := reader.BillingCommitments(ctx, r.PayerAccountID)
	if e != nil {
		return e
	}
	commitID := model.ID()
	commitment["receipt_id"], commitment["observed_at"] = commitID, p.now().Format(time.RFC3339Nano)
	native, _ := json.Marshal(commitment)
	if e = p.ArchiveObject(ctx, tenant, id, "commitments/"+BytesHash(native), native); e != nil {
		return e
	}
	if e = p.do(ctx, tenant, func(t *store.Tx) error {
		_, e := t.SourceReceiptCreate(ctx, model.Document{"id": commitID, "kind": "AWS_COMMITMENT", "source_id": id, "config_hash": configHash, "observed_at": commitment["observed_at"], "commitment_scope": commitment, "native_hash": BytesHash(native)})
		return e
	}); e != nil {
		return e
	}
	status["commitment_receipt_id"] = commitID
	executions, e := reader.ListBillingExecutions(ctx, r.ExportARN)
	if e != nil {
		return e
	}
	successful := []model.Document{}
	for _, x := range executions {
		if model.String(Object(x["ExecutionStatus"]), "StatusCode") == "DELIVERY_SUCCESS" {
			successful = append(successful, x)
		}
	}
	sort.Slice(successful, func(i, j int) bool {
		return model.String(Object(successful[i]["ExecutionStatus"]), "CreatedAt") > model.String(Object(successful[j]["ExecutionStatus"]), "CreatedAt")
	})
	if len(successful) == 0 {
		return errors.New("SOURCE_NO_SUCCESSFUL_EXECUTION")
	}
	// A bounded durable scan backfills earlier billing partitions. Refresh the
	// latest execution and recent month heads even after their chunks are read,
	// so native invoice cancellation is observed without manufacturing new CUR.
	historyKey := "history:" + configHash
	history := model.Document{}
	if e = p.do(ctx, tenant, func(t *store.Tx) error {
		var e error
		history, e = t.SourceCheckpointGet(ctx, id, historyKey)
		if e == pgx.ErrNoRows {
			history = model.Document{}
			return nil
		}
		return e
	}); e != nil {
		return e
	}
	seen := Object(history["processed"])
	monthHeads := Object(history["month_heads"])
	selected := []model.Document{}
	selectedIDs := map[string]bool{}
	add := func(x model.Document) {
		id := model.String(x, "ExecutionId")
		if id != "" && !selectedIDs[id] {
			selected = append(selected, x)
			selectedIDs[id] = true
		}
	}
	add(successful[0])
	for _, x := range successful {
		if len(selected) >= 64 {
			break
		}
		if !model.Bool(seen, model.String(x, "ExecutionId")) {
			add(x)
		}
	}
	olderMonths := []string{}
	for month, headID := range monthHeads {
		date, e := time.Parse("2006-01", month)
		if e != nil {
			continue
		}
		if date.Before(time.Date(p.now().Year(), p.now().Month(), 1, 0, 0, 0, 0, time.UTC).AddDate(0, -2, 0)) {
			olderMonths = append(olderMonths, month)
			continue
		}
		add(model.Document{"ExecutionId": headID})
	}
	rotation, nextCursor := rotateMonths(olderMonths, model.String(history, "older_month_cursor"), 4)
	for _, month := range rotation {
		add(model.Document{"ExecutionId": monthHeads[month]})
	}
	invoiceCache := map[string][]model.Document{}
	processed := 0
	for _, reference := range selected {
		executionID := model.String(reference, "ExecutionId")
		if executionID == "" {
			return errors.New("SOURCE_EXECUTION_ID_REQUIRED")
		}
		execution, e := reader.BillingExecution(ctx, r.ExportARN, executionID)
		if e != nil {
			return e
		}
		name, e := ValidateExecution(r, execution)
		if e != nil {
			return e
		}
		if e = ValidateExecutionTime(execution, p.now()); e != nil {
			return e
		}
		keys, e := reader.BillingManifestKeys(ctx, r.Bucket, r.Prefix+name+"/metadata/", executionID)
		if e != nil {
			return e
		}
		if len(keys) == 0 {
			return errors.New("SOURCE_MANIFEST_REQUIRED")
		}
		sort.Strings(keys)
		for _, key := range keys {
			receipt, e := p.delivery(ctx, r, registration, reader, execution, name, executionID, key, bucket, commitment, invoiceCache)
			if e != nil {
				return e
			}
			processed++
			period := model.String(Object(receipt["source_proof"]), "billing_period_start")
			monthHeads[strings.TrimSuffix(period, "-01T00:00:00Z")] = receipt["execution_id"]
			if period >= model.String(status, "latest_period_start") {
				status["latest_period_start"] = period
				status["latest_revision_id"], status["latest_receipt_id"], status["ingestion_job_id"] = receipt["revision_id"], receipt["id"], receipt["ingestion_job_id"]
			}
		}
		seen[executionID] = true
		history["processed"], history["month_heads"] = seen, monthHeads
		if e = p.do(ctx, tenant, func(t *store.Tx) error { return t.SourceCheckpointSet(ctx, id, historyKey, history) }); e != nil {
			return e
		}
	}
	// Advance the rotation only after every selected read succeeds. A crash or
	// provider failure retries that bounded batch rather than skipping authority.
	history["older_month_cursor"] = nextCursor
	if e = p.do(ctx, tenant, func(t *store.Tx) error { return t.SourceCheckpointSet(ctx, id, historyKey, history) }); e != nil {
		return e
	}
	status["status"], status["reason_code"], status["manifest_count"] = "HEALTHY", "SOURCE_AUTHENTICATED", processed
	pending := 0
	for _, x := range successful {
		if !model.Bool(seen, model.String(x, "ExecutionId")) {
			pending++
		}
	}
	status["backfill_pending"] = pending
	if pending > 0 {
		status["reason_code"] = "SOURCE_HISTORY_BACKFILL_PENDING"
	}
	if !model.Bool(commitment, "complete") || model.Number(commitment, "reserved_instance_count") != 0 || model.Number(commitment, "savings_plan_count") != 0 {
		status["reason_code"] = "COMMITMENT_SCOPE_UNAVAILABLE"
	}
	return nil
}

func (p *Pipeline) delivery(ctx context.Context, r Registration, registration model.Document, reader Reader, execution model.Document, name, executionID, key string, bucket, commitment model.Document, invoiceCache map[string][]model.Document) (model.Document, error) {
	checkpointKey := "delivery:" + Hash(model.Document{"execution": executionID, "key": key, "config_hash": ConfigurationHash(registration)})
	checkpoint := model.Document{}
	if e := p.do(ctx, r.TenantID, func(t *store.Tx) error {
		d, e := t.SourceCheckpointGet(ctx, r.ID, checkpointKey)
		if e == pgx.ErrNoRows {
			return nil
		}
		checkpoint = d
		return e
	}); e != nil {
		return nil, e
	}
	manifestObject, e := reader.BillingObject(ctx, r.Bucket, key, model.String(Object(checkpoint["manifest"]), "version_id"))
	if e != nil {
		return nil, e
	}
	if e = validateObject(manifestObject, key); e != nil {
		return nil, e
	}
	executionTime, _ := time.Parse(time.RFC3339Nano, model.String(Object(execution["ExecutionStatus"]), "CreatedAt"))
	if manifestObject.LastModified.After(p.now().Add(30*time.Second)) || manifestObject.LastModified.Before(executionTime) {
		return nil, errors.New("SOURCE_MANIFEST_TIME_INVALID")
	}
	manifest, e := ParseManifest(r, name, executionID, key, manifestObject.Data)
	if e != nil {
		return nil, e
	}
	monthHeadKey := "month:" + ConfigurationHash(registration) + ":" + manifest.Start.Format("2006-01")
	executedAt := model.String(Object(execution["ExecutionStatus"]), "CreatedAt")
	var newer model.Document
	monthHead := model.Document{}
	if e = p.do(ctx, r.TenantID, func(t *store.Tx) error {
		head, e := t.SourceCheckpointGet(ctx, r.ID, monthHeadKey)
		if e == pgx.ErrNoRows {
			return nil
		}
		if e != nil {
			return e
		}
		monthHead = head
		if model.String(head, "execution_created_at") > executedAt || (model.String(head, "execution_created_at") == executedAt && model.String(head, "execution_id") > executionID) {
			newer, e = t.SourceReceiptGet(ctx, model.String(head, "receipt_id"))
			return e
		}
		return nil
	}); e != nil {
		return nil, e
	}
	if newer != nil {
		return newer, nil
	}
	if e = p.ArchiveObject(ctx, r.TenantID, r.ID, key, manifestObject.Data); e != nil {
		return nil, e
	}
	manifestRef := objectReference(manifestObject)
	checkpoint["manifest"], checkpoint["status"] = manifestRef, "READING"
	if e = p.checkpoint(ctx, r, checkpointKey, checkpoint); e != nil {
		return nil, e
	}
	month := manifest.Start.Format("2006-01")
	invoices, ok := invoiceCache[month]
	if !ok {
		nativeInvoices, e := reader.BillingInvoices(ctx, r.PayerAccountID, manifest.Start.Year(), int(manifest.Start.Month()))
		if e == nil {
			for _, invoice := range nativeInvoices {
				encoded, _ := json.Marshal(invoice)
				invoiceID := "invoice-" + Hash(model.Document{"source_id": r.ID, "config": ConfigurationHash(registration), "native": invoice})
				if e = p.ArchiveObject(ctx, r.TenantID, r.ID, "invoices/"+invoiceID, encoded); e != nil {
					return nil, e
				}
				if e = p.do(ctx, r.TenantID, func(t *store.Tx) error {
					if _, e := t.SourceReceiptGet(ctx, invoiceID); e == nil {
						return nil
					} else if e != pgx.ErrNoRows {
						return e
					}
					_, e := t.SourceReceiptCreate(ctx, model.Document{"id": invoiceID, "source_id": r.ID, "kind": "AWS_INVOICE", "config_hash": ConfigurationHash(registration), "observed_at": p.now().Format(time.RFC3339Nano), "native": invoice, "native_hash": BytesHash(encoded)})
					return e
				}); e != nil {
					return nil, e
				}
				invoices = append(invoices, model.Document{"receipt_id": invoiceID, "native": invoice})
			}
		}
		sort.Slice(invoices, func(i, j int) bool {
			return model.String(invoices[i], "receipt_id") < model.String(invoices[j], "receipt_id")
		})
		invoiceCache[month] = invoices
	}
	invoiceHash := Hash(invoices)
	if model.String(checkpoint, "receipt_id") != "" && model.String(checkpoint, "invoice_hash") == invoiceHash {
		var receipt model.Document
		e := p.do(ctx, r.TenantID, func(t *store.Tx) error {
			var e error
			receipt, e = t.SourceReceiptGet(ctx, model.String(checkpoint, "receipt_id"))
			return e
		})
		return receipt, e
	}
	allRows := []model.Document{}
	objects := []model.Document{}
	pinned := map[string]model.Document{}
	for _, v := range Rows(checkpoint["objects"]) {
		pinned[model.String(v, "key")] = v
	}
	for _, objectKey := range manifest.Keys {
		object, e := reader.BillingObject(ctx, r.Bucket, objectKey, model.String(pinned[objectKey], "version_id"))
		if e != nil {
			return nil, e
		}
		if e = validateObject(object, objectKey); e != nil {
			return nil, e
		}
		if object.LastModified.After(manifestObject.LastModified) {
			return nil, errors.New("SOURCE_OBJECT_AFTER_MANIFEST")
		}
		reference := objectReference(object)
		if prior, ok := pinned[objectKey]; ok && model.String(prior, "sha256") != model.String(reference, "sha256") {
			return nil, errors.New("SOURCE_OBJECT_VERSION_CHANGED")
		}
		rows, e := ParseGzipCSV(object.Data)
		if e != nil {
			return nil, e
		}
		if len(allRows)+len(rows) > 100000 {
			return nil, errors.New("SOURCE_ROW_LIMIT")
		}
		if e = p.ArchiveObject(ctx, r.TenantID, r.ID, objectKey, object.Data); e != nil {
			return nil, e
		}
		allRows = append(allRows, rows...)
		objects = append(objects, reference)
		checkpoint["objects"] = objects
		if e = p.checkpoint(ctx, r, checkpointKey, checkpoint); e != nil {
			return nil, e
		}
	}
	if e = ValidateRows(r, manifest, allRows); e != nil {
		return nil, e
	}
	if len(allRows) == 0 {
		return nil, errors.New("SOURCE_EMPTY_DELIVERY")
	}
	contentHash := Hash(model.Document{"source_id": r.ID, "config_hash": ConfigurationHash(registration), "execution": execution, "manifest": manifestRef, "objects": objects, "invoices": invoices})
	revisionHash := contentHash
	previousReceipt := model.String(monthHead, "receipt_id")
	// Native authority can return to earlier content (issued -> cancelled ->
	// issued). Revivals append a new observation after the current month head;
	// reusing the original content-addressed receipt would leave cancellation
	// newer forever. Retries keep the same predecessor and remain idempotent.
	if previousReceipt != "" {
		if e = p.do(ctx, r.TenantID, func(t *store.Tx) error {
			prior, e := t.SourceReceiptGet(ctx, "receipt-"+contentHash)
			if e == pgx.ErrNoRows {
				return nil
			}
			if e != nil {
				return e
			}
			currentContent := model.String(monthHead, "content_hash")
			if currentContent == "" {
				head, e := t.SourceReceiptGet(ctx, previousReceipt)
				if e != nil {
					return e
				}
				currentContent = model.String(head, "content_hash")
				if currentContent == "" {
					currentContent = model.String(head, "source_version")
				}
			}
			if currentContent != contentHash && model.String(prior, "id") != previousReceipt {
				revisionHash = Hash(model.Document{"content_hash": contentHash, "previous_receipt_id": previousReceipt})
			}
			return nil
		}); e != nil {
			return nil, e
		}
	}
	revisionID := "revision-" + revisionHash
	receiptID := "receipt-" + revisionHash
	jobID := "source-" + revisionHash
	raw := model.Document{"schema_version": "3", "source_id": r.ID, "source_version": revisionHash, "records": allRows, "provider_manifest": manifest.Raw, "provider_execution": execution, "provider_objects": objects, "provider_manifest_reference": manifestRef}
	canonical, e := p.Normalize(ctx, raw)
	if e != nil {
		return nil, e
	}
	if len(Rows(canonical["records"])) != len(allRows) {
		return nil, errors.New("SOURCE_NORMALIZATION_COUNT_MISMATCH")
	}
	if e = p.Persist(ctx, r.TenantID, r.ID, raw, canonical); e != nil {
		return nil, e
	}
	// Re-read the pinned manifest and bucket boundary before publishing authority.
	verify, e := reader.BillingObject(ctx, r.Bucket, key, manifestObject.VersionID)
	if e != nil || BytesHash(verify.Data) != BytesHash(manifestObject.Data) {
		return nil, errors.New("SOURCE_MANIFEST_VERSION_CHANGED")
	}
	currentBucket, e := reader.BillingBucket(ctx, r.Bucket)
	if e != nil {
		return nil, e
	}
	if e = ValidateWriterPolicy(r, currentBucket); e != nil {
		return nil, e
	}
	if Hash(currentBucket["policy"]) != Hash(bucket["policy"]) {
		return nil, errors.New("SOURCE_WRITER_POLICY_CHANGED")
	}
	proof := sourceProof(r, manifest, allRows, objects, receiptID, revisionID, BytesHash(manifestObject.Data), invoices, p.now())
	proof["source_id"], proof["source_version"] = r.ID, revisionHash
	receipt := model.Document{"id": receiptID, "source_id": r.ID, "kind": "AWS_CUR2", "content_hash": contentHash, "previous_receipt_id": previousReceipt, "execution_id": executionID, "execution_created_at": executedAt, "revision_id": revisionID, "registration_id": r.ID, "registration_version": r.Version, "config_hash": ConfigurationHash(registration), "ingestion_job_id": jobID, "source_version": revisionHash, "raw_hash": Hash(raw), "canonical_hash": Hash(canonical), "manifest": manifestRef, "objects": objects, "source_proof": proof, "commitment_scope": commitment, "invoices": invoices, "observed_at": p.now().Format(time.RFC3339Nano), "writer_policy_hash": Hash(bucket["policy"])}
	e = p.do(ctx, r.TenantID, func(t *store.Tx) error {
		active, e := t.SourceGet(ctx, r.ID)
		if e != nil {
			return e
		}
		if !model.Bool(active, "enabled") || model.Bool(active, "revoked") || ConfigurationHash(active) != ConfigurationHash(registration) {
			return errors.New("SOURCE_REGISTRATION_CHANGED")
		}
		if _, e = t.SourceRevisionGet(ctx, revisionID); e == pgx.ErrNoRows {
			if _, e = t.SourceRevisionCreate(ctx, model.Document{"id": revisionID, "source_id": r.ID, "content_hash": contentHash, "previous_receipt_id": previousReceipt, "registration_id": r.ID, "revision_hash": revisionHash, "config_hash": ConfigurationHash(registration), "raw_hash": Hash(raw), "canonical_hash": Hash(canonical), "ingestion_job_id": jobID, "source_proof": proof, "manifest": manifestRef, "objects": objects, "observed_at": p.now().Format(time.RFC3339Nano)}); e != nil {
				return e
			}
		} else if e != nil {
			return e
		}
		if _, e = t.Get(ctx, "ingestion_jobs", jobID); e == pgx.ErrNoRows {
			if _, e = t.Create(ctx, "ingestion_jobs", model.Document{"id": jobID, "status": "PERSISTED", "source_id": r.ID, "source_version": revisionHash, "source_registration_id": r.ID, "source_revision_id": revisionID, "source_receipt_id": receiptID, "source_provenance": "AWS_CUR2_AUTHENTICATED", "raw": raw, "canonical": canonical, "persisted_at": p.now().Format(time.RFC3339Nano)}); e != nil {
				return e
			}
		} else if e != nil {
			return e
		}
		if _, e = t.SourceReceiptGet(ctx, receiptID); e == pgx.ErrNoRows {
			if _, e = t.SourceReceiptCreate(ctx, receipt); e != nil {
				return e
			}
		} else if e != nil {
			return e
		}
		checkpoint["status"], checkpoint["receipt_id"], checkpoint["revision_id"] = "PERSISTED", receiptID, revisionID
		checkpoint["invoice_hash"] = invoiceHash
		checkpoint["content_hash"] = contentHash
		if e = t.SourceCheckpointSet(ctx, r.ID, checkpointKey, checkpoint); e != nil {
			return e
		}
		if e = t.SourceCheckpointSet(ctx, r.ID, monthHeadKey, model.Document{"execution_id": executionID, "execution_created_at": executedAt, "content_hash": contentHash, "receipt_id": receiptID}); e != nil {
			return e
		}
		return t.Audit(ctx, "trusted-billing-ingester", "source.revision_persisted", revisionID, model.Document{"source_id": r.ID, "receipt_id": receiptID, "object_count": len(objects), "row_count": len(allRows)})
	})
	return receipt, e
}

func rotateMonths(months []string, after string, limit int) ([]string, string) {
	if len(months) == 0 || limit <= 0 {
		return nil, after
	}
	sort.Strings(months)
	start := sort.SearchStrings(months, after)
	for start < len(months) && months[start] <= after {
		start++
	}
	if start == len(months) {
		start = 0
	}
	if limit > len(months) {
		limit = len(months)
	}
	out := make([]string, 0, limit)
	for i := 0; i < limit; i++ {
		out = append(out, months[(start+i)%len(months)])
	}
	return out, out[len(out)-1]
}
func (p *Pipeline) checkpoint(ctx context.Context, r Registration, key string, d model.Document) error {
	return p.do(ctx, r.TenantID, func(t *store.Tx) error { return t.SourceCheckpointSet(ctx, r.ID, key, d) })
}
func objectReference(o provider.BillingObject) model.Document {
	return model.Document{"key": o.Key, "version_id": o.VersionID, "etag": o.ETag, "sha256": BytesHash(o.Data), "size_bytes": len(o.Data), "last_modified": o.LastModified.UTC().Format(time.RFC3339Nano)}
}
func validateObject(o provider.BillingObject, key string) error {
	if o.Key != key || o.VersionID == "" || o.VersionID == "null" || o.LastModified.IsZero() {
		return errors.New("SOURCE_OBJECT_VERSION_REQUIRED")
	}
	return nil
}
func safeReason(e error) string {
	s := e.Error()
	if strings.HasPrefix(s, "SOURCE_") || strings.HasPrefix(s, "COMMITMENT_") {
		if i := strings.IndexAny(s, ":\n"); i >= 0 {
			return s[:i]
		}
		return s
	}
	return "SOURCE_PROVIDER_UNAVAILABLE"
}

func sourceProof(r Registration, m Manifest, rows, objects []model.Document, receipt, revision, manifestHash string, invoices []model.Document, now time.Time) model.Document {
	final := true
	currencies := map[string]bool{}
	entities := map[string]bool{}
	latest := m.Start
	for _, row := range rows {
		currencies[model.String(row, "line_item_currency_code")] = true
		entities[model.String(row, "bill_invoicing_entity")] = true
		invoice := model.String(row, "bill_invoice_id")
		if invoice == "" {
			final = false
		}
		end, _ := time.Parse(time.RFC3339Nano, model.String(row, "line_item_usage_end_date"))
		if end.After(latest) {
			latest = end
		}
	}
	state := "COMPLETE"
	end := time.Date(latest.Year(), latest.Month(), latest.Day(), 0, 0, 0, 0, time.UTC)
	if end.After(now) {
		end = time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	}
	if final && m.End.Before(now) {
		state = "FINAL"
		end = m.End
	}
	currency, entity := "", ""
	if len(currencies) == 1 {
		for k := range currencies {
			currency = k
		}
	}
	if len(entities) == 1 {
		for k := range entities {
			entity = k
		}
	}
	return model.Document{"receipt_id": receipt, "revision_id": revision, "manifest_hash": manifestHash, "payer_account_id": r.PayerAccountID, "usage_account_ids": r.UsageAccountIDs, "region": r.Region, "currency": currency, "invoice_entity": entity, "period_start": m.Start.Format(time.RFC3339), "period_end": end.Format(time.RFC3339), "billing_period_start": m.Start.Format(time.RFC3339), "billing_period_end": m.End.Format(time.RFC3339), "state": state, "object_count": len(objects), "verified_object_count": len(objects), "row_count": len(rows), "verified_row_count": len(rows), "invoice_count": len(invoices), "observed_at": now.Format(time.RFC3339Nano)}
}
