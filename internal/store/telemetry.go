package store

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/telemetry"
	"github.com/jackc/pgx/v5"
)

var ErrTelemetryConflict = errors.New("TELEMETRY_REPLAY_CONFLICT")
var ErrTelemetrySource = errors.New("TELEMETRY_SOURCE_INVALID")

// The typed connection is the only registration input persisted. Endpoints and
// credentials are selected by the server's approved read-binding registry, not
// by a telemetry batch. Configuration and definition revisions are append-only.
func (t *Tx) TelemetryConnectionAppend(ctx context.Context, id string, expectedVersion int64, d model.Document) (model.Document, error) {
	if id == "" || expectedVersion < 0 || expectedVersion == math.MaxInt64 {
		return nil, ErrConflict
	}
	if err := t.telemetryLock(ctx, id); err != nil {
		return nil, err
	}
	old, err := t.TelemetryConnection(ctx, id)
	if err != nil && err != pgx.ErrNoRows {
		return nil, err
	}
	if old == nil {
		old = model.Document{"version": 0}
	}
	if model.Number(old, "version") != expectedVersion {
		return nil, ErrConflict
	}
	d = model.Clone(d)
	d["id"], d["version"] = id, expectedVersion+1
	var c telemetry.Connection
	b, err := json.Marshal(d)
	if err == nil {
		err = json.Unmarshal(b, &c)
	}
	if err != nil {
		return nil, err
	}
	if c.Binding.TenantID != "" && c.Binding.TenantID != t.Tenant {
		return nil, ErrTelemetrySource
	}
	c.Binding.TenantID = t.Tenant
	if err = telemetry.ValidateConnection(c); err != nil {
		return nil, err
	}
	config := telemetry.Document(c)
	hash := telemetry.ConfigHash(c)
	b, _ = json.Marshal(config)
	if _, err = t.Exec(ctx, "INSERT INTO telemetry_connections(tenant_id,id,version,kind,config_hash,config) VALUES($1,$2,$3,$4,$5,$6)", t.Tenant, id, c.Version, c.Kind, hash, b); err != nil {
		return nil, err
	}
	for _, def := range c.Definitions {
		document := telemetry.Document(def)
		raw, _ := json.Marshal(document)
		if _, err = t.Exec(ctx, "INSERT INTO telemetry_metric_definitions(tenant_id,connection_id,connection_version,id,version,content_hash,document) VALUES($1,$2,$3,$4,$5,$6,$7)", t.Tenant, id, c.Version, def.ID, def.Version, telemetry.Hash(def), raw); err != nil {
			return nil, err
		}
	}
	if _, err = t.Exec(ctx, "INSERT INTO telemetry_source_revisions(tenant_id,id,connection_id,connection_version,config_hash) VALUES($1,$2,$3,$4,$5)", t.Tenant, model.ID(), id, c.Version, hash); err != nil {
		return nil, err
	}
	return t.TelemetryConnection(ctx, id)
}

const telemetryConnectionProjection = `c.document||jsonb_build_object('revision_id',r.id,'revoked',EXISTS(SELECT 1 FROM telemetry_source_revocations v WHERE v.tenant_id=r.tenant_id AND v.revision_id=r.id))`

func (t *Tx) TelemetryConnection(ctx context.Context, id string) (model.Document, error) {
	return t.sourceOne(ctx, `SELECT `+telemetryConnectionProjection+` FROM telemetry_connections c JOIN telemetry_source_revisions r ON r.tenant_id=c.tenant_id AND r.connection_id=c.id AND r.connection_version=c.version WHERE c.tenant_id=$1 AND c.id=$2 ORDER BY c.version DESC LIMIT 1`, t.Tenant, id)
}
func (t *Tx) TelemetryConnections(ctx context.Context) ([]model.Document, error) {
	return t.sourceRows(ctx, `SELECT `+telemetryConnectionProjection+` FROM telemetry_connections c JOIN telemetry_source_revisions r ON r.tenant_id=c.tenant_id AND r.connection_id=c.id AND r.connection_version=c.version WHERE c.tenant_id=$1 AND NOT EXISTS(SELECT 1 FROM telemetry_connections n WHERE n.tenant_id=c.tenant_id AND n.id=c.id AND n.version>c.version) ORDER BY c.created_at,c.id`, t.Tenant)
}
func (t *Tx) TelemetryRevision(ctx context.Context, id string) (model.Document, error) {
	return t.sourceOne(ctx, `SELECT r.document||jsonb_build_object('revoked',EXISTS(SELECT 1 FROM telemetry_source_revocations v WHERE v.tenant_id=r.tenant_id AND v.revision_id=r.id),'superseded',EXISTS(SELECT 1 FROM telemetry_connections c WHERE c.tenant_id=r.tenant_id AND c.id=r.connection_id AND c.version>r.connection_version)) FROM telemetry_source_revisions r WHERE r.tenant_id=$1 AND r.id=$2`, t.Tenant, id)
}
func (t *Tx) TelemetryRevocationAppend(ctx context.Context, revisionID, reason string) (model.Document, bool, error) {
	rev, err := t.TelemetryRevision(ctx, revisionID)
	if err != nil {
		return nil, false, err
	}
	if err = t.telemetryLock(ctx, model.String(rev, "connection_id")); err != nil {
		return nil, false, err
	}
	old, err := t.sourceOne(ctx, "SELECT document FROM telemetry_source_revocations WHERE tenant_id=$1 AND revision_id=$2", t.Tenant, revisionID)
	if err == nil {
		if model.String(old, "reason") != reason {
			return nil, false, ErrTelemetryConflict
		}
		return old, true, nil
	}
	if err != pgx.ErrNoRows {
		return nil, false, err
	}
	out, err := t.sourceOne(ctx, "INSERT INTO telemetry_source_revocations(tenant_id,id,revision_id,reason) VALUES($1,$2,$3,$4) RETURNING document", t.Tenant, model.ID(), revisionID, reason)
	return out, false, err
}
func (t *Tx) telemetryLock(ctx context.Context, connection string) error {
	if _, err := t.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", t.Tenant+":dependency-graph"); err != nil {
		return err
	}
	_, err := t.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", t.Tenant+":telemetry:"+connection)
	return err
}
func (t *Tx) telemetryActiveRevision(ctx context.Context, connection, configHash string) (model.Document, error) {
	c, err := t.TelemetryConnection(ctx, connection)
	if err != nil {
		return nil, err
	}
	if model.String(c, "config_hash") != configHash || !model.Bool(c, "enabled") || model.Bool(c, "revoked") {
		return nil, ErrTelemetrySource
	}
	return c, nil
}

// Prepare writes only bounded batch metadata. A row here is deliberately not a
// trusted receipt: archive and analytics checkpoints must both be published.
func (t *Tx) TelemetryBatchPrepare(ctx context.Context, connection, configHash, key string, d model.Document) (model.Document, bool, error) {
	if key == "" || len(key) > 200 {
		return nil, false, ErrTelemetryConflict
	}
	if err := t.telemetryLock(ctx, connection); err != nil {
		return nil, false, err
	}
	metadata := model.Clone(d)
	if model.Number(metadata, "sample_count") == 0 {
		metadata["start"], metadata["end"] = nil, nil
	}
	identity := model.Clone(metadata)
	delete(identity, "collected_at")
	hash := telemetry.Hash(model.Document{"connection_id": connection, "config_hash": configHash, "metadata": identity})
	old, err := t.sourceOne(ctx, "SELECT document FROM telemetry_batches WHERE tenant_id=$1 AND connection_id=$2 AND idempotency_key=$3", t.Tenant, connection, key)
	if err == nil {
		if model.String(old, "request_hash") != hash {
			return nil, false, ErrTelemetryConflict
		}
		return old, true, nil
	}
	if err != pgx.ErrNoRows {
		return nil, false, err
	}
	c, err := t.telemetryActiveRevision(ctx, connection, configHash)
	if err != nil {
		return nil, false, err
	}
	b, err := json.Marshal(metadata)
	if err != nil {
		return nil, false, err
	}
	out, err := t.sourceOne(ctx, "INSERT INTO telemetry_batches(tenant_id,id,connection_id,revision_id,idempotency_key,request_hash,metadata) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING document", t.Tenant, model.ID(), connection, model.String(c, "revision_id"), key, hash, b)
	return out, false, err
}
func (t *Tx) TelemetryBatch(ctx context.Context, id string) (model.Document, error) {
	return t.sourceOne(ctx, "SELECT document FROM telemetry_batches WHERE tenant_id=$1 AND id=$2", t.Tenant, id)
}

// BatchByKey is a read-only lookup before any fresh transport decoding. The
// caller must compare the exact incoming raw hash/config/binding. Retrying an
// old published native batch never changes its original collection timestamp.
func (t *Tx) TelemetryBatchByKey(ctx context.Context, connection, key string) (model.Document, error) {
	return t.sourceOne(ctx, `SELECT b.document||jsonb_build_object('receipt_id',r.id,'published',r.id IS NOT NULL) FROM telemetry_batches b LEFT JOIN telemetry_receipts r ON r.tenant_id=b.tenant_id AND r.batch_id=b.id WHERE b.tenant_id=$1 AND b.connection_id=$2 AND b.idempotency_key=$3`, t.Tenant, connection, key)
}
func (t *Tx) TelemetryCheckpointAppend(ctx context.Context, batchID, stage string, d model.Document) (model.Document, bool, error) {
	batch, err := t.TelemetryBatch(ctx, batchID)
	if err != nil {
		return nil, false, err
	}
	if err = t.telemetryLock(ctx, model.String(batch, "connection_id")); err != nil {
		return nil, false, err
	}
	hash := telemetry.Hash(d)
	old, err := t.sourceOne(ctx, "SELECT document FROM telemetry_checkpoints WHERE tenant_id=$1 AND batch_id=$2 AND stage=$3", t.Tenant, batchID, stage)
	if err == nil {
		if model.String(old, "hash") != hash {
			return nil, false, ErrTelemetryConflict
		}
		return old, true, nil
	}
	if err != pgx.ErrNoRows {
		return nil, false, err
	}
	b, err := json.Marshal(d)
	if err != nil {
		return nil, false, err
	}
	out, err := t.sourceOne(ctx, "INSERT INTO telemetry_checkpoints(tenant_id,id,batch_id,stage,content_hash,metadata) VALUES($1,$2,$3,$4,$5,$6) RETURNING document", t.Tenant, model.ID(), batchID, stage, hash, b)
	return out, false, err
}
func (t *Tx) TelemetryCheckpoints(ctx context.Context, batchID string) ([]model.Document, error) {
	return t.sourceRows(ctx, "SELECT document FROM telemetry_checkpoints WHERE tenant_id=$1 AND batch_id=$2 ORDER BY created_at,id", t.Tenant, batchID)
}
func (t *Tx) TelemetryPublish(ctx context.Context, batchID string) (model.Document, bool, error) {
	batch, err := t.TelemetryBatch(ctx, batchID)
	if err != nil {
		return nil, false, err
	}
	if err = t.telemetryLock(ctx, model.String(batch, "connection_id")); err != nil {
		return nil, false, err
	}
	old, err := t.sourceOne(ctx, "SELECT document FROM telemetry_receipts WHERE tenant_id=$1 AND batch_id=$2", t.Tenant, batchID)
	if err == nil {
		return old, true, nil
	}
	if err != pgx.ErrNoRows {
		return nil, false, err
	}
	out, err := t.sourceOne(ctx, "INSERT INTO telemetry_receipts(tenant_id,id,batch_id,revision_id,connection_id) VALUES($1,$2,$3,$4,$5) RETURNING document", t.Tenant, model.ID(), batchID, model.String(batch, "revision_id"), model.String(batch, "connection_id"))
	return out, false, err
}

const telemetryReceiptProjection = `r.document||jsonb_build_object('active_source',NOT EXISTS(SELECT 1 FROM telemetry_source_revocations v WHERE v.tenant_id=r.tenant_id AND v.revision_id=r.revision_id) AND EXISTS(SELECT 1 FROM telemetry_source_revisions s JOIN telemetry_connections c ON c.tenant_id=s.tenant_id AND c.id=s.connection_id AND c.version=s.connection_version WHERE s.tenant_id=r.tenant_id AND s.id=r.revision_id AND c.config->>'enabled'='true' AND NOT EXISTS(SELECT 1 FROM telemetry_connections n WHERE n.tenant_id=c.tenant_id AND n.id=c.id AND n.version>c.version)) AND EXISTS(SELECT 1 FROM entities e WHERE e.tenant_id=r.tenant_id AND e.kind='resources' AND e.id=r.document->'binding'->>'resource_id' AND r.document->'binding'=jsonb_build_object('tenant_id',r.tenant_id,'resource_id',e.id,'workload_id',e.document->>'workload_id','provider',e.document->>'provider','provider_resource_id',e.document->>'provider_resource_id','account_id',e.document->>'account_id','region',e.document->>'region')))`

func (t *Tx) TelemetryReceipt(ctx context.Context, id string) (model.Document, error) {
	return t.sourceOne(ctx, "SELECT "+telemetryReceiptProjection+" FROM telemetry_receipts r WHERE r.tenant_id=$1 AND r.id=$2", t.Tenant, id)
}
func (t *Tx) TelemetryReceiptByBatch(ctx context.Context, batchID string) (model.Document, error) {
	return t.sourceOne(ctx, "SELECT "+telemetryReceiptProjection+" FROM telemetry_receipts r WHERE r.tenant_id=$1 AND r.batch_id=$2", t.Tenant, batchID)
}
func (t *Tx) TelemetryReceipts(ctx context.Context, connection string) ([]model.Document, error) {
	return t.sourceRows(ctx, "SELECT "+telemetryReceiptProjection+" FROM telemetry_receipts r WHERE r.tenant_id=$1 AND ($2='' OR r.connection_id=$2) ORDER BY r.created_at,r.id", t.Tenant, connection)
}

func (t *Tx) TelemetryEvaluationCreate(ctx context.Context, d model.Document) (model.Document, error) {
	connection, hash := model.String(d, "connection_id"), model.String(d, "config_hash")
	if err := t.telemetryLock(ctx, connection); err != nil {
		return nil, err
	}
	c, err := t.telemetryActiveRevision(ctx, connection, hash)
	if err != nil {
		return nil, err
	}
	b, err := json.Marshal(d)
	if err != nil {
		return nil, err
	}
	return t.sourceOne(ctx, "INSERT INTO telemetry_evaluations(tenant_id,id,connection_id,revision_id,content_hash,metadata) VALUES($1,$2,$3,$4,$5,$6) RETURNING document", t.Tenant, model.ID(), connection, model.String(c, "revision_id"), telemetry.Hash(d), b)
}
func (t *Tx) TelemetryEvaluation(ctx context.Context, id string) (model.Document, error) {
	return t.sourceOne(ctx, "SELECT document FROM telemetry_evaluations WHERE tenant_id=$1 AND id=$2", t.Tenant, id)
}
func (t *Tx) TelemetryEvaluations(ctx context.Context, connection string) ([]model.Document, error) {
	return t.sourceRows(ctx, "SELECT document FROM telemetry_evaluations WHERE tenant_id=$1 AND ($2='' OR connection_id=$2) ORDER BY created_at,id", t.Tenant, connection)
}

const telemetrySyncProjection = `document||jsonb_build_object('status',status,'attempts',attempts,'lease_token',lease_token,'lease_until',lease_until,'next_attempt',next_attempt,'receipt_id',receipt_id,'receipt_ids',receipt_ids,'reason_code',reason_code,'updated_at',updated_at)`

func (t *Tx) TelemetrySyncRequest(ctx context.Context, connection, key string, d model.Document) (model.Document, bool, error) {
	if key == "" || len(key) > 200 {
		return nil, false, ErrTelemetryConflict
	}
	if err := t.telemetryLock(ctx, connection); err != nil {
		return nil, false, err
	}
	hash := telemetry.Hash(d)
	old, err := t.sourceOne(ctx, "SELECT "+telemetrySyncProjection+" FROM telemetry_sync_requests WHERE tenant_id=$1 AND connection_id=$2 AND idempotency_key=$3", t.Tenant, connection, key)
	if err == nil {
		if model.String(old, "request_hash") != hash {
			return nil, false, ErrTelemetryConflict
		}
		return old, true, nil
	}
	if err != pgx.ErrNoRows {
		return nil, false, err
	}
	c, err := t.TelemetryConnection(ctx, connection)
	if err != nil {
		return nil, false, err
	}
	b, err := json.Marshal(d)
	if err != nil {
		return nil, false, err
	}
	returnDoc, err := t.sourceOne(ctx, "INSERT INTO telemetry_sync_requests(tenant_id,id,connection_id,revision_id,idempotency_key,request_hash,metadata) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING "+telemetrySyncProjection, t.Tenant, model.ID(), connection, model.String(c, "revision_id"), key, hash, b)
	return returnDoc, false, err
}
func (t *Tx) TelemetrySyncGet(ctx context.Context, id string) (model.Document, error) {
	return t.sourceOne(ctx, "SELECT "+telemetrySyncProjection+" FROM telemetry_sync_requests WHERE tenant_id=$1 AND id=$2", t.Tenant, id)
}

const telemetrySyncEligible = `status NOT IN('COMPLETED','BLOCKED') AND next_attempt<=clock_timestamp() AND (status<>'RUNNING' OR lease_until<=clock_timestamp())`

func (t *Tx) TelemetryReaderPending(ctx context.Context, limit int) ([]model.Document, error) {
	if limit < 1 || limit > 100 {
		limit = 20
	}
	return t.sourceRows(ctx, "SELECT "+telemetrySyncProjection+" FROM telemetry_sync_requests WHERE tenant_id=$1 AND "+telemetrySyncEligible+" ORDER BY next_attempt,created_at,id LIMIT $2", t.Tenant, limit)
}
func (t *Tx) TelemetrySyncClaim(ctx context.Context, connection string, lease time.Duration) (model.Document, error) {
	if lease < time.Second || lease > 15*time.Minute {
		return nil, errors.New("TELEMETRY_LEASE_INVALID")
	}
	// Lock connection before queue rows, matching registration/publication order.
	// For a global poll, choose a connection without locking then recheck under lock.
	if connection == "" {
		var err error
		err = t.QueryRow(ctx, "SELECT connection_id FROM telemetry_sync_requests WHERE tenant_id=$1 AND "+telemetrySyncEligible+" ORDER BY next_attempt,created_at,id LIMIT 1", t.Tenant).Scan(&connection)
		if err != nil {
			return nil, err
		}
	}
	if err := t.telemetryLock(ctx, connection); err != nil {
		return nil, err
	}
	return t.sourceOne(ctx, `UPDATE telemetry_sync_requests SET status='RUNNING',attempts=attempts+1,lease_token=$3,lease_until=clock_timestamp()+$4*interval '1 second',receipt_id=NULL,receipt_ids='[]',reason_code=NULL WHERE tenant_id=$1 AND id=(SELECT id FROM telemetry_sync_requests WHERE tenant_id=$1 AND connection_id=$2 AND `+telemetrySyncEligible+` ORDER BY next_attempt,created_at,id FOR UPDATE SKIP LOCKED LIMIT 1) RETURNING `+telemetrySyncProjection, t.Tenant, connection, model.ID(), lease.Seconds())
}
func (t *Tx) TelemetrySyncFinish(ctx context.Context, id, leaseToken string, d model.Document) (model.Document, error) {
	status := model.String(d, "status")
	if status != "COMPLETED" && status != "RETRY" && status != "BLOCKED" {
		return nil, errors.New("TELEMETRY_FINISH_INVALID")
	}
	retry := model.Number(d, "retry_after_seconds")
	if status == "RETRY" && (retry < 1 || retry > 3600) {
		return nil, errors.New("TELEMETRY_RETRY_INVALID")
	}
	var receipt any
	ids := model.Strings(d, "receipt_ids")
	if s := model.String(d, "receipt_id"); s != "" {
		receipt = s
		if len(ids) == 0 {
			ids = []string{s}
		}
	}
	if ids == nil {
		ids = []string{}
	}
	if len(ids) > 400 {
		return nil, errors.New("TELEMETRY_RECEIPT_LIMIT")
	}
	job, err := t.TelemetrySyncGet(ctx, id)
	if err != nil {
		return nil, err
	}
	if err = t.telemetryLock(ctx, model.String(job, "connection_id")); err != nil {
		return nil, err
	}
	encoded, _ := json.Marshal(ids)
	out, err := t.sourceOne(ctx, `UPDATE telemetry_sync_requests SET status=$4,receipt_id=$5,reason_code=$6,next_attempt=clock_timestamp()+$7*interval '1 second',receipt_ids=$8 WHERE tenant_id=$1 AND id=$2 AND status='RUNNING' AND lease_token=$3 AND lease_until>clock_timestamp() RETURNING `+telemetrySyncProjection, t.Tenant, id, leaseToken, status, receipt, model.String(d, "reason_code"), retry, encoded)
	if err == pgx.ErrNoRows {
		return nil, ErrTelemetryConflict
	}
	return out, err
}
func (s *Store) TelemetryTenants(ctx context.Context) ([]string, error) {
	rows, err := s.Pool.Query(ctx, "SELECT tenant_id FROM tenant_registry ORDER BY tenant_id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var tenant string
		if err = rows.Scan(&tenant); err != nil {
			return nil, err
		}
		out = append(out, tenant)
	}
	return out, rows.Err()
}
