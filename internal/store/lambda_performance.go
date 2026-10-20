package store

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/evidence"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/jackc/pgx/v5"
)

// Returns only the newest point per registered producer, comparable cohort and
// candidate configuration. Revocation and registration revisions remove authority
// from current evaluation, without modifying any historical receipt.
func (t *Tx) LambdaPerformanceForResource(ctx context.Context, resource, qualifier string) (model.Document, error) {
	rows, e := t.sourceRows(ctx, `SELECT document FROM (
 SELECT DISTINCT ON(p.source_id,p.document->'point'->>'memory_size_mb',p.document->'point'->>'architecture',p.document->'point'->>'comparison_fingerprint') p.document,p.source_id,p.sequence
 FROM lambda_performance_receipts p JOIN source_registrations s ON s.tenant_id=p.tenant_id AND s.id=p.source_id
 WHERE p.tenant_id=$1 AND p.resource_id=$2 AND p.qualifier=$3 AND s.version=p.source_version AND s.document->'enabled'='true'::jsonb
 ORDER BY p.source_id,p.document->'point'->>'memory_size_mb',p.document->'point'->>'architecture',p.document->'point'->>'comparison_fingerprint',p.sequence DESC
 ) q ORDER BY source_id,sequence LIMIT 129`, t.Tenant, resource, qualifier)
	if e != nil {
		return nil, e
	}
	if len(rows) > 128 {
		return nil, errors.New("LAMBDA_PERFORMANCE_POINT_BOUND_EXCEEDED")
	}
	out := []model.Document{}
	for _, d := range rows {
		p := model.Clone(evidence.Object(d["point"]))
		p["id"], p["version"], p["sha256"], p["received_at"] = d["id"], "1", d["body_hash"], d["received_at"]
		p["source_ref"] = model.Document{"kind": "AWS_LAMBDA_PERFORMANCE_RECEIPT_V1", "id": d["id"], "version": "1", "sha256": d["body_hash"]}
		p["provenance"] = "REGISTERED_MACHINE_BENCHMARK"
		out = append(out, p)
	}
	return model.Document{"receipts": out}, nil
}
func (t *Tx) LambdaPerformanceReplay(ctx context.Context, source, key, seq, hash string) (model.Document, bool, error) {
	d, e := t.sourceOne(ctx, "SELECT document FROM lambda_performance_receipts WHERE tenant_id=$1 AND source_id=$2 AND (idempotency_key=$3 OR sequence=$4::bigint)", t.Tenant, source, key, seq)
	if errors.Is(e, pgx.ErrNoRows) {
		return nil, false, nil
	}
	if e != nil {
		return nil, false, e
	}
	if model.String(d, "body_hash") != hash || model.String(d, "idempotency_key") != key || model.String(d, "sequence") != seq {
		return nil, false, ErrConflict
	}
	return d, true, nil
}
func (t *Tx) LambdaPerformanceAppend(ctx context.Context, d model.Document) (model.Document, error) {
	if _, e := t.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", t.Tenant+":lambda-performance:"+model.String(d, "source_id")); e != nil {
		return nil, e
	}
	if old, ok, e := t.LambdaPerformanceReplay(ctx, model.String(d, "source_id"), model.String(d, "idempotency_key"), model.String(d, "sequence"), model.String(d, "body_hash")); e != nil || ok {
		return old, e
	}
	var stale bool
	if e := t.QueryRow(ctx, "SELECT EXISTS(SELECT FROM lambda_performance_receipts WHERE tenant_id=$1 AND source_id=$2 AND sequence >= $3::bigint)", t.Tenant, d["source_id"], d["sequence"]).Scan(&stale); e != nil {
		return nil, e
	}
	if stale {
		return nil, ErrConflict
	}
	raw, e := json.Marshal(d)
	if e != nil {
		return nil, e
	}
	return t.sourceOne(ctx, "INSERT INTO lambda_performance_receipts(tenant_id,id,source_id,source_version,resource_id,qualifier,sequence,body_hash,idempotency_key,document) VALUES($1,$2,$3,$4,$5,$6,$7::bigint,$8,$9,$10) RETURNING document", t.Tenant, d["id"], d["source_id"], d["source_version"], d["resource_id"], d["qualifier"], d["sequence"], d["body_hash"], d["idempotency_key"], raw)
}

func (t *Tx) LambdaPerformanceSource(ctx context.Context, id string) (model.Document, error) {
	d, e := t.sourceOne(ctx, "SELECT lambda_performance_source($1)", id)
	if e == nil && d == nil {
		return nil, pgx.ErrNoRows
	}
	return d, e
}
func (t *Tx) LambdaPerformanceResource(ctx context.Context, id string) (model.Document, error) {
	d, e := t.sourceOne(ctx, "SELECT lambda_performance_resource($1)", id)
	if e == nil && d == nil {
		return nil, pgx.ErrNoRows
	}
	return d, e
}
