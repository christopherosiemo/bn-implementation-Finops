// Package native connects protocol parsers to durable native evidence storage.
// It has no signing, execution or financial-write capability.
package native

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/telemetry"
)

type Pipeline struct {
	Store      *store.Store
	Archive    func(context.Context, string, string, string, []byte) (model.Document, error)
	ReadObject func(context.Context, string, model.Document) ([]byte, error)
	WriteFacts func(context.Context, string, string, telemetry.Batch) (model.Document, error)
}

// Publish records intent first and publishes only after both storage systems
// acknowledged the exact raw/canonical evidence. Retrying resumes checkpoints.
func (p *Pipeline) Publish(ctx context.Context, c telemetry.Connection, b telemetry.Batch, key string, queryStart, queryEnd time.Time) (model.Document, bool, error) {
	if p.Store == nil || p.Archive == nil || p.WriteFacts == nil || telemetry.ValidateConnection(c) != nil || b.ConnectionID != c.ID || b.Binding != c.Binding || b.ConfigHash != telemetry.ConfigHash(c) || b.SourceKind != c.Kind || b.RawSHA256 != telemetry.BytesHash(b.Raw) || len(b.Raw) > 128<<20 || len(b.Samples) > telemetry.MaxSamples {
		return nil, false, errors.New("TELEMETRY_BATCH_BINDING_INVALID")
	}
	metadata := model.Document{"raw_sha256": b.RawSHA256, "canonical_hash": telemetry.CanonicalHash(b), "binding": b.Binding, "source_kind": b.SourceKind, "collected_at": b.CollectedAt, "start": b.Start, "end": b.End, "sample_count": len(b.Samples), "rejection_count": len(b.Rejections), "warning_count": len(b.Warnings)}
	if c.Kind == "PROMETHEUS" {
		metadata["query_start"], metadata["query_end"] = queryStart.UTC(), queryEnd.UTC()
	}
	var prepared model.Document
	var replay bool
	err := p.Store.Do(ctx, c.Binding.TenantID, func(tx *store.Tx) error {
		var e error
		prepared, replay, e = tx.TelemetryBatchPrepare(ctx, c.ID, b.ConfigHash, key, metadata)
		return e
	})
	if err != nil {
		return nil, false, err
	}
	batchID := model.String(prepared, "id")
	// A collection timestamp belongs to the first durable receipt attempt. It is
	// excluded from canonical identity and retained when transport retries later.
	if at, e := time.Parse(time.RFC3339Nano, model.String(prepared, "collected_at")); e == nil {
		b.CollectedAt = at
	}
	var checkpoints []model.Document
	if err = p.Store.Do(ctx, c.Binding.TenantID, func(tx *store.Tx) error {
		var e error
		checkpoints, e = tx.TelemetryCheckpoints(ctx, batchID)
		return e
	}); err != nil {
		return nil, false, err
	}
	seen := map[string]bool{}
	for _, d := range checkpoints {
		seen[model.String(d, "stage")] = true
	}
	if !seen["RAW_PERSISTED"] {
		ref, e := p.Archive(ctx, c.Binding.TenantID, "wire", batchID, b.Raw)
		if e != nil {
			return nil, false, e
		}
		if model.String(ref, "body_sha256") != b.RawSHA256 {
			return nil, false, errors.New("TELEMETRY_ARCHIVE_HASH_MISMATCH")
		}
		if e = p.Store.Do(ctx, c.Binding.TenantID, func(tx *store.Tx) error {
			_, _, e := tx.TelemetryCheckpointAppend(ctx, batchID, "RAW_PERSISTED", ref)
			return e
		}); e != nil {
			return nil, false, e
		}
	}
	if !seen["ANALYTICS_PERSISTED"] {
		raw, e := json.Marshal(b)
		if e != nil {
			return nil, false, e
		}
		ref, e := p.Archive(ctx, c.Binding.TenantID, "canonical", batchID, raw)
		if e != nil {
			return nil, false, e
		}
		facts, e := p.WriteFacts(ctx, c.Binding.TenantID, batchID, b)
		if e != nil {
			return nil, false, e
		}
		if model.String(facts, "canonical_hash") != telemetry.CanonicalHash(b) || model.Number(facts, "sample_count") != int64(len(b.Samples)) {
			return nil, false, errors.New("TELEMETRY_ANALYTICS_HASH_MISMATCH")
		}
		facts["canonical_bucket"], facts["canonical_key"], facts["canonical_version_id"], facts["canonical_body_sha256"] = ref["bucket"], ref["key"], ref["version_id"], ref["body_sha256"]
		if e = p.Store.Do(ctx, c.Binding.TenantID, func(tx *store.Tx) error {
			_, _, e := tx.TelemetryCheckpointAppend(ctx, batchID, "ANALYTICS_PERSISTED", facts)
			return e
		}); e != nil {
			return nil, false, e
		}
	}
	var receipt model.Document
	err = p.Store.Do(ctx, c.Binding.TenantID, func(tx *store.Tx) error { var e error; receipt, _, e = tx.TelemetryPublish(ctx, batchID); return e })
	return receipt, replay, err
}
func (p *Pipeline) ReadBatch(ctx context.Context, tenant string, receipt model.Document) (telemetry.Batch, error) {
	var b telemetry.Batch
	if p.ReadObject == nil || !model.Bool(receipt, "active_source") {
		return b, errors.New("TELEMETRY_SOURCE_INACTIVE")
	}
	var checkpoints []model.Document
	err := p.Store.Do(ctx, tenant, func(tx *store.Tx) error {
		var e error
		checkpoints, e = tx.TelemetryCheckpoints(ctx, model.String(receipt, "batch_id"))
		return e
	})
	if err != nil {
		return b, err
	}
	var ref model.Document
	for _, d := range checkpoints {
		if model.String(d, "stage") == "ANALYTICS_PERSISTED" {
			ref = model.Document{"bucket": d["canonical_bucket"], "key": d["canonical_key"], "version_id": d["canonical_version_id"], "body_sha256": d["canonical_body_sha256"]}
		}
	}
	if ref == nil {
		return b, errors.New("TELEMETRY_CANONICAL_EVIDENCE_MISSING")
	}
	raw, err := p.ReadObject(ctx, tenant, ref)
	if err != nil {
		return b, err
	}
	if json.Unmarshal(raw, &b) != nil || b.Binding.TenantID != tenant || b.ConnectionID != model.String(receipt, "connection_id") || b.ConfigHash != model.String(receipt, "config_hash") || b.RawSHA256 != model.String(receipt, "raw_sha256") || telemetry.CanonicalHash(b) != model.String(receipt, "canonical_hash") {
		return b, errors.New("TELEMETRY_CANONICAL_EVIDENCE_CHANGED")
	}
	return b, nil
}
