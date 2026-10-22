package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
)

var ErrHardwareIdentitySource = errors.New("HARDWARE_IDENTITY_SOURCE_UNAVAILABLE")

// HardwareIdentitySourceLock serializes native sync, mapping and revocation.
// Busy synchronization is a usable-transaction error; direct SQL repeats it.
func (t *Tx) HardwareIdentitySourceLock(ctx context.Context, source string) error {
	if _, err := t.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", t.Tenant+":dependency-graph"); err != nil {
		return err
	}
	var ok bool
	if err := t.QueryRow(ctx, "SELECT pg_try_advisory_xact_lock_shared(hashtextextended($1,0))", t.Tenant+":trusted-source:"+source).Scan(&ok); err != nil {
		return err
	}
	if !ok {
		return ErrHardwareIdentitySource
	}
	if err := t.QueryRow(ctx, "SELECT public.hardware_identity_source_lock($1,$2)", t.Tenant, source).Scan(&ok); err != nil {
		return err
	}
	if !ok {
		return ErrHardwareIdentitySource
	}
	return nil
}

func (t *Tx) HardwareIdentityGet(ctx context.Context, id string) (model.Document, error) {
	return t.sourceOne(ctx, `SELECT document||jsonb_build_object('id',id,'hash',content_hash,'created_at',created_at,'writer_role',writer_role) FROM public.hardware_identity_derivations WHERE tenant_id=$1 AND id=$2`, t.Tenant, id)
}
func (t *Tx) HardwareIdentityByParent(ctx context.Context, parent, decoder string) (model.Document, error) {
	return t.sourceOne(ctx, `SELECT document||jsonb_build_object('id',id,'hash',content_hash,'created_at',created_at,'writer_role',writer_role) FROM public.hardware_identity_derivations WHERE tenant_id=$1 AND parent_receipt_id=$2 AND decoder_version=$3`, t.Tenant, parent, decoder)
}

// HardwareIdentityAppend accepts a private trusted-decoder payload, never an
// operator upload. Its trigger validates exact issued parent closure and cannot
// attest XML semantics omitted by the v1 typed hardware representation.
func (t *Tx) HardwareIdentityAppend(ctx context.Context, d model.Document) (model.Document, bool, error) {
	if model.String(d, "tenant_id") != t.Tenant {
		return nil, false, ErrHardwareIdentitySource
	}
	if err := t.HardwareIdentitySourceLock(ctx, model.String(d, "source_id")); err != nil {
		return nil, false, err
	}
	raw, err := json.Marshal(d)
	if err != nil {
		return nil, false, err
	}
	if len(raw) > 16384 {
		return nil, false, errors.New("HARDWARE_IDENTITY_METADATA_LIMIT")
	}
	sum := sha256.Sum256(raw)
	hash := hex.EncodeToString(sum[:])
	id := "hardware-identity-v2-" + hash
	// BEFORE INSERT guards also run on a replay conflict. Do not short-circuit
	// around current source/mapping closure merely because a row exists.
	r, err := t.Exec(ctx, `INSERT INTO public.hardware_identity_derivations(tenant_id,id,source_id,parent_receipt_id,parent_revision_id,resource_id,workload_id,decoder_version,content_hash,document,raw_document) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) ON CONFLICT(tenant_id,parent_receipt_id,decoder_version) DO NOTHING`, t.Tenant, id, d["source_id"], d["parent_receipt_id"], d["parent_revision_id"], model.String(mapDocument(d["binding"]), "resource_id"), model.String(mapDocument(d["binding"]), "workload_id"), d["decoder_version"], hash, raw, raw)
	if err != nil {
		return nil, false, err
	}
	out, err := t.HardwareIdentityByParent(ctx, model.String(d, "parent_receipt_id"), model.String(d, "decoder_version"))
	if err == nil && model.String(out, "hash") != hash {
		return nil, false, ErrConflict
	}
	return out, r.RowsAffected() == 1, err
}

func mapDocument(v any) model.Document {
	if d, ok := v.(model.Document); ok {
		return d
	}
	if d, ok := v.(map[string]any); ok {
		return model.Document(d)
	}
	return nil
}
