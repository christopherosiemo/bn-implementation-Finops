package fleetbilling

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
)

func insert(ctx context.Context, tx *store.Tx, e Evidence) error {
	if e.Binding.TenantID != tx.Tenant || e.Status != "READY" || e.ExecutionAuthorized || e.HardSpendCap || e.VerifiedSaving != nil {
		return errors.New("PRICE_RECEIPT_CANNOT_GRANT_AUTHORITY")
	}
	raw, err := json.Marshal(e)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO fleet_billing_price_evidence(tenant_id,id,source_id,membership_receipt_id,templates_receipt_id,commitment_receipt_id,content_hash,document) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(tenant_id,id) DO NOTHING`, tx.Tenant, e.ID, e.SourceConnectionID, e.MembershipReceiptID, e.LaunchTemplatesReceiptID, e.CommitmentReceiptID, Hash(e), raw)
	return err
}

// Get returns immutable metadata under tenant RLS. It does not validate current
// source/commitment authority; callers must use Revalidate before forward use.
func Get(ctx context.Context, tx *store.Tx, id string) (Evidence, error) {
	var raw []byte
	err := tx.QueryRow(ctx, `SELECT document FROM fleet_billing_price_evidence WHERE tenant_id=$1 AND id=$2`, tx.Tenant, id).Scan(&raw)
	if err != nil {
		return Evidence{}, err
	}
	var e Evidence
	err = json.Unmarshal(raw, &e)
	return e, err
}
func List(ctx context.Context, tx *store.Tx, resource string) ([]model.Document, error) {
	r, err := tx.Query(ctx, `SELECT document||jsonb_build_object('writer_role',writer_role,'created_at',created_at,'hash',content_hash) FROM fleet_billing_price_evidence WHERE tenant_id=$1 AND ($2='' OR document->'binding'->>'resource_id'=$2) ORDER BY created_at,id`, tx.Tenant, resource)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	out := []model.Document{}
	for r.Next() {
		var raw []byte
		if err = r.Scan(&raw); err != nil {
			return nil, err
		}
		var d model.Document
		if err = json.Unmarshal(raw, &d); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, r.Err()
}
