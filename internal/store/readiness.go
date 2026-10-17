package store

import (
	"context"
	"encoding/json"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
)

func (t *Tx) EvidenceCreate(ctx context.Context, kind string, d model.Document) (model.Document, error) {
	d = model.Clone(d)
	if model.String(d, "id") == "" {
		d["id"] = model.ID()
	}
	d["tenant_id"] = t.Tenant
	d["created_at"] = model.Now()
	b, e := json.Marshal(d)
	if e != nil {
		return nil, e
	}
	_, e = t.Exec(ctx, "INSERT INTO readiness_evidence(tenant_id,kind,id,resource_id,document) VALUES($1,$2,$3,$4,$5)", t.Tenant, kind, d["id"], d["resource_id"], b)
	return d, e
}
func (t *Tx) EvidenceGet(ctx context.Context, kind, id string) (model.Document, error) {
	var b []byte
	e := t.QueryRow(ctx, "SELECT document FROM readiness_evidence WHERE tenant_id=$1 AND kind=$2 AND id=$3", t.Tenant, kind, id).Scan(&b)
	if e != nil {
		return nil, e
	}
	var d model.Document
	e = json.Unmarshal(b, &d)
	return d, e
}
func (t *Tx) EvidenceList(ctx context.Context, kind, resource string) ([]model.Document, error) {
	rows, e := t.Query(ctx, "SELECT document FROM readiness_evidence WHERE tenant_id=$1 AND kind=$2 AND ($3='' OR resource_id=$3) ORDER BY created_at,id", t.Tenant, kind, resource)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []model.Document{}
	for rows.Next() {
		var b []byte
		var d model.Document
		if e = rows.Scan(&b); e != nil {
			return nil, e
		}
		if e = json.Unmarshal(b, &d); e != nil {
			return nil, e
		}
		out = append(out, d)
	}
	return out, rows.Err()
}
