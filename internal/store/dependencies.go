package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/jackc/pgx/v5"
)

func dependencyContentHash(version int64, edges []model.Document) string {
	b, _ := json.Marshal(model.Document{"version": version, "edges": edges})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func (t *Tx) DependencyGraph(ctx context.Context) (model.Document, error) {
	d, e := t.sourceOne(ctx, "SELECT document||jsonb_build_object('writer_role',writer_role,'created_at',created_at) FROM dependency_graph_revisions WHERE tenant_id=$1 ORDER BY version DESC LIMIT 1", t.Tenant)
	if e == pgx.ErrNoRows {
		return model.Document{"id": "dependency-graph-empty", "tenant_id": t.Tenant, "version": int64(0), "edges": []model.Document{}, "hash": dependencyContentHash(0, []model.Document{})}, nil
	}
	return d, e
}

func (t *Tx) DependencyGraphAppend(ctx context.Context, version int64, d model.Document) (model.Document, error) {
	if version < 0 || version == math.MaxInt64 {
		return nil, ErrConflict
	}
	if _, e := t.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", t.Tenant+":dependency-graph"); e != nil {
		return nil, e
	}
	current, e := t.DependencyGraph(ctx)
	if e != nil {
		return nil, e
	}
	if model.Number(current, "version") != version {
		return nil, ErrConflict
	}
	raw, ok := d["edges"]
	if !ok || raw == nil {
		return nil, errors.New("DEPENDENCY_EDGES_REQUIRED")
	}
	b, e := json.Marshal(raw)
	if e != nil {
		return nil, e
	}
	edges := []model.Document{}
	if e = json.Unmarshal(b, &edges); e != nil || edges == nil {
		return nil, errors.New("DEPENDENCY_EDGES_INVALID")
	}
	d = model.Clone(d)
	d["id"], d["tenant_id"], d["version"], d["edges"] = model.ID(), t.Tenant, version+1, edges
	content := dependencyContentHash(version+1, edges)
	d["content_hash"], d["hash"] = content, content
	b, e = json.Marshal(d)
	if e != nil {
		return nil, e
	}
	var returned []byte
	e = t.QueryRow(ctx, "INSERT INTO dependency_graph_revisions(tenant_id,id,version,content_hash,document) VALUES($1,$2,$3,$4,$5) RETURNING document", t.Tenant, d["id"], version+1, content, b).Scan(&returned)
	if e != nil {
		return nil, e
	}
	e = json.Unmarshal(returned, &d)
	return d, e
}

func (t *Tx) DependencyReviewCreate(ctx context.Context, d model.Document) (model.Document, error) {
	if _, e := t.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", t.Tenant+":dependency-graph"); e != nil {
		return nil, e
	}
	graph, e := t.DependencyGraph(ctx)
	if e != nil {
		return nil, e
	}
	version := model.Number(d, "graph_version")
	if version <= 0 || version != model.Number(graph, "version") {
		return nil, ErrConflict
	}
	resource := model.String(d, "resource_id")
	if resource == "" || model.String(d, "reviewed_by") == "" {
		return nil, errors.New("DEPENDENCY_REVIEW_BINDING_REQUIRED")
	}
	if _, e = t.Get(ctx, "resources", resource); e != nil {
		return nil, e
	}
	expires, e := time.Parse(time.RFC3339Nano, model.String(d, "expires_at"))
	if e != nil {
		return nil, errors.New("DEPENDENCY_REVIEW_EXPIRY_REQUIRED")
	}
	d = model.Clone(d)
	d["id"], d["tenant_id"] = model.ID(), t.Tenant
	b, e := json.Marshal(d)
	if e != nil {
		return nil, e
	}
	var returned []byte
	e = t.QueryRow(ctx, "INSERT INTO dependency_reviews(tenant_id,id,resource_id,graph_version,graph_hash,inventory_hash,reviewed_by,expires_at,document) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING document", t.Tenant, d["id"], resource, version, model.String(d, "graph_hash"), model.String(d, "inventory_hash"), model.String(d, "reviewed_by"), expires, b).Scan(&returned)
	if e != nil {
		return nil, e
	}
	e = json.Unmarshal(returned, &d)
	return d, e
}
func (t *Tx) DependencyReviewLatest(ctx context.Context, resource string) (model.Document, error) {
	return t.sourceOne(ctx, "SELECT document||jsonb_build_object('writer_role',writer_role,'created_at',created_at) FROM dependency_reviews WHERE tenant_id=$1 AND resource_id=$2 ORDER BY created_at DESC,id DESC LIMIT 1", t.Tenant, resource)
}
func (t *Tx) DependencyReviewGet(ctx context.Context, id string) (model.Document, error) {
	return t.sourceOne(ctx, "SELECT document||jsonb_build_object('writer_role',writer_role,'created_at',created_at) FROM dependency_reviews WHERE tenant_id=$1 AND id=$2", t.Tenant, id)
}
func (t *Tx) DependencyReviewList(ctx context.Context, resource string) ([]model.Document, error) {
	return t.sourceRows(ctx, "SELECT document||jsonb_build_object('writer_role',writer_role,'created_at',created_at) FROM dependency_reviews WHERE tenant_id=$1 AND ($2='' OR resource_id=$2) ORDER BY created_at,id", t.Tenant, resource)
}
