package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrConflict = errors.New("stale resource version")

type Store struct{ Pool *pgxpool.Pool }
type Tx struct {
	pgx.Tx
	Tenant string
}

func Open(ctx context.Context, url string) (*Store, error) {
	p, e := pgxpool.New(ctx, url)
	if e != nil {
		return nil, e
	}
	if e = p.Ping(ctx); e != nil {
		p.Close()
		return nil, e
	}
	return &Store{p}, nil
}
func (s *Store) Begin(ctx context.Context, tenant string) (*Tx, error) {
	if tenant == "" {
		return nil, errors.New("tenant required")
	}
	t, e := s.Pool.Begin(ctx)
	if e != nil {
		return nil, e
	}
	if _, e = t.Exec(ctx, "SELECT set_config('app.tenant_id',$1,true)", tenant); e != nil {
		_ = t.Rollback(ctx)
		return nil, e
	}
	return &Tx{t, tenant}, nil
}
func (s *Store) Do(ctx context.Context, tenant string, f func(*Tx) error) error {
	t, e := s.Begin(ctx, tenant)
	if e != nil {
		return e
	}
	defer func() { _ = t.Rollback(ctx) }()
	if e = f(t); e != nil {
		return e
	}
	return t.Commit(ctx)
}
func (t *Tx) Get(ctx context.Context, kind, id string) (model.Document, error) {
	var b []byte
	var v int64
	e := t.QueryRow(ctx, "SELECT document,version FROM entities WHERE tenant_id=$1 AND kind=$2 AND id=$3", t.Tenant, kind, id).Scan(&b, &v)
	if e != nil {
		return nil, e
	}
	var d model.Document
	e = json.Unmarshal(b, &d)
	d["id"] = id
	d["version"] = v
	return d, e
}
func (t *Tx) List(ctx context.Context, kind string) ([]model.Document, error) {
	r, e := t.Query(ctx, "SELECT id,document,version FROM entities WHERE tenant_id=$1 AND kind=$2 ORDER BY created_at,id", t.Tenant, kind)
	if e != nil {
		return nil, e
	}
	defer r.Close()
	out := []model.Document{}
	for r.Next() {
		var id string
		var b []byte
		var v int64
		if e = r.Scan(&id, &b, &v); e != nil {
			return nil, e
		}
		var d model.Document
		if e = json.Unmarshal(b, &d); e != nil {
			return nil, e
		}
		d["id"], d["version"] = id, v
		out = append(out, d)
	}
	return out, r.Err()
}
func (t *Tx) Create(ctx context.Context, kind string, d model.Document) (model.Document, error) {
	id := model.String(d, "id")
	if id == "" {
		id = model.ID()
	}
	d = model.Clone(d)
	d["id"], d["version"], d["tenant_id"] = id, 1, t.Tenant
	b, e := json.Marshal(d)
	if e != nil {
		return nil, e
	}
	_, e = t.Exec(ctx, "INSERT INTO entities(tenant_id,kind,id,document) VALUES($1,$2,$3,$4)", t.Tenant, kind, id, b)
	return d, e
}
func (t *Tx) Update(ctx context.Context, kind, id string, version int64, d model.Document) (model.Document, error) {
	d = model.Clone(d)
	d["id"], d["version"], d["tenant_id"] = id, version+1, t.Tenant
	b, e := json.Marshal(d)
	if e != nil {
		return nil, e
	}
	r, e := t.Exec(ctx, "UPDATE entities SET version=version+1,document=$4,updated_at=now() WHERE tenant_id=$1 AND kind=$2 AND id=$3 AND version=$5", t.Tenant, kind, id, b, version)
	if e == nil && r.RowsAffected() != 1 {
		return nil, ErrConflict
	}
	return d, e
}
func (t *Tx) Audit(ctx context.Context, actor, action, resource string, data model.Document) error {
	id := model.ID()
	d := model.Document{"id": id, "actor": actor, "action": action, "resource": resource, "timestamp": model.Now(), "details": data}
	b, _ := json.Marshal(d)
	_, e := t.Exec(ctx, "INSERT INTO audit_events(tenant_id,id,actor,action,resource,document) VALUES($1,$2,$3,$4,$5,$6)", t.Tenant, id, actor, action, resource, b)
	return e
}
func (t *Tx) Event(ctx context.Context, event string, d model.Document) error {
	b, _ := json.Marshal(d)
	_, e := t.Exec(ctx, "INSERT INTO outbox(tenant_id,id,event_type,payload) VALUES($1,$2,$3,$4)", t.Tenant, model.ID(), event, b)
	return e
}
func (t *Tx) Evidence(ctx context.Context, table string) ([]model.Document, error) {
	if table != "audit_events" && table != "savings_ledger" {
		return nil, errors.New("invalid evidence table")
	}
	query := "SELECT document,true FROM " + table + " WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT 200"
	if table == "savings_ledger" {
		query = "SELECT l.document,NOT EXISTS(SELECT 1 FROM savings_ledger newer WHERE newer.tenant_id=l.tenant_id AND newer.document->>'supersedes_id'=l.id) FROM savings_ledger l WHERE l.tenant_id=$1 ORDER BY l.created_at DESC LIMIT 200"
	}
	rows, e := t.Query(ctx, query, t.Tenant)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	r := []model.Document{}
	for rows.Next() {
		var b []byte
		var current bool
		if e = rows.Scan(&b, &current); e != nil {
			return nil, e
		}
		var d model.Document
		if e = json.Unmarshal(b, &d); e != nil {
			return nil, e
		}
		if table == "savings_ledger" {
			d["is_current"] = current
		}
		r = append(r, d)
	}
	return r, rows.Err()
}
func (s *Store) Migrate(ctx context.Context, dir string) error {
	files, e := filepath.Glob(filepath.Join(dir, "*.sql"))
	if e != nil {
		return e
	}
	if len(files) == 0 {
		return errors.New("no migrations found")
	}
	tx, e := s.Pool.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	// One transaction and one connection serialize schema changes across deploys
	// and independent package integration tests; no partially applied role boundary
	// can become visible between migration files.
	if _, e = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended('finops:schema-migrations',0))"); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, "CREATE TABLE IF NOT EXISTS schema_migrations(filename text PRIMARY KEY,sha256 text NOT NULL,applied_at timestamptz NOT NULL DEFAULT now())"); e != nil {
		return e
	}
	sort.Strings(files)
	for _, p := range files {
		b, e := os.ReadFile(p)
		if e != nil {
			return e
		}
		name := filepath.Base(p)
		sum := sha256.Sum256(b)
		checksum := hex.EncodeToString(sum[:])
		var applied string
		e = tx.QueryRow(ctx, "SELECT sha256 FROM schema_migrations WHERE filename=$1", name).Scan(&applied)
		if e == nil {
			if applied != checksum {
				return fmt.Errorf("migration %s checksum differs from the applied migration; add a new migration instead of editing history", name)
			}
			continue
		}
		if e != pgx.ErrNoRows {
			return e
		}
		if _, e = tx.Exec(ctx, string(b)); e != nil {
			return fmt.Errorf("migration %s: %w", p, e)
		}
		if _, e = tx.Exec(ctx, "INSERT INTO schema_migrations(filename,sha256) VALUES($1,$2)", name, checksum); e != nil {
			return e
		}
	}
	for _, role := range []string{"api", "worker", "signer", "executor", "ingester"} {
		if p := os.Getenv("DB_" + strings.ToUpper(role) + "_PASSWORD"); p != "" {
			sql := "ALTER ROLE " + pgx.Identifier{"finops_" + role}.Sanitize() + " LOGIN PASSWORD '" + strings.ReplaceAll(p, "'", "''") + "'"
			if _, e = tx.Exec(ctx, sql); e != nil {
				return e
			}
		}
	}
	return tx.Commit(ctx)
}
