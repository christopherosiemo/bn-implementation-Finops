package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/slo"
	"github.com/jackc/pgx/v5"
	"math"
	"time"
)

var ErrSLOSource = errors.New("SLO_SOURCE_INVALID")
var ErrSLOConflict = errors.New("SLO_REPLAY_CONFLICT")
var ErrSLOOrder = errors.New("SLO_INTERVAL_ORDER_INVALID")

type SLOSubmission struct {
	Interval                        slo.Interval
	RawBody                         []byte
	Issuer, Subject, IdempotencyKey string
}

func (t *Tx) SLOObjectiveAppend(ctx context.Context, workload string, version int64, d model.Document) (model.Document, error) {
	if version < 0 || version == math.MaxInt64 {
		return nil, ErrConflict
	}
	if _, e := t.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", t.Tenant+":dependency-graph"); e != nil {
		return nil, e
	}
	old, e := t.SLOObjectiveLatest(ctx, workload)
	if e != nil && e != pgx.ErrNoRows {
		return nil, e
	}
	if old == nil {
		old = model.Document{"version": 0}
	}
	if model.Number(old, "version") != version {
		return nil, ErrConflict
	}
	if _, e = t.Get(ctx, "workloads", workload); e != nil {
		return nil, e
	}
	d = model.Clone(d)
	d["workload_id"], d["id"], d["version"] = workload, model.ID(), version+1
	o, e := slo.ParseObjective(d)
	if e != nil {
		return nil, e
	}
	d = slo.Document(o)
	d["hash"] = slo.ObjectiveHash(o)
	b, _ := json.Marshal(d)
	return t.sourceOne(ctx, "INSERT INTO slo_objectives(tenant_id,id,workload_id,version,content_hash,document) VALUES($1,$2,$3,$4,$5,$6) RETURNING document", t.Tenant, o.ID, workload, o.Version, d["hash"], b)
}
func (t *Tx) SLOObjectiveLatest(ctx context.Context, workload string) (model.Document, error) {
	return t.sourceOne(ctx, "SELECT document FROM slo_objectives WHERE tenant_id=$1 AND workload_id=$2 ORDER BY version DESC LIMIT 1", t.Tenant, workload)
}
func (t *Tx) SLOObjectiveGet(ctx context.Context, id string) (model.Document, error) {
	return t.sourceOne(ctx, "SELECT document FROM slo_objectives WHERE tenant_id=$1 AND id=$2", t.Tenant, id)
}
func (t *Tx) SLOObjectives(ctx context.Context) ([]model.Document, error) {
	return t.sourceRows(ctx, "SELECT document FROM slo_objectives WHERE tenant_id=$1 ORDER BY created_at,id", t.Tenant)
}
func (t *Tx) SLORegister(ctx context.Context, s slo.Source) (slo.Source, error) {
	s.TenantID = t.Tenant
	if s.ID == "" {
		s.ID = model.ID()
	}
	if s.SchemaVersion != "1" || s.ObjectiveID == "" || s.ResourceID == "" || s.WorkloadID == "" || s.ProviderResourceID == "" || len(s.AccountID) != 12 || s.Region != "eu-west-1" || s.Issuer == "" || s.Subject == "" {
		return s, ErrSLOSource
	}
	for _, c := range s.AccountID {
		if c < '0' || c > '9' {
			return s, ErrSLOSource
		}
	}
	b, _ := json.Marshal(s)
	_, e := t.Exec(ctx, "INSERT INTO slo_sources(tenant_id,id,objective_id,resource_id,workload_id,document) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(tenant_id,id) DO NOTHING", t.Tenant, s.ID, s.ObjectiveID, s.ResourceID, s.WorkloadID, b)
	if e != nil {
		return s, e
	}
	old, e := t.SLOSource(ctx, s.ID)
	if e == nil && old != s {
		return s, ErrSLOConflict
	}
	return old, e
}
func (t *Tx) SLOSource(ctx context.Context, id string) (slo.Source, error) {
	var s slo.Source
	d, e := t.sourceOne(ctx, "SELECT document FROM slo_sources WHERE tenant_id=$1 AND id=$2", t.Tenant, id)
	if e == nil {
		b, _ := json.Marshal(d)
		e = json.Unmarshal(b, &s)
	}
	return s, e
}
func (t *Tx) SLOSources(ctx context.Context) ([]slo.Source, error) {
	ds, e := t.sourceRows(ctx, "SELECT document FROM slo_sources WHERE tenant_id=$1 ORDER BY created_at,id", t.Tenant)
	out := []slo.Source{}
	for _, d := range ds {
		var s slo.Source
		b, _ := json.Marshal(d)
		if e = json.Unmarshal(b, &s); e != nil {
			return nil, e
		}
		out = append(out, s)
	}
	return out, e
}
func (t *Tx) SLOAppend(ctx context.Context, in SLOSubmission) (slo.Receipt, bool, error) {
	var r slo.Receipt
	i, e := slo.DecodeInterval(in.RawBody)
	if e != nil || slo.Hash(i) != slo.Hash(in.Interval) {
		return r, false, ErrSLOSource
	}
	if in.IdempotencyKey == "" || len(in.IdempotencyKey) > 200 {
		return r, false, ErrSLOConflict
	}
	if _, e = t.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", t.Tenant+":slo:"+i.SourceID); e != nil {
		return r, false, e
	}
	s, e := t.SLOSource(ctx, i.SourceID)
	if e != nil {
		return r, false, e
	}
	if !s.Enabled || s.Issuer != in.Issuer || s.Subject != in.Subject || s.ObjectiveID != i.ObjectiveID || s.ResourceID != i.ResourceID || s.WorkloadID != i.WorkloadID {
		return r, false, ErrSLOSource
	}
	sum := sha256.Sum256(in.RawBody)
	digest := hex.EncodeToString(sum[:])
	d, e := t.sourceOne(ctx, "SELECT document FROM slo_receipts WHERE tenant_id=$1 AND source_id=$2 AND (sequence=$3 OR interval_start=$4 OR idempotency_key=$5) ORDER BY sequence DESC LIMIT 1", t.Tenant, i.SourceID, i.Sequence, i.IntervalStart, in.IdempotencyKey)
	if e == nil {
		b, _ := json.Marshal(d)
		_ = json.Unmarshal(b, &r)
		if r.BodySHA256 != digest || r.Sequence != i.Sequence || r.IdempotencyKey != in.IdempotencyKey {
			return r, false, ErrSLOConflict
		}
		return r, true, nil
	}
	if e != pgx.ErrNoRows {
		return r, false, e
	}
	var now time.Time
	if e = t.QueryRow(ctx, "SELECT slo_receive_time()").Scan(&now); e != nil {
		return r, false, e
	}
	if i.IntervalEnd.After(now.Add(5*time.Second)) || now.Sub(i.IntervalEnd) > 2*time.Minute {
		return r, false, ErrSLOOrder
	}
	var seq int64
	var end time.Time
	e = t.QueryRow(ctx, "SELECT sequence,interval_end FROM slo_receipts WHERE tenant_id=$1 AND source_id=$2 ORDER BY sequence DESC LIMIT 1", t.Tenant, s.ID).Scan(&seq, &end)
	if e != nil && e != pgx.ErrNoRows {
		return r, false, e
	}
	if e == nil && (i.Sequence <= seq || i.IntervalStart.Before(end)) {
		return r, false, ErrSLOOrder
	}
	r = slo.Receipt{Interval: i, ID: model.ID(), TenantID: t.Tenant, Subject: in.Subject, ReceivedAt: now, BodySHA256: digest, IdempotencyKey: in.IdempotencyKey, WriterRole: "finops_activity", Binding: s.Binding()}
	b, _ := json.Marshal(r)
	d, e = t.sourceOne(ctx, "INSERT INTO slo_receipts(tenant_id,id,source_id,objective_id,resource_id,sequence,interval_start,interval_end,received_at,body_sha256,idempotency_key,raw_body,document) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) RETURNING document", t.Tenant, r.ID, s.ID, i.ObjectiveID, i.ResourceID, i.Sequence, i.IntervalStart, i.IntervalEnd, now, digest, in.IdempotencyKey, in.RawBody, b)
	if e == nil {
		b, _ = json.Marshal(d)
		e = json.Unmarshal(b, &r)
	}
	return r, false, e
}
func (t *Tx) SLOLatest(ctx context.Context, resource, objective string) (slo.Receipt, error) {
	var r slo.Receipt
	d, e := t.sourceOne(ctx, "SELECT r.document FROM slo_receipts r JOIN slo_sources s ON s.tenant_id=r.tenant_id AND s.id=r.source_id WHERE r.tenant_id=$1 AND r.resource_id=$2 AND r.objective_id=$3 AND s.document->>'enabled'='true' ORDER BY r.interval_end DESC,r.received_at DESC LIMIT 1", t.Tenant, resource, objective)
	if e == nil {
		b, _ := json.Marshal(d)
		e = json.Unmarshal(b, &r)
	}
	return r, e
}
func (t *Tx) SLOReceipts(ctx context.Context, resource, objective string, start, end time.Time) ([]slo.Receipt, error) {
	ds, e := t.sourceRows(ctx, "SELECT document FROM slo_receipts WHERE tenant_id=$1 AND resource_id=$2 AND objective_id=$3 AND interval_start >= $4 AND interval_end <= $5 ORDER BY interval_start,sequence", t.Tenant, resource, objective, start, end)
	out := []slo.Receipt{}
	for _, d := range ds {
		var r slo.Receipt
		b, _ := json.Marshal(d)
		if e = json.Unmarshal(b, &r); e != nil {
			return nil, e
		}
		out = append(out, r)
	}
	return out, e
}
func (t *Tx) SLOEvaluationCreate(ctx context.Context, d model.Document) (model.Document, error) {
	selected := d
	if raw, ok := d["evaluation"]; ok {
		b, _ := json.Marshal(raw)
		selected = model.Document{}
		if err := json.Unmarshal(b, &selected); err != nil {
			return nil, err
		}
	}
	e, err := slo.ParseEvaluation(selected)
	if err != nil {
		return nil, err
	}
	e.ID = ""
	e.EvaluationHash = slo.EvaluationHash(e)
	core := model.Document{"resource_id": e.ResourceID, "workload_id": e.WorkloadID, "objective_id": e.ObjectiveID, "objective_version": e.ObjectiveVersion, "objective_hash": e.ObjectiveHash, "source_id": e.SourceID, "evaluation": slo.Document(e)}
	if _, wrapped := d["evaluation"]; wrapped {
		for _, key := range []string{"resource_id", "workload_id", "objective_id", "objective_hash", "source_id"} {
			if model.String(d, key) != model.String(core, key) {
				return nil, errors.New("SLO_EVALUATION_BINDING_INVALID")
			}
		}
		if model.Number(d, "objective_version") != e.ObjectiveVersion {
			return nil, errors.New("SLO_EVALUATION_BINDING_INVALID")
		}
	}
	content := slo.Hash(core)
	d = core
	d["hash"], d["evaluation_hash"], d["id"] = content, content, model.ID()
	b, _ := json.Marshal(d)
	return t.sourceOne(ctx, "INSERT INTO slo_evaluations(tenant_id,id,objective_id,resource_id,content_hash,document) VALUES($1,$2,$3,$4,$5,$6) RETURNING document", t.Tenant, d["id"], e.ObjectiveID, e.ResourceID, content, b)
}
func (t *Tx) SLOEvaluationGet(ctx context.Context, id string) (model.Document, error) {
	return t.sourceOne(ctx, "SELECT document FROM slo_evaluations WHERE tenant_id=$1 AND id=$2", t.Tenant, id)
}
func (t *Tx) SLOEvaluations(ctx context.Context, resource string) ([]model.Document, error) {
	return t.sourceRows(ctx, "SELECT document FROM slo_evaluations WHERE tenant_id=$1 AND ($2='' OR resource_id=$2) ORDER BY created_at,id", t.Tenant, resource)
}
func (t *Tx) SLOViolationAppend(ctx context.Context, execution, plan, measurement string, d model.Document) (model.Document, bool, error) {
	if execution == "" || plan == "" || measurement == "" {
		return nil, false, errors.New("SLO_VIOLATION_BINDING_REQUIRED")
	}
	if _, e := t.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", t.Tenant+":dependency-graph"); e != nil {
		return nil, false, e
	}
	if _, e := t.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", t.Tenant+":slo-violation:"+execution); e != nil {
		return nil, false, e
	}
	old, e := t.sourceOne(ctx, "SELECT document FROM slo_violations WHERE tenant_id=$1 AND execution_id=$2", t.Tenant, execution)
	if e == nil {
		if model.String(old, "plan_id") != plan || model.String(old, "measurement_id") != measurement {
			return nil, false, ErrSLOConflict
		}
		return old, false, nil
	}
	if e != pgx.ErrNoRows {
		return nil, false, e
	}
	d = model.Clone(d)
	d["id"] = model.ID()
	b, _ := json.Marshal(d)
	out, e := t.sourceOne(ctx, "INSERT INTO slo_violations(tenant_id,id,execution_id,plan_id,measurement_id,document) VALUES($1,$2,$3,$4,$5,$6) RETURNING document", t.Tenant, d["id"], execution, plan, measurement, b)
	return out, e == nil, e
}
func (t *Tx) SLOViolations(ctx context.Context, measurement string) ([]model.Document, error) {
	return t.sourceRows(ctx, "SELECT document FROM slo_violations WHERE tenant_id=$1 AND ($2='' OR measurement_id=$2) ORDER BY created_at,id", t.Tenant, measurement)
}
