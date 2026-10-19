package commitmentportfolio

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrJob = errors.New("COMMITMENT_PORTFOLIO_JOB_REFUSED")
var ErrBusy = errors.New("COMMITMENT_PORTFOLIO_SOURCE_BUSY")

type Calculator interface {
	Evaluate(context.Context, Input) (Analysis, error)
}
type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// The endpoint/transport is configured by the private process, never API input.
// A production constructor must pin the service endpoint, TLS, redirects and
// separate token; this type alone is not an endpoint-validation boundary.
type HTTPCalculator struct {
	Client   HTTPDoer
	Endpoint string
	Token    string
}

func (c HTTPCalculator) Evaluate(ctx context.Context, in Input) (Analysis, error) {
	var out Analysis
	if c.Client == nil || c.Endpoint == "" || c.Token == "" {
		return out, ErrJob
	}
	raw, e := json.Marshal(in)
	if e != nil || len(raw) > 32<<20 {
		return out, ErrEvidence
	}
	call, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	r, e := http.NewRequestWithContext(call, http.MethodPost, strings.TrimRight(c.Endpoint, "/")+"/v5/commitment-portfolio", bytes.NewReader(raw))
	if e != nil {
		return out, e
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+c.Token)
	response, e := c.Client.Do(r)
	if e != nil {
		return out, e
	}
	defer response.Body.Close()
	if response.StatusCode == 422 {
		return out, ErrEvidence
	}
	if response.StatusCode != 200 {
		return out, ErrJob
	}
	body, e := io.ReadAll(io.LimitReader(response.Body, (2<<20)+1))
	if e != nil || len(body) > 2<<20 {
		return out, ErrJob
	}
	d := json.NewDecoder(bytes.NewReader(body))
	d.DisallowUnknownFields()
	if d.Decode(&out) != nil || d.Decode(new(any)) != io.EOF {
		return out, ErrJob
	}
	if validateAnalysis(in, out) != nil {
		return Analysis{}, ErrJob
	}
	return out, nil
}

type Worker struct {
	Pool       *pgxpool.Pool
	Tenant     string
	Calculator Calculator
	Now        func() time.Time
}

func (w *Worker) begin(ctx context.Context) (pgx.Tx, error) {
	tx, e := w.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if e != nil {
		return nil, e
	}
	if _, e = tx.Exec(ctx, "SELECT set_config('app.tenant_id',$1,true)", w.Tenant); e != nil {
		tx.Rollback(ctx)
		return nil, e
	}
	return tx, nil
}
func (w *Worker) Ready(ctx context.Context) bool {
	if w == nil || w.Pool == nil || w.Tenant == "" {
		return false
	}
	tx, e := w.begin(ctx)
	if e != nil {
		return false
	}
	defer tx.Rollback(ctx)
	var okay bool
	e = tx.QueryRow(ctx, "SELECT current_user='finops_commitment_portfolio' AND public.commitment_portfolio_scope($1)", w.Tenant).Scan(&okay)
	return e == nil && okay
}
func (w *Worker) Process(ctx context.Context, id string) (bool, error) {
	if w == nil || w.Pool == nil || w.Calculator == nil || !tenantPattern.MatchString(w.Tenant) || !idPattern.MatchString(id) {
		return false, ErrJob
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	// One live process owns a request. Closing a killed worker's DB session
	// releases this session lock; the immutable queue then resumes elsewhere.
	owner, e := w.Pool.Acquire(ctx)
	if e != nil {
		return false, e
	}
	defer owner.Release()
	key := w.Tenant + ":commitment-portfolio-request:" + id
	var locked bool
	if e = owner.QueryRow(ctx, "SELECT pg_try_advisory_lock(hashtextextended($1,0))", key).Scan(&locked); e != nil {
		return false, e
	}
	if !locked {
		return false, ErrBusy
	}
	defer func() {
		release, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		var unlocked bool
		if e := owner.QueryRow(release, "SELECT pg_advisory_unlock(hashtextextended($1,0))", key).Scan(&unlocked); e != nil || !unlocked {
			_ = owner.Conn().Close(release)
		}
	}()
	tx, e := w.begin(ctx)
	if e != nil {
		return false, e
	}
	defer tx.Rollback(ctx)
	var permitted bool
	if e = tx.QueryRow(ctx, "SELECT current_user='finops_commitment_portfolio' AND public.commitment_portfolio_scope($1)", w.Tenant).Scan(&permitted); e != nil || !permitted {
		return false, ErrJob
	}
	if _, e = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", w.Tenant+":dependency-graph"); e != nil {
		return false, e
	}
	var selectionRaw []byte
	var expected string
	var existing bool
	if e = tx.QueryRow(ctx, `SELECT selection,input_hash,EXISTS(SELECT 1 FROM commitment_portfolio_results x WHERE x.tenant_id=r.tenant_id AND x.request_id=r.id) FROM commitment_portfolio_requests r WHERE tenant_id=$1 AND id=$2`, w.Tenant, id).Scan(&selectionRaw, &expected, &existing); e != nil {
		return false, e
	}
	if existing {
		return true, tx.Commit(ctx)
	}
	var raw []byte
	e = tx.QueryRow(ctx, "SELECT public.commitment_portfolio_resolve($1,$2::jsonb)", w.Tenant, selectionRaw).Scan(&raw)
	if e != nil {
		var pg *pgconn.PgError
		if errors.As(e, &pg) && pg.Code == "P0001" {
			if pg.Message == "portfolio source busy" {
				return false, ErrBusy
			}
			if pg.Message == "portfolio source not current" || pg.Message == "portfolio inventory changed" || pg.Message == "portfolio billing changed" {
				_ = tx.Rollback(ctx)
				return false, w.refuse(ctx, id, "ISSUED_INPUTS_CHANGED")
			}
		}
		return false, e
	}
	if len(raw) > 32<<20 {
		_ = tx.Rollback(ctx)
		return false, w.refuse(ctx, id, "ISSUED_INPUT_FORMAT_UNSUPPORTED")
	}
	var resolved Resolved
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	d.UseNumber()
	if d.Decode(&resolved) != nil || d.Decode(new(any)) != io.EOF {
		_ = tx.Rollback(ctx)
		return false, w.refuse(ctx, id, "ISSUED_INPUT_FORMAT_UNSUPPORTED")
	}
	if Hash(documentFromRaw(raw)) != expected {
		_ = tx.Rollback(ctx)
		return false, w.refuse(ctx, id, "ISSUED_INPUTS_CHANGED")
	}
	resolved.RequestID = id
	now := time.Now().UTC()
	if w.Now != nil {
		now = w.Now().UTC()
	}
	in, e := Prepare(resolved, now)
	if e != nil {
		_ = tx.Rollback(ctx)
		return false, w.refuse(ctx, id, "ISSUED_INPUT_FORMAT_UNSUPPORTED")
	}
	// No graph/source lock is held while the private model computes. Publication
	// resolves the same issued inputs again under those locks in its SQL trigger.
	if e = tx.Commit(ctx); e != nil {
		return false, e
	}
	analysis, e := w.Calculator.Evaluate(ctx, in)
	if e != nil {
		if errors.Is(e, ErrEvidence) {
			return false, w.refuse(ctx, id, "PORTFOLIO_MODEL_EVIDENCE_UNSUPPORTED")
		}
		return false, e
	}
	if validateAnalysis(in, analysis) != nil {
		return false, w.refuse(ctx, id, "PORTFOLIO_MODEL_EVIDENCE_UNSUPPORTED")
	}
	body, e := json.Marshal(analysis)
	if e != nil || len(body) > 2<<20 {
		return false, ErrJob
	}
	publication, e := w.begin(ctx)
	if e != nil {
		return false, e
	}
	defer publication.Rollback(ctx)
	_, e = publication.Exec(ctx, "INSERT INTO commitment_portfolio_results(tenant_id,request_id,status,document,content_hash) VALUES($1,$2,'ASSESSED',$3,$4)", w.Tenant, id, body, Hash(analysis))
	if e != nil {
		var pg *pgconn.PgError
		if errors.As(e, &pg) && pg.Code == "P0001" && (pg.Message == "portfolio source not current" || pg.Message == "portfolio inventory changed" || pg.Message == "portfolio billing changed") {
			_ = publication.Rollback(ctx)
			return false, w.refuse(ctx, id, "ISSUED_INPUTS_CHANGED")
		}
		return false, e
	}
	return false, publication.Commit(ctx)
}
func documentFromRaw(raw []byte) any {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var v any
	_ = d.Decode(&v)
	return v
}
func (w *Worker) refuse(ctx context.Context, id, reason string) error {
	tx, e := w.begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	body, e := json.Marshal(Refusal{reason, time.Now().UTC()})
	if e != nil {
		return e
	}
	_, e = tx.Exec(ctx, "INSERT INTO commitment_portfolio_results(tenant_id,request_id,status,document,content_hash) VALUES($1,$2,'REFUSED',$3,$4) ON CONFLICT(tenant_id,request_id) DO NOTHING", w.Tenant, id, body, Hash(documentFromRaw(body)))
	if e != nil {
		return e
	}
	return tx.Commit(ctx)
}
func (w *Worker) RunOnce(ctx context.Context) (int, error) {
	tx, e := w.begin(ctx)
	if e != nil {
		return 0, e
	}
	rows, e := tx.Query(ctx, "SELECT r.id FROM commitment_portfolio_requests r WHERE tenant_id=$1 AND NOT EXISTS(SELECT 1 FROM commitment_portfolio_results x WHERE x.tenant_id=r.tenant_id AND x.request_id=r.id) ORDER BY r.id LIMIT 16", w.Tenant)
	if e != nil {
		tx.Rollback(ctx)
		return 0, e
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if e = rows.Scan(&id); e != nil {
			rows.Close()
			tx.Rollback(ctx)
			return 0, e
		}
		ids = append(ids, id)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		tx.Rollback(ctx)
		return 0, e
	}
	if e = tx.Commit(ctx); e != nil {
		return 0, e
	}
	completed := 0
	for _, id := range ids {
		if _, e = w.Process(ctx, id); errors.Is(e, ErrBusy) {
			continue
		} else if e != nil {
			return completed, e
		}
		completed++
	}
	return completed, nil
}
func (w *Worker) Run(ctx context.Context, report func(int, error)) error {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		n, e := w.RunOnce(ctx)
		if report != nil {
			report(n, e)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		}
	}
}
