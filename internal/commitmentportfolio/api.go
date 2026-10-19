package commitmentportfolio

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/auth"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

func Route(path string) bool {
	return path == "/v1/commitment-portfolio-analyses" || strings.HasPrefix(path, "/v1/commitment-portfolio-analyses/") || path == "/v1/commitment-portfolio-sources" || strings.HasPrefix(path, "/v1/commitment-portfolio-sources/")
}

type Authenticator interface {
	Validate(*http.Request) (auth.Identity, error)
}
type API struct {
	Pool *pgxpool.Pool
	Auth Authenticator
	Now  func() time.Time
}

var idPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)

type cursor struct {
	Tenant string `json:"tenant"`
	Kind   string `json:"kind"`
	Scope  string `json:"scope"`
	After  string `json:"after"`
}

func paging(r *http.Request, tenant, kind, scope string) (string, int, error) {
	for key, values := range r.URL.Query() {
		if key != "limit" && key != "cursor" && !(kind == "receipts" && key == "kind") || len(values) != 1 {
			return "", 0, ErrEvidence
		}
	}
	limit := 10
	if s := r.URL.Query().Get("limit"); s != "" {
		n, e := strconv.Atoi(s)
		if e != nil || n < 1 || n > 20 {
			return "", 0, ErrEvidence
		}
		limit = n
	}
	s := r.URL.Query().Get("cursor")
	if s == "" {
		return "", limit, nil
	}
	if len(s) > 1024 {
		return "", 0, ErrEvidence
	}
	raw, e := base64.RawURLEncoding.DecodeString(s)
	if e != nil {
		return "", 0, ErrEvidence
	}
	var c cursor
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&c) != nil || d.Decode(new(any)) != io.EOF || c.Tenant != tenant || c.Kind != kind || c.Scope != scope || !idPattern.MatchString(c.After) {
		return "", 0, ErrEvidence
	}
	return c.After, limit, nil
}
func nextCursor(tenant, kind, scope, id string) string {
	raw, _ := json.Marshal(cursor{tenant, kind, scope, id})
	return base64.RawURLEncoding.EncodeToString(raw)
}
func ValidateSelection(s Selection, now time.Time) error {
	if !idPattern.MatchString(s.SourceID) || !idPattern.MatchString(s.CommitmentReceiptID) || s.BillingReceiptIDs == nil || len(s.BillingReceiptIDs) > 24 || s.Period.Start.IsZero() || !s.Period.Start.Before(s.Period.End) || s.Period.End.After(now) || s.Period.End.Sub(s.Period.Start) > 31*24*time.Hour || s.Period.End.Sub(s.Period.Start) < 24*time.Hour {
		return ErrEvidence
	}
	for _, t := range []time.Time{s.Period.Start, s.Period.End} {
		_, off := t.Zone()
		if off != 0 || !t.Equal(t.Truncate(24*time.Hour)) {
			return ErrEvidence
		}
	}
	seen := map[string]bool{}
	for _, id := range s.BillingReceiptIDs {
		if !idPattern.MatchString(id) || seen[id] {
			return ErrEvidence
		}
		seen[id] = true
	}
	return nil
}
func (a *API) reply(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func (a *API) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if a.Auth == nil || a.Pool == nil {
		a.reply(w, 503, map[string]string{"error": "PORTFOLIO_UNAVAILABLE"})
		return
	}
	identity, e := a.Auth.Validate(r)
	if e != nil {
		a.reply(w, 401, map[string]string{"error": "UNAUTHENTICATED"})
		return
	}
	// Authenticate and authorize before request lookup, selector reads or replay.
	if identity.Tenant == "" || identity.Subject == "" || !identity.Roles["FINANCE"] && !identity.Roles["FINOPS_ADMIN"] {
		a.reply(w, 403, map[string]string{"error": "FINANCE_REQUIRED"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	tx, e := a.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if e != nil {
		a.reply(w, 503, map[string]string{"error": "PORTFOLIO_UNAVAILABLE"})
		return
	}
	defer tx.Rollback(ctx)
	if _, e = tx.Exec(ctx, "SELECT set_config('app.tenant_id',$1,true)", identity.Tenant); e != nil {
		a.reply(w, 503, map[string]string{"error": "PORTFOLIO_UNAVAILABLE"})
		return
	}
	var role string
	if tx.QueryRow(ctx, "SELECT current_user").Scan(&role) != nil || role != "finops_api" {
		a.reply(w, 503, map[string]string{"error": "PORTFOLIO_DATABASE_IDENTITY_REFUSED"})
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/v1/")
	parts := strings.Split(path, "/")
	if len(parts) == 1 && parts[0] == "commitment-portfolio-analyses" && r.Method == http.MethodPost {
		if strings.Trim(r.Header.Get("If-Match"), "\"") != "0" || len(r.Header.Get("Idempotency-Key")) < 8 || len(r.Header.Get("Idempotency-Key")) > 200 {
			a.reply(w, 428, map[string]string{"error": "CREATION_PRECONDITIONS_REQUIRED"})
			return
		}
		raw, e := io.ReadAll(io.LimitReader(r.Body, 8193))
		if e != nil || len(raw) > 8192 {
			a.reply(w, 422, map[string]string{"error": "IDS_ONLY_SELECTION_REQUIRED"})
			return
		}
		var selection Selection
		d := json.NewDecoder(bytes.NewReader(raw))
		d.DisallowUnknownFields()
		now := time.Now().UTC()
		if a.Now != nil {
			now = a.Now().UTC()
		}
		if d.Decode(&selection) != nil || d.Decode(new(any)) != io.EOF || ValidateSelection(selection, now) != nil {
			a.reply(w, 422, map[string]string{"error": "IDS_ONLY_SELECTION_REQUIRED"})
			return
		}
		sort.Strings(selection.BillingReceiptIDs)
		body, _ := json.Marshal(selection)
		if _, e = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", identity.Tenant+":commitment-portfolio-idempotency:"+identity.Subject+":"+r.Header.Get("Idempotency-Key")); e != nil {
			a.reply(w, 503, map[string]string{"error": "PORTFOLIO_UNAVAILABLE"})
			return
		}
		id := ""
		var old []byte
		e = tx.QueryRow(ctx, "SELECT id,selection FROM commitment_portfolio_requests WHERE tenant_id=$1 AND creator_id=$2 AND idempotency_key=$3", identity.Tenant, identity.Subject, r.Header.Get("Idempotency-Key")).Scan(&id, &old)
		if e == nil {
			if Hash(documentFromRaw(old)) != Hash(selection) {
				a.reply(w, 409, map[string]string{"error": "IDEMPOTENCY_CONFLICT"})
				return
			}
		} else if errors.Is(e, pgx.ErrNoRows) {
			id = model.ID()
			_, e = tx.Exec(ctx, "INSERT INTO commitment_portfolio_requests(tenant_id,id,creator_id,idempotency_key,selection,input_refs,input_hash) VALUES($1,$2,$3,$4,$5,'[]',$6)", identity.Tenant, id, identity.Subject, r.Header.Get("Idempotency-Key"), body, strings.Repeat("0", 64))
			if e != nil {
				status, code := apiDatabaseProblem(e)
				a.reply(w, status, map[string]string{"error": code})
				return
			}
			if e = (&store.Tx{Tx: tx, Tenant: identity.Tenant}).Audit(ctx, identity.Subject, "commitment.portfolio_requested", id, model.Document{"source_id": selection.SourceID, "commitment_receipt_id": selection.CommitmentReceiptID, "billing_receipt_ids": selection.BillingReceiptIDs}); e != nil {
				a.reply(w, 503, map[string]string{"error": "PORTFOLIO_UNAVAILABLE"})
				return
			}
		} else {
			a.reply(w, 503, map[string]string{"error": "PORTFOLIO_UNAVAILABLE"})
			return
		}
		record, e := getRecord(ctx, tx, identity.Tenant, id)
		if e != nil || tx.Commit(ctx) != nil {
			a.reply(w, 503, map[string]string{"error": "PORTFOLIO_UNAVAILABLE"})
			return
		}
		a.reply(w, http.StatusAccepted, record)
		return
	}
	if len(parts) == 2 && parts[0] == "commitment-portfolio-analyses" && r.Method == http.MethodGet && idPattern.MatchString(parts[1]) {
		record, e := getRecord(ctx, tx, identity.Tenant, parts[1])
		if e != nil {
			a.reply(w, 404, map[string]string{"error": "NOT_FOUND"})
			return
		}
		if tx.Commit(ctx) != nil {
			a.reply(w, 503, map[string]string{"error": "PORTFOLIO_UNAVAILABLE"})
			return
		}
		a.reply(w, 200, record)
		return
	}
	if r.Method == http.MethodGet && (len(parts) == 1 && parts[0] == "commitment-portfolio-analyses" || len(parts) == 1 && parts[0] == "commitment-portfolio-sources" || len(parts) == 3 && parts[0] == "commitment-portfolio-sources" && parts[2] == "receipts" && idPattern.MatchString(parts[1])) {
		kind, scope := "analyses", ""
		if parts[0] == "commitment-portfolio-sources" {
			kind = "sources"
		}
		if len(parts) == 3 {
			kind = "receipts"
			scope = parts[1] + ":" + r.URL.Query().Get("kind")
			if r.URL.Query().Get("kind") != "AWS_COMMITMENT" && r.URL.Query().Get("kind") != "AWS_CUR2" {
				a.reply(w, 422, map[string]string{"error": "RECEIPT_KIND_REQUIRED"})
				return
			}
		}
		after, limit, e := paging(r, identity.Tenant, kind, scope)
		if e != nil {
			a.reply(w, 422, map[string]string{"error": "CURSOR_INVALID"})
			return
		}
		var rows pgx.Rows
		if kind == "analyses" {
			rows, e = tx.Query(ctx, pageProjection+" WHERE r.tenant_id=$1 AND r.id>$2 ORDER BY r.id LIMIT $3", identity.Tenant, after, limit+1)
		} else {
			source, receiptKind := "", ""
			if kind == "receipts" {
				source = parts[1]
				receiptKind = r.URL.Query().Get("kind")
			}
			rows, e = tx.Query(ctx, "SELECT value FROM public.commitment_portfolio_choices($1,$2,$3,$4,$5,$6)", identity.Tenant, kind, source, receiptKind, after, limit+1)
		}
		if e != nil {
			a.reply(w, 503, map[string]string{"error": "PORTFOLIO_UNAVAILABLE"})
			return
		}
		items := []map[string]any{}
		for rows.Next() {
			var raw []byte
			if rows.Scan(&raw) != nil {
				rows.Close()
				a.reply(w, 503, map[string]string{"error": "PORTFOLIO_UNAVAILABLE"})
				return
			}
			var item map[string]any
			d := json.NewDecoder(bytes.NewReader(raw))
			d.UseNumber()
			if d.Decode(&item) != nil {
				rows.Close()
				a.reply(w, 503, map[string]string{"error": "PORTFOLIO_UNAVAILABLE"})
				return
			}
			items = append(items, item)
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			a.reply(w, 503, map[string]string{"error": "PORTFOLIO_UNAVAILABLE"})
			return
		}
		var next *string
		if len(items) > limit {
			items = items[:limit]
			value := nextCursor(identity.Tenant, kind, scope, stringValue(items[len(items)-1]["id"]))
			next = &value
		}
		if tx.Commit(ctx) != nil {
			a.reply(w, 503, map[string]string{"error": "PORTFOLIO_UNAVAILABLE"})
			return
		}
		a.reply(w, 200, map[string]any{"items": items, "next_cursor": next})
		return
	}
	a.reply(w, 404, map[string]string{"error": "NOT_FOUND"})
}

const recordProjection = `SELECT jsonb_build_object('id',r.id,'version',1,'creator_id',r.creator_id,'status',coalesce(x.status,'QUEUED'),'selection',r.selection,'input_refs',r.input_refs,'analysis',CASE WHEN x.status='ASSESSED' THEN x.document ELSE NULL END,'refusal',CASE WHEN x.status='REFUSED' THEN x.document ELSE NULL END,'created_at',r.created_at,'execution_authorized',false,'verified_saving',NULL) FROM commitment_portfolio_requests r LEFT JOIN commitment_portfolio_results x ON x.tenant_id=r.tenant_id AND x.request_id=r.id`
const pageProjection = `SELECT jsonb_build_object('id',r.id,'version',1,'creator_id',r.creator_id,'status',coalesce(x.status,'QUEUED'),'selection',r.selection,'input_refs',r.input_refs,'analysis',NULL,'analysis_summary',CASE WHEN x.status='ASSESSED' THEN jsonb_build_object('id',x.document->>'id','inventory_status',x.document->>'inventory_status','billing_status',x.document->>'billing_status','position_count',jsonb_array_length(x.document->'positions'),'recommendation_status','BLOCKED','execution_authorized',false,'verified_saving',NULL) ELSE NULL END,'refusal',CASE WHEN x.status='REFUSED' THEN x.document ELSE NULL END,'created_at',r.created_at,'execution_authorized',false,'verified_saving',NULL) FROM commitment_portfolio_requests r LEFT JOIN commitment_portfolio_results x ON x.tenant_id=r.tenant_id AND x.request_id=r.id`

func getRecord(ctx context.Context, tx pgx.Tx, tenant, id string) (json.RawMessage, error) {
	var raw []byte
	e := tx.QueryRow(ctx, recordProjection+" WHERE r.tenant_id=$1 AND r.id=$2", tenant, id).Scan(&raw)
	return raw, e
}

func apiDatabaseProblem(err error) (int, string) {
	var pg *pgconn.PgError
	if errors.As(err, &pg) && pg.Code == "P0001" {
		switch pg.Message {
		case "portfolio source busy":
			return 503, "PORTFOLIO_SOURCE_BUSY"
		case "portfolio source not current", "portfolio inventory changed", "portfolio billing changed":
			return 409, "PORTFOLIO_INPUTS_NOT_CURRENT"
		case "portfolio input byte limit":
			return 413, "PORTFOLIO_INPUT_LIMIT"
		case "portfolio selection differs", "portfolio UTC days differ", "portfolio receipt limit":
			return 422, "IDS_ONLY_SELECTION_REQUIRED"
		}
	}
	return 503, "PORTFOLIO_UNAVAILABLE"
}
