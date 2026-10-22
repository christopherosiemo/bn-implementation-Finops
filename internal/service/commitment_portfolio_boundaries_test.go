package service

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	portfolio "github.com/christopherosiemo/bn-implementation-Finops/internal/commitmentportfolio"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/source"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/jackc/pgx/v5"
)

// These checks use the already-issued native population and actual restricted
// connections. They grant no additional rights or fabricated source receipts.
func commitmentPortfolioAssertBoundaries(t *testing.T, ctx context.Context, f *mutationReplayFixture, analyst *store.Store, selection portfolio.Selection, finance, requestID string) {
	t.Helper()
	get := func(path, token string) (int, model.Document) {
		r := httptest.NewRequest(http.MethodGet, "/v1/"+path, nil)
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		f.api.ServeHTTP(w, r)
		var document model.Document
		if json.Unmarshal(w.Body.Bytes(), &document) != nil {
			t.Fatal("portfolio boundary response not JSON")
		}
		return w.Code, document
	}
	owner := f.token(f.tenant, "portfolio-owner", "APPLICATION_OWNER")
	foreign := f.token("portfolio-other-tenant", "portfolio-foreign-finance", "FINANCE")
	for _, check := range []struct {
		path, token string
		status      int
	}{
		{"commitment-portfolio-analyses/" + requestID, "", 401},
		{"commitment-portfolio-sources", owner, 403},
		{"commitment-portfolio-analyses/" + requestID, foreign, 404},
	} {
		if code, _ := get(check.path, check.token); code != check.status {
			t.Fatal("portfolio authentication/tenant boundary differs", check.status, code)
		}
	}
	for _, path := range []string{"commitment-portfolio-analyses", "commitment-portfolio-sources", "commitment-portfolio-sources/" + selection.SourceID + "/receipts?kind=AWS_CUR2"} {
		code, document := get(path, foreign)
		if code != 200 || len(source.Rows(document["items"])) != 0 {
			t.Fatal("portfolio foreign tenant observed source or analysis")
		}
	}
	body := source.Object(selection)
	code, replay, _ := f.request("commitment-portfolio-analyses", `"0"`, "native-portfolio-actual", finance, body)
	if code != 202 || model.String(replay, "id") != requestID || model.String(replay, "status") != "ASSESSED" {
		t.Fatal("portfolio same-key persisted replay changed")
	}
	changed := selection
	changed.Period.Start = changed.Period.Start.Add(-24 * time.Hour)
	if code, _, _ := f.request("commitment-portfolio-analyses", `"0"`, "native-portfolio-actual", finance, source.Object(changed)); code != 409 {
		t.Fatal("portfolio idempotency conflict accepted", code)
	}
	for _, precondition := range []struct{ etag, key string }{{`"0"`, ""}, {"", "native-portfolio-missing-version"}} {
		if code, _, _ := f.request("commitment-portfolio-analyses", precondition.etag, precondition.key, finance, body); code != 428 {
			t.Fatal("portfolio creation preconditions bypassed", code)
		}
	}
	if e := analyst.Do(ctx, "portfolio-other-tenant", func(tx *store.Tx) error {
		var count int
		if e := tx.Tx.QueryRow(ctx, "SELECT count(*) FROM commitment_portfolio_results").Scan(&count); e != nil {
			return e
		}
		if count != 0 {
			t.Fatal("portfolio SQL tenant setting escaped dedicated credential")
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	tx, e := analyst.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = tx.Exec(ctx, "SELECT set_config('app.tenant_id',$1,true)", f.tenant); e != nil {
		tx.Rollback(ctx)
		t.Fatal(e)
	}
	var permitted bool
	e = tx.QueryRow(ctx, "SELECT public.commitment_portfolio_scope($1)", f.tenant).Scan(&permitted)
	_ = tx.Rollback(ctx)
	if e != nil || permitted {
		t.Fatal("portfolio retained transaction snapshot became authorized", e)
	}
	for _, table := range []string{"entities", "source_receipts", "source_checkpoints", "savings_ledger", "signed_plans", "provider_operations", "commitment_portfolio_requests", "commitment_portfolio_results"} {
		var mutation bool
		if e = analyst.Pool.QueryRow(ctx, "SELECT has_table_privilege(current_user,$1,'UPDATE,DELETE') OR ($1<>'commitment_portfolio_results' AND has_table_privilege(current_user,$1,'INSERT'))", table).Scan(&mutation); e != nil || mutation {
			t.Fatal("portfolio analyst gained mutation authority", table, e)
		}
	}
	t.Log("Actual portfolio boundary checks: signed-JWT roles, foreign tenant API/SQL, creation preconditions, immutable replay/conflict, retained snapshot and no execution/financial-write grants PASS")
}
