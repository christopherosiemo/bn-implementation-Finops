package service

import (
	"context"
	"testing"

	portfolio "github.com/christopherosiemo/bn-implementation-Finops/internal/commitmentportfolio"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
)

// PostgreSQL roles are cluster-wide while every acceptance database is owned
// separately. A second real child must migrate and commission independently.
func commitmentPortfolioAssertSharedRoleMigration(t *testing.T, ctx context.Context, original *store.Store) {
	t.Helper()
	f, second, _, _ := newFleetNativeHTTPTest(t)
	if second.Pool.Config().ConnConfig.Database == original.Pool.Config().ConnConfig.Database {
		t.Fatal("portfolio migration did not use a distinct owned database")
	}
	analyst := commitmentPortfolioNativeRuntime(t, ctx, second, f.tenant)
	var firstOID, secondOID uint32
	query := "SELECT oid FROM pg_roles WHERE rolname='finops_commitment_portfolio' AND NOT(rolcanlogin OR rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls)"
	if original.Pool.QueryRow(ctx, query).Scan(&firstOID) != nil || second.Pool.QueryRow(ctx, query).Scan(&secondOID) != nil || firstOID == 0 || firstOID != secondOID {
		t.Fatal("shared analytical role changed across owned child migrations")
	}
	if !(&portfolio.Worker{Pool: analyst.Pool, Tenant: f.tenant}).Ready(ctx) {
		t.Fatal("second child credential was not independently commissioned")
	}
	t.Log("Actual portfolio migration: two distinct owned databases reuse the same constrained NOLOGIN role and independently commission scoped logins PASS")
}
