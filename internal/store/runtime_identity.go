package store

import (
	"context"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// OpenRuntime pins each process to its commissioned database group. Merely
// switching current_user cannot make a privileged or mixed login safe: the
// authenticated session identity and all transitive memberships are checked.
// Migration administration deliberately uses Open instead.
func OpenRuntime(ctx context.Context, dsn, process string) (*Store, error) {
	group := map[string]string{
		"api": "finops_api", "worker": "finops_worker",
		"signer": "finops_signer", "executor": "finops_executor",
		"ingester": "finops_ingester", "activity-ingress": "finops_activity",
		"fleet-history-reader": "finops_ingester",
		"telemetry-reader":     "finops_telemetry_reader", "telemetry-ingress": "finops_telemetry_ingress",
		"deployment-observer":        "finops_deployment_observer",
		"group-fixture":              "finops_group_fixture",
		"group-ledger":               "finops_group_ledger",
		"group-pipeline":             "finops_group_pipeline",
		"group-workspace-controller": "finops_group_workspace_controller",
		"group-health-observer":      "finops_group_health_observer",
		"group-assessment-reader":    "finops_group_assessor",
		"group-capacity-evaluator":   "finops_group_capacity",
		"group-decision-reader":      "finops_group_decision",
	}[process]
	if group == "" {
		return nil, errors.New("RUNTIME_DATABASE_PROCESS_INVALID")
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, errors.New("RUNTIME_DATABASE_CONFIGURATION_INVALID")
	}
	// CUR synchronization keeps a session-scoped ownership lock while using
	// tenant transactions. Retain another connection for the health endpoint.
	if (process == "ingester" || process == "fleet-history-reader") && cfg.MaxConns < 3 {
		return nil, errors.New("RUNTIME_INGESTION_POOL_MINIMUM_THREE_REQUIRED")
	}
	for key, value := range cfg.ConnConfig.RuntimeParams {
		switch strings.ToLower(key) {
		case "role", "session_authorization":
			return nil, errors.New("RUNTIME_DATABASE_STARTUP_IDENTITY_OVERRIDE_FORBIDDEN")
		case "options":
			if value != "" {
				return nil, errors.New("RUNTIME_DATABASE_STARTUP_OPTIONS_FORBIDDEN")
			}
		case "search_path":
			delete(cfg.ConnConfig.RuntimeParams, key)
		}
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = "public,pg_temp"
	cfg.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		var permitted bool
		err := conn.QueryRow(ctx, `SELECT session_user::text=$1
		 AND pg_has_role(session_user,$2,'MEMBER')
		 AND NOT EXISTS(SELECT 1 FROM pg_roles r WHERE pg_has_role(session_user,r.oid,'MEMBER')
		 AND (r.rolsuper OR r.rolcreaterole OR r.rolcreatedb OR r.rolbypassrls OR r.rolreplication
		 OR r.rolname NOT IN(session_user,$2)))`, cfg.ConnConfig.User, group).Scan(&permitted)
		if err != nil || !permitted {
			return errors.New("RUNTIME_DEDICATED_DATABASE_IDENTITY_REQUIRED")
		}
		_, err = conn.Exec(ctx, "SET ROLE "+pgx.Identifier{group}.Sanitize())
		return err
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, errors.New("RUNTIME_DATABASE_CONFIGURATION_INVALID")
	}
	if err = pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, errors.New("RUNTIME_DEDICATED_DATABASE_IDENTITY_REQUIRED")
	}
	return &Store{Pool: pool}, nil
}
