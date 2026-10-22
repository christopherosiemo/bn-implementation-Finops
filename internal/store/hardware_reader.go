package store

import (
	"context"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// OpenHardwareReader uses a distinct login whose commissioned membership is the
// ingestion-only hardware role. Setting the ingestion group on every connection
// preserves the existing immutable source writer identity without sharing login
// credentials with the main billing ingester.
func OpenHardwareReader(ctx context.Context, url string) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, errors.New("HARDWARE_DATABASE_CONFIGURATION_INVALID")
	}
	// One connection owns the cross-replica advisory lock, one publishes a
	// tenant transaction, and one remains available to health probes.
	if cfg.MaxConns < 3 {
		return nil, errors.New("HARDWARE_DATABASE_POOL_MINIMUM_THREE_REQUIRED")
	}
	for key, value := range cfg.ConnConfig.RuntimeParams {
		switch strings.ToLower(key) {
		case "role", "session_authorization":
			return nil, errors.New("HARDWARE_DATABASE_STARTUP_IDENTITY_OVERRIDE_FORBIDDEN")
		case "options":
			if value != "" {
				return nil, errors.New("HARDWARE_DATABASE_STARTUP_OPTIONS_FORBIDDEN")
			}
		case "search_path":
			delete(cfg.ConnConfig.RuntimeParams, key)
		}
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = "public,pg_temp"
	cfg.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		var permitted bool
		err := conn.QueryRow(ctx, `SELECT session_user::text=$1
		 AND pg_has_role(session_user,'finops_hardware_reader','MEMBER')
		 AND NOT EXISTS(SELECT 1 FROM pg_roles other
		 WHERE pg_has_role(session_user,other.oid,'MEMBER')
		 AND (other.rolsuper OR other.rolcreaterole OR other.rolcreatedb OR other.rolbypassrls OR other.rolreplication
		 OR other.rolname NOT IN(session_user,'finops_hardware_reader','finops_ingester')))`, cfg.ConnConfig.User).Scan(&permitted)
		if err != nil || !permitted {
			return errors.New("HARDWARE_DEDICATED_DATABASE_IDENTITY_REQUIRED")
		}
		_, err = conn.Exec(ctx, "SET ROLE finops_ingester")
		return err
	}
	p, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, errors.New("HARDWARE_DATABASE_CONFIGURATION_INVALID")
	}
	if err = p.Ping(ctx); err != nil {
		p.Close()
		return nil, errors.New("HARDWARE_DEDICATED_DATABASE_IDENTITY_REQUIRED")
	}
	return &Store{Pool: p}, nil
}
