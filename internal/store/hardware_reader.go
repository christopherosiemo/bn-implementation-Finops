package store

import (
	"context"
	"errors"

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
	cfg.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		var permitted bool
		err := conn.QueryRow(ctx, `SELECT NOT r.rolsuper AND NOT r.rolcreaterole AND NOT r.rolcreatedb AND NOT r.rolbypassrls
		 AND pg_has_role(session_user,'finops_hardware_reader','MEMBER')
		 AND NOT EXISTS(SELECT 1 FROM pg_roles other
		 WHERE other.rolname NOT IN(session_user,'finops_hardware_reader','finops_ingester')
		 AND pg_has_role(session_user,other.oid,'MEMBER'))
		 FROM pg_roles r WHERE r.rolname=session_user`).Scan(&permitted)
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
