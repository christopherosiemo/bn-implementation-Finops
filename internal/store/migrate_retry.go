package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

func concurrentRoleCreation(err error) bool {
	var failure *pgconn.PgError
	return errors.As(err, &failure) && (failure.Code == "23505" && failure.ConstraintName == "pg_authid_rolname_index" ||
		failure.Code == "42710" && failure.Routine == "CreateRole")
}

// Migrate preserves one atomic transaction and checksum checking for the entire
// ordered migration set. Two different application databases can initialize on
// one PostgreSQL cluster simultaneously. Their database-local advisory locks
// cannot serialize CREATE ROLE, so retry only its system-catalog name conflict
// after the failed transaction has rolled back. Other uniqueness/DDL failures
// remain failures; no migration file or applied checksum is changed.
func (s *Store) Migrate(ctx context.Context, dir string) error {
	for attempt := 0; ; attempt++ {
		err := s.migrateOnce(ctx, dir)
		if err == nil || attempt == 3 || !concurrentRoleCreation(err) {
			return err
		}
		timer := time.NewTimer(time.Duration(attempt+1) * 100 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}
