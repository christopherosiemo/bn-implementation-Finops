package store

import (
	"context"
	"errors"
	"testing"
)

func TestGroupAdmissionLegacyDatabaseKeepsCommonLocksUntilCommit(t *testing.T) {
	f := newFleetHistoryDBTest(t) // Explicit pre-group migration snapshot.
	ctx := context.Background()
	first, err := f.roles["finops_executor"].Begin(ctx, f.tenant)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Rollback(ctx)
	if err = first.GroupForwardAdmission(ctx, "workload-legacy", "R1"); err != nil {
		t.Fatal("pre-group database stopped accepting valid admission", err)
	}
	keys := []string{f.tenant + ":dependency-graph", f.tenant + ":fleet-workload:workload-legacy"}
	for _, key := range keys {
		f.must("finops_worker", func(tx *Tx) error {
			var granted bool
			if err := tx.QueryRow(ctx, "SELECT pg_try_advisory_xact_lock(hashtextextended($1,0))", key).Scan(&granted); err != nil {
				return err
			}
			if granted {
				t.Fatal("workload admission lock was released before commit", key)
			}
			return nil
		})
	}
	if err = first.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	f.must("finops_worker", func(tx *Tx) error { return tx.GroupForwardAdmission(ctx, "workload-legacy", "V4") })
}

func TestGroupAdmissionPartialInstallationFailsClosed(t *testing.T) {
	for _, part := range []string{"table-only", "function-only"} {
		t.Run(part, func(t *testing.T) {
			f := newFleetHistoryDBTest(t)
			var command string
			if part == "table-only" {
				command = "CREATE TABLE public.fleet_group_journal_reservations(tenant_id text)"
			} else {
				command = "CREATE FUNCTION public.fleet_group_admission(text,text,text,text) RETURNS boolean LANGUAGE sql AS 'SELECT true'"
			}
			if _, err := f.admin.Pool.Exec(f.ctx, command); err != nil {
				t.Fatal(err)
			}
			for _, family := range []string{"R1", "V4"} {
				err := f.run("finops_executor", func(tx *Tx) error { return tx.GroupForwardAdmission(f.ctx, "workload-legacy", family) })
				if !errors.Is(err, ErrGroupAdmissionUnavailable) {
					t.Fatal("partial installation admitted a new forward action", family, err)
				}
			}
		})
	}
}
