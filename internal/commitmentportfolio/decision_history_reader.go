package commitmentportfolio

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// The actual queued PREPARE identity is fixed by the worker, not an API body.
// All data comes from tenant/OID-bound private SQL using Worker.begin. This
// adapter receives no ClickHouse, object-store, acquisition or signing keys.
type postgresDecisionHistoryReader struct {
	worker    *Worker
	requestID string
}

type decisionHistoryCursor struct {
	RequestID   string    `json:"request_id"`
	QuerySHA256 string    `json:"query_sha256"`
	After       time.Time `json:"after"`
}

type decisionHistoryWirePage struct {
	Chunks    []json.RawMessage `json:"chunks"`
	NextAfter *time.Time        `json:"next_after"`
	// Actual original039 analysis clock from the owner-only financial resolver.
	// This validates immutable selected observations; it is not current authority.
	SnapshotObservedAt time.Time `json:"snapshot_observed_at"`
}

func decisionHistoryRestoreSnapshot(chunk *Resolved, snapshot, actualNow time.Time) error {
	if chunk == nil || !ownershipUTC(snapshot) || !ownershipUTC(actualNow) || snapshot.After(actualNow.Add(5*time.Second)) {
		return ErrDecisionHistory
	}
	chunk.DecisionSnapshotObservedAt = snapshot
	return nil
}

// Whole-day receipt selections need enough actual hours for all existing
// calibration/held-out origins, including the real billing-to-projection gap.
// The private SQL context derives and checks the same interval independently.
func DecisionHistoryTrainingPeriod(selection Period, projectionStart time.Time) (Period, error) {
	if !ownershipPeriod(selection) || !ownershipUTC(projectionStart) || !selection.End.Equal(selection.End.Truncate(24*time.Hour)) || !projectionStart.Equal(projectionStart.Truncate(time.Hour)) || projectionStart.Before(selection.End) {
		return Period{}, ErrDecisionHistory
	}
	gap := projectionStart.Sub(selection.End) / time.Hour
	if gap > 49 {
		return Period{}, ErrDecisionHistory
	}
	hours := int64(decisionHistoryMinimumHours) + 2*int64(gap)
	days := (hours + 23) / 24
	return Period{Start: selection.End.Add(-time.Duration(days) * 24 * time.Hour), End: selection.End}, nil
}

func decisionHistoryQueryJSON(query DecisionHistoryQuery) ([]byte, error) {
	return json.Marshal(map[string]any{"selection": query.Selection, "scope": query.Scope, "training_period": query.TrainingPeriod, "ownership_ref": query.OwnershipRef})
}

func decisionHistoryReadError(err error) error {
	var pg *pgconn.PgError
	if errors.As(err, &pg) && pg.Code == "P0001" {
		switch pg.Message {
		case "decision history unavailable", "decision history byte limit", "decision history population limit":
			return ErrDecisionHistory
		case "decision history inputs changed", "decision history query differs", "decision history proof differs":
			return ErrEvidence
		}
	}
	return decisionSourceError(err)
}

func (r postgresDecisionHistoryReader) transaction(ctx context.Context, run func(pgx.Tx) error) error {
	if r.worker == nil || r.worker.Pool == nil || !idPattern.MatchString(r.requestID) {
		return ErrDecisionHistory
	}
	tx, err := r.worker.begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err = run(tx); err != nil {
		return decisionHistoryReadError(err)
	}
	return tx.Commit(ctx)
}

func (r postgresDecisionHistoryReader) DecisionHistoryPage(ctx context.Context, query DecisionHistoryQuery, cursor string) (DecisionHistoryPage, error) {
	page := DecisionHistoryPage{Chunks: []Resolved{}}
	if r.worker == nil || query.Scope.TenantID != r.worker.Tenant || !ownershipPeriod(query.TrainingPeriod) {
		return page, ErrDecisionHistory
	}
	queryRaw, err := decisionHistoryQueryJSON(query)
	if err != nil || len(queryRaw) > 64<<10 {
		return page, ErrDecisionHistory
	}
	queryHash := Hash(documentFromRaw(queryRaw))
	after := query.TrainingPeriod.Start
	if cursor != "" {
		if len(cursor) > 2048 {
			return page, ErrDecisionHistory
		}
		raw, e := base64.RawURLEncoding.DecodeString(cursor)
		var value decisionHistoryCursor
		if e != nil || decodeDecisionPrivate(raw, &value, 1024) != nil || base64.RawURLEncoding.EncodeToString(raw) != cursor || value.RequestID != r.requestID || value.QuerySHA256 != queryHash || !ownershipUTC(value.After) || !value.After.After(query.TrainingPeriod.Start) || !value.After.Before(query.TrainingPeriod.End) || value.After.Day() != 1 || !value.After.Equal(value.After.Truncate(24*time.Hour)) {
			return page, ErrDecisionHistory
		}
		after = value.After
	}
	err = r.transaction(ctx, func(tx pgx.Tx) error {
		var raw []byte
		if e := tx.QueryRow(ctx, "SELECT public.commitment_decision_history_page($1,$2,$3::jsonb,$4)", r.worker.Tenant, r.requestID, queryRaw, after).Scan(&raw); e != nil {
			return e
		}
		var wire decisionHistoryWirePage
		if decodeDecisionPrivate(raw, &wire, decisionHistoryPageBytes) != nil || len(wire.Chunks) < 1 || len(wire.Chunks) > decisionHistoryPageChunks {
			return ErrDecisionHistory
		}
		for _, chunkRaw := range wire.Chunks {
			var chunk Resolved
			if decodeDecisionPrivate(chunkRaw, &chunk, decisionHistoryPageBytes) != nil || chunk.TenantID != r.worker.Tenant {
				return ErrDecisionHistory
			}
			if err := decisionHistoryRestoreSnapshot(&chunk, wire.SnapshotObservedAt, time.Now().UTC()); err != nil {
				return err
			}
			// Resolved intentionally omits RequestID on its JSON wire. These
			// chunks belong to this actual queued preparation, not a new job.
			chunk.RequestID = r.requestID
			page.Chunks = append(page.Chunks, chunk)
		}
		if wire.NextAfter != nil {
			stamp := *wire.NextAfter
			if !ownershipUTC(stamp) || !stamp.After(after) || !stamp.Before(query.TrainingPeriod.End) || stamp.Day() != 1 || !stamp.Equal(stamp.Truncate(24*time.Hour)) {
				return ErrDecisionHistory
			}
			value := decisionHistoryCursor{RequestID: r.requestID, QuerySHA256: queryHash, After: stamp}
			body, e := json.Marshal(value)
			if e != nil {
				return e
			}
			page.NextCursor = base64.RawURLEncoding.EncodeToString(body)
		}
		return nil
	})
	if err != nil {
		return DecisionHistoryPage{}, err
	}
	return page, nil
}

func (r postgresDecisionHistoryReader) RecheckDecisionHistory(ctx context.Context, query DecisionHistoryQuery, pins DecisionHistoryPins) error {
	return r.transaction(ctx, func(tx pgx.Tx) error {
		return recheckDecisionHistoryPublication(ctx, tx, r.worker.Tenant, r.requestID, query, pins)
	})
}

// Calling this in the actual final publication transaction keeps all source,
// credential and ownership locks held through existing preparation publication.
// A separate earlier read is only an early movement check, never that fence.
func recheckDecisionHistoryPublication(ctx context.Context, tx pgx.Tx, tenant, requestID string, query DecisionHistoryQuery, pins DecisionHistoryPins) error {
	queryRaw, err := decisionHistoryQueryJSON(query)
	if err != nil || len(queryRaw) > 64<<10 {
		return ErrDecisionHistory
	}
	pinRaw, err := json.Marshal(pins)
	if err != nil || len(pinRaw) > 1<<20 {
		return ErrDecisionHistory
	}
	var valid bool
	if err = tx.QueryRow(ctx, "SELECT public.commitment_decision_history_assert($1,$2,$3::jsonb,$4::jsonb)", tenant, requestID, queryRaw, pinRaw).Scan(&valid); err != nil {
		return decisionHistoryReadError(err)
	}
	if !valid {
		return ErrEvidence
	}
	return nil
}

// The SQL publisher stores only the checked immutable history closure using
// the existing private evidence relation. It adds no table/role/update grant.
// Existing preparation publication must call history_current below and include
// the returned refs for CALIBRATED outputs; architecture merges that hook.
func (w *Worker) publishDecisionHistory(ctx context.Context, requestID string, query DecisionHistoryQuery, pins DecisionHistoryPins) (Ref, []Ref, error) {
	var result struct {
		Reference Ref   `json:"reference"`
		InputRefs []Ref `json:"input_refs"`
	}
	queryRaw, err := decisionHistoryQueryJSON(query)
	if err != nil || len(queryRaw) > 64<<10 {
		return Ref{}, nil, ErrDecisionHistory
	}
	pinRaw, err := json.Marshal(pins)
	if err != nil || len(pinRaw) > 1<<20 {
		return Ref{}, nil, ErrDecisionHistory
	}
	r := postgresDecisionHistoryReader{worker: w, requestID: requestID}
	err = r.transaction(ctx, func(tx pgx.Tx) error {
		var raw []byte
		if e := tx.QueryRow(ctx, "SELECT public.commitment_decision_history_publish($1,$2,$3::jsonb,$4::jsonb)", w.Tenant, requestID, queryRaw, pinRaw).Scan(&raw); e != nil {
			return e
		}
		if decodeDecisionPrivate(raw, &result, 1<<20) != nil || result.Reference.Kind != "HISTORICAL_USAGE" || !idPattern.MatchString(result.Reference.ID) || !shaPattern.MatchString(result.Reference.SHA256) {
			return ErrEvidence
		}
		refs, e := decisionRefs(result.InputRefs)
		if e != nil || Hash(refs) != Hash(result.InputRefs) {
			return ErrEvidence
		}
		return nil
	})
	if err != nil {
		return Ref{}, nil, err
	}
	return result.Reference, result.InputRefs, nil
}
