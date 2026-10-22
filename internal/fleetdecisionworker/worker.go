package fleetdecisionworker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"time"

	b "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetbilling"
	d "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetdecision"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
)

var ErrJob = errors.New("FLEET_JOINT_DECISION_REFUSED")

type Worker struct {
	Store  *store.Store
	Tenant string
	Now    func() time.Time
	cursor string
}

func (w *Worker) Process(ctx context.Context, id string) (model.Document, bool, error) {
	if w.Store == nil || w.Tenant == "" || id == "" {
		return nil, false, ErrJob
	}
	job, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	ctx = job
	tx, e := w.Store.Begin(ctx, w.Tenant)
	if e != nil {
		return nil, false, e
	}
	defer tx.Rollback(ctx)
	var role string
	if e = tx.QueryRow(ctx, `SELECT current_user`).Scan(&role); e != nil || role != "finops_group_decision" {
		return nil, false, ErrJob
	}
	old, e := tx.FleetJointDecisionGet(ctx, id)
	if e != nil {
		return nil, false, e
	}
	if old["decision"] != nil || old["refusal"] != nil {
		e = tx.Commit(ctx)
		return old, true, e
	}
	rawInput, e := tx.FleetJointDecisionInputs(ctx, id)
	if e != nil {
		if errors.Is(e, store.ErrFleetJointDecision) {
			_ = tx.Rollback(ctx)
			return w.refuse(ctx, id, "JOINT_DECISION_INPUTS_CHANGED")
		}
		return nil, false, e
	}
	raw, e := json.Marshal(rawInput)
	if e != nil {
		return nil, false, ErrJob
	}
	if len(raw) > 36<<20 {
		_ = tx.Rollback(ctx)
		return w.refuse(ctx, id, "JOINED_INPUT_FORMAT_UNSUPPORTED")
	}
	var input d.Input
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	decoder.DisallowUnknownFields()
	if decoder.Decode(&input) != nil || decoder.Decode(new(any)) != io.EOF {
		_ = tx.Rollback(ctx)
		return w.refuse(ctx, id, "JOINED_INPUT_FORMAT_UNSUPPORTED")
	}
	// This identifier is the actual server-issued queue row, not a proof or an
	// uploaded evaluator field. SQL repeats the exact request binding.
	input.RequestID = id
	now := time.Now().UTC()
	if w.Now != nil {
		now = w.Now().UTC()
	}
	decision, e := d.Build(input, now)
	if e != nil {
		if errors.Is(e, d.ErrJoin) {
			_ = tx.Rollback(ctx)
			reason := "JOINED_MODEL_SUMMARY_UNSUPPORTED"
			if errors.Is(e, d.ErrReservePrecision) {
				reason = "RESERVE_ARITHMETIC_OR_UNSUPPORTED_PRECISION"
			}
			if errors.Is(e, d.ErrRatePrecision) {
				reason = "RATE_ARITHMETIC_OR_UNSUPPORTED_PRECISION"
			}
			return w.refuse(ctx, id, reason)
		}
		return nil, false, e
	}
	raw, e = json.Marshal(decision)
	if e != nil {
		return nil, false, e
	}
	var doc model.Document
	decoder = json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if decoder.Decode(&doc) != nil {
		return nil, false, ErrJob
	}
	out, replayed, e := tx.FleetJointDecisionAppend(ctx, id, b.Hash(rawInput), doc)
	if e != nil {
		if errors.Is(e, store.ErrFleetJointDecision) {
			_ = tx.Rollback(ctx)
			return w.refuse(ctx, id, "JOINT_DECISION_INPUTS_CHANGED")
		}
		return nil, false, e
	}
	e = tx.Commit(ctx)
	return out, replayed, e
}

func (w *Worker) refuse(ctx context.Context, id, reason string) (model.Document, bool, error) {
	tx, e := w.Store.Begin(ctx, w.Tenant)
	if e != nil {
		return nil, false, e
	}
	defer tx.Rollback(ctx)
	out, replay, e := tx.FleetJointDecisionRefuse(ctx, id, reason)
	if e != nil {
		return nil, false, e
	}
	e = tx.Commit(ctx)
	return out, replay, e
}

// RunOnce consumes the commissioned daemon's persisted analytical queue.
// It has no archive/network/native/provider/signing/dispatch dependency.
func (w *Worker) RunOnce(ctx context.Context, limit int) (int, error) {
	if w.Store == nil || w.Tenant == "" || limit < 1 || limit > 100 {
		return 0, ErrJob
	}
	tx, e := w.Store.Begin(ctx, w.Tenant)
	if e != nil {
		return 0, e
	}
	rows, e := tx.FleetJointDecisionPending(ctx, w.cursor, limit)
	if e != nil {
		tx.Rollback(ctx)
		return 0, e
	}
	if e = tx.Commit(ctx); e != nil {
		return 0, e
	}
	count := 0
	var refused []error
	for _, row := range rows {
		id := model.String(row, "id")
		if id == "" || id <= w.cursor {
			return count, ErrJob
		}
		w.cursor = id
		if _, _, e = w.Process(ctx, id); e != nil {
			refused = append(refused, e)
			continue
		}
		count++
	}
	if len(rows) < limit {
		w.cursor = ""
	}
	return count, errors.Join(refused...)
}

// Run supplies a concrete bounded queue consumer. The deployment must create
// this Store with OpenRuntime(...,"group-decision-reader") and its own login.
// No caller authority, provider operation or financial ledger is involved.
func (w *Worker) Run(ctx context.Context, report func(int, bool)) error {
	tick := time.NewTicker(10 * time.Second)
	defer tick.Stop()
	for {
		count, e := w.RunOnce(ctx, 16)
		if report != nil {
			report(count, e != nil)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		}
	}
}
