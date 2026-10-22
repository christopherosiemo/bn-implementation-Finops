package commitmentportfolio

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type DecisionCalculator interface {
	EvaluateDecision(context.Context, DecisionInput) (Decision, error)
	ProduceDecisionForecast(context.Context, DecisionForecastRequest) (DecisionForecastProduction, error)
}

// Resolved deliberately omits RequestID from its JSON representation. Restore
// it and the immutable mapping anchor from the selected039 analysis after the
// caller validates the private SQL base hash. SQL separately checks actual
// current financial health, registration, inventory and billing heads. Neither
// private value can come from a caller's evidence or a synthetic new request.
func restoreDecisionPortfolioRequestID(base *decisionBase) error {
	if base == nil || !idPattern.MatchString(base.Portfolio.RequestID) || base.Portfolio.RequestID != selectionPortfolioID(base.Selection) || base.Portfolio.ObservedAt.IsZero() {
		return ErrEvidence
	}
	base.PortfolioInputs.RequestID = base.Portfolio.RequestID
	base.PortfolioInputs.DecisionSnapshotObservedAt = base.Portfolio.ObservedAt
	return nil
}

func decisionSourceError(err error) error {
	var pg *pgconn.PgError
	if errors.As(err, &pg) && pg.Code == "P0001" {
		switch pg.Message {
		case "portfolio source busy":
			return ErrBusy
		case "portfolio source not current", "portfolio inventory changed", "portfolio billing changed", "decision native offer not current", "decision portfolio changed", "decision preparation scope differs", "decision issued inputs changed", "ownership registered key changed", "configuration artifact registration inactive", "configuration artifact declaration superseded":
			return ErrEvidence
		case "archive current authority changed", "archive source unavailable", "archive reviewer unavailable", "archive current review deadline differs", "ownership full current interval differs", "ownership exact issued reference unavailable", "optimization current inputs changed", "optimization ownership scope differs", "optimization retained inputs changed", "optimization selected inputs changed", "decision history inputs changed":
			return ErrEvidence
		case "decision original financial snapshot unavailable", "decision current native inventory unavailable", "decision financial source or billing changed", "decision native financial inventory changed", "decision original financial selection differs":
			return ErrEvidence
		}
	}
	return err
}

// ProcessDecision extends the same credentialed analytical daemon. It holds a
// request-local session lock across private model I/O, releases graph/source
// guards before HTTP, and repeats source and credential checks at publication.
func (w *Worker) ProcessDecision(parent context.Context, id string) (bool, error) {
	if w == nil || w.Pool == nil || !idPattern.MatchString(id) || !tenantPattern.MatchString(w.Tenant) {
		return false, ErrJob
	}
	calculator, ok := w.Calculator.(DecisionCalculator)
	if !ok {
		return false, ErrJob
	}
	ctx, cancel := context.WithTimeout(parent, 5*time.Minute)
	defer cancel()
	owner, err := w.Pool.Acquire(ctx)
	if err != nil {
		return false, err
	}
	defer owner.Release()
	key := w.Tenant + ":commitment-decision-request:" + id
	var owned bool
	if err = owner.QueryRow(ctx, "SELECT pg_try_advisory_lock(hashtextextended($1,0))", key).Scan(&owned); err != nil {
		return false, err
	}
	if !owned {
		return false, ErrBusy
	}
	defer func() {
		release, done := context.WithTimeout(context.Background(), 2*time.Second)
		defer done()
		var unlocked bool
		if e := owner.QueryRow(release, "SELECT pg_advisory_unlock(hashtextextended($1,0))", key).Scan(&unlocked); e != nil || !unlocked {
			_ = owner.Conn().Close(release)
		}
	}()
	tx, err := w.begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	request, err := loadDecisionRequest(ctx, tx, w.Tenant, id)
	if err != nil {
		return false, err
	}
	if _, err = loadDecisionTerminal(ctx, tx, w.Tenant, id); err == nil {
		return true, tx.Commit(ctx)
	} else if err != pgx.ErrNoRows {
		return false, err
	}
	var raw []byte
	err = tx.QueryRow(ctx, "SELECT public.commitment_decision_base($1,$2,$3::jsonb)", w.Tenant, request.WorkloadID, request.Selection).Scan(&raw)
	if err != nil {
		_ = tx.Rollback(ctx)
		if errors.Is(decisionSourceError(err), ErrEvidence) {
			return false, w.refuseDecision(ctx, request, "ISSUED_INPUTS_CHANGED")
		}
		return false, decisionSourceError(err)
	}
	if len(raw) > 32<<20 || Hash(documentFromRaw(raw)) != request.InputSHA256 {
		_ = tx.Rollback(ctx)
		return false, w.refuseDecision(ctx, request, "ISSUED_INPUTS_CHANGED")
	}
	var base decisionBase
	if decodeDecisionPrivate(raw, &base, 32<<20) != nil {
		_ = tx.Rollback(ctx)
		return false, w.refuseDecision(ctx, request, "ISSUED_INPUT_FORMAT_UNSUPPORTED")
	}
	if restoreDecisionPortfolioRequestID(&base) != nil {
		_ = tx.Rollback(ctx)
		return false, w.refuseDecision(ctx, request, "ISSUED_INPUT_FORMAT_UNSUPPORTED")
	}
	now := time.Now().UTC()
	if w.Now != nil {
		now = w.Now().UTC()
	}
	if err = tx.Commit(ctx); err != nil {
		return false, err
	}
	var body []byte
	if request.Purpose == "PREPARE" {
		assessment, forecast, err := w.prepareConnectedDecisionArtifacts(ctx, base, id, now, calculator)
		if err != nil {
			if (!errors.Is(err, ErrEvidence) && errors.Is(decisionSourceError(err), ErrEvidence)) || errors.Is(err, ErrDecisionStageInputsAbsent) {
				return false, w.refuseDecision(ctx, request, "ISSUED_INPUTS_CHANGED")
			}
			if errors.Is(err, ErrEvidence) {
				return false, w.refuseDecision(ctx, request, "DECISION_MODEL_EVIDENCE_UNSUPPORTED")
			}
			return false, err
		}
		publication, err := w.begin(ctx)
		if err != nil {
			return false, err
		}
		defer publication.Rollback(ctx)
		a, _ := json.Marshal(assessment)
		f, _ := json.Marshal(forecast)
		err = publication.QueryRow(ctx, "SELECT public.commitment_decision_publish_preparation($1,$2,$3::jsonb,$4::jsonb)", w.Tenant, id, a, f).Scan(&body)
		if err != nil {
			_ = publication.Rollback(ctx)
			if errors.Is(decisionSourceError(err), ErrEvidence) {
				return false, w.refuseDecision(ctx, request, "ISSUED_INPUTS_CHANGED")
			}
			return false, decisionSourceError(err)
		}
		if _, err = publication.Exec(ctx, "INSERT INTO commitment_decision_results(tenant_id,request_id,purpose,status,document,content_hash) VALUES($1,$2,'PREPARE','ASSESSED',$3,$4)", w.Tenant, id, body, Hash(documentFromRaw(body))); err != nil {
			return false, decisionSourceError(err)
		}
		return false, publication.Commit(ctx)
	}
	if request.Purpose != "DECISION" {
		return false, ErrJob
	}
	input, err := buildDecisionInput(base, id, now)
	if err != nil {
		return false, w.refuseDecision(ctx, request, "ISSUED_INPUT_FORMAT_UNSUPPORTED")
	}
	decision, err := calculator.EvaluateDecision(ctx, input)
	if err != nil {
		if errors.Is(err, ErrEvidence) {
			return false, w.refuseDecision(ctx, request, "DECISION_MODEL_EVIDENCE_UNSUPPORTED")
		}
		return false, err
	}
	if validateDecision(input, decision) != nil {
		return false, w.refuseDecision(ctx, request, "DECISION_MODEL_EVIDENCE_UNSUPPORTED")
	}
	body, err = json.Marshal(decision)
	if err != nil || len(body) > 2<<20 {
		return false, ErrEvidence
	}
	publication, err := w.begin(ctx)
	if err != nil {
		return false, err
	}
	defer publication.Rollback(ctx)
	_, err = publication.Exec(ctx, "INSERT INTO commitment_decision_results(tenant_id,request_id,purpose,status,document,content_hash) VALUES($1,$2,'DECISION','ASSESSED',$3,$4)", w.Tenant, id, body, Hash(decision))
	if err != nil {
		_ = publication.Rollback(ctx)
		if errors.Is(decisionSourceError(err), ErrEvidence) {
			return false, w.refuseDecision(ctx, request, "ISSUED_INPUTS_CHANGED")
		}
		return false, decisionSourceError(err)
	}
	return false, publication.Commit(ctx)
}

func (w *Worker) refuseDecision(ctx context.Context, request decisionRequest, reason string) error {
	tx, err := w.begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	raw, err := json.Marshal(Refusal{ReasonCode: reason, ObservedAt: time.Now().UTC()})
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, "INSERT INTO commitment_decision_results(tenant_id,request_id,purpose,status,document,content_hash) VALUES($1,$2,$3,'REFUSED',$4,$5) ON CONFLICT(tenant_id,request_id) DO NOTHING", w.Tenant, request.ID, request.Purpose, raw, Hash(documentFromRaw(raw)))
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (w *Worker) RunDecisionOnce(ctx context.Context) (int, error) {
	tx, err := w.begin(ctx)
	if err != nil {
		return 0, err
	}
	rows, err := tx.Query(ctx, "SELECT id,purpose FROM public.commitment_decision_pending($1,16)", w.Tenant)
	if err != nil {
		_ = tx.Rollback(ctx)
		return 0, err
	}
	ids := []string{}
	for rows.Next() {
		var id, purpose string
		if err = rows.Scan(&id, &purpose); err != nil {
			rows.Close()
			_ = tx.Rollback(ctx)
			return 0, err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		_ = tx.Rollback(ctx)
		return 0, err
	}
	if err = tx.Commit(ctx); err != nil {
		return 0, err
	}
	completed := 0
	for _, id := range ids {
		if _, err = w.ProcessDecision(ctx, id); errors.Is(err, ErrBusy) {
			continue
		} else if err != nil {
			return completed, err
		}
		completed++
	}
	return completed, nil
}
