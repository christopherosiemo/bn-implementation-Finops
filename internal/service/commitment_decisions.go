package service

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/auth"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/commitmentportfolio"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/jackc/pgx/v5/pgconn"
)

func commitmentDecisionProblem(err error) error {
	if err == nil {
		return nil
	}
	if err == commitmentportfolio.ErrEvidence {
		return problem(422, "COMMITMENT_DECISION_SELECTION_INVALID", "select exact issued input IDs")
	}
	if pg, ok := err.(*pgconn.PgError); ok && pg.Code == "P0001" {
		switch pg.Message {
		case "portfolio source busy":
			return problem(503, "COMMITMENT_DECISION_SOURCE_BUSY", "source synchronization is busy; retry the same request")
		case "decision input byte limit", "portfolio input byte limit":
			return problem(413, "COMMITMENT_DECISION_INPUT_LIMIT", "selected evidence exceeds the supported bound")
		case "decision IDs-only selection differs":
			return problem(422, "COMMITMENT_DECISION_SELECTION_INVALID", "select exact issued input IDs")
		case "decision issued inputs unavailable":
			return problem(422, "COMMITMENT_DECISION_INPUTS_UNAVAILABLE", "preparation has unresolved ownership, optimization or forecast evidence")
		case "decision native offer not current", "decision portfolio changed", "decision preparation scope differs", "decision issued inputs changed", "portfolio source not current", "portfolio inventory changed", "portfolio billing changed":
			return problem(409, "COMMITMENT_DECISION_INPUTS_CHANGED", "selected evidence is no longer current")
		}
	}
	return err
}

func commitmentDecisionCollection(parts []string) bool {
	return len(parts) == 3 && parts[0] == "workloads" && (parts[2] == "commitment-decisions" || parts[2] == "commitment-decision-inputs")
}

// These analytical recommendations/reviews are never inputs to the existing
// STOP planner, scheduler or signer, even if unrelated fields are supplied.
func IsCommitmentAdvice(d model.Document) bool {
	return strings.HasPrefix(model.String(d, "category"), "COMMITMENT_") || strings.HasPrefix(model.String(d, "target_type"), "COMMITMENT_") || d["commitment_decision_id"] != nil
}
func commitmentDecisionRole(i auth.Identity) error {
	if !i.Roles["FINANCE"] && !i.Roles["FINOPS_ADMIN"] {
		return problem(403, "FINANCE_REQUIRED", "Finance or FinOps administrator role required")
	}
	return nil
}

func (a *API) commitmentDecisionGet(ctx context.Context, tx *store.Tx, i auth.Identity, r *http.Request) (any, bool, error) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/v1/"), "/")
	detail := len(parts) == 2 && (parts[0] == "commitment-decisions" || parts[0] == "commitment-decision-inputs")
	if !detail && !commitmentDecisionCollection(parts) {
		return nil, false, nil
	}
	if err := commitmentDecisionRole(i); err != nil {
		return nil, true, err
	}
	if detail {
		if len(r.URL.Query()) != 0 {
			return nil, true, problem(422, "UNSUPPORTED_FILTER", "detail has no filters")
		}
		if parts[0] == "commitment-decisions" {
			record, err := commitmentportfolio.DecisionRecordGet(ctx, tx.Tx, i.Tenant, parts[1], i.Subject, i.Roles["FINANCE"], false)
			if err != nil {
				return nil, true, err
			}
			if err = fleetHistoryWorkload(ctx, tx, i, record.WorkloadID); err != nil {
				return nil, true, err
			}
			return record, true, nil
		}
		record, err := commitmentportfolio.DecisionPreparationGet(ctx, tx.Tx, i.Tenant, parts[1])
		if err != nil {
			return nil, true, err
		}
		if err = fleetHistoryWorkload(ctx, tx, i, record.WorkloadID); err != nil {
			return nil, true, err
		}
		return record, true, nil
	}
	if err := fleetHistoryWorkload(ctx, tx, i, parts[1]); err != nil {
		return nil, true, err
	}
	kind := r.URL.Query().Get("kind")
	if kind != "" && (parts[2] != "commitment-decision-inputs" || kind != "PORTFOLIO_ANALYSIS" && kind != "OFFER" && kind != "POST_OPTIMIZATION_ASSESSMENT" && kind != "FORECAST") {
		return nil, true, problem(422, "COMMITMENT_DECISION_KIND_INVALID", "select an issued input kind")
	}
	query := r.URL.Query()
	for key, values := range query {
		if key != "limit" && key != "cursor" && key != "kind" || len(values) != 1 {
			return nil, true, problem(422, "UNSUPPORTED_FILTER", "unsupported collection filter")
		}
	}
	clone := r.Clone(ctx)
	copied := *r.URL
	clone.URL = &copied
	query.Del("kind")
	if query.Get("limit") == "" {
		query.Set("limit", "10")
	}
	clone.URL.RawQuery = query.Encode()
	after, limit, err := nativeCursor(clone, i.Tenant, parts[2], parts[1]+":"+kind)
	if err != nil {
		return nil, true, err
	}
	if limit > 20 {
		return nil, true, problem(422, "LIMIT_INVALID", "limit cannot exceed 20")
	}
	if kind != "" {
		rows, err := tx.Query(ctx, "SELECT value FROM public.commitment_decision_choices($1,$2,$3,$4,$5)", i.Tenant, parts[1], kind, after, limit+1)
		if err != nil {
			return nil, true, commitmentDecisionProblem(err)
		}
		defer rows.Close()
		items := []model.Document{}
		for rows.Next() {
			var raw []byte
			if err = rows.Scan(&raw); err != nil {
				return nil, true, err
			}
			var item model.Document
			if json.Unmarshal(raw, &item) != nil {
				return nil, true, commitmentportfolio.ErrEvidence
			}
			items = append(items, item)
		}
		return nativePage(items, limit, i.Tenant, parts[2], parts[1]+":"+kind), true, rows.Err()
	}
	purpose := "DECISION"
	if parts[2] == "commitment-decision-inputs" {
		purpose = "PREPARE"
	}
	rows, err := tx.Query(ctx, "SELECT id FROM entities WHERE tenant_id=$1 AND kind='recommendations' AND document->>'category'=$2 AND document->>'workload_id'=$3 AND document->>'purpose'=$4 AND id>$5 ORDER BY id LIMIT $6", i.Tenant, commitmentportfolio.DecisionCategory, parts[1], purpose, after, limit+1)
	if err != nil {
		return nil, true, err
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return nil, true, err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, true, err
	}
	items := []model.Document{}
	for _, id := range ids {
		var value any
		if purpose == "DECISION" {
			value, err = commitmentportfolio.DecisionRecordGet(ctx, tx.Tx, i.Tenant, id, i.Subject, i.Roles["FINANCE"], true)
		} else {
			value, err = commitmentportfolio.DecisionPreparationGet(ctx, tx.Tx, i.Tenant, id)
		}
		if err != nil {
			return nil, true, err
		}
		raw, _ := json.Marshal(value)
		var item model.Document
		if json.Unmarshal(raw, &item) != nil {
			return nil, true, commitmentportfolio.ErrEvidence
		}
		items = append(items, item)
	}
	return nativePage(items, limit, i.Tenant, parts[2], parts[1]+":"), true, nil
}

func (a *API) commitmentDecisionMutate(ctx context.Context, tx *store.Tx, i auth.Identity, r *http.Request, in model.Document, parts []string) (model.Document, int, bool, error) {
	if len(parts) == 1 && parts[0] == "approvals" && in["commitment_decision_id"] != nil {
		return a.commitmentDecisionApprove(ctx, tx, i, r, in)
	}
	if !commitmentDecisionCollection(parts) {
		return nil, 0, false, nil
	}
	if err := commitmentDecisionRole(i); err != nil {
		return nil, 0, true, err
	}
	if err := fleetHistoryWorkload(ctx, tx, i, parts[1]); err != nil {
		return nil, 0, true, err
	}
	if err := match(r, model.Document{"version": int64(0)}); err != nil {
		return nil, 0, true, err
	}
	purpose := "DECISION"
	var selection any
	if parts[2] == "commitment-decision-inputs" {
		purpose = "PREPARE"
		if len(in) != 2 {
			return nil, 0, true, problem(422, "IDS_ONLY_SELECTION_REQUIRED", "select exactly the issued portfolio analysis and offer receipt")
		}
		selection = commitmentportfolio.DecisionPreparationSelection{PortfolioAnalysisRequestID: model.String(in, "portfolio_analysis_request_id"), OfferReceiptID: model.String(in, "offer_receipt_id")}
	} else {
		if len(in) != 4 {
			return nil, 0, true, problem(422, "IDS_ONLY_SELECTION_REQUIRED", "select exactly four issued IDs")
		}
		selection = commitmentportfolio.DecisionSelection{PortfolioAnalysisRequestID: model.String(in, "portfolio_analysis_request_id"), OfferReceiptID: model.String(in, "offer_receipt_id"), PostOptimizationAssessmentID: model.String(in, "post_optimization_assessment_id"), ForecastID: model.String(in, "forecast_id")}
	}
	id, err := commitmentportfolio.CreateDecisionRequest(ctx, tx.Tx, i.Tenant, parts[1], i.Subject, purpose, selection)
	if err != nil {
		return nil, 0, true, commitmentDecisionProblem(err)
	}
	if err = tx.Audit(ctx, i.Subject, "commitment.decision_requested", id, model.Document{"purpose": purpose, "workload_id": parts[1], "selection": selection}); err != nil {
		return nil, 0, true, err
	}
	if err = tx.Event(ctx, "commitment.decision_requested", model.Document{"id": id, "purpose": purpose, "workload_id": parts[1]}); err != nil {
		return nil, 0, true, err
	}
	var value any
	if purpose == "DECISION" {
		value, err = commitmentportfolio.DecisionRecordGet(ctx, tx.Tx, i.Tenant, id, i.Subject, i.Roles["FINANCE"], false)
	} else {
		value, err = commitmentportfolio.DecisionPreparationGet(ctx, tx.Tx, i.Tenant, id)
	}
	if err != nil {
		return nil, 0, true, err
	}
	raw, _ := json.Marshal(value)
	out := model.Document{}
	err = json.Unmarshal(raw, &out)
	return out, 202, true, err
}

func (a *API) commitmentDecisionApprove(ctx context.Context, tx *store.Tx, i auth.Identity, r *http.Request, in model.Document) (model.Document, int, bool, error) {
	if !i.Roles["FINANCE"] {
		return nil, 0, true, problem(403, "FINANCE_REQUIRED", "independent Finance review required")
	}
	if len(in) != 2 || model.String(in, "commitment_decision_id") == "" || len(model.String(in, "decision_sha256")) != 64 {
		return nil, 0, true, problem(422, "EXACT_DECISION_REVIEW_REQUIRED", "select one issued decision and its full server hash")
	}
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", i.Tenant+":dependency-graph"); err != nil {
		return nil, 0, true, err
	}
	record, err := commitmentportfolio.DecisionRecordGet(ctx, tx.Tx, i.Tenant, model.String(in, "commitment_decision_id"), i.Subject, true, false)
	if err != nil {
		return nil, 0, true, err
	}
	if err = fleetHistoryWorkload(ctx, tx, i, record.WorkloadID); err != nil {
		return nil, 0, true, err
	}
	if err = match(r, model.Document{"version": record.Version}); err != nil {
		return nil, 0, true, err
	}
	if !record.CanFinanceReview || record.Decision == nil || record.DecisionSHA256 == nil || *record.DecisionSHA256 != model.String(in, "decision_sha256") || record.InputSHA256 == nil {
		return nil, 0, true, problem(409, "EXACT_DECISION_REVIEW_UNAVAILABLE", "the exact current positive recommendation requires an independent reviewer")
	}
	review := commitmentportfolio.DecisionFinanceReview{ID: model.ID(), ActorID: i.Subject, DecisionID: record.Decision.ID, DecisionSHA256: *record.DecisionSHA256, InputSHA256: *record.InputSHA256, ApprovedAt: a.now(), ApprovalScope: "COMMITMENT_RECOMMENDATION_REVIEW_NO_PURCHASE"}
	_, err = tx.Create(ctx, "approvals", model.Document{"id": review.ID, "commitment_decision_id": record.ID, "review": review})
	if err != nil {
		return nil, 0, true, commitmentDecisionProblem(err)
	}
	if err = tx.Audit(ctx, i.Subject, "commitment.recommendation_reviewed", record.ID, model.Document{"approval_id": review.ID, "decision_sha256": review.DecisionSHA256, "input_sha256": review.InputSHA256, "purchase_authorized": false}); err != nil {
		return nil, 0, true, err
	}
	if err = tx.Event(ctx, "commitment.recommendation_reviewed", model.Document{"id": record.ID, "approval_id": review.ID, "purchase_authorized": false}); err != nil {
		return nil, 0, true, err
	}
	updated, err := commitmentportfolio.DecisionRecordGet(ctx, tx.Tx, i.Tenant, record.ID, i.Subject, true, false)
	return model.Document{"approval": review, "recommendation": updated, "id": record.ID, "version": updated.Version}, 201, true, err
}

// Cached approval responses still require the same exact Finance actor and
// current issued selection. Replaying review cannot become purchase authority.
func commitmentDecisionReviewReplay(ctx context.Context, tx *store.Tx, i auth.Identity, in model.Document) error {
	if !i.Roles["FINANCE"] || len(in) != 2 || in["change_plan_id"] != nil {
		return problem(403, "FINANCE_REQUIRED", "independent Finance review required")
	}
	record, err := commitmentportfolio.DecisionRecordGet(ctx, tx.Tx, i.Tenant, model.String(in, "commitment_decision_id"), i.Subject, true, false)
	if err != nil {
		return err
	}
	if err = fleetHistoryWorkload(ctx, tx, i, record.WorkloadID); err != nil {
		return err
	}
	if record.FinanceReview == nil || record.FinanceReview.ActorID != i.Subject || record.DecisionSHA256 == nil || *record.DecisionSHA256 != model.String(in, "decision_sha256") || record.FinanceReview.DecisionSHA256 != *record.DecisionSHA256 {
		return problem(409, "EXACT_DECISION_REVIEW_UNAVAILABLE", "the exact approved decision and reviewer are required")
	}
	var current bool
	if err = tx.QueryRow(ctx, "SELECT public.commitment_decision_current($1,$2)", i.Tenant, record.ID).Scan(&current); err != nil {
		return err
	}
	if !current {
		return problem(409, "COMMITMENT_DECISION_INPUTS_CHANGED", "selected evidence is no longer current")
	}
	return nil
}
