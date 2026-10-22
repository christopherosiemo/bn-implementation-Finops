package commitmentportfolio

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/jackc/pgx/v5"
)

const DecisionCategory = "COMMITMENT_PORTFOLIO_DECISION"

type decisionRequest struct {
	ID                  string          `json:"id"`
	Version             int64           `json:"version"`
	TenantID            string          `json:"tenant_id"`
	Category            string          `json:"category"`
	Purpose             string          `json:"purpose"`
	CreatorID           string          `json:"creator_id"`
	WorkloadID          string          `json:"workload_id"`
	Selection           json.RawMessage `json:"selection"`
	Status              string          `json:"status"`
	InputRefs           []Ref           `json:"input_refs"`
	InputSHA256         string          `json:"input_sha256"`
	CreatedAt           time.Time       `json:"created_at"`
	ExecutionAuthorized bool            `json:"execution_authorized"`
	VerifiedSaving      *string         `json:"verified_saving"`
}

func decodeDecisionPrivate(raw []byte, out any, maximum int) error {
	if len(raw) > maximum {
		return ErrEvidence
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	d.DisallowUnknownFields()
	if d.Decode(out) != nil || d.Decode(new(any)) != io.EOF {
		return ErrEvidence
	}
	return nil
}

// CreateDecisionRequest uses the existing recommendation queue. The INSERT
// trigger resolves and pins all selected issued IDs before returning QUEUED.
func CreateDecisionRequest(ctx context.Context, tx pgx.Tx, tenant, workload, creator, purpose string, selection any) (string, error) {
	if !tenantPattern.MatchString(tenant) || !idPattern.MatchString(workload) || creator == "" || purpose != "PREPARE" && purpose != "DECISION" {
		return "", ErrEvidence
	}
	raw, err := json.Marshal(selection)
	if err != nil || len(raw) > 8192 {
		return "", ErrEvidence
	}
	fields := map[string]string{}
	if decodeDecisionPrivate(raw, &fields, 8192) != nil {
		return "", ErrEvidence
	}
	expected := 2
	if purpose == "DECISION" {
		expected = 4
	}
	if len(fields) != expected {
		return "", ErrEvidence
	}
	for _, key := range []string{"portfolio_analysis_request_id", "offer_receipt_id"} {
		if !idPattern.MatchString(fields[key]) {
			return "", ErrEvidence
		}
	}
	if purpose == "DECISION" {
		for _, key := range []string{"post_optimization_assessment_id", "forecast_id"} {
			if !idPattern.MatchString(fields[key]) {
				return "", ErrEvidence
			}
		}
	}
	id := model.ID()
	doc := map[string]any{"id": id, "version": 1, "tenant_id": tenant, "category": DecisionCategory, "purpose": purpose, "creator_id": creator, "workload_id": workload, "selection": selection, "status": "QUEUED", "input_refs": []Ref{}, "input_sha256": "", "created_at": time.Now().UTC(), "execution_authorized": false, "verified_saving": nil}
	body, err := json.Marshal(doc)
	if err != nil {
		return "", err
	}
	_, err = tx.Exec(ctx, "INSERT INTO entities(tenant_id,kind,id,document) VALUES($1,'recommendations',$2,$3)", tenant, id, body)
	return id, err
}

func loadDecisionRequest(ctx context.Context, tx pgx.Tx, tenant, id string) (decisionRequest, error) {
	var raw []byte
	var result decisionRequest
	err := tx.QueryRow(ctx, "SELECT public.commitment_decision_request($1,$2)", tenant, id).Scan(&raw)
	if err != nil {
		return result, err
	}
	if decodeDecisionPrivate(raw, &result, 131072) != nil {
		return result, ErrEvidence
	}
	return result, nil
}

type decisionTerminal struct {
	Status   string
	Purpose  string
	Document []byte
	SHA256   string
}

func loadDecisionTerminal(ctx context.Context, tx pgx.Tx, tenant, id string) (decisionTerminal, error) {
	var out decisionTerminal
	err := tx.QueryRow(ctx, "SELECT status,purpose,document,content_hash FROM commitment_decision_results WHERE tenant_id=$1 AND request_id=$2", tenant, id).Scan(&out.Status, &out.Purpose, &out.Document, &out.SHA256)
	return out, err
}

func DecisionRecordGet(ctx context.Context, tx pgx.Tx, tenant, id, actor string, finance, page bool) (DecisionRecord, error) {
	request, err := loadDecisionRequest(ctx, tx, tenant, id)
	if err != nil {
		return DecisionRecord{}, err
	}
	if request.Purpose != "DECISION" {
		return DecisionRecord{}, ErrEvidence
	}
	var selection DecisionSelection
	if decodeDecisionPrivate(request.Selection, &selection, 8192) != nil {
		return DecisionRecord{}, ErrEvidence
	}
	out := DecisionRecord{ID: id, Version: 1, WorkloadID: request.WorkloadID, CreatorID: request.CreatorID, Status: "QUEUED", Selection: selection, InputRefs: request.InputRefs, InputSHA256: &request.InputSHA256, ReviewReasonCodes: []string{}, CreatedAt: request.CreatedAt}
	terminal, err := loadDecisionTerminal(ctx, tx, tenant, id)
	if err == pgx.ErrNoRows {
		return out, nil
	}
	if err != nil {
		return out, err
	}
	out.Status = terminal.Status
	out.Version = 2
	if terminal.Status == "REFUSED" {
		out.Refusal = &Refusal{}
		if decodeDecisionPrivate(terminal.Document, out.Refusal, 4096) != nil {
			return out, ErrEvidence
		}
		return out, nil
	}
	var decision Decision
	if decodeDecisionPrivate(terminal.Document, &decision, 2<<20) != nil || Hash(decision) != terminal.SHA256 {
		return out, ErrEvidence
	}
	out.DecisionSHA256 = &terminal.SHA256
	if page {
		out.DecisionSummary = &DecisionSummary{ID: decision.ID, Status: decision.Status, Currency: decision.Scope.Currency, ProposedHourlyCommitment: decision.ProposedHourlyCommitment.Value, ExpectedSavings: decision.ExpectedSavings.Value, ReasonCodes: decision.ReasonCodes, FinanceStatus: "PENDING"}
	} else {
		out.Decision = &decision
	}
	var approval []byte
	err = tx.QueryRow(ctx, "SELECT document FROM entities WHERE tenant_id=$1 AND kind='approvals' AND document->>'commitment_decision_id'=$2 ORDER BY id LIMIT 1", tenant, id).Scan(&approval)
	if err == nil {
		var wrapper struct {
			Review DecisionFinanceReview `json:"review"`
		}
		var doc map[string]json.RawMessage
		if json.Unmarshal(approval, &doc) != nil || json.Unmarshal(doc["review"], &wrapper.Review) != nil {
			return out, ErrEvidence
		}
		out.FinanceReview = &wrapper.Review
		out.Version = 3
		if out.DecisionSummary != nil {
			out.DecisionSummary.FinanceStatus = "REVIEWED"
		}
	} else if err != pgx.ErrNoRows {
		return out, err
	}
	switch {
	case !finance:
		out.ReviewReasonCodes = append(out.ReviewReasonCodes, "FINANCE_REQUIRED")
	case actor == request.CreatorID:
		out.ReviewReasonCodes = append(out.ReviewReasonCodes, "INDEPENDENT_FINANCE_REVIEW_REQUIRED")
	case out.FinanceReview != nil:
		out.ReviewReasonCodes = append(out.ReviewReasonCodes, "ALREADY_REVIEWED")
	case decision.Status != "RECOMMEND_PURCHASE_PENDING_FINANCE":
		out.ReviewReasonCodes = append(out.ReviewReasonCodes, "PURCHASE_RECOMMENDATION_UNAVAILABLE")
	default:
		var current bool
		if err = tx.QueryRow(ctx, "SELECT public.commitment_decision_current($1,$2)", tenant, id).Scan(&current); err != nil {
			return out, err
		}
		if current {
			out.CanFinanceReview = true
		} else {
			out.ReviewReasonCodes = append(out.ReviewReasonCodes, "ISSUED_INPUTS_CHANGED")
		}
	}
	return out, nil
}

type decisionPreparationResult struct {
	RequestID           string    `json:"request_id"`
	AssessmentID        string    `json:"post_optimization_assessment_id"`
	ForecastID          string    `json:"forecast_id"`
	InputRefs           []Ref     `json:"input_refs"`
	ReasonCodes         []string  `json:"reason_codes"`
	ObservedAt          time.Time `json:"observed_at"`
	ExecutionAuthorized bool      `json:"execution_authorized"`
	VerifiedSaving      *string   `json:"verified_saving"`
}

func DecisionPreparationGet(ctx context.Context, tx pgx.Tx, tenant, id string) (DecisionPreparationRecord, error) {
	request, err := loadDecisionRequest(ctx, tx, tenant, id)
	if err != nil {
		return DecisionPreparationRecord{}, err
	}
	if request.Purpose != "PREPARE" {
		return DecisionPreparationRecord{}, ErrEvidence
	}
	var selection DecisionPreparationSelection
	if decodeDecisionPrivate(request.Selection, &selection, 8192) != nil {
		return DecisionPreparationRecord{}, ErrEvidence
	}
	out := DecisionPreparationRecord{ID: id, Version: 1, WorkloadID: request.WorkloadID, CreatorID: request.CreatorID, Status: "QUEUED", Selection: selection, InputRefs: request.InputRefs, ReasonCodes: []string{}, CreatedAt: request.CreatedAt}
	terminal, err := loadDecisionTerminal(ctx, tx, tenant, id)
	if err == pgx.ErrNoRows {
		return out, nil
	}
	if err != nil {
		return out, err
	}
	out.Status = terminal.Status
	out.Version = 2
	if terminal.Status == "REFUSED" {
		var refusal Refusal
		if decodeDecisionPrivate(terminal.Document, &refusal, 4096) != nil {
			return out, ErrEvidence
		}
		out.ReasonCodes = []string{refusal.ReasonCode}
		return out, nil
	}
	var result decisionPreparationResult
	if decodeDecisionPrivate(terminal.Document, &result, 131072) != nil {
		return out, ErrEvidence
	}
	out.PostOptimizationAssessmentID = &result.AssessmentID
	out.ForecastID = &result.ForecastID
	out.InputRefs = result.InputRefs
	out.ReasonCodes = result.ReasonCodes
	return out, nil
}
