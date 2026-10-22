package commitmentportfolio

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/configuration"
	"github.com/jackc/pgx/v5"
)

// This adapter reads only operator/observer/attestor-issued rows through the
// restricted 040 functions. It has no object-store or decryption credentials.
// Each call uses READ COMMITTED; final publication repeats the pins under the
// registration fences rather than treating these separate reads as a snapshot.
type postgresDecisionOwnershipReader struct{ worker *Worker }

type ownershipPageCursor struct {
	QuerySHA256  string `json:"query_sha256"`
	Registration string `json:"registration"`
	Resource     string `json:"resource"`
	Sequence     int64  `json:"sequence"`
}

func (r postgresDecisionOwnershipReader) transaction(ctx context.Context, run func(pgx.Tx) error) error {
	if r.worker == nil || r.worker.Pool == nil {
		return ErrDecisionOwnershipEvidence
	}
	tx, err := r.worker.begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err = run(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func ownershipReadError(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrDecisionOwnershipAbsent
	}
	return err
}

func (r postgresDecisionOwnershipReader) OwnershipRegistration(ctx context.Context, id string) (DecisionOwnershipRegistration, error) {
	var value DecisionOwnershipRegistration
	if !idPattern.MatchString(id) {
		return value, ErrDecisionOwnershipEvidence
	}
	err := r.transaction(ctx, func(tx pgx.Tx) error {
		var raw []byte
		if err := tx.QueryRow(ctx, "SELECT public.commitment_ownership_registration($1,$2)", r.worker.Tenant, id).Scan(&raw); err != nil {
			return ownershipReadError(err)
		}
		if len(raw) == 0 || string(raw) == "null" {
			return ErrDecisionOwnershipAbsent
		}
		return decodeOwnershipRegistration(raw, &value)
	})
	return value, err
}

func decodeOwnershipRegistration(raw []byte, out *DecisionOwnershipRegistration) error {
	if err := decodeDecisionPrivate(raw, out, 8192); err != nil {
		return err
	}
	out.IssuedDocumentSHA256 = Hash(documentFromRaw(raw))
	return nil
}

func (r postgresDecisionOwnershipReader) OwnershipReview(ctx context.Context, query DecisionOwnershipQuery) (DecisionOwnershipStoredEnvelope, error) {
	var value DecisionOwnershipStoredEnvelope
	if !ownershipScope(query.Scope) || !ownershipPeriod(query.Period) || query.Scope.TenantID != r.worker.Tenant {
		return value, ErrDecisionOwnershipEvidence
	}
	err := r.transaction(ctx, func(tx pgx.Tx) error {
		value.Reference.Kind = "OWNERSHIP_REVIEW"
		return ownershipReadError(tx.QueryRow(ctx, "SELECT id,envelope_sha256,server_recorded_at,raw_envelope FROM public.commitment_ownership_review($1,$2,$3,$4,$5)", r.worker.Tenant, query.Scope.WorkloadID, Hash(query.Scope), query.Period.Start, query.Period.End).Scan(&value.Reference.ID, &value.Reference.SHA256, &value.ServerRecordedAt, &value.RawEnvelope))
	})
	return value, err
}

func (r postgresDecisionOwnershipReader) OwnershipJournalPage(ctx context.Context, query DecisionOwnershipQuery, registrationID, cursor string) (DecisionOwnershipPage, error) {
	page := DecisionOwnershipPage{Items: []DecisionOwnershipStoredEnvelope{}}
	if !ownershipScope(query.Scope) || !ownershipPeriod(query.Period) || query.Scope.TenantID != r.worker.Tenant || !idPattern.MatchString(registrationID) {
		return page, ErrDecisionOwnershipEvidence
	}
	after := ownershipPageCursor{QuerySHA256: Hash(query), Registration: registrationID}
	if cursor != "" {
		raw, err := base64.RawURLEncoding.DecodeString(cursor)
		if err != nil || len(raw) > 1024 || decodeDecisionPrivate(raw, &after, 1024) != nil || after.QuerySHA256 != Hash(query) || after.Registration != registrationID || !idPattern.MatchString(after.Resource) || after.Sequence < 1 {
			return page, ErrDecisionOwnershipEvidence
		}
	}
	resources := make([]string, 0, len(query.Scope.Resources))
	for _, resource := range query.Scope.Resources {
		resources = append(resources, resource.ResourceID)
	}
	err := r.transaction(ctx, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, "SELECT id,envelope_sha256,server_recorded_at,raw_envelope,resource_id,sequence FROM public.commitment_ownership_journal_page($1,$2,$3,$4,$5,$6,$7,$8,$9)", r.worker.Tenant, query.Scope.WorkloadID, Hash(query.Scope), registrationID, query.Period.Start, query.Period.End, resources, after.Resource, after.Sequence)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var value DecisionOwnershipStoredEnvelope
			var resource string
			var sequence int64
			value.Reference.Kind = "OWNERSHIP_JOURNAL"
			if err = rows.Scan(&value.Reference.ID, &value.Reference.SHA256, &value.ServerRecordedAt, &value.RawEnvelope, &resource, &sequence); err != nil {
				return err
			}
			if len(page.Items) == 256 {
				return ErrDecisionOwnershipEvidence
			}
			page.Items = append(page.Items, value)
			after.Resource, after.Sequence = resource, sequence
		}
		if err = rows.Err(); err != nil {
			return err
		}
		if len(page.Items) == 256 {
			raw, _ := json.Marshal(after)
			page.NextCursor = base64.RawURLEncoding.EncodeToString(raw)
		}
		return nil
	})
	return page, err
}

func (r postgresDecisionOwnershipReader) OwnershipArtifact(ctx context.Context, reference Ref, archive configuration.ArtifactArchiveRef) (configuration.ArtifactReceipt, []byte, error) {
	var receipt configuration.ArtifactReceipt
	var ciphertext []byte
	if !ownershipRef(reference, "CONFIGURATION_ARTIFACT") || !ownershipArchive(archive, r.worker.Tenant) {
		return receipt, nil, ErrDecisionOwnershipEvidence
	}
	err := r.transaction(ctx, func(tx pgx.Tx) error {
		var raw []byte
		archiveJSON, err := json.Marshal(archive)
		if err != nil {
			return err
		}
		if err = tx.QueryRow(ctx, "SELECT receipt,ciphertext FROM public.commitment_ownership_artifact($1,$2,$3,$4::jsonb)", r.worker.Tenant, reference.ID, reference.SHA256, archiveJSON).Scan(&raw, &ciphertext); err != nil {
			return ownershipReadError(err)
		}
		if len(ciphertext) > 8<<20 {
			return ErrDecisionOwnershipEvidence
		}
		return decodeDecisionPrivate(raw, &receipt, 128<<10)
	})
	return receipt, ciphertext, err
}

func (r postgresDecisionOwnershipReader) OwnershipDeployment(ctx context.Context, reference Ref) (DecisionOwnershipDeployment, error) {
	var value DecisionOwnershipDeployment
	if !ownershipRef(reference, "DEPLOYMENT_RECEIPT") {
		return value, ErrDecisionOwnershipEvidence
	}
	err := r.transaction(ctx, func(tx pgx.Tx) error {
		var raw []byte
		var body DecisionOwnershipDeploymentObservation
		if err := tx.QueryRow(ctx, "SELECT raw_body,body_sha256,issuer,subject,audience,server_recorded_at FROM public.commitment_ownership_deployment($1,$2,$3)", r.worker.Tenant, reference.ID, reference.SHA256).Scan(&raw, &value.Reference.SHA256, &value.Issuer, &value.Subject, &value.Audience, &value.ServerRecordedAt); err != nil {
			return ownershipReadError(err)
		}
		if !ownershipCanonical(raw, &body, 16<<10) || body.ID != reference.ID || ownershipBytesHash(raw) != reference.SHA256 {
			return ErrDecisionOwnershipEvidence
		}
		value.Reference.Kind, value.Reference.ID = "DEPLOYMENT_RECEIPT", body.ID
		value.TenantID, value.WorkloadID, value.Resource, value.ObservedAt = body.TenantID, body.WorkloadID, body.Resource, body.ObservedAt
		return nil
	})
	return value, err
}

// publishDecisionOwnership accepts only a verified private factory result and
// binds it to the still-current queued preparation. The SQL function independently
// repeats registration, source, resource and artifact pins under shared fences.
func (w *Worker) publishDecisionOwnership(ctx context.Context, requestID string, evidence DecisionOwnershipEvidence) (Ref, error) {
	reference, err := evidence.HistoricalReference()
	if err != nil || !idPattern.MatchString(requestID) || evidence.Scope.TenantID != w.Tenant {
		return Ref{}, ErrDecisionOwnershipEvidence
	}
	tx, err := w.begin(ctx)
	if err != nil {
		return Ref{}, err
	}
	defer tx.Rollback(ctx)
	raw, err := json.Marshal(evidence)
	if err != nil || len(raw) > 1<<20 {
		return Ref{}, ErrDecisionOwnershipEvidence
	}
	var hash string
	if err = tx.QueryRow(ctx, "SELECT public.commitment_ownership_publish($1,$2,$3::jsonb)", w.Tenant, requestID, raw).Scan(&hash); err != nil {
		return Ref{}, err
	}
	if hash != reference.SHA256 {
		return Ref{}, ErrDecisionOwnershipEvidence
	}
	if err = tx.Commit(ctx); err != nil {
		return Ref{}, err
	}
	return reference, nil
}
