package commitmentportfolio

import (
	"context"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/configuration"
	"github.com/jackc/pgx/v5"
)

// This is a customer deployment observation of an already attested artifact.
// It is neither a cloud ownership witness nor an execution/dispatch receipt.
// Only the registered observer's authenticated OIDC subject may append it.
type DecisionOwnershipDeploymentObservation struct {
	SchemaVersion        string                           `json:"schema_version"`
	ID                   string                           `json:"id"`
	RegistrationID       string                           `json:"registration_id"`
	RegistrationRevision int64                            `json:"registration_revision"`
	ScopeSHA256          string                           `json:"scope_sha256"`
	TenantID             string                           `json:"tenant_id"`
	WorkloadID           string                           `json:"workload_id"`
	Resource             DecisionOwnershipResource        `json:"resource"`
	ArtifactRef          Ref                              `json:"artifact_ref"`
	ArchiveRef           configuration.ArtifactArchiveRef `json:"archive_ref"`
	ObservedAt           time.Time                        `json:"observed_at"`
}

func appendDecisionOwnershipDeployment(ctx context.Context, tx pgx.Tx, tenant, issuer, subject, audience string, raw []byte) (DecisionOwnershipStoredEnvelope, bool, error) {
	var out DecisionOwnershipStoredEnvelope
	var body DecisionOwnershipDeploymentObservation
	if !ownershipCanonical(raw, &body, 16<<10) || body.SchemaVersion != "1" || body.TenantID != tenant || !idPattern.MatchString(body.ID) || !idPattern.MatchString(body.WorkloadID) || !idPattern.MatchString(body.RegistrationID) || body.RegistrationRevision < 1 || !shaPattern.MatchString(body.ScopeSHA256) || !ownershipRef(body.ArtifactRef, "CONFIGURATION_ARTIFACT") || !ownershipArchive(body.ArchiveRef, tenant) || !ownershipUTC(body.ObservedAt) || issuer == "" || subject == "" || audience != configuration.ObserverAudience {
		return out, false, ErrDecisionOwnershipEvidence
	}
	// The fixed function checks registered OIDC identity, live configuration,
	// exact ciphertext readback and replay bytes again inside the append fence.
	var replay bool
	err := tx.QueryRow(ctx, "SELECT envelope_sha256,server_recorded_at,replay FROM public.commitment_ownership_append_deployment($1,$2,$3,$4,$5)", tenant, issuer, subject, audience, raw).Scan(&out.Reference.SHA256, &out.ServerRecordedAt, &replay)
	if err != nil {
		return out, false, err
	}
	out.Reference.Kind, out.Reference.ID = "DEPLOYMENT_RECEIPT", body.ID
	out.RawEnvelope = append([]byte{}, raw...)
	return out, replay, nil
}
