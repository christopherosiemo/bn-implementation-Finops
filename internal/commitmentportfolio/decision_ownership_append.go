package commitmentportfolio

import (
	"bytes"
	"context"
	"math"
	"time"

	"github.com/jackc/pgx/v5"
)

// AppendDecisionOwnership is private deployment-observer ingress. Identity is
// the already verified dedicated OIDC principal, never a field from the body.
// The database independently stamps its clock and fences operator revocation.
func AppendDecisionOwnership(ctx context.Context, tx pgx.Tx, tenant, issuer, subject, audience, kind string, raw []byte) (DecisionOwnershipStoredEnvelope, bool, error) {
	if kind == "DEPLOYMENT" {
		return appendDecisionOwnershipDeployment(ctx, tx, tenant, issuer, subject, audience, raw)
	}
	var out DecisionOwnershipStoredEnvelope
	var id, registrationID, workload string
	var revision int64
	var signature, algorithm string
	var signing []byte
	var sequence uint64
	var resource string
	if kind != "JOURNAL" && kind != "REVIEW" || !tenantPattern.MatchString(tenant) || issuer == "" || subject == "" || audience != "finops-deployment-observer" {
		return out, false, ErrDecisionOwnershipEvidence
	}
	var role, isolation string
	if tx.QueryRow(ctx, "SELECT current_user,current_setting('transaction_isolation')").Scan(&role, &isolation) != nil || role != "finops_deployment_observer" || isolation != "read committed" {
		return out, false, ErrDecisionOwnershipEvidence
	}
	if kind == "JOURNAL" {
		var envelope DecisionOwnershipJournalEnvelope
		if !ownershipCanonical(raw, &envelope, 16<<10) {
			return out, false, ErrDecisionOwnershipEvidence
		}
		body := envelope.Journal
		if body.TenantID != tenant || body.SchemaVersion != "1" || !idPattern.MatchString(body.ID) || !idPattern.MatchString(body.WorkloadID) || !idPattern.MatchString(body.Resource.ResourceID) || body.Sequence == 0 || body.Sequence > math.MaxInt64 || !ownershipPeriod(body.Period) || body.Period.End.Sub(body.Period.Start) > time.Hour {
			return out, false, ErrDecisionOwnershipEvidence
		}
		id, registrationID, revision, workload, signature, algorithm, sequence, resource = body.ID, body.RegistrationID, body.RegistrationRevision, body.WorkloadID, envelope.Signature, envelope.Algorithm, body.Sequence, body.Resource.ResourceID
		signing, _ = DecisionOwnershipJournalSigningBytes(body)
	} else {
		var envelope DecisionOwnershipReviewEnvelope
		if !ownershipCanonical(raw, &envelope, 64<<10) {
			return out, false, ErrDecisionOwnershipEvidence
		}
		body := envelope.Review
		if body.TenantID != tenant || body.SchemaVersion != "1" || !idPattern.MatchString(body.ID) || !idPattern.MatchString(body.WorkloadID) || len(body.Heads) == 0 || len(body.Heads) > 128 || !ownershipPeriod(body.Period) {
			return out, false, ErrDecisionOwnershipEvidence
		}
		id, registrationID, revision, workload, signature, algorithm = body.ID, body.RegistrationID, body.RegistrationRevision, body.WorkloadID, envelope.Signature, envelope.Algorithm
		signing, _ = DecisionOwnershipReviewSigningBytes(body)
	}
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock_shared(hashtextextended($1,0)),pg_advisory_xact_lock(hashtextextended($2,0))", tenant+":commitment-ownership-key:"+registrationID, tenant+":commitment-ownership-envelope:"+kind+":"+id); err != nil {
		return out, false, err
	}
	var registrationRaw []byte
	err := tx.QueryRow(ctx, `SELECT r.document||jsonb_build_object('revoked_at',(SELECT v.created_at FROM commitment_ownership_revocations v WHERE v.tenant_id=r.tenant_id AND v.registration_id=r.id AND v.revision=r.revision)) FROM commitment_ownership_registrations r WHERE tenant_id=$1 AND id=$2 ORDER BY revision DESC LIMIT 1`, tenant, registrationID).Scan(&registrationRaw)
	if err != nil {
		return out, false, err
	}
	var registration DecisionOwnershipRegistration
	if decodeDecisionPrivate(registrationRaw, &registration, 8192) != nil {
		return out, false, ErrDecisionOwnershipEvidence
	}
	purpose := "DEPLOYMENT_JOURNAL"
	expectedAlgorithm := ownershipJournalAlgorithm
	table := "commitment_ownership_journals"
	refKind := "OWNERSHIP_JOURNAL"
	if kind == "REVIEW" {
		purpose = "OWNERSHIP_REVIEW"
		expectedAlgorithm = ownershipReviewAlgorithm
		table = "commitment_ownership_reviews"
		refKind = "OWNERSHIP_REVIEW"
	}
	var now time.Time
	if err = tx.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&now); err != nil {
		return out, false, err
	}
	if registration.Revision != revision || registration.Issuer != issuer || registration.Subject != subject || registration.Audience != audience || registration.Purpose != purpose || registration.RevokedAt != nil || now.Before(registration.ValidFrom) || !now.Before(registration.ValidUntil) || algorithm != expectedAlgorithm || !ownershipSignature(registration.PublicKey, signing, signature) {
		return out, false, ErrDecisionOwnershipEvidence
	}
	// Only these two fixed table names reach this statement; none is API input.
	var existing []byte
	var storedIssuer, storedSubject, storedAudience string
	err = tx.QueryRow(ctx, "SELECT raw_envelope,server_recorded_at,envelope_sha256,issuer,subject,audience FROM "+table+" WHERE tenant_id=$1 AND id=$2", tenant, id).Scan(&existing, &out.ServerRecordedAt, &out.Reference.SHA256, &storedIssuer, &storedSubject, &storedAudience)
	if err == nil {
		if !bytes.Equal(existing, raw) || storedIssuer != issuer || storedSubject != subject || storedAudience != audience {
			return out, false, ErrDecisionOwnershipEvidence
		}
		out.Reference.Kind = refKind
		out.Reference.ID = id
		out.RawEnvelope = existing
		return out, true, nil
	}
	if err != pgx.ErrNoRows {
		return out, false, err
	}
	if kind == "JOURNAL" {
		err = tx.QueryRow(ctx, "INSERT INTO commitment_ownership_journals(tenant_id,id,registration_id,registration_revision,workload_id,resource_id,sequence,issuer,subject,audience,raw_envelope,envelope_sha256) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'') RETURNING server_recorded_at,envelope_sha256", tenant, id, registrationID, revision, workload, resource, int64(sequence), issuer, subject, audience, raw).Scan(&out.ServerRecordedAt, &out.Reference.SHA256)
	} else {
		err = tx.QueryRow(ctx, "INSERT INTO commitment_ownership_reviews(tenant_id,id,registration_id,registration_revision,workload_id,issuer,subject,audience,raw_envelope,envelope_sha256) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,'') RETURNING server_recorded_at,envelope_sha256", tenant, id, registrationID, revision, workload, issuer, subject, audience, raw).Scan(&out.ServerRecordedAt, &out.Reference.SHA256)
	}
	if err != nil {
		return out, false, err
	}
	out.Reference.Kind = refKind
	out.Reference.ID = id
	out.RawEnvelope = append([]byte{}, raw...)
	return out, false, nil
}
