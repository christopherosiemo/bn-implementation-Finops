package commitmentarchive

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"

	portfolio "github.com/christopherosiemo/bn-implementation-Finops/internal/commitmentportfolio"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/source"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/jackc/pgx/v5"
)

// This repository belongs to the existing approved ingestion identity. Archive
// must use the ordinary immutable write+version-readback path, before any DB
// witness is issued. The analyst receives neither this callback nor AWS keys.
type PostgresRepository struct {
	Store   *store.Store
	Tenant  string
	Archive func(context.Context, string, string, []byte) (model.Document, error)
	// ArchiveReview has the same immutable version readback contract as Archive,
	// with a separate 24MiB review limit instead of the 64KiB object limit.
	ArchiveReview     func(context.Context, string, string, []byte) (model.Document, error)
	ReadCurrentBucket func(context.Context, portfolio.DecisionOwnershipArchiveRegistration) (map[string]any, error)
}

func archiveProjection(raw []byte, out any) (string, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var projection any
	if decoder.Decode(&projection) != nil || json.Unmarshal(raw, out) != nil {
		return "", errors.New("OWNERSHIP_ARCHIVE_PROJECTION_INVALID")
	}
	return portfolio.Hash(projection), nil
}

func (r *PostgresRepository) ArchiveRegistration(ctx context.Context, id string) (portfolio.DecisionOwnershipArchiveRegistration, error) {
	var result portfolio.DecisionOwnershipArchiveRegistration
	if r == nil || r.Store == nil || r.Tenant == "" {
		return result, errors.New("OWNERSHIP_ARCHIVE_REPOSITORY_REQUIRED")
	}
	err := r.Store.Do(ctx, r.Tenant, func(tx *store.Tx) error {
		var raw []byte
		if e := tx.QueryRow(ctx, "SELECT public.commitment_archive_source($1,$2)", r.Tenant, id).Scan(&raw); e != nil {
			return e
		}
		sha, e := archiveProjection(raw, &result)
		result.IssuedDocumentSHA256 = sha
		return e
	})
	return result, err
}

func (r *PostgresRepository) ArchiveReviewRegistration(ctx context.Context, id string) (portfolio.DecisionOwnershipRegistration, error) {
	var result portfolio.DecisionOwnershipRegistration
	if r == nil || r.Store == nil || r.Tenant == "" {
		return result, errors.New("OWNERSHIP_ARCHIVE_REPOSITORY_REQUIRED")
	}
	err := r.Store.Do(ctx, r.Tenant, func(tx *store.Tx) error {
		var raw []byte
		if e := tx.QueryRow(ctx, "SELECT public.commitment_archive_review_registration($1,$2)", r.Tenant, id).Scan(&raw); e != nil {
			return e
		}
		sha, e := archiveProjection(raw, &result)
		result.IssuedDocumentSHA256 = sha
		return e
	})
	return result, err
}

func (r *PostgresRepository) PersistArchiveWitness(ctx context.Context, registration portfolio.DecisionOwnershipArchiveRegistration, witness portfolio.DecisionOwnershipArchiveWitness, raw []byte) (portfolio.Ref, error) {
	var result portfolio.Ref
	if r == nil || r.Store == nil || r.Archive == nil || r.Tenant == "" || witness.TenantID != r.Tenant || registration.TenantID != r.Tenant || witness.SourceRegistrationSHA256 != registration.IssuedDocumentSHA256 || int64(len(raw)) != witness.Pin.Bytes || len(raw) == 0 || len(raw) > 64<<10 || source.BytesHash(raw) != witness.Pin.SHA256 {
		return result, errors.New("OWNERSHIP_ARCHIVE_RAW_EVIDENCE_REQUIRED")
	}
	archive, err := r.Archive(ctx, r.Tenant, registration.ID, raw)
	if err != nil {
		return result, err
	}
	if model.String(archive, "body_sha256") != witness.Pin.SHA256 {
		return result, errors.New("OWNERSHIP_ARCHIVE_VERSION_READBACK_REQUIRED")
	}
	wire, err := json.Marshal(witness)
	if err != nil {
		return result, err
	}
	archiveRaw, err := json.Marshal(archive)
	if err != nil {
		return result, err
	}
	id := portfolio.Hash(witness)
	err = r.persistWitnessTransaction(ctx, registration, id, wire, raw, archiveRaw)
	if err != nil {
		return result, err
	}
	return portfolio.Ref{Kind: "AWS_OWNERSHIP_ARCHIVE_OBJECT", ID: id, SHA256: id}, nil
}

// Pipeline the commands for ONE witness, without batching witness commits.
// The explicit transaction retains the source fence and local tenant context
// through the exact-row check. No reference escapes until COMMIT succeeds.
func (r *PostgresRepository) persistWitnessTransaction(ctx context.Context, registration portfolio.DecisionOwnershipArchiveRegistration, id string, wire, raw, archiveRaw []byte) error {
	conn, err := r.Store.Pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	// An error, mismatch or cancellation rolls back before the connection is
	// reused. pgxpool also destroys any connection released with a non-idle
	// transaction, including when cancellation prevents this rollback.
	committed := false
	defer func() {
		if !committed {
			_, _ = conn.Exec(ctx, "ROLLBACK")
		}
	}()
	batch := &pgx.Batch{}
	batch.Queue("BEGIN")
	batch.Queue("SELECT set_config('app.tenant_id',$1,true)", r.Tenant)
	batch.Queue("INSERT INTO commitment_ownership_archive_witnesses(tenant_id,id,source_id,source_revision,source_hash,resource_id,sequence,period_start,period_end,document,content_hash,raw_envelope,archive) VALUES($1,$2,$3,$4,$5,'',0,clock_timestamp(),clock_timestamp(),$6,'',$7,$8) ON CONFLICT(tenant_id,id) DO NOTHING", r.Tenant, id, registration.ID, registration.Revision, registration.IssuedDocumentSHA256, wire, raw, archiveRaw)
	batch.Queue("SELECT document=$3::jsonb AND raw_envelope=$4 AND content_hash=$2 FROM commitment_ownership_archive_witnesses WHERE tenant_id=$1 AND id=$2", r.Tenant, id, wire, raw)
	results := conn.SendBatch(ctx, batch)
	for i := 0; i < 3; i++ {
		if _, err := results.Exec(); err != nil {
			_ = results.Close()
			return err
		}
	}
	var exact bool
	err = results.QueryRow().Scan(&exact)
	closeErr := results.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if !exact {
		return errors.New("OWNERSHIP_ARCHIVE_IMMUTABLE_WITNESS_CONFLICT")
	}
	tag, err := conn.Exec(ctx, "COMMIT")
	if err != nil {
		return err
	}
	if tag.String() != "COMMIT" {
		return pgx.ErrTxCommitRollback
	}
	committed = true
	return nil
}

func (r *PostgresRepository) PublishArchiveEvidence(ctx context.Context, registration portfolio.DecisionOwnershipArchiveRegistration, value portfolio.DecisionOwnershipArchiveEvidence, rawReview []byte) error {
	if r == nil || r.Store == nil || r.ArchiveReview == nil || r.Tenant == "" || registration.TenantID != r.Tenant || value.Query.Scope.TenantID != r.Tenant || value.RegistrationSHA256 != registration.IssuedDocumentSHA256 || len(rawReview) == 0 || len(rawReview) > 24<<20 || source.BytesHash(rawReview) != value.ReviewSHA256 {
		return errors.New("OWNERSHIP_ARCHIVE_PUBLICATION_SCOPE_INVALID")
	}
	reviewArchive, err := r.ArchiveReview(ctx, r.Tenant, registration.ID, rawReview)
	if err != nil {
		return err
	}
	if model.String(reviewArchive, "body_sha256") != value.ReviewSHA256 {
		return errors.New("OWNERSHIP_ARCHIVE_REVIEW_READBACK_REQUIRED")
	}
	reviewArchiveRaw, err := json.Marshal(reviewArchive)
	if err != nil {
		return err
	}
	if err := r.RefreshArchiveSource(ctx, registration); err != nil {
		return err
	}
	wire, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return r.Store.Do(ctx, r.Tenant, func(tx *store.Tx) error {
		_, e := tx.Exec(ctx, "INSERT INTO commitment_ownership_archive_evidence(tenant_id,id,source_id,source_revision,workload_id,document,content_hash,raw_review,raw_review_archive) VALUES($1,$2,$3,$4,$5,$6,'',$7,$8) ON CONFLICT(tenant_id,id) DO NOTHING", r.Tenant, value.ID, registration.ID, registration.Revision, value.Query.Scope.WorkloadID, wire, rawReview, reviewArchiveRaw)
		if e != nil {
			return e
		}
		var exact bool
		if e = tx.QueryRow(ctx, "SELECT document=$3::jsonb AND raw_review=$4 FROM commitment_ownership_archive_evidence WHERE tenant_id=$1 AND id=$2", r.Tenant, value.ID, wire, rawReview).Scan(&exact); e != nil {
			return e
		}
		if !exact {
			return errors.New("OWNERSHIP_ARCHIVE_IMMUTABLE_PUBLICATION_CONFLICT")
		}
		return nil
	})
}

// RefreshArchiveSource acquires an actual approved native bucket read. The
// retained snapshot expires; the analyst never upgrades a registration hash
// into a fresh S3 permission/policy observation.
func (r *PostgresRepository) RefreshArchiveSource(ctx context.Context, registration portfolio.DecisionOwnershipArchiveRegistration) error {
	if r == nil || r.Store == nil || r.ReadCurrentBucket == nil || r.Tenant == "" || registration.TenantID != r.Tenant {
		return errors.New("OWNERSHIP_ARCHIVE_NATIVE_SOURCE_READER_REQUIRED")
	}
	document, err := r.ReadCurrentBucket(ctx, registration)
	if err != nil {
		return err
	}
	wire, err := json.Marshal(document)
	if err != nil {
		return err
	}
	id := portfolio.Hash(map[string]any{"source_registration_sha256": registration.IssuedDocumentSHA256, "document": document})
	return r.Store.Do(ctx, r.Tenant, func(tx *store.Tx) error {
		_, err := tx.Exec(ctx, "INSERT INTO commitment_ownership_archive_source_checks(tenant_id,id,source_id,source_revision,source_hash,document) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(tenant_id,id) DO NOTHING", r.Tenant, id, registration.ID, registration.Revision, registration.IssuedDocumentSHA256, wire)
		return err
	})
}
