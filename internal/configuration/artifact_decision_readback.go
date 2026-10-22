package configuration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5"
)

// This optional repository extension is invoked only after the existing private
// artifact pipeline reread, decrypted and revalidated the exact archive version.
// It retains ciphertext, never plaintext or keys. Historical consumers use a
// retained authenticated snapshot, not a fresh S3 permission claim.
type artifactDecisionReadbackRepository interface {
	RecordDecisionReadback(context.Context, ArtifactRegistration, ArtifactReceipt, []byte, ArtifactBundle) error
}

func (r *ArtifactPostgresRepository) RecordDecisionReadback(ctx context.Context, registration ArtifactRegistration, receipt ArtifactReceipt, ciphertext []byte, bundle ArtifactBundle) error {
	// Larger legacy artifacts remain usable by their existing path. The bounded
	// commitment-history reader reports a missing supported readback proof.
	if len(ciphertext) > 8<<20 {
		return nil
	}
	if len(ciphertext) == 0 || int64(len(ciphertext)) != receipt.Archive.Bytes || artifactBytesHash(ciphertext) != receipt.Archive.SHA256 {
		return errors.New("CONFIGURATION_ARTIFACT_DECISION_READBACK_INVALID")
	}
	// Unsupported mappings retain their original observable artifact/readback,
	// but cannot establish a new commitment decision's configuration baseline.
	var resourceBinding any
	if binding, err := artifactDecisionBinding(registration, bundle, receipt.Metadata); err == nil {
		resourceBinding = binding
	}
	bindingJSON, err := json.Marshal(resourceBinding)
	if err != nil {
		return err
	}
	return r.transaction(ctx, receipt.Metadata.Binding.TenantID, func(tx pgx.Tx) error {
		var installed bool
		if err := tx.QueryRow(ctx, "SELECT to_regclass('public.configuration_artifact_readback_proofs') IS NOT NULL").Scan(&installed); err != nil {
			return err
		}
		if !installed {
			return nil
		}
		archive, err := json.Marshal(receipt.Archive)
		if err != nil {
			return err
		}
		typedReceipt, err := json.Marshal(receipt)
		if err != nil {
			return err
		}
		// The historical consumer uses the existing portfolio sorted-map hash.
		// Preserve all legacy artifactHash signatures; this new cache stores a
		// separate canonical receipt hash over exactly the attestor-returned bytes.
		var projection any
		decoder := json.NewDecoder(bytes.NewReader(typedReceipt))
		decoder.UseNumber()
		if err = decoder.Decode(&projection); err != nil {
			return err
		}
		canonical, err := json.Marshal(projection)
		if err != nil {
			return err
		}
		receiptSHA := artifactBytesHash(canonical)
		_, err = tx.Exec(ctx, "INSERT INTO configuration_artifact_readback_proofs(tenant_id,receipt_id,registration_id,registration_version,receipt_sha256,metadata_sha256,archive,ciphertext,receipt,resource_binding) VALUES($1,$2,$3,$4,$5,'',$6,$7,$8,NULLIF($9::jsonb,'null'::jsonb)) ON CONFLICT(tenant_id,receipt_id) DO NOTHING", receipt.Metadata.Binding.TenantID, receipt.ID, receipt.Metadata.RegistrationID, receipt.Metadata.RegistrationVersion, receiptSHA, archive, ciphertext, typedReceipt, bindingJSON)
		if err != nil {
			return err
		}
		var exact bool
		err = tx.QueryRow(ctx, "SELECT receipt_sha256=$3 AND archive=$4::jsonb AND ciphertext=$5::bytea AND (resource_binding IS NULL OR resource_binding IS NOT DISTINCT FROM NULLIF($6::jsonb,'null'::jsonb)) FROM configuration_artifact_readback_proofs WHERE tenant_id=$1 AND receipt_id=$2", receipt.Metadata.Binding.TenantID, receipt.ID, receiptSHA, archive, ciphertext, bindingJSON).Scan(&exact)
		if err != nil {
			return err
		}
		if !exact {
			return ErrArtifactConflict
		}
		return nil
	})
}
