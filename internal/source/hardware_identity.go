package source

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/provider"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/telemetry"
)

const HardwareIdentityKind = "AWS_EC2_IDENTITY_DERIVATION"

// HardwareIdentityPipeline is private derivation from an already issued parent.
// No process or public route enables it by default. ReadObject must retrieve
// exactly the parent's immutable object version, never a latest-object fallback.
type HardwareIdentityPipeline struct {
	Store      *store.Store
	ReadObject func(context.Context, string, model.Document) ([]byte, error)
}

func hardwareIdentityParentHash(parent model.Document) string {
	d := model.Clone(parent)
	delete(d, "writer_role")
	delete(d, "created_at")
	return Hash(d)
}

func hardwareIdentityBinding(parent model.Document) (telemetry.Binding, error) {
	var b telemetry.Binding
	raw, err := json.Marshal(parent["binding"])
	if err != nil || json.Unmarshal(raw, &b) != nil || b.TenantID == "" || b.ResourceID == "" || b.WorkloadID == "" || b.Provider != "AWS" || b.Region != "eu-west-1" || !accountPattern.MatchString(b.AccountID) || !fleetInstanceID.MatchString(b.ProviderResourceID) || Hash(Object(b)) != Hash(parent["binding"]) {
		return b, errors.New("HARDWARE_IDENTITY_PARENT_BINDING_INVALID")
	}
	return b, nil
}

func hardwareIdentityParent(ctx context.Context, tx *store.Tx, receiptID string) (model.Document, error) {
	parent, err := tx.SourceReceiptGet(ctx, receiptID)
	if err != nil {
		return nil, err
	}
	if model.String(parent, "kind") != HardwareKind || model.String(parent, "writer_role") != "finops_ingester" {
		return nil, errors.New("HARDWARE_IDENTITY_ISSUED_PARENT_REQUIRED")
	}
	binding, err := hardwareIdentityBinding(parent)
	if err != nil || binding.TenantID != tx.Tenant {
		return nil, errors.New("HARDWARE_IDENTITY_PARENT_BINDING_INVALID")
	}
	if err = tx.HardwareIdentitySourceLock(ctx, model.String(parent, "source_id")); err != nil {
		return nil, err
	}
	registration, err := tx.SourceGet(ctx, model.String(parent, "source_id"))
	if err != nil {
		return nil, err
	}
	r, err := ParseRegistration(registration)
	if err != nil || !r.Enabled || model.Bool(registration, "revoked") || r.Version < model.Number(parent, "registration_version") || ConfigurationHash(registration) != model.String(parent, "config_hash") || r.ReadRoleBindingID != model.String(parent, "read_role_binding_id") {
		return nil, store.ErrHardwareIdentitySource
	}
	resource, err := tx.Get(ctx, "resources", binding.ResourceID)
	if err != nil {
		return nil, err
	}
	if hardwareResourceBinding(tx.Tenant, resource) != binding {
		return nil, errors.New("HARDWARE_IDENTITY_CURRENT_MAPPING_DIFFERS")
	}
	revision, err := tx.SourceRevisionGet(ctx, model.String(parent, "revision_id"))
	if err != nil {
		return nil, err
	}
	ref, rev := Object(parent["raw_object"]), Object(revision["raw_object"])
	if model.String(revision, "kind") != HardwareKind || model.String(revision, "writer_role") != "finops_ingester" || model.String(revision, "source_id") != r.ID || model.String(revision, "config_hash") != model.String(parent, "config_hash") || model.String(ref, "bucket") != model.String(rev, "bucket") || model.String(ref, "key") != model.String(rev, "key") || model.String(ref, "body_sha256") != model.String(rev, "body_sha256") || !bucketPattern.MatchString(model.String(ref, "bucket")) || !strings.HasPrefix(model.String(ref, "key"), "tenant/"+tx.Tenant+"/hardware/"+binding.ResourceID+"/") || strings.Contains(model.String(ref, "key"), "..") || strings.ContainsAny(model.String(ref, "key"), "\\\r\n\x00") || model.String(ref, "version_id") == "" || model.String(ref, "version_id") == "null" || model.String(rev, "version_id") == "" || model.String(rev, "version_id") == "null" {
		return nil, errors.New("HARDWARE_IDENTITY_PINNED_PARENT_REQUIRED")
	}
	return parent, nil
}

// Derive preserves original observation and receive times; the new row's
// created_at is its actual derivation publication time. Even exact writer replay
// rechecks current source configuration/revocation. Immutable reads remain reads.
func (p *HardwareIdentityPipeline) Derive(ctx context.Context, tenant, parentReceiptID string) (model.Document, error) {
	if p.Store == nil || p.ReadObject == nil {
		return nil, errors.New("HARDWARE_IDENTITY_DEPENDENCIES_REQUIRED")
	}
	var parent model.Document
	if err := p.Store.Do(ctx, tenant, func(tx *store.Tx) error {
		var err error
		parent, err = hardwareIdentityParent(ctx, tx, parentReceiptID)
		return err
	}); err != nil {
		return nil, err
	}
	binding, _ := hardwareIdentityBinding(parent)
	ref := Object(parent["raw_object"])
	readCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
	raw, err := p.ReadObject(readCtx, tenant, ref)
	cancel()
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 || len(raw) > 32<<20 || BytesHash(raw) != model.String(ref, "body_sha256") {
		return nil, errors.New("HARDWARE_IDENTITY_PARENT_BYTES_DIFFER")
	}
	var native provider.HardwareEvidence
	b, _ := json.Marshal(parent["native"])
	if json.Unmarshal(b, &native) != nil || native.CollectedAt.IsZero() || native.CollectedAt.After(time.Now().UTC().Add(5*time.Second)) {
		return nil, errors.New("HARDWARE_IDENTITY_PARENT_NATIVE_INVALID")
	}
	native.Raw = raw
	identity, err := provider.DecodeHardwareIdentityV2(native, binding.ProviderResourceID, model.Strings(parent, "candidate_types"))
	if err != nil {
		return nil, err
	}
	parentHash := hardwareIdentityParentHash(parent)
	doc := model.Document{"schema_version": "2", "kind": HardwareIdentityKind, "decoder_version": provider.HardwareIdentityDecoderV2, "tenant_id": tenant, "source_id": parent["source_id"], "source_config_hash": parent["config_hash"], "parent_receipt_id": parent["id"], "parent_revision_id": parent["revision_id"], "parent_canonical_hash": parentHash, "parent_hash_version": "GO_JSON_V1", "parent_registration_version": parent["registration_version"], "parent_collected_at": parent["collected_at"], "parent_received_at": parent["created_at"], "binding": parent["binding"], "raw_object": parent["raw_object"], "identity": Object(identity), "status": "OBSERVED_ONLY", "incarnation_status": "UNKNOWN", "interval_ownership": "UNPROVEN", "execution_authorized": false, "verified_saving": nil}
	var result model.Document
	err = p.Store.Do(ctx, tenant, func(tx *store.Tx) error {
		current, err := hardwareIdentityParent(ctx, tx, parentReceiptID)
		if err != nil {
			return err
		}
		if hardwareIdentityParentHash(current) != parentHash || Hash(current["raw_object"]) != Hash(ref) {
			return errors.New("HARDWARE_IDENTITY_PARENT_CHANGED_DURING_READ")
		}
		result, _, err = tx.HardwareIdentityAppend(ctx, doc)
		return err
	})
	return result, err
}

type HardwareIdentityS3Reader struct {
	Client FleetS3Client
	Bucket string
}

func (r *HardwareIdentityS3Reader) Read(ctx context.Context, tenant string, ref model.Document) ([]byte, error) {
	key, version := model.String(ref, "key"), model.String(ref, "version_id")
	if r.Client == nil || !bucketPattern.MatchString(r.Bucket) || model.String(ref, "bucket") != r.Bucket || !fleetObjectPart.MatchString(tenant) || !strings.HasPrefix(key, "tenant/"+tenant+"/hardware/") || strings.Contains(key, "..") || strings.ContainsAny(key, "\\\r\n\x00") || version == "" || version == "null" || len(model.String(ref, "body_sha256")) != 64 {
		return nil, errors.New("HARDWARE_IDENTITY_OBJECT_SCOPE_INVALID")
	}
	out, err := r.Client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(r.Bucket), Key: aws.String(key), VersionId: aws.String(version)})
	if err != nil || out == nil || out.Body == nil {
		return nil, errors.New("HARDWARE_IDENTITY_VERSION_READ_FAILED")
	}
	defer out.Body.Close()
	body, err := io.ReadAll(io.LimitReader(out.Body, (32<<20)+1))
	if err != nil || len(body) > 32<<20 || aws.ToString(out.VersionId) != version || BytesHash(body) != model.String(ref, "body_sha256") {
		return nil, errors.New("HARDWARE_IDENTITY_VERSION_READ_MISMATCH")
	}
	return body, nil
}
