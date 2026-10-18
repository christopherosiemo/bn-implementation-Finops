package source

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
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
	"github.com/jackc/pgx/v5"
)

const HardwareKind = "AWS_EC2_HARDWARE"

type HardwareReader interface {
	HardwareInventory(context.Context, string, string, string, []string) (provider.HardwareEvidence, error)
}

// HardwareTarget is private ingester configuration, never a public request.
// It pins account/resource scope and a bounded candidate allowlist, not prices.
type HardwareTarget struct {
	Binding        telemetry.Binding `json:"binding"`
	SourceID       string            `json:"source_id"`
	CandidateTypes []string          `json:"candidate_types"`
}

func HardwareTargets(encoded string) (map[string]HardwareTarget, error) {
	out := map[string]HardwareTarget{}
	if strings.TrimSpace(encoded) == "" {
		return out, nil
	}
	if len(encoded) > 128<<10 {
		return nil, errors.New("HARDWARE_TARGETS_LIMIT")
	}
	var rows []HardwareTarget
	d := json.NewDecoder(strings.NewReader(encoded))
	d.DisallowUnknownFields()
	if d.Decode(&rows) != nil || d.Decode(&struct{}{}) != io.EOF || len(rows) > 64 {
		return nil, errors.New("HARDWARE_TARGETS_INVALID")
	}
	for _, target := range rows {
		b := target.Binding
		key := b.TenantID + ":" + b.ResourceID
		if target.SourceID == "" || b.TenantID == "" || b.ResourceID == "" || b.WorkloadID == "" || b.Provider != "AWS" || !accountPattern.MatchString(b.AccountID) || b.Region != "eu-west-1" || !fleetInstanceID.MatchString(b.ProviderResourceID) || len(target.CandidateTypes) > 99 {
			return nil, errors.New("HARDWARE_TARGET_BINDING_INVALID")
		}
		types, err := provider.HardwareTypeNames(target.CandidateTypes)
		if err != nil {
			return nil, err
		}
		if _, exists := out[key]; exists {
			return nil, errors.New("HARDWARE_TARGET_DUPLICATE")
		}
		target.CandidateTypes = types
		out[key] = target
	}
	return out, nil
}
func HardwareAWSFactory(encoded string) (func(context.Context, Registration, string) (HardwareReader, error), error) {
	bindings, err := ParseAWSBindings(encoded)
	if err != nil {
		return nil, err
	}
	return func(ctx context.Context, r Registration, account string) (HardwareReader, error) {
		b, err := fleetReadBinding(bindings, r, account)
		if err != nil {
			return nil, errors.New("HARDWARE_APPROVED_READ_BINDING_REQUIRED")
		}
		return provider.NewAWS(ctx, b.Region, b.RoleARN, b.ExternalID)
	}, nil
}

type HardwarePipeline struct {
	Store         *store.Store
	Targets       map[string]HardwareTarget
	ReaderFactory func(context.Context, Registration, string) (HardwareReader, error)
	Archive       func(context.Context, string, string, []byte) (model.Document, error)
	Now           func() time.Time
}

func (p *HardwarePipeline) now() time.Time {
	if p.Now != nil {
		return p.Now().UTC()
	}
	return time.Now().UTC()
}
func hardwareResourceBinding(tenant string, r model.Document) telemetry.Binding {
	return telemetry.Binding{TenantID: tenant, ResourceID: model.String(r, "id"), WorkloadID: model.String(r, "workload_id"), Provider: model.String(r, "provider"), ProviderResourceID: model.String(r, "provider_resource_id"), AccountID: model.String(r, "account_id"), Region: model.String(r, "region")}
}

// Capture performs native read-only calls, archives exact bytes, then publishes
// under the ingestion identity only if registration and inventory still match.
func (p *HardwarePipeline) Capture(ctx context.Context, tenant, resource string) (model.Document, error) {
	if p.Store == nil || p.ReaderFactory == nil || p.Archive == nil {
		return nil, errors.New("HARDWARE_PIPELINE_DEPENDENCIES_REQUIRED")
	}
	target, ok := p.Targets[tenant+":"+resource]
	if !ok || target.Binding.TenantID != tenant || target.Binding.ResourceID != resource {
		return nil, errors.New("HARDWARE_APPROVED_TARGET_REQUIRED")
	}
	// Validate even a directly constructed private configuration.
	encoded, _ := json.Marshal([]HardwareTarget{target})
	if _, err := HardwareTargets(string(encoded)); err != nil {
		return nil, err
	}
	var registration, inventory model.Document
	err := p.Store.Do(ctx, tenant, func(tx *store.Tx) error {
		var e error
		registration, e = tx.SourceGet(ctx, target.SourceID)
		if e != nil {
			return e
		}
		inventory, e = tx.Get(ctx, "resources", resource)
		return e
	})
	if err != nil {
		return nil, err
	}
	r, err := ParseRegistration(registration)
	if err != nil || !r.Enabled || model.Bool(registration, "revoked") || r.TenantID != tenant || hardwareResourceBinding(tenant, inventory) != target.Binding {
		return nil, errors.New("HARDWARE_SOURCE_OR_INVENTORY_BINDING_INVALID")
	}
	approved := r.PayerAccountID == target.Binding.AccountID
	for _, account := range r.UsageAccountIDs {
		approved = approved || account == target.Binding.AccountID
	}
	if !approved || r.Region != target.Binding.Region {
		return nil, errors.New("HARDWARE_ACCOUNT_OUTSIDE_REGISTERED_SOURCE")
	}
	reader, err := p.ReaderFactory(ctx, r, target.Binding.AccountID)
	if err != nil {
		return nil, err
	}
	readCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	native, err := reader.HardwareInventory(readCtx, target.Binding.Region, target.Binding.AccountID, target.Binding.ProviderResourceID, target.CandidateTypes)
	cancel()
	if err != nil {
		return nil, err
	}
	if native.AccountID != target.Binding.AccountID || native.Region != target.Binding.Region || native.CollectedAt.Before(p.now().Add(-2*time.Minute)) || native.CollectedAt.After(p.now().Add(5*time.Second)) || native.Instance.Type != model.String(inventory, "instance_type") {
		return nil, errors.New("HARDWARE_NATIVE_SNAPSHOT_STALE_OR_CHANGED")
	}
	if err = provider.ValidateHardwareEvidence(native, target.Binding.ProviderResourceID, target.CandidateTypes); err != nil {
		return nil, err
	}
	ref, err := p.Archive(ctx, tenant, resource, native.Raw)
	if err != nil {
		return nil, err
	}
	if model.String(ref, "bucket") == "" || !strings.HasPrefix(model.String(ref, "key"), "tenant/"+tenant+"/hardware/"+resource+"/") || strings.Contains(model.String(ref, "key"), "..") || model.String(ref, "version_id") == "" || model.String(ref, "version_id") == "null" || model.String(ref, "body_sha256") != native.RawSHA256 {
		return nil, errors.New("HARDWARE_VERSIONED_RAW_ARCHIVE_REQUIRED")
	}
	config := ConfigurationHash(registration)
	snapshotHash := telemetry.Hash(inventory)
	revisionHash := Hash(model.Document{"kind": HardwareKind, "source_id": target.SourceID, "registration_version": r.Version, "config_hash": config, "resource_snapshot_hash": snapshotHash, "raw_sha256": native.RawSHA256})
	revisionID := "hardware-rev-" + revisionHash
	document := model.Document{"id": "hardware-" + Hash(model.Document{"revision": revisionID, "collected_at": native.CollectedAt}), "kind": HardwareKind, "source_id": target.SourceID, "revision_id": revisionID, "registration_version": r.Version, "read_role_binding_id": r.ReadRoleBindingID, "config_hash": config, "binding": target.Binding, "resource_version": model.Number(inventory, "version"), "resource_snapshot_hash": snapshotHash, "inventory_snapshot": inventory, "candidate_types": target.CandidateTypes, "native": Object(native), "collected_at": native.CollectedAt, "raw_object": ref, "execution_authorized": false}
	raw, _ := json.Marshal(document)
	if len(raw) > 256<<10 {
		return nil, errors.New("HARDWARE_NATIVE_METADATA_LIMIT")
	}
	var result model.Document
	err = p.Store.Do(ctx, tenant, func(tx *store.Tx) error {
		if _, e := tx.Exec(ctx, "SELECT hardware_source_current_lock($1,$2)", tenant, target.SourceID); e != nil {
			return e
		}
		active, e := tx.SourceGet(ctx, target.SourceID)
		if e != nil {
			return e
		}
		current, e := tx.Get(ctx, "resources", resource)
		if e != nil {
			return e
		}
		if !model.Bool(active, "enabled") || model.Bool(active, "revoked") || model.Number(active, "version") != r.Version || ConfigurationHash(active) != config || telemetry.Hash(current) != snapshotHash || native.CollectedAt.Before(p.now().Add(-2*time.Minute)) {
			return errors.New("HARDWARE_SOURCE_CHANGED_DURING_CAPTURE")
		}
		if old, e := tx.SourceReceiptGet(ctx, model.String(document, "id")); e == nil {
			if model.String(old, "revision_id") != revisionID {
				return errors.New("HARDWARE_REPLAY_CONFLICT")
			}
			result = old
			return nil
		} else if e != pgx.ErrNoRows {
			return e
		}
		if _, e := tx.SourceRevisionGet(ctx, revisionID); e == pgx.ErrNoRows {
			if _, e = tx.SourceRevisionCreate(ctx, model.Document{"id": revisionID, "source_id": target.SourceID, "kind": HardwareKind, "registration_version": r.Version, "revision_hash": revisionHash, "config_hash": config, "resource_snapshot_hash": snapshotHash, "raw_object": ref, "observed_at": native.CollectedAt}); e != nil {
				return e
			}
		} else if e != nil {
			return e
		}
		if _, e := tx.SourceReceiptCreate(ctx, document); e != nil {
			return e
		}
		result, e = tx.SourceReceiptGet(ctx, model.String(document, "id"))
		return e
	})
	return result, err
}

type HardwareS3Archive struct {
	Client FleetS3Client
	Bucket string
}

func (a *HardwareS3Archive) Archive(ctx context.Context, tenant, resource string, raw []byte) (model.Document, error) {
	if a.Client == nil || !bucketPattern.MatchString(a.Bucket) || !fleetObjectPart.MatchString(tenant) || !fleetObjectPart.MatchString(resource) || len(raw) == 0 || len(raw) > 32<<20 {
		return nil, errors.New("HARDWARE_ARCHIVE_SCOPE_INVALID")
	}
	digest := BytesHash(raw)
	key := "tenant/" + tenant + "/hardware/" + resource + "/" + digest + ".bin"
	sum := sha256.Sum256(raw)
	put, err := a.Client.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(a.Bucket), Key: aws.String(key), Body: bytes.NewReader(raw), ContentType: aws.String("application/octet-stream"), ChecksumSHA256: aws.String(base64.StdEncoding.EncodeToString(sum[:]))})
	if err != nil || put == nil {
		return nil, errors.New("HARDWARE_RAW_ARCHIVE_FAILED")
	}
	version := aws.ToString(put.VersionId)
	if version == "" || version == "null" {
		return nil, errors.New("HARDWARE_RAW_VERSION_REQUIRED")
	}
	get, err := a.Client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(a.Bucket), Key: aws.String(key), VersionId: aws.String(version)})
	if err != nil || get == nil || get.Body == nil {
		return nil, errors.New("HARDWARE_RAW_READBACK_FAILED")
	}
	defer get.Body.Close()
	body, err := io.ReadAll(io.LimitReader(get.Body, (32<<20)+1))
	if err != nil || len(body) > 32<<20 || aws.ToString(get.VersionId) != version || BytesHash(body) != digest {
		return nil, errors.New("HARDWARE_RAW_READBACK_MISMATCH")
	}
	return model.Document{"bucket": a.Bucket, "key": key, "version_id": version, "body_sha256": digest}, nil
}
