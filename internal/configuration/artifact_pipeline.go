package configuration

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

type ArtifactPipeline struct {
	Repository ArtifactRepository
	Collector  ArtifactCollector
	Archive    ArtifactArchive
	Keys       ArtifactKeyProvider
	Fixture    bool
}

func (p *ArtifactPipeline) Capture(ctx context.Context, principal ArtifactPrincipal, registration, key string) (ArtifactReceipt, bool, error) {
	if p == nil || p.Repository == nil || p.Collector == nil || p.Archive == nil || p.Keys == nil || !artifactID.MatchString(registration) || len(key) < 8 || len(key) > 200 {
		return ArtifactReceipt{}, false, errors.New("CONFIGURATION_ARTIFACT_DEPENDENCIES_REQUIRED")
	}
	if !p.Fixture {
		local, ok := p.Collector.(*LocalArtifactCollector)
		if !ok {
			return ArtifactReceipt{}, false, errors.New("CONFIGURATION_ARTIFACT_ISOLATED_COLLECTOR_REQUIRED")
		}
		if _, ok = local.Tools.(*DockerArtifactTools); !ok {
			return ArtifactReceipt{}, false, errors.New("CONFIGURATION_ARTIFACT_ISOLATED_COLLECTOR_REQUIRED")
		}
		kms, kmsOK := p.Keys.(*ArtifactKMSKeys)
		if !kmsOK || !kms.valid() {
			return ArtifactReceipt{}, false, errors.New("CONFIGURATION_ARTIFACT_KMS_REQUIRED")
		}
	}
	reg, e := p.Repository.Current(ctx, principal.tenant, registration)
	if e != nil {
		return ArtifactReceipt{}, false, e
	}
	if e = ValidateArtifactRegistration(reg); e != nil {
		return ArtifactReceipt{}, false, e
	}
	if !artifactPrincipalMatches(principal, reg) {
		return ArtifactReceipt{}, false, errors.New("CONFIGURATION_ARTIFACT_MACHINE_BINDING_INVALID")
	}
	job, e := p.Repository.JobByKey(ctx, reg.Binding.TenantID, reg.ID, key)
	if e == nil {
		if _, checkpointErr := p.Repository.Archive(ctx, reg.Binding.TenantID, job.ID); checkpointErr == nil {
			return p.resume(ctx, reg, job, true)
		} else if !errors.Is(checkpointErr, pgx.ErrNoRows) {
			return ArtifactReceipt{}, false, checkpointErr
		}
	} else if !errors.Is(e, pgx.ErrNoRows) {
		return ArtifactReceipt{}, false, e
	}
	bundle, e := p.Collector.Collect(ctx, reg)
	if e != nil {
		return ArtifactReceipt{}, false, errors.New(artifactSafeReason(e))
	}
	meta, e := ValidateArtifactBundle(reg, bundle)
	if e != nil {
		return ArtifactReceipt{}, false, e
	}
	if p.Fixture {
		meta.ReasonCodes = artifactUnique(append(meta.ReasonCodes, "FIXTURE_ARTIFACT_CAPTURE"))
	}
	job, replay, e := p.Repository.Prepare(ctx, reg, key, meta)
	if e != nil {
		return ArtifactReceipt{}, false, e
	}
	if artifactHash(job.Metadata) != artifactHash(meta) {
		return ArtifactReceipt{}, false, ErrArtifactConflict
	}
	raw, e := json.Marshal(bundle)
	if e != nil {
		return ArtifactReceipt{}, false, errors.New("CONFIGURATION_ARTIFACT_BUNDLE_INVALID")
	}
	encrypted, e := artifactSeal(ctx, p.Keys, p.Fixture, reg.Binding.TenantID, job.ID, raw)
	if e != nil {
		return ArtifactReceipt{}, false, e
	}
	ref, e := p.Archive.Put(ctx, reg.Binding.TenantID, job.ID, encrypted)
	if e != nil {
		return ArtifactReceipt{}, false, e
	}
	if !artifactRefValid(ref, reg.Binding.TenantID, job.ID) {
		return ArtifactReceipt{}, false, errors.New("CONFIGURATION_ARTIFACT_ARCHIVE_REFERENCE_INVALID")
	}
	read, e := p.Archive.Read(ctx, reg.Binding.TenantID, ref)
	if e != nil {
		return ArtifactReceipt{}, false, e
	}
	plain, e := artifactOpen(ctx, p.Keys, p.Fixture, reg.Binding.TenantID, job.ID, meta.BundleSHA256, read)
	if e != nil || artifactBytesHash(plain) != artifactBytesHash(raw) {
		return ArtifactReceipt{}, false, errors.New("CONFIGURATION_ARTIFACT_ARCHIVE_READBACK_CHANGED")
	}
	if e = p.Repository.Checkpoint(ctx, reg.Binding.TenantID, job.ID, ref); e != nil && !errors.Is(e, ErrArtifactConflict) {
		return ArtifactReceipt{}, false, e
	}
	return p.resume(ctx, reg, job, replay)
}

// Resume never refreshes observation times or reruns a customer command. The
// entire original bundle is re-read at its immutable encrypted object version.
func (p *ArtifactPipeline) resume(ctx context.Context, reg ArtifactRegistration, job ArtifactJob, replay bool) (ArtifactReceipt, bool, error) {
	if job.Metadata.RegistrationHash != artifactHash(reg) || job.Metadata.Binding != reg.Binding {
		return ArtifactReceipt{}, false, ErrArtifactInactive
	}
	ref, e := p.Repository.Archive(ctx, reg.Binding.TenantID, job.ID)
	if e != nil {
		return ArtifactReceipt{}, false, e
	}
	if !artifactRefValid(ref, reg.Binding.TenantID, job.ID) {
		return ArtifactReceipt{}, false, errors.New("CONFIGURATION_ARTIFACT_ARCHIVE_REFERENCE_INVALID")
	}
	body, e := p.Archive.Read(ctx, reg.Binding.TenantID, ref)
	if e != nil {
		return ArtifactReceipt{}, false, e
	}
	plain, e := artifactOpen(ctx, p.Keys, p.Fixture, reg.Binding.TenantID, job.ID, job.Metadata.BundleSHA256, body)
	if e != nil {
		return ArtifactReceipt{}, false, e
	}
	var bundle ArtifactBundle
	if json.Unmarshal(plain, &bundle) != nil {
		return ArtifactReceipt{}, false, errors.New("CONFIGURATION_ARTIFACT_BUNDLE_INVALID")
	}
	meta, e := ValidateArtifactBundle(reg, bundle)
	if e != nil {
		return ArtifactReceipt{}, false, e
	}
	if p.Fixture {
		meta.ReasonCodes = artifactUnique(append(meta.ReasonCodes, "FIXTURE_ARTIFACT_CAPTURE"))
	}
	if artifactHash(meta) != artifactHash(job.Metadata) {
		return ArtifactReceipt{}, false, errors.New("CONFIGURATION_ARTIFACT_PERSISTED_METADATA_CHANGED")
	}
	receipt, existing, e := p.Repository.Publish(ctx, reg.Binding.TenantID, job.ID)
	if e != nil {
		return ArtifactReceipt{}, false, e
	}
	if receipt.Archive != ref || artifactHash(receipt.Metadata) != artifactHash(meta) || receipt.Metadata.ExecutionAuthorized || receipt.Metadata.VerifiedSaving != nil || !receipt.ObservedAt.Equal(job.CreatedAt) || !receipt.ExpiresAt.Equal(job.CreatedAt.Add(15*time.Minute)) || receipt.ReceivedAt.Before(receipt.ObservedAt) {
		return ArtifactReceipt{}, false, errors.New("CONFIGURATION_ARTIFACT_RECEIPT_INVALID")
	}
	return receipt, replay || existing, nil
}
