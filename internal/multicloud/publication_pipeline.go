package multicloud

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
)

func rawKind(i int) string { return fmt.Sprintf("raw-%04d", i) }

func archiveRefValid(ref ArchiveRef, tenant, job, kind, sha string, size int64) bool {
	return safeID.MatchString(ref.Bucket) && ref.VersionID != "" && ref.VersionID != "null" && len(ref.VersionID) <= 1024 && ref.SHA256 == sha && ref.Bytes == size && strings.HasPrefix(ref.Key, "tenant/"+tenant+"/multicloud/"+job+"/"+kind+"/") && !strings.Contains(ref.Key, "..") && !strings.ContainsAny(ref.Key, "\\\x00\r\n")
}
func (p *PublicationPipeline) verifiedObject(ctx context.Context, tenant, job, kind string, raw []byte, ref ArchiveRef) error {
	if !archiveRefValid(ref, tenant, job, kind, BytesHash(raw), int64(len(raw))) {
		return errors.New("MULTICLOUD_ARCHIVE_REFERENCE_INVALID")
	}
	body, e := p.Archive.Read(ctx, tenant, ref)
	if e != nil {
		return e
	}
	if !bytes.Equal(body, raw) || BytesHash(body) != ref.SHA256 {
		return errors.New("MULTICLOUD_ARCHIVE_READBACK_CHANGED")
	}
	return nil
}
func factAckValid(ack FactAck, m PublicationManifest) bool {
	return ack.TenantID == m.TenantID && ack.PopulationID == m.PopulationID && ack.FactHash == m.FactHash && ack.EconomicHash == m.EconomicHash && ack.DistinctRows == m.DistinctRows && ack.RecordCount == m.RecordCount && warehouseIdentifier.MatchString(ack.Database) && warehouseIdentifier.MatchString(ack.Table)
}
func (p *PublicationPipeline) checkpoints(ctx context.Context, tenant, job string) (map[string]PublicationCheckpoint, error) {
	all, e := p.Repository.Checkpoints(ctx, tenant, job)
	if e != nil {
		return nil, e
	}
	out := map[string]PublicationCheckpoint{}
	for _, checkpoint := range all {
		if _, exists := out[checkpoint.Stage]; exists {
			return nil, errors.New("MULTICLOUD_CHECKPOINT_AMBIGUOUS")
		}
		out[checkpoint.Stage] = checkpoint
	}
	return out, nil
}
func (p *PublicationPipeline) appendCheckpoint(ctx context.Context, tenant, job string, c PublicationCheckpoint) (PublicationCheckpoint, error) {
	if e := p.Repository.Checkpoint(ctx, tenant, job, c); e != nil && !errors.Is(e, ErrPublicationConflict) {
		return PublicationCheckpoint{}, e
	}
	all, e := p.checkpoints(ctx, tenant, job)
	if e != nil {
		return PublicationCheckpoint{}, e
	}
	saved, ok := all[c.Stage]
	if !ok {
		return PublicationCheckpoint{}, errors.New("MULTICLOUD_CHECKPOINT_NOT_PERSISTED")
	}
	return saved, nil
}

// Publish accepts a private native reader result, not authoritative uploads.
// Native I/O/query costs happen outside this method; retries resume durable
// checkpoint stages and re-read every exact pinned object/analytics population.
func (p *PublicationPipeline) Publish(ctx context.Context, reg RegistrationSnapshot, s Snapshot, key string) (PublicationReceipt, bool, error) {
	if p.Repository == nil || p.Archive == nil || p.Facts == nil || key == "" || len(key) > 200 {
		return PublicationReceipt{}, false, errors.New("MULTICLOUD_PUBLICATION_DEPENDENCIES_REQUIRED")
	}
	m, canonical, facts, e := PublicationContent(reg, s)
	if e != nil {
		return PublicationReceipt{}, false, e
	}
	current, e := p.Repository.Current(ctx, reg.Registration.TenantID, reg.Registration.ID)
	if e != nil {
		return PublicationReceipt{}, false, e
	}
	if Hash(current) != Hash(reg) {
		return PublicationReceipt{}, false, ErrPublicationInactive
	}
	job, replay, e := p.Repository.Prepare(ctx, reg, key, m)
	if e != nil {
		return PublicationReceipt{}, false, e
	}
	if Hash(job.Manifest) != Hash(m) || job.ID == "" {
		return PublicationReceipt{}, false, errors.New("MULTICLOUD_JOB_CONTENT_CHANGED")
	}
	tenant := reg.Registration.TenantID
	stages, e := p.checkpoints(ctx, tenant, job.ID)
	if e != nil {
		return PublicationReceipt{}, false, e
	}
	rawStage, ok := stages["RAW_ARCHIVED"]
	if !ok {
		rawStage = PublicationCheckpoint{Stage: "RAW_ARCHIVED", Raw: []ArchiveRef{}}
		for i, o := range s.Objects {
			kind := fmt.Sprintf("raw-%04d", i)
			ref, e := p.Archive.Put(ctx, tenant, job.ID, kind, o.Body)
			if e != nil {
				return PublicationReceipt{}, false, e
			}
			if e = p.verifiedObject(ctx, tenant, job.ID, kind, o.Body, ref); e != nil {
				return PublicationReceipt{}, false, e
			}
			rawStage.Raw = append(rawStage.Raw, ref)
		}
		rawStage, e = p.appendCheckpoint(ctx, tenant, job.ID, rawStage)
		if e != nil {
			return PublicationReceipt{}, false, e
		}
	}
	if len(rawStage.Raw) != len(s.Objects) {
		return PublicationReceipt{}, false, errors.New("MULTICLOUD_RAW_CHECKPOINT_INCOMPLETE")
	}
	for i, o := range s.Objects {
		if e = p.verifiedObject(ctx, tenant, job.ID, fmt.Sprintf("raw-%04d", i), o.Body, rawStage.Raw[i]); e != nil {
			return PublicationReceipt{}, false, e
		}
	}
	canonicalStage, ok := stages["CANONICAL_ARCHIVED"]
	if !ok {
		ref, e := p.Archive.Put(ctx, tenant, job.ID, "canonical", canonical)
		if e != nil {
			return PublicationReceipt{}, false, e
		}
		if e = p.verifiedObject(ctx, tenant, job.ID, "canonical", canonical, ref); e != nil {
			return PublicationReceipt{}, false, e
		}
		canonicalStage, e = p.appendCheckpoint(ctx, tenant, job.ID, PublicationCheckpoint{Stage: "CANONICAL_ARCHIVED", Canonical: &ref})
		if e != nil {
			return PublicationReceipt{}, false, e
		}
	}
	if canonicalStage.Canonical == nil {
		return PublicationReceipt{}, false, errors.New("MULTICLOUD_CANONICAL_CHECKPOINT_INCOMPLETE")
	}
	if e = p.verifiedObject(ctx, tenant, job.ID, "canonical", canonical, *canonicalStage.Canonical); e != nil {
		return PublicationReceipt{}, false, e
	}
	analyticsStage, ok := stages["ANALYTICS_PERSISTED"]
	if !ok {
		ack, e := p.Facts.Write(ctx, facts)
		if e != nil {
			return PublicationReceipt{}, false, e
		}
		if !factAckValid(ack, m) {
			return PublicationReceipt{}, false, errors.New("MULTICLOUD_ANALYTICS_ACK_CHANGED")
		}
		readback, e := p.Facts.Readback(ctx, ack)
		if e != nil {
			return PublicationReceipt{}, false, e
		}
		if Hash(readback) != Hash(ack) {
			return PublicationReceipt{}, false, errors.New("MULTICLOUD_ANALYTICS_READBACK_CHANGED")
		}
		analyticsStage, e = p.appendCheckpoint(ctx, tenant, job.ID, PublicationCheckpoint{Stage: "ANALYTICS_PERSISTED", Facts: &ack})
		if e != nil {
			return PublicationReceipt{}, false, e
		}
	}
	if analyticsStage.Facts == nil || !factAckValid(*analyticsStage.Facts, m) {
		return PublicationReceipt{}, false, errors.New("MULTICLOUD_ANALYTICS_CHECKPOINT_INCOMPLETE")
	}
	readback, e := p.Facts.Readback(ctx, *analyticsStage.Facts)
	if e != nil {
		return PublicationReceipt{}, false, e
	}
	if Hash(readback) != Hash(*analyticsStage.Facts) {
		return PublicationReceipt{}, false, errors.New("MULTICLOUD_ANALYTICS_READBACK_CHANGED")
	}
	receipt, existing, e := p.Repository.Publish(ctx, tenant, job.ID)
	if e != nil {
		return PublicationReceipt{}, false, e
	}
	if receipt.Manifest.Status != "PROVISIONAL" || receipt.ExecutionAuthorized || receipt.VerifiedSaving != nil || Hash(receipt.Manifest) != Hash(m) {
		return PublicationReceipt{}, false, errors.New("MULTICLOUD_RECEIPT_AUTHORITY_INVALID")
	}
	return receipt, replay || existing, nil
}
