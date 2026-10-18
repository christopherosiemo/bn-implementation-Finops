package multicloud

import (
	"context"
	"errors"
	"time"
)

// Resume reconstructs source records from the original version-pinned native
// archive, without repeating a potentially billable provider query. A job that
// died before its complete raw checkpoint still needs its original collection;
// it cannot assert completeness from a partial archive or empty query result.
func (p *PublicationPipeline) Resume(ctx context.Context, tenant, jobID string) (PublicationReceipt, bool, error) {
	if p.Repository == nil || p.Archive == nil || p.Facts == nil {
		return PublicationReceipt{}, false, errors.New("MULTICLOUD_PUBLICATION_DEPENDENCIES_REQUIRED")
	}
	job, e := p.Repository.Job(ctx, tenant, jobID)
	if e != nil {
		return PublicationReceipt{}, false, e
	}
	m := job.Manifest
	var collectionBytes int64
	if len(m.RawObjects) < 1 || len(m.RawObjects) > 1100 {
		return PublicationReceipt{}, false, errors.New("MULTICLOUD_COLLECTION_LIMIT")
	}
	for _, o := range m.RawObjects {
		if o.Bytes < 1 || o.Bytes > MaxBodyBytes {
			return PublicationReceipt{}, false, errors.New("MULTICLOUD_COLLECTION_LIMIT")
		}
		collectionBytes += o.Bytes
		if collectionBytes > MaxCollectionBytes {
			return PublicationReceipt{}, false, errors.New("MULTICLOUD_COLLECTION_LIMIT")
		}
	}
	if m.TenantID != tenant {
		return PublicationReceipt{}, false, errors.New("MULTICLOUD_JOB_BINDING_INVALID")
	}
	reg, e := p.Repository.Current(ctx, tenant, m.RegistrationID)
	if e != nil {
		return PublicationReceipt{}, false, e
	}
	if reg.ConfigHash != m.ConfigHash || reg.ScopeHash != m.ScopeHash || reg.BindingHash != m.BindingHash || reg.Registration.Version != m.RegistrationVersion {
		return PublicationReceipt{}, false, ErrPublicationInactive
	}
	stages, e := p.checkpoints(ctx, tenant, jobID)
	if e != nil {
		return PublicationReceipt{}, false, e
	}
	raw, ok := stages["RAW_ARCHIVED"]
	if !ok || len(raw.Raw) != len(m.RawObjects) {
		return PublicationReceipt{}, false, errors.New("MULTICLOUD_COMPLETE_RAW_CHECKPOINT_REQUIRED")
	}
	s := base(reg.Registration, time.Time{})
	s.Period = m.Period
	s.NativeReference = m.NativeReference
	s.ReasonCodes = append([]string{}, m.SourceReasonCodes...)
	for i, metadata := range m.RawObjects {
		ref := raw.Raw[i]
		if !archiveRefValid(ref, tenant, jobID, rawKind(i), metadata.SHA256, metadata.Bytes) {
			return PublicationReceipt{}, false, errors.New("MULTICLOUD_RAW_CHECKPOINT_BINDING_INVALID")
		}
		body, e := p.Archive.Read(ctx, tenant, ref)
		if e != nil {
			return PublicationReceipt{}, false, e
		}
		if int64(len(body)) != metadata.Bytes || BytesHash(body) != metadata.SHA256 {
			return PublicationReceipt{}, false, errors.New("MULTICLOUD_ARCHIVE_READBACK_CHANGED")
		}
		metadata.Body = body
		s.Objects = append(s.Objects, metadata)
	}
	if reg.Registration.Azure != nil {
		s.Records, s.NativeRowCount, e = deriveAzurePublication(reg.Registration, s)
	} else {
		s.Records, s.NativeRowCount, e = deriveGCPPublication(reg.Registration, s)
	}
	if e != nil {
		return PublicationReceipt{}, false, e
	}
	for _, row := range s.Records {
		addTotal(s.BilledTotals, row.Currency, row.BilledCost)
		if s.Kind == AzureAmortized {
			addTotal(s.AmortizedTotals, row.Currency, row.EffectiveCost)
		}
	}
	s = seal(s)
	if s.Revision != m.NativeRevision {
		return PublicationReceipt{}, false, errors.New("MULTICLOUD_RESTORED_NATIVE_REVISION_CHANGED")
	}
	return p.Publish(ctx, reg, s, job.Key)
}
