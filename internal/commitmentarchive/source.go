package commitmentarchive

import (
	"context"
	"errors"
	"sync"

	portfolio "github.com/christopherosiemo/bn-implementation-Finops/internal/commitmentportfolio"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/provider"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/source"
)

// Registry is implemented by the ingester-only immutable registry. It must
// enforce tenant/source and key commissioning; public imports are not a registry.
type OwnershipArchiveRegistry interface {
	ArchiveRegistration(context.Context, string) (portfolio.DecisionOwnershipArchiveRegistration, error)
	ArchiveReviewRegistration(context.Context, string) (portfolio.DecisionOwnershipRegistration, error)
}

type OwnershipArchiveAWSReader struct {
	OwnershipArchiveRegistry
	PersistWitness func(context.Context, portfolio.DecisionOwnershipArchiveRegistration, portfolio.DecisionOwnershipArchiveWitness, []byte) (portfolio.Ref, error)
	// Reuses only already-issued native readbacks with immutable raw version
	// readback; it never manufactures an earlier live-ingress receipt.
	CachedObject        func(context.Context, portfolio.DecisionOwnershipArchiveRegistration, portfolio.DecisionOwnershipArchiveObjectPin) (provider.BillingObject, bool, error)
	factory             func(context.Context, source.Registration) (source.Reader, error)
	mu                  sync.Mutex
	currentRegistration string
	current             source.Reader
}

// Reuses the existing external-ID/tenant/account/region-bound AWS read factory
// and renewable SDK credentials. This object belongs only in ingestion, never
// in the commitment analyst or public API process.
func NewOwnershipArchiveAWSReader(bindings string, registry OwnershipArchiveRegistry, persist func(context.Context, portfolio.DecisionOwnershipArchiveRegistration, portfolio.DecisionOwnershipArchiveWitness, []byte) (portfolio.Ref, error)) (*OwnershipArchiveAWSReader, error) {
	if registry == nil || persist == nil {
		return nil, errors.New("OWNERSHIP_ARCHIVE_REGISTRY_AND_PERSISTENCE_REQUIRED")
	}
	factory, err := source.AWSFactory(bindings)
	if err != nil {
		return nil, err
	}
	return &OwnershipArchiveAWSReader{OwnershipArchiveRegistry: registry, PersistWitness: persist, factory: factory}, nil
}

func (r *OwnershipArchiveAWSReader) reader(ctx context.Context, reg portfolio.DecisionOwnershipArchiveRegistration) (source.Reader, error) {
	if r == nil || r.factory == nil || r.OwnershipArchiveRegistry == nil || reg.Region != "eu-west-1" || reg.BucketOwner != reg.AccountID || reg.ReadRoleBinding.Kind != "APPROVED_READ_ROLE_BINDING" {
		return nil, errors.New("OWNERSHIP_ARCHIVE_BINDING_INVALID")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	key := portfolio.Hash(reg) + reg.IssuedDocumentSHA256
	if r.current != nil && r.currentRegistration == key {
		return r.current, nil
	}
	reader, err := r.factory(ctx, source.Registration{ID: reg.ID, TenantID: reg.TenantID, Kind: "AWS_OWNERSHIP_ARCHIVE", PayerAccountID: reg.AccountID, Region: reg.Region, Bucket: reg.Bucket, BucketOwner: reg.BucketOwner, Prefix: reg.Prefix, ReadRoleBindingID: reg.ReadRoleBinding.ID, Version: reg.Revision})
	if err != nil {
		return nil, err
	}
	r.currentRegistration, r.current = key, reader
	return reader, nil
}

func (r *OwnershipArchiveAWSReader) ArchiveBucket(ctx context.Context, reg portfolio.DecisionOwnershipArchiveRegistration) (map[string]any, error) {
	reader, err := r.reader(ctx, reg)
	if err != nil {
		return nil, err
	}
	document, err := reader.BillingBucket(ctx, reg.Bucket)
	return map[string]any(document), err
}

func (r *OwnershipArchiveAWSReader) ArchiveObject(ctx context.Context, reg portfolio.DecisionOwnershipArchiveRegistration, pin portfolio.DecisionOwnershipArchiveObjectPin) (provider.BillingObject, error) {
	reader, err := r.reader(ctx, reg)
	if err != nil {
		return provider.BillingObject{}, err
	}
	if r.CachedObject != nil {
		value, found, err := r.CachedObject(ctx, reg, pin)
		if err != nil || found {
			return value, err
		}
	}
	bounded, ok := reader.(interface {
		BillingObjectBounded(context.Context, string, string, string, int64) (provider.BillingObject, error)
	})
	if !ok {
		return provider.BillingObject{}, errors.New("OWNERSHIP_ARCHIVE_BOUNDED_TRANSPORT_REQUIRED")
	}
	return bounded.BillingObjectBounded(ctx, reg.Bucket, pin.Key, pin.VersionID, 64<<10)
}

// The current review is signed customer input, not a historical timestamp
// witness. Its original native version/bytes are pinned before verification.
func (r *OwnershipArchiveAWSReader) ArchiveReviewObject(ctx context.Context, reg portfolio.DecisionOwnershipArchiveRegistration, pin portfolio.DecisionOwnershipArchiveObjectPin) (provider.BillingObject, error) {
	reader, err := r.reader(ctx, reg)
	if err != nil {
		return provider.BillingObject{}, err
	}
	bounded, ok := reader.(interface {
		BillingObjectBounded(context.Context, string, string, string, int64) (provider.BillingObject, error)
	})
	if !ok {
		return provider.BillingObject{}, errors.New("OWNERSHIP_ARCHIVE_BOUNDED_TRANSPORT_REQUIRED")
	}
	return bounded.BillingObjectBounded(ctx, reg.Bucket, pin.Key, pin.VersionID, 24<<20)
}

func (r *OwnershipArchiveAWSReader) PersistArchiveWitness(ctx context.Context, reg portfolio.DecisionOwnershipArchiveRegistration, witness portfolio.DecisionOwnershipArchiveWitness, raw []byte) (portfolio.Ref, error) {
	if r == nil || r.PersistWitness == nil || witness.SourceRegistrationSHA256 != reg.IssuedDocumentSHA256 || witness.TenantID != reg.TenantID || int64(len(raw)) != witness.Pin.Bytes || source.BytesHash(raw) != witness.Pin.SHA256 {
		return portfolio.Ref{}, errors.New("OWNERSHIP_ARCHIVE_RAW_EVIDENCE_REQUIRED")
	}
	return r.PersistWitness(ctx, reg, witness, raw)
}
