package commitmentarchive

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"

	portfolio "github.com/christopherosiemo/bn-implementation-Finops/internal/commitmentportfolio"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/source"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
)

// Private ingestion configuration selects a registered source and one exact
// signed review object. It cannot supply native provenance, amounts, completeness
// or timestamps. An empty configuration performs no AWS/storage/DB operations.
type Target struct {
	TenantID string                                      `json:"tenant_id"`
	SourceID string                                      `json:"source_id"`
	Review   portfolio.DecisionOwnershipArchiveObjectPin `json:"review"`
}

func Targets(encoded string) ([]Target, error) {
	if strings.TrimSpace(encoded) == "" {
		return []Target{}, nil
	}
	if len(encoded) > 1<<20 {
		return nil, errors.New("OWNERSHIP_ARCHIVE_TARGETS_INVALID")
	}
	var result []Target
	decoder := json.NewDecoder(strings.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&result) != nil || decoder.Decode(new(any)) != io.EOF || result == nil || len(result) > 8 {
		return nil, errors.New("OWNERSHIP_ARCHIVE_TARGETS_INVALID")
	}
	seen := map[string]bool{}
	for _, t := range result {
		key := t.TenantID + ":" + t.SourceID
		if !archivePart.MatchString(t.TenantID) || !archivePart.MatchString(t.SourceID) || seen[key] || t.Review.Key == "" || strings.HasPrefix(t.Review.Key, "/") || strings.Contains(t.Review.Key, "..") || strings.Contains(t.Review.Key, "//") || strings.ContainsAny(t.Review.Key, "\\\x00\r\n") || len(t.Review.Key) > 2048 || t.Review.VersionID == "" || t.Review.VersionID == "null" || len(t.Review.VersionID) > 1024 || len(t.Review.SHA256) != 64 || t.Review.Bytes < 1 || t.Review.Bytes > 24<<20 {
			return nil, errors.New("OWNERSHIP_ARCHIVE_TARGETS_INVALID")
		}
		seen[key] = true
		for _, r := range t.Review.SHA256 {
			if !(r >= 'a' && r <= 'f' || r >= '0' && r <= '9') {
				return nil, errors.New("OWNERSHIP_ARCHIVE_TARGETS_INVALID")
			}
		}
	}
	return result, nil
}

type Pipeline struct {
	Store    *store.Store
	Bindings string
	Storage  *ImmutableArchive
}

// Capture uses the existing ingestion identity. Each successful native readback
// is durable before the aggregate; interrupted or stale collections retain only
// those immutable checkpoints and cannot authorize recommendations. A retry can
// read their exact archived versions and reconcile already committed witnesses.
func (p *Pipeline) Capture(parent context.Context, target Target) (portfolio.DecisionOwnershipArchiveEvidence, error) {
	var none portfolio.DecisionOwnershipArchiveEvidence
	wire, _ := json.Marshal([]Target{target})
	if _, err := Targets(string(wire)); err != nil {
		return none, err
	}
	if p == nil || p.Store == nil || p.Storage == nil {
		return none, errors.New("OWNERSHIP_ARCHIVE_PIPELINE_REQUIRED")
	}
	// A batch cannot monopolize the ingester indefinitely. Checkpoints survive
	// this budget; the next invocation resumes without widening freshness gates.
	ctx, cancel := context.WithTimeout(parent, 3*time.Minute)
	defer cancel()
	repository := &PostgresRepository{Store: p.Store, Tenant: target.TenantID, Archive: p.Storage.Witness, ArchiveReview: p.Storage.Review}
	var replay *ReplayCache
	persist := func(ctx context.Context, r portfolio.DecisionOwnershipArchiveRegistration, w portfolio.DecisionOwnershipArchiveWitness, raw []byte) (portfolio.Ref, error) {
		if ref, found, err := replay.RecordedWitness(w, raw); err != nil || found {
			return ref, err
		}
		ref, found, err := ReuseRecordedWitness(ctx, repository, r, w, raw)
		if err != nil || found {
			return ref, err
		}
		return repository.PersistArchiveWitness(ctx, r, w, raw)
	}
	reader, err := NewOwnershipArchiveAWSReader(p.Bindings, repository, persist)
	if err != nil {
		return none, err
	}
	repository.ReadCurrentBucket = reader.ArchiveBucket
	registration, err := repository.ArchiveRegistration(ctx, target.SourceID)
	if err != nil {
		return none, err
	}
	if registration.TenantID != target.TenantID || !strings.HasPrefix(target.Review.Key, registration.Prefix) {
		return none, errors.New("OWNERSHIP_ARCHIVE_REVIEW_SCOPE_INVALID")
	}
	original, err := reader.ArchiveReviewObject(ctx, registration, target.Review)
	if err != nil || original.Key != target.Review.Key || original.VersionID != target.Review.VersionID || int64(len(original.Data)) != target.Review.Bytes || source.BytesHash(original.Data) != target.Review.SHA256 {
		return none, errors.New("OWNERSHIP_ARCHIVE_REVIEW_VERSION_CHANGED")
	}
	var envelope portfolio.DecisionOwnershipArchiveReviewEnvelope
	if json.Unmarshal(original.Data, &envelope) != nil {
		return none, errors.New("OWNERSHIP_ARCHIVE_REVIEW_INVALID")
	}
	if envelope.Review.Query.Scope.TenantID != target.TenantID || portfolio.Hash(envelope.Review.Query.Scope) != registration.ScopeSHA256 {
		return none, errors.New("OWNERSHIP_ARCHIVE_REVIEW_SCOPE_INVALID")
	}
	replay = NewReplayCache(repository, p.Storage, envelope.Review.Objects)
	reader.CachedObject = replay.Lookup
	value, err := portfolio.VerifyDecisionOwnershipArchive(ctx, reader, target.SourceID, original.Data, envelope.Review.Query, time.Now().UTC())
	if err != nil {
		return none, err
	}
	if err = repository.PublishArchiveEvidence(ctx, registration, value, original.Data); err != nil {
		return none, err
	}
	return value, nil
}
