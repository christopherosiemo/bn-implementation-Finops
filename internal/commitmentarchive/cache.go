package commitmentarchive

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"

	portfolio "github.com/christopherosiemo/bn-implementation-Finops/internal/commitmentportfolio"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/provider"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/source"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/jackc/pgx/v5"
)

const archiveReplayPage = 128

// A request-local bounded cache of already issued ingestion witnesses. Original
// app versions were written and read back before these immutable rows existed.
// Reusing those authenticated receipts avoids rescanning thousands of S3 objects
// on every interrupted import. Current source/key/bucket checks still surround
// the complete verifier and final SQL publication.
type ReplayCache struct {
	Repository *PostgresRepository
	Storage    *ImmutableArchive
	Pins       []portfolio.DecisionOwnershipArchiveObjectPin
	index      map[string]int
	page       int
	values     map[string]provider.BillingObject
	references map[string]portfolio.Ref
}

func NewReplayCache(r *PostgresRepository, storage *ImmutableArchive, pins []portfolio.DecisionOwnershipArchiveObjectPin) *ReplayCache {
	c := &ReplayCache{Repository: r, Storage: storage, Pins: pins, index: map[string]int{}, page: -1}
	for i, p := range pins {
		key := p.Key + "\x00" + p.VersionID
		if _, exists := c.index[key]; exists {
			c.index[key] = -1
		} else {
			c.index[key] = i
		}
	}
	return c
}
func (c *ReplayCache) Lookup(ctx context.Context, registration portfolio.DecisionOwnershipArchiveRegistration, pin portfolio.DecisionOwnershipArchiveObjectPin) (provider.BillingObject, bool, error) {
	var none provider.BillingObject
	if c == nil || c.Repository == nil || c.Repository.Store == nil || c.Storage == nil || c.Repository.Tenant != registration.TenantID {
		return none, false, errors.New("OWNERSHIP_ARCHIVE_CACHE_SCOPE_INVALID")
	}
	key := pin.Key + "\x00" + pin.VersionID
	index, ok := c.index[key]
	if !ok || index < 0 || portfolio.Hash(c.Pins[index]) != portfolio.Hash(pin) {
		return none, false, errors.New("OWNERSHIP_ARCHIVE_REPLAY_SELECTOR_CHANGED")
	}
	page := index / archiveReplayPage
	if page != c.page {
		end := (page + 1) * archiveReplayPage
		if end > len(c.Pins) {
			end = len(c.Pins)
		}
		selected := c.Pins[page*archiveReplayPage : end]
		keys := []string{}
		versions := []string{}
		expected := map[string]portfolio.DecisionOwnershipArchiveObjectPin{}
		for _, p := range selected {
			keys = append(keys, p.Key)
			versions = append(versions, p.VersionID)
			expected[p.Key+"\x00"+p.VersionID] = p
		}
		values := map[string]provider.BillingObject{}
		references := map[string]portfolio.Ref{}
		total := 0
		err := c.Repository.Store.Do(ctx, registration.TenantID, func(tx *store.Tx) error {
			var current []byte
			if e := tx.QueryRow(ctx, "SELECT public.commitment_archive_source($1,$2)", registration.TenantID, registration.ID).Scan(&current); e != nil {
				return e
			}
			var projected any
			decoder := json.NewDecoder(bytes.NewReader(current))
			decoder.UseNumber()
			if decoder.Decode(&projected) != nil || portfolio.Hash(projected) != registration.IssuedDocumentSHA256 {
				return errors.New("OWNERSHIP_ARCHIVE_SOURCE_CHANGED")
			}
			rows, e := tx.Query(ctx, `SELECT w.document,w.content_hash,w.raw_envelope,w.archive FROM commitment_ownership_archive_witnesses w JOIN unnest($5::text[],$6::text[]) p(key,version) ON w.document->'pin'->>'key'=p.key AND w.document->'pin'->>'version_id'=p.version WHERE w.tenant_id=$1 AND w.source_id=$2 AND w.source_revision=$3 AND w.source_hash=$4 AND w.writer_role='finops_ingester' LIMIT 129`, registration.TenantID, registration.ID, registration.Revision, registration.IssuedDocumentSHA256, keys, versions)
			if e != nil {
				return e
			}
			defer rows.Close()
			for rows.Next() {
				var document, raw, archive []byte
				var digest string
				if e = rows.Scan(&document, &digest, &raw, &archive); e != nil {
					return e
				}
				total += len(document) + len(raw) + len(archive)
				if total > 12<<20 || len(values) >= archiveReplayPage {
					return errors.New("OWNERSHIP_ARCHIVE_REPLAY_PAGE_LIMIT")
				}
				var witness portfolio.DecisionOwnershipArchiveWitness
				hash, e := archiveProjection(document, &witness)
				k := witness.Pin.Key + "\x00" + witness.Pin.VersionID
				p, found := expected[k]
				var ref model.Document
				if e != nil || hash != digest || !found || portfolio.Hash(p) != portfolio.Hash(witness.Pin) || witness.TenantID != registration.TenantID || witness.SourceRegistrationSHA256 != registration.IssuedDocumentSHA256 || witness.AccountID != registration.AccountID || witness.BucketOwner != registration.BucketOwner || witness.Bucket != registration.Bucket || witness.Region != registration.Region || witness.NativeTimeResolutionSeconds != 1 || len(raw) == 0 || len(raw) > 64<<10 || int64(len(raw)) != p.Bytes || source.BytesHash(raw) != p.SHA256 || json.Unmarshal(archive, &ref) != nil || model.String(ref, "bucket") != c.Storage.Bucket || model.String(ref, "body_sha256") != p.SHA256 || model.String(ref, "version_id") == "" || model.String(ref, "version_id") == "null" || !strings.HasPrefix(model.String(ref, "key"), "tenant/"+registration.TenantID+"/commitment-ownership-archive/") {
					return errors.New("OWNERSHIP_ARCHIVE_CACHED_WITNESS_CHANGED")
				}
				if _, duplicate := values[k]; duplicate {
					return errors.New("OWNERSHIP_ARCHIVE_REPLAY_DUPLICATE")
				}
				values[k] = provider.BillingObject{Key: p.Key, VersionID: p.VersionID, LastModified: witness.NativeLastModified, Data: raw}
				references[k] = portfolio.Ref{Kind: "AWS_OWNERSHIP_ARCHIVE_OBJECT", ID: hash, SHA256: hash}
			}
			return rows.Err()
		})
		if err != nil {
			return none, false, err
		}
		c.page = page
		c.values = values
		c.references = references
	}
	value, found := c.values[key]
	return value, found, nil
}

// Only the exact issued row already verified in this page can reconcile a
// repeat publication. New native reads still use the transactional repository.
func (c *ReplayCache) RecordedWitness(w portfolio.DecisionOwnershipArchiveWitness, raw []byte) (portfolio.Ref, bool, error) {
	if c == nil {
		return portfolio.Ref{}, false, nil
	}
	key := w.Pin.Key + "\x00" + w.Pin.VersionID
	ref, found := c.references[key]
	if !found {
		return portfolio.Ref{}, false, nil
	}
	value := c.values[key]
	if ref.ID != portfolio.Hash(w) || !bytes.Equal(value.Data, raw) {
		return portfolio.Ref{}, false, errors.New("OWNERSHIP_ARCHIVE_IMMUTABLE_REPLAY_CONFLICT")
	}
	return ref, true, nil
}

// The cache contains already-issued ingestion readbacks, not uploaded evidence.
// It rechecks current commissioning and reads the exact immutable raw version.
// This is a resumable historical import; no guarded live timestamps are added.
func ReadCachedNativeObject(ctx context.Context, r *PostgresRepository, storage *ImmutableArchive, registration portfolio.DecisionOwnershipArchiveRegistration, pin portfolio.DecisionOwnershipArchiveObjectPin) (provider.BillingObject, bool, error) {
	var result provider.BillingObject
	if r == nil || r.Store == nil || storage == nil || registration.TenantID != r.Tenant {
		return result, false, errors.New("OWNERSHIP_ARCHIVE_CACHE_SCOPE_INVALID")
	}
	var document, raw, archive []byte
	var digest string
	err := r.Store.Do(ctx, r.Tenant, func(tx *store.Tx) error {
		var current []byte
		if e := tx.QueryRow(ctx, "SELECT public.commitment_archive_source($1,$2)", r.Tenant, registration.ID).Scan(&current); e != nil {
			return e
		}
		var projected any
		decoder := json.NewDecoder(bytes.NewReader(current))
		decoder.UseNumber()
		if decoder.Decode(&projected) != nil || portfolio.Hash(projected) != registration.IssuedDocumentSHA256 {
			return errors.New("OWNERSHIP_ARCHIVE_SOURCE_CHANGED")
		}
		return tx.QueryRow(ctx, `SELECT document,content_hash,raw_envelope,archive FROM commitment_ownership_archive_witnesses WHERE tenant_id=$1 AND source_id=$2 AND source_revision=$3 AND source_hash=$4 AND writer_role='finops_ingester' AND document->'pin'->>'key'=$5 AND document->'pin'->>'version_id'=$6`, r.Tenant, registration.ID, registration.Revision, registration.IssuedDocumentSHA256, pin.Key, pin.VersionID).Scan(&document, &digest, &raw, &archive)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return result, false, nil
	}
	if err != nil {
		return result, false, err
	}
	var witness portfolio.DecisionOwnershipArchiveWitness
	hash, err := archiveProjection(document, &witness)
	if err != nil || hash != digest || witness.SourceRegistrationSHA256 != registration.IssuedDocumentSHA256 || witness.TenantID != r.Tenant || portfolio.Hash(witness.Pin) != portfolio.Hash(pin) || len(raw) == 0 || len(raw) > 64<<10 || int64(len(raw)) != pin.Bytes || source.BytesHash(raw) != pin.SHA256 {
		return result, false, errors.New("OWNERSHIP_ARCHIVE_CACHED_WITNESS_CHANGED")
	}
	var ref model.Document
	if json.Unmarshal(archive, &ref) != nil {
		return result, false, errors.New("OWNERSHIP_ARCHIVE_CACHED_RAW_REF_INVALID")
	}
	back, err := storage.ReadWitness(ctx, r.Tenant, ref)
	if err != nil || !bytes.Equal(back, raw) {
		return result, false, errors.New("OWNERSHIP_ARCHIVE_CACHED_RAW_UNAVAILABLE")
	}
	return provider.BillingObject{Key: pin.Key, VersionID: pin.VersionID, LastModified: witness.NativeLastModified, Data: back}, true, nil
}

// Exact committed replay is reconciled before attempting another object write.
// A different body/time/source pin never overwrites the prior native version.
func ReuseRecordedWitness(ctx context.Context, r *PostgresRepository, registration portfolio.DecisionOwnershipArchiveRegistration, witness portfolio.DecisionOwnershipArchiveWitness, raw []byte) (portfolio.Ref, bool, error) {
	var result portfolio.Ref
	if r == nil || r.Store == nil || registration.TenantID != r.Tenant || witness.SourceRegistrationSHA256 != registration.IssuedDocumentSHA256 || source.BytesHash(raw) != witness.Pin.SHA256 {
		return result, false, errors.New("OWNERSHIP_ARCHIVE_REPLAY_SCOPE_INVALID")
	}
	id := portfolio.Hash(witness)
	wire, err := json.Marshal(witness)
	if err != nil {
		return result, false, err
	}
	var equal bool
	err = r.Store.Do(ctx, r.Tenant, func(tx *store.Tx) error {
		var current []byte
		if e := tx.QueryRow(ctx, "SELECT public.commitment_archive_source($1,$2)", r.Tenant, registration.ID).Scan(&current); e != nil {
			return e
		}
		var projected any
		decoder := json.NewDecoder(bytes.NewReader(current))
		decoder.UseNumber()
		if decoder.Decode(&projected) != nil || portfolio.Hash(projected) != registration.IssuedDocumentSHA256 {
			return errors.New("OWNERSHIP_ARCHIVE_SOURCE_CHANGED")
		}
		return tx.QueryRow(ctx, `SELECT document=$5::jsonb AND raw_envelope=$6 AND content_hash=$2 FROM commitment_ownership_archive_witnesses WHERE tenant_id=$1 AND id=$2 AND source_id=$3 AND source_hash=$4 AND writer_role='finops_ingester'`, r.Tenant, id, registration.ID, registration.IssuedDocumentSHA256, wire, raw).Scan(&equal)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return result, false, nil
	}
	if err != nil {
		return result, false, err
	}
	if !equal {
		return result, false, errors.New("OWNERSHIP_ARCHIVE_IMMUTABLE_REPLAY_CONFLICT")
	}
	return portfolio.Ref{Kind: "AWS_OWNERSHIP_ARCHIVE_OBJECT", ID: id, SHA256: id}, true, nil
}
