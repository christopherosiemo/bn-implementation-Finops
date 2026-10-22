package source

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/provider"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/jackc/pgx/v5"
)

const ControllerDiscoveryKind = "AWS_CONTROLLER_DISCOVERY"

type ControllerDiscoveryReader interface {
	ControllerDiscovery(context.Context, string, string, []string) (provider.ControllerDiscoveryEvidence, error)
}

type ControllerDiscoveryBinding struct {
	TenantID   string `json:"tenant_id"`
	WorkloadID string `json:"workload_id"`
	Provider   string `json:"provider"`
	AccountID  string `json:"account_id"`
	Region     string `json:"region"`
}

// Ingester-only operator configuration selects read scope, not observed facts.
// ResourceIDs are internal registered IDs; native IDs come only from the DB.
type ControllerDiscoveryTarget struct {
	SourceID    string                     `json:"source_id"`
	Binding     ControllerDiscoveryBinding `json:"binding"`
	ResourceIDs []string                   `json:"resource_ids"`
}

func ControllerDiscoveryBindings(encoded string) (map[string]ControllerDiscoveryTarget, error) {
	result := map[string]ControllerDiscoveryTarget{}
	if strings.TrimSpace(encoded) == "" {
		return result, nil
	}
	decoder := json.NewDecoder(strings.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if len(encoded) > 1<<20 || decoder.Decode(&result) != nil || decoder.Decode(new(any)) != io.EOF || len(result) > 32 {
		return nil, errors.New("CONTROLLER_DISCOVERY_BINDINGS_INVALID")
	}
	for id, target := range result {
		if !fleetObjectPart.MatchString(id) || !fleetObjectPart.MatchString(target.SourceID) || !fleetObjectPart.MatchString(target.Binding.TenantID) || !fleetObjectPart.MatchString(target.Binding.WorkloadID) || target.Binding.Provider != "AWS" || !accountPattern.MatchString(target.Binding.AccountID) || target.Binding.Region != "eu-west-1" || len(target.ResourceIDs) < 1 || len(target.ResourceIDs) > 256 {
			return nil, errors.New("CONTROLLER_DISCOVERY_BINDINGS_INVALID")
		}
		seen := map[string]bool{}
		for _, resource := range target.ResourceIDs {
			if !fleetObjectPart.MatchString(resource) || seen[resource] {
				return nil, errors.New("CONTROLLER_DISCOVERY_BINDINGS_INVALID")
			}
			seen[resource] = true
		}
	}
	return result, nil
}

// Reuses the existing external-ID/account-bound approved member read factory.
// Targets contain no role ARN, credentials, prices or caller completeness flag.
func ControllerDiscoveryAWSFactory(encoded string) (func(context.Context, Registration, string) (ControllerDiscoveryReader, error), error) {
	factory, err := FleetAWSFactory(encoded)
	if err != nil {
		return nil, err
	}
	return func(ctx context.Context, registration Registration, account string) (ControllerDiscoveryReader, error) {
		reader, err := factory(ctx, registration, account)
		if err != nil {
			return nil, err
		}
		typed, ok := reader.(ControllerDiscoveryReader)
		if !ok {
			return nil, errors.New("CONTROLLER_DISCOVERY_NATIVE_READER_REQUIRED")
		}
		return typed, nil
	}, nil
}

type ControllerDiscoveryPipeline struct {
	Store         *store.Store
	Bindings      map[string]ControllerDiscoveryTarget
	ReaderFactory func(context.Context, Registration, string) (ControllerDiscoveryReader, error)
	// Use the existing FleetS3Archive.Archive: checksum+versioned GET readback.
	Archive func(context.Context, string, string, []byte) (model.Document, error)
	Now     func() time.Time
}

func (p *ControllerDiscoveryPipeline) now() time.Time {
	if p.Now != nil {
		return p.Now().UTC()
	}
	return time.Now().UTC()
}

func controllerDiscoveryRoster(ctx context.Context, tx *store.Tx, target ControllerDiscoveryTarget) ([]model.Document, []string, error) {
	var role bool
	if err := tx.QueryRow(ctx, "SELECT current_user='finops_ingester'").Scan(&role); err != nil {
		return nil, nil, err
	}
	if !role {
		return nil, nil, errors.New("CONTROLLER_DISCOVERY_INGESTER_REQUIRED")
	}
	var count int
	var size int64
	if err := tx.QueryRow(ctx, "SELECT count(*),coalesce(sum(octet_length(document::text)),0) FROM entities WHERE tenant_id=$1 AND kind='resources' AND document->>'resource_type'='EC2' AND document->>'workload_id'=$2 AND document->>'provider'='AWS' AND document->>'account_id'=$3 AND document->>'region'=$4", target.Binding.TenantID, target.Binding.WorkloadID, target.Binding.AccountID, target.Binding.Region).Scan(&count, &size); err != nil {
		return nil, nil, err
	}
	if count < 1 || count > 256 || count != len(target.ResourceIDs) || size > 2<<20 {
		return nil, nil, errors.New("CONTROLLER_DISCOVERY_ROSTER_CHANGED")
	}
	rows, err := tx.Query(ctx, "SELECT document||jsonb_build_object('id',id,'version',version) FROM entities WHERE tenant_id=$1 AND kind='resources' AND document->>'resource_type'='EC2' AND document->>'workload_id'=$2 AND document->>'provider'='AWS' AND document->>'account_id'=$3 AND document->>'region'=$4 ORDER BY id", target.Binding.TenantID, target.Binding.WorkloadID, target.Binding.AccountID, target.Binding.Region)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	wanted := map[string]bool{}
	for _, id := range target.ResourceIDs {
		wanted[id] = true
	}
	seen := map[string]bool{}
	roster := []model.Document{}
	nativeIDs := []string{}
	for rows.Next() {
		var raw []byte
		if err = rows.Scan(&raw); err != nil {
			return nil, nil, err
		}
		var resource model.Document
		decoder := json.NewDecoder(strings.NewReader(string(raw)))
		decoder.UseNumber()
		if decoder.Decode(&resource) != nil {
			return nil, nil, errors.New("CONTROLLER_DISCOVERY_ROSTER_INVALID")
		}
		id, native := model.String(resource, "id"), model.String(resource, "provider_resource_id")
		if !wanted[id] || !fleetInstanceID.MatchString(native) || seen[native] || model.Number(resource, "version") < 1 {
			return nil, nil, errors.New("CONTROLLER_DISCOVERY_ROSTER_CHANGED")
		}
		delete(wanted, id)
		seen[native] = true
		roster = append(roster, resource)
		nativeIDs = append(nativeIDs, native)
	}
	if err = rows.Err(); err != nil {
		return nil, nil, err
	}
	if len(wanted) != 0 || len(roster) != count {
		return nil, nil, errors.New("CONTROLLER_DISCOVERY_ROSTER_CHANGED")
	}
	sort.Strings(nativeIDs)
	return roster, nativeIDs, nil
}

// This new path preserves JSON integers in immutable roster/source versions.
// Legacy Source* helpers clone through float64 and are deliberately unchanged.
func controllerDiscoveryDecode(raw []byte) (model.Document, error) {
	var document model.Document
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if len(raw) > 8<<20 || decoder.Decode(&document) != nil || document == nil || decoder.Decode(new(any)) != io.EOF {
		return nil, errors.New("CONTROLLER_DISCOVERY_DOCUMENT_INVALID")
	}
	return document, nil
}
func controllerDiscoveryEncode(document model.Document, tenant string) ([]byte, error) {
	copy := model.Document{}
	for key, value := range document {
		copy[key] = value
	}
	copy["tenant_id"] = tenant
	raw, err := json.Marshal(copy)
	if err != nil || len(raw) > 8<<20 {
		return nil, errors.New("CONTROLLER_DISCOVERY_METADATA_LIMIT")
	}
	return raw, nil
}
func controllerDiscoveryEvidenceGet(ctx context.Context, tx *store.Tx, id string, revision bool) (model.Document, error) {
	query := "SELECT document||jsonb_build_object('writer_role',writer_role,'created_at',created_at) FROM source_receipts WHERE tenant_id=$1 AND id=$2"
	if revision {
		query = "SELECT document||jsonb_build_object('writer_role',writer_role,'created_at',created_at) FROM source_revisions WHERE tenant_id=$1 AND id=$2"
	}
	var raw []byte
	if err := tx.QueryRow(ctx, query, tx.Tenant, id).Scan(&raw); err != nil {
		return nil, err
	}
	return controllerDiscoveryDecode(raw)
}
func controllerDiscoveryEvidenceCreate(ctx context.Context, tx *store.Tx, document model.Document, revision bool) error {
	raw, err := controllerDiscoveryEncode(document, tx.Tenant)
	if err != nil {
		return err
	}
	if revision {
		_, err = tx.Exec(ctx, "INSERT INTO source_revisions(tenant_id,id,source_id,revision_hash,document) VALUES($1,$2,$3,$4,$5) ON CONFLICT(tenant_id,source_id,revision_hash) DO NOTHING", tx.Tenant, document["id"], document["source_id"], document["revision_hash"], raw)
	} else {
		_, err = tx.Exec(ctx, "INSERT INTO source_receipts(tenant_id,id,source_id,revision_id,kind,document) VALUES($1,$2,$3,$4,$5,$6)", tx.Tenant, document["id"], document["source_id"], document["revision_id"], document["kind"], raw)
	}
	return err
}

// Capture is default-off until an operator supplies a binding and archive/read
// dependencies. Successful absence is ASG-only point evidence. No EKS/ECS or
// other-controller completeness, unmanaged, deployment or execution fact is made.
func (p *ControllerDiscoveryPipeline) Capture(ctx context.Context, tenant, bindingID string) (model.Document, error) {
	if p == nil || p.Store == nil || p.ReaderFactory == nil || p.Archive == nil {
		return nil, errors.New("CONTROLLER_DISCOVERY_DEPENDENCIES_REQUIRED")
	}
	target, ok := p.Bindings[bindingID]
	if !ok || target.Binding.TenantID != tenant {
		return nil, errors.New("CONTROLLER_DISCOVERY_APPROVED_BINDING_REQUIRED")
	}
	encoded, err := json.Marshal(map[string]ControllerDiscoveryTarget{bindingID: target})
	if err != nil {
		return nil, err
	}
	if _, err = ControllerDiscoveryBindings(string(encoded)); err != nil {
		return nil, err
	}
	var registration model.Document
	var roster []model.Document
	var nativeIDs []string
	err = p.Store.Do(ctx, tenant, func(tx *store.Tx) error {
		var e error
		registration, e = tx.SourceGet(ctx, target.SourceID)
		if e != nil {
			return e
		}
		roster, nativeIDs, e = controllerDiscoveryRoster(ctx, tx, target)
		return e
	})
	if err != nil {
		return nil, err
	}
	approved, err := ParseRegistration(registration)
	if err != nil || !approved.Enabled || model.Bool(registration, "revoked") || approved.TenantID != tenant || approved.Region != target.Binding.Region {
		return nil, errors.New("CONTROLLER_DISCOVERY_SOURCE_REQUIRED")
	}
	accountOK := approved.PayerAccountID == target.Binding.AccountID
	for _, id := range approved.UsageAccountIDs {
		accountOK = accountOK || id == target.Binding.AccountID
	}
	if !accountOK {
		return nil, errors.New("CONTROLLER_DISCOVERY_ACCOUNT_NOT_REGISTERED")
	}
	reader, err := p.ReaderFactory(ctx, approved, target.Binding.AccountID)
	if err != nil {
		return nil, err
	}
	call, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	native, err := reader.ControllerDiscovery(call, target.Binding.Region, target.Binding.AccountID, nativeIDs)
	if err != nil {
		return nil, err
	}
	if native.CollectedAt.Before(p.now().Add(-2*time.Minute)) || native.CollectedAt.After(p.now().Add(5*time.Second)) {
		return nil, errors.New("CONTROLLER_DISCOVERY_OBSERVATION_STALE")
	}
	if err = provider.ValidateControllerDiscoveryEvidence(call, native, target.Binding.Region, target.Binding.AccountID, nativeIDs); err != nil {
		return nil, err
	}
	graphHash, err := controllerDiscoveryNativeGraph(native.Raw)
	if err != nil {
		return nil, err
	}
	archive, err := p.Archive(ctx, tenant, bindingID, native.Raw)
	if err != nil {
		return nil, err
	}
	if model.String(archive, "bucket") == "" || !strings.HasPrefix(model.String(archive, "key"), "tenant/"+tenant+"/fleet/"+bindingID+"/") || strings.Contains(model.String(archive, "key"), "..") || strings.ContainsAny(model.String(archive, "key"), "\\\x00\r\n") || model.String(archive, "version_id") == "" || model.String(archive, "version_id") == "null" || model.String(archive, "body_sha256") != native.RawSHA256 {
		return nil, errors.New("CONTROLLER_DISCOVERY_RAW_READBACK_REQUIRED")
	}
	config, rosterHash, targetHash := ConfigurationHash(registration), Hash(roster), Hash(target)
	revisionHash := Hash(model.Document{"kind": ControllerDiscoveryKind, "source_id": target.SourceID, "registration_version": approved.Version, "config_hash": config, "binding_id": bindingID, "target_sha256": targetHash, "roster_sha256": rosterHash, "controller_graph_sha256": graphHash, "raw_sha256": native.RawSHA256})
	revisionID := "controller-rev-" + revisionHash
	doc := model.Document{"id": "controller-" + Hash(model.Document{"revision": revisionID, "collected_at": native.CollectedAt}), "kind": ControllerDiscoveryKind, "source_id": target.SourceID, "revision_id": revisionID, "registration_version": approved.Version, "read_role_binding_id": approved.ReadRoleBindingID, "config_hash": config, "binding_id": bindingID, "binding": target.Binding, "resource_ids": nativeIDs, "roster_snapshot": roster, "roster_sha256": rosterHash, "target_sha256": targetHash, "controller_graph_sha256": graphHash, "native": Object(native), "collected_at": native.CollectedAt, "raw_object": archive, "execution_authorized": false}
	metadata, err := json.Marshal(doc)
	if err != nil || len(metadata) > 8<<20 {
		return nil, errors.New("CONTROLLER_DISCOVERY_METADATA_LIMIT")
	}
	var result model.Document
	err = p.Store.Do(ctx, tenant, func(tx *store.Tx) error {
		if _, e := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", tenant+":dependency-graph"); e != nil {
			return e
		}
		var sourceLocked bool
		if e := tx.QueryRow(ctx, "SELECT pg_try_advisory_xact_lock_shared(hashtextextended($1,0))", tenant+":trusted-source:"+target.SourceID).Scan(&sourceLocked); e != nil {
			return e
		}
		if !sourceLocked {
			return errors.New("CONTROLLER_DISCOVERY_SOURCE_BUSY")
		}
		current, e := tx.SourceGet(ctx, target.SourceID)
		if e != nil {
			return e
		}
		currentRoster, currentIDs, e := controllerDiscoveryRoster(ctx, tx, target)
		if e != nil {
			return e
		}
		if !model.Bool(current, "enabled") || model.Bool(current, "revoked") || model.Number(current, "version") != approved.Version || ConfigurationHash(current) != config || Hash(currentRoster) != rosterHash || Hash(currentIDs) != Hash(nativeIDs) || native.CollectedAt.Before(p.now().Add(-2*time.Minute)) || native.CollectedAt.After(p.now().Add(5*time.Second)) {
			return errors.New("CONTROLLER_DISCOVERY_SOURCE_OR_ROSTER_CHANGED")
		}
		if existing, e := controllerDiscoveryEvidenceGet(ctx, tx, model.String(doc, "id"), false); e == nil {
			if model.String(existing, "revision_id") != revisionID || model.String(existing, "roster_sha256") != rosterHash || Hash(existing["native"]) != Hash(doc["native"]) {
				return errors.New("CONTROLLER_DISCOVERY_REPLAY_CONFLICT")
			}
			result = existing
			return nil
		} else if e != pgx.ErrNoRows {
			return e
		}
		if _, e = controllerDiscoveryEvidenceGet(ctx, tx, revisionID, true); e == pgx.ErrNoRows {
			if e = controllerDiscoveryEvidenceCreate(ctx, tx, model.Document{"id": revisionID, "source_id": target.SourceID, "kind": ControllerDiscoveryKind, "revision_hash": revisionHash, "registration_version": approved.Version, "read_role_binding_id": approved.ReadRoleBindingID, "config_hash": config, "binding_id": bindingID, "binding": target.Binding, "resource_ids": nativeIDs, "roster_sha256": rosterHash, "target_sha256": targetHash, "controller_graph_sha256": graphHash, "raw_object": archive, "observed_at": native.CollectedAt}, true); e != nil {
				return e
			}
		} else if e != nil {
			return e
		}
		if e = controllerDiscoveryEvidenceCreate(ctx, tx, doc, false); e != nil {
			return e
		}
		result, e = controllerDiscoveryEvidenceGet(ctx, tx, model.String(doc, "id"), false)
		return e
	})
	return result, err
}

var _ ControllerDiscoveryReader = (*provider.AWS)(nil)
