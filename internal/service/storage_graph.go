package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/configuration"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/evidence"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/jackc/pgx/v5"
)

// Private snapshot metadata is loaded from immutable columns, never from a
// public projection. Strip it before hashing or publishing the issued document.
func storageAuthorityDocument(authority model.Document) model.Document {
	out := storageObject(authority)
	delete(out, "_resource_snapshot")
	delete(out, "_column_content_hash")
	return out
}

func storageConfigurationAuthority(ctx context.Context, t *store.Tx, resourceID string) (model.Document, error) {
	var document, snapshot []byte
	var contentHash string
	if err := t.QueryRow(ctx, "SELECT document,resource_snapshot,content_hash FROM configuration_authority_revisions WHERE tenant_id=$1 AND resource_id=$2 ORDER BY version DESC LIMIT 1", t.Tenant, resourceID).Scan(&document, &snapshot, &contentHash); err != nil {
		return nil, err
	}
	authority, err := decodeDatabaseDocument(document)
	if err != nil {
		return nil, err
	}
	previous, err := decodeDatabaseDocument(snapshot)
	if err != nil {
		return nil, err
	}
	authority["_resource_snapshot"] = previous
	authority["_column_content_hash"] = contentHash
	return authority, nil
}

func storageBoundAuthority(authority, resource model.Document, tenant string) bool {
	if !storageResource(resource) || model.String(resource, "provider") != "AWS" || model.String(resource, "provider_resource_id") == "" || model.String(resource, "account_id") == "" || model.String(resource, "region") == "" || tenant == "" || model.String(authority, "tenant_id") != tenant || model.String(authority, "writer_role") != "finops_api" || model.String(authority, "id") == "" || model.Number(authority, "version") < 1 || model.String(authority, "schema_version") != "1" || model.String(authority, "status") != "DECLARED_NOT_ATTESTED" || authority["execution_authorized"] != false || model.String(authority, "declared_by") == "" {
		return false
	}
	doc := storageAuthorityDocument(authority)
	contentHash := model.String(doc, "hash")
	if len(contentHash) != 64 || contentHash != model.String(authority, "_column_content_hash") {
		return false
	}
	core := storageObject(doc)
	for _, key := range []string{"tenant_id", "hash", "created_at", "writer_role"} {
		delete(core, key)
	}
	// Version-1 declarations hash the embedded binding as its original typed
	// structure. Reproduce that issued wire order after JSONB map decoding.
	bindingRaw, marshalErr := json.Marshal(core["binding"])
	var issuedBinding configuration.Binding
	decoder := json.NewDecoder(bytes.NewReader(bindingRaw))
	decoder.DisallowUnknownFields()
	if marshalErr != nil || decoder.Decode(&issuedBinding) != nil {
		return false
	}
	core["binding"] = issuedBinding
	if evidence.Hash(core) != contentHash {
		return false
	}
	binding, previous := storageObject(authority["binding"]), storageObject(authority["_resource_snapshot"])
	if binding["tenant_id"] != tenant || model.String(binding, "provider") != "AWS" || binding["resource_id"] != resource["id"] || binding["workload_id"] != resource["workload_id"] || binding["provider_resource_id"] != resource["provider_resource_id"] || binding["account_id"] != resource["account_id"] || binding["region"] != resource["region"] || model.String(binding, "workload_id") == "" || model.Number(binding, "resource_version") < 1 || model.Number(binding, "resource_version") != model.Number(previous, "version") || model.String(binding, "resource_snapshot_hash") != evidence.Hash(previous) || StorageConfigurationHash(previous) != StorageConfigurationHash(resource) {
		return false
	}
	switch model.String(authority, "authority") {
	case "TERRAFORM":
		declaration := model.Document{}
		for _, key := range []string{"schema_version", "authority", "repository", "pipeline", "terraform"} {
			declaration[key] = doc[key]
		}
		raw, err := json.Marshal(declaration)
		if err != nil {
			return false
		}
		d, err := configuration.Decode(raw)
		if err != nil {
			return false
		}
		expected := "aws_ebs_volume"
		if model.String(resource, "resource_type") == "EBS_SNAPSHOT" {
			expected = "aws_ebs_snapshot"
		}
		for _, address := range d.Terraform.Addresses {
			parts := strings.Split(address, ".")
			if len(parts) < 2 || parts[len(parts)-2] != expected {
				return false
			}
		}
	case "MANUAL", "GITOPS", "CLOUDFORMATION", "OTHER_DECLARATIVE":
		// These can qualify only if an actual registered immutable issuer has
		// produced the same scoped declaration. This helper creates no issuer.
	default:
		return false
	}
	return true
}

// Only graph-local reference nodes are projected. No inventory entity, observed
// state, saved plan, execution permission or historical binding is manufactured.
func storageGraphResources(ctx context.Context, t *store.Tx, resources []model.Document) ([]model.Document, error) {
	out := append([]model.Document{}, resources...)
	for i, resource := range resources {
		if !storageResource(resource) {
			continue
		}
		// Public inventory metadata cannot commission this context. Rebuild it
		// only from the current immutable ingester row and exact resource hash.
		resource = storageObject(resource)
		delete(resource, "storage_stop_context")
		out[i] = resource
		if storageGraphPhysicalRelationship(resource) {
			proof, err := storageGraphPhysicalProof(ctx, t, resource)
			if err != nil && !errors.Is(err, pgx.ErrNoRows) {
				return nil, err
			}
			if context := storageGraphStopContext(proof, resource, t.Tenant, time.Now().UTC()); context != nil {
				resource["storage_stop_context"] = context
			}
		}
		authority, err := storageConfigurationAuthority(ctx, t, model.String(resource, "id"))
		if errors.Is(err, pgx.ErrNoRows) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if !storageBoundAuthority(authority, resource, t.Tenant) {
			continue
		}
		doc := storageAuthorityDocument(authority)
		id := "ebs-iac-reference-" + model.String(doc, "id")
		nativeID := "configuration-authority:" + model.String(doc, "id")
		ref := model.Document{"id": doc["id"], "version": strconv.FormatInt(model.Number(doc, "version"), 10), "sha256": evidence.Hash(doc), "declaration_hash": doc["hash"], "status": "DECLARED_NOT_ATTESTED", "basis": "REGISTERED_CONFIGURATION_DECLARATION", "execution_authorized": false}
		out = append(out, model.Document{"id": id, "tenant_id": t.Tenant, "provider": "AWS", "account_id": resource["account_id"], "region": resource["region"], "resource_type": "IAC_AUTHORITY_REFERENCE", "provider_resource_id": nativeID, "name": "Registered configuration declaration", "configuration_authority_reference": ref})
		copy := storageObject(resource)
		relationships := storageRows(copy["provider_relationships"])
		copy["provider_relationships"] = append(relationships, model.Document{"type": "CONFIGURED_BY", "target_resource_id": id, "target_provider_resource_id": nativeID, "basis": "REGISTERED_CONFIGURATION_DECLARATION", "authority_id": ref["id"], "authority_version": ref["version"], "authority_sha256": ref["sha256"]})
		out[i] = copy
	}
	return out, nil
}

func storageGraphPhysicalRelationship(r model.Document) bool {
	for _, rel := range storageRows(r["provider_relationships"]) {
		if rel["basis"] == "NATIVE_EBS_POINT_RELATIONSHIP" && (r["resource_type"] == "EBS_VOLUME" && rel["type"] == "ATTACHED_TO" || r["resource_type"] == "EBS_SNAPSHOT" && rel["type"] == "BACKED_BY") {
			return true
		}
	}
	return false
}

func storageGraphPhysicalProof(ctx context.Context, t *store.Tx, r model.Document) (model.Document, error) {
	var raw []byte
	err := t.QueryRow(ctx, `SELECT document||jsonb_build_object('_row_writer_role',writer_role,'_row_config_hash',config_hash,'_row_content_hash',content_hash,'_row_id',id,'_row_created_at',created_at) FROM storage_evidence_snapshots WHERE tenant_id=$1 AND resource_id=$2 AND account_id=$3 AND region=$4 ORDER BY created_at DESC,id DESC LIMIT 1`, t.Tenant, r["id"], r["account_id"], r["region"]).Scan(&raw)
	if err != nil {
		return nil, err
	}
	return decodeDatabaseDocument(raw)
}

// Freshness is rechecked at every graph/forward read, independently from the
// stable graph hash. Acquisition clocks, page hashes and receipt IDs cannot
// renew changed physical facts or require a new review for identical facts.
func storageGraphStopContext(proof, r model.Document, tenant string, now time.Time) model.Document {
	at, ae := time.Parse(time.RFC3339Nano, model.String(proof, "observed_at"))
	created, ce := time.Parse(time.RFC3339Nano, model.String(proof, "_row_created_at"))
	archive := storageObject(proof["archive"])
	configHash, contentHash := model.String(proof, "_row_config_hash"), model.String(proof, "_row_content_hash")
	if !storageResource(r) || r["tenant_id"] != tenant || tenant == "" || proof["_row_writer_role"] != "finops_ingester" || model.String(proof, "_row_id") == "" || proof["schema_version"] != "1" || proof["resource_id"] != r["id"] || proof["account_id"] != r["account_id"] || proof["region"] != r["region"] || len(configHash) != 64 || configHash != StorageConfigurationHash(r) || proof["config_hash"] != configHash || len(contentHash) != 64 || proof["content_hash"] != contentHash || archive["body_sha256"] != contentHash || model.String(archive, "version_id") == "" || archive["version_id"] == "null" || model.String(archive, "key") == "" && model.String(archive, "object_key") == "" || ae != nil || ce != nil || at.After(now) || created.After(now.Add(30*time.Second)) || created.Before(at) || now.Sub(at) > 10*time.Minute {
		return nil
	}
	n := storageObject(r["storage_configuration"])
	if n["account_id"] != r["account_id"] || n["region"] != r["region"] || n["provider_resource_id"] != r["provider_resource_id"] {
		return nil
	}
	native := model.Document{}
	for _, key := range []string{"volume_id", "snapshot_id", "state", "multi_attach_enabled", "operator", "attachments"} {
		if value, ok := n[key]; ok {
			native[key] = value
		}
	}
	return model.Document{"schema_version": "1", "basis": "CURRENT_INGESTER_EBS_CONFIGURATION_V1", "writer_role": "finops_ingester", "tenant_id": tenant, "resource_id": r["id"], "provider_resource_id": r["provider_resource_id"], "resource_type": r["resource_type"], "account_id": r["account_id"], "region": r["region"], "workload_id": r["workload_id"], "config_hash": configHash, "native": native}
}
