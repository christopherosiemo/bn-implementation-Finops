package service

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/configuration"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/evidence"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/jackc/pgx/v5"
	"strconv"
	"strings"
)

// An inventory label never establishes configuration authority. Initial S3
// support selects an existing immutable Terraform declaration; it grants no
// execution or deployment rights.
func objectStorageAuthority(ctx context.Context, t *store.Tx, r model.Document) (string, model.Document, error) {
	a, e := storageConfigurationAuthority(ctx, t, model.String(r, "id"))
	if errors.Is(e, pgx.ErrNoRows) {
		return "UNKNOWN", nil, nil
	}
	if e != nil {
		return "UNKNOWN", nil, e
	}
	if !objectStorageResource(r) || model.String(a, "tenant_id") != t.Tenant || model.String(a, "writer_role") != "finops_api" || model.String(a, "status") != "DECLARED_NOT_ATTESTED" || a["execution_authorized"] != false || model.String(a, "declared_by") == "" || model.String(a, "authority") != "TERRAFORM" || model.String(r, "configuration_authority") != "TERRAFORM" {
		return "UNKNOWN", nil, nil
	}
	doc := storageAuthorityDocument(a)
	hash := model.String(doc, "hash")
	if len(hash) != 64 || hash != model.String(a, "_column_content_hash") {
		return "UNKNOWN", nil, nil
	}
	core := storageObject(doc)
	for _, k := range []string{"tenant_id", "hash", "created_at", "writer_role"} {
		delete(core, k)
	}
	var binding configuration.Binding
	raw, _ := json.Marshal(core["binding"])
	if json.Unmarshal(raw, &binding) != nil {
		return "UNKNOWN", nil, nil
	}
	core["binding"] = binding
	previous := storageObject(a["_resource_snapshot"])
	if evidence.Hash(core) != hash || binding.TenantID != t.Tenant || binding.ResourceID != model.String(r, "id") || binding.WorkloadID == "" || binding.WorkloadID != model.String(r, "workload_id") || binding.Provider != "AWS" || binding.ProviderResourceID != model.String(r, "provider_resource_id") || binding.AccountID != model.String(r, "account_id") || binding.Region != model.String(r, "region") || binding.ResourceVersion != model.Number(previous, "version") || binding.ResourceSnapshotHash != evidence.Hash(previous) || ObjectStorageConfigurationHash(previous) != ObjectStorageConfigurationHash(r) || model.String(previous, "owner") == "" || model.String(previous, "owner") != model.String(r, "owner") {
		return "UNKNOWN", nil, nil
	}
	declaration := model.Document{}
	for _, k := range []string{"schema_version", "authority", "repository", "pipeline", "terraform"} {
		declaration[k] = doc[k]
	}
	raw, _ = json.Marshal(declaration)
	d, e := configuration.Decode(raw)
	if e != nil {
		return "UNKNOWN", nil, nil
	}
	if e = configuration.ValidateBinding(d, binding); e != nil {
		return "UNKNOWN", nil, nil
	}
	for _, address := range d.Terraform.Addresses {
		parts := strings.Split(address, ".")
		if len(parts) < 2 || parts[len(parts)-2] != "aws_s3_bucket" {
			return "UNKNOWN", nil, nil
		}
	}
	return "TERRAFORM", storageRef("DECLARED_S3_CONFIGURATION_AUTHORITY", model.String(a, "id"), strconv.FormatInt(model.Number(a, "version"), 10), hash), nil
}
