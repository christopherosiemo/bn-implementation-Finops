package service

import (
	"context"
	"encoding/json"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/lambdacost"
	"net/http"
	"os"
	"strings"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/auth"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/network"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/objectstorage"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/source"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
)

// Registrations identify provider locations, never credentials or authoritative
// billing data. Only the ingestion identity can publish authenticated receipts.
func (a *API) sourceMutate(ctx context.Context, t *store.Tx, i auth.Identity, r *http.Request, in model.Document, parts []string) (model.Document, int, bool, error) {
	if len(parts) == 0 || parts[0] != "source-connections" {
		return nil, 0, false, nil
	}
	if e := requireRole(i, "FINOPS_ADMIN", "PLATFORM_ADMIN"); e != nil {
		return nil, 0, true, e
	}
	if len(parts) == 1 {
		d := model.Clone(in)
		allowed := map[string]bool{"kind": true, "payer_account_id": true, "usage_account_ids": true, "region": true, "export_arn": true, "read_role_binding_id": true, "bucket": true, "bucket_owner": true, "prefix": true}
		isObjectSource := strings.HasPrefix(model.String(d, "kind"), "AWS_S3_")
		isLambdaSource := strings.HasPrefix(model.String(d, "kind"), "AWS_LAMBDA_")
		isNetworkSource := model.String(d, "kind") == network.FlowKind
		if isLambdaSource {
			allowed = map[string]bool{"kind": true, "account_id": true, "region": true, "function_arn": true, "qualifier": true, "read_role_binding_id": true, "log_group_arn": true, "log_group_name": true, "format": true, "issuer": true, "audience": true, "subject": true, "name": true}
		}
		if isNetworkSource {
			allowed = map[string]bool{"kind": true, "account_id": true, "region": true, "read_role_binding_id": true, "flow_log_id": true, "resource_ids": true, "report_bucket": true, "report_owner": true, "report_region": true, "prefix": true, "fields": true, "traffic_type": true, "max_aggregation_seconds": true}
		}
		if isObjectSource {
			allowed = map[string]bool{"kind": true, "account_id": true, "region": true, "bucket": true, "report_bucket": true, "report_owner": true, "report_region": true, "prefix": true, "inventory_id": true, "read_role_binding_id": true, "dataset_ids": true, "report_type": true}
		}
		for k := range d {
			if !allowed[k] {
				return nil, 0, true, problem(422, "SOURCE_REGISTRATION_FIELDS_INVALID", "only source location and approved binding fields are accepted")
			}
		}
		for _, k := range []string{"credentials", "role_arn", "external_id", "provenance", "complete", "trusted", "source_revision_id", "source_receipt_id"} {
			if _, ok := d[k]; ok {
				return nil, 0, true, problem(422, "SOURCE_REGISTRATION_FIELDS_INVALID", "credentials and evidence authority cannot be submitted")
			}
		}
		d["id"], d["tenant_id"], d["version"], d["enabled"], d["sync_requested"], d["status"] = model.ID(), t.Tenant, 1, true, false, "REGISTERED"
		if isObjectSource {
			datasets := []model.Document{}
			ids := model.Strings(d, "dataset_ids")
			if len(ids) > 256 {
				return nil, 0, true, problem(422, "OBJECT_STORAGE_DATASET_LIMIT", "select at most 256 registered datasets")
			}
			seen := map[string]bool{}
			for _, id := range ids {
				if seen[id] {
					return nil, 0, true, problem(422, "OBJECT_STORAGE_DATASET_DUPLICATE", "dataset IDs must be unique")
				}
				seen[id] = true
				dataset, e := t.ObjectStorageDatasetGet(ctx, id)
				if e != nil {
					return nil, 0, true, e
				}
				resource, e := t.Get(ctx, "resources", model.String(dataset, "resource_id"))
				if e != nil {
					return nil, 0, true, e
				}
				name := strings.TrimPrefix(model.String(resource, "provider_resource_id"), "arn:aws:s3:::")
				if !objectStorageResource(resource) || name != model.String(d, "bucket") || model.String(resource, "account_id") != model.String(d, "account_id") || model.String(resource, "region") != model.String(d, "region") {
					return nil, 0, true, problem(422, "OBJECT_STORAGE_DATASET_SOURCE_SCOPE_MISMATCH", "dataset must belong to the registered bucket/account/region")
				}
				selector := storageObject(dataset["selector"])
				selector["id"] = id
				selector["dataset_version"] = dataset["version"]
				selector["dataset_hash"] = objectStorageDatasetHash(dataset)
				datasets = append(datasets, selector)
			}
			d["datasets"] = datasets
			delete(d, "dataset_ids")
		}
		var validation error
		if isLambdaSource {
			validation = lambdacost.ValidateRegistration(d)
			if model.String(d, "kind") == "AWS_LAMBDA_PERFORMANCE_CURVE_V1" {
				issuer := os.Getenv("LAMBDA_PERFORMANCE_OIDC_ISSUER")
				if issuer == "" {
					issuer = a.Config.Issuer
				}
				aud := os.Getenv("LAMBDA_PERFORMANCE_OIDC_AUDIENCE")
				if aud == "" {
					aud = "finops-lambda-performance"
				}
				if model.String(d, "issuer") != issuer || model.String(d, "audience") != aud || aud == a.Config.Audience || aud == "finops-activity" || aud == "finops-telemetry" || aud == "finops-deployment-observer" {
					return nil, 0, true, problem(422, "LAMBDA_MACHINE_SOURCE_BINDING_INVALID", "use the commissioned independent machine issuer and audience")
				}
			}
		} else if isNetworkSource {
			var registration network.Registration
			raw, _ := json.Marshal(d)
			validation = json.Unmarshal(raw, &registration)
			if validation == nil {
				validation = network.ValidateRegistration(registration)
			}
		} else if isObjectSource {
			validation = objectstorage.ValidateRegistration(d)
		} else {
			validation = source.ValidateRegistration(d)
		}
		if validation != nil {
			return nil, 0, true, problem(422, validation.Error(), "unsupported or incorrectly bound AWS export")
		}
		out, e := t.SourceCreate(ctx, d)
		if e == nil {
			e = t.Audit(ctx, i.Subject, "source.registered", model.String(out, "id"), model.Document{"source_id": out["id"], "read_role_binding_id": out["read_role_binding_id"]})
		}
		return out, 201, true, e
	}
	if len(parts) == 3 && (parts[2] == "sync" || parts[2] == "revoke") {
		d, e := t.SourceGet(ctx, parts[1])
		if e != nil {
			return nil, 0, true, e
		}
		if e = match(r, d); e != nil {
			return nil, 0, true, e
		}
		if parts[2] == "sync" {
			if !model.Bool(d, "enabled") {
				return nil, 0, true, problem(422, "SOURCE_REVOKED", "register a new approved connection before syncing")
			}
			d["sync_requested"], d["status"] = true, "SYNC_QUEUED"
		} else {
			d["enabled"], d["sync_requested"], d["status"] = false, false, "REVOKED"
		}
		out, e := t.SourceUpdate(ctx, parts[1], model.Number(d, "version"), d)
		if e == nil {
			e = t.Audit(ctx, i.Subject, "source."+parts[2], parts[1], model.Document{"source_id": parts[1]})
		}
		return out, 202, true, e
	}
	return nil, 0, true, problem(404, "NOT_FOUND", "unknown source operation")
}

func sourceGet(ctx context.Context, t *store.Tx, path string) (any, bool, error) {
	parts := strings.Split(strings.TrimPrefix(path, "/v1/"), "/")
	if len(parts) == 0 || parts[0] != "source-connections" {
		return nil, false, nil
	}
	if len(parts) == 1 {
		d, e := t.SourceList(ctx)
		return d, true, e
	}
	if len(parts) == 2 {
		d, e := t.SourceGet(ctx, parts[1])
		if e != nil {
			return nil, true, e
		}
		receipts, e := t.SourceReceiptList(ctx, model.String(d, "kind"), parts[1])
		if e != nil {
			return nil, true, e
		}
		d["receipts"] = receipts
		return d, true, nil
	}
	return nil, true, problem(404, "NOT_FOUND", "unknown source resource")
}
