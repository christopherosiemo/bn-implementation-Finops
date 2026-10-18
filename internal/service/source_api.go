package service

import (
	"context"
	"net/http"
	"strings"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/auth"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
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
		if e := source.ValidateRegistration(d); e != nil {
			return nil, 0, true, problem(422, e.Error(), "unsupported or incorrectly bound AWS export")
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
		receipts, e := t.SourceReceiptList(ctx, "AWS_CUR2", parts[1])
		if e != nil {
			return nil, true, e
		}
		d["receipts"] = receipts
		return d, true, nil
	}
	return nil, true, problem(404, "NOT_FOUND", "unknown source resource")
}
