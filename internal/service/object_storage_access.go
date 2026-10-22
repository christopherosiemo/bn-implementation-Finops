package service

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/auth"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/evidence"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
)

func (a *API) objectStorageAccessMutate(ctx context.Context, t *store.Tx, i auth.Identity, r *http.Request, in model.Document) (model.Document, int, bool, error) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/v1/"), "/")
	if parts[0] != "object-storage-access-sources" {
		return nil, 0, false, nil
	}
	if err := requireRole(i, "PLATFORM_ADMIN"); err != nil {
		return nil, 0, true, err
	}
	if len(parts) == 3 && parts[2] == "revoke" {
		if len(in) != 0 {
			return nil, 0, true, problem(422, "OBJECT_STORAGE_ACCESS_REVOKE_FIELDS", "source revocation accepts no observation fields")
		}
		source, err := t.ObjectStorageAccessSourceGet(ctx, parts[1])
		if err != nil {
			return nil, 0, true, err
		}
		if err = match(r, model.Document{"version": source.Version}); err != nil {
			return nil, 0, true, err
		}
		if !source.Enabled {
			return evidence.Object(source), 200, true, nil
		}
		source, err = t.ObjectStorageAccessRevoke(ctx, source.ID, i.Subject)
		if err == nil {
			err = t.Audit(ctx, i.Subject, "object_storage.access_source.revoked", source.ID, model.Document{"resource_id": source.ResourceID, "dataset_id": source.DatasetID})
		}
		return evidence.Object(source), 200, true, err
	}
	if len(parts) != 1 {
		return nil, 0, true, problem(404, "NOT_FOUND", "unknown object storage access source operation")
	}
	if err := match(r, model.Document{"version": 0}); err != nil {
		return nil, 0, true, err
	}
	for key := range in {
		if key != "resource_id" && key != "dataset_id" && key != "subject" && key != "metric_definition" && key != "authoritative_access_scope" {
			return nil, 0, true, problem(422, "OBJECT_STORAGE_ACCESS_SOURCE_FIELDS", "only resource, dataset, machine subject, metric definition and declared access scope are accepted")
		}
	}
	declared, ok := in["authoritative_access_scope"].(bool)
	if !ok {
		return nil, 0, true, problem(422, "OBJECT_STORAGE_ACCESS_SCOPE_REQUIRED", "explicitly declare whether this application collector observes every dataset read path; declaration is not independent coverage proof")
	}
	resource, err := t.Get(ctx, "resources", model.String(in, "resource_id"))
	if err != nil {
		return nil, 0, true, err
	}
	if !objectStorageResource(resource) {
		return nil, 0, true, problem(422, "S3_BUCKET_REQUIRED", "select a discovered S3 bucket")
	}
	dataset, err := t.ObjectStorageDatasetGet(ctx, model.String(in, "dataset_id"))
	if err != nil {
		return nil, 0, true, err
	}
	if model.String(dataset, "resource_id") != model.String(resource, "id") {
		return nil, 0, true, problem(422, "OBJECT_STORAGE_ACCESS_DATASET_SCOPE", "dataset belongs to another bucket")
	}
	var metric store.ActivityMetric
	raw, err := json.Marshal(in["metric_definition"])
	if err != nil || strictSLO(storageObject(in["metric_definition"]), &metric) != nil || metric.Unit != store.ObjectStorageAccessUnit {
		return nil, 0, true, problem(422, "OBJECT_STORAGE_ACCESS_METRIC_INVALID", "versioned s3-get-requests-and-bytes definition required")
	}
	if json.Unmarshal(raw, &metric) != nil {
		return nil, 0, true, problem(422, "OBJECT_STORAGE_ACCESS_METRIC_INVALID", "versioned metric definition required")
	}
	source, err := t.ObjectStorageAccessRegister(ctx, store.ObjectStorageAccessSource{ResourceID: model.String(resource, "id"), DatasetID: model.String(dataset, "id"), DatasetVersion: model.Number(dataset, "version"), ProviderResourceID: model.String(resource, "provider_resource_id"), AccountID: model.String(resource, "account_id"), Region: model.String(resource, "region"), Issuer: env("ACTIVITY_OIDC_ISSUER", a.Config.Issuer), Subject: model.String(in, "subject"), MetricDefinition: metric, AuthoritativeAccessScope: declared})
	if err != nil {
		return nil, 0, true, evidenceProblem(err)
	}
	err = t.Audit(ctx, i.Subject, "object_storage.access_source.registered", source.ID, model.Document{"resource_id": source.ResourceID, "dataset_id": source.DatasetID, "dataset_version": source.DatasetVersion, "authoritative_access_scope_declared": declared})
	return evidence.Object(source), 201, true, err
}

func (a *API) objectStorageAccessGet(ctx context.Context, t *store.Tx, i auth.Identity, r *http.Request) (any, bool, error) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/v1/"), "/")
	if parts[0] != "object-storage-access-sources" {
		return nil, false, nil
	}
	if len(parts) == 2 {
		source, err := t.ObjectStorageAccessSourceGet(ctx, parts[1])
		if err == nil {
			err = storageReadScope(ctx, t, i, source.ResourceID)
		}
		return evidence.Object(source), true, err
	}
	if len(parts) != 1 {
		return nil, true, problem(404, "NOT_FOUND", "unknown access source")
	}
	resource := r.URL.Query().Get("resource_id")
	if err := storageReadScope(ctx, t, i, resource); err != nil {
		return nil, true, err
	}
	after, limit, err := storagePage(r, t.Tenant, i.Subject)
	if err != nil {
		return nil, true, err
	}
	rows, err := t.ObjectStorageAccessSourcePage(ctx, after, resource, limit+1)
	if err != nil {
		return nil, true, err
	}
	next := ""
	if len(rows) > limit {
		rows = rows[:limit]
		next = model.String(rows[len(rows)-1], "id")
	}
	return model.Document{"items": rows, "next_cursor": storageNextCursor(r, t.Tenant, i.Subject, next)}, true, nil
}
