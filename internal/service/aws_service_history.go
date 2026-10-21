package service

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/awsservice"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/native"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/telemetry"
	"github.com/jackc/pgx/v5"
)

// Historical ECS demand comes from a separately registered native telemetry
// reader. It never creates the guarded minute-ingress receipts, and an AWS task
// roster at assessment time cannot substitute for the observed service epoch.
func awsServiceHistoricalDemand(ctx context.Context, a *API, tx *store.Tx, resource, configuration model.Document, start, end time.Time, read databaseArchiveRead) (model.Document, []model.Document, []model.Document, []string, error) {
	missing := []string{"INSUFFICIENT_HISTORICAL_DEMAND"}
	if a.Store == nil || read == nil || !end.After(start) {
		return nil, nil, nil, missing, nil
	}
	rows, err := tx.Query(ctx, `SELECT c.id FROM telemetry_connections c WHERE c.tenant_id=$1 AND c.kind='PROMETHEUS' AND c.config->'binding'->>'resource_id'=$2 AND c.config->>'enabled'='true' AND NOT EXISTS(SELECT 1 FROM telemetry_connections n WHERE n.tenant_id=c.tenant_id AND n.id=c.id AND n.version>c.version) ORDER BY c.created_at,c.id LIMIT 3`, tx.Tenant, model.String(resource, "id"))
	if err != nil {
		return nil, nil, nil, nil, err
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			break
		}
		ids = append(ids, id)
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return nil, nil, nil, nil, err
	}
	binding := telemetry.Binding{TenantID: tx.Tenant, ResourceID: model.String(resource, "id"), WorkloadID: model.String(resource, "workload_id"), Provider: model.String(resource, "provider"), ProviderResourceID: model.String(resource, "provider_resource_id"), AccountID: model.String(resource, "account_id"), Region: model.String(resource, "region")}
	var connection telemetry.Connection
	var selected model.Document
	for _, id := range ids {
		candidate, err := tx.TelemetryConnection(ctx, id)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		if model.Bool(candidate, "revoked") {
			continue
		}
		parsed, err := telemetry.ParseConnection(candidate)
		if err != nil || !parsed.Enabled || parsed.Binding != binding {
			return nil, nil, nil, []string{"ECS_HISTORICAL_SERVICE_SOURCE_BINDING_CHANGED"}, nil
		}
		if selected != nil {
			return nil, nil, nil, []string{"ECS_HISTORICAL_SERVICE_SOURCE_AMBIGUOUS"}, nil
		}
		connection, selected = parsed, candidate
	}
	if selected == nil {
		return nil, nil, nil, missing, nil
	}
	var receiptID string
	err = tx.QueryRow(ctx, `SELECT id FROM telemetry_receipts WHERE tenant_id=$1 AND connection_id=$2 AND revision_id=$3 ORDER BY created_at DESC,id DESC LIMIT 1`, tx.Tenant, connection.ID, model.String(selected, "revision_id")).Scan(&receiptID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, nil, missing, nil
	}
	if err != nil {
		return nil, nil, nil, nil, err
	}
	receipt, err := tx.TelemetryReceipt(ctx, receiptID)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	from, leftErr := time.Parse(time.RFC3339Nano, model.String(receipt, "query_start"))
	until, rightErr := time.Parse(time.RFC3339Nano, model.String(receipt, "query_end"))
	if !model.Bool(receipt, "active_source") || receipt["config_hash"] != telemetry.ConfigHash(connection) || leftErr != nil || rightErr != nil || from.After(start) || until.Before(end) {
		return nil, nil, nil, missing, nil
	}
	pipeline := native.Pipeline{Store: a.Store, ReadObject: read}
	batch, err := pipeline.ReadBatch(ctx, tx.Tenant, receipt)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	if batch.Binding != binding || batch.SourceKind != "PROMETHEUS" || batch.CollectedAt.After(a.now().Add(time.Minute)) {
		return nil, nil, nil, []string{"ECS_HISTORICAL_SERVICE_SOURCE_BINDING_CHANGED"}, nil
	}
	ref := storageRef("AWS_SERVICE_HISTORICAL_DEMAND_RECEIPT", receiptID, strconv.FormatInt(connection.Version, 10), model.String(receipt, "canonical_hash"))
	ref["binding"] = storageBinding(tx.Tenant, resource)
	history, activity, err := awsservice.ServiceHistoryFromBatch(connection, batch, start, end, configuration, ref)
	if err != nil {
		return nil, nil, nil, []string{"ECS_HISTORICAL_SERVICE_EVIDENCE_INVALID"}, nil
	}
	revisionRef := storageRef("NATIVE_TELEMETRY_SOURCE_REVISION", model.String(selected, "revision_id"), strconv.FormatInt(connection.Version, 10), telemetry.ConfigHash(connection))
	return history, activity, []model.Document{ref, revisionRef}, model.Strings(history, "reason_codes"), nil
}

func awsServiceHistoricalReferencesCurrent(ctx context.Context, tx *store.Tx, refs []model.Document) (bool, error) {
	for _, ref := range refs {
		switch ref["kind"] {
		case "AWS_SERVICE_HISTORICAL_DEMAND_RECEIPT":
			receipt, err := tx.TelemetryReceipt(ctx, model.String(ref, "id"))
			if errors.Is(err, pgx.ErrNoRows) {
				return false, nil
			}
			if err != nil {
				return false, err
			}
			if !model.Bool(receipt, "active_source") || receipt["canonical_hash"] != ref["sha256"] {
				return false, nil
			}
		case "NATIVE_TELEMETRY_SOURCE_REVISION":
			revision, err := tx.TelemetryRevision(ctx, model.String(ref, "id"))
			if errors.Is(err, pgx.ErrNoRows) {
				return false, nil
			}
			if err != nil {
				return false, err
			}
			if model.Bool(revision, "revoked") || model.Bool(revision, "superseded") || revision["config_hash"] != ref["sha256"] {
				return false, nil
			}
		}
	}
	return true, nil
}
