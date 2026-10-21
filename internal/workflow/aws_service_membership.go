package workflow

import (
	"context"
	"errors"
	"strings"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/awsservice"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/jackc/pgx/v5"
)

// A positive native container-instance membership can only add a STOP blocker.
// Absence from a bounded collection never clears management or ownership, and
// existing owned START restoration remains independent of this classification.
func retainAWSServiceManagement(ctx context.Context, tx *store.Tx, r awsservice.Registration, generation string, row model.Document) error {
	if model.String(row, "resource_type") != "ECS_CONTAINER_INSTANCE" {
		return nil
	}
	for _, relation := range awsservice.Rows(row["provider_relationships"]) {
		target := model.String(relation, "target_provider_resource_id")
		if model.String(relation, "type") != "RUNS_ON" || !strings.HasPrefix(target, "i-") {
			continue
		}
		var id string
		err := tx.QueryRow(ctx, `SELECT id FROM entities WHERE tenant_id=$1 AND kind='resources' AND document->>'provider'='AWS' AND document->>'resource_type'='EC2' AND document->>'account_id'=$2 AND document->>'region'=$3 AND document->>'provider_resource_id'=$4`, tx.Tenant, r.AccountID, r.Region, target).Scan(&id)
		if errors.Is(err, pgx.ErrNoRows) {
			continue
		}
		if err != nil {
			return err
		}
		instance, err := tx.Get(ctx, "resources", id)
		if err != nil {
			return err
		}
		if model.Bool(instance, "fleet_managed") {
			continue
		}
		version := model.Number(instance, "version")
		instance["fleet_managed"] = true
		instance["aws_service_management_evidence"] = model.Document{"kind": "ECS_CONTAINER_INSTANCE_MEMBERSHIP", "source_id": r.ID, "source_version": r.Version, "generation_id": generation, "container_instance_arn": row["provider_resource_id"], "analytical": true}
		if _, err = tx.Update(ctx, "resources", id, version, instance); err != nil {
			return err
		}
	}
	return nil
}
