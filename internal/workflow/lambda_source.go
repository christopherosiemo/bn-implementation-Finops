package workflow

import (
	"context"
	"errors"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/lambdacost"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/native"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/jackc/pgx/v5"
)

type LambdaRegisteredReader interface {
	LambdaNativeReader
	LambdaDiscover(context.Context, lambdacost.Scope, lambdacost.DiscoverySelection) (lambdacost.Discovery, error)
}

// SyncLambdaNativeSource uses the private registered role, retaining one native
// account page per tick and publishing only the exact registered function and
// qualifier. Registration versions reset old cursors. No receipt is invented
// for a configuration registration; native observation references stay separate.
func SyncLambdaNativeSource(ctx context.Context, a *Activities, storage *native.Storage, reader LambdaRegisteredReader, r lambdacost.Registration, reports []lambdacost.Registration, options LambdaCollectionOptions) error {
	if lambdacost.ValidateRegistration(r) != nil || r.Kind != lambdacost.NativeKind || !r.Enabled {
		return lambdacost.ErrEvidence
	}
	marker := ""
	err := a.Store.Do(ctx, r.TenantID, func(tx *store.Tx) error {
		current, e := tx.SourceGet(ctx, r.ID)
		if e != nil {
			return e
		}
		if !model.Bool(current, "enabled") || model.Bool(current, "revoked") || model.Number(current, "version") != r.Version || model.String(current, "function_arn") != r.FunctionARN || model.String(current, "qualifier") != r.Qualifier || model.String(current, "read_role_binding_id") != r.ReadRoleBindingID {
			return errors.New("LAMBDA_SOURCE_CHANGED_BEFORE_SYNC")
		}
		checkpoint, e := tx.SourceCheckpointGet(ctx, r.ID, "lambda-native-discovery")
		if e == nil && model.Number(checkpoint, "registration_version") == r.Version {
			marker = model.String(checkpoint, "next_marker")
		} else if e != nil && e != pgx.ErrNoRows {
			return e
		}
		return nil
	})
	if err != nil {
		return err
	}
	scope := lambdacost.Scope{TenantID: r.TenantID, AccountID: r.AccountID, Region: r.Region}
	discovery, err := reader.LambdaDiscover(ctx, scope, lambdacost.DiscoverySelection{Marker: marker, MaxFunctions: 5, FunctionARN: r.FunctionARN})
	if err != nil {
		return err
	}
	selected := []model.Document{}
	for _, row := range discovery.Functions {
		if model.String(row, "provider_resource_id") == r.FunctionARN {
			selected = append(selected, row)
		}
	}
	discovery.Functions = selected
	options.NativeRegistration = &r
	published := []model.Document{}
	if len(selected) > 0 {
		published, err = CollectAndPublishLambda(ctx, a.Store, storage, reader, discovery, "", reports, options)
		if err != nil {
			return err
		}
	}
	status, reason, next := "SYNCING", "LAMBDA_REGISTERED_FUNCTION_SEARCH_IN_PROGRESS", discovery.NextMarker
	if len(published) > 0 {
		status, reason, next = "HEALTHY", "LAMBDA_REGISTERED_NATIVE_EVIDENCE_PERSISTED", ""
	} else if len(selected) > 0 {
		status, reason, next = "BLOCKED", "LAMBDA_REGISTERED_QUALIFIER_UNAVAILABLE", ""
	} else if discovery.Complete {
		status, reason, next = "BLOCKED", "LAMBDA_REGISTERED_FUNCTION_NOT_OBSERVED", ""
	}
	return a.Store.Do(ctx, r.TenantID, func(tx *store.Tx) error {
		current, e := tx.SourceGet(ctx, r.ID)
		if e != nil {
			return e
		}
		if !model.Bool(current, "enabled") || model.Bool(current, "revoked") || model.Number(current, "version") != r.Version {
			return errors.New("LAMBDA_SOURCE_CHANGED_DURING_SYNC")
		}
		if e = tx.SourceCheckpointSet(ctx, r.ID, "lambda-native-discovery", model.Document{"registration_version": r.Version, "next_marker": next, "target_observed": len(selected) > 0, "qualifier_published": len(published) > 0}); e != nil {
			return e
		}
		checkpoint := model.Document{"status": status, "reason_code": reason, "last_sync_version": r.Version, "config_hash": lambdacost.Hash(r)}
		if status != "SYNCING" {
			checkpoint["last_sync_at"] = model.Now()
		}
		return tx.SourceCheckpointSet(ctx, r.ID, "status", checkpoint)
	})
}
