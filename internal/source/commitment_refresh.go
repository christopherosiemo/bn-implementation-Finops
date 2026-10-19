package source

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/jackc/pgx/v5"
)

// Routine three-second workflow ticks must not replace valid quote heads every
// three seconds. Explicit Capture remains a native read; this private scheduled
// path reuses only an issued, still-fresh exact-scope snapshot. Changed source,
// target, commitment economics or complete exposure causes immediate recapture.
func (p *SavingsPlanQuotePipeline) CaptureIfDue(ctx context.Context, target SavingsPlanQuoteTarget) ([]model.Document, error) {
	if p == nil || p.Store == nil {
		return nil, errors.New("SAVINGS_PLAN_QUOTE_DEPENDENCIES_REQUIRED")
	}
	wire, _ := json.Marshal([]SavingsPlanQuoteTarget{target})
	if _, err := SavingsPlanQuoteTargets(string(wire)); err != nil {
		return nil, err
	}
	usable := false
	err := p.Store.Do(ctx, target.TenantID, func(tx *store.Tx) error {
		return tx.QueryRow(ctx, `SELECT EXISTS(
 SELECT 1 FROM source_registrations r
 JOIN source_checkpoints c ON c.tenant_id=r.tenant_id AND c.source_id=r.id AND c.checkpoint_key='status'
 JOIN source_checkpoints q ON q.tenant_id=r.tenant_id AND q.source_id=r.id AND q.checkpoint_key='savings-plan-quotes'
 JOIN source_revisions v ON v.tenant_id=r.tenant_id AND v.source_id=r.id AND v.id=q.document->>'revision_id' AND v.writer_role='finops_ingester'
 JOIN source_receipts old ON old.tenant_id=r.tenant_id AND old.source_id=r.id AND old.id=v.document->>'commitment_receipt_id' AND old.kind='AWS_COMMITMENT' AND old.writer_role='finops_ingester'
 JOIN source_receipts current_inventory ON current_inventory.tenant_id=r.tenant_id AND current_inventory.source_id=r.id AND current_inventory.id=c.document->>'commitment_receipt_id' AND current_inventory.kind='AWS_COMMITMENT' AND current_inventory.writer_role='finops_ingester'
 WHERE current_user='finops_ingester' AND r.tenant_id=$1 AND r.id=$2 AND r.kind='AWS_CUR2' AND r.document->'enabled'='true'::jsonb AND r.document->'revoked' IS DISTINCT FROM 'true'::jsonb
 AND c.document->>'status'='HEALTHY' AND (c.document->>'last_sync_at')::timestamptz BETWEEN $5::timestamptz-interval '5 minutes' AND $5::timestamptz+interval '5 seconds'
 AND v.document->>'kind'='AWS_SAVINGS_PLAN_RATE_QUOTES' AND v.document->>'config_hash'=public.fleet_history_source_config(r.document) AND (v.document->>'registration_version')::bigint=r.version
 AND v.document->'native'->>'authenticated_account_id'=r.document->>'payer_account_id' AND v.document->'native'->'complete'='true'::jsonb
 AND v.document->'native'->>'native_projection'='AWS_SAVINGS_PLAN_RATE_QUOTES_V1' AND v.document->'native'->>'serialization'='SDK_PROJECTION'
 AND v.document->'native'->'selection'->>'payment_option'='No Upfront' AND v.document->'native'->'selection'->'duration_seconds'='31536000'::jsonb
 AND v.document->'native'->'selection'->>'plan_type'=$3 AND v.document->'native'->'selection'->>'currency'=$4
 AND v.document->'observed_at'=q.document->'collected_at' AND v.document->'native'->'observed_at'=v.document->'observed_at'
 AND (q.document->>'collected_at')::timestamptz BETWEEN $5::timestamptz-interval '4 minutes' AND $5::timestamptz+interval '5 seconds'
 AND old.document->>'config_hash'=v.document->>'config_hash' AND current_inventory.document->>'config_hash'=v.document->>'config_hash'
 AND current_inventory.document->'commitment_scope'->'complete'='true'::jsonb
 AND (old.document->'commitment_scope'-ARRAY['receipt_id','observed_at'])=(current_inventory.document->'commitment_scope'-ARRAY['receipt_id','observed_at'])
 )`, target.TenantID, target.SourceID, target.PlanType, target.Currency, p.now()).Scan(&usable)
	})
	if err != nil {
		return nil, err
	}
	if usable {
		return []model.Document{}, nil
	}
	return p.Capture(ctx, target)
}

// ASG snapshots retain the existing two-minute maximum age. Scheduled reads
// renew at ninety seconds, rather than replacing the exact policy proof on each
// workflow tick. Source and whole-roster changes bypass this reuse immediately.
func (p *ControllerDiscoveryPipeline) CaptureIfDue(ctx context.Context, tenant, bindingID string) (model.Document, error) {
	if p == nil || p.Store == nil {
		return nil, errors.New("CONTROLLER_DISCOVERY_DEPENDENCIES_REQUIRED")
	}
	target, ok := p.Bindings[bindingID]
	if !ok || target.Binding.TenantID != tenant {
		return nil, errors.New("CONTROLLER_DISCOVERY_APPROVED_BINDING_REQUIRED")
	}
	wire, _ := json.Marshal(map[string]ControllerDiscoveryTarget{bindingID: target})
	if _, err := ControllerDiscoveryBindings(string(wire)); err != nil {
		return nil, err
	}
	var retained model.Document
	err := p.Store.Do(ctx, tenant, func(tx *store.Tx) error {
		registration, err := tx.SourceGet(ctx, target.SourceID)
		if err != nil {
			return err
		}
		if !model.Bool(registration, "enabled") || model.Bool(registration, "revoked") {
			return nil
		}
		roster, _, err := controllerDiscoveryRoster(ctx, tx, target)
		if err != nil {
			return err
		}
		var raw []byte
		err = tx.QueryRow(ctx, `SELECT e.document FROM source_receipts e JOIN source_registrations r ON r.tenant_id=e.tenant_id AND r.id=e.source_id WHERE e.tenant_id=$1 AND e.source_id=$2 AND e.kind='AWS_CONTROLLER_DISCOVERY' AND e.writer_role='finops_ingester' AND (e.document->>'registration_version')::bigint=r.version AND e.document->>'binding_id'=$3 AND e.document->>'config_hash'=$4 AND e.document->>'roster_sha256'=$5 AND e.document->>'target_sha256'=$6 ORDER BY e.created_at DESC,e.id DESC LIMIT 1`, tenant, target.SourceID, bindingID, ConfigurationHash(registration), Hash(roster), Hash(target)).Scan(&raw)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		var value model.Document
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		if decoder.Decode(&value) != nil {
			return errors.New("CONTROLLER_DISCOVERY_ISSUED_RECEIPT_INVALID")
		}
		observed, err := time.Parse(time.RFC3339Nano, model.String(value, "collected_at"))
		if err != nil {
			return errors.New("CONTROLLER_DISCOVERY_ISSUED_RECEIPT_INVALID")
		}
		if !observed.Before(p.now().Add(-90*time.Second)) && !observed.After(p.now().Add(5*time.Second)) {
			retained = value
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if retained != nil {
		return retained, nil
	}
	return p.Capture(ctx, tenant, bindingID)
}
