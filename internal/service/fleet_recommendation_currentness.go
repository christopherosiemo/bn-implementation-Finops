package service

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	g "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetgroup"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/source"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/telemetry"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Fleet analyses already retain their group proposals and safety references.
// Reuse the existing current-selection broker rather than materializing their
// native populations or changing an immutable historical decision.
func (a *API) fleetSelectionCurrentness(ctx context.Context, tx *store.Tx, d model.Document) (model.Document, error) {
	if d["status"] == "QUEUED" || d["status"] == "RUNNING" {
		return d, nil
	}
	selection := storageObject(d["selection"])
	groups := storageObject(selection["groups"])
	oldID := model.String(storageObject(groups["old_configuration_proposal"]), "id")
	candidateID := model.String(storageObject(groups["candidate_configuration_proposal"]), "id")
	// These existing records did not freeze owner, policy and SLO context.
	// Native selection checks cannot reconstruct that historical authority.
	reasons := []string{"LEGACY_RECOMMENDATION_CONTEXT_UNAVAILABLE"}
	if oldID == "" || candidateID == "" {
		reasons = append(reasons, "FLEET_CONFIGURATION_SELECTION_UNAVAILABLE")
	} else {
		// Native selection can reject a stale source inside SQL. A savepoint
		// preserves the surrounding read transaction for its explicit refusal.
		nested, err := tx.Tx.Begin(ctx)
		if err != nil { return nil, err }
		current, err := (&store.Tx{Tx: nested, Tenant: tx.Tenant}).FleetNativeSelectionCurrent(ctx, oldID, candidateID)
		if err != nil {
			if rollback := nested.Rollback(ctx); rollback != nil { return nil, rollback }
		} else if err = nested.Commit(ctx); err != nil { return nil, err }
		var native *pgconn.PgError
		domainRefusal := errors.As(err, &native) && native.Code == "P0001" && !strings.Contains(native.Message, "tenant") && (strings.HasPrefix(native.Message, "fleet history ") || strings.HasPrefix(native.Message, "fleet configuration ") || strings.HasPrefix(native.Message, "group assessment "))
		if domainRefusal || errors.Is(err, store.ErrFleetNativeCurrent) || errors.Is(err, store.ErrFleetNativeEvidence) || errors.Is(err, pgx.ErrNoRows) {
			reasons = append(reasons, "FLEET_CONFIGURATION_OR_NATIVE_SOURCE_CHANGED")
		} else if err != nil {
			return nil, err
		} else {
			var selected g.Binding
			raw, _ := json.Marshal(groups["binding"])
			if json.Unmarshal(raw, &selected) != nil || g.ValidateBinding(selected) != nil || g.Digest(current) != g.Digest(selected) {
				reasons = append(reasons, "FLEET_CONFIGURATION_OR_NATIVE_SOURCE_CHANGED")
			}
		}
	}
	profile, err := tx.WorkloadSafetyLatest(ctx, model.String(d, "workload_id"))
	if errors.Is(err, pgx.ErrNoRows) {
		reasons = append(reasons, "WORKLOAD_SAFETY_PROFILE_CHANGED")
	} else if err != nil {
		return nil, err
	} else {
		selected := storageObject(selection["safety_profile"])
		if selected["id"] != profile["id"] || selected["sha256"] != profile["hash"] || model.Number(selected, "version") != model.Number(profile, "version") {
			reasons = append(reasons, "WORKLOAD_SAFETY_PROFILE_CHANGED")
		}
	}
	analysis := storageObject(d["assessment"])
	if model.String(d, "assessment_request_id") != "" {
		original, err := tx.FleetNativeAssessmentGet(ctx, model.String(d, "assessment_request_id"))
		if errors.Is(err, pgx.ErrNoRows) {
			reasons = append(reasons, "FLEET_NATIVE_ASSESSMENT_UNAVAILABLE")
		} else if err != nil {
			return nil, err
		} else {
			analysis = storageObject(original["assessment"])
		}
	}
	financial := storageObject(analysis["native_rates"])
	refs := storageRows(financial["billing_source_refs"])
	if len(refs) > 25 {
		reasons = append(reasons, "FLEET_BILLING_REFERENCE_BOUND")
	} else {
		for _, ref := range refs {
			receipt, err := tx.SourceReceiptGet(ctx, model.String(ref, "receipt_id"))
			if errors.Is(err, pgx.ErrNoRows) {
				reasons = append(reasons, "BILLING_SOURCE_CHANGED_OR_REVOKED")
				continue
			}
			if err != nil {
				return nil, err
			}
			registration, err := tx.SourceGet(ctx, model.String(receipt, "source_id"))
			if err != nil {
				return nil, err
			}
			period, parseErr := time.Parse(time.RFC3339Nano, model.String(storageObject(receipt["source_proof"]), "billing_period_start"))
			if parseErr != nil || !model.Bool(registration, "enabled") || model.Bool(registration, "revoked") || receipt["config_hash"] != source.ConfigurationHash(registration) || ref["canonical_hash"] != receipt["canonical_hash"] || ref["raw_hash"] != receipt["raw_hash"] || ref["revision_id"] != receipt["revision_id"] || ref["ingestion_job_id"] != receipt["ingestion_job_id"] {
				reasons = append(reasons, "BILLING_SOURCE_CHANGED_OR_REVOKED")
				continue
			}
			head, err := tx.SourceCheckpointGet(ctx, model.String(registration, "id"), "month:"+source.ConfigurationHash(registration)+":"+period.Format("2006-01"))
			if errors.Is(err, pgx.ErrNoRows) {
				reasons = append(reasons, "BILLING_SOURCE_CHANGED_OR_REVOKED")
			} else if err != nil {
				return nil, err
			} else if head["receipt_id"] != receipt["id"] || head["ambiguous_at"] != nil {
				reasons = append(reasons, "BILLING_SOURCE_CHANGED_OR_REVOKED")
			}
		}
	}
	if expires := model.String(financial, "valid_until"); expires != "" {
		at, err := time.Parse(time.RFC3339Nano, expires)
		if err != nil || !a.now().Before(at) {
			reasons = append(reasons, "FLEET_NATIVE_ECONOMICS_EXPIRED")
		}
	}
	return fleetAnalysisCurrentnessProjection(d, reasons, a.now()), nil
}

func fleetAnalysisCurrentnessProjection(d model.Document, reasons []string, now time.Time) model.Document {
	projection := model.Clone(d)
	for _, key := range []string{"assessment", "batch", "decision", "member"} {
		if value := storageObject(d[key]); value != nil && model.String(value, "status") == "BLOCKED" {
			projection["assessment"] = value
		}
	}
	if d["status"] == "REFUSED" {
		projection["status"] = "BLOCKED"
	}
	return recommendationCurrentnessCopy(d, recommendationCurrentnessProjection(projection, nil, reasons, "", now))
}

func (a *API) capacityResultCurrentness(ctx context.Context, tx *store.Tx, d model.Document) (model.Document, error) {
	reasons := []string{"LEGACY_RECOMMENDATION_CONTEXT_UNAVAILABLE"}
	resource, err := tx.Get(ctx, "resources", model.String(d, "resource_id"))
	if errors.Is(err, pgx.ErrNoRows) {
		reasons = append(reasons, "RESOURCE_REMOVED_OR_SCOPE_CHANGED")
	} else if err != nil {
		return nil, err
	} else {
		if d["workload_id"] != resource["workload_id"] {
			reasons = append(reasons, "WORKLOAD_MAPPING_CHANGED")
		}
		if hash := model.String(d, "resource_snapshot_hash"); hash != "" && hash != telemetry.Hash(resource) {
			reasons = append(reasons, "RESOURCE_CONFIGURATION_CHANGED")
		}
	}
	profile, err := tx.WorkloadSafetyLatest(ctx, model.String(d, "workload_id"))
	if errors.Is(err, pgx.ErrNoRows) {
		reasons = append(reasons, "WORKLOAD_SAFETY_PROFILE_CHANGED")
	} else if err != nil {
		return nil, err
	} else if d["safety_profile_id"] != profile["id"] || model.Number(d, "safety_profile_version") != model.Number(profile, "version") || d["safety_profile_hash"] != profile["hash"] {
		reasons = append(reasons, "WORKLOAD_SAFETY_PROFILE_CHANGED")
	}
	connection, err := tx.TelemetryConnection(ctx, model.String(d, "connection_id"))
	if errors.Is(err, pgx.ErrNoRows) {
		reasons = append(reasons, "TELEMETRY_REVISION_CHANGED_OR_REVOKED")
	} else if err != nil {
		return nil, err
	} else if model.Bool(connection, "revoked") || !model.Bool(connection, "enabled") || d["revision_id"] != connection["revision_id"] || d["config_hash"] != connection["config_hash"] || model.Number(d, "connection_version") != model.Number(connection, "version") {
		reasons = append(reasons, "TELEMETRY_REVISION_CHANGED_OR_REVOKED")
	}
	if receiptID := model.String(d, "hardware_receipt_id"); receiptID != "" {
		receipt, err := tx.SourceReceiptGet(ctx, receiptID)
		if errors.Is(err, pgx.ErrNoRows) {
			reasons = append(reasons, "NATIVE_HARDWARE_SOURCE_CHANGED")
		} else if err != nil {
			return nil, err
		} else {
			registration, err := tx.SourceGet(ctx, model.String(receipt, "source_id"))
			if err != nil {
				return nil, err
			}
			if !model.Bool(registration, "enabled") || model.Bool(registration, "revoked") || receipt["config_hash"] != source.ConfigurationHash(registration) || model.Number(receipt, "registration_version") != model.Number(registration, "version") {
				reasons = append(reasons, "NATIVE_HARDWARE_SOURCE_CHANGED")
			}
		}
	}
	// Exact resource snapshots and existing native source identities remain the
	// authorities; this projection does not recalculate or renew their history.
	return fleetAnalysisCurrentnessProjection(d, databaseSortedReasons(reasons), a.now()), nil
}
