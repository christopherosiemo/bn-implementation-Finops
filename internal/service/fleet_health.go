package service

import (
	"context"
	"encoding/json"
	"errors"
	"math/big"
	"sort"
	"strings"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/evidence"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/fleet"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/slo"
	trustedsource "github.com/christopherosiemo/bn-implementation-Finops/internal/source"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/telemetry"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/workload"
	"github.com/jackc/pgx/v5"
)

// There is deliberately no HTTP route for these factories. Their identifiers
// are selected by trusted control-plane code; callers cannot submit health,
// counters, histograms, proof documents, amounts or native membership lists.
func fleetHealthLock(ctx context.Context, tx *store.Tx, workloadID string) error {
	_, err := tx.Exec(ctx, "SELECT fleet_lock($1,$2)", tx.Tenant, workloadID)
	return err
}
func fleetHealthDecode(in any, out any) error {
	raw, err := json.Marshal(in)
	if err == nil {
		err = json.Unmarshal(raw, out)
	}
	return err
}
func fleetHealthOne(ctx context.Context, tx *store.Tx, query string, args ...any) (model.Document, error) {
	var raw []byte
	if err := tx.QueryRow(ctx, query, args...).Scan(&raw); err != nil {
		return nil, err
	}
	var out model.Document
	err := json.Unmarshal(raw, &out)
	return out, err
}
func fleetHealthSorted(ids []string) []string {
	out := append([]string{}, ids...)
	sort.Strings(out)
	return out
}
func fleetHealthIDsEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	a, b = fleetHealthSorted(a), fleetHealthSorted(b)
	for i := range a {
		if a[i] != b[i] || i > 0 && a[i] == a[i-1] {
			return false
		}
	}
	return true
}

func fleetHealthMembership(ctx context.Context, tx *store.Tx, id string, b fleet.Binding, now time.Time, maxAge time.Duration) (model.Document, error) {
	d, err := tx.SourceReceiptGet(ctx, id)
	if err != nil {
		return nil, err
	}
	var actual fleet.Binding
	if err = fleetHealthDecode(d["binding"], &actual); err != nil || actual != b || model.String(d, "kind") != "AWS_FLEET_MEMBERSHIP" || model.String(d, "writer_role") != "finops_ingester" {
		return nil, errors.New("COHORT_NATIVE_MEMBERSHIP_BINDING_INVALID")
	}
	// SourceUpdate takes a row lock: hold a shared lock until publication so a
	// revocation cannot race an apparently healthy private factory transaction.
	if _, err = tx.Exec(ctx, "SELECT id FROM source_registrations WHERE tenant_id=$1 AND id=$2 FOR SHARE", tx.Tenant, model.String(d, "source_id")); err != nil {
		return nil, err
	}
	registration, err := tx.SourceGet(ctx, model.String(d, "source_id"))
	if err != nil {
		return nil, err
	}
	revision, err := tx.SourceRevisionGet(ctx, model.String(d, "revision_id"))
	if err != nil {
		return nil, err
	}
	approved := model.String(registration, "payer_account_id") == b.AccountID
	for _, account := range model.Strings(registration, "usage_account_ids") {
		approved = approved || account == b.AccountID
	}
	if !approved || !model.Bool(registration, "enabled") || model.Bool(registration, "revoked") || model.Number(d, "registration_version") != model.Number(registration, "version") || model.String(d, "read_role_binding_id") == "" || model.String(d, "read_role_binding_id") != model.String(registration, "read_role_binding_id") || model.String(revision, "writer_role") != "finops_ingester" || model.String(revision, "source_id") != model.String(d, "source_id") || model.String(revision, "config_hash") != model.String(d, "config_hash") || trustedsource.ConfigurationHash(registration) != model.String(d, "config_hash") || model.Number(revision, "registration_version") != model.Number(registration, "version") {
		return nil, errors.New("COHORT_NATIVE_SOURCE_REVOKED_OR_CHANGED")
	}
	ref := evidence.Object(d["raw_object"])
	if model.String(ref, "bucket") == "" || model.String(ref, "version_id") == "" || model.String(ref, "version_id") == "null" || !fleetHealthHash.MatchString(model.String(ref, "body_sha256")) || !strings.HasPrefix(model.String(ref, "key"), "tenant/"+tx.Tenant+"/fleet/") || strings.Contains(model.String(ref, "key"), "..") {
		return nil, errors.New("COHORT_NATIVE_VERSIONED_RAW_REQUIRED")
	}
	var collected time.Time
	if maxAge <= 0 || fleetHealthDecode(d["collected_at"], &collected) != nil || collected.IsZero() || collected.After(now.Add(5*time.Second)) || collected.Before(now.Add(-maxAge)) {
		return nil, errors.New("COHORT_NATIVE_MEMBERSHIP_STALE")
	}
	return d, nil
}

func fleetHealthSource(ctx context.Context, tx *store.Tx, b fleet.Binding, objectiveID string) (slo.Source, error) {
	sources, err := tx.SLOSources(ctx)
	if err != nil {
		return slo.Source{}, err
	}
	var found slo.Source
	for _, source := range sources {
		if source.ObjectiveID == objectiveID && source.ProviderResourceID == b.ProviderResourceID && source.ResourceID == b.ResourceID && source.Binding() == (slo.Binding{TenantID: b.TenantID, WorkloadID: b.WorkloadID, ResourceID: b.ResourceID, ProviderResourceID: b.ProviderResourceID, AccountID: b.AccountID, Region: b.Region}) && source.Enabled {
			if found.ID != "" {
				return slo.Source{}, errors.New("COHORT_MEMBER_SOURCE_AMBIGUOUS")
			}
			found = source
		}
	}
	if found.ID == "" {
		return found, errors.New("COHORT_MEMBER_REGISTERED_SLO_SOURCE_REQUIRED")
	}
	return found, nil
}
func fleetHealthMemberBinding(ctx context.Context, tx *store.Tx, parent fleet.Binding, instanceID string) (fleet.Binding, error) {
	d, err := fleetHealthOne(ctx, tx, "SELECT document FROM entities WHERE tenant_id=$1 AND kind='resources' AND document->>'workload_id'=$2 AND document->>'provider'='AWS' AND document->>'provider_resource_id'=$3 AND document->>'account_id'=$4 AND document->>'region'=$5", tx.Tenant, parent.WorkloadID, instanceID, parent.AccountID, parent.Region)
	if err != nil {
		return fleet.Binding{}, err
	}
	b := parent
	b.ResourceID, b.ProviderResourceID = model.String(d, "id"), instanceID
	return b, nil
}
func fleetHealthReceipts(ctx context.Context, tx *store.Tx, source slo.Source, start, end time.Time) ([]fleetSLOReceipt, error) {
	rows, err := tx.Query(ctx, "SELECT document,raw_body FROM slo_receipts WHERE tenant_id=$1 AND source_id=$2 AND objective_id=$3 AND resource_id=$4 AND interval_start >= $5 AND interval_end <= $6 ORDER BY interval_start,sequence", tx.Tenant, source.ID, source.ObjectiveID, source.ResourceID, start, end)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []fleetSLOReceipt{}
	for rows.Next() {
		var raw, original []byte
		if err = rows.Scan(&raw, &original); err != nil {
			return nil, err
		}
		var r slo.Receipt
		if err = json.Unmarshal(raw, &r); err != nil {
			return nil, err
		}
		out = append(out, fleetSLOReceipt{r, original})
	}
	return out, rows.Err()
}
func fleetHealthPersistMember(ctx context.Context, tx *store.Tx, e fleetMemberEvaluation) (model.Document, error) {
	if e.Hash != fleetMemberEvaluationHash(e) {
		return nil, errors.New("COHORT_MEMBER_WINDOW_HASH_INVALID")
	}
	if old, err := fleetHealthOne(ctx, tx, "SELECT document FROM fleet_member_slo_windows WHERE tenant_id=$1 AND content_hash=$2", tx.Tenant, e.Hash); err == nil {
		return old, nil
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	raw, err := json.Marshal(e)
	if err != nil {
		return nil, err
	}
	return fleetHealthOne(ctx, tx, "INSERT INTO fleet_member_slo_windows(tenant_id,id,objective_id,source_id,resource_id,window_start,window_end,status,content_hash,document) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING document", tx.Tenant, e.Member.EvaluationID, e.Member.ObjectiveID, e.Member.SourceID, e.Member.Binding.ResourceID, e.WindowStart, e.WindowEnd, e.Status, e.Hash, raw)
}

func fleetNativeMetricWithin(value *string, unit string, maximumPPM int64) bool {
	if value == nil || len(*value) > 128 {
		return false
	}
	r, ok := new(big.Rat).SetString(*value)
	if !ok || r.Sign() < 0 || r.Num().BitLen() > 512 || r.Denom().BitLen() > 512 {
		return false
	}
	switch unit {
	case "ratio":
		r.Mul(r, big.NewRat(1_000_000, 1))
	case "percent":
		r.Mul(r, big.NewRat(10_000, 1))
	default:
		return false
	}
	return r.Cmp(big.NewRat(maximumPPM, 1)) <= 0
}

func fleetHealthNativeAuthority(ctx context.Context, tx *store.Tx, d model.Document) (bool, error) {
	connection, err := tx.TelemetryConnection(ctx, model.String(d, "connection_id"))
	if err != nil {
		return false, err
	}
	if !model.Bool(connection, "enabled") || model.Bool(connection, "revoked") || model.String(connection, "config_hash") != model.String(d, "config_hash") || model.String(connection, "revision_id") != model.String(d, "revision_id") {
		return false, nil
	}
	active := len(model.Strings(d, "receipt_ids")) > 0
	for _, id := range model.Strings(d, "receipt_ids") {
		r, receiptErr := tx.TelemetryReceipt(ctx, id)
		if receiptErr != nil {
			return false, receiptErr
		}
		active = active && model.Bool(r, "active_source") && model.String(r, "revision_id") == model.String(d, "revision_id")
	}
	return active, nil
}

// A recent two-minute native summary cannot stand in for the full canary. Both
// required physical metrics must have real continuous bounds covering the same
// window, zero unknown duration, and their registered ratio/percent units.
func fleetHealthNativeWindow(ctx context.Context, tx *store.Tx, b fleet.Binding, profile workload.Profile, start, end, now time.Time) (model.Document, error) {
	rows, err := tx.Query(ctx, "SELECT document FROM telemetry_evaluations WHERE tenant_id=$1 AND document->'binding'->>'provider_resource_id'=$2 AND document->'binding'->>'account_id'=$3 AND document->'binding'->>'region'=$4 ORDER BY created_at DESC,id DESC LIMIT 128", tx.Tenant, b.ProviderResourceID, b.AccountID, b.Region)
	if err != nil {
		return nil, err
	}
	selected := []model.Document{}
	for rows.Next() {
		var raw []byte
		if err = rows.Scan(&raw); err != nil {
			rows.Close()
			return nil, err
		}
		var d model.Document
		if err = json.Unmarshal(raw, &d); err != nil {
			rows.Close()
			return nil, err
		}
		selected = append(selected, d)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	for _, d := range selected {
		var binding fleet.Binding
		var e telemetry.Evaluation
		if fleetHealthDecode(d["binding"], &binding) != nil || binding != b || fleetHealthDecode(d["evaluation"], &e) != nil || e.Status != "READY" || e.HistoryDays != 0 || e.EvaluatedAt.Before(now.Add(-5*time.Minute)) || e.EvaluatedAt.After(now.Add(5*time.Second)) || e.Start.After(start) || e.End.Before(end) {
			continue
		}
		hash := e.Hash
		e.Hash = ""
		if !fleetHealthHash.MatchString(hash) || telemetry.Hash(e) != hash {
			continue
		}
		active, authorityErr := fleetHealthNativeAuthority(ctx, tx, d)
		if authorityErr != nil {
			return nil, authorityErr
		}
		cpu, memory := false, false
		for _, metric := range e.Metrics {
			if metric.Status != "READY" || metric.CoveragePPM != 1_000_000 || metric.UnknownDurationNS != 0 || metric.Start.After(start) || metric.End.Before(end) || metric.ObservedDurationNS < end.Sub(start).Nanoseconds() {
				continue
			}
			switch metric.Metric {
			case "cpu_utilization":
				cpu = fleetNativeMetricWithin(metric.Maximum, metric.Unit, min(profile.Saturation.CPUP99PPM, 1_000_000-profile.Headroom.CPUFreePPM))
				if active && !cpu {
					return nil, errors.New("COHORT_NATIVE_CPU_HEADROOM_NOT_CLEAR")
				}
			case "memory_utilization":
				memory = fleetNativeMetricWithin(metric.Maximum, metric.Unit, min(profile.Saturation.MemoryP99PPM, 1_000_000-profile.Headroom.MemoryFreePPM))
				if active && !memory {
					return nil, errors.New("COHORT_NATIVE_MEMORY_HEADROOM_NOT_CLEAR")
				}
			}
		}
		if active && cpu && memory {
			return d, nil
		}
	}
	return nil, errors.New("COHORT_FULL_WINDOW_NATIVE_CPU_MEMORY_REQUIRED")
}

// freezeFleetCohortBaseline is pre-plan: the approved read-only DISCOVERY
// receipt selects the physical blue population without inventing a FleetPlan.
// A baseline is immutable historical evidence, not permission to stop or apply.
func (a *API) freezeFleetCohortBaseline(ctx context.Context, tx *store.Tx, binding fleet.Binding, membershipID string) (model.Document, error) {
	if binding.TenantID != tx.Tenant || fleet.ValidateBinding(binding) != nil {
		return nil, errors.New("COHORT_BASELINE_BINDING_INVALID")
	}
	if err := fleetHealthLock(ctx, tx, binding.WorkloadID); err != nil {
		return nil, err
	}
	now := a.now()
	membership, err := fleetHealthMembership(ctx, tx, membershipID, binding, now, 5*time.Minute)
	if err != nil {
		return nil, err
	}
	if position := model.String(membership, "position"); position != "DISCOVERY" && position != "BASELINE" || model.String(membership, "old_asg") != binding.ProviderResourceID || len(model.Strings(membership, "old_instance_ids")) == 0 || len(model.Strings(membership, "candidate_instance_ids")) != 0 || len(model.Strings(membership, "reason_codes")) != 0 {
		return nil, errors.New("COHORT_BASELINE_NATIVE_READY_BLUE_REQUIRED")
	}
	objectiveDoc, err := tx.SLOObjectiveLatest(ctx, binding.WorkloadID)
	if err != nil {
		return nil, err
	}
	objective, err := slo.ParseObjective(objectiveDoc)
	if err != nil || !objective.Regression.Enabled {
		return nil, errors.New("COHORT_EXPLICIT_REGRESSION_OBJECTIVE_REQUIRED")
	}
	profileDoc, err := tx.WorkloadSafetyLatest(ctx, binding.WorkloadID)
	if err != nil {
		return nil, err
	}
	var profile workload.Profile
	if fleetHealthDecode(profileDoc, &profile) != nil || workload.Validate(profile) != nil || profile.Statefulness != "STATELESS" {
		return nil, errors.New("COHORT_STATELESS_SAFETY_PROFILE_REQUIRED")
	}
	end := now.Truncate(time.Minute)
	start := end.Add(-time.Duration(objective.EvaluationMinutes) * time.Minute)
	memberIDs, memberWindowIDs, nativeIDs := fleetHealthSorted(model.Strings(membership, "old_instance_ids")), []string{}, []string{}
	for _, id := range memberIDs {
		memberBinding, e := fleetHealthMemberBinding(ctx, tx, binding, id)
		if e != nil {
			return nil, e
		}
		source, e := fleetHealthSource(ctx, tx, memberBinding, objective.ID)
		if e != nil {
			return nil, e
		}
		receipts, e := fleetHealthReceipts(ctx, tx, source, start, end)
		if e != nil {
			return nil, e
		}
		window := fleetBuildMemberWindow(memberBinding, objective, source, start, end, now, receipts)
		if window.Status != "CLEAR" {
			return nil, errors.New("COHORT_BASELINE_MEMBER_NOT_CLEAR")
		}
		native, e := fleetHealthNativeWindow(ctx, tx, memberBinding, profile, start, end, now)
		if e != nil {
			return nil, e
		}
		stored, e := fleetHealthPersistMember(ctx, tx, window)
		if e != nil {
			return nil, e
		}
		memberWindowIDs, nativeIDs = append(memberWindowIDs, model.String(stored, "id")), append(nativeIDs, model.String(native, "id"))
	}
	d := model.Document{"schema_version": "1", "kind": "FROZEN_BLUE_BASELINE", "status": "CLEAR", "binding": evidence.Object(binding), "objective_id": objective.ID, "objective_version": objective.Version, "objective_hash": slo.ObjectiveHash(objective), "membership_receipt_id": membershipID, "member_ids": memberIDs, "member_window_ids": memberWindowIDs, "native_evaluation_ids": nativeIDs, "window_start": start, "window_end": end, "safety_profile_id": profile.ID, "safety_profile_hash": model.String(profileDoc, "hash"), "expires_at": end.Add(6 * time.Hour)}
	hash := fleet.Digest(d)
	if old, e := fleetHealthOne(ctx, tx, "SELECT document FROM fleet_cohort_baselines WHERE tenant_id=$1 AND content_hash=$2", tx.Tenant, hash); e == nil {
		return a.sealFleetCohortBaselineProof(ctx, tx, model.String(old, "id"))
	} else if !errors.Is(e, pgx.ErrNoRows) {
		return nil, e
	}
	raw, err := json.Marshal(d)
	if err != nil {
		return nil, err
	}
	stored, err := fleetHealthOne(ctx, tx, "INSERT INTO fleet_cohort_baselines(tenant_id,id,workload_id,objective_id,membership_receipt_id,content_hash,document) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING document", tx.Tenant, "fleet-baseline-"+hash, binding.WorkloadID, objective.ID, membershipID, hash, raw)
	if err != nil {
		return nil, err
	}
	return a.sealFleetCohortBaselineProof(ctx, tx, model.String(stored, "id"))
}

func (a *API) sealFleetCohortBaselineProof(ctx context.Context, tx *store.Tx, baselineID string) (model.Document, error) {
	baseline, err := fleetHealthOne(ctx, tx, "SELECT document FROM fleet_cohort_baselines WHERE tenant_id=$1 AND id=$2", tx.Tenant, baselineID)
	if err != nil {
		return nil, err
	}
	var binding fleet.Binding
	var expires time.Time
	if fleetHealthDecode(baseline["binding"], &binding) != nil || binding.TenantID != tx.Tenant || fleetHealthDecode(baseline["expires_at"], &expires) != nil || !expires.After(a.now()) {
		return nil, errors.New("COHORT_BASELINE_PROOF_EXPIRED_OR_WRONG_TENANT")
	}
	if err = fleetHealthLock(ctx, tx, binding.WorkloadID); err != nil {
		return nil, err
	}
	objective, err := tx.SLOObjectiveLatest(ctx, binding.WorkloadID)
	if err != nil {
		return nil, err
	}
	profile, err := tx.WorkloadSafetyLatest(ctx, binding.WorkloadID)
	if err != nil {
		return nil, err
	}
	var end time.Time
	if fleetHealthDecode(baseline["window_end"], &end) != nil || end.Before(a.now().Add(-2*time.Minute)) || model.String(objective, "id") != model.String(baseline, "objective_id") || model.String(objective, "hash") != model.String(baseline, "objective_hash") || model.String(profile, "id") != model.String(baseline, "safety_profile_id") || model.String(profile, "hash") != model.String(baseline, "safety_profile_hash") {
		return nil, errors.New("COHORT_BASELINE_NO_LONGER_CURRENT_FOR_NEW_PARENT")
	}
	if _, err = fleetHealthMembership(ctx, tx, model.String(baseline, "membership_receipt_id"), binding, a.now(), 5*time.Minute); err != nil {
		return nil, err
	}
	for _, id := range model.Strings(baseline, "native_evaluation_ids") {
		native, e := tx.TelemetryEvaluation(ctx, id)
		if e != nil {
			return nil, e
		}
		active, e := fleetHealthNativeAuthority(ctx, tx, native)
		if e != nil {
			return nil, e
		}
		if !active {
			return nil, errors.New("COHORT_FROZEN_NATIVE_SOURCE_CHANGED")
		}
	}
	proof := model.Document{"id": "fleet-baseline-proof-" + model.String(baseline, "hash"), "kind": "SLO_EVALUATION", "version": "1", "binding": baseline["binding"], "cohort_baseline_id": baselineID, "objective_id": baseline["objective_id"], "objective_hash": baseline["objective_hash"], "expires_at": baseline["expires_at"], "source_refs": []model.Document{{"table": "fleet_cohort_baselines", "id": baselineID, "sha256": baseline["hash"]}}}
	raw, err := json.Marshal(proof)
	if err != nil {
		return nil, err
	}
	if _, err = tx.Exec(ctx, "INSERT INTO fleet_proof_sets(tenant_id,id,kind,version,content_hash,document) VALUES($1,$2,'SLO_EVALUATION','1',$3,$4) ON CONFLICT(tenant_id,id) DO NOTHING", tx.Tenant, proof["id"], fleet.Digest(proof), raw); err != nil {
		return nil, err
	}
	stored, err := tx.FleetProof(ctx, model.String(proof, "id"))
	if err != nil {
		return nil, err
	}
	out := model.Clone(baseline)
	out["proof_id"], out["proof_hash"] = stored["id"], stored["hash"]
	return out, nil
}
