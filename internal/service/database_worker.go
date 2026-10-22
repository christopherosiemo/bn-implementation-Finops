package service

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"regexp"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/evidence"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/native"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/jackc/pgx/v5"
)

type databaseArchiveRead func(context.Context, string, model.Document) ([]byte, error)

// The assessor owns analytical publications only. It has neither an execution
// queue nor a customer credential provider. A transaction retains queue ownership;
// loss of this process rolls it back to QUEUED, including any unpublished result.
func RunDatabaseAssessor(ctx context.Context, cfg Config, db *store.Store) error {
	if cfg.AWSReadRole != "" || cfg.AWSExecutionRole != "" || cfg.PrivateKey != "" || cfg.SignerToken != "" || cfg.ExecutorToken != "" {
		return errors.New("DATABASE_ANALYST_IDENTITY_MUST_BE_READ_ONLY")
	}
	if cfg.EconomicsToken == "" {
		return errors.New("DATABASE_ECONOMICS_IDENTITY_REQUIRED")
	}
	storage, err := native.StorageFromEnvironment(ctx, cfg.Fixture)
	if err != nil {
		return err
	}
	a := &API{Store: db, Config: cfg, Client: &http.Client{Timeout: HTTPTimeout}}
	timer := time.NewTicker(3 * time.Second)
	defer timer.Stop()
	for {
		if err = databaseAssessmentTick(ctx, a, storage.Read); err != nil {
			slog.Error("database assessment retry required", "code", "DATABASE_ASSESSMENT_RETRY")
		}
		select {
		case <-ctx.Done():
			return nil
		case <-timer.C:
		}
	}
}

func databaseAssessmentTick(ctx context.Context, a *API, read databaseArchiveRead) error {
	rows, err := a.Store.Pool.Query(ctx, "SELECT tenant_id FROM tenant_registry ORDER BY tenant_id")
	if err != nil {
		return err
	}
	tenants := []string{}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		tenants = append(tenants, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	var lastErr error
	for _, tenant := range tenants {
		err = a.Store.Do(ctx, tenant, func(t *store.Tx) error { return databaseAssessmentOne(ctx, a, t, read) })
		if err != nil {
			lastErr = err
		}
	}
	return lastErr
}

func databaseAssessmentOne(ctx context.Context, a *API, t *store.Tx, read databaseArchiveRead) error {
	var id, resourceID, snapshotID, profileID string
	err := t.QueryRow(ctx, `SELECT id,resource_id,coalesce(snapshot_id,''),coalesce(safety_profile_id,'') FROM database_assessments
 WHERE tenant_id=$1 AND status='QUEUED' ORDER BY created_at,id LIMIT 1 FOR UPDATE SKIP LOCKED`, t.Tenant).Scan(&id, &resourceID, &snapshotID, &profileID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if _, err = t.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", t.Tenant+":dependency-graph"); err != nil {
		return err
	}
	resource, err := t.Get(ctx, "resources", resourceID)
	if err != nil {
		return err
	}
	blockers := []string{}
	refs := []model.Document{}
	var input, assessment model.Document
	var snapshot, profile, canonical model.Document
	if snapshotID == "" {
		blockers = append(blockers, "DATABASE_PERSISTED_EVIDENCE_REQUIRED")
	} else {
		snapshot, err = t.DatabaseEvidenceGet(ctx, snapshotID)
		if err != nil {
			return err
		}
		observed, parseErr := time.Parse(time.RFC3339Nano, model.String(snapshot, "observed_at"))
		if parseErr != nil || observed.After(time.Now().UTC().Add(time.Minute)) || time.Since(observed) > 24*time.Hour {
			blockers = append(blockers, "DATABASE_INVENTORY_STALE")
		}
		if model.String(snapshot, "config_hash") != DatabaseConfigurationHash(resource) {
			blockers = append(blockers, "DATABASE_CONFIGURATION_CHANGED")
		}
		raw, readErr := read(ctx, t.Tenant, databaseObject(snapshot["archive"]))
		if readErr != nil {
			return readErr
		}
		canonical, err = decodeDatabaseDocument(raw)
		if err != nil {
			return err
		}
		if model.String(canonical, "schema_version") != "1" {
			return errors.New("DATABASE_ARCHIVE_CONTRACT_INVALID")
		}
		if evidence.Hash(canonical["resource"]) != evidence.Hash(resource) {
			// Row versions and acquisition times may differ; configuration identity is the authority.
			if DatabaseConfigurationHash(databaseObject(canonical["resource"])) != DatabaseConfigurationHash(resource) {
				blockers = append(blockers, "DATABASE_ARCHIVE_RESOURCE_MISMATCH")
			}
		}
	}
	if profileID == "" {
		blockers = append(blockers, "DATABASE_SAFETY_POLICY_REQUIRED")
	} else {
		profile, err = t.WorkloadSafetyGet(ctx, profileID)
		if err != nil {
			return err
		}
		latest, e := t.WorkloadSafetyLatest(ctx, model.String(resource, "workload_id"))
		if e != nil {
			return e
		}
		if model.String(latest, "id") != profileID {
			blockers = append(blockers, "DATABASE_SAFETY_POLICY_CHANGED")
		}
	}
	if len(blockers) == 0 {
		var reasons []string
		input, refs, reasons, err = a.databaseAssessmentInput(ctx, t, resource, snapshot, canonical, profile)
		if err != nil {
			return err
		}
		blockers = append(blockers, reasons...)
	}
	if len(blockers) > 0 {
		assessment = databaseBlocked(resource, snapshot, blockers, refs)
	} else {
		assessment, err = a.economics(ctx, "v7/database-assessment", input)
		if err != nil {
			return err
		}
		if err = databaseValidateResult(assessment, input); err != nil {
			return err
		}
		// Native record selections are resolved by this process, never by a caller
		// or by the economics response. They also make corrections invalidate advice.
		assessment["source_refs"] = append(documentList(assessment["source_refs"]), refs...)
	}
	assessment["provider_comparison"] = databaseProviderComparison(resource, canonical, assessment)
	if model.String(assessment, "assessment_hash") != "" {
		assessment["model_assessment_hash"] = assessment["assessment_hash"]
	}
	delete(assessment, "assessment_hash")
	assessment["assessment_hash"] = evidence.Hash(assessment)
	status := "ASSESSED"
	if model.String(assessment, "status") == "BLOCKED" {
		status = "BLOCKED"
	}
	body, _ := json.Marshal(model.Document{"assessment": assessment})
	if _, err = t.Exec(ctx, "UPDATE database_assessments SET status=$3,document=$4 WHERE tenant_id=$1 AND id=$2", t.Tenant, id, status, body); err != nil {
		return err
	}
	publication := model.Document{"id": "database-" + id, "model_kind": "DATABASE_ASSESSMENT_V1", "database_assessment_id": id, "resource_id": resourceID, "workload_id": resource["workload_id"], "status": assessment["status"], "action_type": assessment["recommendation_kind"], "assessment": assessment, "pre_execution_ready": false, "execution_authorized": false, "risk_class": "R3", "verified_saving": nil, "created_at": model.Now(), "version": 1}
	economics := databaseObject(assessment["economics"])
	name := model.String(resource, "name")
	if name == "" {
		name = model.String(resource, "provider_resource_id")
	}
	publication["title"] = "Review database capacity: " + name
	publication["monthly_saving"], publication["currency"] = economics["estimated_monthly_saving"], economics["currency"]
	publication["reason_code"] = assessment["decision_code"]
	if reasons := model.Strings(assessment, "blockers"); len(reasons) > 0 {
		publication["reason_code"] = reasons[0]
	}
	raw, _ := json.Marshal(publication)
	if _, err = t.Exec(ctx, `INSERT INTO database_recommendation_publications(tenant_id,assessment_id,resource_id,document,current_hourly_cost,candidate_hourly_cost,currency) VALUES($1,$2,$3,$4,$5,$6,$7)`, t.Tenant, id, resourceID, raw, economics["current_hourly_cost"], economics["candidate_hourly_cost"], economics["currency"]); err != nil {
		return err
	}
	if err = t.Audit(ctx, "database-assessor", "database.assessment.published", id, model.Document{"resource_id": resourceID, "status": status, "execution_authorized": false}); err != nil {
		return err
	}
	return t.Event(ctx, "database.assessment.published", model.Document{"id": id, "resource_id": resourceID, "status": status})
}

func databaseBlocked(resource, snapshot model.Document, reasons []string, refs []model.Document) model.Document {
	engine := model.String(databaseObject(resource["database_configuration"]), "engine")
	if engine == "" {
		engine = "UNKNOWN"
	}
	return model.Document{"schema_version": "1", "resource_kind": resource["resource_type"], "engine": engine, "current_configuration": resource["database_configuration"], "candidate_configuration": nil, "evidence_window": snapshot["period"], "metric_distributions": []any{}, "economics": model.Document{"current_hourly_cost": nil, "current_monthly_cost": nil, "candidate_hourly_cost": nil, "candidate_monthly_cost": nil, "estimated_monthly_saving": nil, "estimated_annual_saving": nil, "currency": nil, "basis": "UNAVAILABLE"}, "blockers": reasons, "confidence": model.Document{"status": "UNAVAILABLE", "reasons": reasons}, "proposal": model.Document{"risk_class": "R3", "executable": false, "execution_authorized": false}, "verified_saving": nil, "source_refs": refs, "candidates": []any{}, "recommendation_kind": "DATABASE_INSTANCE_RIGHTSIZE", "status": "BLOCKED", "decision_code": "BLOCKED"}
}

var databaseMoney = regexp.MustCompile(`^-?(0|[1-9][0-9]{0,25})(\.[0-9]{1,12})?$`)

func databaseValidateResult(result, input model.Document) error {
	invalid := errors.New("DATABASE_ECONOMICS_RESPONSE_INVALID")
	p := databaseObject(result["proposal"])
	if model.String(result, "schema_version") != "1" || evidence.Hash(result["binding"]) != evidence.Hash(input["binding"]) || p["executable"] != false || p["execution_authorized"] != false || model.String(p, "risk_class") != "R3" {
		return invalid
	}
	verified, ok := result["verified_saving"]
	if !ok || verified != nil {
		return invalid
	}
	switch model.String(result, "status") {
	case "RECOMMENDED", "NO_CHANGE", "BLOCKED":
	default:
		return invalid
	}
	if model.String(result, "status") != "BLOCKED" {
		currency := model.String(databaseObject(result["economics"]), "currency")
		if !databaseCoverageCurrency.MatchString(currency) || currency != model.String(databaseObject(input["current_pricing"]), "currency") {
			return invalid
		}
	}
	for _, key := range []string{"current_hourly_cost", "current_monthly_cost", "candidate_hourly_cost", "candidate_monthly_cost", "estimated_monthly_saving", "estimated_annual_saving"} {
		v := databaseObject(result["economics"])[key]
		if v != nil {
			txt, ok := v.(string)
			if !ok || !databaseMoney.MatchString(txt) {
				return invalid
			}
		}
	}
	return nil
}
