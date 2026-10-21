package service

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/awsservice"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/evidence"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/native"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/jackc/pgx/v5"
	"log/slog"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func RunAWSServiceAssessor(ctx context.Context, cfg Config, db *store.Store) error {
	if cfg.AWSReadRole != "" || cfg.AWSExecutionRole != "" || cfg.AWSExternalID != "" || cfg.PrivateKey != "" || cfg.SignerToken != "" || cfg.ExecutorToken != "" {
		return errors.New("AWS_SERVICE_ANALYST_IDENTITY_MUST_BE_READ_ONLY")
	}
	if cfg.EconomicsToken == "" {
		return errors.New("AWS_SERVICE_ECONOMICS_IDENTITY_REQUIRED")
	}
	archive, e := native.StorageFromEnvironment(ctx, cfg.Fixture)
	if e != nil {
		return e
	}
	a := &API{Store: db, Config: cfg, Client: &http.Client{Timeout: HTTPTimeout}}
	tick := time.NewTicker(3 * time.Second)
	defer tick.Stop()
	for {
		rows, e := db.Pool.Query(ctx, "SELECT tenant_id FROM tenant_registry ORDER BY tenant_id")
		if e != nil {
			return e
		}
		tenants := []string{}
		for rows.Next() {
			var tenant string
			if e = rows.Scan(&tenant); e != nil {
				break
			}
			tenants = append(tenants, tenant)
		}
		if e == nil {
			e = rows.Err()
		}
		rows.Close()
		if e != nil {
			return e
		}
		for _, tenant := range tenants {
			if e = db.Do(ctx, tenant, func(t *store.Tx) error { return awsServiceAssessmentOne(ctx, a, t, archive.Read) }); e != nil {
				slog.Error("AWS service assessment requires retry", "code", "AWS_SERVICE_ASSESSMENT_RETRY")
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		}
	}
}
func awsServiceResourceAuthorityHash(r model.Document) string {
	return evidence.Hash(model.Document{"workload_id": r["workload_id"], "owner": r["owner"], "configuration_authority": r["configuration_authority"], "environment": r["environment"]})
}

func (a *API) awsServiceAssessmentCurrent(ctx context.Context, t *store.Tx, d model.Document) (model.Document, error) {
	if d["status"] == "QUEUED" || d["status"] == "RUNNING" {
		return d, nil
	}
	r, e := t.Get(ctx, "resources", model.String(d, "resource_id"))
	if e != nil {
		return nil, e
	}
	reasons := []string{}
	sid, pid := model.String(d, "snapshot_id"), model.String(d, "safety_profile_id")
	result := storageObject(d["assessment"])
	if sid == "" {
		reasons = append(reasons, "AWS_SERVICE_NATIVE_SNAPSHOT_REQUIRED")
	} else {
		s, e := t.AWSServiceEvidenceGet(ctx, sid)
		if e != nil {
			return nil, e
		}
		latest, e := t.AWSServiceEvidenceLatest(ctx, model.String(r, "id"))
		if e != nil {
			return nil, e
		}
		if s["content_hash"] != latest["content_hash"] || s["config_hash"] != awsservice.ConfigurationHash(r) {
			reasons = append(reasons, "AWS_SERVICE_NATIVE_CONFIGURATION_OR_SOURCE_CHANGED")
		}
		source, e := t.SourceGet(ctx, model.String(s, "source_id"))
		if e != nil {
			return nil, e
		}
		if !model.Bool(source, "enabled") || model.Bool(source, "revoked") || model.Number(source, "version") != model.Number(s, "registration_version") {
			reasons = append(reasons, "AWS_SERVICE_SOURCE_CHANGED_OR_REVOKED")
		}
		at, e := time.Parse(time.RFC3339Nano, model.String(s, "observed_at"))
		if e != nil || at.After(a.now().Add(time.Minute)) || a.now().Sub(at) > 30*time.Minute {
			reasons = append(reasons, "AWS_SERVICE_NATIVE_INVENTORY_STALE")
		}
	}
	if pid == "" {
		reasons = append(reasons, "AWS_SERVICE_WORKLOAD_SAFETY_PROFILE_REQUIRED")
	} else {
		latest, e := t.WorkloadSafetyLatest(ctx, model.String(r, "workload_id"))
		if e != nil && !errors.Is(e, pgx.ErrNoRows) {
			return nil, e
		}
		if latest["id"] != pid {
			reasons = append(reasons, "AWS_SERVICE_SAFETY_PROFILE_CHANGED")
		}
	}
	if result["resource_authority_hash"] != awsServiceResourceAuthorityHash(r) {
		reasons = append(reasons, "AWS_SERVICE_OWNERSHIP_OR_CONFIGURATION_AUTHORITY_CHANGED")
	}
	if refs := storageRows(result["financial_references"]); len(refs) > 0 {
		ok, e := databaseBillingReferencesCurrent(ctx, t, refs)
		if e != nil {
			return nil, e
		}
		if !ok {
			reasons = append(reasons, "AWS_SERVICE_BILLING_CORRECTED_OR_REVOKED")
		}
	}
	out := model.Clone(d)
	out["current"], out["currentness_blockers"] = len(reasons) == 0, databaseSortedReasons(reasons)
	return out, nil
}

func awsServiceAssessmentInput(ctx context.Context, a *API, t *store.Tx, r, s, canonical, profile model.Document, read databaseArchiveRead) (model.Document, []string, error) {
	reasons := []string{}
	configuration := storageObject(r["aws_service_configuration"])
	observations := model.Document{"metrics": []model.Document{}, "activity": []model.Document{}}
	capabilities := model.Document{"candidates": []model.Document{}}
	sourceRefs := []model.Document{}
	if s != nil {
		sourceRefs = append(sourceRefs, storageRef("AWS_SERVICE_NATIVE_SNAPSHOT_V1", model.String(s, "id"), strconv.FormatInt(model.Number(s, "registration_version"), 10), model.String(s, "content_hash")))
	}
	captured := storageObject(canonical["resource"])
	descriptor := storageObject(captured["aws_service_assessment_evidence"])
	if descriptor["status"] == "OBSERVED_NATIVE_METRICS" {
		if descriptor["source_id"] != s["source_id"] || model.Number(descriptor, "source_registration_version") != model.Number(s, "registration_version") {
			reasons = append(reasons, "AWS_SERVICE_METRIC_SOURCE_BINDING_CHANGED")
		} else {
			raw, e := read(ctx, t.Tenant, storageObject(descriptor["archive"]))
			if e != nil {
				return nil, nil, e
			}
			if awsservice.BytesHash(raw) != model.String(storageObject(descriptor["archive"]), "body_sha256") {
				return nil, nil, errors.New("AWS_SERVICE_METRIC_ARCHIVE_HASH_MISMATCH")
			}
			data := storageObject(json.RawMessage(raw))
			if data["schema_version"] != "1" {
				reasons = append(reasons, "AWS_SERVICE_METRIC_SCHEMA_UNSUPPORTED")
			} else {
				enriched := storageObject(data["configuration"])
				for key, v := range configuration {
					if evidence.Hash(enriched[key]) != evidence.Hash(v) {
						reasons = append(reasons, "AWS_SERVICE_METRIC_CONFIGURATION_EPOCH_MISMATCH")
						break
					}
				}
				configuration, observations, capabilities = enriched, storageObject(data["observations"]), storageObject(data["capabilities"])
				// This data is read back from the immutable ingester-owned archive.
				// Metadata witnesses constrain customer CUR rates; public prices are omitted.
				canonical["price_dimensions"] = data["price_dimensions"]
				if pricingRef := databaseArchiveRef("AWS_SERVICE_PRICE_DIMENSIONS_V1", data["price_source_ref"]); pricingRef != nil {
					sourceRefs = append(sourceRefs, pricingRef)
				}
				ref := databaseArchiveRef("AWS_SERVICE_NATIVE_METRIC_HISTORY", descriptor["archive"])
				if ref != nil {
					sourceRefs = append(sourceRefs, ref)
				}
			}
		}
	} else {
		reasons = append(reasons, "AWS_SERVICE_NATIVE_TELEMETRY_REQUIRED")
	}
	policy := model.Document{"owner": r["owner"], "configuration_authority": r["configuration_authority"], "criticality": "UNKNOWN", "seasonal": nil, "service_constraints": model.Document{}}
	if profile != nil {
		criticality := "PRODUCTION"
		if profile["criticality"] == "NON_PRODUCTION" {
			criticality = "NON_PRODUCTION"
		}
		policy["criticality"], policy["seasonal"] = criticality, profile["high_seasonality"]
		constraints := storageObject(profile["aws_service"])
		headroom, saturation := storageObject(profile["headroom"]), storageObject(profile["saturation"])
		for target, value := range map[string]int64{"cpu_headroom_fraction": model.Number(headroom, "cpu_free_ppm"), "memory_headroom_fraction": model.Number(headroom, "memory_free_ppm"), "cpu_max_fraction": model.Number(saturation, "cpu_p99_ppm"), "memory_max_fraction": model.Number(saturation, "memory_p99_ppm")} {
			inherited := big.NewRat(value, 1000000)
			declared, ok := databaseDecimal(constraints[target])
			if !ok || strings.Contains(target, "headroom") && declared.Cmp(inherited) < 0 || strings.Contains(target, "max_fraction") && declared.Cmp(inherited) > 0 {
				constraints[target] = databaseInputMoney(inherited)
			}
		}
		constraints["min_replicas"], constraints["min_zones"] = strconv.FormatInt(model.Number(profile, "min_replicas"), 10), strconv.FormatInt(model.Number(profile, "min_zones"), 10)
		policy["service_constraints"] = constraints
		sourceRefs = append(sourceRefs, storageRef("WORKLOAD_SAFETY_PROFILE", model.String(profile, "id"), strconv.FormatInt(model.Number(profile, "version"), 10), evidence.Hash(profile)))
	} else {
		reasons = append(reasons, "AWS_SERVICE_WORKLOAD_SAFETY_PROFILE_REQUIRED")
	}
	if model.String(r, "workload_id") == "" || model.String(r, "configuration_authority") == "" || r["configuration_authority"] == "UNKNOWN" {
		reasons = append(reasons, "AWS_SERVICE_WORKLOAD_AND_CONFIGURATION_AUTHORITY_REQUIRED")
	}
	if model.String(r, "workload_id") != "" {
		w, e := t.Get(ctx, "workloads", model.String(r, "workload_id"))
		if errors.Is(e, pgx.ErrNoRows) {
			reasons = append(reasons, "AWS_SERVICE_WORKLOAD_BINDING_UNKNOWN")
		} else if e != nil {
			return nil, nil, e
		}
		if model.String(policy, "owner") == "" {
			policy["owner"] = w["owner"]
		}
	}
	start, end := model.String(observations, "start"), model.String(observations, "end")
	days := 30
	if policy["criticality"] == "NON_PRODUCTION" {
		days = 14
	}
	if policy["seasonal"] == true {
		days = 90
	}
	until, e := time.Parse(time.RFC3339Nano, end)
	if e == nil {
		from := until.Add(-time.Duration(days) * 24 * time.Hour)
		actual, e := time.Parse(time.RFC3339Nano, start)
		if e == nil && actual.After(from) {
			from = actual
		}
		start = from.UTC().Format(time.RFC3339Nano)
		observations["start"] = start
		kept := []model.Document{}
		for _, row := range storageRows(observations["metrics"]) {
			at, e := time.Parse(time.RFC3339Nano, model.String(row, "source_time"))
			if e == nil && !at.Before(from) && at.Before(until) {
				kept = append(kept, row)
			}
		}
		observations["metrics"] = kept
	}
	input := model.Document{"schema_version": "1", "model_version": "aws-service-v1", "model_kind": "AWS_SERVICE_ASSESSMENT_V1", "binding": storageBinding(t.Tenant, r), "family": r["service_family"], "now": a.now().UTC().Format(time.RFC3339Nano), "configuration": configuration, "snapshot_ref": nil, "observations": observations, "capabilities": capabilities, "policy": policy, "source_refs": sourceRefs, "period": model.Document{"start": start, "end": end}, "billing": model.Document{}}
	if s != nil {
		input["snapshot_ref"] = sourceRefs[0]
	}
	if r["service_family"] == "ECS" || r["service_family"] == "ELASTICACHE" {
		refs, rs, e := databaseApplicationSLO(ctx, t, r, a.now())
		if e != nil {
			return nil, nil, e
		}
		sourceRefs = append(sourceRefs, refs...)
		for _, reason := range rs {
			reasons = append(reasons, strings.ReplaceAll(reason, "DATABASE_APPLICATION_", "AWS_SERVICE_APPLICATION_"))
		}
		input["source_refs"] = sourceRefs
	}
	return input, databaseSortedReasons(reasons), nil
}

func awsServiceBlocked(binding model.Document, family string, reasons []string) model.Document {
	rs := databaseSortedReasons(reasons)
	return model.Document{"schema_version": "1", "model_version": "aws-service-v1", "model_kind": "AWS_SERVICE_ASSESSMENT_V1", "family": family, "binding": binding, "resource_id": binding["resource_id"], "status": "BLOCKED", "decision_code": "AWS_SERVICE_EVIDENCE_INCOMPLETE", "recommendation_kind": "AWS_SERVICE_REVIEW", "current_configuration": nil, "proposed_configuration": nil, "metric_distributions": []model.Document{}, "candidates": []model.Document{}, "reason_codes": rs, "blockers": rs, "economics": model.Document{"status": "ECONOMICS_UNAVAILABLE", "currency": nil, "current_window_cost": nil, "candidate_window_cost": nil, "estimated_window_saving": nil, "conditional_monthly_run_rate": nil, "basis": "NO_CUSTOMER_RATE_ESTIMATE"}, "confidence": model.Document{"status": "UNAVAILABLE", "reason_codes": rs}, "source_refs": []model.Document{}, "economically_analysed_source_record_ids": []string{}, "risk_class": "R3", "read_only": true, "pre_execution_ready": false, "execution_authorized": false, "verified_saving": nil}
}
func awsServiceBlockResult(result model.Document, reasons []string) {
	reasons = databaseSortedReasons(append(model.Strings(result, "blockers"), reasons...))
	result["status"], result["blockers"], result["reason_codes"] = "BLOCKED", reasons, reasons
	result["decision_code"] = "AWS_SERVICE_SERVER_EVIDENCE_BLOCKED"
	result["proposed_configuration"] = nil
	result["economically_analysed_source_record_ids"] = []string{}
	clear := func(e model.Document) {
		e["status"] = "ECONOMICS_UNAVAILABLE"
		e["candidate_window_cost"], e["estimated_window_saving"], e["conditional_monthly_run_rate"] = nil, nil, nil
	}
	econ := storageObject(result["economics"])
	clear(econ)
	result["economics"] = econ
	candidates := storageRows(result["candidates"])
	for _, candidate := range candidates {
		econ := storageObject(candidate["economics"])
		clear(econ)
		candidate["economics"] = econ
		if candidate["status"] == "RECOMMENDED" {
			candidate["status"] = "BLOCKED"
			candidate["reason_codes"] = reasons
		}
	}
	result["candidates"] = candidates
}
func validateAWSServiceResult(result, input model.Document) error {
	if result["schema_version"] != "1" || result["model_kind"] != "AWS_SERVICE_ASSESSMENT_V1" || result["model_version"] != "aws-service-v1" || result["family"] != input["family"] || result["resource_id"] != storageObject(input["binding"])["resource_id"] || evidence.Hash(result["binding"]) != evidence.Hash(input["binding"]) || result["read_only"] != true || result["pre_execution_ready"] != false || result["execution_authorized"] != false || result["verified_saving"] != nil || result["risk_class"] != "R3" {
		return errors.New("AWS_SERVICE_RESULT_BOUNDARY_INVALID")
	}
	switch result["status"] {
	case "RECOMMENDED", "NO_CHANGE", "BLOCKED":
	default:
		return errors.New("AWS_SERVICE_RESULT_STATUS_INVALID")
	}
	economics := append([]model.Document{storageObject(result["economics"])}, storageRows(result["candidates"])...)
	for j, e := range economics {
		if j > 0 {
			e = storageObject(e["economics"])
		}
		for _, key := range []string{"current_window_cost", "candidate_window_cost", "estimated_window_saving", "conditional_monthly_run_rate"} {
			if v := e[key]; v != nil {
				value, ok := v.(string)
				if !ok || !databaseCoverageDecimal.MatchString(value) {
					return errors.New("AWS_SERVICE_RESULT_DECIMAL_REQUIRED")
				}
				if key != "current_window_cost" {
					billing := storageObject(input["billing"])
					if e["currency"] != billing["currency"] {
						return errors.New("AWS_SERVICE_RESULT_CURRENCY_BINDING_INVALID")
					}
					for _, gate := range []string{"complete", "scope_complete", "marginal_pricing_known", "commitment_scope_known"} {
						if billing[gate] != true {
							return errors.New("AWS_SERVICE_RESULT_FINANCIAL_AUTHORITY_UNAVAILABLE")
						}
					}
				}
			}
		}
		if value := e["currency"]; value != nil {
			currency, ok := value.(string)
			if !ok || !databaseCoverageCurrency.MatchString(currency) {
				return errors.New("AWS_SERVICE_RESULT_CURRENCY_INVALID")
			}
		}
	}
	return nil
}

func awsServiceAssessmentOne(ctx context.Context, a *API, t *store.Tx, read databaseArchiveRead) error {
	var id, rid, family, sid, pid string
	e := t.QueryRow(ctx, "SELECT id,resource_id,family,coalesce(snapshot_id,''),coalesce(safety_profile_id,'') FROM aws_service_assessments WHERE tenant_id=$1 AND status='QUEUED' ORDER BY created_at,id LIMIT 1 FOR UPDATE SKIP LOCKED", t.Tenant).Scan(&id, &rid, &family, &sid, &pid)
	if errors.Is(e, pgx.ErrNoRows) {
		return nil
	}
	if e != nil {
		return e
	}
	resource, e := t.Get(ctx, "resources", rid)
	if e != nil {
		return e
	}
	var snapshot, profile model.Document
	canonical := model.Document{}
	reasons := []string{}
	if sid != "" {
		snapshot, e = t.AWSServiceEvidenceGet(ctx, sid)
		if e != nil {
			return e
		}
		raw, e := read(ctx, t.Tenant, storageObject(snapshot["archive"]))
		if e != nil {
			return e
		}
		if awsservice.BytesHash(raw) != model.String(snapshot, "content_hash") {
			return errors.New("AWS_SERVICE_SNAPSHOT_HASH_MISMATCH")
		}
		canonical = storageObject(json.RawMessage(raw))
		if canonical["tenant_id"] != t.Tenant || canonical["resource_id"] != rid || canonical["account_id"] != resource["account_id"] || canonical["region"] != resource["region"] || canonical["config_hash"] != awsservice.ConfigurationHash(resource) {
			reasons = append(reasons, "AWS_SERVICE_NATIVE_SNAPSHOT_BINDING_CHANGED")
		}
	} else {
		reasons = append(reasons, "AWS_SERVICE_NATIVE_SNAPSHOT_REQUIRED")
	}
	if pid != "" {
		profile, e = t.WorkloadSafetyGet(ctx, pid)
		if e != nil {
			return e
		}
	}
	input, inputReasons, e := awsServiceAssessmentInput(ctx, a, t, resource, snapshot, canonical, profile, read)
	if e != nil {
		return e
	}
	reasons = append(reasons, inputReasons...)
	financial, financialReasons, e := a.awsServiceFinancialInput(ctx, t, resource, snapshot, canonical, input)
	if e != nil {
		return e
	}
	result := awsServiceBlocked(storageBinding(t.Tenant, resource), family, reasons)
	observedWindow := storageObject(input["observations"])
	if sid != "" && model.String(observedWindow, "start") != "" && model.String(observedWindow, "end") != "" && model.String(resource, "workload_id") != "" {
		result, e = a.economics(ctx, "v12/aws-service-assessment", input)
		if e != nil {
			return e
		}
		if e = validateAWSServiceResult(result, input); e != nil {
			return e
		}
	}
	result["financial_references"], result["source_refs"], result["resource_authority_hash"], result["snapshot_id"] = financial, input["source_refs"], awsServiceResourceAuthorityHash(resource), sid
	economicContext := storageObject(result["economics"])
	economicContext["blockers"] = financialReasons
	result["economics"] = economicContext
	if profile != nil {
		result["profile_ref"] = storageRef("WORKLOAD_SAFETY_PROFILE", pid, strconv.FormatInt(model.Number(profile, "version"), 10), evidence.Hash(profile))
	}
	prospective, e := t.AWSServiceAssessmentGet(ctx, id)
	if e != nil {
		return e
	}
	prospective["status"], prospective["assessment"] = "ASSESSED", result
	current, e := a.awsServiceAssessmentCurrent(ctx, t, prospective)
	if e != nil {
		return e
	}
	reasons = append(reasons, model.Strings(current, "currentness_blockers")...)
	if len(reasons) > 0 {
		awsServiceBlockResult(result, reasons)
	}
	result["assessment_hash"] = evidence.Hash(result)
	status := "ASSESSED"
	if result["status"] == "BLOCKED" {
		status = "BLOCKED"
	}
	raw, _ := json.Marshal(model.Document{"assessment": result})
	if _, e = t.Exec(ctx, "UPDATE aws_service_assessments SET status=$3,document=$4 WHERE tenant_id=$1 AND id=$2", t.Tenant, id, status, raw); e != nil {
		return e
	}
	economics := storageObject(result["economics"])
	publication := model.Document{"id": "aws-service-" + id, "aws_service_assessment_id": id, "resource_id": rid, "family": family, "workload_id": resource["workload_id"], "model_kind": "AWS_SERVICE_ASSESSMENT_V1", "assessment": result, "status": result["status"], "action_type": "AWS_SERVICE_CONFIGURATION_REVIEW", "title": "Review " + family + " configuration: " + model.String(resource, "name"), "reason_code": result["decision_code"], "pre_execution_ready": false, "execution_authorized": false, "verified_saving": nil, "risk_class": "R3", "monthly_saving": nil, "currency": economics["currency"], "created_at": model.Now(), "version": 1}
	raw, _ = json.Marshal(publication)
	if _, e = t.Exec(ctx, "INSERT INTO aws_service_recommendation_publications(tenant_id,assessment_id,resource_id,document,currency) VALUES($1,$2,$3,$4,$5)", t.Tenant, id, rid, raw, economics["currency"]); e != nil {
		return e
	}
	if e = t.Audit(ctx, "aws-service-assessor", "aws_service.assessment.published", id, model.Document{"resource_id": rid, "family": family, "status": status, "execution_authorized": false}); e != nil {
		return e
	}
	return t.Event(ctx, "aws_service.assessment.published", model.Document{"id": id, "resource_id": rid, "family": family, "status": status})
}
