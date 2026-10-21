package workflow

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/native"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/provider"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/service"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/source"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/jackc/pgx/v5"
)

// One short claim, bounded external reads, then a short publication transaction.
// No customer execution, paid telemetry configuration or payload reads occur.
func awsAccountCommissioningTick(ctx context.Context, a *Activities, tenant string) error {
	token := model.ID()
	var request model.Document
	e := a.Store.Do(ctx, tenant, func(tx *store.Tx) error {
		var err error
		request, err = tx.AWSAccountPreflightClaim(ctx, token, time.Now().UTC())
		return err
	})
	if errors.Is(e, pgx.ErrNoRows) {
		return nil
	}
	if e != nil {
		return e
	}
	id := model.String(request, "id")
	fail := func(reason string) error {
		return a.Store.Do(ctx, tenant, func(tx *store.Tx) error { return tx.AWSAccountPreflightFail(ctx, id, token, reason) })
	}
	var account model.Document
	e = a.Store.Do(ctx, tenant, func(tx *store.Tx) error {
		var err error
		account, err = tx.Get(ctx, "cloud_accounts", model.String(request, "cloud_account_id"))
		return err
	})
	if e != nil {
		return fail("AWS_ACCOUNT_BINDING_UNAVAILABLE")
	}
	for _, key := range []string{"account_id", "region", "read_role_binding_id"} {
		if account[key] != request[key] {
			return fail("AWS_ACCOUNT_BINDING_CHANGED")
		}
	}
	if account["provider"] != "AWS" || account["connection_mode"] != "READ_ONLY" {
		return fail("AWS_ACCOUNT_READ_ONLY_BINDING_REQUIRED")
	}
	// Discovery status can advance the entity version without changing the pinned
	// account binding. It cannot substitute a different target or read identity.
	work, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()
	probeRequest := provider.AWSAccountProbeRequest{TenantID: tenant, AccountID: model.String(request, "account_id"), Region: model.String(request, "region")}
	var probe provider.AWSAccountProbeResult
	var selectedBinding source.AWSReadBinding
	if a.Config.Fixture {
		if model.String(request, "read_role_binding_id") != "fixture-aws-readonly" {
			return fail("AWS_FIXTURE_BINDING_REQUIRED")
		}
		probeRequest.ExpectedRoleARN = "arn:aws:iam::" + probeRequest.AccountID + ":role/FixtureReadOnlyRole"
		probeRequest.ExternalIDConfigured = true // Synthetic example only; no credential or AWS call.
		probe, e = provider.FixtureAWSAccountReadPreflight(probeRequest)
		if e != nil {
			return fail("AWS_FIXTURE_ACCESS_PROBE_UNAVAILABLE")
		}
	} else {
		if service.ValidateAWSTenant(tenant) != nil {
			return fail("AWS_ACCOUNT_TENANT_NOT_CONFIGURED")
		}
		binding, err := source.ResolveApprovedAWSAccountReadBinding(os.Getenv("AWS_ACCOUNT_READ_BINDINGS_JSON"), os.Getenv("AWS_ACCOUNT_APPROVED_BINDINGS_JSON"), model.String(request, "read_role_binding_id"), tenant, probeRequest.AccountID, probeRequest.Region)
		if err != nil {
			probe = unavailableAWSAccountProbe(probeRequest, "NOT_CONFIGURED", "AWS_ACCOUNT_READ_BINDING_NOT_CONFIGURED")
		} else {
			selectedBinding = binding
			probeRequest.ExpectedRoleARN = binding.RoleARN
			probeRequest.ExternalIDConfigured = binding.ExternalID != ""
			reader, err := provider.NewAWS(work, binding.Region, binding.RoleARN, binding.ExternalID)
			if err != nil {
				probe = unavailableAWSAccountProbe(probeRequest, "ERROR", "AWS_ACCOUNT_READ_IDENTITY_UNAVAILABLE")
			} else {
				probe, err = reader.AccountReadPreflight(work, probeRequest)
				if err != nil {
					probe = unavailableAWSAccountProbe(probeRequest, "ERROR", "AWS_ACCOUNT_ACCESS_PROBE_UNAVAILABLE")
				}
			}
		}
	}
	// The adapter emits only safe typed probe metadata, never raw configurations,
	// provider messages, environment values or credential material.
	raw, e := json.Marshal(probe)
	if e != nil {
		return fail("AWS_ACCOUNT_PROBE_ENCODING_FAILED")
	}
	storage, e := native.StorageFromEnvironment(work, a.Config.Fixture)
	if e != nil {
		return fail("AWS_ACCOUNT_EVIDENCE_STORAGE_UNAVAILABLE")
	}
	archive, e := storage.Archive(work, tenant, "wire", "account-preflight-"+id, raw)
	if e != nil {
		return fail("AWS_ACCOUNT_PROBE_ARCHIVE_FAILED")
	}
	read, e := storage.Read(work, tenant, archive)
	if e != nil || string(read) != string(raw) {
		return fail("AWS_ACCOUNT_PROBE_ARCHIVE_READBACK_FAILED")
	}
	return a.Store.Do(ctx, tenant, func(tx *store.Tx) error {
		if !a.Config.Fixture && selectedBinding.RoleARN != "" {
			currentBinding, err := source.ResolveApprovedAWSAccountReadBinding(os.Getenv("AWS_ACCOUNT_READ_BINDINGS_JSON"), os.Getenv("AWS_ACCOUNT_APPROVED_BINDINGS_JSON"), model.String(request, "read_role_binding_id"), tenant, probeRequest.AccountID, probeRequest.Region)
			if err != nil || currentBinding.RoleARN != selectedBinding.RoleARN || currentBinding.ExternalID != selectedBinding.ExternalID {
				return tx.AWSAccountPreflightFail(ctx, id, token, "AWS_ACCOUNT_APPROVED_BINDING_CHANGED")
			}
		}
		current, e := tx.Get(ctx, "cloud_accounts", model.String(request, "cloud_account_id"))
		if e != nil {
			return e
		}
		for _, key := range []string{"account_id", "region", "read_role_binding_id"} {
			if current[key] != request[key] {
				return tx.AWSAccountPreflightFail(ctx, id, token, "AWS_ACCOUNT_BINDING_CHANGED")
			}
		}
		api := &service.API{Store: a.Store, Config: a.Config, Client: a.HTTP}
		evidence, e := api.CommissioningEvidence(ctx, tx, probeRequest.AccountID, probeRequest.Region, time.Now().UTC())
		if e != nil {
			return e
		}
		report := buildAWSCommissioningReport(tenant, request, probe, evidence, archive)
		return tx.AWSAccountPreflightComplete(ctx, id, token, report)
	})
}

func unavailableAWSAccountProbe(req provider.AWSAccountProbeRequest, status, reason string) provider.AWSAccountProbeResult {
	out := provider.AWSAccountProbeResult{SchemaVersion: "1", ObservedAt: time.Now().UTC(), ObservationBasis: "BOUNDED_NATIVE_READ_ACCESS_PROBE", Identity: provider.AWSAccountProbeIdentity{Status: status, ReasonCode: reason, ExpectedAccountID: req.AccountID, ConfiguredRoleARN: req.ExpectedRoleARN}, Classes: []provider.AWSAccountProbeClass{}}
	for _, key := range []string{"EC2_ASG", "EBS", "RDS_AURORA", "ECS_FARGATE", "EKS", "LAMBDA", "S3", "ELASTICACHE", "DYNAMODB", "NETWORK_NAT", "PUBLIC_IPV4", "ELB", "COMMITMENTS"} {
		out.Classes = append(out.Classes, provider.AWSAccountProbeClass{Category: key, Status: "NOT_CONFIGURED", ReasonCode: "AWS_IDENTITY_PREFLIGHT_REQUIRED", Operations: []provider.AWSAccountProbeOperation{}, Limitations: []string{"ACCESS_PROBE_ONLY_NOT_COMPLETE_INVENTORY", "NO_TELEMETRY_OR_RECOMMENDATION_AUTHORITY"}})
	}
	return out
}

func commissioningDocument(v any) model.Document {
	raw, _ := json.Marshal(v)
	var out model.Document
	_ = json.Unmarshal(raw, &out)
	return out
}
func commissioningDimensions(v any) []model.Document {
	raw, _ := json.Marshal(v)
	out := []model.Document{}
	_ = json.Unmarshal(raw, &out)
	return out
}

func buildAWSCommissioningReport(tenant string, request model.Document, probe provider.AWSAccountProbeResult, evidence, archive model.Document) model.Document {
	dimensions := []model.Document{
		{"key": "IDENTITY", "status": probe.Identity.Status, "reason_codes": []string{probe.Identity.ReasonCode}, "remediation": []string{"Review the approved account read-role binding and cross-account trust policy."}, "affected_spend": []model.Document{}, "details": commissioningDocument(probe.Identity)},
	}
	ready, partial := 0, 0
	for _, c := range probe.Classes {
		if c.Status == "READY" {
			ready++
		}
		if c.Status == "PARTIAL" {
			partial++
		}
	}
	inventoryStatus := "BLOCKED"
	inventoryReason := "AWS_INVENTORY_ACCESS_NOT_READY"
	if ready == len(probe.Classes) && ready == 13 {
		inventoryStatus = "READY"
		inventoryReason = "AWS_BOUNDED_METADATA_READS_AVAILABLE"
	} else if ready+partial > 0 {
		inventoryStatus = "PARTIAL"
		inventoryReason = "AWS_INVENTORY_ACCESS_PARTIAL"
	}
	dimensions = append(dimensions, model.Document{"key": "INVENTORY", "status": inventoryStatus, "reason_codes": []string{inventoryReason}, "remediation": []string{"Review denied or unsupported metadata reads; a successful access probe is not a complete inventory census."}, "affected_spend": []model.Document{}, "details": model.Document{"classes": probe.Classes, "inventory_complete": false}})
	dimensions = append(dimensions, commissioningDimensions(evidence["dimensions"])...)
	for _, d := range dimensions {
		for _, key := range []string{"reason_codes", "remediation"} {
			if d[key] == nil {
				d[key] = []string{}
			}
		}
		// Empty is unavailable/not attributed, never an evidenced zero amount.
		if d["affected_spend"] == nil {
			d["affected_spend"] = []model.Document{}
		}
		if d["details"] == nil {
			d["details"] = model.Document{}
		}
	}
	summary := "NOT_READY"
	if probe.Identity.Status == "READY" && ready+partial > 0 {
		summary = "READ_ONLY_READY"
		evidenceReady := 0
		economicCoverage := false
		for _, d := range dimensions[2:] {
			if d["status"] == "READY" {
				evidenceReady++
			}
			if d["key"] == "RECOMMENDATION_COVERAGE" && (d["status"] == "READY" || d["status"] == "PARTIAL") {
				economicCoverage = true
			}
		}
		if economicCoverage {
			summary = "RECOMMENDATION_PARTIAL"
		}
		if evidenceReady == 8 && inventoryStatus == "READY" {
			summary = "RECOMMENDATION_READY"
		}
	}
	report := model.Document{"schema_version": "1", "id": model.ID(), "tenant_id": tenant, "preflight_id": request["id"], "cloud_account_id": request["cloud_account_id"], "cloud_account_version": request["cloud_account_version"], "read_role_binding_id": request["read_role_binding_id"], "account_id": request["account_id"], "region": request["region"], "observed_at": probe.ObservedAt, "fixture": probe.Fixture, "provider_mode": "AWS_NATIVE", "observation_basis": probe.ObservationBasis, "summary_state": summary, "identity": probe.Identity, "inventory": probe.Classes, "dimensions": dimensions, "execution_credentials": model.Document{"status": "UNKNOWN", "reason_code": "EXECUTION_CREDENTIALS_NOT_INSPECTED"}, "execution_authorized": false, "verified_saving": nil}
	if probe.Fixture {
		report["provider_mode"] = "DETERMINISTIC_FIXTURE"
	}
	for _, key := range []string{"billing", "telemetry", "ownership", "configuration_authority", "commitments", "coverage", "coverage_scope", "evidence_refs"} {
		report[key] = evidence[key]
	}
	report["access_probe_evidence_ref"] = archive
	raw, _ := json.Marshal(report)
	sum := sha256.Sum256(raw)
	report["content_hash"] = hex.EncodeToString(sum[:])
	return report
}
