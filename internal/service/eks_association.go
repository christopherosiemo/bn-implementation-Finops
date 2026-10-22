package service

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/auth"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/awsservice"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/eksassociation"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/source"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/jackc/pgx/v5"
	"net/http"
	"os"
	"time"
)

func (a *API) eksAssociationGet(ctx context.Context, t *store.Tx, i auth.Identity, r *http.Request, parts []string) (any, bool, error) {
	if len(parts) == 1 && parts[0] == "eks-kubernetes-bindings" {
		var bindings map[string]source.EKSApprovedBinding
		if json.Unmarshal([]byte(os.Getenv("EKS_KUBERNETES_APPROVED_BINDINGS_JSON")), &bindings) != nil {
			bindings = map[string]source.EKSApprovedBinding{}
		}
		out := []model.Document{}
		for id, b := range bindings {
			if b.TenantID == t.Tenant {
				out = append(out, model.Document{"id": id, "account_id": b.AccountID, "region": b.Region, "cluster_arn": b.ClusterARN})
			}
		}
		return model.Document{"items": out}, true, nil
	}
	if len(parts) != 3 || parts[0] != "resources" || parts[2] != "eks-association" {
		return nil, false, nil
	}
	if e := storageReadScope(ctx, t, i, parts[1]); e != nil {
		return nil, true, e
	}
	resource, e := t.Get(ctx, "resources", parts[1])
	if e != nil {
		return nil, true, e
	}
	if resource["resource_type"] != "EKS_CLUSTER" {
		return nil, true, problem(422, "EKS_CLUSTER_RESOURCE_REQUIRED", "select an observed EKS cluster")
	}
	d, e := t.EKSAssociationLatest(ctx, parts[1])
	if errors.Is(e, pgx.ErrNoRows) {
		return model.Document{"resource_id": parts[1], "status": "BLOCKED", "current": false, "reason_codes": []string{"EKS_KUBERNETES_ASSOCIATION_NOT_COLLECTED"}, "nodes": []model.Document{}, "workloads": []model.Document{}, "execution_authorized": false, "verified_saving": nil, "cost_attribution": "RELATIONSHIP_ONLY_NO_ADDITIONAL_COST"}, true, nil
	}
	if e != nil {
		return nil, true, e
	}
	reasons := []string{}
	for _, pair := range [][2]string{{"source_id", "source_version"}, {"native_source_id", "native_source_version"}} {
		s, e := t.SourceGet(ctx, model.String(d, pair[0]))
		if e != nil {
			return nil, true, e
		}
		if !model.Bool(s, "enabled") || model.Bool(s, "revoked") || model.Number(s, "version") != model.Number(d, pair[1]) {
			reasons = append(reasons, "EKS_ASSOCIATION_SOURCE_CHANGED_OR_REVOKED")
		}
		if pair[0] == "source_id" {
			if model.String(s, "status") == "BLOCKED" {
				reasons = append(reasons, "EKS_ASSOCIATION_LATEST_COLLECTION_FAILED")
			}
			registration, e := eksassociation.Parse(s)
			if e != nil || source.ValidateEKSApprovedBinding(os.Getenv("EKS_KUBERNETES_APPROVED_BINDINGS_JSON"), registration) != nil {
				reasons = append(reasons, "EKS_APPROVED_BINDING_UNAVAILABLE")
			}
		}
	}
	if d["config_hash"] != awsservice.ConfigurationHash(resource) {
		reasons = append(reasons, "EKS_ASSOCIATION_NATIVE_CONFIGURATION_CHANGED")
	}
	for id, hash := range storageObject(d["native_configuration_hashes"]) {
		native, e := t.Get(ctx, "resources", id)
		if e != nil || awsservice.ConfigurationHash(native) != hash {
			reasons = append(reasons, "EKS_ASSOCIATION_NATIVE_TOPOLOGY_CHANGED")
		}
	}
	at, e := time.Parse(time.RFC3339Nano, model.String(d, "observed_at"))
	if e != nil || at.After(a.now().Add(time.Minute)) || a.now().Sub(at) > 30*time.Minute {
		reasons = append(reasons, "EKS_ASSOCIATION_STALE")
	}
	d["current"], d["currentness_blockers"] = len(reasons) == 0, databaseSortedReasons(reasons)
	if scopedOwner(i) {
		visible := []model.Document{}
		visibleWorkloads := map[string]model.Document{}
		for _, binding := range eksassociation.Rows(d["workloads"]) {
			workload, err := t.Get(ctx, "workloads", model.String(binding, "workload_id"))
			if err == nil && workloadAccess(i, workload) == nil {
				binding["owner"] = eksWorkloadOwner(workload)
				visible = append(visible, binding)
				visibleWorkloads[model.String(binding, "workload_id")] = workload
			}
		}
		d["workloads"] = visible
		assessments := []model.Document{}
		for _, assessment := range eksassociation.Rows(d["request_assessments"]) {
			if workload, ok := visibleWorkloads[model.String(assessment, "workload_id")]; ok {
				assessment["owner"] = eksWorkloadOwner(workload)
				if model.String(assessment, "owner") == "" {
					assessment["status"] = "BLOCKED"
					assessment["reason_codes"] = databaseSortedReasons(append(model.Strings(assessment, "reason_codes"), "K8S_WORKLOAD_OWNER_UNAVAILABLE"))
				}
				assessments = append(assessments, assessment)
			}
		}
		d["request_assessments"] = assessments
	} else {
		visibleWorkloads := map[string]model.Document{}
		for _, binding := range eksassociation.Rows(d["workloads"]) {
			workload, err := t.Get(ctx, "workloads", model.String(binding, "workload_id"))
			if err != nil {
				continue
			}
			binding["owner"] = eksWorkloadOwner(workload)
			visibleWorkloads[model.String(binding, "workload_id")] = workload
		}
		for _, assessment := range eksassociation.Rows(d["request_assessments"]) {
			workload, ok := visibleWorkloads[model.String(assessment, "workload_id")]
			if !ok {
				blockEKSRequestAssessment(assessment)
				continue
			}
			assessment["owner"] = eksWorkloadOwner(workload)
			if model.String(assessment, "owner") == "" {
				blockEKSRequestAssessment(assessment)
			}
		}
	}
	return d, true, nil
}

func eksWorkloadOwner(w model.Document) string {
	if subject := model.String(w, "owner_subject"); subject != "" {
		return subject
	}
	return model.String(w, "owner")
}

func blockEKSRequestAssessment(assessment model.Document) {
	assessment["owner"] = nil
	assessment["status"] = "BLOCKED"
	assessment["reason_codes"] = databaseSortedReasons(append(model.Strings(assessment, "reason_codes"), "K8S_WORKLOAD_OWNER_UNAVAILABLE"))
}
