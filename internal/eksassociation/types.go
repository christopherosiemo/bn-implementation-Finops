package eksassociation

import (
	"encoding/json"
	"errors"
	"regexp"
	"sort"
	"strings"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/awsservice"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/kubernetes"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
)

const Kind = "AWS_EKS_KUBERNETES_V1"

var ErrBinding = errors.New("EKS_KUBERNETES_BINDING_INVALID")
var safe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)
var providerID = regexp.MustCompile(`^aws:///([a-z]{2}-[a-z]+-[0-9][a-z])/(i-[a-f0-9]{8}(?:[a-f0-9]{9})?)$`)

type Registration struct {
	ID                      string                               `json:"id"`
	TenantID                string                               `json:"tenant_id"`
	Kind                    string                               `json:"kind"`
	AccountID               string                               `json:"account_id"`
	Region                  string                               `json:"region"`
	ClusterARN              string                               `json:"cluster_arn"`
	ReadRoleBindingID       string                               `json:"read_role_binding_id"`
	KubernetesReadBindingID string                               `json:"kubernetes_read_binding_id"`
	WorkloadBindings        []kubernetes.IdentityWorkloadBinding `json:"workload_bindings"`
	Version                 int64                                `json:"version"`
	Enabled                 bool                                 `json:"enabled"`
}

func Parse(d model.Document) (Registration, error) {
	var r Registration
	b, e := json.Marshal(d)
	if e != nil || json.Unmarshal(b, &r) != nil || Validate(r) != nil {
		return r, ErrBinding
	}
	return r, nil
}
func Validate(r Registration) error {
	if r.Kind != Kind || !safe.MatchString(r.ID) || !safe.MatchString(r.TenantID) || !safe.MatchString(r.ReadRoleBindingID) || !safe.MatchString(r.KubernetesReadBindingID) || r.Version < 1 || r.Region != "eu-west-1" || awsservice.ValidateScope(awsservice.Scope{TenantID: r.TenantID, AccountID: r.AccountID, Region: r.Region}) != nil || !strings.HasPrefix(r.ClusterARN, "arn:aws:eks:"+r.Region+":"+r.AccountID+":cluster/") || !safe.MatchString(strings.TrimPrefix(r.ClusterARN, "arn:aws:eks:"+r.Region+":"+r.AccountID+":cluster/")) || len(r.WorkloadBindings) > 64 {
		return ErrBinding
	}
	seen := map[string]bool{}
	for _, b := range r.WorkloadBindings {
		if !safe.MatchString(b.WorkloadID) || !safe.MatchString(b.Namespace) || !safe.MatchString(b.NamespaceUID) || !safe.MatchString(b.Deployment) || !safe.MatchString(b.DeploymentUID) || seen[b.WorkloadID] {
			return ErrBinding
		}
		seen[b.WorkloadID] = true
	}
	return nil
}
func Hash(v any) string             { return awsservice.Hash(v) }
func Document(v any) model.Document { return awsservice.Document(v) }
func Rows(v any) []model.Document   { return awsservice.Rows(v) }
func reasons(xs []string) []string {
	sort.Strings(xs)
	out := []string{}
	for _, s := range xs {
		if s != "" && (len(out) == 0 || out[len(out)-1] != s) {
			out = append(out, s)
		}
	}
	return out
}

// Associate emits relationships only. Provider billing and existing Kubernetes
// resource quantities are never copied into additional economic resources.
func Associate(r Registration, s kubernetes.IdentitySnapshot, native, membership []model.Document) model.Document {
	nodes := []model.Document{}
	workloads := []model.Document{}
	all := append([]string{}, s.Problems...)
	groupByASG := map[string][]model.Document{}
	profiles := map[string][]model.Document{}
	instances := map[string][]model.Document{}
	clusterName := r.ClusterARN[strings.LastIndexByte(r.ClusterARN, '/')+1:]
	for _, resource := range native {
		if resource["account_id"] != r.AccountID || resource["region"] != r.Region {
			continue
		}
		cfg := Document(resource["aws_service_configuration"])
		switch model.String(resource, "resource_type") {
		case "EKS_NODE_GROUP":
			if cfg["clusterName"] != clusterName {
				continue
			}
			for _, name := range model.Strings(cfg, "native_auto_scaling_group_names") {
				groupByASG[name] = append(groupByASG[name], resource)
			}
		case "EKS_FARGATE_PROFILE":
			if cfg["clusterName"] == clusterName {
				profiles[model.String(cfg, "fargateProfileName")] = append(profiles[model.String(cfg, "fargateProfileName")], resource)
			}
		case "EC2":
			instances[model.String(resource, "provider_resource_id")] = append(instances[model.String(resource, "provider_resource_id")], resource)
		}
	}
	matchedNodes := map[string]model.Document{}
	nodeUIDs := map[string]string{}
	for _, node := range s.Nodes {
		rs := []string{}
		out := model.Document{"kubernetes_node_uid": node.UID, "kubernetes_node_name": node.Name, "provider_id": node.ProviderID, "resource_version": node.ResourceVersion, "ec2_resource_id": nil, "nodegroup_resource_id": nil, "fargate_profile_resource_id": nil, "status": "BLOCKED", "reason_codes": []string{}}
		nodeUIDs[node.Name] = node.UID
		if node.ComputeType == "fargate" {
			out["status"] = "FARGATE_PLACEMENT_UNPROVEN"
			if !node.Ready {
				rs = append(rs, "EKS_FARGATE_NODE_NOT_READY")
			}
			out["fargate_profile_name"] = node.Profile
		} else {
			p := providerID.FindStringSubmatch(node.ProviderID)
			if len(p) != 3 || !strings.HasPrefix(p[1], r.Region) || node.Zone != p[1] {
				rs = append(rs, "EKS_NODE_PROVIDER_ID_SCOPE_UNPROVEN")
			} else {
				out["ec2_instance_id"] = p[2]
				matches := []model.Document{}
				for _, m := range membership {
					if m["instance_id"] == p[2] && m["account_id"] == r.AccountID && m["region"] == r.Region && m["zone"] == p[1] && m["state"] == "running" {
						for _, g := range groupByASG[model.String(m, "asg_name")] {
							matches = append(matches, g)
						}
					}
				}
				if len(matches) != 1 {
					rs = append(rs, "EKS_MANAGED_GROUP_MEMBERSHIP_UNPROVEN")
				} else {
					cfg := Document(matches[0]["aws_service_configuration"])
					if node.Nodegroup != "" && node.Nodegroup != cfg["nodegroupName"] {
						rs = append(rs, "EKS_NODEGROUP_LABEL_CONFLICT")
					} else {
						out["nodegroup_resource_id"] = matches[0]["id"]
					}
				}
				if len(instances[p[2]]) == 1 {
					out["ec2_resource_id"] = instances[p[2]][0]["id"]
				} else {
					rs = append(rs, "EKS_EC2_CANONICAL_IDENTITY_UNAVAILABLE")
				}
				if len(rs) == 0 {
					out["status"] = "ASSOCIATED"
				}
			}
		}
		out["reason_codes"] = reasons(rs)
		matchedNodes[node.Name] = out
		nodes = append(nodes, out)
	}
	for _, w := range s.Workloads {
		rs := append([]string{}, w.Problems...)
		podIDs, nodeIDs := []string{}, []string{}
		for _, pod := range w.Pods {
			podIDs = append(podIDs, pod.UID)
			n := matchedNodes[pod.Node]
			if n == nil {
				rs = append(rs, "EKS_POD_NODE_UNOBSERVED")
				continue
			}
			nodeIDs = append(nodeIDs, nodeUIDs[pod.Node])
			if n["status"] == "FARGATE_PLACEMENT_UNPROVEN" {
				profileName := model.String(n, "fargate_profile_name")
				matches := profiles[profileName]
				valid := profileName != "" && pod.Labels["eks.amazonaws.com/fargate-profile"] == profileName && len(matches) == 1 && pod.Scheduled && pod.Running && pod.Phase == "Running"
				if valid {
					cfg := Document(matches[0]["aws_service_configuration"])
					valid = cfg["status"] == "ACTIVE" && profileMatches(cfg, w.Binding.Namespace, pod.Labels)
					if valid {
						n["fargate_profile_resource_id"] = matches[0]["id"]
					}
				}
				if valid && len(model.Strings(n, "reason_codes")) == 0 {
					n["status"] = "ASSOCIATED"
				} else {
					n["status"] = "PARTIAL"
					n["reason_codes"] = reasons(append(model.Strings(n, "reason_codes"), "EKS_EXACT_FARGATE_PROFILE_UNPROVEN"))
					rs = append(rs, "EKS_EXACT_FARGATE_PROFILE_UNPROVEN")
				}
			}
			if n["status"] != "ASSOCIATED" {
				rs = append(rs, "EKS_WORKLOAD_CAPACITY_ASSOCIATION_INCOMPLETE")
			}
		}
		status := "ASSOCIATED"
		if len(rs) > 0 || len(podIDs) == 0 {
			status = "BLOCKED"
		}
		workloads = append(workloads, model.Document{"workload_id": w.Binding.WorkloadID, "namespace_uid": w.NamespaceUID, "deployment_uid": w.DeploymentUID, "pod_uids": podIDs, "node_uids": nodeIDs, "status": status, "reason_codes": reasons(rs)})
		all = append(all, rs...)
	}
	for _, n := range nodes {
		all = append(all, model.Strings(n, "reason_codes")...)
		if n["status"] != "ASSOCIATED" {
			all = append(all, "EKS_NODE_ASSOCIATION_INCOMPLETE")
		}
	}
	status := "ASSOCIATED"
	if len(all) > 0 {
		status = "PARTIAL"
	}
	if len(nodes) == 0 {
		status = "BLOCKED"
		all = append(all, "EKS_NODE_PLACEMENT_UNOBSERVED")
	}
	return model.Document{"schema_version": "1", "status": status, "reason_codes": reasons(all), "cluster": model.Document{"arn": r.ClusterARN, "kube_system_uid": s.ClusterID}, "nodes": nodes, "workloads": workloads, "execution_authorized": false, "verified_saving": nil, "cost_attribution": "RELATIONSHIP_ONLY_NO_ADDITIONAL_COST"}
}
func profileMatches(cfg model.Document, namespace string, labels map[string]string) bool {
	for _, selector := range Rows(cfg["selectors"]) {
		if !selectorPattern(model.String(selector, "namespace"), namespace) {
			continue
		}
		match := true
		for k, v := range Document(selector["labels"]) {
			matched := false
			for key, value := range labels {
				if selectorPattern(k, key) && selectorPattern(model.String(model.Document{"v": v}, "v"), value) {
					matched = true
				}
			}
			if !matched {
				match = false
			}
		}
		if match {
			return true
		}
	}
	return false
}
func selectorPattern(pattern, value string) bool {
	if pattern == "" || len(pattern) > 256 {
		return false
	}
	escaped := regexp.QuoteMeta(pattern)
	escaped = strings.ReplaceAll(strings.ReplaceAll(escaped, `\*`, ".*"), `\?`, ".")
	compiled, e := regexp.Compile("^" + escaped + "$")
	return e == nil && compiled.MatchString(value)
}
