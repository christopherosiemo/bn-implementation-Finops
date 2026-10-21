package kubernetes

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"time"
)

type IdentityWorkloadBinding struct {
	WorkloadID    string `json:"workload_id"`
	Namespace     string `json:"namespace"`
	NamespaceUID  string `json:"namespace_uid"`
	Deployment    string `json:"deployment"`
	DeploymentUID string `json:"deployment_uid"`
}
type IdentityNode struct {
	UID             string `json:"uid"`
	Name            string `json:"name"`
	ResourceVersion string `json:"resource_version"`
	ProviderID      string `json:"provider_id"`
	Zone            string `json:"zone"`
	ComputeType     string `json:"compute_type"`
	Profile         string `json:"fargate_profile"`
	Nodegroup       string `json:"nodegroup"`
	Ready           bool   `json:"ready"`
}
type IdentityPod struct {
	UID             string            `json:"uid"`
	Name            string            `json:"name"`
	ResourceVersion string            `json:"resource_version"`
	Node            string            `json:"node_name"`
	Labels          map[string]string `json:"labels"`
	Scheduled       bool              `json:"scheduled"`
	Running         bool              `json:"running"`
	Phase           string            `json:"phase"`
}
type IdentityWorkload struct {
	Binding       IdentityWorkloadBinding `json:"binding"`
	NamespaceUID  string                  `json:"namespace_uid"`
	DeploymentUID string                  `json:"deployment_uid"`
	Pods          []IdentityPod           `json:"pods"`
	Problems      []string                `json:"problems"`
}
type IdentitySnapshot struct {
	SchemaVersion string             `json:"schema_version"`
	ClusterID     string             `json:"kube_system_uid"`
	CollectedAt   time.Time          `json:"collected_at"`
	Nodes         []IdentityNode     `json:"nodes"`
	Workloads     []IdentityWorkload `json:"workloads"`
	RawHashes     map[string]string  `json:"raw_hashes"`
	Problems      []string           `json:"problems"`
	Hash          string             `json:"hash"`
}

// CollectIdentity is independent of Git or optimization authority. Only
// allowlisted identity/placement fields survive; environment/config/payload
// values from workload specifications are never retained.
func (r Reader) CollectIdentity(ctx context.Context, expectedUID string, bindings []IdentityWorkloadBinding) (IdentitySnapshot, error) {
	s := IdentitySnapshot{SchemaVersion: "1", CollectedAt: time.Now().UTC(), Nodes: []IdentityNode{}, Workloads: []IdentityWorkload{}, RawHashes: map[string]string{}, Problems: []string{}}
	if r.Now != nil {
		s.CollectedAt = r.Now().UTC()
	}
	if expectedUID == "" || len(bindings) > 64 {
		return s, errors.New("EKS_KUBERNETES_SCOPE_INVALID")
	}
	reads := 0
	read := func(key, path string) (Document, error) {
		reads++
		if reads > 512 {
			return nil, errors.New("EKS_KUBERNETES_READ_BOUND")
		}
		d, h, e := r.getDocument(ctx, path, true)
		if e == nil {
			s.RawHashes[key] = h
		}
		return d, e
	}
	list := func(key, path string) ([]any, error) {
		out := []any{}
		token := ""
		seen := map[string]bool{}
		for page := 0; page < 32; page++ {
			q := url.Values{"limit": {"500"}}
			if token != "" {
				q.Set("continue", token)
			}
			d, e := read(key+"/"+string(rune(page+'A')), path+"?"+q.Encode())
			if e != nil {
				return nil, e
			}
			rows, ok := d["items"].([]any)
			if !ok {
				return nil, errors.New("EKS_KUBERNETES_LIST_INVALID")
			}
			out = append(out, rows...)
			if len(out) > 10000 {
				return nil, errors.New("EKS_KUBERNETES_OBJECT_BOUND")
			}
			token = str(object(d["metadata"]), "continue")
			if token == "" {
				return out, nil
			}
			if len(token) > 4096 || seen[token] {
				return nil, errors.New("EKS_KUBERNETES_CURSOR_INVALID")
			}
			seen[token] = true
		}
		return nil, errors.New("EKS_KUBERNETES_PAGE_BOUND")
	}
	cluster, e := read("cluster", "/api/v1/namespaces/kube-system")
	if e != nil {
		return s, e
	}
	s.ClusterID = str(object(cluster["metadata"]), "uid")
	if s.ClusterID != expectedUID {
		return s, errors.New("EKS_KUBERNETES_CLUSTER_UID_CHANGED")
	}
	nodes, e := list("nodes", "/api/v1/nodes")
	if e != nil {
		return s, e
	}
	seenNodes := map[string]bool{}
	seenNodeUIDs := map[string]bool{}
	for _, item := range nodes {
		d := object(item)
		m, spec, status := object(d["metadata"]), object(d["spec"]), object(d["status"])
		labels := stringMap(m["labels"])
		n := IdentityNode{UID: str(m, "uid"), Name: str(m, "name"), ResourceVersion: str(m, "resourceVersion"), ProviderID: str(spec, "providerID"), Zone: labels["topology.kubernetes.io/zone"], ComputeType: labels["eks.amazonaws.com/compute-type"], Profile: labels["eks.amazonaws.com/fargate-profile"], Nodegroup: labels["eks.amazonaws.com/nodegroup"], Ready: condition(status, "Ready")}
		if n.UID == "" || n.Name == "" || seenNodes[n.Name] || seenNodeUIDs[n.UID] {
			return s, errors.New("EKS_KUBERNETES_NODE_IDENTITY_AMBIGUOUS")
		}
		seenNodes[n.Name] = true
		seenNodeUIDs[n.UID] = true
		s.Nodes = append(s.Nodes, n)
	}
	for _, binding := range bindings {
		w := IdentityWorkload{Binding: binding, Pods: []IdentityPod{}, Problems: []string{}}
		if !identityName(binding.Namespace) || !identityName(binding.Deployment) || binding.WorkloadID == "" || binding.NamespaceUID == "" || binding.DeploymentUID == "" {
			return s, errors.New("EKS_KUBERNETES_WORKLOAD_SCOPE_INVALID")
		}
		ns, e := read(binding.WorkloadID+"/namespace", "/api/v1/namespaces/"+binding.Namespace)
		if e != nil {
			w.Problems = append(w.Problems, identityReadReason(e))
			s.Workloads = append(s.Workloads, w)
			continue
		}
		w.NamespaceUID = str(object(ns["metadata"]), "uid")
		base := "/apis/apps/v1/namespaces/" + binding.Namespace
		deployment, e := read(binding.WorkloadID+"/deployment", base+"/deployments/"+binding.Deployment)
		if e != nil {
			w.Problems = append(w.Problems, identityReadReason(e))
			s.Workloads = append(s.Workloads, w)
			continue
		}
		w.DeploymentUID = str(object(deployment["metadata"]), "uid")
		if w.NamespaceUID != binding.NamespaceUID || w.DeploymentUID != binding.DeploymentUID {
			w.Problems = append(w.Problems, "EKS_KUBERNETES_WORKLOAD_UID_CHANGED")
			s.Workloads = append(s.Workloads, w)
			continue
		}
		sets, e := list(binding.WorkloadID+"/replicasets", base+"/replicasets")
		if e != nil {
			w.Problems = append(w.Problems, identityReadReason(e))
			s.Workloads = append(s.Workloads, w)
			continue
		}
		owners := map[string]bool{}
		for _, set := range sets {
			d := object(set)
			if ownedBy(d, binding.DeploymentUID, "Deployment") {
				owners[str(object(d["metadata"]), "uid")] = true
			}
		}
		pods, e := list(binding.WorkloadID+"/pods", "/api/v1/namespaces/"+binding.Namespace+"/pods")
		if e != nil {
			w.Problems = append(w.Problems, identityReadReason(e))
			s.Workloads = append(s.Workloads, w)
			continue
		}
		seen := map[string]bool{}
		for _, item := range pods {
			d := object(item)
			m, spec, status := object(d["metadata"]), object(d["spec"]), object(d["status"])
			ours := false
			for _, owner := range array(m["ownerReferences"]) {
				v := object(owner)
				if str(v, "kind") == "ReplicaSet" && owners[str(v, "uid")] && boolean(v, "controller") {
					ours = true
				}
			}
			if !ours {
				continue
			}
			labels := stringMap(m["labels"])
			if len(labels) > 128 {
				return s, errors.New("EKS_KUBERNETES_LABEL_BOUND")
			}
			for k, v := range labels {
				if len(k) > 256 || len(v) > 256 {
					return s, errors.New("EKS_KUBERNETES_LABEL_BOUND")
				}
			}
			p := IdentityPod{UID: str(m, "uid"), Name: str(m, "name"), ResourceVersion: str(m, "resourceVersion"), Node: str(spec, "nodeName"), Labels: labels, Scheduled: condition(status, "PodScheduled"), Phase: str(status, "phase")}
			for _, c := range array(status["containerStatuses"]) {
				if object(object(c)["state"])["running"] != nil {
					p.Running = true
				}
			}
			if p.UID == "" || seen[p.UID] {
				return s, errors.New("EKS_KUBERNETES_POD_IDENTITY_AMBIGUOUS")
			}
			seen[p.UID] = true
			w.Pods = append(w.Pods, p)
		}
		if len(w.Pods) == 0 {
			w.Problems = append(w.Problems, "EKS_KUBERNETES_WORKLOAD_PLACEMENT_UNOBSERVED")
		}
		s.Workloads = append(s.Workloads, w)
	}
	s.Hash = Hash(s)
	return s, nil
}
func identityName(value string) bool {
	if value == "" || len(value) > 63 {
		return false
	}
	for n, c := range value {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' && n > 0 && n < len(value)-1) {
			return false
		}
	}
	return true
}
func identityReadReason(e error) string {
	if strings.Contains(e.Error(), "STATUS_403") {
		return "EKS_KUBERNETES_READ_DENIED"
	}
	if strings.Contains(e.Error(), "STATUS_404") {
		return "EKS_KUBERNETES_OBJECT_ABSENT_AT_READ"
	}
	return "EKS_KUBERNETES_READ_UNAVAILABLE"
}
