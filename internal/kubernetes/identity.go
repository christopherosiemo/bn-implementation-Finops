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
	Architecture    string `json:"architecture,omitempty"`
	CPUAllocatableMilli    int64 `json:"cpu_allocatable_milli,omitempty"`
	MemoryAllocatableBytes int64 `json:"memory_allocatable_bytes,omitempty"`
	CapacityKnown   bool   `json:"capacity_known"`
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
	Terminating     bool              `json:"terminating"`
	Phase           string            `json:"phase"`
	CPURequestMilli int64             `json:"cpu_request_milli,omitempty"`
	MemoryRequestBytes int64          `json:"memory_request_bytes,omitempty"`
	CPULimitMilli int64               `json:"cpu_limit_milli,omitempty"`
	MemoryLimitBytes int64            `json:"memory_limit_bytes,omitempty"`
	ResourceRequestsKnown bool        `json:"resource_requests_known"`
	ResourceLimitsKnown bool          `json:"resource_limits_known"`
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
		allocatable := object(status["allocatable"])
		cpu, cpuErr := CPUQuantity(str(allocatable, "cpu"))
		memory, memoryErr := MemoryQuantity(str(allocatable, "memory"))
		n := IdentityNode{UID: str(m, "uid"), Name: str(m, "name"), ResourceVersion: str(m, "resourceVersion"), ProviderID: str(spec, "providerID"), Zone: labels["topology.kubernetes.io/zone"], Architecture: labels["kubernetes.io/arch"], CPUAllocatableMilli: cpu, MemoryAllocatableBytes: memory, CapacityKnown: cpuErr == nil && memoryErr == nil, ComputeType: labels["eks.amazonaws.com/compute-type"], Profile: labels["eks.amazonaws.com/fargate-profile"], Nodegroup: labels["eks.amazonaws.com/nodegroup"], Ready: condition(status, "Ready")}
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
			cpuRequest, memoryRequest, cpuLimit, memoryLimit, requestsKnown, limitsKnown := podResourceProfile(spec)
			p := IdentityPod{UID: str(m, "uid"), Name: str(m, "name"), ResourceVersion: str(m, "resourceVersion"), Node: str(spec, "nodeName"), Labels: labels, Scheduled: condition(status, "PodScheduled"), Terminating: str(m, "deletionTimestamp") != "", Phase: str(status, "phase"), CPURequestMilli: cpuRequest, MemoryRequestBytes: memoryRequest, CPULimitMilli: cpuLimit, MemoryLimitBytes: memoryLimit, ResourceRequestsKnown: requestsKnown, ResourceLimitsKnown: limitsKnown}
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

// podResourceProfile retains only bounded resource quantities. The aggregate is
// marked unknown when init-container or pod-overhead semantics would make a
// regular-container sum an incomplete scheduling request.
func podResourceProfile(spec Document) (int64, int64, int64, int64, bool, bool) {
	containers := array(spec["containers"])
	if len(containers) == 0 || len(containers) > 256 || len(array(spec["initContainers"])) != 0 || len(object(spec["overhead"])) != 0 {
		return 0, 0, 0, 0, false, false
	}
	var cpuRequest, memoryRequest, cpuLimit, memoryLimit int64
	requestsKnown, limitsKnown := true, true
	for _, raw := range containers {
		container := object(raw)
		resources := object(container["resources"])
		requests, limits := object(resources["requests"]), object(resources["limits"])
		cpu, cpuErr := CPUQuantity(str(requests, "cpu"))
		memory, memoryErr := MemoryQuantity(str(requests, "memory"))
		if cpuErr != nil || memoryErr != nil || cpu < 0 || memory < 0 || cpuRequest > int64(^uint64(0)>>1)-cpu || memoryRequest > int64(^uint64(0)>>1)-memory {
			requestsKnown = false
		} else {
			cpuRequest += cpu
			memoryRequest += memory
		}
		if value := str(limits, "cpu"); value != "" {
			parsed, err := CPUQuantity(value)
			if err != nil || parsed < 0 || cpuLimit > int64(^uint64(0)>>1)-parsed {
				limitsKnown = false
			} else {
				cpuLimit += parsed
			}
		} else {
			limitsKnown = false
		}
		if value := str(limits, "memory"); value != "" {
			parsed, err := MemoryQuantity(value)
			if err != nil || parsed < 0 || memoryLimit > int64(^uint64(0)>>1)-parsed {
				limitsKnown = false
			} else {
				memoryLimit += parsed
			}
		} else {
			limitsKnown = false
		}
	}
	return cpuRequest, memoryRequest, cpuLimit, memoryLimit, requestsKnown, limitsKnown
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
