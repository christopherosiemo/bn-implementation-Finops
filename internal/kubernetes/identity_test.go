package kubernetes

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func identityTestReader(t *testing.T, deny bool) (Reader, *bool) {
	t.Helper()
	mutated := false
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.Header.Get("Authorization") != "Bearer readonly" {
			mutated = true
		}
		var d Document
		switch r.URL.Path {
		case "/api/v1/namespaces/kube-system":
			d = Document{"metadata": Document{"uid": "cluster-uid"}}
		case "/api/v1/nodes":
			if r.URL.Query().Get("continue") == "next" {
				d = Document{"items": []any{Document{"metadata": Document{"uid": "other-node", "name": "other"}}}}
			} else {
				d = Document{"metadata": Document{"continue": "next"}, "items": []any{Document{"metadata": Document{"uid": "node-uid", "name": "worker", "labels": Document{"topology.kubernetes.io/zone": "eu-west-1a", "kubernetes.io/arch": "amd64"}}, "spec": Document{"providerID": "aws:///eu-west-1a/i-0123456789abcdef0"}, "status": Document{"allocatable": Document{"cpu": "4", "memory": "8Gi"}, "conditions": []any{Document{"type": "Ready", "status": "True"}}}}}}
			}
		case "/api/v1/namespaces/apps":
			d = Document{"metadata": Document{"uid": "namespace-uid"}}
		case "/apis/apps/v1/namespaces/apps/deployments/web":
			if deny {
				w.WriteHeader(403)
				return
			}
			d = Document{"metadata": Document{"uid": "deployment-uid"}, "spec": Document{"template": Document{"spec": Document{"containers": []any{Document{"env": []any{Document{"value": "NEVER_RETAIN_APPLICATION_SECRET"}}}}}}}}
		case "/apis/apps/v1/namespaces/apps/replicasets":
			d = Document{"items": []any{Document{"metadata": Document{"uid": "rs-uid", "ownerReferences": []any{Document{"kind": "Deployment", "uid": "deployment-uid", "controller": true}}}}}}
		case "/api/v1/namespaces/apps/pods":
			d = Document{"items": []any{Document{"metadata": Document{"uid": "pod-uid", "name": "pod", "ownerReferences": []any{Document{"kind": "ReplicaSet", "uid": "rs-uid", "controller": true}}}, "spec": Document{"nodeName": "worker", "containers": []any{Document{"env": []any{Document{"value": "NEVER_RETAIN_APPLICATION_SECRET"}}, "resources": Document{"requests": Document{"cpu": "250m", "memory": "128Mi"}, "limits": Document{"cpu": "1", "memory": "512Mi"}}}}}, "status": Document{"phase": "Running", "conditions": []any{Document{"type": "PodScheduled", "status": "True"}}, "containerStatuses": []any{Document{"state": Document{"running": Document{"startedAt": "2026-10-20T12:00:00Z"}}}}}}, Document{"metadata": Document{"uid": "unrelated", "ownerReferences": []any{Document{"kind": "ReplicaSet", "uid": "foreign-rs", "controller": true}}}}}}
		default:
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(d)
	}))
	t.Cleanup(server.Close)
	return Reader{URL: server.URL, Token: "readonly", Client: server.Client()}, &mutated
}
func TestEKSIdentityReaderUsesObservedUIDOwnershipPaginationAndSecretMinimization(t *testing.T) {
	r, mutated := identityTestReader(t, false)
	s, e := r.CollectIdentity(context.Background(), "cluster-uid", []IdentityWorkloadBinding{{WorkloadID: "web", Namespace: "apps", NamespaceUID: "namespace-uid", Deployment: "web", DeploymentUID: "deployment-uid"}})
	if e != nil {
		t.Fatal(e)
	}
	if *mutated || len(s.Nodes) != 2 || !s.Nodes[0].CapacityKnown || s.Nodes[0].CPUAllocatableMilli != 4000 || s.Nodes[0].MemoryAllocatableBytes != 8*1024*1024*1024 || s.Nodes[0].Architecture != "amd64" || len(s.Workloads) != 1 || len(s.Workloads[0].Pods) != 1 || !s.Workloads[0].Pods[0].Scheduled || !s.Workloads[0].Pods[0].Running || !s.Workloads[0].Pods[0].ResourceRequestsKnown || s.Workloads[0].Pods[0].CPURequestMilli != 250 || s.Workloads[0].Pods[0].MemoryRequestBytes != 128*1024*1024 || s.Workloads[0].Pods[0].CPULimitMilli != 1000 || s.Workloads[0].Pods[0].MemoryLimitBytes != 512*1024*1024 || len(s.RawHashes) != 7 {
		t.Fatalf("observed identity incomplete: %+v", s)
	}
	raw, _ := json.Marshal(s)
	if strings.Contains(string(raw), "NEVER_RETAIN") {
		t.Fatal("application configuration retained")
	}
}
func TestEKSIdentityReaderRejectsReplacementClusterAndWorkload(t *testing.T) {
	r, _ := identityTestReader(t, false)
	if _, e := r.CollectIdentity(context.Background(), "other-cluster", nil); e == nil {
		t.Fatal("cluster replacement accepted")
	}
	s, e := r.CollectIdentity(context.Background(), "cluster-uid", []IdentityWorkloadBinding{{WorkloadID: "web", Namespace: "apps", NamespaceUID: "other-namespace", Deployment: "web", DeploymentUID: "deployment-uid"}})
	if e != nil || len(s.Workloads) != 1 || len(s.Workloads[0].Pods) != 0 || !contains(s.Workloads[0].Problems, "EKS_KUBERNETES_WORKLOAD_UID_CHANGED") {
		t.Fatalf("workload replacement not blocked: %v %+v", e, s)
	}
}
func TestEKSIdentityReaderDenialIsNotAbsence(t *testing.T) {
	r, _ := identityTestReader(t, true)
	s, e := r.CollectIdentity(context.Background(), "cluster-uid", []IdentityWorkloadBinding{{WorkloadID: "web", Namespace: "apps", NamespaceUID: "namespace-uid", Deployment: "web", DeploymentUID: "deployment-uid"}})
	if e != nil || !contains(s.Workloads[0].Problems, "EKS_KUBERNETES_READ_DENIED") {
		t.Fatalf("denial hidden: %v %+v", e, s)
	}
}
