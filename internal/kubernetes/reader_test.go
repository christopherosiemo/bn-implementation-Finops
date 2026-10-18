package kubernetes

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestReadOnlyReaderPinnedNativeUIDsAndAllSafetyEndpoints(t *testing.T) {
	in := testInput(t)
	b := in.Snapshot.Binding
	seen := map[string]bool{}
	mutated := false
	docs := map[string]Document{
		"/api/v1/namespaces/kube-system":                                           {"metadata": Document{"uid": b.ClusterID}},
		"/api/v1/namespaces/" + b.Namespace:                                        {"metadata": Document{"uid": b.NamespaceUID, "labels": Document{"finops.autopilot/environment": "NON_PRODUCTION", "finops.autopilot/owner": b.Owner}}},
		"/apis/apps/v1/namespaces/" + b.Namespace + "/deployments/" + b.Deployment: {"metadata": Document{"uid": b.DeploymentUID, "name": b.Deployment, "generation": 2, "resourceVersion": "7"}, "spec": in.Snapshot.Deployment.Spec, "status": Document{"observedGeneration": 2, "readyReplicas": 2, "updatedReplicas": 2}},
		"/api/v1/nodes": {"items": []any{Document{"metadata": Document{"uid": "node-a", "name": "node-a", "labels": Document{"topology.kubernetes.io/zone": "a"}}, "spec": Document{}, "status": Document{"allocatable": Document{"cpu": "4", "memory": "8Gi"}, "conditions": []any{Document{"type": "Ready", "status": "True"}}}}}},
		"/apis/apps/v1/namespaces/" + b.Namespace + "/replicasets":                     {"items": []any{Document{"metadata": Document{"uid": "rs-a", "ownerReferences": []any{Document{"uid": b.DeploymentUID, "kind": "Deployment", "controller": true}}}}}},
		"/api/v1/namespaces/" + b.Namespace + "/pods":                                  {"items": []any{Document{"metadata": Document{"uid": "pod-a", "ownerReferences": []any{Document{"uid": "rs-a", "kind": "ReplicaSet", "controller": true}}}, "spec": Document{"nodeName": "node-a"}, "status": Document{"conditions": []any{Document{"type": "Ready", "status": "True"}}}}, Document{"metadata": Document{"uid": "unrelated", "ownerReferences": []any{Document{"uid": "unrelated-rs", "kind": "ReplicaSet", "controller": true}}}}}},
		"/apis/policy/v1/namespaces/" + b.Namespace + "/poddisruptionbudgets":          {"items": []any{Document{"metadata": Document{"uid": "pdb", "name": "gateway", "generation": 1}, "spec": Document{"selector": Document{"matchLabels": Document{"app": "gateway"}}}, "status": Document{"observedGeneration": 1, "disruptionsAllowed": 0, "currentHealthy": 2, "desiredHealthy": 2}}}},
		"/apis/autoscaling/v2/namespaces/" + b.Namespace + "/horizontalpodautoscalers": {"items": []any{}},
		"/apis/apiextensions.k8s.io/v1/customresourcedefinitions":                      {"items": []any{}},
		"/apis/apps/v1/namespaces/kube-system/deployments":                             {"items": []any{}},
		"/api/v1/namespaces/" + b.Namespace + "/configmaps/" + b.Git.ControllerName:    {"metadata": Document{"name": b.Git.ControllerName}, "data": Document{"engine": b.Git.Engine, "repository": b.Git.Repository, "path": b.Git.Path, "revision": in.ExpectedGitRevision, "synced": "true", "ready": "true", "observed_at": in.Now.Format("2006-01-02T15:04:05Z07:00"), "deployment_spec_hash": in.Snapshot.Deployment.SpecHash}},
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			mutated = true
		}
		if r.Header.Get("Authorization") != "Bearer readonly-token" {
			t.Error("identity missing")
		}
		if r.Header.Get("Accept-Encoding") != "identity" {
			t.Error("wire archive encoding changed")
		}
		seen[r.URL.Path] = true
		doc, ok := docs[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(doc)
	}))
	defer server.Close()
	r := Reader{URL: server.URL, Token: "readonly-token", Client: server.Client(), Now: func() time.Time { return in.Now }}
	s, err := r.Collect(context.Background(), b)
	if err != nil {
		t.Fatal(err)
	}
	if mutated || len(seen) != len(docs) || len(s.Pods) != 1 || s.PDBs[0].DisruptionsAllowed != 0 || s.Nodes[0].CPUAllocatableMilli != 4000 || s.Hash != SnapshotHash(s) {
		t.Fatalf("native projection invalid: %+v", s)
	}
	changed := b
	changed.ClusterID = "other"
	s, err = r.Collect(context.Background(), changed)
	if err != nil || !contains(s.Problems, "K8S_IDENTITY_CHANGED") {
		t.Fatal("cluster replacement silently rebound")
	}
}
func TestRedirectNeverForwardsReadCredential(t *testing.T) {
	forwarded := false
	target := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { forwarded = true }))
	defer target.Close()
	source := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer source.Close()
	r := Reader{URL: source.URL, Token: "never-forward", Client: source.Client()}
	_, _, err := r.get(context.Background(), "/api/v1/nodes")
	if err == nil || forwarded || !strings.Contains(err.Error(), "307") {
		t.Fatalf("redirect accepted: %v", err)
	}
}
func TestSelectorPolicyV1EmptyMatchesAllAndUnsupportedBlocks(t *testing.T) {
	if match, known := selectorMatches(Document{}, map[string]string{"app": "gateway"}); !match || !known {
		t.Fatal("policy/v1 empty selector must match all")
	}
	if _, known := selectorMatches(Document{"matchExpressions": []any{Document{"key": "app", "operator": "future"}}}, nil); known {
		t.Fatal("unknown selector operator accepted")
	}
}
