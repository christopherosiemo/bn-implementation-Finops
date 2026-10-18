package kubernetes

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func testInput(t *testing.T) Input {
	t.Helper()
	now := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	raw := `{"metadata":{"uid":"deployment-1","name":"gateway","generation":2},"spec":{"replicas":2,"selector":{"matchLabels":{"app":"gateway"}},"strategy":{"type":"RollingUpdate","rollingUpdate":{"maxUnavailable":0,"maxSurge":1}},"template":{"metadata":{"labels":{"app":"gateway"}},"spec":{"containers":[{"name":"gateway","image":"python:3.13-slim","resources":{"requests":{"cpu":"50m","memory":"128Mi"},"limits":{"cpu":"250m","memory":"256Mi"}},"readinessProbe":{"httpGet":{"path":"/healthz","port":8096}}}],"topologySpreadConstraints":[{"maxSkew":1,"topologyKey":"topology.kubernetes.io/zone","whenUnsatisfiable":"DoNotSchedule","labelSelector":{"matchLabels":{"app":"gateway"}}}]} }},"status":{"observedGeneration":2,"readyReplicas":2,"updatedReplicas":2}}`
	var doc Document
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		t.Fatal(err)
	}
	d, err := ParseDeployment(doc)
	if err != nil {
		t.Fatal(err)
	}
	b := Binding{TenantID: "tenant-test", WorkloadID: "workload-test", Provider: "LOCAL_KIND", ClusterID: "cluster-1", Namespace: "finops-k8s-lab", NamespaceUID: "namespace-1", Deployment: "gateway", DeploymentUID: "deployment-1", Owner: "lab-operator", Git: GitBinding{Engine: "LOCAL_GITOPS_TEST_DOUBLE", Repository: "local:lab", Path: "deployment.json", ControllerNamespace: "finops-k8s-lab", ControllerName: "gitops-ack"}}
	s := Snapshot{SchemaVersion: "1", Binding: b, CollectedAt: now, ClusterID: b.ClusterID, NamespaceUID: b.NamespaceUID, Environment: "NON_PRODUCTION", Owner: b.Owner, Deployment: d, Pods: []Pod{{UID: "pod-a", Node: "node-a", Zone: "a", Ready: true}, {UID: "pod-b", Node: "node-b", Zone: "b", Ready: true}}, PDBs: []PDB{{UID: "pdb-1", Name: "gateway", Generation: 1, ObservedGeneration: 1, Matches: true, SelectorKnown: true, DisruptionsAllowed: 1, CurrentHealthy: 2, DesiredHealthy: 1}}, AutoscalerDiscoveryComplete: true, Git: GitObservation{Engine: b.Git.Engine, Repository: b.Git.Repository, Path: b.Git.Path, Revision: strings.Repeat("a", 40), Ready: true, Synced: true, ObservedAt: now, DeploymentSpecHash: d.SpecHash}, RawHashes: map[string]string{"a": "1", "b": "2", "c": "3", "d": "4", "e": "5"}, Problems: []string{}}
	s.Hash = SnapshotHash(s)
	return Input{Now: now, Snapshot: s, ExpectedGitRevision: s.Git.Revision, Change: Change{Container: "gateway", CPURequestMilli: 50, MemoryRequestBytes: 160 << 20}, Policy: Policy{MinimumReplicas: 2, MaintenanceStart: now.Add(-time.Minute), MaintenanceEnd: now.Add(time.Hour), RolloutBudgetSeconds: 60}}
}
func TestGitProposalHasExactIdentityAndPreservesOtherFields(t *testing.T) {
	in := testInput(t)
	p := Assess(in)
	if p.Status != "READY_FOR_GIT_PROPOSAL" {
		t.Fatalf("blocked: %v", p.ReasonCodes)
	}
	if p.DesiredSpecHash == p.BeforeSpecHash || p.SnapshotHash != in.Snapshot.Hash || p.FinancialStatus == "VERIFIED" {
		t.Fatal("missing bound proposal or invented financial result")
	}
	current := clone(in.Snapshot.Deployment.Spec)
	desired := clone(p.DesiredSpec)
	for _, d := range []Document{current, desired} {
		c := object(array(object(object(d["template"])["spec"])["containers"])[0])
		delete(object(c["resources"]), "requests")
	}
	if Hash(current) != Hash(desired) {
		t.Fatal("unrelated spec change")
	}
	after := in.Snapshot
	after.Deployment.Spec = p.DesiredSpec
	after.Deployment.SpecHash = p.DesiredSpecHash
	after.Git.DeploymentSpecHash = p.DesiredSpecHash
	after.Git.Revision = strings.Repeat("b", 40)
	after.Hash = SnapshotHash(after)
	if err := VerifySync(p, after, after.Git.Revision, in.Now); err != nil {
		t.Fatal(err)
	}
	after.Git.Revision = in.ExpectedGitRevision
	after.Hash = SnapshotHash(after)
	if VerifySync(p, after, strings.Repeat("b", 40), in.Now) == nil {
		t.Fatal("stale Git ack accepted")
	}
	after.Git.Revision = strings.Repeat("b", 40)
	after.Deployment.SpecHash = p.BeforeSpecHash
	after.Hash = SnapshotHash(after)
	if VerifySync(p, after, after.Git.Revision, in.Now) == nil {
		t.Fatal("live drift accepted")
	}
}
func TestPostRolloutChangesCannotInheritCompletedHealth(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*Snapshot)
	}{
		{"production", func(s *Snapshot) { s.Environment = "PRODUCTION" }},
		{"owner", func(s *Snapshot) { s.Owner = "different-owner" }},
		{"stale-controller-generation", func(s *Snapshot) { s.Git.Generation = 2; s.Git.ObservedGeneration = 1 }},
		{"deleting", func(s *Snapshot) { s.Deployment.Deleting = true }},
		{"paused", func(s *Snapshot) { s.Deployment.Paused = true }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := testInput(t)
			p := Assess(in)
			s := in.Snapshot
			s.Deployment.Spec = p.DesiredSpec
			s.Deployment.SpecHash = p.DesiredSpecHash
			s.Git.DeploymentSpecHash = p.DesiredSpecHash
			s.Git.Revision = strings.Repeat("b", 40)
			s.Hash = SnapshotHash(s)
			if err := VerifySync(p, s, s.Git.Revision, in.Now); err != nil {
				t.Fatal(err)
			}
			tc.change(&s)
			s.Hash = SnapshotHash(s)
			if VerifySync(p, s, s.Git.Revision, in.Now) == nil {
				t.Fatal("changed post-rollout authority/health accepted")
			}
		})
	}
}

func TestHardSafetyGuardsBlockIndependently(t *testing.T) {
	tests := []struct {
		name, reason string
		change       func(*Input)
	}{
		{"pdbzero", "K8S_PDB_BLOCKS_DISRUPTION", func(i *Input) { i.Snapshot.PDBs[0].DisruptionsAllowed = 0 }},
		{"pdbstale", "K8S_PDB_BLOCKS_DISRUPTION", func(i *Input) { i.Snapshot.PDBs[0].ObservedGeneration = 0 }},
		{"pdbmissing", "K8S_PDB_REQUIRED", func(i *Input) { i.Snapshot.PDBs = nil }},
		{"notready", "K8S_WORKLOAD_NOT_STABLE", func(i *Input) { i.Snapshot.Deployment.ReadyReplicas = 1 }},
		{"mintwo", "K8S_MINIMUM_REPLICAS_VIOLATION", func(i *Input) { i.Policy.MinimumReplicas = 3 }},
		{"topology", "K8S_READY_TOPOLOGY_INSUFFICIENT", func(i *Input) { i.Snapshot.Pods[1].Zone = "a" }},
		{"vpa", "K8S_VPA_OWNS_REQUESTS", func(i *Input) { i.Snapshot.VPAs = []VPA{{Name: "vpa", Mode: "Auto"}} }},
		{"hpa", "K8S_HPA_COUPLED_SIMULATION_REQUIRED", func(i *Input) {
			i.Snapshot.HPAs = []HPA{{Name: "hpa", MinReplicas: 2, MaxReplicas: 6, MetricsKnown: true, UtilizationResources: []string{"memory"}}}
		}},
		{"autoscaler", "K8S_NODE_AUTOSCALER_COORDINATION_REQUIRED", func(i *Input) { i.Snapshot.NodeAutoscalers = []string{"KARPENTER"} }},
		{"unknown", "K8S_AUTOSCALER_AUTHORITY_UNKNOWN", func(i *Input) { i.Snapshot.AutoscalerDiscoveryComplete = false }},
		{"gitrevision", "K8S_GIT_REVISION_NOT_ACKNOWLEDGED", func(i *Input) { i.ExpectedGitRevision = strings.Repeat("b", 40) }},
		{"identity", "K8S_IDENTITY_CHANGED", func(i *Input) { i.Snapshot.NamespaceUID = "different" }},
		{"prod", "K8S_CLASSIFICATION_OR_OWNER_UNKNOWN", func(i *Input) { i.Snapshot.Environment = "PRODUCTION" }},
		{"stale", "K8S_SNAPSHOT_STALE", func(i *Input) { i.Snapshot.CollectedAt = i.Now.Add(-3 * time.Minute) }},
		{"maintenance", "K8S_MAINTENANCE_AND_ROLLBACK_WINDOW_REQUIRED", func(i *Input) { i.Policy.MaintenanceEnd = i.Now.Add(time.Minute) }},
		{"capacity", "K8S_NATIVE_CAPACITY_ASSESSMENT_REQUIRED", func(i *Input) { i.Change.MemoryRequestBytes = 64 << 20 }},
		{"restarts", "K8S_RECOVERY_OR_OOM_EVIDENCE_REQUIRES_REVIEW", func(i *Input) { i.Snapshot.Pods[0].Restarts = 1 }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			in := testInput(t)
			tc.change(&in)
			in.Snapshot.Hash = SnapshotHash(in.Snapshot)
			p := Assess(in)
			if p.Status != "BLOCKED" || !contains(p.ReasonCodes, tc.reason) {
				t.Fatalf("%s: %+v", tc.reason, p)
			}
		})
	}
}
func TestEquivalentQuantitiesOnlyNormalizeSameSpec(t *testing.T) {
	in := testInput(t)
	d := clone(in.Snapshot.Deployment.Spec)
	c := object(array(object(object(d["template"])["spec"])["containers"])[0])
	r := object(object(c["resources"])["requests"])
	r["cpu"] = "0.05"
	r["memory"] = "134217728"
	if SpecHash(d) != in.Snapshot.Deployment.SpecHash {
		t.Fatal("equivalent API quantity serialization changes authority")
	}
	object(c["readinessProbe"])["httpGet"] = Document{"path": "/bad", "port": 8096}
	if SpecHash(d) == in.Snapshot.Deployment.SpecHash {
		t.Fatal("health change hidden")
	}
}
func TestHPARequestDenominatorAndRoundingCanIncreaseTotal(t *testing.T) {
	r, err := SimulateHPA(HPAInput{Replicas: 2, OldRequestMilli: 1000, NewRequestMilli: 700, ObservedUsageMilli: 490, TargetUtilizationPercent: 50, MinReplicas: 2, MaxReplicas: 10})
	if err != nil {
		t.Fatal(err)
	}
	if r.PredictedReplicas != 3 || r.PredictedRequestedMilli != 2100 || r.OldRequestedMilli != 2000 || r.ReasonCode != "K8S_HPA_TOTAL_REQUESTS_INCREASE" {
		t.Fatalf("incorrect coupled result: %+v", r)
	}
}
func TestQuantityNoFloatOrUnsupportedPrecision(t *testing.T) {
	for _, tc := range []struct {
		s string
		n int64
	}{{"100m", 100}, {"0.25", 250}, {"200000000n", 200}} {
		n, e := CPUQuantity(tc.s)
		if e != nil || n != tc.n {
			t.Fatalf("%s => %d %v", tc.s, n, e)
		}
	}
	if _, e := CPUQuantity("1n"); e == nil {
		t.Fatal("sub-millicore precision silently rounded")
	}
	if _, e := MemoryQuantity("1e9"); e == nil {
		t.Fatal("unsupported spelling silently coerced")
	}
	if _, e := MemoryQuantity("999999999999999999999Gi"); e == nil {
		t.Fatal("overflow accepted")
	}
}

func TestPreApplyRecheckRejectsLaterPDBAndExpiredAuthority(t *testing.T) {
	in := testInput(t)
	p := Assess(in)
	if err := Revalidate(p, in.Snapshot, in.Now); err != nil {
		t.Fatal(err)
	}
	s := in.Snapshot
	s.PDBs = append([]PDB{}, s.PDBs...)
	s.PDBs[0].DisruptionsAllowed = 0
	s.Hash = SnapshotHash(s)
	if err := Revalidate(p, s, in.Now); err == nil || err.Error() != "K8S_PDB_BLOCKS_DISRUPTION" {
		t.Fatalf("later PDB lost: %v", err)
	}
	if Revalidate(p, in.Snapshot, in.Now.Add(3*time.Minute)) == nil {
		t.Fatal("expired proposal authority accepted")
	}
}
func contains(xs []string, v string) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}
