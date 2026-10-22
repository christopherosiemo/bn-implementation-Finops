package kubernetes

import (
	"encoding/json"
	"errors"
	"math/big"
	"time"
)

// Assess creates a reviewable Git proposal, never a direct Kubernetes write.
// Historical capacity evidence and monetary attribution remain separate gates.
func Assess(in Input) Plan {
	s, d := in.Snapshot, in.Snapshot.Deployment
	p := Plan{SchemaVersion: "1", Status: "BLOCKED", Binding: s.Binding, SnapshotHash: SnapshotHash(s), BeforeSpecHash: d.SpecHash, BaseGitRevision: in.ExpectedGitRevision, Change: in.Change, MinimumReplicas: in.Policy.MinimumReplicas, Policy: in.Policy, FinancialStatus: "UNAVAILABLE_NODE_COST_AND_REALISATION_EVIDENCE_REQUIRED", ReasonCodes: []string{}}
	add := func(x string) { p.ReasonCodes = append(p.ReasonCodes, x) }
	if err := ValidateBinding(s.Binding); err != nil {
		add(err.Error())
	}
	if s.SchemaVersion != "1" || s.Hash == "" || s.Hash != SnapshotHash(s) {
		add("K8S_SNAPSHOT_HASH_INVALID")
	}
	if s.CollectedAt.IsZero() || s.CollectedAt.After(in.Now.Add(5*time.Second)) || in.Now.Sub(s.CollectedAt) > 2*time.Minute {
		add("K8S_SNAPSHOT_STALE")
	}
	if s.ClusterID != s.Binding.ClusterID || s.NamespaceUID != s.Binding.NamespaceUID || d.UID != s.Binding.DeploymentUID || d.Name != s.Binding.Deployment {
		add("K8S_IDENTITY_CHANGED")
	}
	if s.Environment != "NON_PRODUCTION" || s.Owner == "" || s.Owner != s.Binding.Owner {
		add("K8S_CLASSIFICATION_OR_OWNER_UNKNOWN")
	}
	for _, x := range s.Problems {
		add(x)
	}
	if len(s.RawHashes) < 5 {
		add("K8S_RAW_EVIDENCE_INCOMPLETE")
	}
	if d.SpecHash == "" || d.SpecHash != SpecHash(d.Spec) {
		add("K8S_SPEC_HASH_INVALID")
	}
	if d.Paused || d.Deleting || d.ObservedGeneration < d.Generation || d.Replicas < 2 || d.ReadyReplicas != d.Replicas || d.UpdatedReplicas != d.Replicas || d.UnavailableReplicas != 0 {
		add("K8S_WORKLOAD_NOT_STABLE")
	}
	if in.Policy.MinimumReplicas < 2 || d.Replicas < in.Policy.MinimumReplicas {
		add("K8S_MINIMUM_REPLICAS_VIOLATION")
	}
	if d.Strategy != "RollingUpdate" || !d.MaxUnavailableZero || !d.MaxSurgeOne {
		add("K8S_ROLLOUT_STRATEGY_UNSAFE")
	}
	if !d.ZoneSpread {
		add("K8S_TOPOLOGY_GUARD_MISSING")
	}
	zones := map[string]bool{}
	ready := int64(0)
	for _, pod := range s.Pods {
		if pod.Ready && !pod.Terminating {
			ready++
			if pod.Zone != "" {
				zones[pod.Zone] = true
			}
		}
		if pod.OOMKilled || pod.Restarts > 0 {
			add("K8S_RECOVERY_OR_OOM_EVIDENCE_REQUIRES_REVIEW")
		}
	}
	if ready < d.Replicas || len(zones) < 2 {
		add("K8S_READY_TOPOLOGY_INSUFFICIENT")
	}
	matched := 0
	for _, b := range s.PDBs {
		if !b.SelectorKnown {
			add("K8S_PDB_SELECTOR_UNKNOWN")
		}
		if b.Matches {
			matched++
			if b.ObservedGeneration < b.Generation || b.DisruptionsAllowed < 1 || b.CurrentHealthy < b.DesiredHealthy {
				add("K8S_PDB_BLOCKS_DISRUPTION")
			}
		}
	}
	if matched == 0 {
		add("K8S_PDB_REQUIRED")
	}
	if !s.AutoscalerDiscoveryComplete {
		add("K8S_AUTOSCALER_AUTHORITY_UNKNOWN")
	}
	if len(s.NodeAutoscalers) > 0 {
		add("K8S_NODE_AUTOSCALER_COORDINATION_REQUIRED")
	}
	for _, v := range s.VPAs {
		if v.Mode != "Off" {
			add("K8S_VPA_OWNS_REQUESTS")
		}
	}
	found := false
	for _, c := range d.Containers {
		if !c.ReadinessProbe {
			add("K8S_READINESS_PROBE_REQUIRED")
		}
		if c.Name != in.Change.Container {
			continue
		}
		found = true
		if in.Change.CPURequestMilli <= 0 || in.Change.MemoryRequestBytes <= 0 {
			add("K8S_REQUEST_INVALID")
		}
		if c.CPURequestMilli <= 0 || c.MemoryRequestBytes <= 0 {
			add("K8S_EXISTING_REQUEST_UNKNOWN")
		}
		if (c.CPULimitMilli > 0 && in.Change.CPURequestMilli > c.CPULimitMilli) || (c.MemoryLimitBytes > 0 && in.Change.MemoryRequestBytes > c.MemoryLimitBytes) {
			add("K8S_REQUEST_EXCEEDS_LIMIT")
		}
		for _, h := range s.HPAs {
			if !h.MetricsKnown {
				add("K8S_HPA_METRICS_UNKNOWN")
			}
			for _, r := range h.UtilizationResources {
				if (r == "cpu" && in.Change.CPURequestMilli != c.CPURequestMilli) || (r == "memory" && in.Change.MemoryRequestBytes != c.MemoryRequestBytes) {
					add("K8S_HPA_COUPLED_SIMULATION_REQUIRED")
				}
			}
			if h.MinReplicas < in.Policy.MinimumReplicas {
				add("K8S_HPA_MINIMUM_REPLICAS_VIOLATION")
			}
		}
		// Reductions require the native history/capacity broker, which is not
		// silently substituted with Kubernetes requests or current usage.
		if in.Change.CPURequestMilli < c.CPURequestMilli || in.Change.MemoryRequestBytes < c.MemoryRequestBytes {
			add("K8S_NATIVE_CAPACITY_ASSESSMENT_REQUIRED")
		}
	}
	if !found {
		add("K8S_CONTAINER_NOT_FOUND")
	}
	if in.Policy.RolloutBudgetSeconds < 15 || in.Policy.RolloutBudgetSeconds > 1800 || in.Policy.MaintenanceStart.After(in.Now) || !in.Policy.MaintenanceEnd.After(in.Now.Add(time.Duration(in.Policy.RolloutBudgetSeconds)*time.Second*2)) {
		add("K8S_MAINTENANCE_AND_ROLLBACK_WINDOW_REQUIRED")
	}
	p.ExpiresAt = in.Now.Add(2 * time.Minute)
	if in.Policy.MaintenanceEnd.Before(p.ExpiresAt) {
		p.ExpiresAt = in.Policy.MaintenanceEnd
	}
	if !revisionPattern.MatchString(in.ExpectedGitRevision) || s.Git.Revision != in.ExpectedGitRevision || s.Git.Engine != s.Binding.Git.Engine || s.Git.Repository != s.Binding.Git.Repository || s.Git.Path != s.Binding.Git.Path || !s.Git.Ready || !s.Git.Synced || s.Git.ObservedGeneration < s.Git.Generation || s.Git.ObservedAt.After(in.Now.Add(5*time.Second)) || in.Now.Sub(s.Git.ObservedAt) > 2*time.Minute {
		add("K8S_GIT_REVISION_NOT_ACKNOWLEDGED")
	}
	if s.Git.DeploymentSpecHash != "" && s.Git.DeploymentSpecHash != d.SpecHash {
		add("K8S_GIT_LIVE_DRIFT")
	}
	// A live controller's native health/revision is collected, but a complete
	// Git rendered-spec proof has not yet been commissioned outside this lab.
	if s.Binding.Provider != "LOCAL_KIND" {
		add("K8S_HOSTED_GIT_RENDERED_SPEC_PROOF_REQUIRED")
	}
	if len(p.ReasonCodes) == 0 {
		p.DesiredSpec = clone(d.Spec)
		cs := array(object(object(p.DesiredSpec["template"])["spec"])["containers"])
		changed := false
		for _, x := range cs {
			c := object(x)
			if str(c, "name") == in.Change.Container {
				res := object(c["resources"])
				requests := object(res["requests"])
				requests["cpu"] = formatMilli(in.Change.CPURequestMilli)
				requests["memory"] = formatBytes(in.Change.MemoryRequestBytes)
				res["requests"] = requests
				c["resources"] = res
				changed = true
			}
		}
		if !changed {
			add("K8S_SPEC_CONTAINER_MISSING")
		} else {
			p.DesiredSpecHash = SpecHash(p.DesiredSpec)
			p.Status = "READY_FOR_GIT_PROPOSAL"
		}
	}
	p.ReasonCodes = stable(p.ReasonCodes)
	p.Hash = ""
	p.Hash = Hash(p)
	return p
}

// Revalidate repeats every safety gate immediately before a Git-owned apply.
// A PDB/policy/identity change after proposal creation must not inherit authority.
func Revalidate(p Plan, s Snapshot, now time.Time) error {
	copy := p
	copy.Hash = ""
	if p.Status != "READY_FOR_GIT_PROPOSAL" || p.Hash != Hash(copy) {
		return errors.New("K8S_PLAN_HASH_INVALID")
	}
	if !p.ExpiresAt.After(now) {
		return errors.New("K8S_PLAN_EXPIRED")
	}
	current := Assess(Input{Now: now, Snapshot: s, ExpectedGitRevision: p.BaseGitRevision, Change: p.Change, Policy: p.Policy})
	if current.Status != "READY_FOR_GIT_PROPOSAL" {
		if len(current.ReasonCodes) > 0 {
			return errors.New(current.ReasonCodes[0])
		}
		return errors.New("K8S_PLAN_NOT_READY")
	}
	if Hash(current.Binding) != Hash(p.Binding) || current.BeforeSpecHash != p.BeforeSpecHash || current.DesiredSpecHash != p.DesiredSpecHash {
		return errors.New("K8S_PLAN_TARGET_CHANGED")
	}
	return nil
}

// VerifySync verifies the exact Git revision, target identity and rendered spec
// after a rollout. Merely having two Ready pods does not acknowledge a Git change.
func VerifySync(p Plan, s Snapshot, revision string, now time.Time) error {
	if p.Status != "READY_FOR_GIT_PROPOSAL" {
		return errors.New("K8S_PLAN_NOT_READY")
	}
	copy := p
	copy.Hash = ""
	if p.Hash != Hash(copy) {
		return errors.New("K8S_PLAN_HASH_INVALID")
	}
	if !revisionPattern.MatchString(revision) || revision == p.BaseGitRevision || s.Git.Revision != revision || !s.Git.Synced || !s.Git.Ready || s.Git.ObservedGeneration < s.Git.Generation || s.Git.Engine != p.Binding.Git.Engine || s.Git.Repository != p.Binding.Git.Repository || s.Git.Path != p.Binding.Git.Path || s.Git.ObservedAt.IsZero() || s.Git.ObservedAt.After(now.Add(5*time.Second)) || now.Sub(s.Git.ObservedAt) > 2*time.Minute {
		return errors.New("K8S_GIT_REVISION_NOT_ACKNOWLEDGED")
	}
	if Hash(s.Binding) != Hash(p.Binding) || s.ClusterID != p.Binding.ClusterID || s.NamespaceUID != p.Binding.NamespaceUID || s.Deployment.UID != p.Binding.DeploymentUID {
		return errors.New("K8S_IDENTITY_CHANGED")
	}
	if s.Environment != "NON_PRODUCTION" || s.Owner != p.Binding.Owner || s.Owner == "" {
		return errors.New("K8S_CLASSIFICATION_OR_OWNER_UNKNOWN")
	}
	if s.Hash != SnapshotHash(s) || s.CollectedAt.After(now.Add(5*time.Second)) || now.Sub(s.CollectedAt) > 2*time.Minute || len(s.Problems) > 0 {
		return errors.New("K8S_SNAPSHOT_INVALID")
	}
	if s.Deployment.SpecHash != p.DesiredSpecHash || s.Git.DeploymentSpecHash != p.DesiredSpecHash {
		return errors.New("K8S_GIT_LIVE_DRIFT")
	}
	if s.Deployment.Paused || s.Deployment.Deleting || s.Deployment.ObservedGeneration < s.Deployment.Generation || s.Deployment.Replicas < p.MinimumReplicas || s.Deployment.ReadyReplicas != s.Deployment.Replicas || s.Deployment.UpdatedReplicas != s.Deployment.Replicas || s.Deployment.UnavailableReplicas != 0 {
		return errors.New("K8S_ROLLOUT_NOT_HEALTHY")
	}
	zones := map[string]bool{}
	ready := int64(0)
	for _, pod := range s.Pods {
		if pod.Ready && !pod.Terminating {
			ready++
			if pod.Zone != "" {
				zones[pod.Zone] = true
			}
		}
		if pod.OOMKilled || pod.Restarts > 0 {
			return errors.New("K8S_RECOVERY_OR_OOM_EVIDENCE_REQUIRES_REVIEW")
		}
	}
	if ready < s.Deployment.Replicas || len(zones) < 2 {
		return errors.New("K8S_READY_TOPOLOGY_INSUFFICIENT")
	}
	return nil
}

type HPAInput struct{ Replicas, OldRequestMilli, NewRequestMilli, ObservedUsageMilli, TargetUtilizationPercent, MinReplicas, MaxReplicas int64 }
type HPAResult struct {
	PredictedReplicas       int64  `json:"predicted_replicas"`
	OldRequestedMilli       int64  `json:"old_requested_milli"`
	PredictedRequestedMilli int64  `json:"predicted_requested_milli"`
	ReasonCode              string `json:"reason_code"`
}

// SimulateHPA exposes the utilization denominator effect with exact integers.
// It is a planning calculation, not a telemetry source or a money-saving claim.
func SimulateHPA(in HPAInput) (HPAResult, error) {
	if in.Replicas < 1 || in.OldRequestMilli < 1 || in.NewRequestMilli < 1 || in.ObservedUsageMilli < 0 || in.TargetUtilizationPercent < 1 || in.TargetUtilizationPercent > 100 || in.MinReplicas < 1 || in.MaxReplicas < in.MinReplicas {
		return HPAResult{}, errors.New("K8S_HPA_INPUT_INVALID")
	}
	n := new(big.Int).Mul(big.NewInt(in.Replicas), big.NewInt(in.ObservedUsageMilli))
	n.Mul(n, big.NewInt(100))
	den := new(big.Int).Mul(big.NewInt(in.NewRequestMilli), big.NewInt(in.TargetUtilizationPercent))
	n.Add(n, new(big.Int).Sub(den, big.NewInt(1)))
	n.Div(n, den)
	if !n.IsInt64() {
		return HPAResult{}, errors.New("K8S_HPA_INPUT_OVERFLOW")
	}
	rep := n.Int64()
	if rep < in.MinReplicas {
		rep = in.MinReplicas
	}
	if rep > in.MaxReplicas {
		rep = in.MaxReplicas
	}
	old := new(big.Int).Mul(big.NewInt(in.Replicas), big.NewInt(in.OldRequestMilli))
	after := new(big.Int).Mul(big.NewInt(rep), big.NewInt(in.NewRequestMilli))
	if !old.IsInt64() || !after.IsInt64() {
		return HPAResult{}, errors.New("K8S_HPA_INPUT_OVERFLOW")
	}
	r := HPAResult{rep, old.Int64(), after.Int64(), "K8S_HPA_REQUEST_DENOMINATOR_SIMULATED"}
	if rep > in.Replicas {
		r.ReasonCode = "K8S_HPA_REPLICA_INCREASE"
	}
	if r.PredictedRequestedMilli > r.OldRequestedMilli {
		r.ReasonCode = "K8S_HPA_TOTAL_REQUESTS_INCREASE"
	}
	return r, nil
}
func clone(d Document) Document {
	raw, _ := json.Marshal(d)
	var out Document
	_ = json.Unmarshal(raw, &out)
	return out
}
