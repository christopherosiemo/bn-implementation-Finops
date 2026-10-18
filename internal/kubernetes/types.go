// Package kubernetes provides read-only inventory and conservative, Git-owned
// Deployment change assessment. It does not contain an imperative cluster writer.
package kubernetes

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"sort"
	"time"
)

type Document map[string]any

type Binding struct {
	TenantID      string     `json:"tenant_id"`
	WorkloadID    string     `json:"workload_id"`
	Provider      string     `json:"provider"`
	ClusterID     string     `json:"cluster_id"` // kube-system namespace UID, not an invented Kubernetes cluster UID.
	Namespace     string     `json:"namespace"`
	NamespaceUID  string     `json:"namespace_uid"`
	Deployment    string     `json:"deployment"`
	DeploymentUID string     `json:"deployment_uid"`
	Owner         string     `json:"owner"`
	Git           GitBinding `json:"git"`
}
type GitBinding struct {
	Engine              string `json:"engine"` // ARGOCD, FLUX, or visibly labelled LOCAL_GITOPS_TEST_DOUBLE.
	Repository          string `json:"repository"`
	Path                string `json:"path"`
	ControllerNamespace string `json:"controller_namespace"`
	ControllerName      string `json:"controller_name"`
}
type GitObservation struct {
	Engine             string    `json:"engine"`
	Repository         string    `json:"repository"`
	Path               string    `json:"path"`
	Revision           string    `json:"revision"`
	Ready              bool      `json:"ready"`
	Synced             bool      `json:"synced"`
	ObservedGeneration int64     `json:"observed_generation"`
	Generation         int64     `json:"generation"`
	DeploymentSpecHash string    `json:"deployment_spec_hash,omitempty"`
	ObservedAt         time.Time `json:"observed_at"`
	RawHash            string    `json:"raw_hash"`
}
type Container struct {
	Name               string `json:"name"`
	CPURequestMilli    int64  `json:"cpu_request_milli"`
	MemoryRequestBytes int64  `json:"memory_request_bytes"`
	CPULimitMilli      int64  `json:"cpu_limit_milli"`
	MemoryLimitBytes   int64  `json:"memory_limit_bytes"`
	ReadinessProbe     bool   `json:"readiness_probe"`
}
type Deployment struct {
	UID                 string            `json:"uid"`
	Name                string            `json:"name"`
	Generation          int64             `json:"generation"`
	ObservedGeneration  int64             `json:"observed_generation"`
	Replicas            int64             `json:"replicas"`
	ReadyReplicas       int64             `json:"ready_replicas"`
	UpdatedReplicas     int64             `json:"updated_replicas"`
	UnavailableReplicas int64             `json:"unavailable_replicas"`
	Paused              bool              `json:"paused"`
	Deleting            bool              `json:"deleting"`
	Labels              map[string]string `json:"labels"`
	TemplateLabels      map[string]string `json:"template_labels"`
	Containers          []Container       `json:"containers"`
	Strategy            string            `json:"strategy"`
	MaxUnavailableZero  bool              `json:"max_unavailable_zero"`
	MaxSurgeOne         bool              `json:"max_surge_one"`
	ZoneSpread          bool              `json:"zone_spread"`
	Spec                Document          `json:"spec"`
	SpecHash            string            `json:"spec_hash"`
}
type Pod struct {
	UID         string   `json:"uid"`
	Node        string   `json:"node"`
	Zone        string   `json:"zone"`
	Ready       bool     `json:"ready"`
	Terminating bool     `json:"terminating"`
	Restarts    int64    `json:"restarts"`
	OOMKilled   bool     `json:"oom_killed"`
	ImageIDs    []string `json:"image_ids"`
}
type PDB struct {
	UID                string `json:"uid"`
	Name               string `json:"name"`
	Generation         int64  `json:"generation"`
	ObservedGeneration int64  `json:"observed_generation"`
	Matches            bool   `json:"matches"`
	SelectorKnown      bool   `json:"selector_known"`
	DisruptionsAllowed int64  `json:"disruptions_allowed"`
	CurrentHealthy     int64  `json:"current_healthy"`
	DesiredHealthy     int64  `json:"desired_healthy"`
}
type HPA struct {
	Name                 string   `json:"name"`
	MinReplicas          int64    `json:"min_replicas"`
	MaxReplicas          int64    `json:"max_replicas"`
	UtilizationResources []string `json:"utilization_resources"`
	MetricsKnown         bool     `json:"metrics_known"`
}
type VPA struct {
	Name string `json:"name"`
	Mode string `json:"mode"`
}
type Node struct {
	UID                    string `json:"uid"`
	Name                   string `json:"name"`
	Zone                   string `json:"zone"`
	Ready                  bool   `json:"ready"`
	Unschedulable          bool   `json:"unschedulable"`
	CPUAllocatableMilli    int64  `json:"cpu_allocatable_milli"`
	MemoryAllocatableBytes int64  `json:"memory_allocatable_bytes"`
	ProviderID             string `json:"provider_id,omitempty"`
}
type Snapshot struct {
	SchemaVersion               string            `json:"schema_version"`
	Binding                     Binding           `json:"binding"`
	CollectedAt                 time.Time         `json:"collected_at"`
	ClusterID                   string            `json:"cluster_id"`
	NamespaceUID                string            `json:"namespace_uid"`
	Environment                 string            `json:"environment"`
	Owner                       string            `json:"owner"`
	Deployment                  Deployment        `json:"deployment"`
	Pods                        []Pod             `json:"pods"`
	Nodes                       []Node            `json:"nodes"`
	PDBs                        []PDB             `json:"pdbs"`
	HPAs                        []HPA             `json:"hpas"`
	VPAs                        []VPA             `json:"vpas"`
	NodeAutoscalers             []string          `json:"node_autoscalers"`
	AutoscalerDiscoveryComplete bool              `json:"autoscaler_discovery_complete"`
	Git                         GitObservation    `json:"git"`
	RawHashes                   map[string]string `json:"raw_hashes"`
	Problems                    []string          `json:"problems"`
	Hash                        string            `json:"hash"`
}
type Change struct {
	Container          string `json:"container"`
	CPURequestMilli    int64  `json:"cpu_request_milli"`
	MemoryRequestBytes int64  `json:"memory_request_bytes"`
}
type Policy struct {
	MinimumReplicas      int64     `json:"minimum_replicas"`
	MaintenanceStart     time.Time `json:"maintenance_start"`
	MaintenanceEnd       time.Time `json:"maintenance_end"`
	RolloutBudgetSeconds int64     `json:"rollout_budget_seconds"`
}
type Input struct {
	Now                 time.Time `json:"now"`
	Snapshot            Snapshot  `json:"snapshot"`
	ExpectedGitRevision string    `json:"expected_git_revision"`
	Change              Change    `json:"change"`
	Policy              Policy    `json:"policy"`
}
type Plan struct {
	SchemaVersion   string    `json:"schema_version"`
	Status          string    `json:"status"`
	ReasonCodes     []string  `json:"reason_codes"`
	Binding         Binding   `json:"binding"`
	SnapshotHash    string    `json:"snapshot_hash"`
	BeforeSpecHash  string    `json:"before_spec_hash"`
	DesiredSpecHash string    `json:"desired_spec_hash,omitempty"`
	BaseGitRevision string    `json:"base_git_revision"`
	Change          Change    `json:"change"`
	DesiredSpec     Document  `json:"desired_spec,omitempty"`
	ExpiresAt       time.Time `json:"expires_at"`
	MinimumReplicas int64     `json:"minimum_replicas"`
	Policy          Policy    `json:"policy"`
	FinancialStatus string    `json:"financial_status"`
	Hash            string    `json:"hash"`
}

var revisionPattern = regexp.MustCompile(`^(?:[0-9a-f]{40}|[0-9a-f]{64})$`)

func Hash(v any) string {
	b, _ := json.Marshal(v)
	x := sha256.Sum256(b)
	return hex.EncodeToString(x[:])
}
func HashBytes(v []byte) string      { x := sha256.Sum256(v); return hex.EncodeToString(x[:]) }
func SnapshotHash(s Snapshot) string { s.Hash = ""; return Hash(s) }
func ValidateBinding(b Binding) error {
	if b.TenantID == "" || b.WorkloadID == "" || b.ClusterID == "" || b.NamespaceUID == "" || b.DeploymentUID == "" || b.Owner == "" {
		return errors.New("K8S_BINDING_INCOMPLETE")
	}
	name := regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)
	if !name.MatchString(b.Namespace) || !name.MatchString(b.Deployment) || !name.MatchString(b.Git.ControllerNamespace) || !name.MatchString(b.Git.ControllerName) {
		return errors.New("K8S_BINDING_INVALID")
	}
	if b.Git.Repository == "" || b.Git.Path == "" {
		return errors.New("K8S_GIT_AUTHORITY_UNKNOWN")
	}
	if b.Git.Engine != "ARGOCD" && b.Git.Engine != "FLUX" && b.Git.Engine != "LOCAL_GITOPS_TEST_DOUBLE" {
		return errors.New("K8S_GIT_AUTHORITY_UNKNOWN")
	}
	if b.Git.Engine == "LOCAL_GITOPS_TEST_DOUBLE" && b.Provider != "LOCAL_KIND" {
		return errors.New("K8S_LOCAL_CONTROLLER_FORBIDDEN")
	}
	if b.Provider != "LOCAL_KIND" && b.Provider != "AWS" && b.Provider != "AZURE" && b.Provider != "GCP" {
		return errors.New("K8S_PROVIDER_UNSUPPORTED")
	}
	return nil
}
func stable(xs []string) []string {
	sort.Strings(xs)
	out := []string{}
	for _, x := range xs {
		if len(out) == 0 || out[len(out)-1] != x {
			out = append(out, x)
		}
	}
	return out
}
