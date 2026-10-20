package provider

import "time"
import "github.com/christopherosiemo/bn-implementation-Finops/internal/model"

// Scope comes from the registered tenant/customer read binding, never a public
// evidence upload. APIs here contain no mutating AWS action.
type RDSScope struct {
	TenantID  string `json:"tenant_id"`
	AccountID string `json:"account_id"`
	Region    string `json:"region"`
}
type RDSReadEvidence struct {
	SchemaVersion    string           `json:"schema_version"`
	Scope            RDSScope         `json:"scope"`
	ObservationBasis string           `json:"observation_basis"`
	StartedAt        time.Time        `json:"started_at"`
	CollectedAt      time.Time        `json:"collected_at"`
	Callers          []model.Document `json:"callers"`
	RawSHA256        string           `json:"raw_sha256"`
	Raw              []byte           `json:"-"`
}
type RDSDiscoveryEvidence struct {
	RDSReadEvidence
	Instances         []model.Document `json:"instances"`
	Clusters          []model.Document `json:"clusters"`
	ReservedInstances []model.Document `json:"reserved_instances"`
}
type RDSCatalogEvidence struct {
	RDSReadEvidence
	Instance                      model.Document   `json:"instance"`
	Options                       []model.Document `json:"options"`
	Capacities                    []model.Document `json:"capacities"`
	ModificationConstraints       model.Document   `json:"modification_constraints"`
	ModificationConstraintsStatus string           `json:"modification_constraints_status"`
}
type RDSMetricSelection struct {
	ResourceARN   string    `json:"resource_arn"`
	Start         time.Time `json:"start"`
	End           time.Time `json:"end"`
	PeriodSeconds int       `json:"period_seconds"`
}
type RDSMetricEvidence struct {
	RDSReadEvidence
	Selection RDSMetricSelection `json:"selection"`
	Metrics   []model.Document   `json:"metrics"`
	Coverage  []model.Document   `json:"coverage"`
}
type RDSParameterEvidence struct {
	RDSReadEvidence
	Instance                 model.Document   `json:"instance"`
	Parameters               []model.Document `json:"parameters"`
	ConnectionCapacity       *string          `json:"connection_capacity"`
	ConnectionCapacityStatus string           `json:"connection_capacity_status"`
}
