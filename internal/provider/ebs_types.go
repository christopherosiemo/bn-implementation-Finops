package provider

import (
	"context"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
)

// EBSScope is selected by the registered ordinary customer read binding.
type EBSScope struct {
	TenantID  string `json:"tenant_id"`
	AccountID string `json:"account_id"`
	Region    string `json:"region"`
}

type EBSReadEvidence struct {
	SchemaVersion    string           `json:"schema_version"`
	Scope            EBSScope         `json:"scope"`
	ObservationBasis string           `json:"observation_basis"`
	StartedAt        time.Time        `json:"started_at"`
	CollectedAt      time.Time        `json:"collected_at"`
	Callers          []model.Document `json:"callers"`
	RawSHA256        string           `json:"raw_sha256"`
	Raw              []byte           `json:"-"`
}

type EBSSnapshot struct {
	EBSReadEvidence
	Volumes              []model.Document `json:"volumes"`
	Snapshots            []model.Document `json:"snapshots"`
	OwnedImages          []model.Document `json:"owned_images"`
	FastSnapshotRestores []model.Document `json:"fast_snapshot_restores"`
	SnapshotTierStatuses []model.Document `json:"snapshot_tier_statuses"`
	LockedSnapshots      []model.Document `json:"locked_snapshots"`
	VolumeModifications  []model.Document `json:"volume_modifications"`
	VolumeStatuses       []model.Document `json:"volume_statuses"`
	Instances            []model.Document `json:"instances"`
	InstanceTypes        []model.Document `json:"instance_types"`
	SnapshotPermissions  []model.Document `json:"snapshot_permissions"`
	Coverage             []model.Document `json:"coverage"`
}

// Native periods are preserved; an hourly consumer must count distinct native
// bins and native SampleCount rather than treating one rollup as a full hour.
type EBSMetricSelection struct {
	VolumeID      string    `json:"volume_id"`
	Start         time.Time `json:"start"`
	End           time.Time `json:"end"`
	PeriodSeconds int       `json:"period_seconds"`
}
type EBSMetricEvidence struct {
	EBSReadEvidence
	Selection     EBSMetricSelection `json:"selection"`
	Volume        model.Document     `json:"volume"`
	Instances     []model.Document   `json:"instances"`
	InstanceTypes []model.Document   `json:"instance_types"`
	Metrics       []model.Document   `json:"metrics"`
	Coverage      []model.Document   `json:"coverage"`
}

type EBSReader interface {
	EBSDiscover(context.Context, EBSScope) (EBSSnapshot, error)
	EBSMetrics(context.Context, EBSScope, EBSMetricSelection) (EBSMetricEvidence, error)
}
