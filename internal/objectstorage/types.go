// Package objectstorage defines read-only object evidence. No type grants
// permission to mutate a customer bucket, object, retention or lifecycle rule.
package objectstorage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
)

const RawChunkBytes = 8 << 20
const InventoryBatchRows = 2000
const InventoryKind = "AWS_S3_INVENTORY"
const AccessKind = "AWS_S3_ANALYTICS"

type Scope struct {
	TenantID  string `json:"tenant_id"`
	AccountID string `json:"account_id"`
	Region    string `json:"region"`
}
type Observation struct {
	Status     string `json:"status"`
	ReasonCode string `json:"reason_code,omitempty"`
	Value      any    `json:"value"`
}
type Bucket struct {
	Name           string                 `json:"name"`
	ARN            string                 `json:"arn"`
	AccountID      string                 `json:"account_id"`
	Region         string                 `json:"region"`
	CreatedAt      time.Time              `json:"created_at"`
	ObservedAt     time.Time              `json:"observed_at"`
	Configurations map[string]Observation `json:"configurations"`
	Tags           map[string]string      `json:"tags"`
}
type RawFrame struct {
	Service    string `json:"service"`
	Region     string `json:"region"`
	Action     string `json:"action"`
	Selector   string `json:"selector"`
	StatusCode int    `json:"status_code"`
	Body       []byte `json:"body"`
}
type Discovery struct {
	SchemaVersion string           `json:"schema_version"`
	Scope         Scope            `json:"scope"`
	StartedAt     time.Time        `json:"started_at"`
	CollectedAt   time.Time        `json:"collected_at"`
	Buckets       []Bucket         `json:"buckets"`
	Coverage      []model.Document `json:"coverage"`
	Frames        []RawFrame       `json:"-"`
	Raw           []byte           `json:"-"`
	RawSHA256     string           `json:"raw_sha256"`
	Complete      bool             `json:"complete"`
}

// Prefix is literal, never a regexp or an object-list query. Tags identify
// evidenced bucket/dataset tags; Inventory does not invent per-object tags.
type DatasetSelector struct {
	ID             string            `json:"id"`
	Kind           string            `json:"kind"`
	Prefix         string            `json:"prefix,omitempty"`
	Tags           map[string]string `json:"tags,omitempty"`
	WorkloadID     string            `json:"workload_id,omitempty"`
	DatasetVersion int64             `json:"dataset_version"`
	DatasetHash    string            `json:"dataset_hash"`
	StorageClasses []string          `json:"storage_classes,omitempty"`
}
type Registration struct {
	ID                      string            `json:"id"`
	TenantID                string            `json:"tenant_id"`
	Kind                    string            `json:"kind"`
	AccountID               string            `json:"account_id"`
	Region                  string            `json:"region"`
	ReadRoleBindingID       string            `json:"read_role_binding_id"`
	Bucket                  string            `json:"bucket"`
	ReportBucket            string            `json:"report_bucket"`
	ReportOwner             string            `json:"report_owner"`
	Prefix                  string            `json:"prefix"`
	InventoryID             string            `json:"inventory_id"`
	ReportType              string            `json:"report_type,omitempty"`
	ReportRegion            string            `json:"report_region,omitempty"`
	ApprovedWriterPrincipal string            `json:"-"`
	MetricDefinitionID      string            `json:"-"`
	MetricDefinitionVersion string            `json:"-"`
	NativeBucketTags        map[string]string `json:"-"`
	Version                 int64             `json:"version"`
	Enabled                 bool              `json:"enabled"`
	Datasets                []DatasetSelector `json:"datasets"`
}
type Object struct {
	Bucket       string        `json:"bucket"`
	Key          string        `json:"key"`
	VersionID    string        `json:"version_id"`
	ETag         string        `json:"etag"`
	Length       int64         `json:"length"`
	LastModified time.Time     `json:"last_modified"`
	Body         io.ReadCloser `json:"-"`
}
type ObjectReader interface {
	OpenObject(context.Context, Registration, string, string) (Object, error)
	ReportBoundary(context.Context, Registration) (model.Document, error)
}
type Archive interface {
	Archive(context.Context, string, string, string, []byte) (model.Document, error)
	Read(context.Context, string, model.Document) ([]byte, error)
}
type InventoryRow struct {
	ID             string            `json:"id"`
	Bucket         string            `json:"bucket"`
	ObjectIdentity string            `json:"object_identity"`
	VersionID      *string           `json:"version_id"`
	CohortID       string            `json:"cohort_id"`
	Size           *int64            `json:"size_bytes"`
	LastModified   *time.Time        `json:"last_modified"`
	StorageClass   *string           `json:"storage_class"`
	IsLatest       *bool             `json:"is_latest"`
	IsDeleteMarker *bool             `json:"is_delete_marker"`
	Fields         map[string]string `json:"fields"`
}

// Facts must acknowledge the exact ordered rows; a receipt is published only
// after the full generation and every batch have been validated and read back.
type Facts interface {
	WriteObjectRows(context.Context, Scope, string, string, []InventoryRow) (model.Document, error)
}
type Generation struct {
	ID            string           `json:"id"`
	SourceID      string           `json:"source_id"`
	SourceVersion string           `json:"source_version"`
	Scope         Scope            `json:"scope"`
	Bucket        string           `json:"bucket"`
	ObservedAt    time.Time        `json:"observed_at"`
	Complete      bool             `json:"complete"`
	Inventory     model.Document   `json:"inventory"`
	Cohorts       []model.Document `json:"cohorts"`
	Access        model.Document   `json:"access"`
	SourceRefs    []model.Document `json:"source_refs"`
}

var account = regexp.MustCompile(`^[0-9]{12}$`)
var safe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)
var bucket = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)
var region = regexp.MustCompile(`^[a-z]{2}-[a-z]+-[0-9]$`)

func ValidateScope(s Scope) error {
	if !safe.MatchString(s.TenantID) || !account.MatchString(s.AccountID) || !region.MatchString(s.Region) || strings.HasPrefix(s.Region, "cn-") {
		return errors.New("OBJECT_STORAGE_SCOPE_INVALID")
	}
	return nil
}
func ParseRegistration(d model.Document) (Registration, error) {
	var r Registration
	b, e := json.Marshal(d)
	if e != nil {
		return r, e
	}
	e = json.Unmarshal(b, &r)
	if e != nil {
		return r, e
	}
	return r, ValidateRegistration(d)
}
func ValidateRegistration(d model.Document) error {
	var r Registration
	b, _ := json.Marshal(d)
	if json.Unmarshal(b, &r) != nil || ValidateScope(Scope{r.TenantID, r.AccountID, r.Region}) != nil || (r.Kind != InventoryKind && r.Kind != AccessKind) || !bucket.MatchString(r.Bucket) || !bucket.MatchString(r.ReportBucket) || !account.MatchString(r.ReportOwner) || !safe.MatchString(r.ReadRoleBindingID) || !safe.MatchString(r.InventoryID) || r.Prefix == "" || len(r.Prefix) > 1024 || !strings.HasSuffix(r.Prefix, "/") || strings.HasPrefix(r.Prefix, "/") || strings.ContainsAny(r.Prefix, "*?\\\x00\r\n") || strings.Contains(r.Prefix, "..") || len(r.Datasets) > 256 {
		return errors.New("OBJECT_STORAGE_REGISTRATION_INVALID")
	}
	if r.Kind == AccessKind && r.ReportType != "S3_STORAGE_CLASS_ANALYSIS" && r.ReportType != "S3_STORAGE_LENS" && r.ReportType != "APP_ACCESS" {
		return errors.New("S3_ANALYTICS_REPORT_TYPE_UNSUPPORTED")
	}
	if r.ReportRegion != "" && (ValidateScope(Scope{r.TenantID, r.AccountID, r.ReportRegion}) != nil || r.ReportType == "S3_STORAGE_CLASS_ANALYSIS" && r.ReportRegion != r.Region || r.Kind == InventoryKind && r.ReportRegion != r.Region) {
		return errors.New("S3_REPORT_REGION_INVALID")
	}
	seen := map[string]bool{}
	for _, s := range r.Datasets {
		if !safe.MatchString(s.ID) || seen[s.ID] || (s.Kind != "BUCKET" && s.Kind != "PREFIX" && s.Kind != "TAG_GROUP" && s.Kind != "WORKLOAD_DATASET" && s.Kind != "STORAGE_POLICY") || len(s.Prefix) > 1024 || strings.ContainsAny(s.Prefix, "\x00\r\n") || len(s.Tags) > 32 {
			return errors.New("OBJECT_STORAGE_DATASET_INVALID")
		}
		seen[s.ID] = true
	}
	return nil
}
func Hash(v any) string         { b, _ := json.Marshal(v); return BytesHash(b) }
func BytesHash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func ConfigurationHash(b Bucket) string {
	return Hash(model.Document{"bucket": b.Name, "arn": b.ARN, "account_id": b.AccountID, "region": b.Region, "configurations": b.Configurations, "tags": b.Tags})
}
