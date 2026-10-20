// Package network contains read-only AWS topology and traffic evidence. It has
// no provider mutation, approval, signing or execution interface.
package network

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

const FlowKind = "AWS_VPC_FLOW_LOGS"
const RawChunkBytes = 8 << 20
const FlowBatchRows = 2000
const MaxCohorts = 4096

var ErrEvidence = errors.New("NETWORK_SCOPE_OR_EVIDENCE_UNAVAILABLE")
var accountID = regexp.MustCompile(`^[0-9]{12}$`)
var safeID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)
var regionID = regexp.MustCompile(`^[a-z]{2}-[a-z]+-[0-9]$`)
var bucketID = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)
var hashID = regexp.MustCompile(`^[0-9a-f]{64}$`)

type Scope struct {
	TenantID  string `json:"tenant_id"`
	AccountID string `json:"account_id"`
	Region    string `json:"region"`
}
type Discovery struct {
	SchemaVersion string           `json:"schema_version"`
	Scope         Scope            `json:"scope"`
	StartedAt     time.Time        `json:"started_at"`
	CollectedAt   time.Time        `json:"collected_at"`
	Resources     []model.Document `json:"resources"`
	Coverage      []model.Document `json:"coverage"`
	Complete      bool             `json:"complete"`
	TopologyHash  string           `json:"topology_hash"`
	RawSHA256     string           `json:"raw_sha256"`
	Raw           []byte           `json:"-"`
}
type RawFrame struct {
	Service    string `json:"service"`
	Action     string `json:"action"`
	Region     string `json:"region"`
	Selector   string `json:"selector"`
	StatusCode int    `json:"status_code"`
	Body       []byte `json:"body"`
}
type MetricSelection struct {
	NATGatewayID     string    `json:"nat_gateway_id"`
	AvailabilityZone string    `json:"availability_zone,omitempty"`
	Start            time.Time `json:"start"`
	End              time.Time `json:"end"`
	PeriodSeconds    int       `json:"period_seconds"`
}
type MetricEvidence struct {
	SchemaVersion string           `json:"schema_version"`
	Scope         Scope            `json:"scope"`
	Selection     MetricSelection  `json:"selection"`
	Metrics       []model.Document `json:"metrics"`
	Coverage      []model.Document `json:"coverage"`
	RawSHA256     string           `json:"raw_sha256"`
	Raw           []byte           `json:"-"`
}

// Registration describes already commissioned logs. Collection never creates a
// flow log or changes its delivery configuration. Scope is a list of native
// VPC/subnet/interface resource IDs, not a caller assertion of total traffic.
type Registration struct {
	ID                    string   `json:"id"`
	TenantID              string   `json:"tenant_id"`
	Kind                  string   `json:"kind"`
	AccountID             string   `json:"account_id"`
	Region                string   `json:"region"`
	ReadRoleBindingID     string   `json:"read_role_binding_id"`
	FlowLogID             string   `json:"flow_log_id"`
	ResourceIDs           []string `json:"resource_ids"`
	ReportBucket          string   `json:"report_bucket"`
	ReportOwner           string   `json:"report_owner"`
	ReportRegion          string   `json:"report_region"`
	Prefix                string   `json:"prefix"`
	Fields                []string `json:"fields"`
	TrafficType           string   `json:"traffic_type"`
	MaxAggregationSeconds int      `json:"max_aggregation_seconds"`
	Version               int64    `json:"version"`
	Enabled               bool     `json:"enabled"`
}
type ObjectRef struct {
	Key       string `json:"key"`
	VersionID string `json:"version_id"`
	SHA256    string `json:"sha256"`
	Size      int64  `json:"size"`
}
type Object struct {
	Bucket       string        `json:"bucket"`
	Key          string        `json:"key"`
	VersionID    string        `json:"version_id"`
	Length       int64         `json:"length"` // -1 means absent GET length; the pinned size and streamed size/hash remain mandatory.
	LastModified time.Time     `json:"last_modified"`
	Body         io.ReadCloser `json:"-"`
}
type ObjectReader interface {
	OpenFlowObject(context.Context, Registration, string, string) (Object, error)
	FlowBoundary(context.Context, Registration) (model.Document, error)
}
type Archive interface {
	Archive(context.Context, string, string, string, []byte) (model.Document, error)
	Read(context.Context, string, model.Document) ([]byte, error)
}
type FlowRow struct {
	ID                 string            `json:"id"`
	CohortID           string            `json:"cohort_id"`
	AccountID          string            `json:"account_id"`
	Region             string            `json:"region"`
	InterfaceID        string            `json:"interface_id"`
	ResourceID         string            `json:"resource_id"`
	VPCID              string            `json:"vpc_id"`
	SubnetID           string            `json:"subnet_id"`
	AZID               string            `json:"az_id"`
	Source             string            `json:"source"`
	Destination        string            `json:"destination"`
	PacketSource       string            `json:"packet_source"`
	PacketDestination  string            `json:"packet_destination"`
	SourceService      string            `json:"source_service"`
	DestinationService string            `json:"destination_service"`
	Direction          string            `json:"direction"`
	TrafficPath        string            `json:"traffic_path"`
	Action             string            `json:"action"`
	LogStatus          string            `json:"log_status"`
	Protocol           string            `json:"protocol"`
	Bytes              *uint64           `json:"bytes"`
	Packets            *uint64           `json:"packets"`
	Start              *time.Time        `json:"start"`
	End                *time.Time        `json:"end"`
	Fields             map[string]string `json:"fields"`
}
type Facts interface {
	WriteNetworkRows(context.Context, Scope, string, string, []FlowRow) (model.Document, error)
}
type Generation struct {
	ID             string           `json:"id"`
	SourceID       string           `json:"source_id"`
	SourceVersion  int64            `json:"source_version"`
	Scope          Scope            `json:"scope"`
	Rows           int64            `json:"rows"`
	Cohorts        []model.Document `json:"cohorts"`
	SourceRefs     []model.Document `json:"source_refs"`
	Coverage       model.Document   `json:"coverage"`
	PopulationHash string           `json:"population_hash"`
	Complete       bool             `json:"complete"`
}
type Checkpoint interface {
	Load(context.Context, string, string) (model.Document, error)
	Save(context.Context, string, string, model.Document) error
}

func ValidateScope(s Scope) error {
	if !safeID.MatchString(s.TenantID) || !accountID.MatchString(s.AccountID) || !regionID.MatchString(s.Region) || strings.HasPrefix(s.Region, "cn-") || strings.HasPrefix(s.Region, "us-gov-") {
		return ErrEvidence
	}
	return nil
}
func Hash(v any) string         { b, _ := json.Marshal(v); return BytesHash(b) }
func BytesHash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func ValidateRegistration(r Registration) error {
	if ValidateScope(Scope{r.TenantID, r.AccountID, r.Region}) != nil || r.Kind != FlowKind || !safeID.MatchString(r.ID) || !safeID.MatchString(r.ReadRoleBindingID) || !strings.HasPrefix(r.FlowLogID, "fl-") || !bucketID.MatchString(r.ReportBucket) || !accountID.MatchString(r.ReportOwner) || !regionID.MatchString(r.ReportRegion) || r.Prefix == "" || !strings.HasSuffix(r.Prefix, "/") || strings.HasPrefix(r.Prefix, "/") || strings.Contains(r.Prefix, "..") || strings.ContainsAny(r.Prefix, "*?\\\x00\r\n") || len(r.Prefix) > 1024 || len(r.ResourceIDs) == 0 || len(r.ResourceIDs) > 1000 || len(r.Fields) < 14 || len(r.Fields) > 100 || r.Version < 1 || (r.TrafficType != "ALL" && r.TrafficType != "ACCEPT" && r.TrafficType != "REJECT") || (r.MaxAggregationSeconds != 60 && r.MaxAggregationSeconds != 600) {
		return ErrEvidence
	}
	seen := map[string]bool{}
	for _, f := range r.Fields {
		if f == "" || seen[f] || strings.ContainsAny(f, " \t\r\n${}") {
			return ErrEvidence
		}
		seen[f] = true
	}
	for _, f := range []string{"version", "account-id", "interface-id", "srcaddr", "dstaddr", "packets", "bytes", "start", "end", "action", "log-status", "protocol"} {
		if !seen[f] {
			return ErrEvidence
		}
	}
	seen = map[string]bool{}
	for _, id := range r.ResourceIDs {
		if seen[id] || (!strings.HasPrefix(id, "vpc-") && !strings.HasPrefix(id, "subnet-") && !strings.HasPrefix(id, "eni-")) {
			return ErrEvidence
		}
		seen[id] = true
	}
	return nil
}

func ParseRegistration(d model.Document) (Registration, error) {
	var r Registration
	b, e := json.Marshal(d)
	if e != nil || json.Unmarshal(b, &r) != nil {
		return r, ErrEvidence
	}
	return r, ValidateRegistration(r)
}
