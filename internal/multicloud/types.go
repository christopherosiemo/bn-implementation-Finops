// Package multicloud collects provider-shaped native billing evidence. It is
// deliberately separate from AWS execution/source-proof schemas: these initial
// adapters publish provisional observations, never execution or savings authority.
package multicloud

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"
)

type Document map[string]any
type Kind string

const (
	AzureActual    Kind = "AZURE_ACTUAL_COST"
	AzureAmortized Kind = "AZURE_AMORTIZED_COST"
	AzureFOCUS     Kind = "AZURE_FOCUS_COST"
	GCPDetailed    Kind = "GCP_DETAILED_BILLING"
	GCPPricing     Kind = "GCP_ACCOUNT_PRICING"
	GCPCommitments Kind = "GCP_SPEND_CUD_METADATA"
)
const MaxBodyBytes = 32 << 20
const MaxCollectionBytes = 128 << 20
const MaxRows = 100000

type AzureScope struct {
	DirectoryTenantID        string   `json:"directory_tenant_id"`
	ExportResourceID         string   `json:"export_resource_id"`
	BillingAccountID         string   `json:"billing_account_id,omitempty"`
	SubscriptionIDs          []string `json:"subscription_ids"`
	StorageAccountResourceID string   `json:"storage_account_resource_id"`
	StorageAccountName       string   `json:"storage_account_name"`
	Container                string   `json:"container"`
	Prefix                   string   `json:"prefix"`
	DataVersion              string   `json:"data_version"`
}
type GCPScope struct {
	BillingAccountID   string   `json:"billing_account_id"`
	QueryProjectID     string   `json:"query_project_id"`
	DatasetProjectID   string   `json:"dataset_project_id"`
	DatasetID          string   `json:"dataset_id"`
	TableID            string   `json:"table_id"`
	Location           string   `json:"location"`
	UsageProjectIDs    []string `json:"usage_project_ids"`
	MaximumBytesBilled string   `json:"maximum_bytes_billed"`
}
type Registration struct {
	SchemaVersion string      `json:"schema_version"`
	ID            string      `json:"id"`
	Version       int64       `json:"version"`
	TenantID      string      `json:"tenant_id"`
	ReadBindingID string      `json:"read_binding_id"`
	Kind          Kind        `json:"kind"`
	Azure         *AzureScope `json:"azure,omitempty"`
	GCP           *GCPScope   `json:"gcp,omitempty"`
}

// ReadBinding belongs to the server's credential registry. It is never selected
// by a caller-provided role ARN, token, producer assertion or trusted=true flag.
type ReadBinding struct {
	ID, TenantID, Provider, DirectoryTenantID, BillingAccountID, DatasetProjectID, ScopeHash string
}
type TokenSource interface {
	Token(context.Context, string) (string, error)
}
type TokenFunc func(context.Context, string) (string, error)

func (f TokenFunc) Token(ctx context.Context, scope string) (string, error) { return f(ctx, scope) }

type Config struct {
	HTTP    *http.Client
	Tokens  TokenSource
	Binding ReadBinding
	Now     func() time.Time
}
type Period struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}
type Object struct {
	Kind         string    `json:"kind"`
	Resource     string    `json:"resource"`
	Version      string    `json:"version,omitempty"`
	ETag         string    `json:"etag,omitempty"`
	SHA256       string    `json:"sha256"`
	Bytes        int64     `json:"bytes"`
	LastModified time.Time `json:"last_modified,omitempty"`
	Body         []byte    `json:"-"`
}

// Record preserves native money as decimal text. Nil is unknown, not zero.
// Native contains the full source row, including corrections, credits, pricing
// models, commitment identifiers, original units and calendar/time semantics.
type Record struct {
	ID               string     `json:"id"`
	Kind             Kind       `json:"kind"`
	BillingAccountID string     `json:"billing_account_id,omitempty"`
	UsageAccountID   string     `json:"usage_account_id,omitempty"`
	ResourceID       string     `json:"resource_id,omitempty"`
	Region           string     `json:"region,omitempty"`
	Currency         string     `json:"currency,omitempty"`
	BilledCost       *string    `json:"billed_cost"`
	EffectiveCost    *string    `json:"effective_cost"`
	ListCost         *string    `json:"list_cost"`
	ChargeCategory   string     `json:"charge_category,omitempty"`
	ChargeClass      string     `json:"charge_class,omitempty"`
	ChargeStart      *time.Time `json:"charge_start"`
	ChargeEnd        *time.Time `json:"charge_end"`
	InvoiceMonth     string     `json:"invoice_month,omitempty"`
	Precision        string     `json:"precision"`
	MappingGaps      []string   `json:"mapping_gaps"`
	Native           Document   `json:"native"`
}
type Snapshot struct {
	SchemaVersion       string            `json:"schema_version"`
	RegistrationID      string            `json:"registration_id"`
	RegistrationVersion int64             `json:"registration_version"`
	ConfigHash          string            `json:"config_hash"`
	TenantID            string            `json:"tenant_id"`
	Kind                Kind              `json:"kind"`
	SourceClass         string            `json:"source_class"`
	Status              string            `json:"status"`
	ReasonCodes         []string          `json:"reason_codes"`
	ObservedAt          time.Time         `json:"observed_at"`
	Period              Period            `json:"period"`
	NativeReference     string            `json:"native_reference"`
	Objects             []Object          `json:"objects"`
	Records             []Record          `json:"records"`
	NativeRowCount      int64             `json:"native_row_count"`
	BilledTotals        map[string]string `json:"billed_totals"`
	AmortizedTotals     map[string]string `json:"amortized_totals"`
	Revision            string            `json:"revision"`
}

func (s Snapshot) ExecutionReady() bool    { return false }
func (s Snapshot) VerifiedSaving() *string { return nil }
func Hash(v any) string {
	raw, e := json.Marshal(v)
	if e != nil {
		return ""
	}
	return BytesHash(raw)
}

// ScopeHash binds the server credential registry to the entire permitted native
// scope, including the query billing project and storage destination. It excludes
// only registration identity/version, so a broad credential cannot be retargeted.
func ScopeHash(r Registration) string {
	return Hash(Document{"tenant_id": r.TenantID, "kind": r.Kind, "azure": r.Azure, "gcp": r.GCP})
}
func BytesHash(v []byte) string { x := sha256.Sum256(v); return hex.EncodeToString(x[:]) }
func base(r Registration, now time.Time) Snapshot {
	return Snapshot{SchemaVersion: "multicloud-billing-1", RegistrationID: r.ID, RegistrationVersion: r.Version, ConfigHash: Hash(r), TenantID: r.TenantID, Kind: r.Kind, SourceClass: "AUTHENTICATED_PROVIDER_READ_PROVISIONAL", Status: "PROVISIONAL", ReasonCodes: []string{"EXCLUSIVE_PRODUCER_POLICY_UNPROVEN", "REPORTING_PERIOD_COMPLETENESS_UNPROVEN", "INVOICE_FINALITY_UNPROVEN", "NO_EXECUTION_AUTHORITY"}, ObservedAt: now.UTC(), Objects: []Object{}, Records: []Record{}, BilledTotals: map[string]string{}, AmortizedTotals: map[string]string{}}
}
func seal(s Snapshot) Snapshot {
	s.ReasonCodes = unique(s.ReasonCodes)
	s.Revision = ""
	copy := s
	copy.ObservedAt = time.Time{}
	s.Revision = Hash(copy)
	return s
}
func CustomerImport(r Registration, records []Record, now time.Time) Snapshot {
	s := base(r, now)
	s.SourceClass = "CUSTOMER_IMPORT_UNTRUSTED"
	s.Records = records
	s.NativeRowCount = int64(len(records))
	s.ReasonCodes = append(s.ReasonCodes, "TRUSTED_PROVIDER_SOURCE_REQUIRED")
	return seal(s)
}

var guid = regexp.MustCompile(`^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$`)
var safeID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
var azureExport = regexp.MustCompile(`(?i)^/(?:subscriptions/[a-f0-9-]{36}|providers/Microsoft\.Billing/billingAccounts/[a-z0-9._:-]+(?:/billingProfiles/[a-z0-9._:-]+)?)/providers/Microsoft\.CostManagement/exports/[a-z0-9_-]+$`)
var azureStorage = regexp.MustCompile(`(?i)^/subscriptions/[a-f0-9-]{36}/resourceGroups/[a-z0-9_.()-]+/providers/Microsoft\.Storage/storageAccounts/([a-z0-9]{3,24})$`)
var gcpAccount = regexp.MustCompile(`^[A-Z0-9]{6}-[A-Z0-9]{6}-[A-Z0-9]{6}$`)
var gcpProject = regexp.MustCompile(`^[a-z][a-z0-9-]{4,28}[a-z0-9]$`)
var gcpDataset = regexp.MustCompile(`^[A-Za-z0-9_]+$`)

func Validate(r Registration) error {
	if r.SchemaVersion != "1" || !safeID.MatchString(r.ID) || !safeID.MatchString(r.TenantID) || r.Version < 1 || !safeID.MatchString(r.ReadBindingID) {
		return errors.New("MULTICLOUD_REGISTRATION_INVALID")
	}
	switch r.Kind {
	case AzureActual, AzureAmortized, AzureFOCUS:
		if r.Azure == nil || r.GCP != nil {
			return errors.New("AZURE_SCOPE_REQUIRED")
		}
		a := r.Azure
		match := azureStorage.FindStringSubmatch(a.StorageAccountResourceID)
		if !guid.MatchString(a.DirectoryTenantID) || !azureExport.MatchString(a.ExportResourceID) || len(match) != 2 || match[1] != a.StorageAccountName || !regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$`).MatchString(a.Container) || strings.Contains(a.Container, "--") || !safePath(a.Prefix) || !strings.HasSuffix(a.Prefix, "/") || a.DataVersion == "" || len(a.SubscriptionIDs) == 0 {
			return errors.New("AZURE_SCOPE_INVALID")
		}
		seen := map[string]bool{}
		for _, id := range a.SubscriptionIDs {
			key := strings.ToLower(id)
			if !guid.MatchString(id) || seen[key] {
				return errors.New("AZURE_SUBSCRIPTION_SCOPE_INVALID")
			}
			seen[key] = true
		}
	case GCPDetailed, GCPPricing, GCPCommitments:
		if r.GCP == nil || r.Azure != nil {
			return errors.New("GCP_SCOPE_REQUIRED")
		}
		g := r.GCP
		if !gcpAccount.MatchString(g.BillingAccountID) || !gcpProject.MatchString(g.QueryProjectID) || !gcpProject.MatchString(g.DatasetProjectID) || !gcpDataset.MatchString(g.DatasetID) || len(g.DatasetID) > 1024 || !(g.Location == "EU" || regexp.MustCompile(`^europe-[a-z]+[0-9]+$`).MatchString(g.Location)) || len(g.UsageProjectIDs) == 0 || !regexp.MustCompile(`^[1-9][0-9]{0,11}$`).MatchString(g.MaximumBytesBilled) {
			return errors.New("GCP_SCOPE_INVALID")
		}
		want := "gcp_billing_export_resource_v1_" + strings.ReplaceAll(g.BillingAccountID, "-", "_")
		if r.Kind == GCPPricing {
			want = "cloud_pricing_export"
		}
		if r.Kind == GCPCommitments {
			want = "cud_subscriptions_export"
		}
		if g.TableID != want {
			return errors.New("GCP_TABLE_KIND_BINDING_INVALID")
		}
		seen := map[string]bool{}
		for _, id := range g.UsageProjectIDs {
			if !gcpProject.MatchString(id) || seen[id] {
				return errors.New("GCP_PROJECT_SCOPE_INVALID")
			}
			seen[id] = true
		}
	default:
		return errors.New("MULTICLOUD_KIND_UNSUPPORTED")
	}
	return nil
}
func safePath(s string) bool {
	return s != "" && !strings.HasPrefix(s, "/") && !strings.Contains(s, "..") && !strings.ContainsAny(s, "\\%?#\x00\r\n")
}
func (c Config) now() time.Time {
	if c.Now != nil {
		return c.Now().UTC()
	}
	return time.Now().UTC()
}
func (c Config) validate(r Registration, provider string) error {
	if err := Validate(r); err != nil {
		return err
	}
	if (provider == "AZURE" && r.Azure == nil) || (provider == "GCP" && r.GCP == nil) || c.HTTP == nil || c.Tokens == nil || c.Binding.ID != r.ReadBindingID || c.Binding.TenantID != r.TenantID || c.Binding.Provider != provider || c.Binding.ScopeHash != ScopeHash(r) {
		return errors.New("MULTICLOUD_READ_BINDING_MISMATCH")
	}
	if provider == "AZURE" && !strings.EqualFold(c.Binding.DirectoryTenantID, r.Azure.DirectoryTenantID) {
		return errors.New("AZURE_DIRECTORY_BINDING_MISMATCH")
	}
	if provider == "GCP" && (c.Binding.BillingAccountID != r.GCP.BillingAccountID || c.Binding.DatasetProjectID != r.GCP.DatasetProjectID) {
		return errors.New("GCP_ACCOUNT_BINDING_MISMATCH")
	}
	return nil
}
