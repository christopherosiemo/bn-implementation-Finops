package multicloud

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"time"
)

// Inventory registrations deliberately cannot reuse a billing registration or
// credential merely because both belong to the same directory/project.
type InventoryRegistration struct {
	SchemaVersion string               `json:"schema_version"`
	ID            string               `json:"id"`
	Version       int64                `json:"version"`
	TenantID      string               `json:"tenant_id"`
	ReadBindingID string               `json:"read_binding_id"`
	Provider      string               `json:"provider"`
	Azure         *AzureInventoryScope `json:"azure,omitempty"`
	GCP           *GCPInventoryScope   `json:"gcp,omitempty"`
}
type AzureInventoryScope struct {
	DirectoryTenantID string   `json:"directory_tenant_id"`
	SubscriptionID    string   `json:"subscription_id"`
	ResourceGroup     string   `json:"resource_group"`
	Locations         []string `json:"locations"`
}
type GCPInventoryScope struct {
	ProjectID string   `json:"project_id"`
	Zones     []string `json:"zones"`
}
type InstanceIdentity struct {
	Provider       string `json:"provider"`
	TenantID       string `json:"tenant_id"`
	SubscriptionID string `json:"subscription_id,omitempty"`
	ResourceID     string `json:"resource_id"`
	VMID           string `json:"vm_id,omitempty"`
	ProjectID      string `json:"project_id,omitempty"`
	Zone           string `json:"zone,omitempty"`
	NumericID      string `json:"numeric_id,omitempty"`
	Name           string `json:"name"`
}
type Instance struct {
	Identity          InstanceIdentity `json:"identity"`
	Location          string           `json:"location"`
	InstanceType      string           `json:"instance_type"`
	State             string           `json:"state"`
	ObservedAt        time.Time        `json:"observed_at"`
	ProviderCreatedAt *time.Time       `json:"provider_created_at"`
	Tags              Document         `json:"tags"`
	OS                string           `json:"os"`
	Architecture      string           `json:"architecture"`
	LicenseType       string           `json:"license_type"`
	Image             Document         `json:"image"`
	ManagedAuthority  string           `json:"managed_authority"`
	ManagedReferences []string         `json:"managed_references"`
	Blockers          []string         `json:"blockers"`
	Currency          *string          `json:"currency"`
	HourlyCost        *string          `json:"hourly_cost"`
	Native            Document         `json:"-"`
}
type InventorySnapshot struct {
	SchemaVersion       string     `json:"schema_version"`
	RegistrationID      string     `json:"registration_id"`
	RegistrationVersion int64      `json:"registration_version"`
	ConfigHash          string     `json:"config_hash"`
	TenantID            string     `json:"tenant_id"`
	Provider            string     `json:"provider"`
	Status              string     `json:"status"`
	ObservedAt          time.Time  `json:"observed_at"`
	Objects             []Object   `json:"objects"`
	Instances           []Instance `json:"instances"`
	ReasonCodes         []string   `json:"reason_codes"`
	Revision            string     `json:"revision"`
}

func (s InventorySnapshot) ExecutionReady() bool { return false }
func InventoryScopeHash(r InventoryRegistration) string {
	return Hash(Document{"tenant_id": r.TenantID, "provider": r.Provider, "azure": r.Azure, "gcp": r.GCP})
}
func ValidateInventory(r InventoryRegistration) error {
	if r.SchemaVersion != "1" || !safeID.MatchString(r.ID) || r.Version < 1 || !safeID.MatchString(r.TenantID) || !safeID.MatchString(r.ReadBindingID) {
		return errors.New("INVENTORY_REGISTRATION_INVALID")
	}
	var scopes []string
	switch r.Provider {
	case "AZURE":
		if r.Azure == nil || r.GCP != nil {
			return errors.New("AZURE_INVENTORY_SCOPE_REQUIRED")
		}
		a := r.Azure
		if !guid.MatchString(a.DirectoryTenantID) || !guid.MatchString(a.SubscriptionID) || !regexp.MustCompile(`^[A-Za-z0-9_().-]{1,90}$`).MatchString(a.ResourceGroup) || strings.HasSuffix(a.ResourceGroup, ".") {
			return errors.New("AZURE_INVENTORY_SCOPE_INVALID")
		}
		scopes = a.Locations
		for _, v := range scopes {
			if !regexp.MustCompile(`^[a-z][a-z0-9]{1,39}$`).MatchString(v) {
				return errors.New("AZURE_LOCATION_SCOPE_INVALID")
			}
		}
	case "GCP":
		if r.GCP == nil || r.Azure != nil || !gcpProject.MatchString(r.GCP.ProjectID) {
			return errors.New("GCP_INVENTORY_SCOPE_INVALID")
		}
		scopes = r.GCP.Zones
		for _, v := range scopes {
			if !regexp.MustCompile(`^[a-z]+-[a-z]+[0-9]+-[a-z]$`).MatchString(v) {
				return errors.New("GCP_ZONE_SCOPE_INVALID")
			}
		}
	default:
		return errors.New("INVENTORY_PROVIDER_UNSUPPORTED")
	}
	if len(scopes) == 0 || len(scopes) > 32 {
		return errors.New("INVENTORY_SCOPE_LIMIT")
	}
	seen := map[string]bool{}
	for _, v := range scopes {
		if seen[v] {
			return errors.New("INVENTORY_DUPLICATE_SCOPE")
		}
		seen[v] = true
	}
	return nil
}
func (c Config) validateInventory(r InventoryRegistration) error {
	if e := ValidateInventory(r); e != nil {
		return e
	}
	if c.HTTP == nil || c.Tokens == nil || c.Binding.ID != r.ReadBindingID || c.Binding.TenantID != r.TenantID || c.Binding.Provider != r.Provider || c.Binding.ScopeHash != InventoryScopeHash(r) {
		return errors.New("INVENTORY_READ_BINDING_MISMATCH")
	}
	if r.Azure != nil && !strings.EqualFold(c.Binding.DirectoryTenantID, r.Azure.DirectoryTenantID) {
		return errors.New("AZURE_DIRECTORY_BINDING_MISMATCH")
	}
	return nil
}
func newInventory(r InventoryRegistration, now time.Time) InventorySnapshot {
	return InventorySnapshot{SchemaVersion: "multicloud-inventory-1", RegistrationID: r.ID, RegistrationVersion: r.Version, ConfigHash: Hash(r), TenantID: r.TenantID, Provider: r.Provider, Status: "PROVISIONAL", ObservedAt: now, Objects: []Object{}, Instances: []Instance{}, ReasonCodes: []string{"NO_EXECUTION_AUTHORITY", "CONFIGURATION_AUTHORITY_UNPROVEN", "OS_LICENSE_COMPATIBILITY_UNPROVEN", "RESOURCE_COST_UNKNOWN"}}
}
func sealInventory(s InventorySnapshot) InventorySnapshot {
	s.ReasonCodes = unique(s.ReasonCodes)
	for i := range s.Instances {
		s.Instances[i].Blockers = unique(s.Instances[i].Blockers)
	}
	copy := s
	copy.ObservedAt = time.Time{}
	copy.Revision = ""
	copy.Instances = append([]Instance{}, s.Instances...)
	for i := range copy.Instances {
		copy.Instances[i].ObservedAt = time.Time{}
	}
	s.Revision = Hash(copy)
	return s
}
func inventoryObject(s *InventorySnapshot, o Object) error {
	var total int64
	for _, old := range s.Objects {
		total += old.Bytes
	}
	if len(s.Objects) >= 2000 || total+o.Bytes > MaxCollectionBytes {
		return errors.New("INVENTORY_COLLECTION_LIMIT")
	}
	s.Objects = append(s.Objects, o)
	return nil
}
func contains(in []string, s string) bool {
	for _, v := range in {
		if v == s {
			return true
		}
	}
	return false
}

type AzureInventoryReader struct{ Config Config }
type GCPInventoryReader struct{ Config Config }
type InventoryReader interface {
	Collect(context.Context, InventoryRegistration) (InventorySnapshot, error)
}
