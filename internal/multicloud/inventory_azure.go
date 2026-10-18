package multicloud

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const azureComputeAPI = "2025-04-01"

func (a AzureInventoryReader) Collect(ctx context.Context, r InventoryRegistration) (InventorySnapshot, error) {
	c := a.Config
	if e := c.validateInventory(r); e != nil {
		return InventorySnapshot{}, e
	}
	if r.Provider != "AZURE" {
		return InventorySnapshot{}, errors.New("AZURE_INVENTORY_SCOPE_REQUIRED")
	}
	s := newInventory(r, c.now())
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	scope := r.Azure
	listPath := "/subscriptions/" + scope.SubscriptionID + "/resourceGroups/" + scope.ResourceGroup + "/providers/Microsoft.Compute/virtualMachines"
	address := "https://management.azure.com" + listPath + "?api-version=" + azureComputeAPI
	seen := map[string]bool{}
	identities := map[string]bool{}
	for page := 0; address != ""; page++ {
		if page >= 1000 || seen[address] {
			return s, errors.New("AZURE_INVENTORY_PAGINATION_INVALID")
		}
		seen[address] = true
		o, d, e := c.nativeRead(ctx, http.MethodGet, address, armScope)
		if e != nil {
			return s, e
		}
		o.Kind = "AZURE_VM_LIST"
		if e = inventoryObject(&s, o); e != nil {
			return s, e
		}
		for _, raw := range list(d["value"]) {
			listed := obj(raw)
			id := str(listed, "id")
			name := str(listed, "name")
			if !azureInstancePath(r, id, name) {
				return s, errors.New("AZURE_INSTANCE_IDENTITY_INVALID")
			}
			if identities[strings.ToLower(id)] {
				return s, errors.New("AZURE_INSTANCE_DUPLICATE")
			}
			identities[strings.ToLower(id)] = true
			if len(identities) > 1000 {
				return s, errors.New("INVENTORY_INSTANCE_LIMIT")
			}
			o, detail, e := c.nativeRead(ctx, http.MethodGet, "https://management.azure.com"+id+"?api-version="+azureComputeAPI, armScope)
			if e != nil {
				return s, e
			}
			o.Kind = "AZURE_VM_DETAIL"
			if e = inventoryObject(&s, o); e != nil {
				return s, e
			}
			if !strings.EqualFold(str(detail, "id"), id) || str(obj(listed["properties"]), "vmId") != str(obj(detail["properties"]), "vmId") {
				return s, errors.New("AZURE_INSTANCE_CHANGED_DURING_READ")
			}
			o, view, e := c.nativeRead(ctx, http.MethodGet, "https://management.azure.com"+id+"/instanceView?api-version="+azureComputeAPI, armScope)
			if e != nil {
				return s, e
			}
			o.Kind = "AZURE_VM_INSTANCE_VIEW"
			if e = inventoryObject(&s, o); e != nil {
				return s, e
			}
			instance, e := ParseAzureInstance(r, detail, view, c.now())
			if e != nil {
				return s, e
			}
			s.Instances = append(s.Instances, instance)
		}
		next := str(d, "nextLink")
		if next != "" {
			if e = nextNativeLink(next, "management.azure.com", listPath); e != nil {
				return s, e
			}
		}
		address = next
	}
	return sealInventory(s), nil
}
func azureInstancePath(r InventoryRegistration, id, name string) bool {
	return r.Azure != nil && regexpVMName(name) && strings.EqualFold(id, "/subscriptions/"+r.Azure.SubscriptionID+"/resourceGroups/"+r.Azure.ResourceGroup+"/providers/Microsoft.Compute/virtualMachines/"+name)
}
func regexpVMName(s string) bool {
	return len(s) > 0 && len(s) <= 64 && !strings.HasSuffix(s, ".") && !strings.ContainsAny(s, "/\\%?#\x00\r\n") && url.PathEscape(s) == s
}
func ParseAzureInstance(r InventoryRegistration, native, view Document, now time.Time) (Instance, error) {
	if e := ValidateInventory(r); e != nil {
		return Instance{}, e
	}
	if r.Azure == nil {
		return Instance{}, errors.New("AZURE_INVENTORY_SCOPE_REQUIRED")
	}
	p := obj(native["properties"])
	name, id := str(native, "name"), str(native, "id")
	if !azureInstancePath(r, id, name) || !guid.MatchString(str(p, "vmId")) || !strings.EqualFold(str(native, "type"), "Microsoft.Compute/virtualMachines") || !contains(r.Azure.Locations, str(native, "location")) {
		return Instance{}, errors.New("AZURE_INSTANCE_IDENTITY_INVALID")
	}
	created := optionalTime(str(p, "timeCreated"))
	if created != nil && created.After(now.Add(5*time.Second)) {
		return Instance{}, errors.New("AZURE_INSTANCE_TIME_INVALID")
	}
	storage := obj(p["storageProfile"])
	osDisk := obj(storage["osDisk"])
	os := str(osDisk, "osType")
	image := obj(storage["imageReference"])
	safeImage := Document{}
	for _, key := range []string{"id", "publisher", "offer", "sku", "version", "exactVersion", "communityGalleryImageId", "sharedGalleryImageId"} {
		if v := str(image, key); v != "" {
			safeImage[key] = v
		}
	}
	instance := Instance{Identity: InstanceIdentity{Provider: "AZURE", TenantID: r.TenantID, SubscriptionID: r.Azure.SubscriptionID, ResourceID: id, VMID: str(p, "vmId"), Name: name}, Location: str(native, "location"), InstanceType: str(obj(p["hardwareProfile"]), "vmSize"), State: "UNKNOWN", ObservedAt: now, ProviderCreatedAt: created, Tags: obj(native["tags"]), OS: os, LicenseType: str(p, "licenseType"), Image: safeImage, ManagedAuthority: "UNKNOWN", ManagedReferences: []string{}, Blockers: []string{"CONFIGURATION_AUTHORITY_UNPROVEN", "OS_LICENSE_COMPATIBILITY_UNPROVEN", "ARCHITECTURE_UNKNOWN", "RESOURCE_COST_UNKNOWN"}, Native: native}
	seenPower := false
	for _, v := range list(view["statuses"]) {
		code := str(obj(v), "code")
		if strings.HasPrefix(code, "PowerState/") {
			if seenPower {
				return Instance{}, errors.New("AZURE_POWER_STATE_AMBIGUOUS")
			}
			instance.State = strings.TrimPrefix(code, "PowerState/")
			seenPower = true
		}
	}
	if reference := str(obj(p["virtualMachineScaleSet"]), "id"); reference != "" {
		prefix := "/subscriptions/" + r.Azure.SubscriptionID + "/resourceGroups/"
		if !strings.HasPrefix(strings.ToLower(reference), strings.ToLower(prefix)) || !strings.Contains(strings.ToLower(reference), "/providers/microsoft.compute/virtualmachinescalesets/") {
			return Instance{}, errors.New("AZURE_VMSS_SCOPE_INVALID")
		}
		instance.ManagedAuthority = "VMSS"
		instance.ManagedReferences = append(instance.ManagedReferences, reference)
		instance.Blockers = append(instance.Blockers, "AZURE_VMSS_MANAGED")
	} else {
		instance.Blockers = append(instance.Blockers, "MANAGED_AUTHORITY_UNKNOWN")
	}
	if created == nil {
		instance.Blockers = append(instance.Blockers, "PROVIDER_CREATION_TIME_UNKNOWN")
	}
	if os != "Linux" && os != "Windows" {
		instance.Blockers = append(instance.Blockers, "OS_UNKNOWN")
	}
	if instance.State == "UNKNOWN" {
		instance.Blockers = append(instance.Blockers, "POWER_STATE_UNKNOWN")
	}
	return instance, nil
}
