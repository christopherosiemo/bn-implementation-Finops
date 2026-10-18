package multicloud

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var gceName = regexp.MustCompile(`^[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

func numericInstanceID(s string) bool {
	v, e := strconv.ParseUint(s, 10, 64)
	return e == nil && v > 0 && strconv.FormatUint(v, 10) == s
}
func googleInstanceLink(raw, project string) (zone, name string, valid bool) {
	u, e := url.Parse(raw)
	if e != nil || u.Scheme != "https" || (u.Host != "compute.googleapis.com" && u.Host != "www.googleapis.com") || u.User != nil || u.Port() != "" || u.RawQuery != "" || u.Fragment != "" {
		return "", "", false
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) != 8 || parts[0] != "compute" || parts[1] != "v1" || parts[2] != "projects" || parts[3] != project || parts[4] != "zones" || !regexp.MustCompile(`^[a-z]+-[a-z]+[0-9]+-[a-z]$`).MatchString(parts[5]) || parts[6] != "instances" || !gceName.MatchString(parts[7]) {
		return "", "", false
	}
	return parts[5], parts[7], true
}
func (g GCPInventoryReader) Collect(ctx context.Context, r InventoryRegistration) (InventorySnapshot, error) {
	c := g.Config
	if e := c.validateInventory(r); e != nil {
		return InventorySnapshot{}, e
	}
	if r.Provider != "GCP" {
		return InventorySnapshot{}, errors.New("GCP_INVENTORY_SCOPE_REQUIRED")
	}
	s := newInventory(r, c.now())
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	scope := r.GCP
	byName := map[string]int{}
	pages := func(method, address, kind, field string) ([]Document, error) {
		values := []Document{}
		tokens := map[string]bool{}
		for page := 0; ; page++ {
			if page >= 1000 {
				return nil, errors.New("GCP_INVENTORY_PAGE_LIMIT")
			}
			o, d, e := c.nativeRead(ctx, method, address, computeScope)
			if e != nil {
				return nil, e
			}
			o.Kind = kind
			if e = inventoryObject(&s, o); e != nil {
				return nil, e
			}
			if len(list(d["unreachables"])) > 0 || (len(obj(d["warning"])) > 0 && str(obj(d["warning"]), "code") != "NO_RESULTS_ON_PAGE") {
				return nil, errors.New("GCP_INVENTORY_PARTIAL_RESULT")
			}
			for _, x := range list(d[field]) {
				if len(values) >= 1000 {
					return nil, errors.New("INVENTORY_INSTANCE_LIMIT")
				}
				values = append(values, obj(x))
			}
			token := str(d, "nextPageToken")
			if token == "" {
				return values, nil
			}
			if len(token) > 4096 || tokens[token] {
				return nil, errors.New("GCP_INVENTORY_PAGINATION_INVALID")
			}
			tokens[token] = true
			u, _ := url.Parse(address)
			q := u.Query()
			q.Set("pageToken", token)
			u.RawQuery = q.Encode()
			address = u.String()
		}
	}
	regions := []string{}
	for _, zone := range scope.Zones {
		instances, e := pages(http.MethodGet, computeAPI+"/projects/"+scope.ProjectID+"/zones/"+zone+"/instances?maxResults=500", "GCP_INSTANCE_LIST", "items")
		if e != nil {
			return s, e
		}
		for _, native := range instances {
			instance, e := ParseGCPInstance(r, zone, native, c.now())
			if e != nil {
				return s, e
			}
			key := zone + "/" + instance.Identity.Name
			if _, ok := byName[key]; ok {
				return s, errors.New("GCP_INSTANCE_DUPLICATE")
			}
			if len(s.Instances) >= 1000 {
				return s, errors.New("INVENTORY_INSTANCE_LIMIT")
			}
			byName[key] = len(s.Instances)
			s.Instances = append(s.Instances, instance)
		}
		region := zone[:strings.LastIndex(zone, "-")]
		if !contains(regions, region) {
			regions = append(regions, region)
		}
	}
	type groupScope struct{ kind, name string }
	groups := []groupScope{}
	for _, zone := range scope.Zones {
		groups = append(groups, groupScope{"zones", zone})
	}
	for _, region := range regions {
		groups = append(groups, groupScope{"regions", region})
	}
	for _, location := range groups {
		base := computeAPI + "/projects/" + scope.ProjectID + "/" + location.kind + "/" + location.name + "/instanceGroupManagers"
		managers, e := pages(http.MethodGet, base+"?maxResults=500", "GCP_MIG_LIST", "items")
		if e != nil {
			return s, e
		}
		seen := map[string]bool{}
		for _, manager := range managers {
			name := str(manager, "name")
			if !gceName.MatchString(name) || !googleLink(str(manager, "selfLink"), scope.ProjectID, location.kind, location.name, "instanceGroupManagers", name) || seen[name] {
				return s, errors.New("GCP_MIG_SCOPE_INVALID")
			}
			seen[name] = true
			members, e := pages(http.MethodPost, base+"/"+name+"/listManagedInstances?maxResults=500", "GCP_MIG_MEMBERS", "managedInstances")
			if e != nil {
				return s, e
			}
			for _, member := range members {
				zone, instanceName, valid := googleInstanceLink(str(member, "instance"), scope.ProjectID)
				if !valid {
					return s, errors.New("GCP_MIG_MEMBER_SCOPE_INVALID")
				}
				if location.kind == "zones" && zone != location.name || location.kind == "regions" && !strings.HasPrefix(zone, location.name+"-") {
					return s, errors.New("GCP_MIG_MEMBER_LOCATION_INVALID")
				}
				if !contains(scope.Zones, zone) {
					continue
				}
				index, ok := byName[zone+"/"+instanceName]
				if !ok {
					s.ReasonCodes = append(s.ReasonCodes, "GCP_MIG_MEMBER_INVENTORY_RACE")
					continue
				}
				instance := &s.Instances[index]
				if id := str(member, "id"); !numericInstanceID(id) || id != instance.Identity.NumericID {
					return s, errors.New("GCP_MIG_MEMBER_INSTANCE_CHANGED")
				}
				instance.ManagedAuthority = "MIG"
				filtered := []string{}
				for _, reason := range instance.Blockers {
					if reason != "MANAGED_AUTHORITY_UNKNOWN" {
						filtered = append(filtered, reason)
					}
				}
				instance.Blockers = filtered
				instance.ManagedReferences = append(instance.ManagedReferences, str(manager, "selfLink"))
				instance.Blockers = append(instance.Blockers, "GCP_MIG_MANAGED")
			}
		}
	}
	return sealInventory(s), nil
}
func ParseGCPInstance(r InventoryRegistration, zone string, native Document, now time.Time) (Instance, error) {
	if e := ValidateInventory(r); e != nil {
		return Instance{}, e
	}
	if r.GCP == nil || !contains(r.GCP.Zones, zone) {
		return Instance{}, errors.New("GCP_INSTANCE_SCOPE_INVALID")
	}
	project := r.GCP.ProjectID
	name, id := str(native, "name"), str(native, "id")
	if !gceName.MatchString(name) || !numericInstanceID(id) || !googleLink(str(native, "selfLink"), project, "zones", zone, "instances", name) || str(native, "zone") != "https://www.googleapis.com/compute/v1/projects/"+project+"/zones/"+zone && str(native, "zone") != "https://compute.googleapis.com/compute/v1/projects/"+project+"/zones/"+zone {
		return Instance{}, errors.New("GCP_INSTANCE_IDENTITY_INVALID")
	}
	created := optionalTime(str(native, "creationTimestamp"))
	if created != nil && created.After(now.Add(5*time.Second)) {
		return Instance{}, errors.New("GCP_INSTANCE_TIME_INVALID")
	}
	machine := str(native, "machineType")
	parts := strings.Split(machine, "/")
	machineName := parts[len(parts)-1]
	if !gceName.MatchString(machineName) || !googleLink(machine, project, "zones", zone, "machineTypes", machineName) {
		return Instance{}, errors.New("GCP_MACHINE_TYPE_SCOPE_INVALID")
	}
	safeImage := Document{}
	licenses := []string{}
	for _, x := range list(native["disks"]) {
		disk := obj(x)
		if boolean(disk, "boot") {
			for _, v := range list(disk["licenses"]) {
				if license, ok := v.(string); ok {
					licenses = append(licenses, license)
				}
			}
			safeImage["boot_disk_source"] = str(disk, "source")
			safeImage["licenses"] = licenses
		}
	}
	instance := Instance{Identity: InstanceIdentity{Provider: "GCP", TenantID: r.TenantID, ProjectID: project, Zone: zone, NumericID: id, Name: name, ResourceID: "//compute.googleapis.com/projects/" + project + "/zones/" + zone + "/instances/" + name}, Location: zone[:strings.LastIndex(zone, "-")], InstanceType: machineName, State: str(native, "status"), ObservedAt: now, ProviderCreatedAt: created, Tags: obj(native["labels"]), Image: safeImage, ManagedAuthority: "UNKNOWN", ManagedReferences: []string{}, Blockers: []string{"CONFIGURATION_AUTHORITY_UNPROVEN", "MANAGED_AUTHORITY_UNKNOWN", "OS_LICENSE_COMPATIBILITY_UNPROVEN", "OS_UNKNOWN", "ARCHITECTURE_UNKNOWN", "RESOURCE_COST_UNKNOWN"}, Native: native}
	if created == nil {
		instance.Blockers = append(instance.Blockers, "PROVIDER_CREATION_TIME_UNKNOWN")
	}
	if instance.State == "" {
		instance.State = "UNKNOWN"
		instance.Blockers = append(instance.Blockers, "POWER_STATE_UNKNOWN")
	}
	return instance, nil
}
