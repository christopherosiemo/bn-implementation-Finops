package multicloud

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

func inventoryRegistration(provider string) InventoryRegistration {
	r := InventoryRegistration{SchemaVersion: "1", ID: "inventory-a", Version: 1, TenantID: "tenant-a", ReadBindingID: "native-reader", Provider: provider}
	if provider == "AZURE" {
		r.Azure = &AzureInventoryScope{DirectoryTenantID: directory, SubscriptionID: subscription, ResourceGroup: "finops", Locations: []string{"westeurope"}}
	} else {
		r.GCP = &GCPInventoryScope{ProjectID: "usage-project", Zones: []string{"europe-west1-b"}}
	}
	return r
}
func inventoryConfig(r InventoryRegistration, rt roundTripFunc) Config {
	b := ReadBinding{ID: r.ReadBindingID, TenantID: r.TenantID, Provider: r.Provider, ScopeHash: InventoryScopeHash(r)}
	if r.Azure != nil {
		b.DirectoryTenantID = r.Azure.DirectoryTenantID
	}
	return Config{HTTP: &http.Client{Transport: rt}, Binding: b, Now: func() time.Time { return testNow }, Tokens: TokenFunc(func(_ context.Context, scope string) (string, error) { return "test-machine-token", nil })}
}
func azureNativeInstance(r InventoryRegistration) Document {
	id := "/subscriptions/" + r.Azure.SubscriptionID + "/resourceGroups/" + r.Azure.ResourceGroup + "/providers/Microsoft.Compute/virtualMachines/vm-a"
	return Document{"id": id, "name": "vm-a", "type": "Microsoft.Compute/virtualMachines", "location": "westeurope", "tags": Document{"owner": "app-a", "environment": "NON_PRODUCTION"}, "properties": Document{"vmId": runID, "timeCreated": "2026-09-01T00:00:00Z", "hardwareProfile": Document{"vmSize": "Standard_D2s_v5"}, "licenseType": "Windows_Server", "storageProfile": Document{"osDisk": Document{"osType": "Windows"}, "imageReference": Document{"publisher": "MicrosoftWindowsServer", "offer": "WindowsServer", "sku": "2022-datacenter", "version": "latest"}}, "osProfile": Document{"adminPassword": "never-public"}}}
}
func gcpNativeInstance(r InventoryRegistration) Document {
	project, zone := r.GCP.ProjectID, r.GCP.Zones[0]
	return Document{"kind": "compute#instance", "id": "18446744073709551614", "name": "vm-a", "selfLink": "https://www.googleapis.com/compute/v1/projects/" + project + "/zones/" + zone + "/instances/vm-a", "zone": "https://www.googleapis.com/compute/v1/projects/" + project + "/zones/" + zone, "creationTimestamp": "2026-09-01T00:00:00Z", "machineType": "https://www.googleapis.com/compute/v1/projects/" + project + "/zones/" + zone + "/machineTypes/e2-standard-2", "status": "RUNNING", "labels": Document{"owner": "app-a"}, "disks": []any{Document{"boot": true, "source": "https://www.googleapis.com/compute/v1/projects/usage-project/zones/europe-west1-b/disks/boot", "licenses": []any{"https://www.googleapis.com/compute/v1/projects/windows-cloud/global/licenses/windows-server-2022-dc"}}}, "metadata": Document{"items": []any{Document{"key": "startup-script", "value": "never-public"}}}}
}

func TestInventoryIdentityAndUnknownMoneyDoNotCreateAuthority(t *testing.T) {
	for _, provider := range []string{"AZURE", "GCP"} {
		t.Run(provider, func(t *testing.T) {
			r := inventoryRegistration(provider)
			var instance Instance
			var e error
			if provider == "AZURE" {
				instance, e = ParseAzureInstance(r, azureNativeInstance(r), Document{"statuses": []any{Document{"code": "PowerState/running"}}}, testNow)
			} else {
				instance, e = ParseGCPInstance(r, r.GCP.Zones[0], gcpNativeInstance(r), testNow)
			}
			if e != nil {
				t.Fatal(e)
			}
			if instance.HourlyCost != nil || instance.Currency != nil || instance.Architecture != "" || instance.ManagedAuthority != "UNKNOWN" || !hasReason(instance.Blockers, "OS_LICENSE_COMPATIBILITY_UNPROVEN") {
				t.Fatal("unknown facts inferred", instance)
			}
			raw, _ := json.Marshal(instance)
			if strings.Contains(string(raw), "never-public") || strings.Contains(string(raw), "startup-script") {
				t.Fatal("private raw instance metadata leaked")
			}
			if instance.Native == nil {
				t.Fatal("native configuration discarded")
			}
		})
	}
}
func TestInventoryScopeAndRecreatedInstanceBindings(t *testing.T) {
	r := inventoryRegistration("AZURE")
	native := azureNativeInstance(r)
	native["id"] = strings.Replace(str(native, "id"), subscription, directory, 1)
	_, e := ParseAzureInstance(r, native, Document{}, testNow)
	wantError(t, e, "IDENTITY_INVALID")
	r = inventoryRegistration("GCP")
	native = gcpNativeInstance(r)
	native["id"] = json.Number("18446744073709551614")
	_, e = ParseGCPInstance(r, r.GCP.Zones[0], native, testNow)
	wantError(t, e, "IDENTITY_INVALID")
	native = gcpNativeInstance(r)
	native["selfLink"] = "https://evil.test/compute/v1/projects/usage-project/zones/europe-west1-b/instances/vm-a"
	_, e = ParseGCPInstance(r, r.GCP.Zones[0], native, testNow)
	wantError(t, e, "IDENTITY_INVALID")
	c := inventoryConfig(r, func(*http.Request) (*http.Response, error) { t.Fatal("retargeted call dispatched"); return nil, nil })
	copy := *r.GCP
	copy.ProjectID = "other-project"
	r.GCP = &copy
	wantError(t, c.validateInventory(r), "READ_BINDING_MISMATCH")
}

type inventoryDouble struct {
	t        *testing.T
	r        InventoryRegistration
	mutation string
	posts    int
	calls    int
}

func (d *inventoryDouble) transport(req *http.Request) (*http.Response, error) {
	d.calls++
	if req.Header.Get("Authorization") != "Bearer test-machine-token" {
		d.t.Fatal("identity absent")
	}
	if d.r.Azure != nil {
		native := azureNativeInstance(d.r)
		if strings.HasSuffix(req.URL.Path, "/instanceView") {
			return response(200, wire(d.t, Document{"statuses": []any{Document{"code": "PowerState/running"}}}), nil), nil
		}
		if strings.HasSuffix(req.URL.Path, "/virtualMachines") {
			if req.URL.Query().Get("page") == "2" {
				return response(200, wire(d.t, Document{"value": []any{native}}), nil), nil
			}
			next := "https://management.azure.com" + req.URL.Path + "?page=2"
			if d.mutation == "next" {
				next = "https://evil.test/virtualMachines"
			}
			return response(200, wire(d.t, Document{"value": []any{}, "nextLink": next}), nil), nil
		}
		if d.mutation == "recreate" {
			obj(native["properties"])["vmId"] = directory
		}
		if d.mutation == "vmss" {
			obj(native["properties"])["virtualMachineScaleSet"] = Document{"id": "/subscriptions/" + subscription + "/resourceGroups/finops/providers/Microsoft.Compute/virtualMachineScaleSets/group-a"}
		}
		return response(200, wire(d.t, native), nil), nil
	}
	native := gcpNativeInstance(d.r)
	if strings.HasSuffix(req.URL.Path, "/instances") {
		return response(200, wire(d.t, Document{"items": []any{native}}), nil), nil
	}
	if strings.HasSuffix(req.URL.Path, "/listManagedInstances") {
		d.posts++
		if req.Method != http.MethodPost {
			d.t.Fatal("native membership method changed")
		}
		id := str(native, "id")
		if d.mutation == "member" {
			id = "123"
		}
		return response(200, wire(d.t, Document{"managedInstances": []any{Document{"id": id, "instance": native["selfLink"], "currentAction": "NONE"}}}), nil), nil
	}
	if strings.HasSuffix(req.URL.Path, "/instanceGroupManagers") {
		regional := strings.Contains(req.URL.Path, "/regions/")
		if regional && d.mutation != "regional" || !regional && d.mutation == "regional" {
			return response(200, wire(d.t, Document{"items": []any{}}), nil), nil
		}
		link := "https://www.googleapis.com" + req.URL.Path + "/group-a"
		if d.mutation == "link" {
			link = "https://evil.test/group-a"
		}
		return response(200, wire(d.t, Document{"items": []any{Document{"name": "group-a", "selfLink": link}}}), nil), nil
	}
	d.t.Fatalf("unexpected path %s", req.URL.Path)
	return nil, nil
}
func TestNativeRegionalMIGMembershipAndRedirectFence(t *testing.T) {
	r := inventoryRegistration("GCP")
	d := &inventoryDouble{t: t, r: r, mutation: "regional"}
	s, e := (GCPInventoryReader{Config: inventoryConfig(r, d.transport)}).Collect(context.Background(), r)
	if e != nil || s.Instances[0].ManagedAuthority != "MIG" || d.posts != 1 || !strings.Contains(s.Instances[0].ManagedReferences[0], "/regions/europe-west1/") {
		t.Fatal("regional native membership missing", s, e)
	}
	calls := 0
	c := inventoryConfig(r, func(req *http.Request) (*http.Response, error) {
		calls++
		return response(302, nil, map[string]string{"Location": "https://evil.test/"}), nil
	})
	_, _, e = c.nativeRead(context.Background(), http.MethodGet, computeAPI+"/projects/usage-project/zones/europe-west1-b/instances", computeScope)
	wantError(t, e, "PROVIDER_REJECTED")
	if calls != 1 {
		t.Fatal("redirect forwarded native machine token")
	}
}
func TestNativeInventoryHTTPJourneysAndManagedGuards(t *testing.T) {
	for _, provider := range []string{"AZURE", "GCP"} {
		t.Run(provider, func(t *testing.T) {
			r := inventoryRegistration(provider)
			d := &inventoryDouble{t: t, r: r}
			if provider == "AZURE" {
				d.mutation = "vmss"
			}
			c := inventoryConfig(r, d.transport)
			var s InventorySnapshot
			var e error
			if provider == "AZURE" {
				s, e = (AzureInventoryReader{Config: c}).Collect(context.Background(), r)
			} else {
				s, e = (GCPInventoryReader{Config: c}).Collect(context.Background(), r)
			}
			if e != nil {
				t.Fatal(e)
			}
			if s.ExecutionReady() || len(s.Instances) != 1 || s.Instances[0].HourlyCost != nil {
				t.Fatal("inventory conferred authority")
			}
			want := "VMSS"
			if provider == "GCP" {
				want = "MIG"
				if d.posts != 1 {
					t.Fatal("membership evidence missing")
				}
			}
			if s.Instances[0].ManagedAuthority != want {
				t.Fatal(s.Instances[0])
			}
			for _, o := range s.Objects {
				if o.SHA256 != BytesHash(o.Body) {
					t.Fatal("raw hash lost")
				}
			}
		})
	}
}
func TestNativeInventoryHTTPFailsClosed(t *testing.T) {
	for mutation, code := range map[string]string{"next": "NEXT_LINK_INVALID", "recreate": "CHANGED_DURING_READ", "link": "MIG_SCOPE_INVALID", "member": "INSTANCE_CHANGED"} {
		t.Run(mutation, func(t *testing.T) {
			provider := "GCP"
			if mutation == "next" || mutation == "recreate" {
				provider = "AZURE"
			}
			r := inventoryRegistration(provider)
			d := &inventoryDouble{t: t, r: r, mutation: mutation}
			c := inventoryConfig(r, d.transport)
			var e error
			if provider == "AZURE" {
				_, e = (AzureInventoryReader{Config: c}).Collect(context.Background(), r)
			} else {
				_, e = (GCPInventoryReader{Config: c}).Collect(context.Background(), r)
			}
			wantError(t, e, code)
		})
	}
}
func TestNativeInventoryMethodGuardDeniesExecution(t *testing.T) {
	r := inventoryRegistration("GCP")
	calls := 0
	c := inventoryConfig(r, func(*http.Request) (*http.Response, error) { calls++; return response(200, []byte(`{}`), nil), nil })
	for _, method := range []string{"POST", "PUT", "PATCH", "DELETE"} {
		_, _, e := c.nativeRead(context.Background(), method, computeAPI+"/projects/usage-project/zones/europe-west1-b/instances/vm-a/stop", computeScope)
		wantError(t, e, "METHOD_NOT_ALLOWED")
	}
	if calls != 0 {
		t.Fatal("execution verb dispatched")
	}
}
