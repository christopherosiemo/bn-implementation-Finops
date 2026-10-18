# Read-only native inventory and metrics

This is a separate adapter component alongside the provisional billing readers.
It has no application route, credential discovery, object/analytics publisher,
database write, execution client or customer-account deployment. Local acceptance
uses native-shaped HTTP doubles with Docker network disabled. It does not certify
a live Azure or GCP account, authorize a VM change, or prove application health.

`InventoryRegistration` schema `1` binds a tenant/read binding to an Azure
directory, subscription, resource group and location list, or a GCP project and
zone list. `InventoryScopeHash` covers that complete scope and is mandatory in
the server credential registry. A billing scope hash cannot be reused. Tokens
are supplied by server-owned `TokenSource`; configured clients must preserve
normal TLS validation and provider egress controls. Customer wiring and identity
commissioning remain separate authorized work.

`AzureInventoryReader.Collect` reads paginated resource-group VMs, individual
native VM details and instance views using Compute API `2025-04-01`. It checks
the exact subscription/resource-group/resource ID, name, native `vmId`, location,
creation time and list/detail identity agreement. VMSS references remain managed
blockers. `GCPInventoryReader.Collect` reads each registered zone's VMs, zonal
managers and regional managers for those zones, then their native memberships.
Native GCP identity binds project, zone, full instance selfLink, name and uint64
numeric ID as a string. Numeric IDs are not converted to floating point.

MIG membership uses Google's documented read-only `listManagedInstances` POST.
The only POST accepted by this component is that exact reconstructed method;
there are no start, stop, update, delete or resize calls. Native selfLinks are
validated against the registered project/zone or corresponding region and are
never followed as arbitrary URLs. Member IDs must match discovered VM IDs.
Both known managed members and unknown configuration authority block execution.
Absence from a MIG/VMSS is not treated as delegation or proof of unmanaged IaC.

Inventory preserves raw original response hashes and private bodies. Public
instance fields retain tags, native image/license metadata, timestamps and
provider state. Full native VM configuration is private (`Native` and object
bodies are excluded from JSON), so guest startup scripts and OS-profile secrets
cannot become ordinary inventory-preview fields. OS/license compatibility and
architecture remain explicit unknown blockers. Hourly cost and currency are
nullable and remain unavailable; instance names do not imply a price.

## Native telemetry contract

`MetricsRequest` pins a discovered `InstanceIdentity`, exact period and a bounded
native metric list. A reader re-fetches the native VM and checks the unique
instance ID before querying metrics. History predating the current VM creation
is rejected, including reuse of an Azure resource ID or GCP instance name.

`AzureMetricsReader` validates native metric definitions, unit, aggregation and
supported time grain. It explicitly disables automatic time-grain adjustment.
CPU is `INTERVAL_MAXIMUM`; memory and IOPS are interval averages; network/disk
bytes are interval totals. Native responses must echo the resource, namespace,
region, time span, interval and requested aggregation. A maximum is never a
percentile, and no CPU/memory distribution is inferred from it.

`GCPMetricsReader` validates each native descriptor's type, kind, unit and value
type, and requests Monitoring `FULL` raw series with no alignment or reducer.
Every series must bind the project, zone and numeric instance ID. All original
resource/metric labels remain distinct stream attributes. CPU keeps its native
`10^2.%` fractional unit; this package does not silently rescale it. The bounded
catalog includes native CPU, disk and network metrics plus agent memory metrics;
agent installation and actual evidence availability are not inferred.

`MetricPoint` preserves actual native end/start times, scalar decimal/int64 text,
epochs, null values and source hashes. Cumulative epochs may predate the query
window. `EpochChanges` exposes reset boundaries without deriving interval counts.
Delta intervals that start before the requested window remain explicitly marked.
Native explicit histograms preserve finite bounds and exact non-cumulative bucket
counts (including values beyond JavaScript's safe integer range); the sum must
match the native count. Unsupported bucket formats and ambiguous/invalid native
values fail closed. No percentiles are calculated here. Equal overlapping native
points merge provenance; conflicting values at the same point identity reject
the snapshot rather than blending corrections into a population.

True zero and missing samples remain distinct. No query-success watermark,
coverage percentage, held value, extrapolated counter, missing zero or demand
signal is fabricated. Snapshot coverage is always `UNKNOWN`, status is
`PROVISIONAL`, and execution readiness is always false. Publication, immutable
receipt/provenance authority, historical coverage evaluation, independent
workload/SLO evidence and capacity integration remain pending.

`WarehouseDecimal` is a future sink guard: it returns unavailable plus
`WAREHOUSE_DECIMAL_PRECISION_UNSUPPORTED` when an exact native value cannot fit
`DECIMAL(38,12)`. The original source text is retained, never rounded. Billing
native strings and currencies stay separate from warehouse projections.

## Acceptance and primary references

Run `go test ./internal/multicloud` and `go vet ./internal/multicloud`. The
provider-shaped journeys cover Azure pagination/detail/instance view and metric
definitions/results, GCP zonal/regional MIG membership and raw Monitoring pages,
scope and recreated-instance rejection, redirect/mutation fences, native unit/
aggregation mismatch, missing versus zero, raw epochs and exact histogram counts.
Source bodies are bounded; unexpected partial results, cycles and source identity
changes fail instead of yielding silently truncated evidence.

- [Azure VM list and native fields](https://learn.microsoft.com/en-us/rest/api/compute/virtual-machines/list?view=rest-compute-2025-04-01)
- [Azure native metric semantics](https://learn.microsoft.com/en-us/azure/virtual-machines/monitor-vm-reference) and [Metrics List](https://learn.microsoft.com/en-us/rest/api/monitor/metrics/list?view=rest-monitor-2023-10-01)
- [GCP VM native identity](https://docs.cloud.google.com/compute/docs/reference/rest/v1/instances)
- [GCP zonal](https://docs.cloud.google.com/compute/docs/reference/rest/v1/instanceGroupManagers/listManagedInstances) and [regional](https://docs.cloud.google.com/compute/docs/reference/rest/v1/regionInstanceGroupManagers/listManagedInstances) managed membership reads
- [GCP raw Monitoring query semantics](https://docs.cloud.google.com/monitoring/api/ref_v3/rest/v3/projects.timeSeries/list)
- [GCP compute metrics](https://docs.cloud.google.com/monitoring/api/metrics_gcp_c) and [Ops Agent metrics](https://docs.cloud.google.com/monitoring/api/metrics_opsagent)
