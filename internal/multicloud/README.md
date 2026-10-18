# Native Azure and GCP billing adapters

This package is an isolated read-only adapter foundation. It has no public API,
database writer, credential discovery, cloud provisioning, or executor integration.
Its snapshots always have `status: PROVISIONAL`, `ExecutionReady()` returns false,
and `VerifiedSaving()` returns nil. HTTP-double acceptance proves parser and reader
behavior; no customer Azure/GCP account has been commissioned or accessed.

## Contract

`Registration` schema `1` binds tenant, native source kind, full source scope and a
server-selected `read_binding_id`. `Config` requires an injected HTTP client and
token provider. The server credential registry must pin `ReadBinding.ScopeHash`
to `ScopeHash(registration)`, as well as the directory/billing identity. A caller
cannot retarget a broad credential to another export, destination, table, or query
billing project. Credential acquisition and trust-policy review remain integration
work; `TokenSource` receives only the required service OAuth scope.

`AzureReader.Collect(ctx, registration, AzureRequest)` reads an ARM export and its
historical run settings, all run-history pages, a supported native manifest and
every CSV partition. `ManifestVersion`/`BlobVersions` are optional server-selected
prior pins. Every blob needs a native version ID, ETag and modification time; an
unpinned read is repeated at the actual immutable version with an ETag fence.

`GCPReader.Collect(ctx, registration, Period)` reads native billing-account,
dataset and table metadata, then creates a server-built SELECT query through
`jobs.query`. Query creation may incur BigQuery charges in a future live setup;
the registered query project, location and maximum bytes billed are mandatory.
Customer access must remain unwired until the customer explicitly authorizes
the query billing project, query-cost budget and enforced maximum bytes billed;
read-only does not mean free. No such customer access is enabled by this package.
The reader collects every query page and validates the native successful job,
exact SQL/parameters, referenced table and cache policy. `FOR SYSTEM_TIME AS OF`
pins the query to the collection-time table snapshot, not to the start of the
historical usage period. No free-form SQL is accepted.

`Snapshot` schema `multicloud-billing-1` preserves original response bodies in
private `Object.Body`, exact original byte SHA-256 values and native identity/
version metadata. Bodies are omitted from JSON; a future writer must archive
them before publishing any source receipt. Content revisions exclude collection
time but include all native content hashes, records and registration revision.
There is no checkpoint, immutable object archive, append-only authority receipt,
cross-poll revision ordering or tenant RLS persistence in this package yet.

| Kind | Mapping |
| --- | --- |
| `AZURE_ACTUAL_COST` | Native billing cost; effective cost stays unknown. |
| `AZURE_AMORTIZED_COST` | Native amortized cost separately; billed cost stays unknown. |
| `AZURE_FOCUS_COST` | Native billed/effective/list fields remain distinct. |
| `GCP_DETAILED_BILLING` | Native cost plus separate signed credit records; original correction rows remain. |
| `GCP_ACCOUNT_PRICING` | Account pricing, consumption models, USD list prices and native FX metadata retained without conversion or resource-cost substitution. |
| `GCP_SPEND_CUD_METADATA` | Native daily spend-based CUD metadata, original units and local entitlement schedule retained; it does not prove complete commitment coverage. |

Amounts use decimal strings without a float conversion. GCP native FLOAT64 cost
lexemes retain an explicit provider-precision warning; decimal text does not
recover precision absent from the provider. Missing amounts/currency remain
unknown, and totals stay separated by currency. No public price is substituted
for contracted marginal cost. Identical native rows are not deduplicated: native
row ordinals preserve legitimate duplicates, credits, negations and replacement
adjustments. A new snapshot can correct an old one; persistence must choose and
retain authoritative revision history before using it for financial claims.

## Supported boundaries and unresolved gates

Azure supports Cost Management API `2025-03-01`, manifest `2024-04-01`, partitioned
CSV with None/Gzip, and explicitly registered data versions. It validates native
run IDs, historical destination/type, manifest totals, physical partition byte
counts, native row counts and actual blob versions. A supported manifest date
with a timezone must match the ARM range. A timezone-free manifest date is
retained as an explicit gap; it is not assumed UTC. Native daily usage dates also
do not acquire invented UTC interval boundaries. Other export formats, missing
versioned blobs or unsupported manifest shapes fail with a stable reason.

GCP supports regional EU/europe-* BigQuery native detailed billing, account
pricing and spend-based CUD tables. Reads retain whole registered billing-account
invoice scopes, including rows outside the target usage-project list, so global
charges and invoice adjustments are visible. A query's complete result count
proves that query was read, not that Google has delivered all usage. Account
pricing is ancillary evidence, and preview spend-based CUD export omits
resource-based commitment inventory. `invoice.month` is not an issued invoice.

All native readers retain `EXCLUSIVE_PRODUCER_POLICY_UNPROVEN`,
`REPORTING_PERIOD_COMPLETENESS_UNPROVEN`, `INVOICE_FINALITY_UNPROVEN` and
`NO_EXECUTION_AUTHORITY`. Producer RBAC/ACL/organization ownership, source gaps,
late-arrival/correction polling, independent invoice reconciliation, complete
commitment inventory and workload evidence require separate trusted integration.
Azure has native invoice APIs for supported billing agreements, but they are not
integrated here. No caller `trusted`, `complete`, or `final` flag clears a gate.
`CustomerImport` remains explicitly `CUSTOMER_IMPORT_UNTRUSTED`.

Readers use fixed provider hosts, HTTPS, normal TLS validation and no redirects.
They bound physical/decoded body size, aggregate objects/canonical bytes, rows,
columns, fields, credit expansion, pages, decimal exponents and query duration.
Failed reads return errors rather than a usable partial snapshot. Live deployment
still needs a server-owned hardened transport/egress policy, token identity
commissioning and the missing persistence/trust gates above.

## Local acceptance

Run `go test ./internal/multicloud` and `go vet ./internal/multicloud`. Tests use
in-memory HTTP transports against provider-shaped messages, with Docker network
disabled in the recorded local run. They cover complete native reads, historical
settings, immutable version races, pagination, manifest totals, compression
limits, exact money and credits, source binding, query-definition tampering,
cross-currency rejection and permanent absence of execution/savings authority.

Primary schema and capability references:

- [Azure export and manifest formats](https://learn.microsoft.com/en-us/azure/cost-management-billing/costs/tutorial-improved-exports)
- [Azure historical export execution settings](https://learn.microsoft.com/en-us/rest/api/cost-management/exports/get-execution-history?view=rest-cost-management-2025-03-01)
- [Azure usage cost columns](https://learn.microsoft.com/en-us/azure/cost-management-billing/automate/understand-usage-details-fields) and [FOCUS schema](https://learn.microsoft.com/en-us/azure/cost-management-billing/dataset-schema/cost-usage-details-focus)
- [Google detailed billing export](https://docs.cloud.google.com/billing/docs/how-to/export-data-bigquery-tables/detailed-usage)
- [Google account pricing export](https://docs.cloud.google.com/billing/docs/how-to/export-data-bigquery-tables/pricing-data)
- [Google spend-based CUD metadata and local schedule semantics](https://docs.cloud.google.com/billing/docs/how-to/export-data-bigquery-tables/cud-export)
- [BigQuery jobs.query](https://docs.cloud.google.com/bigquery/docs/reference/rest/v2/jobs/query), [query results](https://docs.cloud.google.com/bigquery/docs/reference/rest/v2/jobs/getQueryResults), and [historical table snapshots](https://docs.cloud.google.com/bigquery/docs/access-historical-data)
