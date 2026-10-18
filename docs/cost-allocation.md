# Observed cost allocation

The R0 allocation view is a separate analytical projection of persisted native
`BilledCost`. It does not change billing facts, invoices, optimization economics
or the savings ledger. `CURRENT_OWNERSHIP_VIEW` means current inventory ownership
was captured when this report was created; it does not assert who owned a resource
during the historical billing period.

Finance and FinOps administrators can append an immutable policy and create a
report. Auditors can inspect reports. Application owners, viewers and platform
administrators without a financial role cannot read organization-wide allocation.
The organization owner retains the existing role inheritance. Mutations require
an idempotency key and the current policy version in `If-Match`, initially zero.
Updating a policy appends a revision. Reports retain their selected revision and
current mapping snapshot even after ownership changes, fixture reset or source
revocation.

Rules select explicit existing resource IDs and divide their observed charges
among existing workloads using integer parts per million summing to 1,000,000.
A resource can occur in at most one rule. Without a rule, an exact
provider/account/region/resource identity uses its current owner. Unmatched
resources and missing ownership remain unallocated. The same algorithm allocates
negative credits without reversing their native sign. Largest-remainder rounding
at twelve decimal places breaks equal remainders by workload ID, and conserves
every source amount exactly. Currencies have independent totals; there is no FX
conversion.

An unknown amount remains null and makes the complete observed total unavailable.
The known subtotal stays separately visible. Explicit observed zero is valid.
An empty source has no invented currency or zero invoice. Continuing storage and
other observed charges remain in this view; allocation does not imply that any
charge was avoided.

`/v1/allocation-sources` returns bounded import metadata without raw payloads.
Customer imports retain `CUSTOMER_IMPORT` provenance and unknown coverage.
Deterministic fixtures retain their fixture label. Selecting an AWS connection
and exact billing month resolves one current authenticated CUR2 export revision
server-side, checks its issued receipt, current registration, source revision,
raw/canonical hashes and payer binding, and retains the whole payer record set.
It does not add together different export revisions. A revoked or changed source
cannot produce a new native report. Existing reports remain immutable snapshots.
New native selections refuse an active or interrupted source sync, and their
source-row lock serializes registration revocation through report publication.
Authenticated export provenance does not imply invoice finality or complete
workload ownership; all report results remain provisional observations.

The API accepts policy and source identifiers, never authoritative amounts,
observations, totals or trust flags. Policy history, report summaries, observed
facts and derived allocation entries each use tenant/query-scoped cursors. One
observed charge is stored once, separately from its potentially several derived
entries. Clients must not sum report history or repeat original charges for each
recipient. The explicit bounds are 5,000 observations, 25,000 entries and 100 rows
per page; larger reports need the later streaming reporting contract.
Public report creation has a cancellable 25-second transaction budget inside the
console's 30-second and server's 40-second limits. A 503 keeps the same idempotency
key for reconciliation, including an uncertain commit response. Maximum-size
storage acceptance is not a synchronous API latency or production SLO claim;
provider-scale asynchronous reporting remains outstanding.

PostgreSQL stores exact signed `DECIMAL(38,12)` observations and entries under
forced tenant RLS. Only the API identity can append these records. A report is
visible after its immutable seal independently checks row counts, exact
per-record allocation and currency conservation. A sealed report cannot receive
more observations or entries. Existing billing facts and savings history are not
rewritten. A corrected source produces a separate report with new source and
input references; these snapshots are not additive financial revisions.

This bounded view does not complete GA allocation: historical ownership,
provider-scale streaming, Azure/GCP financial reporting, tag/account hierarchies,
multi-level policies, native Kubernetes/node attribution and approved chargeback
processes remain separate acceptance obligations. No report grants execution
permission or verified savings.
