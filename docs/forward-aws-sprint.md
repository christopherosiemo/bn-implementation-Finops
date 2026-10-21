# Forward-only AWS sprint

Starting source: `20dacc218b18fc3840b297f50050fe3983e67d17`, existing pilot PR #1.
Official contractual completion starts at **26.9%**. Exactly three pushed
checkpoints are authorised. No cloud provisioning, customer mutation, purchase,
new execution privileges or verified savings is authorised by this sprint.

## Checkpoint 1 — AWS inventory breadth

**PARTIAL.** Shared `AWS_SERVICE_NATIVE_V1` collection now covers ECS/Fargate,
native EKS infrastructure, ElastiCache, DynamoDB and ALB/NLB/Classic ELB. Native
configuration, analytical topology, registered read bindings, immutable delivery
receipts, archive/readback, ClickHouse inventory facts, canonical resources,
scoped API queries, source health and the ordinary console are connected in
product code. Fargate is a placement/capacity model, not another platform.

Migration 046 is additive and forced-RLS. Only ingestion writes native snapshots;
signers and executors gain no grants. Defaults keep optional customer metadata
permissions off. Refresh preserves ownership, workload and authority. Exact ECS
container-instance membership can add an EC2 managed-fleet STOP blocker; it never
clears that blocker or revokes existing owned restoration.

Service coverage partitions the existing canonical billing denominator once,
retaining unsupported, unowned and resource-less charges. Credits and currencies
remain separate. Inventory is observation-only; unavailable costs are not zero.

Accepted components: provider-shaped protocol tests, tenant-isolated persisted API
readback/revocation, default-off Terraform metadata permissions and supplemental
console presentation. The persistence test explicitly uses synthetic archive
references; presentation cases do not prove the complete native-to-console path.
The all-package offline compilation attempt exhausted its unchanged 240-second
budget without a diagnostic: `UNKNOWN_ACCEPTANCE_FAILURE`, not a proved compiler
defect. The first focused capture overlapped addition of a safety helper and saw
an inconsistent file set; its failure is retained, followed by one frozen-source
rerun passed all 10 selected checks with no skips. TypeScript, two supplemental presentation cases, two existing presentation-boundary checks and five offline IAM mock plans passed. The exact migration guards retain 001–045 and reject unknown 047.

One new UI accessibility defect was repaired with explicit select labels and its
bounded rerun passed. A new schema-test indexing mistake was corrected; the
29-case exact-schema rerun passed without weakening migration checks.

Remaining software: observed EKS/Kubernetes identity association, durable nested
child-page continuations beyond the explicit bounds, complete native archive/
analytics/financial/OIDC acceptance and native cost attachment on resource detail.
Root-page continuations resume; exhausted nested reads stay incomplete. No broad
inventory-adapter maturity upgrade is earned from this AWS subset.

**EXTERNAL_ACCEPTANCE_REQUIRED:** genuine approved AWS accounts/regions/read roles,
customer workloads and ownership, operational histories and sustained use.

## Checkpoint 2 — Service recommendation breadth

Checkpoint 1 was pushed as `825ff0dd937164fd1d9358e850ac63f2c2b46a06`.

**PARTIAL.** Four service decision families now share IDs-only asynchronous APIs,
immutable publications, source/configuration/profile/financial currentness, an
independent analytical process and private Python `/v12/aws-service-assessment`.
The ordinary inventory and recommendation views expose comparisons, constraints,
negative/no-change outcomes, observed costs and precise unavailable economics.
Optional workload requirements extend existing versioned profiles. EKS continues
to use the existing Kubernetes optimiser.

Native CloudWatch statistics retain dimensions, units, sample counts, period and
actual timestamps. Evidence archives hold bounded histories; ClickHouse receives
provenance-aware facts, while PostgreSQL retains small references. Missing series
and missing demand remain unknown. Coverage derives 14/30/90 complete days and
does not reinterpret period statistics as raw-event percentiles. Group-member
cache metric selectors preserve replica topology.

ECS/Fargate evaluates CPU/memory and scaling safety without treating task allocation
as avoided EC2 host cost. DynamoDB evaluates provisioned capacity, customer-rate
mode comparisons, indexes and idle review while retaining replication costs.
Cache checks independent memory/CPU, swap, eviction, lag and HA constraints.
Load-balancer advice is operational review with null proposed savings.

Financial inputs come from current authenticated canonical CUR records with exact
account, region, resource, payer, source version and decimal arithmetic. Native
catalogue dimensions cannot establish customer prices. Unresolved allocation,
rates/brackets or commitments suppress estimates. Operational reviews may remain
useful without monetary estimates. Coverage advances only the exact financially
evaluated lines; load-balancer operational review earns no analysed-spend credit.

Migration 047 preserves older bytes, forced RLS and immutable results. The optional
assessor defaults off with a separate database/evidence identity and no provider,
signing or execution credentials. All publications reject execution plans and
carry false execution readiness/authority and null verified savings.

Frozen-source Go checks passed 18 selected tests without skips, including all four persisted family subtests; the assessor command compiles. Four-family Python checks passed 10/10; 29 exact migration guards passed.

Component evidence: four-family Python models, native metric protocols, persisted
restricted API refusals, generated TypeScript, normal presentation cases, MinIO
identity tests and Helm deployment guards. Persisted refusals and presentation
cases are not positive native/Python/OIDC acceptance. Local YAML assertion tooling
was unavailable; an isolated bootstrap probe hit existing UID-process EPERM.
Both are `EXTERNAL_INFRASTRUCTURE_FAILURE`; assertions and privileges were not
changed to obtain a pass. Required CI retains these release checks.

Remaining software: complete native cache physical candidate catalogue/per-shard
capacity interpretation, Memcached memory semantics, native payer reservation
closure for cache/DynamoDB, customer-rate/SKU dimensions for numerical candidates,
historical task/service billing allocation, independent demand integration and
the complete positive collected-evidence-to-console journeys. These are software
gaps, not customer commissioning gates. No broader optimisation maturity transition
is banked merely because the component models pass.

## Checkpoint 3 — Ordered completion sweep

Pending; Lambda positive memory economics, supported RDS class breadth, one S3
Standard-to-IA journey, one S3-through-NAT endpoint journey, retained current
commitment evidence inspection, then leave EBS banked. Stop after this checkpoint.

## Acceptance and historical debt

Each failure has one classification: `NEW_PRODUCT_DEFECT`,
`PRE_EXISTING_ACCEPTANCE_DEBT`, `EXTERNAL_INFRASTRUCTURE_FAILURE`, or
`UNKNOWN_ACCEPTANCE_FAILURE`. Only a concrete new product defect permits one
minimal repair and one relevant gate rerun. Original failures remain failures.
Existing deadlines, retries, permissions and resource budgets are unchanged.

The required `commitment-portfolio`, `fleet-native-capacity` and
`fleet-joint-decision` jobs remain enabled. No overall green CI claim is made
while a required job fails. Full final-source CI, generated contracts, security,
dependency/secret checks and installed migration/restoration remain release gates.

Checkpoint-1 CI `39526045919` also reported `GO-2026-6809` in the existing
Go 1.27.2 `crypto/x509`, naming Go 1.27.3 as fixed. Its trace uses the pre-existing
network flow reader. This is newly surfaced `PRE_EXISTING_ACCEPTANCE_DEBT`, not
an introduced service-code regression. The scanner remains enabled. Toolchain
remediation and a successful scan remain explicit software/release obligations;
the external advisory page could not be independently retrieved during this run.

Software partial delivery and genuine external acceptance are reported separately.
Fixed weights, historical reviews and the complete contractual denominator remain
unchanged. Product functionality and verified partial work are reported even when
they do not satisfy a broader package's next official maturity transition.
