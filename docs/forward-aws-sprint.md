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

**PARTIAL.** The ordered queue is finished. Checkpoint 2 was pushed as `3924ed8c2d05e9e3c801434a481d49f050fdc002`; its completed required CI is 12 PASS / 4 FAIL, with the three historical jobs plus the pre-existing Go advisory failing. Checkpoint 1 CI was superseded/cancelled rather than treated as accepted.

| Queue | Demonstrated result | Disposition |
|---|---|---|
| Lambda | Native V2 benchmark authority, published versions, empty environments, immutable proof/currentness ; 11 focused Go checks and TypeScript pass | PARTIAL; positive connected attempt blocked by missing local machine identity |
| RDS/Aurora |18literal reviewed classes connected through native catalogue/archive/evaluator ; 9 focused Go and 17 Python checks pass after one normalization repair | COMPLETE catalogue subset; broader RDS/Aurora PARTIAL |
| S3 | One unchanged connected Standard-to-IA attempt; shared Python preflight deadline prevents native/browser acceptance | PARTIAL; prior bank unchanged |
| Network | One same-population collector/CUR/Python/API/OIDC journey implemented ; 9 projection checks and TypeScript pass | PARTIAL; connected attempt stops at same shared preflight deadline |
| Commitments | Retained current-source failure reviewed without inventing a cause or starting diagnostics | COMMITMENT_ACCEPTANCE_DEFERRED |
| EBS | Accepted bounded package left untouched | Prior bank preserved |

Official completion is **26.9% →26.9%**. No existing package satisfies a broader next maturity gate, and no package is subdivided to manufacture credit. Verified partial software has expanded; planned work, repeated foundations and test totals earn no independent points. The previous rough engineering range remains 27–31%, without a fresh whole-product audit; incomplete connected acceptance makes that range uncertain.

Final-source required CI, generated contracts, dependency/security/secret checks, installed045→046→047 restoration and ordinary browser acceptance are release gates run after this source is committed. Their actual final status is reported with the pushed SHA; this document does not predeclare their outcome.

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

### Lambda completion pass

Benchmark envelope version 2 selects immutable native configuration snapshots and published executed versions. The restricted assessor reopens archived native evidence, validates source authority, epochs, code/runtime/package/layers/dependencies/architecture and a non-memory fingerprint, and requires positively observed empty environments. Legacy receipts remain visible separately and cannot establish new numerical curves or shadow valid V2 receipts. No machine database grants or migration bytes changed.

The positive memory journey now carries the same provider-shaped native configurations, REPORTs, metrics, native CUR/Python normalization and benchmark pair to the restricted evaluator, persisted ordinary OIDC presentation and independent readback. This is implemented acceptance code, not a claimed accepted journey. Its one connected attempt stopped at the existing fixture credential guard: the dedicated Lambda performance object/analytics identity is not commissioned locally. Classification: `EXTERNAL_INFRASTRUCTURE_FAILURE`. It is a local fixture configuration debt, not genuine AWS or customer acceptance. No credentials/permissions were broadened and no journey pass is claimed. TypeScript passed. Combined focused Go validation passed 11 selected tests (including real PostgreSQL isolation/storage checks); the positive native workflow compiled but skipped because commissioned storage is disabled in that focused environment. The separate connected attempt failed the missing-identity guard. Neither skip nor infrastructure failure is positive acceptance.

### RDS/Aurora catalogue completion pass

An additive immutable physical-capability asset covers the literal 8xlarge, 12xlarge and 16xlarge rows of m8g, r8g, m8i, r8i, m7i and r7i. Its SHA-256 is `9b2efcc641706823f35c592b95046332f5f6f9f5423482cb0fd88f25cea7f8de`. CPU, RAM, architecture, fixed network and sustained I/O limits are independent capacity evidence; native eu-west-1 engine/version/licence/zone orderability and actual storage provisioning remain mandatory. Conflicting native hardware or missing archived proof suppresses capacity. No burst maximum becomes sustained capacity.

The existing provider/archive/evaluation path selects the exact per-row asset revision. V1 bytes and historic references remain unchanged. [RDS hardware documentation](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Concepts.DBInstanceClass.Summary.html) and [EC2 sustained EBS specifications](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebs-optimized.html) were reviewed for this bounded table. Class-default vCPU does not prove a customer Optimize CPU runtime configuration. Aurora retains `DATABASE_SHARED_STORAGE_CAPACITY_UNAVAILABLE`, and shared storage remains counted once. The broader database vertical remains PARTIAL. Database Python acceptance passed 17/17. The first focused native/archive/input run passed 8 selected checks and failed the new Ireland-only absence assertion: a missing baseline was a typed nil document rather than explicit unavailable. Classification: `NEW_PRODUCT_DEFECT`. The one permitted repair normalizes that native boundary without relaxing assertions, region checks or V1 bytes; the identical bounded rerun passed all 9 selected checks without skips. The requested catalogue subset is COMPLETE at component acceptance; the database/Aurora vertical remains PARTIAL and native customer acceptance is external.

### S3 Standard-to-IA attempt

The existing commissioned Inventory/access/CUR/assessor/normal-OIDC journey was attempted once against the frozen source. Run `0a4dc6a4-44c6-4407-8d96-c3ffbbfd1419` failed at the unchanged 120-second full Python preflight attachment deadline (`status=null`); the container later reported exit0, but no complete accepted test summary was captured. No native ingestion or browser acceptance was reached. Cleanup and protected-service/source preservation passed. This is `PRE_EXISTING_ACCEPTANCE_DEBT`: the existing shared preflight had retained the same deadline failure before this sprint; the current underlying cause remains unproved. No new deterministic product defect was established, no budgets/assertions changed, no rerun or new ingestion design. S3 stays banked at its prior component maturity; a positive connected Standard-to-IA result remains unaccepted.

### Network connected attempt

The new single path consumes the collector's actual topology, versioned flow generation, immutable archive and ClickHouse rows. The same 30-day window feeds provider-shaped native CUR through the existing trusted pipeline and actual Python normalization. Native pricing supplies dimensions, while customer GBP net rates remain authoritative. Native GB is resolved against independent CloudWatch byte counters; public reference prices are deliberately different. Workload attribution uses native ENI/subnet/route evidence. An invented resource-id flow field is not used in the new positive case. NAT hourly charges remain; only matched processing expenditure can be proposed as avoidable. Old separate synthetic projection tests remain supplementary.

The unchanged 85-second collector context,180-second Go test budget,420-second command budget, normal OIDC protocol and existing storage identities are preserved. Nine focused projection checks and TypeScript passed; the new connected selector compiled but skipped without commissioned storage in the focused environment. The separate single connected attempt, run `8912892d-7e10-4699-b5b9-14e33a40ee83`, failed at the unchanged 120-second full Python preflight attachment deadline (null attachment status, later container exit0). No native/OIDC readback was reached. Cleanup/source/protected-service preservation passed. Classification: `PRE_EXISTING_ACCEPTANCE_DEBT`, shared with the retained preflight failure; its underlying cause remains unproved. No new deterministic product defect was established, so no repair, changed limits or rerun was attempted.

### Retained commitment review and EBS

The retained report for source `20dacc218b18fc3840b297f50050fe3983e67d17`, run 39518356509/job118956116691, records failure at “Exercise issued native commitments, restricted daemon and real Finance journey”. The current report contains no diagnostic proving a new deterministic product defect. Checkpoint 2 also records that required job failing. The older 9810d77 archive diagnosis is not transferred to either source. Status remains `COMMITMENT_ACCEPTANCE_DEFERRED` / `PRE_EXISTING_ACCEPTANCE_DEBT`; no code repair, rerun, new diagnostic infrastructure or purchase authority is introduced. Existing commitment-observation credit does not establish purchase recommendations. EBS remains accepted at its existing bounded bank with no new work.

### Remaining gates and handover

**Software/release gaps:** complete native financial/demand/physical-candidate closure for the new service recommendations; EKS/Kubernetes identity association; bounded nested-page continuation beyond the visible limits; historical task/host allocation; missing local Lambda machine identity; S3/Network shared-preflight acceptance; positive full native financial/performance-to-console acceptance; Aurora shared-storage safety; deferred commitment/fleet acceptance and the Go toolchain security advisory. These are not relabelled customer gates.

**EXTERNAL_ACCEPTANCE_REQUIRED:** authorised AWS accounts/read roles and genuine native sources, customer-owned workloads and customer rates, business requirements/retention/RTO/SLOs, genuine observation periods and invoices, supervised commissioning and sustained operational/customer use. No live or production credit, provisioning, customer mutation, purchasing or new verified-savings claim is awarded. Optional analytical deployment remains off.

The final handover retrieves authenticated installed coverage by service and currency, retaining signed credits and the full denominator; unavailable customer coverage stays unavailable. Synthetic fixture periods and completeness are labelled separately from real customer coverage. Core installed recovery/browser acceptance does not establish optional native service commissioning. Recommended next phase: close the existing connected acceptance and security release debts, then commission supervised AWS read-only use when authorised. That phase is not started. Stop after checkpoint 3; no Azure/GCP work or merge.
