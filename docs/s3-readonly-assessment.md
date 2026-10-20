# Read-only S3 assessment

This bounded increment adds S3 dataset and storage-policy advice. All publications retain `pre_execution_ready=false`, `execution_authorized=false`, R3 risk and `verified_saving=null`. No customer object, lifecycle, retention, replication or logging mutation is implemented. EBS, RDS/Aurora and commitments remain closed at their recorded acceptance levels; the deferred commitment job remains enabled.

## Connected design

The optional read connector discovers account-bound buckets and preserves configuration failures as absent, denied, unsupported or unknown. A bucket is one canonical resource. Object populations live in provenance-aware ClickHouse facts and bounded cohort snapshots, rather than one PostgreSQL resource per object. Dataset containment and replication observations confer no EC2 execution dependency or authority.

The Compose profile is `object-storage-assessment`; hosted opt-in uses `objectStorageAssessor.enabled`. `S3_READONLY_ENABLED`, the private `AWS_OBJECT_STORAGE_READ_BINDINGS_JSON` registry, and the ingester-only `S3_OBJECT_IDENTITY_KEY_HEX` plus `S3_OBJECT_IDENTITY_KEY_VERSION` commission reads. The dedicated database password and `OBJECT_STORAGE_ASSESSOR_ACCESS_KEY`/`OBJECT_STORAGE_ASSESSOR_SECRET_KEY` commission only the product evidence reader. Keep these values in local secrets or the deployment secret manager. Customer-role Terraform leaves `enable_s3_readonly=false`; enabling it selects exact bucket ARNs, report prefixes, owners, regions and KMS keys. None of these switches creates Inventory, logging or other paid customer telemetry.

Operators register versioned datasets and already commissioned Inventory or analytics report locations through the ordinary authenticated console and `/v1` API. Assessment creation accepts only a bucket/resource ID and optional issued dataset ID. It freezes server-selected evidence and policy versions in the queue. A separate analytical PostgreSQL identity and version-only object reader call the private Python evaluator and publish immutable results. They receive no customer provider, signing or execution credentials. The optional Compose profile and Helm deployment remain disabled by default.

Initially trusted Inventory supports gzip CSV only. Parquet and ORC are explicitly unsupported. The reader checks registered account, owners, regions, Inventory configuration, manifest checksum/schema, every listed file's size and checksum, exact object versions and computed hashes. An approved delivery-prefix policy must fence unsupported writers; policy changes invalidate trust. Customer AWS administrators remain an explicit trust boundary. Native bytes stream through fixed-size immutable archive chunks and bounded analytics batches. Resumable checkpoints and deterministic row identities prevent replay from inflating published generations beyond ClickHouse's deduplication window.

A complete Inventory report is a delivered report, not an atomic or continuously current census. Missing versions, historical configuration and mandatory fields constrain completeness. Object keys use tenant-keyed identities in analytical records; restricted raw evidence retains the original bytes. Bucket tags do not become object tags. Exclusive accounting cohorts prevent overlapping customer views from summing the same population twice. [AWS Inventory](https://docs.aws.amazon.com/AmazonS3/latest/userguide/storage-inventory.html)

## Access and policy evidence

Age, observed access and unknown access are separate states. Existing Storage Class Analysis, Storage Lens and configured CloudWatch sources retain their native scope, period and limitations. Best-effort request metrics, logs and tier-reference dates do not prove zero access. Storage Class Analysis needs at least thirty days and supports Standard-to-IA analysis specifically. No paid source is enabled to manufacture confidence. [CloudWatch semantics](https://docs.aws.amazon.com/AmazonS3/latest/userguide/cloudwatch-monitoring.html), [Storage Class Analysis](https://docs.aws.amazon.com/AmazonS3/latest/userguide/analytics-storage-class.html)

The dedicated machine-authenticated current-minute endpoint rejects console tokens, conflicting replays and historical backfills. A separately commissioned historical application report reader preserves actual contiguous minute timestamps, sequence, heartbeat, native metric definition and immutable collector identity. It does not backfill guarded workload receipts. Only complete explicit zero observations, matched to the exact Inventory population, can support zero activity; nonzero aggregates cannot manufacture object-level coldness. Missing intervals remain unknown. The usual fourteen non-production, thirty production and ninety seasonal complete-day requirements apply, along with longer source-specific minima.

Customer declarations record lifetime, RTO, retention/compliance, recovery and external dependency review independently from provider observations. Ownership and an actual registered configuration declaration must match the assessed resource. Retention, legal holds, recovery, replication purpose, resilience and applicable lifecycle behaviour are checked before validation. Terraform ownership selects declarative review, without granting an apply right. Changed population, policy, resource context, source authority or financial evidence invalidates currentness without rewriting history.

## Seven decision families

| Family | Advice and refusal boundary |
|---|---|
| Standard → Intelligent-Tiering | Eligible object sizes, monitoring, transition cost, evidenced occupancy and initial Frequent-Access ramp. Unknown access yields conditional review or break-even bounds, never invented point savings. |
| Standard → Standard-IA | Requires supported infrequent access, retrieval/request quantities and lifetime. Per-object minima, duration or retrieval can reverse the outcome. |
| Glacier alternatives | Instant, Flexible and Deep are compared independently against transition path, latency/RTO, retention, restore workload, metadata overhead, temporary copies and costs. |
| Intelligent-Tiering policy | Optional archive tiers and monitoring are assessed; behaviour already implemented by native policy earns no new saving. |
| Noncurrent versions | Population, age, carrying burden and retention review; no assumed deletion saving. |
| Incomplete multipart uploads | Commissioned aggregate or bounded paginated upload/part observations, with incomplete enumeration and unknown bytes preserved; cleanup-policy review only. |
| Small objects | No-change or filtered-policy advice when monitoring, transitions or minimum sizes reverse nominal storage savings. |

Class semantics are versioned separately from customer prices. One Zone-IA requires explicit resilience permission. Replicated copies are not automatically waste. Existing lifecycle filters and scheduled transitions are compared as absent, implemented, conflicting, suboptimal or unknown. [Storage classes](https://docs.aws.amazon.com/AmazonS3/latest/userguide/storage-class-intro.html), [Lifecycle constraints](https://docs.aws.amazon.com/AmazonS3/latest/userguide/lifecycle-transition-general-considerations.html)

## Economics and coverage

Only authenticated canonical CUR NET rate, quantity and amount arithmetic supplies customer rates. Account/payer, currency, region, class/tier, operation, unit, contractual dimensions and applicable native pricing bracket must match. Native catalogue metadata describes dimensions; public price amounts never replace missing customer economics. Unknown marginal pricing remains unavailable. Observed billed amounts, modelled cohort allocations and conditional future comparisons are labelled separately.

Current and candidate policies use the same evidenced remaining-lifetime horizon. Decimal arithmetic preserves credits and negative results. Component costs include applicable storage, requests, retrieval, transition, monitoring, minimum size/duration, early-transition penalties, restores, temporary restored copies, replication and continuing obligations. Upfront cost, horizon outcome and recurring monthly run-rate are separate. Annual estimates remain unavailable without a supported year. Alternatives are not added together into an inflated total.

The all-AWS coverage denominator retains unsupported services, unowned resources, resource-less charges and separate signed credits/currencies. Unknown or zero denominators produce unavailable percentages. Prefix/cohort allocations never become native bucket attribution, and cannot promote the entire bucket to analysed. Only current complete bucket-level comparisons can classify the exact supported canonical charge IDs once.

## Acceptance and external gates

Implementation and acceptance are recorded separately. The reserved one-point scope advances only to component maturity twenty, adding **0.2 points: 26.3% → 26.5%**. Connected deterministic maturity forty and **26.7%** are not earned. Fixed weights and all twenty-four prior reviews remain unchanged.

Component acceptance already recorded: the full Python suite passed 192 tests in 79.315 seconds within the unchanged 120-second, 512-MiB, one-CPU limit. Dedicated current-access and historical parsing checks passed nine selected Go/real-PostgreSQL tests, without skips or OOM. These counts earn no independent credit. The connected native/API/worker/OIDC readback is unaccepted as recorded below. Migration/restoration and final-source CI are separate release gates reported on the exact head of the existing pilot PR.

**PARTIAL:** this is analytical advice only. Customer-scale operation, broader format support, execution and verified financial outcomes remain outside this package. The original 233 sections and all later obligations remain preserved.

**EXTERNAL_ACCEPTANCE_REQUIRED:** genuine AWS read-role and report-policy commissioning, real source history/customer NET rates, customer ownership, retention/RTO/dependency declarations, privacy/retention review and sustained operational acceptance. Product compute/storage/evidence remain in eu-west-1; customer sources are read only in their registered authorised regions. No AWS resources are provisioned by this increment.

## Bounded acceptance record

**COMPLETE — named component checks only.** Native/source/provider parsers and bindings compile and pass focused checks. The final monetary/API/lifecycle selector passes eight cases with actual isolated PostgreSQL: immutable dataset revisions, IDs-only requests, missing-evidence blocked publication, tenancy and native price dimensions. The independently versioned Python policy evaluator covers all seven families and positive, negative, no-change and unknown outcomes. These are components, not a completed customer operating loop.

| Gate | Evidence and limit |
|---|---|
| Final focused financial/API/lifecycle checks | PASS; run `c29ec5cb-126d-4041-bb61-17c183726c9b`, eight selected cases, no skips/failures/OOM, 23.7 seconds actual tests. Receipt SHA-256 `07adc077d1a49a6810f92a5b7f199b4d89516ded29593710cb102474ffe7b026`. Includes migration 043 read-lock grant. |
| Read-lock compatibility, revocation and owned START | PASS; run `110f1d21-3101-453b-88f0-fa520b73e99b`, unchanged existing recovery subcases, 6.48 seconds. Receipt SHA-256 `0b12ed2af563e00bcccd389b2bd65b3ad7b8b1bd1804368ba7efa7d89ca88886`. The ingestion identity and its pre-existing hardware-reader member gain only the tenant-bound read lock; source UPDATE remains denied. |
| Current activity and historical parsing | PASS; nine selected Go/real-PostgreSQL cases, run `a8fed36f-3d8d-4557-82f0-e9801d0ac4c3`. Receipt SHA-256 `90b44e190743ad94f8f58e8be00b04e9a0bfa55674281aad63feb964d9107513`. Earlier exact component snapshot, not the final connected path. |
| Full Python components | PASS in the model-owned run: 192 tests, 79.315 seconds, 120-second/512-MiB/one-CPU limits. Final evaluator SHA-256 `4e2956cbf9e9a70c161f217b5ff4a9941238c28b2a57c3c119905a8f00db73d2`; this tool-output component result does not replace the failed guarded integration capture below. |
| Schema and deployment components | PASS: 29 exact-schema guards, the full 415-case Linux Node suite, Terraform validate and two S3 offline mock plans, optional Helm render/refusal checks, frontend generation/typecheck/build and four supplemental presentation cases. Actual new ClickHouse table DDL was applied additively without restarting its existing container. These are component results; none proves ingestion or commissioning. |
| Migration immutability | 001–042 unchanged. Final 043 SHA-256 `75fc1e107f55eb7db66233304abe4bf21056376e54a9fb729fcac71571bbc7e7`; unknown 044 is refused. |
| Connected attempt 1 | FAIL; `ca87eb0f-b0c0-4beb-b605-61357e944e23`. Full Python capture exceeded its unchanged 120-second limit without a completed summary; an overlapping Terraform type correction also invalidated source consistency. No native/browser stage ran. |
| Connected bounded rerun | FAIL; `f9c32989-00f2-47d0-b09d-533d8c45ef34`. Same 120-second Python limit expired before native ingestion or browser execution; no completed suite summary or preceding assertion failure was observed. All source/index/HEAD and protected services stayed unchanged and owned helpers cleaned up. Receipt SHA-256 `fcfd4069c8157ab21ed9f2bced74ba2a282598bfa27b1b342a6b2d8aa0992de8`. No timeout increase, retry expansion or check removal. |

**PARTIAL — the requested connected vertical.** The provider-shaped Inventory/archive/ClickHouse → IDs-only API → restricted analyst/Python → normal authenticated console positive journey and its independent stored-result readback remain **UNRUN**. Included acceptance code compiling does not prove that workflow. This is an outstanding software acceptance gate, not an external-only commissioning gate. No deterministic E2E maturity, object mutation or verified savings is credited.

The smallest proven Terraform defect was a conditional Resource string/list type mismatch; the correction uses a one-element list and both unchanged mock plans then pass. The financial source compatibility assertion was updated for the narrow read-lock grant and the hardware reader's existing migration-017 inheritance; it still proves denial of source writes, foreign-tenant locking and preserved owned restoration. Earlier failures remain failures.

Final-source required CI, dependency/security/secret checks, installed 042→043 restoration and ordinary installed browser results are reported separately on [the pilot PR](https://github.com/christopherosiemo/bn-implementation-Finops/pull/1/checks). The deferred commitment failure remains enabled; overall CI must not be called green.

Cross-region S3 metadata/report reads require the explicitly registered regions. Optional CloudWatch request metrics outside the customer role's base region remain unavailable unless separately commissioned. Object-tag selector membership remains unavailable without object-tag evidence. These limitations cannot manufacture a complete population, zero access or monetary confidence.
