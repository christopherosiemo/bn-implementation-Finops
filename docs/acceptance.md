# AWS scheduling pilot acceptance record

Recorded 17 October 2026. This record covers the first operational slice: an approved, reversible stop/start schedule for a standalone, EBS-backed, non-production EC2 instance. The local stack uses labelled deterministic AWS and billing fixtures with real OIDC, PostgreSQL, Temporal, object-storage and ClickHouse services.

This is a pilot acceptance record. It does not establish commercial GA, FOCUS certification, SOC 2/ISO certification, measured production SLOs, platform-scale capacity or realised savings for a customer.

## Results and evidence

| Check | Recorded result | What it establishes |
| --- | --- | --- |
| Python economics tests | 34 passed | Exact decimal arithmetic; actual calendar coverage; immutable source/identity/amount binding; pre-execution versus verification readiness; owned downtime; startup and continuing costs; negative results; finality/reconciliation; missing versus zero activity; immutable corrections and stable claim identity. |
| Go tests and vet | Go 1.27.2 suite and vet passed on final backend source | OIDC signature/issuer/audience checks, tenant and workload scope, eligibility, signed target/window binding, snapshot freshness, provider request semantics and durable workflow behavior. |
| PostgreSQL integration | Passed in a fresh disposable database with normal concurrent package execution | Forced tenant isolation, stale-version rejection, append-only evidence, ingestion/approval identity boundaries and migration serialization/tracking. |
| Consumed restoration replay | Passed using the actual restricted executor database role | An expired, completed recovery envelope cannot start an instance independently stopped afterwards. |
| Signed webhook contract | Targeted PostgreSQL integration passed | Exact-body HMAC covers tenant/event identity; retries preserve body and idempotency key; delivery records failure/success, rejects unsafe configuration and does not follow redirects. Integration/restoration lifecycle events emit on transitions. |
| Deployed API smoke | 17 checks passed against rebuilt local fixtures | Authenticated onboarding, source-backed baseline readiness before verification, exact-plan approval, idempotency, tenant isolation, ETags, one occurrence, pause-safe restoration, exact synthetic £5.16 verification, one current claim across retained history, audit and incident blocking. |
| Browser acceptance | 6 tests passed against final deployed images | Real OIDC sign-in and complete bound fixture operating loop; desktop/mobile layout; execution-ready/verification-pending separation; blocked legacy controls; unavailable costs; current, negative and legacy ledger presentation. |
| Console service discovery | Upstream replacement with a different IP recovered without restarting web | The unprivileged, read-only web image resolves current service addresses using the local platform DNS resolver. |
| Process recovery smoke | All 6 checks passed against final deployed images | Actual API/worker restarts while stopped preserve Temporal/PostgreSQL/executor; restoration completes with ownership cleared and exactly one audited stop/start. |
| Persisted ingestion | Versioned baseline and post-measurement jobs persisted through normal raw/analytics ingestion | A fresh job reaches `PERSISTED` only after raw storage and ClickHouse writes. The baseline contains 336 hourly compute records and 1,008 metric facts; measurement contains 1,344 quarter-hour compute records. Raw/audit object storage retains prior versions and evidence. |
| Infrastructure and clean bootstrap | Both Terraform stacks validate; 11 mock-provider tests and 59 Node sandbox/rollout tests passed; formatting, Helm lint/render, credential checker, Actionlint and bootstrap checks passed | Two distinct account guards; empty read-only bootstrap; no customer execution role by default; wrong target, legacy plans, stale readiness, short tokens and destructive plans rejected; supervised canary confirms schedule pause after restoration. No AWS provisioning. |
| Source hygiene | Staged-source secret scan and whitespace checks passed | Generated local secrets, runtime data, test reports and build outputs remain excluded from Git. |
| Live AWS customer deployment | Not performed | Terraform/Helm assets and adapter tests are not evidence that customer infrastructure was provisioned or mutated. |

The API and browser tests exercise synthetic historical billing and accelerated fixture time. They do not replace 14 complete baseline days, 14 complete post-change days, provider-final invoices and workload evidence in a live pilot. A fixture `VERIFIED` row is synthetic test evidence, not a customer savings claim.

The readiness increment adds immutable baseline/measurement reservations and source references, with their identifiers signed into schema-version-2 plans. Legacy plans cannot initiate a new stop; existing owned restorations retain authority. PostgreSQL regressions cover tenant isolation, evidence immutability, expired readiness, generation-specific fixture baseline selection and verified → provisional → verified ledger revisions that leave exactly one current verified amount. The fixture source clock records both logical financial timestamps and actual executor receipts; live mode rejects it.

API uploads have `CUSTOMER_IMPORT` provenance. Their persistence does not prove provider invoice finality or independent workload collection, so they cannot authorize live stops or verified claims. Trusted AWS export/invoice collection, independent workload-source provenance and authoritative completeness for omitted CUR intervals remain live integration gates. Read-only onboarding and inspection do not require those integrations or execution credentials. See [evidence contracts](readiness-evidence.md) and the [two-account rollout checklist](sandbox-readiness.md). No commissioning bypass is provided.

Reproduce with the commands in [README](../README.md). Run smoke, browser and process-recovery suites sequentially: they mutate shared fixture state or restart local services. PostgreSQL integration tests require `TEST_DATABASE_URL` pointing to a disposable administrator database; without it those integration cases are skipped.

## Safety and financial boundaries

- Live customers default to `RECOMMEND`. Assisted execution requires approval of an exact plan; scheduling Autopilot additionally requires an explicit, expiring workload grant and schedule opt-in.
- Only the executor receives the customer mutation identity. Ingestion cannot sign plans or forge human approvals. The signer independently checks approval provenance and current policy.
- The supported action pair is EC2 stop and owned restoration. Production, managed fleets, Spot, instance-store hardware, unknown authority/drift, unsafe networking, protected instances and unresolved dependencies block stops. Missing or stale incident/deployment/job signals also block stops.
- A signed stop window, current safety/economic snapshot and fresh AWS preflight constrain each occurrence. Pause and expiry do not abandon an owned restoration; completed restoration consumes that authority. Application readiness is required alongside EC2 state/status checks.
- On-demand purchase type alone does not prove avoidable spend. Unknown or covered RI/Savings Plan economics block positive pilot claims. Retained EBS/IP costs are not claimed as eliminated; incremental/startup charges reduce savings.
- Verification requires persisted source/canonical evidence, sufficient observation and provider-final reconciled billing. The ledger retains negative values and superseded revisions, excludes duplicate resource/time claims and projects only current revisions into totals.

These controls have targeted unit/integration and fixture coverage. Provider outages, live IAM/STS behavior, actual startup timing, private health connectivity, operator escalation and backup recovery still require supervised customer-environment validation.

## Billing mapping and live AWS limits

The CUR 2.0 normalizer labels its baseline FOCUS 1.4 and returns `conformance: MAPPED_WITH_EXPLICIT_GAPS`. It preserves source fields and versions, signed credits, native currencies and separate billed/effective/list/contracted values when supplied. Its mapping is not a complete, certified FOCUS export.

Explicit gaps include missing contracted prices, missing commitment effective costs, commitment allocation requirements, missing resource allocation and unsupported/missing FOCUS columns. Positive credit lines require source review. Unsupported values remain null; commitment fee/negation lines are not silently counted as marginal compute savings. Reconciliation is reported separately for each currency; no foreign-exchange conversion is implemented.

The live pilot binds one configured read/execution customer-role pair to exactly one trusted `AWS_TENANT_ID`. Another authenticated tenant cannot borrow those identities. This is a single-customer live identity binding, not a multi-customer cloud credential registry. Local fixture tenants remain isolated independently of that live binding.

Live use is explicit opt-in under [deployment](deployment.md) and [operations](operations.md). Validate the approved AWS account/region, least-privilege role trust and tags, workload ownership, configuration delegation, billing/work evidence, startup health and supervised restoration before enabling a real occurrence.

Live CUR records and bound workload evidence currently enter through authenticated import/update APIs. Inventory, EBS discovery and the bounded CloudWatch adapter have live read implementations; continuous payer-export harvesting and richer incident, deployment and job connectors still require integration work. Configuration authority and runtime delegation must be established explicitly; repository-wide IaC discovery and PR execution are not implemented by this slice.

Optional platform notifications use one operator-configured `WEBHOOK_URL` and `WEBHOOK_SECRET` for this single-customer live deployment; there is no per-tenant subscription registry or Slack/Teams connector. A configured URL without a secret fails delivery visibly. Live destinations require HTTPS, embedded credentials are rejected and redirects are not followed. The receiver must verify `X-Autopilot-Signature: sha256=<hex HMAC-SHA256>` over the exact request bytes, validate the signed `tenant_id`, and deduplicate the signed event `id`/`Idempotency-Key`. Failed attempts remain in the tenant-scoped outbox and retry after one minute. Service secrets stay in runtime configuration, outside event bodies and workflow history. An empty URL disables delivery; notification delivery does not prove a real customer route has been configured.

Azure/GCP, Kubernetes rightsizing, VM/database resizing, Terraform/GitOps execution, portfolio commitment optimisation and the remaining commercial GA requirements remain tracked in [traceability](traceability.md). No production deployment, certification, zero-incident history, tested RTO/RPO or specification-wide acceptance is claimed here.
