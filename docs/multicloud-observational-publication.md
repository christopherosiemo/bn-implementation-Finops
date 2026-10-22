# Private Azure/GCP observational publication

This component persists provisional native billing observations. It has no public registration/upload route, scheduled runtime, customer credentials, financial claim integration, execution integration or default cloud provisioning. The six supported source kinds remain separate: Azure Actual Cost, Amortized Cost and FOCUS; Google detailed billing, account pricing and spend-based CUD metadata. Inventory/metric readers are separate components and are not implicitly published by this pipeline.

`PublicationPipeline.Publish` takes a server-registered `RegistrationSnapshot`, a result from the private native reader and a durable sync idempotency key. `PrivateRegistration` binds the entire native scope and the server credential-registry identifier to configuration/scope/binding hashes. Snapshots with the customer-import source class are rejected. A source-class string is not an external attestation: private authenticated reader selection remains the trust boundary, with no authoritative caller upload path.

Publication independently re-parses the original Azure manifests/CSV partitions or Google query-job definitions, result schemas and every continuation page. It verifies native identity, registered scope, historical query/export definition, counts and exact derived monetary values against the reader result. It retains all original raw bodies. Rehashing a caller-modified amount does not make it acceptable.

## Durable evidence sequence

Migration `019_multicloud_observations.sql` adds five append-only tables: `multicloud_registrations`, `multicloud_revocations`, `multicloud_jobs`, `multicloud_checkpoints`, and `multicloud_receipts`. They use forced tenant RLS. The independent NOLOGIN group `finops_multicloud_ingester` has SELECT/INSERT on these new tables only. It inherits no application, ingestion, execution or signing roles. `finops_api` has SELECT only; no other runtime identity receives publication writes. This component does not add a login/password, main process mode or network route.

`OpenPublicationRepository` requires a dedicated least-privilege login. It rejects superuser, CREATEDB/CREATEROLE/BYPASSRLS/REPLICATION flags on both login and expected group, and any transitive membership other than the login itself and `finops_multicloud_ingester`, including predefined broad database roles. It compares `session_user` with the parsed authentication user, rejects startup `role`/`session_authorization` and nonempty backend `options`, then selects the dedicated group role. Direct custom ACL review remains part of private credential provisioning. Verified TLS with hostname/chain validation and no plaintext fallback is required by default. The explicit fixture option accepts only local `postgres`/loopback hosts. Database migration credentials cannot run the publication process.

The immutable stages are:

1. `RAW_ARCHIVED`: every original provider object has a tenant/job-scoped key, SHA-256, byte count and non-null version ID; the exact pinned version has been read back and compared with the original bytes.
2. `CANONICAL_ARCHIVED`: canonical data has a separate pinned-version object with exact readback. No source billing rows are stored in PostgreSQL metadata.
3. `ANALYTICS_PERSISTED`: a tenant-bound, content-addressed analytics population has been written and read back, including its exact payload hash, tenant, population identity and counts.
4. An immutable receipt is appended only after all three stages exist and the same registration is still current and unrevoked.

SQL guards enforce stage order, tenant/configuration binding, collection bounds, archive version/hash metadata, append-only history and permanently provisional authority fields. Storage clients still perform actual object/fact I/O and readback; a SQL checkpoint is not an independent provider attestation. Archive/analytics errors or a concurrent revocation prevent a new receipt. Already acknowledged stages are read back again on retry. The repository serializes registration revisions, revocation and receipt publication with the same per-registration transaction lock.

`Resume(ctx, tenant, jobID)` re-derives the collection from its complete immutable raw checkpoint without repeating a potentially billable provider query. `Pending` exposes bounded unfinished job metadata to a future private scheduler. A crash before the complete raw checkpoint requires the original collection to be supplied again; partial archive presence never implies completeness. Unreferenced object versions can remain after a failed stage and require scoped retention/garbage collection; this component does not delete evidence. No continuously running source scheduler or recovery-time objective is claimed.

## Money and current observations

Native money text and raw provider lexemes are retained. Canonical decimal normalization is exact; it does not invent provider precision. Google FLOAT64 export values keep their explicit precision caveat. `WarehouseDecimal` yields a nullable DECIMAL(38,12) projection with mapping gaps when a value is missing or cannot fit exactly. No amount is silently rounded or replaced by zero. Currency remains a per-record native dimension; this component produces no cross-currency or portfolio total.

Google economic identity is a sorted multiset of canonical row hashes and multiplicities. It excludes volatile query-job/row ordinals and derived credit-parent IDs, while preserving duplicate source rows, corrections, credits and original native dimensions. A repeat observation can have a new immutable receipt but reuses the same content-addressed facts population. Consumers must never sum observation history.

`IsCurrent` means the latest native observation for the same registration, scope hash and exact period start/end. `ActiveSource` separately describes whether its registration revision is current and unrevoked; revocation retains the historical head and evidence. Candidate heads are ordered by the validated Google query `as_of` snapshot or Azure completed-run `submittedTime`, not collection/receipt arrival time. A delayed older job cannot replace a newer query. Different economics at an equal native timestamp produce no current head and `NATIVE_OBSERVATION_ORDER_AMBIGUOUS`; opaque blob versions and arrival order do not prove a correction order. A genuinely later native observation can revive prior economic content without reusing the old receipt's order. Replaying an old completed sync key never moves the head. Different or overlapping periods remain separate, non-additive observations.

The ClickHouse adapter stores one exact population payload under `(tenant_id, population_id)` using `ReplacingMergeTree`, explicit tenant predicates and `FINAL` for logical readback. Repeated/concurrent physical inserts are not extra logical spend. This table is not a savings ledger and has no financial-authority join. Serving a future population projection must continue to select active exact-period heads and must define overlap reconciliation before any aggregate is offered.

Every receipt remains `PROVISIONAL`, `execution_authorized=false`, `verified_saving=null`, including after successful storage. Reasons include unproven exclusive producer policy, reporting-period completeness, native invoice finality and VM-incarnation allocation. GCP billing resource names and Azure billing ARM paths do not establish an independently observed VM incarnation. Account pricing is not a resource's actual contracted rate; spend-based CUD metadata is not complete commitment inventory. No readiness, verified savings, native invoice finality, complete parity or multicloud execution acceptance is claimed.

## Reproducible local acceptance

Run the ordinary pure package tests and vet, then on the already bootstrapped **local fixture** stack:

```sh
node --test scripts/tests/multicloud-publication-lab.test.mjs
node scripts/multicloud-publication-lab.mjs
```

The runner pins a verified local Docker context, checks running workspace-owned fixture API/PostgreSQL/MinIO/ClickHouse services and their exact private network, and refuses live mode, foreign services and cloud credential variables. It generates ignored 0600/Windows-ACL-protected test environment and evidence files under `work/private/multicloud-publication/<run-id>/`. It does not print credentials. It stages only module manifests, this Go package and migrations 001/019 into a read-only source mount, excluding `.env`, `.git`, private work artifacts and other host credentials. The Go container has bounded resources and no added capabilities. The following tests must actually PASS; a skip fails the runner:

- `TestPublicationPostgresIsolationRestartAndAuthorityBoundary`
- `TestPublicationPostgresNativeOrderingOutOfOrderCompletionAndRevival`
- `TestPublicationRealPostgresVersionedMinIOAndClickHouse`

The direct Go-test environment contract is `TEST_MULTICLOUD_ADMIN_URL` (local administration DSN for creating a **new disposable database**), `TEST_MULTICLOUD_STORAGE=true`, `TEST_MULTICLOUD_S3_ENDPOINT=http://minio:9000`, `TEST_MULTICLOUD_S3_ACCESS_KEY`, `TEST_MULTICLOUD_S3_SECRET_KEY`, `TEST_MULTICLOUD_CH_ENDPOINT=http://clickhouse:8123`, `TEST_MULTICLOUD_CH_USER`, and `TEST_MULTICLOUD_CH_PASSWORD`. Do not use this administration DSN in a runtime identity. The runner derives these privately from inspected fixture containers; it never forwards Azure/GCP credentials or performs provider-side queries.

Each test database applies only 001 and the new 019 inside its own random name, creates a distinct restricted login, and is removed afterward. Main application schemas/migrations/rows are untouched. Actual storage acceptance creates one randomly named, ownership-tagged versioned MinIO bucket and one ownership-commented ClickHouse table, then verifies ownership before deleting only these fixtures. It checks exact version readback, replay, restart, tenant denial, forbidden legacy/signing/execution/financial writes, current heads, native-order conflicts, and analytics tamper rejection. Interrupted tests can leave their exact labelled fixtures; inspect the private run log and matching ownership tags before cleanup. No broad cleanup of existing buckets, tables or application volumes is authorized.

Local PostgreSQL/MinIO/ClickHouse were exercised with provider-shaped HTTP transport doubles. This is component acceptance, not a commissioned native Azure/GCP integration. Customer setup still requires explicit native account/tenant/scope and access approval, raw/analytics/operational/economics residency in Ireland, and provider processing-location review. Google BigQuery queries may be billable: exact query project, dataset/location, access, maximum-bytes budget and cost approval are required before any native reader is wired. A global billing-read exception does not approve arbitrary query-processing locations. Invoice/commitment provenance and incarnation allocation gaps remain visible until independently implemented and accepted.
