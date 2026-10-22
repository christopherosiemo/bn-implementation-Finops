# Fleet history and independent completed-work records

This read-only increment preserves native ASG point observations and independently
received completed-work intervals. Every history scope remains `BLOCKED` with
`INTERVAL_OWNERSHIP_UNPROVEN`: even identical ASG snapshots do not prove who owned
an instance between observations. It adds no execution permission, financial
baseline, workload-preservation attestation or verified savings claim.

## Public selection and immutable records

The three `/v1` collections use the existing OIDC, tenant/workload authorization,
`Idempotency-Key` and optimistic concurrency contracts:

| Collection | Create selection | Read scope |
|---|---|---|
| `fleet-history-registrations` | Existing workload/source connection, fleet identifier, exact Ireland ASG ARN, cadence and maximum gap | Required `workload_id`; individual registration and `/observations` |
| `fleet-demand-definitions` | Registration, existing activity source, business operation and versioned semantic contract identifier/hash | Required `registration_id`; individual definition |
| `fleet-history-scopes` | Registration, definition identifier and expected definition version | Required `registration_id`; individual scope and `/references` |

Registration and definition creation require `If-Match: "0"`. Append a new version
using `POST /{id}/revisions` and the current version. Fleet, workload, account,
region and ASG identity cannot be moved between versions; create another
registration for a different identity. Definitions cannot be reparented. Scope
creation uses the current registration's `If-Match` and the selected definition
version. Only a platform administrator can write these declarations and scopes.
Application owners can read their own workload's records; a cursor is bound to
tenant, collection, workload/registration and reference filter. Pages contain at
most 100 entries. The dashboard does not grow another unbounded collection.

The server derives source configuration hashes, registry versions, account
bindings, activity metric identifiers/versions and native units. Callers cannot
upload observations, counts, authoritative timestamps, complete-day flags,
trusted references or source states through these resources. A completed-work
declaration binds the existing independently authenticated activity source's
`Completed` field, `DELTA` temporality and one external workload total. Its metric
is always `activity.Completed`. The semantic declaration still needs customer
commissioning; authentication alone does not prove business meaning.

Guarded minute-ingress receipts retain the original raw body/hash, authenticated
subject, database receive time and exact metric definition. Observed `0` remains
zero; a missing `completed` field or missing interval remains unknown. A query
cannot backfill the existing ingress receive window. Activity references use
`POSTGRES_RECEIPT` and do not invent an object version, data revision, registry
version or counter epoch. Request throughput is a separate proxy, not completed
business work.

## Native point capture

The ingestion-only factory requests the single registered ASG through an approved
read-role binding. It checks the exact account, region, ARN, native timestamp,
complete response pagination, query selector and raw/typed member equality.
Unhealthy members are retained as observed members. Unknown launch time,
incarnation, hardware or individual inventory mapping stays null; current V1 ASG
responses cannot establish those facts.

Raw provider bytes are archived and read back by their pinned S3 version/hash
before source revision, receipt and membership projection are published. Source
registry version, configuration hash, native data revision and receive receipt
are distinct. A later genuine capture with unchanged bytes is another point,
and can reference another pinned object version of the same bytes. It is not a
new configuration or an interval-ownership proof. Exact replay retains the
original database receipt time and observation identity.

Publication holds the registration guard before the source synchronization and
row guards, then rechecks the registration, source configuration, enablement and
revocation. A change during capture leaves no published point. PostgreSQL checks
the selected issued native receipt, raw-object reference, exact members/template
versions, original receive time and hashes independently of API bodies.
Nanosecond timestamps remain in immutable JSON; PostgreSQL derives its
microsecond timestamp index through the same conversion used by its checks.

## Optional reader process

The backend includes `APP_ROLE=fleet-history-reader`. Compose and Helm do not
start this process by default. Commission it separately with:

- A distinct authenticated PostgreSQL login belonging only to `finops_ingester`,
  verified TLS and a pool of at least three connections. The process has ingestion
  privileges; this is not a claim of a narrower hardware-only database role.
- Renewable IRSA credentials (`AWS_ROLE_ARN`, `AWS_WEB_IDENTITY_TOKEN_FILE`), the
  approved `AWS_SOURCE_READ_BINDINGS_JSON` secret and `AWS_TENANT_ID`.
- Explicit `AWS_FLEET_HISTORY_REGISTRATIONS_JSON`, an array of tenant/registration
  identifier pairs, restricted to that commissioned tenant.
- Existing versioned evidence storage in `eu-west-1`, `OBJECT_BUCKET_RAW` and
  `OBJECT_REGION=eu-west-1`. An explicit endpoint must be an approved Ireland
  HTTPS S3 endpoint. Static AWS/object credentials are rejected in this process.

The optional Helm `fleetHistory.enabled` switch defaults to `false`. The
render-only [example values](../deploy/helm/finops/ci/fleet-history-values.yaml)
are combined with `aws-readonly-values.yaml`; their illustrative ARNs and secret
names grant no authority. Enabling the reader requires a dedicated IRSA role,
distinct database-login secret, exact-registration secret, separate approved
read-binding secret, RDS trust bundle and reviewed regional HTTPS/private RDS
destination CIDRs. Configure these existing identities and secrets through the
commissioning process. The chart creates no IAM roles or customer permissions.
Its reader has no Kubernetes API grants and cannot inherit the shared unrestricted
HTTPS policy. Render checks evaluate every selecting network policy because
Kubernetes grants are additive. The Helm assets remain uncommissioned until the
customer approves the actual trust policies, destinations and inputs.

Keep credentials, external IDs and machine configuration in the approved secret
store, outside tracked files. No collector startup or cloud access is implied by
registering API metadata. The reader refuses fixture mode, which cannot silently
become a live AWS connection. Local acceptance injects labelled provider doubles
into the ingestion factory instead.

The current reader supports cadence from 15 to 600 seconds and checks due work
every 15 seconds. Allow scrape/query jitter in the declared maximum gap; actual
timestamps and gaps remain visible. It holds a per-registration session lock
across capture and persists a three-minute poll lease before I/O. Capture has a
150-second budget. A process failure releases the session lock while the lease
survives; later attempts back off at one, two, four and then five minutes.
`history-poll:{registration_id}` checkpoints contain bounded status/reason codes,
the pinned registration hash, observation identifier and next poll time. Provider
bodies and private error text are not logged or checkpointed. No Temporal action
queue, signing key or customer execution credential is configured here.

## Scope evaluation and remaining gates

Scope capture selects the preceding fourteen complete UTC days using the
database clock; today's ingress cannot fill yesterday's gaps. Current source
state is resolved under synchronization/revocation guards. A revoked or changed
source does not rewrite an older snapshot; a fresh scope records the current
blocker. Explicit corrections append records and retain conflicting/forked
history as unknown.

Scopes persist compact gap/issue previews, counts and content roots, with a
separately paginated immutable reference ledger. PostgreSQL seals the complete
reference root at commit. Evaluation is bounded at 50,000 references, 256 members
per point, 1,024 source namespaces and 16 MiB of aggregate observation/activity
payloads. Dense legitimate populations can exceed this implementation's bound;
they return unavailable rather than being truncated or declared complete.
Streaming dense populations remains a separate requirement.

Public creation has a 25-second synchronous budget within the existing client
and server deadlines. Retry an uncertain outcome with the same idempotency key.
This is a request budget, not an operational latency SLO. Additive migration 025
uses forced tenant RLS and append-only tables. Existing scheduling records,
signatures and owned restoration authorization are unchanged.

Native historical interval ownership, independently commissioned business
semantics, customer history, complete fleet economics and the approved fleet
execution/rollback/verification loop remain required. These observational
records cannot be promoted into the existing fleet proof or savings ledger.
