# Native fleet joint decision

This analytical component joins an issued native account-rate assessment (035)
and an issued per-member physical capacity batch (036). It does not approve or
execute a fleet change. Conditional historical account-rate arithmetic,
physical checks, complete workload suitability and verified savings remain
separate facts.

## Request and result

Choose the original/candidate proposal pair and save the workload safety
profile first. Obtain fresh assessment and capacity records for that exact
selection. A finance-authorized workload operator can submit:

```http
POST /v1/workloads/{workload_id}/fleet-joint-decisions
Idempotency-Key: <fresh request key>
If-Match: <current safety profile version>
Content-Type: application/json

{"assessment_request_id":"<issued 035 request>","capacity_batch_request_id":"<issued 036 request>"}
```

The API accepts identifiers only. It resolves immutable records and current
source authority under the tenant graph lock. The assessed selection, profile,
roster and source pins must agree. An assessment older than two minutes,
capacity scope/member observations older than five minutes, expired rates,
revocation, changed source heads or a changed profile requires recomputation.
These freshness checks do not replace the separate execution safety gates.

Use the workload collection with its opaque cursor to list bounded summaries;
fetch `/v1/fleet-joint-decisions/{request_id}` for the complete decision.
An accepted request progresses from `QUEUED` to `ASSESSED` or an immutable
`REFUSED` outcome. Refusal reason codes distinguish changed inputs,
unsupported input/model formats and unsupported retained decimal precision.
A refusal contains no decision or monetary claim. Recompute the necessary
source analyses and submit a new request after resolving its cause. Transient
database failures remain retryable and do not become invented terminal facts.
Every member has CPU, memory, network, storage IOPS and storage throughput
checks with units and `PASS`, `FAIL` or `UNKNOWN`. Missing observations remain
unknown. A known failure takes precedence over an unknown in aggregate status.
Complete dimensional physical checks still do not establish group capacity,
business-work preservation, SLOs, recovery or execution authority.

The scenario reuses the exact conditional hourly estimate from 035. It does
not convert historical costs into a future contracted avoidable price.
Unavailable prices remain unavailable; zero and negative conditional
differences retain their meaning. `contracted_avoidable_cost`,
`estimated_saving` and `verified_saving` remain null. Plan eligibility and
execution authorization remain false.

## Optional deployment

Migration 037 adds append-only requests and decisions under forced tenant RLS.
Migration 038 independently binds the dedicated database login and its live
PostgreSQL role OID to one tenant. The database checks `SESSION_USER`, so
changing `app.tenant_id` or using `SET ROLE` cannot select another tenant.
The registry and revocations are operator-controlled and append-only; API and
worker identities cannot commission themselves. Startup and readiness require
the configured tenant to match the installed, unrevoked binding. All earlier
migration bytes and historical decision records remain unchanged.
The machine credential also requires `READ COMMITTED`, the worker's normal
transaction isolation. An attacker-controlled transaction cannot retain an old
revocation snapshot using `REPEATABLE READ` or `SERIALIZABLE`. The authenticated
API retains its separate transaction authority.
The `finops_group_decision` group is `NOLOGIN`; a distinct commissioned login
may assume it. The process resolves narrow input sets through a guarded
database function and can publish its own analytical results. It cannot write
source observations, earlier assessments, financial ledgers, signed plans or
execution state. API, ingestion, financial, deployment and signing identities
must not receive this login or its secret.

The process is disabled by default. Local Compose and Helm provide separate
opt-in deployment assets. Hosted mode requires an operator-verified database
CA, `verify-full`, exact tenant and bounded private database networks. Its
service account does not mount a Kubernetes token or assume an AWS role. Its
only persistent credential is the separate PostgreSQL login. Neither enabling
this component nor rendering its deployment provisions a cloud resource.

Commission the login and secret outside tracked files. Review generated SQL
before applying it to the intended database; the bootstrap does not silently
run database administration. Secret files must remain regular files with
restricted permissions. Restart the process after rotating a subPath-mounted
Kubernetes secret. Do not copy another worker's multi-secret bundle.

For a new login, review and apply the generated atomic role-and-binding SQL
after migration 038. A legacy three-file credential bundle is preserved
byte-for-byte and reports that an explicit scope binding is required. Review
the separate upgrade binding against the exact existing login, tenant and
operator-inspected live role OID; it neither changes the password nor connects
to the database. Do not replace legacy private material to make readiness
appear healthy. A dropped and recreated role or a database restore can change
the OID and must fail closed. Commission a fresh dedicated login for rotation
or a recreated role; do not reuse its predecessor's immutable binding ID.
Revocation blocks new analytical publication and leaves historical
evidence readable through the authenticated API. Scheduling restoration uses
its separate original authority throughout.

For the explicit legacy upgrade, retain the existing bootstrap tenant,
database mode, host and database-name settings. Set
`FLEET_DECISION_ENABLED=true` and `FLEET_DECISION_CREDENTIAL_ROLE_OID` to the
operator-inspected live decimal OID, then run:

```sh
node scripts/bootstrap-fleet-decision-credential-binding.mjs
```

It writes only private `binding.sql` and `binding.json` in
`work/private/fleet-decision-credential-binding/`. Review and apply that SQL
through the intended database's operator channel after migration 038. Never
commit the private files. Bootstrap output is a preparation receipt; actual
database readiness confirms installation separately.

## Recovery and acceptance limits

Queue and result state live in PostgreSQL. Process replacement may reread
unfinished requests and repeat consistency checks; it cannot grant new
authority. Completed evidence remains immutable and readable even when later
authority changes. New publication must satisfy current authority again.
Existing scheduling restoration uses its original ownership and remains
independent of this analytical component.

The following remain separate acceptance gates: the complete native cost and
physical join in real local services, real OIDC through the served console,
worker replacement, rejection and replay cases, full final-commit CI,
supervised customer sources, complete group feasibility and action-specific
execution. Synthetic provider responses and historical observations must stay
visibly labelled. No hosted, savings or customer-operation acceptance follows
from a pure join or a deployment render.
