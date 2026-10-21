# AWS pilot readiness closure

Starting source: `20dd765d7414764056c7e0aeae8935e389dc1be2`, draft PR #1.
Official contractual maturity starts at **26.9%**. This is exactly three
forward-only checkpoints, ending before real customer credentials are connected.
The 233-section specification, fixed weights, old acceptance reviews and wider
obligations remain unchanged. No provisioning, purchasing, customer mutation,
execution enablement or new verified-savings claim is part of this sprint.

## Checkpoint A: secure release baseline

Active Go build, CI, fixture/tooling and current operating references now use
`golang:1.27.3-bookworm@sha256:32fa283222e2905d9fee971f60c842e5c815fdc036cf7ea599bf36bd7ca8f67f`.
The official manifest index was inspected before selection. Go's published
[release history](https://go.dev/doc/devel/release#go1.27.0) identifies 1.27.3 as
the crypto/x509 security update. The module language floor remains Go 1.26.0;
Temporal 1.27.2 and historical evidence are different pins and remain unchanged.
Exact fixture Dockerfile assertions track the new reviewed artifact.

Component validation: 103 existing focused Node/static checks passed without
skips, all 22 changed JavaScript files passed syntax checks, and diff whitespace
checks passed. Historical acceptance, release mapping, previous sprint evidence,
go.mod/go.sum and Temporal configuration were verified unchanged.

The first local fixed-image download ended in a DockerHub layer EOF, classified
`EXTERNAL_INFRASTRUCTURE_FAILURE`. It was not retried or replaced with an
unreviewed image. Required checkpoint CI performs the actual reachable
`govulncheck` and existing Go/test/race, contract, dependency, secret and
infrastructure gates. The pushed checkpoint is
`71e1f88ce4e561bfc0a6173309aee368f19f5a69`. Its required reachable scan
**passed** in run `39557938865`, security job `119082036849`; the security
baseline subset is COMPLETE. This closes the reported Go release failure without
suppressing the advisory. Economics, generated types/build, dependency audits,
secret scan and infrastructure also passed. Terminal required CI is **13 PASS /
3 historical FAIL**; optional fleet-protocol is skipped. The three historical commitment/fleet jobs remain
enabled and outside investigation unless a concrete new regression is exposed.
No maturity points are claimed by pin changes or test counts.

## Checkpoint B: bounded connected acceptance

The selected paths are Lambda memory, S3 Standard-to-IA, same-region gateway
endpoint review and one ECS/Fargate service rightsizing path. The implementation
also closes the EKS/Kubernetes identity association. Each receives one connected
attempt; a concrete introduced defect permits one minimal repair and rerun.
Other failures are recorded and deferred without increasing limits or retries.

Lambda uses its own optional object/analytics machine identity. Secrets remain
private; identities, audiences, subjects and source bindings are not shared or
bypassed. Full family Python modules may replace redundant full-suite preflights
only while the full economics suite remains a required final-source CI gate.
Original deadlines, CPU/memory budgets, safety assertions, private model calls,
ordinary OIDC and independent persisted readback remain unchanged.

### Equivalent Python gate composition

The existing connected invocations now discover each complete relevant module:
`test_lambda.py`, `test_object_storage.py` and `test_network.py`. Their module
scope includes private HTTP authentication, safety refusals and decimal model
tests. The full `python -m unittest discover -s tests -v` remains unchanged in the
required economics CI job and must pass on final source before acceptance is
banked. The combined validation is the full suite plus each connected persisted
native/model/browser path, with no removed or split safety tests. Preflights
retain 120 seconds, 512 MiB, one CPU, strict successful-summary parsing and no
accepted skips. Actual CUR normalization and private model HTTP calls remain in
the connected journey. Invocation parent/child hashes and receipts are retained
privately; historical invocations and failed receipts are not rewritten.

### Lambda identity commissioning

Explicit bootstrap opt-in now creates four distinct, replay-stable local secrets
without enabling ingress. Existing empty rows are replaced once; duplicate keys
or mixed identities are refused. Targeted object initialization commissions only
the existing Lambda performance writer policy and user. The explicit local
ClickHouse commissioning command creates that dedicated identity with INSERT on
`native_metric_samples` and `native_metric_batches`, plus SELECT on only the six
columns needed for exact sample readback. It grants no other tables, roles, DDL
or user-management rights and preserves unrelated metadata. Authentication and
tenant/source binding remain the trusted-ingress boundary; these grants are not
database row-level isolation. Neither external AWS nor execution authority is
added. Actual local bootstrap, targeted object commissioning and ClickHouse
commissioning passed; the positive connected result is still pending.

ECS/Fargate retains stable service assessments and real task billing identities.
Only an evidenced long-lived homogeneous cohort with complete history qualifies.
Current task rosters cannot establish historical membership. Native dimensional
metadata does not supply customer prices. EKS associations require independent
native and Kubernetes identities; unknown placement remains blocked and creates
no additional charge or execution authority.

### Bounded checkpoint-B outcome

**PARTIAL; official 26.9 → 26.9.** Actual local Lambda bootstrap, dedicated
MinIO policy/user and narrowly granted ClickHouse identity commissioning passed.
The existing default-off service-assessor object identity was also commissioned
without sharing the ingress identity or changing unrelated users. Ingress and
analytical deployments remain disabled by default.

Lambda, S3 and Network each received one bounded connected invocation. All
stopped at the exact pinned Go-image inspection before Python/native tests:
the approved image is absent following DockerHub EOF downloads. Each retained
receipt confirms zero tests and successful cleanup. These are
`EXTERNAL_INFRASTRUCTURE_FAILURE`, not positive acceptance. ECS received one
invocation, which stopped at a source-file assertion (service path selected;
test actually resides in workflow). This is `UNKNOWN_ACCEPTANCE_FAILURE`;
no acceptance-infrastructure repair or second family was started.

ECS native cohort, customer-rate dimensions, financial association and component
coverage are implemented. Review also found that rightsizing could bypass
independent historical work evidence. One minimal product correction now blocks
all ECS decisions without complete demand, preserving current cost while leaving
candidate savings and analysed charge claims unavailable; 12 focused model
checks passed. Its positive connected assertion remains unchanged. The existing
analyst cannot yet read a trusted ECS historical-demand source. This is a
software gap, not a customer commissioning task disguised as readiness.

EKS association now has independent native endpoint/CA and observed Kubernetes
UID/provider identities, managed-capacity/Fargate placement proofs, immutable
tenant-RLS migration 048, currentness, source/API and ordinary console paths.
Unknown placement remains blocked and relationships create no additional cost.
Frontend generation/build, 29 migration/static checks and default/enabled Helm
secret-boundary renders passed. Ten Go identity tests remain locally unrun
because the fixed image is unavailable. Genuine TLS/native archive-to-console
acceptance and customer commissioning remain outstanding. Migrations 001–047
are unchanged; 048 hash is
`73acc6ce78d3d0b4506baf0bbce36945e6cfba46d9d9ae60512deafe2eda4152`.

The central Node rerun passed 34 checks with one platform-specific shell case
skipped; the targeted actual local commissioning above passed independently.
No whole-family maturity transition, live acceptance or new savings is claimed.
Private receipts retain source hashes, original limits and failure evidence.
All five slices are PARTIAL; genuine AWS/customer/operational requirements are
`EXTERNAL_ACCEPTANCE_REQUIRED`. Checkpoint CI will run on the pushed source.

## Checkpoint C: read-only commissioning product

Account onboarding selects an approved operator-managed secret binding ID.
External IDs, credentials and session tokens stay out of API documents, exports
and logs. Provider checks run in the ingestion identity. Read access, evidence
quality and economic recommendation readiness remain separate dimensions.

The commissioning result must retain identity, access states, billing and
telemetry evidence, ownership/workload/authority gaps, exact spend coverage and
specific remediation. AccessDenied is not absence. Unallocated spend is an
attribution overlay, never another additive charge bucket. Unknown denominators
or zero positive denominators have unavailable percentages; credits and
currencies remain separate. Historical reports remain immutable and explicitly
as-of, with source currentness shown separately.

Software acceptance uses provider-shaped synthetic evidence and the normal
authenticated product. Genuine AWS roles, sources, histories, customer
requirements and operational use remain `EXTERNAL_ACCEPTANCE_REQUIRED`.

## Delivery and failure rules

Every failure is classified once as `NEW_PRODUCT_DEFECT`,
`PRE_EXISTING_ACCEPTANCE_DEBT`, `EXTERNAL_INFRASTRUCTURE_FAILURE` or
`UNKNOWN_ACCEPTANCE_FAILURE`. Only a concrete new defect receives one repair and
one relevant rerun. Earlier failed evidence is retained. Explicitly requested
closure of known security/commissioning debt is implementation, not an excuse
for unbounded historical investigation.

Each checkpoint is committed and pushed, with actual required-CI states and
accepted scope reported. Normal checkpoint CI may run alongside the next
milestone; final source runs all existing required gates and migration/recovery
acceptance. Existing owned EC2 restoration remains authorized. Overall CI is
never called green while a required job fails. After checkpoint C, leave the
worktree clean, PR draft/unmerged, and stop. Human-supervised real AWS read-only
commissioning is the next phase and is not started here.
