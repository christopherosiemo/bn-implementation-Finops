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
infrastructure gates. **Security acceptance is pending on this pushed source;
Checkpoint A cannot be COMPLETE until the vulnerability scan itself passes.**
No advisory is suppressed. The three historical commitment/fleet jobs remain
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

ECS/Fargate retains stable service assessments and real task billing identities.
Only an evidenced long-lived homogeneous cohort with complete history qualifies.
Current task rosters cannot establish historical membership. Native dimensional
metadata does not supply customer prices. EKS associations require independent
native and Kubernetes identities; unknown placement remains blocked and creates
no additional charge or execution authority.

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
