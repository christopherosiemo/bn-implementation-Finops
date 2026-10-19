# Native AWS hardware and capacity evidence

This increment connects registered native telemetry to read-only EC2 hardware
receipts and the actual Python capacity worker. It does not enable fleet changes,
customer Terraform applies or verified financial claims. The existing scheduling
contract, signatures and owned restoration remain separate.

The ingester captures exact `DescribeInstances`, `DescribeInstanceTypes`,
`DescribeInstanceTypeOfferings`, `DescribeImages` and `DescribeVolumes` selectors
using approved member-account read bindings in `eu-west-1`. Native configuration,
actual attached volume/image identity and numbered source bytes are checked again
before publication. Raw bytes are versioned, read back and hashed before immutable
tenant-isolated receipts are issued. Source revision, inventory version/hash,
account, resource and candidate allowlist remain bound. Revocation, inventory
changes, stale captures, archive/version failures and mismatched native selectors
prevent use. No catalogue or prices arrive from a public request.

The mapper requires history with explicitly observed `cpu_capacity` in vCPU and
`memory_capacity` in bytes before interpreting old percentage/ratio observations.
A fresh hardware snapshot alone cannot establish the denominator of historical
utilization. Configured CPU cores/threads must match the observed denominator.
MiB memory is converted to bytes exactly. Missing memory, mixed cadence, changing
denominators or unbound streams remain blockers. The initial supported hardware
calculation uses conservative single-card sustained network and single-gp3-volume
baseline limits; unknown contention or unsupported configurations stay unavailable.
Burst/up-to limits never become sustained capacity.

Capacity requests still contain only `connection_id` with the current profile
version in `If-Match`. The API selects current immutable receipts and profile
server-side, sends the bound population to the private `/v4/capacity` worker, then
validates the response schema, population/profile/hardware references and hashes
before immutable result publication. Cross-tenant requests, stale sources, altered
worker quantities/prices/probabilities and incompatible classifications fail.
The scoped cursor-paginated native result history is distinct from the legacy
blocked assessment/proposal records; it cannot silently become an executable
proposal under migration 016.

Native after-discount candidate pricing and complete commitment exposure are
still required. Where they are missing, money remains null and the result remains
blocked with execution disabled. Compatibility, a low observed utilization or a
hypothetical candidate fit does not authorize a change. The console distinguishes
observed capacity from missing native economics and recovery authority.

## Optional hardware reader

The separate `hardware-reader` process uses a distinct PostgreSQL login in the
`finops_hardware_reader` role. Each connection assumes only the ingestion group,
preserving immutable source writer provenance. Administrator, role-creation,
database-creation and RLS-bypass identities are rejected. The complete transitive
membership set may contain only the login itself, hardware-reader and ingester;
extra application, machine-observation or predefined broad roles are rejected.
At least three pool connections preserve the cross-replica lock,
tenant publication transaction and health probe independently.

The process is never started by default and refuses native AWS access in fixture
mode. Fixture acceptance injects provider-shaped readers into the same private
capture contract. Live startup requires renewable IRSA/web-identity credentials,
the commissioned tenant, approved read bindings and exact private targets. Static
AWS/object credentials are rejected. Object storage uses the regional Ireland S3
endpoint or an Ireland S3 VPC endpoint. No signing, executor, economics, analytics
or audit credentials are supplied to this process.

`AWS_HARDWARE_TARGETS_JSON` is a private array of `HardwareTarget` values containing
the exact tenant/workload/resource/provider account and region, a registered source
ID and candidate instance-type allowlist. `AWS_SOURCE_READ_BINDINGS_JSON` retains
the existing approved payer/member role and external-ID bindings. Keep both in
separately managed runtime secrets. They are not console inputs or tracked files.

The reader persists a poll lease before native I/O, serializes the same resource
across replicas and resumes from durable source checkpoints after process restart.
Success polls at most once a minute; failures back off to at most five-minute
intervals. A crash retains a bounded three-minute lease. Checkpoint health is
operational metadata and never supplies evidence authority or missing zero values.

Helm `hardware.enabled` defaults false. Enabling requires a distinct IRSA role,
database secret, approved target/read-binding secrets, explicit regional HTTPS
destination networks and private RDS subnet CIDRs in `hardware.postgresEgressCidrs`.
The rendered-policy checker examines all policies selecting this pod because
network grants are additive; broad shared database egress must not include it.
The optional Terraform `hardware_tenant_id` defaults empty,
creating no additional identity. A configured identity may write/read versions
only under its tenant's hardware raw prefix and assume explicitly listed customer
read roles. Customer read trust gains the separate hardware principal only when
`hardware_read_principal_arn` is explicitly supplied. Customer execution-role
provisioning stays disabled by default. These are deployment assets; no IAM role
or cloud resource was provisioned during this increment.

Provisioning, account access and costs remain subject to the consolidated
[commissioning dossier](commissioning-dossier.md). Begin read-only, commission
independent telemetry and genuine history, and keep customer mutations disabled
until the entire action-specific pipeline and recovery acceptance pass.

## Group-selected member evaluation

Migration 036 adds a separate analytical queue and immutable scope/member/batch
records. It does not rewrite migration 017 results, migration 035 comparisons,
existing signed plans or owned restoration. The new public request contains only
`old_configuration_proposal_id` and `candidate_configuration_proposal_id`:

- `POST/GET /v1/workloads/{id}/fleet-native-capacity-batches`
- `GET /v1/fleet-native-capacity-batches/{id}`
- `GET /v1/fleet-native-capacity-batches/{id}/members`
- `GET /v1/fleet-native-capacity-members/{id}`

Mutations require an idempotency key, the current safety-profile revision in
`If-Match`, and scoped capacity-analysis permission. The server selects the exact
group registrations, native ASG membership, candidate launch-template identity
and profile. The worker rereads both immutable receipt/revision object versions
and verifies their hashes. Concrete launch-template type, image, storage and
effective CPU/network options must agree with native hardware. Template versions
are decimal strings, preserving values above JavaScript's safe integer range.
An unsupported effective template preserves its source pins and reasons with no
usable candidate.

The original membership point is frozen before evaluating members. Missing
membership is `UNAVAILABLE`; an authenticated empty point is distinct. Missing
inventory, hardware, connections or historical statistics cannot remove an
instance from the roster. Each member uses the registered native population and
actual `/v4/capacity` model. Historical denominators and units retain the existing
017 checks. A passing physical dimension does not establish complete suitability:
commitment exposure, native avoidable economics, recovery requirements, group
safety and completed business work remain independent gates. Request throughput
is explicitly a proxy. All execution, plan and verified-saving fields remain
false or null.

The `finops_group_capacity` identity can issue only the new analytical records.
It cannot write 017 results, source receipts, signing authority or execution
state. Ordinary migrations leave it `NOLOGIN`; only an explicitly supplied local
password or separately commissioned restricted login enables a process. Scope
and member publication repeat current authority and exact membership/template
pin checks in PostgreSQL. A changed or revoked source yields explicit remaining
gaps. Previously published members remain immutable. A per-request session lock,
bounded five-minute job and refs-only resume prevent duplicate member results
after interruption. Failed authenticated object readback remains an integrity/I/O
failure and never substitutes invented observations.

The console loads workload batch history through scoped cursors, then small
member summaries. Full model evidence is fetched only when a member is selected.
It displays missing population, independent physical checks and unavailable
financial/authority gates. Refreshing a historical result does not renew it.

For the optional local process:

```powershell
node scripts/bootstrap-fleet-capacity.mjs
docker compose build api economics minio buckets
node scripts/fleet-capacity-compose-check.mjs
docker compose --profile fleet-capacity up -d fleet-capacity
```

The explicit bootstrap creates a distinct database/archive principal and five
files under ignored, owner-only `work/private/fleet-capacity-secrets`. A separate
network-isolated initializer publishes regular Linux `0444` files; the worker
mounts only its dedicated volume read-only. Reader and economics tokens use
separate files and fixed private service paths. Redirects, proxies, public IPs,
ambiguous secret paths and equal tokens are refused. Re-run the initializer and
restart the worker after credential rotation. Ordinary bootstrap and Compose
keep this worker disabled.

Hosted `fleetCapacity.enabled` also defaults false. It requires the commissioned
native reader, a distinct version-reader IRSA identity, verified-TLS PostgreSQL,
an existing CA bundle, exact bucket owner and reviewed regional/private egress.
Its only internal HTTP destinations are the installed reader and economics
services. It receives no source-write, signing, execution or deployment token.
The chart provisions no IAM role or customer workload. Deployment approval,
authentic history, native financial finality and customer operation remain in the
commissioning dossier.

The [036 acceptance record](fleet-native-capacity-acceptance.md) preserves exact implementation CI, native source/worker/browser evidence, local recovery and backup checks, retained failures and the separate local timing diagnostic. It grants bounded deterministic physical-analysis credit; hosted, whole-group, financial and customer acceptance remain open.
