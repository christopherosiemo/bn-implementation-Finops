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
