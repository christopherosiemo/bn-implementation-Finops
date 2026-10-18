# Private Terraform artifact observations

This component is unregistered and has no public upload route, runtime, signing,
execution or savings integration. Frozen configuration declarations remain
`DECLARED_NOT_ATTESTED`. Receipts cannot clear a Fleet proof gate by themselves.

`ArtifactRegistration` is private operator configuration binding a current
declaration revision, current tenant/workload/resource snapshot, dedicated OIDC
issuer/audience/subject/pipeline, and pinned Terraform toolchain. A verified
machine token must contain only `finops-configuration-attestor` as its audience;
human roles, console tokens and tenant/subject substitution fail. The existing
declaration's deployment-callback audience is deliberately unchanged.

`ArtifactPipeline.Capture` accepts a verified principal, registered ID and
idempotency key. Local paths and tool commands come from private process
configuration. Capture reads a local repository without fetching it, compares
an immutable HEAD commit/tree with the cached index and ordinary file bytes,
and rejects every untracked/ignored input except the validated `.terraform`
metadata. It never invokes Git status/diff, filters, hooks, lazy fetch, external
modules or arbitrary request commands. Local config/attributes, symlinks,
submodules and incomplete dependency capture fail closed. The same source,
state and saved plan are checked again after inspection.

Production tools use a pinned local Docker daemon endpoint and image with a
read-only filesystem/source/artifact mounts, no network, no capabilities, fixed
workdir, resource limits and a minimal environment. The only Terraform commands
are `version -json`, `show -json` for the captured plan/state, and `workspace show`.
No init, plan, refresh, apply, provider download or repository execution occurs.

The first supported toolchain is Terraform 1.16.0 with its built-in provider and
complete local committed modules. A bounded, non-extracting adapter checks that
the saved binary's embedded source snapshots match the committed files and its
current state matches the selected raw lineage/serial/state. The native previous
state uses a documented-in-source stub header; only that exact empty-lineage,
zero-serial pair is normalized, while the current state must match completely.
Unknown plan layouts and other versions fail closed. Filesystem functions,
unbound variables, external providers/modules and provisioners remain blockers.

Terraform's binary layout is opaque and version-dependent; the official pinned
CLI still creates the JSON representation from the exact binary. See the
[show contract](https://developer.hashicorp.com/terraform/cli/commands/show),
[JSON representation](https://developer.hashicorp.com/terraform/internals/json-format),
[pinned source snapshots](https://github.com/hashicorp/terraform/blob/v1.16.0/internal/plans/planfile/config_snapshot.go)
and [previous-state header](https://github.com/hashicorp/terraform/blob/v1.16.0/internal/backend/local/backend_plan.go#L159).

Saved plans, configuration and state are sensitive. The whole bundle is encrypted
with a new AES-256-GCM data key before object storage. Tenant, immutable job ID,
artifact kind and plaintext hash are authenticated context. Live capture requires
a commissioned regional KMS client/key; unavailable KMS never falls back to a
local key. Fixture keys are accepted only in explicit fixture mode. Readback pins
the actual object VersionID, ciphertext hash and size, then authenticates/decrypts
and revalidates the complete original bundle. Bucket retention/IAM, live key
custody and customer identity commissioning remain separate deployment gates.

Migration 020 introduces an independent NOLOGIN group and append-only FORCE RLS
metadata tables. The runtime login must have exactly itself plus the attestor
group as transitive memberships, no elevated/replication flags, no startup role
override, and verified TLS outside local fixtures. It has inventory/declaration
read access and its own evidence writes; API access is metadata SELECT only.
Current declaration/resource binding and source revocation are rechecked under
the same graph/registration locks before publication. Receipt observation and
expiry are anchored to the original immutable job creation, not a delayed first
publication or replay. SQL/transport faults remain distinct from source refusal.

`PublicProjection` returns IDs, binding, hashes, status/reasons and timestamps.
It excludes file names/content, plan/state/variable values and object URLs.
Every receipt has `execution_authorized:false`, `verified_saving:null` and explicit
remote-Git/native-state freshness gaps. A registered machine is the observation
trust boundary; this does not prove the remote branch head, cloud state freshness,
an independently reviewed configuration authority or a permitted deployment.

The local test deliberately maps an actual `terraform_data` plan to a cloud
declaration. Because frozen 016 requires cloud resource addresses, the result is
`BLOCKED` with `CONFIGURATION_DECLARED_ADDRESS_UNOBSERVED`. The test does not fake
AWS state or remove this blocker to manufacture a positive authority claim.

## Isolated acceptance

Build `testdata/artifact.Dockerfile` as a disposable tooling image. Run package
tests with the repository mounted read-only, `/workspace` empty and ephemeral,
`TEST_ARTIFACT_TERRAFORM=/usr/local/bin/terraform` and
`TEST_ARTIFACT_WORKSPACE=/workspace`. The ordinary unit tests need only Go.

For full storage acceptance, use a dedicated Docker **internal** network, a new
PostgreSQL service aliased `postgres`, and a new versioned MinIO service aliased
`minio`. Set `TEST_ARTIFACT_ADMIN_URL` to that isolated local administrator,
`TEST_ARTIFACT_S3_ENDPOINT=http://minio:9000` and the isolated fixture S3 key/secret.
No cloud endpoint is accepted by the storage test. It creates a unique database,
login and exact-owner-tagged bucket and removes only those owned test resources.

The test setup runs built-in `terraform_data` init/plan/apply only to produce
real local fixture state and a saved plan. There are no AWS calls/resources.
The actual collector remains read-only. Acceptance covers real Git/source/index
and commit races, local-filter side effects, embedded source/state binding,
strict OIDC audience/roles, encrypted version readback, process/pool loss before
receipt, replay, latest-version overwrite, cross-tenant denial, source revocation
during archive, SQL mutation/role isolation and absence of financial authority.
