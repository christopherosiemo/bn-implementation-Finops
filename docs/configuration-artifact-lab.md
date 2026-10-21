# Local configuration artifact acceptance

After starting the local fixture Compose stack, run these commands sequentially:

```sh
node --test scripts/tests/configuration-artifact-lab.test.mjs scripts/tests/fixture-go-modules.test.mjs
node scripts/configuration-artifact-lab.mjs
```

The runner requires the current workspace's running fixture API, PostgreSQL and
MinIO containers and a verified local Docker daemon. It builds a uniquely labelled
tooling image from the reviewed digest-pinned Go 1.27.3 / Terraform 1.16 Dockerfile.
It creates a new internal network, new PostgreSQL and MinIO services with random
local credentials, and a read-only public source snapshot. The test receives no
application storage, application credentials, cloud credentials or Docker socket.

Every run starts with fresh labelled module and build cache volumes. A separate
credential-free outbound process mounts only copied `go.mod` and `go.sum` to
download modules. The acceptance process uses the internal network, the downloaded
modules and an empty build cache. Private credentials never enter the outbound
process or tooling build. Resource limits remain in effect during cold
compilation. Module download has a
300-second bound; the credentialed cold compile/test/vet process has a 600-second
bound. In the actual local cold run, the test itself took about 10 seconds and
cold compilation plus test and vet took about four minutes. These are local lab
timings, not product SLO or recovery evidence.

The required test is
`TestArtifactActualGitTerraformEncryptedPostgresS3`. It exercises actual local
Git and built-in `terraform_data` fixture state, restricted PostgreSQL roles and
encrypted, version-pinned MinIO objects, including process loss and replay. It
must pass its storage journey without skipping. The observed cloud declaration
remains `BLOCKED / CONFIGURATION_DECLARED_ADDRESS_UNOBSERVED`; there are no AWS
calls, execution permission or verified savings.

The runner cleans only its exact named and labelled containers, network, image
tag and cache volumes, checking ownership before removal. Acceptance is recorded
only after cleanup succeeds. Its ignored `work/private/configuration-artifact/`
directory retains restricted local environment and diagnostic files; do not
publish those files. The main application's database and migration history are
never changed.

The direct test environment variables and the remaining private attestor limits
are described in [ARTIFACTS.md](../internal/configuration/ARTIFACTS.md). This lab
does not establish native cloud state freshness, remote Git authority or a
permitted deployment.

## Read-only recommendation revision checks

Recommendation currentness binds the existing Terraform authority's exact
repository/ref to an operator-approved local checkout, validates that checkout,
then reads the exact approved HTTPS remote branch with bounded `git ls-remote`.
An unchanged local checkout alone cannot establish currentness. The API does
not clone, fetch objects, update branches, inspect credentials, run Terraform or
apply a change. The operator's existing repository process maintains the
checkout outside the application. The initial resolver supports explicit
branches such as `main` or `refs/heads/main`; unresolved refs, annotated tags,
private remotes requiring credentials and unavailable networks remain unknown.

Configure API-only `CONFIGURATION_REVISION_BINDINGS_JSON` outside tracked files.
The registry key is `tenant_id:authority_id`; each value binds those exact IDs,
an absolute `repository_root`, and the declared `repository` object containing
`url`, `ref` and `directory`. For example, approved metadata can bind
`tenant-demo:approved-terraform` to repository
`https://github.com/example/approved-infrastructure.git`, ref `main`, directory
`terraform`, and root
`/var/run/finops/configuration-revisions/tenant-demo/infrastructure`.
URLs contain no credentials. No public API selects the local root or executable.

For Compose, set that variable in the existing untracked operator environment
and mount the approved checkout into the API through a local Compose override
with `read_only: true` and `bind.create_host_path: false`. The base Compose file
mounts no checkout. For Helm, set `configurationRevision.bindingsJSON` and
`configurationRevision.existingClaim` to an existing operator-provided claim.
Only the API mounts it, read-only, at
`/var/run/finops/configuration-revisions`. The chart creates no repository,
synchronizer, persistent volume, PVC, identity or credentials. Default bindings
are empty and the optional claim is absent. Ensure the existing checkout is
readable by UID 10001 and satisfies Git's ownership checks without a global
`safe.directory=*` exception.

The resolver reuses the artifact collector's hardened Git environment and
bounded source checks. Its remote read disables credential helpers, prompts,
redirects and non-HTTPS protocols, and keeps certificate validation enabled.
Wrong tenant/authority/repository/ref, dirty or unsafe source, symlinks,
missing bindings and unresolved or unavailable remote refs return only
`IAC_REVISION_UNAVAILABLE`; paths, Git errors and source contents are not exposed.
A changed observed commit invalidates the prior recommendation's currentness.
The analysed commit, repository identity, ref, files and Terraform addresses
remain in immutable authority/artifact references; resolution rewrites none of
that history. An unavailable revision cannot establish execution readiness.
