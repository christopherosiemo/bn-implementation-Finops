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
