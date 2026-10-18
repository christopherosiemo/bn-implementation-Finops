# Actual local Flux protocol lab

Run from the repository root:

```sh
node --test scripts/tests/flux-lab.test.mjs
node scripts/flux-lab.mjs
```

The second command creates its own three-node KIND cluster and dedicated Docker
bridge with standard KIND routing. This local fixture permits outbound traffic;
it is not a network isolation or production security boundary. It never adopts
an existing cluster or the main Compose stack. It checks
the selected Docker endpoint is a local Unix socket or named pipe and requires
at least 2.5 GiB available memory in the Docker VM before creating nodes. Images
and tools need network access during preparation; their exact digests/checksums
are pinned in `scripts/flux-bootstrap.mjs`. No customer or cloud credentials are
used. The node image is Kubernetes 1.34.11, KIND is 0.33.0, and Flux is 2.9.6 with
source-controller and kustomize-controller 1.9.6. Flux 2.9 requires Kubernetes
1.34.1 or later, so this lab does not reuse the older local reference cluster.
The three in-cluster images pin the exact linux/amd64 child manifests from
their approved upstream indexes. After archive import the driver checks the
actual manifest digest before restoring its repository name, then requires
CRI resolution of that same digest. It never gives single-platform content
a different index digest. This also works with Docker archives that omit
repository tags when exporting digest-only references.
If CRI normalizes an unnamed import to `docker.io/library/import-...`, the
driver restores that exact normalized alias only after checking the original
object's own digest. Real archive indexes keep their own hashes; the driver
does not relabel them as an upstream index or attach an index hash to a manifest.
Each run prepares fresh labelled Go module/build volumes before creating nodes.
Only copies of `go.mod` and `go.sum` enter the outbound dependency container;
the subsequent binary compilation has no network access. It does not use the
main stack's caches or mount application credentials during dependency setup.
Cleanup removes only those exact run-owned caches and any interrupted build
containers after verifying their ownership.
On Linux, containers that consume private files run as the invoking UID/GID.
Only the new empty build-cache volume's root is assigned that ownership, with
a nonrecursive, network-free helper; downloaded modules are mounted read-only.
Private run directories remain `0700` and the synthetic Git config is `0600`.
The Docker daemon must use the containerd image store, so archive export retains
the original OCI manifest bytes. The script checks this before creating any
resources and never changes daemon settings. A dedicated disposable CI runner
can enable it with the official
[Docker setup action](https://github.com/docker/setup-docker-action), using
`features.containerd-snapshotter: true` in its daemon configuration. This is
separate from the existing local daemon and main lab. Docker documents the
[GitHub runner image-store setup](https://docs.docker.com/build/ci/github-actions/multi-platform/).

The fixture creates a real local Git repository and serves it with a read-only
smart HTTP Git server in its exact owned control-plane node's network namespace
on the dedicated bridge. The node has the native CNI return routes needed by
controller pods. This changes no global routes or firewall rules. The server has no published host
port, Kubernetes token, administrator configuration, or writable repository.
The controller applies committed resources through a dedicated namespaced
service account. The applier observes ReplicaSets and Pods with GET/LIST/WATCH
for the controller's native deployment health checks; it cannot mutate those
children or read Secrets. The safety reader can read native inventory and the
exact Flux source/controller objects. Its only artifact transport is GET through the
Kubernetes API proxy for `source-controller:80`; it has no write, secret-read, or
other Service-proxy permission.
The driver initializes a fresh synthetic bare repository, then writes its exact
three-field core configuration before publishing any commit. This removes
filesystem auto-detection such as Windows `core.ignorecase`; it never rewrites
an existing user's repository or broadens the Git server's config allowlist.
The actual Linux Git/server validation runs without network before any nodes
are created, so initialization failures stop before cluster bootstrap.

The API is bound to localhost only. KIND labels its custom Docker network
override experimental; this use is limited to the local fixture. Administration
uses the private run kubeconfig or Docker exec; the read-only collector uses
the exact internal TLS endpoint. No global Kubernetes context is changed.

The protocol exercises a Git-owned memory-request rollout, an explicit
zero-disruption PDB preflight refusal before any Git change, an intentionally
bad readiness-probe commit, native partial and failed reconciliation, and an
owned Git-revert recovery. Deployment rollouts do not inherently honor eviction
PDBs; the PDB assertion tests the application's preflight gate. The failing probe
is an explicit fixture fault, rather than an additional public action type.
The driver never directly persists a workload Deployment change.

The reader pins source/controller UIDs, repository URL, branch, namespace,
path, applier identity, native artifact digest and exact successful revision.
It requires current generations and Ready conditions, reads the digest-checked
archive through the pinned TLS API, and rechecks authority resource versions
after fetching it. Freshness comes from the controller's matching successful
history entry. A reconcile-request annotation is not an observation timestamp.
The existing `VerifySync` checks still require the Git-derived and live
Deployment-spec hashes to equal the approved hash.

The first renderer deliberately accepts only the fixture's static three-file
layout: a Deployment JSON, a ConfigMap JSON and a JSON-form Kustomization with
those two resources. It rejects extra files, transforms, substitutions,
remote sources, links, path traversal, oversized archives and changed
authority. The archive binds the ConfigMap source bytes, but this component does
not prove live ConfigMap/application-code equivalence. It provides bounded
Deployment-spec evidence. Hosted EKS/AKS/GKE acceptance, arbitrary Kustomize
features, tenant API/runtime integration, SLO/economics and financial claims
remain outside this local protocol.

Successful evidence is written under the ignored `work/flux-lab/` directory.
Cleanup checks exact run IDs, node names/images and network/container ownership
before deleting only its own resources. Reader tokens and temporary admin
kubeconfig are removed after successful cleanup. Bounded startup/failure
snapshots remain for diagnosis. If cleanup refuses an ownership mismatch, it
reports the refusal instead of deleting an unfamiliar resource.

The driver writes `acceptance.json` and reports PASS only after the complete
native rollout, PDB refusal, failed readiness, Git revert and owned cleanup
succeed. `work/flux-lab/acceptance.json` is the most recent successful result;
a later failed run preserves that historical success. Match its `observed_at`
and cluster/source identifiers to the current run's UUID-directory evidence,
and require that process or exact CI job to succeed. Per-run failure diagnostics
are authoritative for that failed run. The separate Flux CI job uploads bounded
acceptance or failure evidence as `local-flux-acceptance`. A missing PASS or
unit-test success alone does not establish native controller acceptance.

Primary references:

- [Flux 2.9.6 release](https://github.com/fluxcd/flux2/releases/tag/v2.9.6)
- [Flux installation prerequisites](https://fluxcd.io/flux/installation/)
- [GitRepository native artifact and status](https://fluxcd.io/flux/components/source/gitrepositories/)
- [Kustomization reconciliation, impersonation and status](https://fluxcd.io/flux/components/kustomize/kustomizations/)
- [Pinned deployment health reader](https://github.com/fluxcd/cli-utils/blob/v1.2.3/pkg/kstatus/polling/statusreaders/deployment.go) and [ReplicaSet/Pod traversal](https://github.com/fluxcd/cli-utils/blob/v1.2.3/pkg/kstatus/polling/statusreaders/replicaset.go)
- [Flux security practices](https://fluxcd.io/flux/security/best-practices/)
- [KIND 0.33.0 release](https://github.com/kubernetes-sigs/kind/releases/tag/v0.33.0)
