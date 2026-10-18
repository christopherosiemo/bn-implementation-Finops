# Fleet, configuration and local Kubernetes components

These additive components advance M3/M4. They do not complete the fleet operating
loop, enable customer mutations or establish hosted Kubernetes acceptance.
The existing scheduling plans, signing domains and Temporal workflow remain
separate. No AWS resources were provisioned or changed.

## Configuration and pipeline identity

The scoped configuration API records immutable Terraform declarations bound to
the actual tenant, resource, workload, provider account/region and inventory
version/hash. A declaration contains repository metadata, a dedicated pipeline
identity, workspace, state lineage and managed addresses. It is always
`DECLARED_NOT_ATTESTED`, with execution disabled. URLs are validated metadata,
never fetched. Branch names and declared state lineage do not prove a Git commit
or observed Terraform state. A blocked proposal selects an existing current
capacity assessment server-side; it cannot accept a patch, price, trusted proof,
plan or execution permission from the console. Monetary results remain null.

The optional `deployment-observer` process has a separate PostgreSQL identity and
OIDC audience. It retains authenticated raw callback bytes and their hash, issuer,
subject, source, receive time and exact command/artifact/state bindings. Console
and approval tokens cannot submit observations. Exact replay returns the same
receipt; changed bytes, identity confusion, mismatched commands and contradictory
outcomes fail closed. An `APPLIED` callback establishes ownership, not health or
permission to expand. It cannot release a reservation, approve, sign, dispatch,
write financial claims or assume a customer role. Compose profile `fleet` and
Helm `deploymentObserver.enabled` are opt-in receipt-ingress controls only.

Hosted observer assets use a separate database secret, no IRSA credential,
approved JWKS HTTPS networks and explicit ingress selectors. Its OIDC provider
must issue the tenant claim itself. A native CI token without that claim needs
an explicitly commissioned federation mapping; a body/header cannot supply it.

## Separate fleet contract

`FleetPlanV4` binds immutable evidence references, exact configuration authority,
Git commit, Terraform addresses and state lineage/serial, concrete launch-template
versions, cohort/traffic constraints, economics and compensation. The v4 Ed25519
domains are distinct from scheduling signatures. The offline workload validator
checks a fresh saved binary, its exact JSON digest, authenticated pipeline
provenance and only the signed stage changes. It rejects stale state, changed
configuration, drift, unknown fields and unrelated creation/replacement/deletion.
ALB set ordering is canonicalized only for the two approved target-group ARNs;
their identity and exact per-ARN weights stay bound.

The reference starts old=20/candidate=0. The first canary is at most two members;
later capacity steps are also at most two. Expansion milestones do not enlarge
the simultaneous-change budget. Old capacity stays until full candidate health
and separately reviewed cleanup. Native ASG replacement, rebalance, refresh,
scheduled scaling and alarm scaling must be explicitly coordinated/suspended;
the reference is not a general unattended ASG default. See the
[Terraform reference](../examples/terraform-fleet/README.md).

PostgreSQL serializes disruption reservations across overlapping plans for the
same workload. Dispatch intent and original dispatch time are durable. Unknown
responses retain their reservation and enter reconciliation; they cannot cause
blind redispatch. A separate Temporal v4 workflow component preserves this
behavior through cancellation/replay. It is not registered to a live execution
queue. Recovery signatures bind genuinely owned changes and a fresh inverse
saved plan, independently of new-change expiry/pause. Rollback disqualifies the
affected result from positive verified savings. Modeled duration bounds the
transition-cost estimate; outages and continuing recovery obligations can exceed
that estimate, so it is not an enforceable cloud spending ceiling.

The native inventory factories use ingester-only approved read-role and exact
group bindings. Parent-independent discovery publishes `OBSERVED_ONLY` evidence;
missing resource mappings remain explicit. Signed-stage captures bind the exact
expected member counts and native launch-template pins. A separate template
receipt archives native numbered-version responses. Versioned raw objects are
read back and hashed before receipt publication. These inventory receipts do not
create billing coverage or prove statelessness. AMI-inherited storage and actual
attached-volume state remain unknown until independently observed.

The cohort calculator checks every member, frozen-blue and current-blue/green
scope, complete windows and conservative histogram bounds. Absolute SLOs and
regression limits are independent; a 35% regression breaches a 15% allowance.
A quiet unhealthy member cannot hide behind a healthy high-volume member.
The private health factory selects continuously observed evidence for the
**entire signed stage window**, preserves any failure latch and rejects gaps.
Elapsed time plus a fresh two-minute snapshot does not prove an hour of safe
canary operation. Its [separate real-clock protocol gate](fleet-cohort-health.md)
does not register a runtime queue. Current private artifact/rate components,
connected authority/capacity/financial factories, customer pipeline dispatch,
the full fleet journey and financial verification remain required before R2
execution can be enabled. No public API signs or dispatches these v4 plans in
this increment.

Terraform binary/JSON/state artifacts can contain sensitive values. Keep them in
restricted encrypted storage, never public API payloads, logs or Git. The offline
wrapper mounts only bounded explicit artifacts and validator sources, without
network or cloud credentials; repository escapes, symlinks outside the checkout
and Docker mount-delimiter injection are rejected.

## Real local Kubernetes lab

The reproducible Windows/Linux x64 bootstrap verifies official binary and image
digests, accepts only a local Docker transport and uses a private workspace
kubeconfig. The actual three-node, two-worker-zone lab exercises a separate
read-only ServiceAccount, exact local Git revision/spec reconciliation, an
explicit zero-disruption PDB block, failed readiness and Git rollback to healthy
replicas. Inventory pins cluster/namespace/Deployment UIDs. Completion rechecks
classification, ownership, controller generation, exact spec, replica/zone health
and restart/OOM evidence. The HPA example starts at a stable two-replica target:
490m observed CPU, 1000m requests, 50% target; reducing requests to 700m produces
three replicas and 2100m total requests instead of 2000m.

The controller is explicitly `LOCAL_GITOPS_TEST_DOUBLE`, not hosted Argo CD or
Flux. Deployment updates do not automatically obey PDBs, so assessment checks
them before Git mutation. Request reductions, VPA/HPA collisions, unknown
autoscaler coordination, missing recovery/capacity evidence and hosted mutation
stay blocked. No node-cost realization, workload-normalized financial saving or
customer production acceptance is established. The lab's private evidence is in
`work/kubernetes-lab/acceptance.json`; CI retains only that bounded evidence, not
kubeconfig or ServiceAccount credentials. See [local reproduction](../examples/kubernetes/README.md).

A separate [native Flux lab](../examples/flux/README.md) installs pinned real
source and Kustomize controllers in a new three-node cluster. Its read-only
collector binds native source/controller identities, generations, exact Git
revision, artifact digest and Deployment spec. The constrained renderer accepts
only the static fixture layout; it does not establish live ConfigMap or code
equivalence. The complete native journey requires successful rollout, an
explicit PDB preflight refusal, failed readiness and an owned Git-revert
recovery before its PASS artifact is written. A separate CI job retains that
bounded outcome; unit tests alone cannot establish native acceptance.

This local fixture uses a dedicated standard Docker bridge with outbound
connectivity, a localhost-only Kubernetes API and no published Git port. It has
no customer/cloud credentials or customer data. Exact ownership checks govern
cleanup. Linux consumers use the invoking UID/GID, retaining private directory
and credential permissions. Actual nonroot Linux compilation and Git/server
checks pass on fresh volumes with networking disabled. These components do not
enable a customer runtime or earn additional progress credit.
