# Local Kubernetes and Git-owned rollout acceptance

Run `node scripts/kubernetes-bootstrap.mjs` and then
`node scripts/kubernetes-lab.mjs`. Bootstrap supports Windows/Linux x64, verifies
the pinned official KIND release and node/application image digests, and refuses
remote Docker transports. It creates only a named local Docker cluster, using a
loopback API and a workspace-private kubeconfig; the user's default kubeconfig
is not changed.

The acceptance script accepts only the already-created three-node
`finops-autopilot-lab` KIND cluster, the `finops-k8s-lab` namespace, and the
private kubeconfig in `work/kubernetes-lab/`. It has no hosted-cloud mode.
The root bootstrap verifies the official KIND binary and node image; the lab
loads the locally cached Python image and records its exact content digest.

The read-only inventory uses a separate Kubernetes ServiceAccount. Its RBAC
cannot mutate Deployments or read Secrets. Cluster identity is the observed
`kube-system` namespace UID; the namespace and target Deployment UIDs are also
pinned. Complete original API response hashes accompany each snapshot.

The Git controller in this lab is **LOCAL_GITOPS_TEST_DOUBLE**. It reads a real
local Git repository and applies its exact committed Deployment, then records
the acknowledged commit, rendered-spec hash and rollout health in a ConfigMap.
This is not a running Argo CD or Flux controller. Native Argo/Flux inventory is
read-only; hosted mutation remains blocked until an independently verified
rendered-Git-spec proof and controller commissioning are implemented.

The acceptance exercises a real two-zone rollout, an explicit zero-disruption
PDB rejection before a Git commit, and failed readiness followed by a Git revert
and healthy rollout. The fault is a labelled test injection after proposal
assessment; it does not grant the evaluator permission to modify health checks.
Rollback goes through Git, so a self-healing controller cannot reapply the bad
revision. All cluster writes are confined to this named disposable local lab.

The evaluator requires fresh, coherent inventory; stable Ready replicas;
explicit maintenance and recovery time; at least two replicas in two zones;
blocking-PDB compliance; and exact Git authority and revision. It refuses
automatic VPA conflicts and request-denominator changes under HPA without a
coupled simulation. A separate exact-integer HPA calculation demonstrates why
lower requests can raise replica count and total requested capacity.
The steady-state example uses two replicas at 490m observed CPU each and a 50%
HPA target. Reducing each request from 1000m to 700m changes the calculated HPA
count from two to three, raising total requests from 2000m to 2100m.

Request reductions still require a trusted native history/capacity assessment.
Node-autoscaler coordination and node billing/cost-realisation evidence are
explicit gates. This lab proves no hosted operation, node termination, monetary
saving, independent application SLO, or production readiness.

Kubernetes Deployment rolling updates are not constrained by PDBs themselves;
the platform must check the matching PDB before proposing a disruptive change.
See the primary [disruption documentation](https://kubernetes.io/docs/concepts/workloads/pods/disruptions/)
and [HPA request-utilization contract](https://kubernetes.io/docs/concepts/workloads/autoscaling/horizontal-pod-autoscale/).
