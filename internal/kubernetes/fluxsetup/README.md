This pure helper prepares the pinned Flux CLI `install --export` YAML for the
isolated local fixture. It reads at most 1 MiB of YAML from stdin and writes
only a JSON Kubernetes List to stdout. Errors go to stderr with a nonzero exit.

```sh
go build -o /out/fluxsetup ./internal/kubernetes/fluxsetup/cmd
/out/fluxsetup < pinned-flux-export.yaml > prepared-flux.json
```

The input must use namespace `finops-flux-system`, contain exactly the official
source-controller and kustomize-controller Deployments at version `v1.9.6`, and
explicitly set `--watch-all-namespaces=false`. The helper replaces the controller
images with the approved linux/amd64 manifest digests, removes every ClusterRoleBinding to
`cluster-admin`, and preserves CRDs and the remaining installation RBAC.
Kustomize receives `--no-cross-namespace-refs=true`, `--no-remote-bases=true`,
and `--default-service-account=default`. Both main containers receive local
fixture requests of 50m CPU/128Mi memory and limits of 500m CPU/384Mi memory.
Their pull policy is `Never`; approved images must already be present in the
owned nodes before the controllers are created.

Unexpected controllers, versions, namespaces, sidecars, YAML aliases, duplicate
keys, unsupported scalar tags, and excessive input shape fail closed. The
helper does not install controllers, create impersonation permissions, contact
a cluster, or assert execution or financial authority. The lab orchestrator
supplies narrowly scoped reconciliation permissions separately.
