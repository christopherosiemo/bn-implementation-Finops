# Dependency safety for the scheduling pilot

The bounded graph/review capability is implemented and its local API acceptance passed. It adds a typed workload/resource graph and an expiring operator review to the existing non-production EC2 scheduling gates for schema-3 plans, including every new live stop. The retained schema-2 fixture/history path does not acquire the new gate and cannot initiate a live stop. It authorizes no AWS access, provisioning, spending or live execution. The new attachment matches the preserved [product specification](product-specification.md) after content normalization; no normative requirement was changed.

## What the graph establishes

The graph starts with resources and workloads already present in the tenant's inventory. Current workload mappings produce `RUNS_ON` relationships; an authorized operator can declare additional typed relationships among the returned nodes. Unmapped resources remain visible without a fabricated workload or owner. Use the exact node identifiers returned by the API.

This is a projection of current inventory plus operator declarations. It does not automatically discover the complete application topology, infer hidden consumers or import all EBS attachment relationships. Existing EC2/EBS discovery and raw attachment documents do not by themselves establish a complete dependency graph. Additional discovery adapters and graph reconciliation remain future work.

An inbound consumer outside the affected workload blocks a new stop. The pilot does not infer that another workload can tolerate the outage from a health URL, a tag, missing traffic or an asserted SLO. Unknown membership or unresolved dependency evidence cannot be treated as an empty graph. An operator review cannot override a declared external consumer blocker.

## Review and trust boundary

A review records an explicit operator assessment of the discovered scope and external dependencies. It binds the current graph and inventory hashes, reviewer identity and expiry. Choose a future expiry within 24 hours; a review cannot provide indefinite authorization. A review can be recorded as `BLOCKED`, so successful persistence is not evidence that stopping is safe.

The acknowledgement is an accountable human declaration, not proof that the system has discovered every dependency. Operators must check the target's actual consumers and record known relationships before reviewing it. A `READY` dependency review satisfies this gate only: financial readiness, independent activity, ownership, policy, exact-plan approval and fresh provider preflight remain separate requirements.

Graph and inventory changes invalidate the reviewed state for new stops. Refresh the graph, resolve blockers and create a new review for the new state; do not reuse an old review merely because its timestamp has not expired. The graph and resource versions enforce optimistic concurrency, while idempotency keys identify an exact mutation request. A changed request needs a new key.

Planning binds the selected dependency review and graph hash. New version-3 plans sign `dependency_review_id` and `dependency_graph_hash`; the signer and executor independently check their binding and freshness before a new `STOP`. A stale, missing or mismatched review blocks that new stop. Legacy plans without this authority cannot acquire it by replaying a previous approval.

During an already-owned schema-3 occurrence, durable observation treats an expired review or changed graph/inventory as a request to restore. This keeps the existing recovery duty active while preventing another stop under the stale review.

An already-owned `START` skips this new dependency gate. Review expiry, graph changes and migration cannot strand an instance stopped by an authorized occurrence. Restoration still requires the original ownership and signed recovery authority; this does not authorize starting an independently stopped instance. Historical plans, reviews and audit evidence remain inspectable.

## API contract

All endpoints use authenticated tenant scope. Mutation authorization is checked separately from read access.

| Endpoint | Contract |
| --- | --- |
| `GET /v1/resource-graph` | Returns `version`, `nodes`, `edges`, `inventory_hash`, `graph_hash`, `status`, `reasons` and `reviews`. The initial graph version is `0`. Graph status is `UNKNOWN`, `DECLARED` or `BLOCKED`; a graph response alone is not stop authorization. |
| `POST /v1/resource-graph` | Body `{edges:[{from,to,type}],reason:string}`. Requires `If-Match` for the current graph version and a fresh `Idempotency-Key`; returns the current graph contract. Declare only relationships supported by the returned nodes and accepted edge types. |
| `GET /v1/resources/{id}/dependency-reviews` | Returns `resource_id`, `latest`, `reviews`, `status`, `reasons` and `current_graph_version`. Inspect current status and reasons rather than treating the existence of an older review as permission. |
| `POST /v1/resources/{id}/dependency-reviews` | Body `{graph_version:int,valid_until:RFC3339,acknowledgement:"REVIEWED_DISCOVERED_AND_EXTERNAL_DEPENDENCIES",note:string}`. Requires the resource's current `If-Match` and a fresh `Idempotency-Key`. Returns an immutable review with `expires_at`, `graph_hash`, `inventory_hash`, `reviewed_by`, `status:READY|BLOCKED` and `reasons`. |

The review body selects the current graph version and requested expiry. It does not submit caller-authored hashes, reviewer identity or an authoritative ready flag. Obtain versions immediately before mutation and handle a conflict by reading the changed state and reviewing it again.

## Reproduce locally

Use the labelled local fixture stack from [README](../README.md). Run acceptance suites sequentially because they share and reset fixture state. Graph and review mutations in the following example belong only to a fresh isolated fixture tenant; an empty `edges` list is not an appropriate way to erase known relationships from an established graph.

Run `node scripts/dependency-smoke.mjs` after local startup for the graph/review API acceptance command. It requires `.env` fixture mode and an API fixture health response, uses only local ports, and keeps its mutations in the seeded `other` tenant. It leaves one uniquely named fixture consumer plus immutable review/audit history, then removes its own declared edges without issuing a new review, plan, approval or execution. The owner credential is used only to check cross-tenant review invisibility. All 15 checks passed against the rebuilt local backend. The full Go suite and vet passed with actual PostgreSQL and the real Python worker; the existing API and process-recovery smokes also passed their 17 and 6 checks respectively. These local results establish no live AWS outcome; the final increment record is maintained in [acceptance](acceptance.md).

The Go contract checks for this increment are:

```powershell
docker run --rm -v "${PWD}:/src" -w /src golang:1.27.2-bookworm go test ./internal/dependency ./internal/store ./internal/service ./internal/workflow
```

Without `TEST_DATABASE_URL`, PostgreSQL integration cases are skipped. A full acceptance run must use a disposable database, the actual restricted roles and a reachable real economics worker through `ECONOMICS_TEST_URL`; do not use an application or customer database as a test database. The CI workflow supplies these dependencies. A unit-only pass does not establish database isolation, signed-plan binding or the complete fixture operating loop.

For a manual fixture check, supply an authorized local operator token through `FINOPS_API_TOKEN` without putting it in a tracked file or printing it. This example uses the seeded `resource-dev-api`; read its graph and inventory first.

```powershell
$apiUrl = 'http://localhost:8080'
$headers = @{ Authorization = "Bearer $env:FINOPS_API_TOKEN" }
$graph = Invoke-RestMethod -Uri "$apiUrl/v1/resource-graph" -Headers $headers

# Fresh isolated fixture only: record that no additional edges are declared.
$graphHeaders = $headers.Clone()
$graphHeaders['If-Match'] = '"' + $graph.version + '"'
$graphHeaders['Idempotency-Key'] = [guid]::NewGuid().ToString()
$body = @{ edges = @(); reason = 'Reviewed this isolated fixture graph; no additional declared relationships.' } | ConvertTo-Json -Depth 5
$graph = Invoke-RestMethod -Method Post -Uri "$apiUrl/v1/resource-graph" -Headers $graphHeaders -ContentType 'application/json' -Body $body

$resource = Invoke-RestMethod -Uri "$apiUrl/v1/resources/resource-dev-api" -Headers $headers
$reviewHeaders = $headers.Clone()
$reviewHeaders['If-Match'] = '"' + $resource.version + '"'
$reviewHeaders['Idempotency-Key'] = [guid]::NewGuid().ToString()
$body = @{
  graph_version = $graph.version
  valid_until = [DateTime]::UtcNow.AddHours(1).ToString('o')
  acknowledgement = 'REVIEWED_DISCOVERED_AND_EXTERNAL_DEPENDENCIES'
  note = 'Reviewed the isolated fixture inventory and known external consumers for this resource.'
} | ConvertTo-Json
$review = Invoke-RestMethod -Method Post -Uri "$apiUrl/v1/resources/resource-dev-api/dependency-reviews" -Headers $reviewHeaders -ContentType 'application/json' -Body $body
$review | Select-Object status, expires_at, reasons
```

Inspect the review result, then create fresh readiness and an exact plan through the ordinary fixture workflow. Add an inbound external consumer or change the reviewed graph/inventory and confirm that the previous plan cannot authorize a new stop. Expired review, stale versions, altered plan hashes, cross-tenant endpoints and replayed requests need their own negative checks. Separately prove that an already-owned restoration still finishes after review invalidation. Record actual results under [acceptance](acceptance.md); these instructions are not a recorded pass.

## Outstanding product requirements

The separate [trusted SLO increment](slo-safety.md) adds bounded objective/receipt/evaluation authority and passed local fixture API/ingress and browser acceptance. Independent activity counters establish demand and operational signals, while an HTTP-success probe establishes a bounded readiness signal; neither substitutes for application latency/error/availability evidence. Broad telemetry adapters and complete workload SLO coverage remain outstanding. CloudWatch hourly maxima are not p95/p99 estimates. Hard objectives and regression thresholds remain independent constraints as recorded in [decisions](decisions.md).

This increment does not implement production rightsizing, candidate/control cohorts, fleet canary expansion, forecasting, automatic full dependency discovery, IaC/GitOps execution or platform SLO measurement. It earns no live/customer-use credit. The fixed-weight [progress ledger](progress-ledger.md) records accepted capability maturity separately from test counts and planned work.
