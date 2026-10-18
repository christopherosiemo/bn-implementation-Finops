# Independent workload activity collector

Run `node scripts/activity-collector.mjs` on an ingress gateway, queue observer or other machine that remains available while the scheduled EC2 instance is stopped. It must observe accepted demand independently of the worker's own runtime. Do not infer zero activity from missing application metrics, a stopped instance or an unreachable endpoint.

Register the machine token's exact issuer and subject, internal resource/workload, AWS account/region/provider resource and immutable metric definition through the control API before collection. The machine access token requires the dedicated `finops-activity` audience and the same `tenant_id` claim as the registered resource, alongside its exact `iss` and `sub`; a console token is insufficient. Configure an explicit server-side activity JWKS URL for providers whose keys are not at Keycloak's `<issuer>/protocol/openid-connect/certs` path. The ingress database identity can only append activity receipts and cannot approve or execute changes.

Required environment:

| Variable | Meaning |
| --- | --- |
| `ACTIVITY_SOURCE_ID`, `ACTIVITY_RESOURCE_ID`, `ACTIVITY_WORKLOAD_ID` | Exact registered binding |
| `ACTIVITY_METRIC_ID`, `ACTIVITY_METRIC_VERSION`, `ACTIVITY_METRIC_UNIT` | Stable business-output definition, for example accepted orders |
| `ACTIVITY_OBSERVATION_URL` | Independent HTTPS endpoint returning one complete minute |
| `ACTIVITY_INGRESS_URL` | HTTPS `/v1/activity/intervals`; local Compose uses port 8093 |
| `ACTIVITY_OIDC_ISSUER`, `ACTIVITY_CLIENT_ID` | Machine issuer and client-credentials identity |
| `ACTIVITY_CLIENT_SECRET_FILE` | Read-only secret file; never a command-line secret |
| `ACTIVITY_STATE_FILE` | Persistent private file for source sequence and uncertain request bytes |

The observation endpoint returns `interval_start`, `interval_end` as UTC minute boundaries, nonnegative integer `accepted`, `completed`, `rejected`, `backlog`, `inflight`, boolean `heartbeat`, and explicit `incident`, `deployment`, `job` states (`CLEAR`, `ACTIVE`, `UNKNOWN`). Counts represent the interval; backlog and inflight are end-of-interval gauges. Rejected demand must remain visible. Metric semantics must not change without a newly registered definition.

The collector polls for closed-minute observations every five seconds and submits each minute once. It fsyncs and atomically replaces its state file before dispatch, retains identical bytes and idempotency key across uncertain responses, and keeps tokens only in memory. A missing or unavailable observation is never replaced with a fabricated zero. TLS is required; `ACTIVITY_ALLOW_LOCAL_HTTP=true` exists only for explicit local development. `ACTIVITY_ONCE=true` performs one collection attempt for supervised checks.

The server records its own receive time and hashes/preserves exact request bytes. New observations more than two minutes old are rejected. An old exact replay returns the original receipt without adding history; altered replays fail. A rejected binding, stale pending interval or conflicting sequence stops this collector visibly for operator review rather than rewriting evidence. Keep the state volume intact across restarts. Do not delete sequence state to bypass a conflict.

Readiness requires two contiguous recent idle intervals, explicit heartbeat and clear operational states. Fresh work requires early restoration; missing/stale/unknown signals block new stops and must not suppress an already-owned restoration. Full-period economics additionally checks accepted and completed work, rejected demand, backlog and inflight; running hours are not the workload denominator.

The local bootstrap creates a fixture-only `activity-collector` machine client bound to `tenant-demo`. Its generated secret stays in the ignored private `.env` and ignored local realm import; the realm file must remain readable by the Keycloak container. Treat that import as local credential material and do not publish it. Existing Keycloak realms are not changed by an import file rewrite; provision/update that client explicitly when upgrading an existing local realm. Hosted operators configure their own OIDC machine client and registered subject. No live collector deployment or AWS mutation is implied by these assets.
