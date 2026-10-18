# Trusted SLO safety for the scheduling pilot

This bounded increment adds a versioned service objective, independent machine observations and a signed SLO evaluation to schema-3 scheduling. Local fixture API/ingress and browser acceptance passed. It authorizes no AWS access, provisioning, spending or live execution. The retained schema-2 fixture/history path stays available and cannot initiate a live stop.

## Objective and observation authority

An authorized operator defines the workload objective through `POST /v1/workloads/{id}/slo-objectives`. `If-Match` selects the current objective version, including `0` initially, and `Idempotency-Key` identifies the exact request. Updates append a new immutable objective identity and hash. Limits use integer milliseconds and parts per million: `1_000_000` ppm is 100 percent, and `10_000` ppm is 1 percent. Evaluation windows contain between 2 and 60 complete UTC minutes.

The operator registers a source through `POST /v1/slo-sources`, selecting the current objective, an existing resource and a machine subject. The server selects the workload/provider/account/region binding and configured machine issuer. Registration is an accountable operator trust decision about instrumentation; it does not prove that a collector measures the intended application correctly.

Only the dedicated activity-ingress process accepts observations, at `POST /v1/slo/intervals`, using the existing machine OIDC issuer/audience and `finops_activity` database identity. A console token cannot submit receipts, and the machine token cannot use the control-plane API. Other runtime identities cannot manufacture receipt rows. No new cloud credentials or signing keys are needed by this ingress.

Each observation contains one complete UTC minute, a monotonic sequence, request/error counts, observed good/total availability seconds and a millisecond latency histogram. Bucket counts are **per bucket**, not cumulative Prometheus counters; bounds increase strictly and the final unbounded bucket has `upper_bound_ms: null`. The sample count equals the request count. Instrumentation must convert and validate its source semantics before submitting observations; this increment does not install OpenTelemetry or Prometheus scrapers.

Ingress preserves the original body/hash, authenticated machine identity, provider binding and server receive time. Only recent complete minutes within the guarded receive window are accepted; there is no historical-backfill or client-clock bypass. Exact replay returns the original receipt. Changed content, sequence/window conflicts, unregistered sources and mismatched bindings fail closed.

## What CLEAR establishes

`GET /v1/resources/{id}/slo-evaluation` selects receipts server-side for the current objective and source. Complete contiguous coverage, correct identity and fresh receive times are required. Missing minutes, insufficient samples and an unbounded percentile remain blocked; they do not become zero latency, zero errors or 100 percent availability.

Hard p95/p99, error-rate and applicable availability limits are independent of the latency regression guard. The section-106 example cannot permit a hard-SLO breach merely because a relative regression threshold is looser; see [specification errata](decisions.md). Histograms produce conservative percentile bounds. Regression compares the current upper bound with the signed baseline's lower bound, so a coarse histogram can block a change rather than manufacture precision. Hourly CloudWatch maxima are not application percentiles.

The immutable regression baseline is a server-selected recent pre-plan evaluation window of 2–60 complete minutes. It is not a fourteen-day application SLI distribution or seasonality model. The separate fourteen-day financial/workload baseline remains mandatory. Enabled regression requires a measurable baseline and can fail closed when current traffic cannot establish a percentile; no-demand handling does not invent a comparable latency.

Availability is explicitly `ALWAYS` or timezone-aware weekly `WINDOWS`. This singleton pilot cannot stop during an availability window; `ALWAYS` therefore blocks a singleton stop even when a current health evaluation passes. Outside declared windows, fully observed zero demand can make latency/error checks not applicable and report `latency_status: NO_DEMAND`. Their numeric values remain unavailable, not zero. Closed windows are an explicit operator requirement and are not inferred from idle traffic.

A `CLEAR` evaluation satisfies the evaluated health contract only. A new stop still requires an allowed complete stop/restoration window, dependency review, independent activity, source-native economics, ownership, policy, approval and provider preflight. Revising an objective requires a source registered for the new objective and fresh evaluation. Old sources/receipts remain historical evidence and cannot be relabelled to supply current authority.

## Off-instance SLI collector

Run the existing `node scripts/activity-collector.mjs` on a gateway or independent observer that remains available while the target is stopped. Select `ACTIVITY_OBSERVATION_KIND=slo` and set `ACTIVITY_SLO_OBJECTIVE_ID` to the exact registered objective. Set `ACTIVITY_SOURCE_ID`, `ACTIVITY_RESOURCE_ID` and `ACTIVITY_WORKLOAD_ID` from the SLO source registration, and point `ACTIVITY_INGRESS_URL` at HTTPS `/v1/slo/intervals`. The existing OIDC issuer/client, read-only client-secret file, observation URL and durable state-file configuration apply; see [collector setup](../scripts/activity-collector.md).

The observation endpoint returns only explicit interval fields and raw SLI counts/histogram, for example:

```json
{
  "interval_start": "2026-10-18T12:00:00Z",
  "interval_end": "2026-10-18T12:01:00Z",
  "request_count": 100,
  "error_count": 0,
  "availability_good_seconds": 60,
  "availability_total_seconds": 60,
  "latency": {
    "unit": "milliseconds",
    "sample_count": 100,
    "buckets": [
      { "upper_bound_ms": 120, "count": 95 },
      { "upper_bound_ms": 180, "count": 5 },
      { "upper_bound_ms": null, "count": 0 }
    ]
  }
}
```

The timestamps above illustrate the schema; collection requires a current complete minute. The collector selects identity from its registered configuration, rejects submitted percentiles/authority fields, incomplete observations, invalid denominators and malformed histograms, and never fills missing counts with zero. Availability seconds are explicit observations; the versioned calendar decides their evaluation denominator.

SLO state binds the observation kind and objective as well as source/resource/workload. Use a separate persistent private state file for each registered stream and retain prior files across restart or objective changes. Conflicts stop visibly; do not delete pending state or reset its sequence to bypass a rejection. Pending bytes and idempotency keys are persisted before dispatch and replayed unchanged after uncertain responses; a rejected token is refreshed without rebuilding the pending observation. Default activity mode keeps its original configuration/source-binding serialization and body contract, so existing pending activity requests remain replayable. Neither mode adds execution credentials or live-deployment authorization.

## Signed execution, restoration and savings

New schema-3 plans bind the objective ID/version/hash and immutable baseline evaluation ID/hash. Readiness, signer and executor independently require current matching SLO authority before a new stop. A stale or changed objective, source, evaluation or observation cannot be repaired by replaying an old plan. The approved baseline remains fixed for regression comparison.

During an owned occurrence, a breach or loss of required SLO authority requests restoration through the durable owned START path. It never revokes that recovery duty. The occurrence retains its failure reason and is marked rolled back after required restoration/health checks rather than claiming a successful optimization. Consumed-restoration and manually-stopped-instance protections remain in force.

The worker can append the first immutable violation for a signed, actively owned occurrence. It cannot write the financial ledger. This disqualifies the entire signed measurement, including another completed occurrence using that measurement. Later healthy telemetry, policy revisions and repeated verification cannot erase the latch.

Before financial verification and ledger projection, the API reconciles these latches. An existing claim receives an append-only current `BLOCKED` correction with `reason_code: SLO_BREACH_DISQUALIFIED` and a null verified saving. Claim identity, coverage, currency and immutable positive/negative history remain intact. Repeated reconciliation returns the same blocked head. With no prior financial claim, the API may return a nonfinancial blocked summary without inventing coverage or inserting a synthetic billing claim. Shared transaction guards serialize first-violation recording and financial reconciliation.

Violation/restoration and financial-disqualification events use the existing signed outbox. Delivery requires an explicitly trusted receiver and worker-only webhook secret. A persisted event does not establish human receipt; see [deployment](deployment.md) and [operations](operations.md).

## Reproduce locally

Run `node scripts/activity-smoke.mjs` before `node scripts/slo-smoke.mjs` on the labelled local fixture stack. The activity smoke synchronizes the fixture-only machine client on older identity-provider volumes. The SLO smoke requires `.env` fixture mode, a fixture API health response and localhost ports. It creates no plans, approvals or executions.

Unlike dependency smoke, SLO smoke uses the existing `tenant-demo` machine identity. The owner console registers objective/source metadata and reads evaluations; the separate `other` console checks tenant isolation. It appends visible SLO history without resetting the owner loop. The final policy revision deliberately leaves the old source unable to provide current authority. The schema-2 fixture loop remains available. CI runs this smoke after activity/dependency smoke and before browser acceptance.

The rebuilt local stack passed all 15 SLO API/ingress checks, 17 operating-loop checks, 6 actual API/worker recovery checks, 6 machine/activity checks, 15 dependency checks and all 20 Chromium tests. The full Go suite and vet passed with a fresh disposable PostgreSQL database and real Python economics worker. Four restricted-PostgreSQL financial regressions separately cover append-only/deduplicated correction, history and tenant preservation, worker financial-write denial, absent-claim summaries, sibling occurrence disqualification and transaction serialization. All 116 Node tests passed, including collector mode/replay compatibility and execution preflight. These are local deterministic results; exact source/CI acceptance and remaining validation are recorded separately in the [acceptance record](acceptance.md).

## Remaining specification and live gates

Full OpenTelemetry/Prometheus adapters, production rightsizing, CPU/memory capacity guards, burst/seasonal forecasting and p50/p90/p99.9 analysis remain separate work. The full workload objective also includes replica/zone minima, capacity headroom, RTO/RPO and maintenance/blackout constraints. The latency guard does not by itself implement the specification's default relative-error regression guard.

Fleet candidate/control comparison, 10→25→50→100 percent expansion and the section-209 two-of-twenty blast-radius test remain outside this singleton flow. The section-210 rollback consequences inform this increment, but a deterministic service test does not establish a production fleet canary. Authentic instrumentation, receiver delivery, read-only account acceptance, supervised recovery, real billing periods and measured platform SLOs require separately authorized live validation. No live, commercial or customer-verified savings credit is established here.
