import { expect, test, type Page } from "@playwright/test";
import type { components } from "../src/api.generated";
import type { Dashboard, TelemetryConnection } from "../src/types";

// Presentation contracts only; Go's real-Python mapper acceptance establishes
// the numerical/native boundary. These transports grant no evidence authority.
const binding = {
  tenant_id: "proxy-contract",
  workload_id: "workload-proxy",
  resource_id: "resource-proxy",
  provider: "AWS",
  provider_resource_id: "i-proxy",
  account_id: "111122223333",
  region: "eu-west-1",
};
const stamp = "2026-10-18T12:00:00Z";
const connection: TelemetryConnection = {
  schema_version: "1",
  id: "proxy-source",
  version: 1,
  kind: "PROMETHEUS",
  read_binding_id: "registered-binding",
  binding,
  enabled: true,
  revoked: false,
  definitions: [],
  config_hash: "config",
  revision_id: "revision",
  created_at: stamp,
};
const dashboard: Dashboard = {
  org: {
    id: binding.tenant_id,
    name: "Proxy contract",
    version: 1,
    paused: false,
  },
  fixture: false,
  cloud_accounts: [],
  recommendations: [],
  policies: [],
  schedules: [],
  change_plans: [],
  executions: [],
  savings: [],
  audit: [],
  data_quality: [],
  workloads: [
    {
      id: binding.workload_id,
      version: 1,
      name: "API workload",
      owner: "owner@example.test",
      environment: "NON_PRODUCTION",
      timezone: "UTC",
      incident: "UNKNOWN",
      deployment: "UNKNOWN",
      job: "UNKNOWN",
      signals_at: stamp,
    },
  ],
  resources: [
    {
      id: binding.resource_id,
      version: 1,
      name: "Native API",
      ...{
        provider: "AWS",
        provider_resource_id: binding.provider_resource_id,
      },
      resource_type: "EC2",
      workload_id: binding.workload_id,
      environment: "NON_PRODUCTION",
      state: "running",
      configuration_authority: "TERRAFORM",
      hourly_effective_cost: null,
      monthly_effective_cost: null,
      currency: null,
      eligibility: "BLOCKED",
      blockers: [],
    },
  ],
};
function result(
  unit: "count" | "requests",
  legacy = false,
): components["schemas"]["NativeCapacityResult"] {
  const ref = {
    id: "source",
    version: "1",
    receipt_id: "receipt",
    sha256: "a".repeat(64),
    binding,
  };
  const capacity = {
    cpu: "2",
    memory: "17179869184",
    network: "100",
    storage_iops: "3000",
    storage_throughput: "100",
  };
  const catalog = {
    id: "m6i.large",
    count: 1,
    capacity,
    architecture: "x86_64",
    cpu_model: "Intel",
    operating_system: "Linux/UNIX",
    licensing: "RunInstances",
    region: "eu-west-1",
    zones: ["eu-west-1a"],
    accelerator: "NONE",
    local_storage: false,
    disk_types: ["gp3"],
    commitment_compatible: null,
    source_ref: ref,
    pricing: null,
  };
  const proxy = legacy
    ? {}
    : {
        semantic_role: "REQUEST_THROUGHPUT_PROXY" as const,
        source_metric: "request_count" as const,
        source_unit: unit,
      };
  const rate = legacy ? "work_unit/second" : `${unit}/second`;
  const q = { lower: "5", upper: "5", status: "OBSERVED" as const };
  return {
    schema_version: "1",
    id: `proxy-${unit}`,
    binding,
    workload_id: binding.workload_id,
    resource_id: binding.resource_id,
    connection_id: connection.id,
    connection_version: 1,
    revision_id: "revision",
    config_hash: "config",
    safety_profile_id: "profile",
    safety_profile_version: 1,
    safety_profile_hash: "profile-hash",
    hardware_receipt_id: "hardware",
    hardware_raw_sha256: ref.sha256,
    resource_snapshot_hash: "inventory",
    population_hash: "population",
    receipt_ids: ["receipt"],
    source_refs: [],
    input_kind: "MODEL_REQUEST",
    input_hash: "input",
    model_requested: true,
    model_evaluated: true,
    model_evaluation: {
      schema_version: "4",
      model_version: legacy
        ? "capacity-weekday-block-v1"
        : "capacity-weekday-block-v2",
      binding,
      status: "BLOCKED",
      reason_codes: [],
      history: {
        start: "2026-10-04T00:00:00Z",
        end: stamp,
        timezone: "UTC",
        environment: "NON_PRODUCTION",
        observed_calendar_days: 14,
        required_calendar_days: 14,
      },
      metrics: [
        {
          name: "demand",
          unit: rate,
          ...proxy,
          statistic: "OBSERVED_INTERVAL_RATE",
          coverage_ppm: 1000000,
          time_coverage_ppm: 1000000,
          sampling_coverage_ppm: 1000000,
          observed_intervals: 336,
          expected_intervals: 336,
          missing_intervals: 0,
          unknown_seconds: "0",
          observed_samples: "336",
          observed_quantiles: {
            p50: q,
            p90: q,
            p95: q,
            p99: q,
            p999: { lower: null, upper: null, status: "UNAVAILABLE" },
          },
          observed_maximum: "5",
          quantile_method: "OBSERVED_INTERVAL_RATE",
          denominator: null,
          reason_codes: [],
          source_refs: [ref],
        },
      ],
      forecasts: [
        {
          horizon: "7_day",
          days: 7,
          status: "UNCALIBRATED",
          future_breach_probability_upper_ppm: null,
          metrics: {
            demand: {
              ...proxy,
              ...(legacy
                ? {}
                : {
                    unit: `${unit}/second` as
                      "count/second" | "requests/second",
                  }),
              status: "UNCALIBRATED",
              reason_codes: ["HORIZON_BACKTEST_INSUFFICIENT"],
              point_peak: "5",
              point_p99: "5",
              prediction_interval: null,
              backtest: {
                method: "EXPANDING_ORIGIN_WEEKDAY_HOUR_MEDIAN",
                block_days: 7,
                residual_day_count: 0,
                nonoverlapping_block_count: 0,
                uses_future_observations: false,
              },
            },
          },
        },
      ],
      candidates: [],
      evidence_refs: [ref],
      model_assumptions: [],
      assessment_hash: "unchanged-result-hash",
    },
    hardware_mapping: {
      current: catalog,
      candidates: [],
      reason_codes: [],
      candidate_reasons: {},
      assumptions: [],
    },
    history: {
      start: "2026-10-04T00:00:00Z",
      end: stamp,
      days: 14,
      timezone: "UTC",
      environment: "NON_PRODUCTION",
    },
    native_evaluation: {
      schema_version: "1",
      status: "READY",
      reason_codes: [],
      start: "2026-10-04T00:00:00Z",
      end: stamp,
      evaluated_at: stamp,
      hash: "native",
      metrics: [],
    },
    status: "BLOCKED",
    reason_codes: ["NATIVE_PRICE_UNAVAILABLE"],
    native_price_status: "UNAVAILABLE",
    execution_authorized: false,
    estimated_saving: null,
    verified_saving: null,
    change_plan_id: null,
    hash: "record-hash",
    created_at: stamp,
    writer_role: "finops_api",
  };
}
async function inspect(
  page: Page,
  records: components["schemas"]["NativeCapacityResult"][],
) {
  const writes: string[] = [];
  await page.route("**/.well-known/openid-configuration", (route) => {
    const origin = new URL(page.url()).origin;
    return route.fulfill({
      json: {
        authorization_endpoint: `${origin}/__proxy/authorize`,
        token_endpoint: `${origin}/__proxy/token`,
      },
    });
  });
  await page.route("**/__proxy/authorize?**", (route) => {
    const params = new URL(route.request().url()).searchParams;
    const redirect = new URL(params.get("redirect_uri")!);
    redirect.searchParams.set("code", "presentation");
    redirect.searchParams.set("state", params.get("state")!);
    return route.fulfill({
      status: 302,
      headers: { location: redirect.toString() },
    });
  });
  await page.route("**/__proxy/token", (route) =>
    route.fulfill({
      json: { access_token: "presentation-token", expires_in: 3600 },
    }),
  );
  await page.route("**/v1/**", (route) => {
    const { pathname } = new URL(route.request().url());
    if (route.request().method() !== "GET") writes.push(pathname);
    if (pathname.endsWith("/dashboard"))
      return route.fulfill({ json: dashboard });
    if (pathname === "/v1/telemetry-connections")
      return route.fulfill({
        json: { items: [connection], next_cursor: null },
      });
    if (pathname === `/v1/telemetry-connections/${connection.id}`)
      return route.fulfill({ json: connection });
    if (pathname.endsWith("/native-capacity-results"))
      return route.fulfill({ json: { items: records, next_cursor: null } });
    if (pathname.endsWith("/safety-profiles"))
      return route.fulfill({
        json: { version: 0, latest: null, items: [], next_cursor: null },
      });
    return route.fulfill({ json: { items: [], next_cursor: null } });
  });
  await page.goto("/");
  await page.getByRole("button", { name: "Sign in to your workspace" }).click();
  await page
    .getByRole("link", { name: "Connections & quality", exact: true })
    .click();
  await page
    .getByRole("button", {
      name: `Inspect native telemetry ${connection.id}`,
      exact: true,
    })
    .click();
  const dialog = page.getByRole("dialog", {
    name: "Native telemetry evidence",
  });
  await dialog
    .getByText("Assess historical capacity evidence", { exact: true })
    .click();
  for (const record of records)
    await dialog
      .getByRole("region", {
        name: `Native physical capacity result ${record.id}`,
        exact: true,
      })
      .getByText("Inspect observations, forecasts & candidate checks", {
        exact: true,
      })
      .click();
  return { dialog, writes };
}

test("request-throughput proxy displays exact native count and requests rate units without completed-work authority", async ({
  page,
}) => {
  const records = [result("count"), result("requests")];
  const { dialog, writes } = await inspect(page, records);
  for (const unit of ["count", "requests"] as const) {
    const evidence = dialog.getByRole("region", {
      name: `Native physical capacity result proxy-${unit}`,
      exact: true,
    });
    await expect(evidence).toContainText("Request throughput proxy");
    await expect(evidence).toContainText(
      `REQUEST_THROUGHPUT_PROXY · source request_count (${unit})`,
    );
    await expect(evidence).toContainText(`${unit}/second`);
    await expect(evidence).toContainText(
      "Requests do not prove completed business work or work preservation",
    );
    await expect(evidence).not.toContainText("work_unit/second");
    await expect(
      evidence.getByRole("button", { name: /approve|execute|verify/i }),
    ).toHaveCount(0);
  }
  expect(writes).toEqual([]);
});

test("legacy immutable generic demand remains readable and unproven despite proxy-looking metadata", async ({
  page,
}) => {
  const record = result("count", true);
  record.model_evaluation!.metrics[0].semantic_role =
    "REQUEST_THROUGHPUT_PROXY";
  const { dialog, writes } = await inspect(page, [record]);
  await expect(dialog).toContainText("Legacy demand · unproven proxy");
  await expect(dialog).toContainText("work_unit/second");
  await expect(dialog).toContainText("capacity-weekday-block-v1");
  await expect(dialog).toContainText("unchanged-result-hash");
  await expect(
    dialog.getByText("Request throughput proxy", { exact: true }),
  ).toHaveCount(0);
  expect(writes).toEqual([]);
});

test("new version with inconsistent proxy units does not acquire a trusted semantic label", async ({
  page,
}) => {
  const record = result("requests");
  record.model_evaluation!.metrics[0].unit = "work_unit/second";
  const { dialog, writes } = await inspect(page, [record]);
  const observations = dialog
    .getByRole("table")
    .filter({ hasText: "Observed p95" });
  await expect(observations).toContainText("Demand semantics unavailable");
  await expect(observations).toContainText("work_unit/second");
  await expect(observations).not.toContainText("REQUEST_THROUGHPUT_PROXY");
  expect(writes).toEqual([]);
});
