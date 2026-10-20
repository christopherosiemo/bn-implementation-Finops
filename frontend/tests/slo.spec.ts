import { expect, test, type Page, type Route } from "@playwright/test";
import type {
  Dashboard,
  SloEvaluationSnapshot,
  SloObjective,
} from "../src/types";

// Presentation contracts stub only OIDC/API transport. Server authorization,
// histogram math, trusted receipts and restoration run in backend acceptance.
const objective = (version = 3): SloObjective => ({
  id: `objective-${version}`,
  version,
  workload_id: "workload-api",
  hash: `objective-hash-${version}`,
  created_at: "2026-10-18T12:00:00Z",
  schema_version: "1",
  limits: {
    max_error_rate_ppm: 10000,
    min_availability_ppm: 999000,
    max_p95_latency_ms: 105,
    max_p99_latency_ms: 200,
    min_latency_samples: 100,
  },
  evaluation_minutes: 2,
  availability: {
    mode: "WINDOWS",
    timezone: "Europe/London",
    windows: [
      { days: [1, 2, 3, 4, 5], start_time: "09:00", end_time: "17:00" },
    ],
  },
  regression: { enabled: true, max_percent: 15 },
});
function dashboard(): Dashboard {
  const policy = objective();
  const source = {
    schema_version: "1" as const,
    id: "slo-source",
    objective_id: policy.id,
    workload_id: "workload-api",
    resource_id: "resource-api",
    subject: "independent-collector",
    issuer: "https://identity.example.test",
    enabled: true,
    provider_resource_id: "i-api",
    account_id: "111122223333",
    region: "eu-west-1",
  };
  const snapshot: SloEvaluationSnapshot = {
    resource_id: "resource-api",
    workload_id: "workload-api",
    objective: policy,
    source,
    snapshot_id: "evaluation-frozen",
    snapshot_hash: "evaluation-frozen-hash",
    evaluation: {
      status: "BLOCKED",
      reason_codes: ["SLO_P95_HARD_LIMIT_BREACH"],
      objective_id: policy.id,
      objective_version: policy.version,
      objective_hash: policy.hash,
      source_id: source.id,
      source_hash: "source-hash",
      resource_id: "resource-api",
      workload_id: "workload-api",
      window_start: "2026-10-18T12:00:00Z",
      window_end: "2026-10-18T12:02:00Z",
      received_at: "2026-10-18T12:02:05Z",
      expected_intervals: 2,
      observed_intervals: 2,
      coverage_ppm: 1000000,
      request_count: 200,
      error_count: 1,
      availability_good_seconds: 120,
      availability_total_seconds: 120,
      error_rate_ppm: 5000,
      availability_ppm: 1000000,
      latency_samples: 200,
      p95_latency_ms: 110,
      p99_latency_ms: 150,
      p95_lower_ms: 109,
      p99_lower_ms: 149,
      latency_status: "OBSERVED",
      hard_checks: [
        {
          name: "P95_LATENCY",
          status: "FAIL",
          reason_code: "SLO_P95_HARD_LIMIT_BREACH",
        },
      ],
      regression_checks: [
        {
          name: "P95_REGRESSION",
          status: "PASS",
          reason_code: "WITHIN_REGRESSION_ALLOWANCE",
        },
      ],
      receipt_ids: ["slo-receipt-1", "slo-receipt-2"],
      baseline_evaluation_id: "baseline-frozen",
      baseline_evaluation_hash: "baseline-hash",
    },
  };
  return {
    org: { id: "slo-ui", version: 1, name: "SLO contracts", paused: false },
    fixture: false,
    cloud_accounts: [],
    policies: [],
    recommendations: [],
    schedules: [],
    change_plans: [],
    executions: [],
    savings: [],
    audit: [],
    data_quality: [],
    workloads: [
      {
        id: "workload-api",
        version: 4,
        name: "Development API",
        owner: "api-owner@example.test",
        environment: "NON_PRODUCTION",
        timezone: "Europe/London",
        incident: "CLEAR",
        deployment: "CLEAR",
        job: "CLEAR",
        signals_at: "2026-10-18T12:02:00Z",
      },
    ],
    resources: [
      {
        id: "resource-api",
        version: 7,
        name: "dev-api",
        provider: "AWS",
        resource_type: "EC2",
        provider_resource_id: "i-api",
        workload_id: "workload-api",
        environment: "NON_PRODUCTION",
        state: "running",
        configuration_authority: "TERRAFORM",
        hourly_effective_cost: null,
        monthly_effective_cost: null,
        currency: null,
        eligibility: "BLOCKED",
        blockers: ["SLO_P95_HARD_LIMIT_BREACH"],
      },
    ],
    slo_objectives: [policy],
    slo_sources: [source],
    slo_evaluations: [snapshot],
  };
}
async function openSlo(
  page: Page,
  data: Dashboard,
  mutate?: (route: Route) => Promise<void>,
) {
  const writes: {
    path: string;
    body: Record<string, unknown>;
    headers: Record<string, string>;
  }[] = [];
  await page.route("**/.well-known/openid-configuration", (route) => {
    const origin = new URL(page.url()).origin;
    return route.fulfill({
      json: {
        authorization_endpoint: `${origin}/__slo-oidc/authorize`,
        token_endpoint: `${origin}/__slo-oidc/token`,
      },
    });
  });
  await page.route("**/__slo-oidc/authorize?**", (route) => {
    const query = new URL(route.request().url()).searchParams;
    const redirect = new URL(query.get("redirect_uri")!);
    redirect.searchParams.set("code", "slo-contract");
    redirect.searchParams.set("state", query.get("state")!);
    return route.fulfill({
      status: 302,
      headers: { location: redirect.toString() },
    });
  });
  await page.route("**/__slo-oidc/token", (route) =>
    route.fulfill({
      json: {
        access_token: `test.${Buffer.from(JSON.stringify({ name: "SLO operator" })).toString("base64url")}.test`,
        expires_in: 3600,
      },
    }),
  );
  await page.route("**/v1/**", async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    if (request.method() === "GET" && path === "/v1/dashboard")
      return route.fulfill({ json: data });
    if (request.method() !== "GET") {
      writes.push({
        path,
        body: request.postDataJSON() as Record<string, unknown>,
        headers: request.headers(),
      });
      if (mutate) return mutate(route);
    }
    return route.fulfill({
      status: 500,
      json: { message: "Unexpected SLO presentation-contract request" },
    });
  });
  await page.goto("/");
  await page.getByRole("button", { name: "Sign in to your workspace" }).click();
  await expect(
    page.getByRole("heading", { name: "Cost operations overview." }),
  ).toBeVisible();
  await page.getByRole("link", { name: "Workloads & resources" }).click();
  return writes;
}

test("null availability windows are optional for ALWAYS and unavailable for required WINDOWS", async ({ page }) => {
  const data = dashboard();
  data.slo_objectives![0].availability = {
    mode: "ALWAYS",
    timezone: "UTC",
    windows: null,
  };
  const errors: string[] = [];
  page.on("pageerror", error => errors.push(error.message));
  const writes = await openSlo(page, data, async route => {
    const saved = { ...objective(4), ...route.request().postDataJSON() } as SloObjective;
    data.slo_objectives = [saved];
    await route.fulfill({ status: 201, json: saved });
  });
  const table = page.getByRole("region", { name: "Workload SLO objectives" });
  await expect(table).toContainText("Always available · singleton stop blocked");
  expect(writes).toEqual([]);
  await page.getByRole("button", { name: "Configure SLO objectives for Development API" }).click();
  let dialog = page.getByRole("dialog", { name: "Configure service objectives" });
  await expect(dialog.getByLabel("Required availability")).toHaveValue("ALWAYS");
  await dialog.getByRole("button", { name: "Save objective revision" }).click();
  await expect(dialog).not.toBeVisible();
  expect(writes).toHaveLength(1);
  expect(writes[0].body.availability).toEqual({ mode: "ALWAYS", timezone: "UTC", windows: [] });

  data.slo_objectives = [{ ...objective(5), availability: { mode: "WINDOWS", timezone: "UTC", windows: null } }];
  await page.getByRole("button", { name: "Refresh data" }).click();
  await expect(table).toContainText("Availability windows unavailable");
  await page.getByRole("button", { name: "Configure SLO objectives for Development API" }).click();
  dialog = page.getByRole("dialog", { name: "Configure service objectives" });
  await expect(dialog.getByRole("alert")).toContainText("Stored availability windows are unavailable");
  await dialog.getByRole("button", { name: "Save objective revision" }).click();
  await expect(dialog).toBeVisible();
  await expect(dialog.getByRole("alert").filter({ hasText: "Add at least one same-day availability window" })).toBeVisible();
  expect(writes).toHaveLength(1);
  expect(errors).toEqual([]);
});

test("hard-limit failure remains separate from a passing regression guard with trusted coverage", async ({
  page,
}, testInfo) => {
  const writes = await openSlo(page, dashboard());
  const evidence = page.getByRole("region", {
    name: "SLO evaluation for dev-api",
  });
  await expect(evidence).toContainText("109–110 ms (bucket bounds)");
  await expect(evidence).toContainText("200 · Observed");
  await expect(evidence).toContainText("100% · 2/2 intervals");
  await expect(
    evidence.getByRole("region", {
      name: "Hard-limit results for dev-api",
      exact: true,
    }),
  ).toContainText("Fail");
  await expect(
    evidence.getByRole("region", {
      name: "Regression results for dev-api",
      exact: true,
    }),
  ).toContainText("Pass");
  await expect(evidence).toContainText("Maximum latency regression: 15%");
  await evidence.getByText("Trusted evidence and snapshot references").click();
  await expect(evidence).toContainText("slo-receipt-1");
  await expect(evidence).toContainText("evaluation-frozen-hash");
  await expect(
    page.getByText("FIXTURE MODE", { exact: true }),
  ).not.toBeVisible();
  await evidence.scrollIntoViewIfNeeded();
  await page.screenshot({
    path: testInfo.outputPath("slo-desktop.png"),
    fullPage: true,
  });
  await page.setViewportSize({ width: 390, height: 844 });
  await expect
    .poll(() =>
      page
        .locator(".sidebar")
        .evaluate((element) => element.getBoundingClientRect().right),
    )
    .toBeLessThanOrEqual(0);
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= window.innerWidth,
    ),
  ).toBe(true);
  await page.screenshot({
    path: testInfo.outputPath("slo-mobile.png"),
    fullPage: true,
  });
  expect(writes).toEqual([]);
});

test("zero demand leaves latency unavailable and incomplete coverage cannot display zero-rate health", async ({
  page,
}) => {
  const data = dashboard();
  const result = data.slo_evaluations![0].evaluation;
  Object.assign(result, {
    status: "CLEAR",
    reason_codes: [],
    request_count: 0,
    error_count: 0,
    error_rate_ppm: null,
    latency_samples: 0,
    p95_latency_ms: null,
    p99_latency_ms: null,
    p95_lower_ms: null,
    p99_lower_ms: null,
    latency_status: "NO_DEMAND",
    hard_checks: [],
    regression_checks: [],
  });
  const writes = await openSlo(page, data);
  const evidence = page.getByRole("region", {
    name: "SLO evaluation for dev-api",
  });
  const p95 = evidence
    .locator(".definition-list > div")
    .filter({ has: page.locator("dt", { hasText: /^p95 latency$/ }) });
  await expect(p95).toHaveText("p95 latencyUnavailable");
  await expect(evidence).toContainText("0 · No demand");
  Object.assign(result, {
    status: "BLOCKED",
    coverage_ppm: 500000,
    observed_intervals: 1,
    reason_codes: ["SLO_COVERAGE_INCOMPLETE"],
    error_rate_ppm: 0,
    availability_ppm: 1000000,
  });
  await page.getByRole("button", { name: "Refresh data" }).click();
  await expect(evidence).toContainText("50% · 1/2 intervals");
  await expect(evidence).toContainText("Unavailable · incomplete coverage");
  const availability = evidence
    .locator(".slo-observations > div")
    .filter({ has: page.locator("dt", { hasText: /^Availability$/ }) });
  await expect(availability).toHaveText("AvailabilityUnavailable");
  data.slo_evaluations![0].evaluation = {
    status: "BLOCKED",
    reason_codes: ["SLO_SOURCE_REQUIRED"],
  };
  data.slo_evaluations![0].source = null;
  await page.getByRole("button", { name: "Refresh data" }).click();
  await expect(evidence).toContainText("Slo source required");
  await expect(p95).toHaveText("p95 latencyUnavailable");
  expect(writes).toEqual([]);
});

test("a passing hard limit cannot hide a failed independent regression guard", async ({
  page,
}) => {
  const data = dashboard();
  data.slo_objectives![0].limits.max_p95_latency_ms = 200;
  const result = data.slo_evaluations![0].evaluation;
  Object.assign(result, {
    reason_codes: ["SLO_P95_REGRESSION_BREACH"],
    p95_lower_ms: 134,
    p95_latency_ms: 135,
    hard_checks: [
      { name: "P95_LATENCY", status: "PASS", reason_code: "WITHIN_HARD_LIMIT" },
    ],
    regression_checks: [
      {
        name: "P95_REGRESSION",
        status: "FAIL",
        reason_code: "SLO_P95_REGRESSION_BREACH",
      },
    ],
  });
  const writes = await openSlo(page, data);
  const evidence = page.getByRole("region", {
    name: "SLO evaluation for dev-api",
  });
  await expect(
    evidence.getByRole("region", {
      name: "Hard-limit results for dev-api",
      exact: true,
    }),
  ).toContainText("Pass");
  await expect(
    evidence.getByRole("region", {
      name: "Regression results for dev-api",
      exact: true,
    }),
  ).toContainText("Fail");
  await expect(evidence).toContainText("134–135 ms (bucket bounds)");
  await expect(evidence).toContainText("200 / 200 ms");
  await expect(evidence).toContainText("Maximum latency regression: 15%");
  expect(writes).toEqual([]);
});

test("an initial explicit objective sends version zero and separate hard and regression policy only", async ({
  page,
}) => {
  const data = dashboard();
  data.slo_objectives = [];
  data.slo_sources = [];
  data.slo_evaluations = [];
  const writes = await openSlo(page, data, async (route) => {
    const saved = {
      ...objective(1),
      ...route.request().postDataJSON(),
    } as SloObjective;
    data.slo_objectives = [saved];
    await route.fulfill({ status: 201, json: saved });
  });
  await page
    .getByRole("button", {
      name: "Configure SLO objectives for Development API",
    })
    .click();
  const dialog = page.getByRole("dialog", {
    name: "Configure service objectives",
  });
  await expect(dialog.getByLabel("Hard maximum p95 latency (ms)")).toHaveValue(
    "",
  );
  await dialog.getByLabel("Hard maximum p95 latency (ms)").fill("105");
  await dialog.getByLabel("Hard maximum p99 latency (ms)").fill("200");
  await dialog.getByLabel("Hard maximum error rate (ppm)").fill("10000");
  await dialog.getByLabel("Hard minimum availability (ppm)").fill("999000");
  await dialog.getByLabel("Minimum latency samples").fill("100");
  await dialog.getByLabel("Evaluation window (minutes)").fill("2");
  await dialog.getByLabel("Required availability").selectOption("WINDOWS");
  await dialog.getByRole("button", { name: "Add availability window" }).click();
  await dialog.getByLabel("Mon", { exact: true }).check();
  await dialog.getByLabel("Window 1 starts").fill("09:00");
  await dialog.getByLabel("Window 1 ends").fill("17:00");
  await dialog
    .getByLabel("Require a frozen, measurable pre-plan latency baseline")
    .check();
  await dialog.getByLabel("Maximum latency regression (%)").fill("15");
  await dialog.getByRole("button", { name: "Save objective revision" }).click();
  await expect(dialog).not.toBeVisible();
  expect(writes).toHaveLength(1);
  expect(writes[0].path).toBe("/v1/workloads/workload-api/slo-objectives");
  expect(writes[0].headers["if-match"]).toBe('"0"');
  expect(writes[0].headers["idempotency-key"]).toMatch(/^[a-f0-9-]{36}$/);
  expect(writes[0].body).toEqual({
    schema_version: "1",
    limits: {
      max_p95_latency_ms: 105,
      max_p99_latency_ms: 200,
      max_error_rate_ppm: 10000,
      min_availability_ppm: 999000,
      min_latency_samples: 100,
    },
    evaluation_minutes: 2,
    availability: {
      mode: "WINDOWS",
      timezone: "Europe/London",
      windows: [{ days: [1], start_time: "09:00", end_time: "17:00" }],
    },
    regression: { enabled: true, max_percent: 15 },
  });
});

test("a rejected concurrent objective revision remains visible and creates no plan", async ({
  page,
}) => {
  const writes = await openSlo(page, dashboard(), (route) =>
    route.fulfill({
      status: 409,
      json: { message: "Objective version changed." },
    }),
  );
  await page
    .getByRole("button", {
      name: "Configure SLO objectives for Development API",
    })
    .click();
  const dialog = page.getByRole("dialog", {
    name: "Configure service objectives",
  });
  await dialog.getByRole("button", { name: "Save objective revision" }).click();
  await expect(dialog.getByRole("alert")).toContainText("Objective not saved");
  expect(writes).toHaveLength(1);
  expect(writes[0].headers["if-match"]).toBe('"3"');
  expect(writes[0].path).toBe("/v1/workloads/workload-api/slo-objectives");
  await expect(dialog).toBeVisible();
});

test("collector registration sends only selected objective, resource and exact machine subject", async ({
  page,
}) => {
  const data = dashboard();
  const writes = await openSlo(page, data, (route) =>
    route.fulfill({
      status: 403,
      json: { message: "PLATFORM_ADMIN required" },
    }),
  );
  await page
    .getByRole("button", { name: "Register SLO collector", exact: true })
    .click();
  const dialog = page.getByRole("dialog", {
    name: "Register independent SLO collector",
  });
  await dialog
    .getByLabel("SLO collector resource")
    .selectOption("resource-api");
  await dialog
    .getByLabel("Exact machine subject")
    .fill("customer-slo-collector");
  await dialog
    .getByRole("button", { name: "Register SLO collector", exact: true })
    .click();
  await expect(dialog.getByRole("alert")).toContainText(
    "Collector not registered",
  );
  expect(writes).toHaveLength(1);
  expect(writes[0].body).toEqual({
    objective_id: "objective-3",
    resource_id: "resource-api",
    subject: "customer-slo-collector",
  });
  expect(writes[0].path).toBe("/v1/slo-sources");
  expect(writes[0].headers["idempotency-key"]).toMatch(/^[a-f0-9-]{36}$/);
});

test("schema-three approval requires frozen SLO bindings and exposes their references", async ({
  page,
}) => {
  const data = dashboard();
  data.readiness = [
    {
      id: "readiness",
      version: 1,
      resource_id: "resource-api",
      status: "READY",
      pre_execution_ready: true,
      verification_status: "MEASURING",
      checked_at: "2026-10-18T12:02:00Z",
      expires_at: "2026-10-18T12:07:00Z",
      binding: {
        tenant_id: "slo-ui",
        resource_id: "resource-api",
        provider_resource_id: "i-api",
        account_id: "111122223333",
        region: "eu-west-1",
        currency: null,
      },
    },
  ];
  data.change_plans = [
    {
      id: "plan-slo",
      version: 1,
      recommendation_id: "recommendation",
      resource_id: "resource-api",
      schedule_id: "",
      status: "APPROVED",
      risk_class: "R1",
      operations: [],
      expires_at: "2026-10-19T00:00:00Z",
      baseline_id: "financial-baseline",
      measurement_id: "measurement",
      readiness_id: "readiness",
      slo_status: "CLEAR",
      slo_objective_id: "objective-3",
      slo_objective_version: 3,
      slo_objective_hash: "objective-hash-3",
      slo_evaluation_id: "evaluation-frozen",
      slo_evaluation_hash: "evaluation-frozen-hash",
      payload: {
        schema_version: "3",
        proof_set_id: "proof",
        dependency_review_id: "dependency-review",
        dependency_graph_hash: "graph-hash",
      },
    },
  ];
  const writes = await openSlo(page, data);
  await page.getByRole("link", { name: "Schedules & policies" }).click();
  const execute = page.getByRole("button", { name: "Execute approved plan" });
  await expect(execute).toBeDisabled();
  Object.assign(data.change_plans[0].payload as object, {
    slo_objective_id: "objective-3",
    slo_objective_version: 3,
    slo_objective_hash: "objective-hash-3",
    slo_evaluation_id: "evaluation-frozen",
    slo_evaluation_hash: "evaluation-frozen-hash",
  });
  await page.getByRole("button", { name: "Refresh data" }).click();
  await expect(execute).toBeEnabled();
  await page
    .getByRole("button", { name: "Inspect plan-slo", exact: true })
    .click();
  const dialog = page.getByRole("dialog");
  await expect(dialog).toContainText("Bound SLO objective");
  await expect(dialog).toContainText("evaluation-frozen-hash");
  expect(writes).toEqual([]);
});
