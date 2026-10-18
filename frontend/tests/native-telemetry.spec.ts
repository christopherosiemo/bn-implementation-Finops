import { test, expect, type Page, type Route } from "@playwright/test";
import type { components } from "../src/api.generated";
import type {
  Dashboard,
  TelemetryConnection,
  TelemetryEvaluationRecord,
  WorkloadSafetyProfile,
} from "../src/types";

const stamp = "2026-10-18T12:00:00Z";
const definition: components["schemas"]["TelemetryDefinition"] = {
  id: "cpu-v1",
  version: "1",
  metric: "cpu_utilization",
  name: "native_cpu_ratio",
  type: "GAUGE",
  unit: "ratio",
  monotonic: false,
  cadence_seconds: 60,
  max_gap_seconds: 120,
  attributes: {},
  resource_attributes: {},
};
const connection: TelemetryConnection = {
  schema_version: "1",
  id: "native-1",
  version: 3,
  kind: "PROMETHEUS",
  read_binding_id: "approved-binding",
  binding: {
    tenant_id: "native-contract",
    workload_id: "workload-api",
    resource_id: "resource-api",
    provider: "AWS",
    provider_resource_id: "i-api",
    account_id: "111122223333",
    region: "eu-west-1",
  },
  enabled: true,
  definitions: [definition],
  config_hash: "config-3",
  revision_id: "revision-3",
  writer_role: "finops_api",
  created_at: stamp,
  revoked: false,
};
const profile: WorkloadSafetyProfile = {
  schema_version: "1",
  id: "requirements-4",
  workload_id: "workload-api",
  version: 4,
  hash: "requirements-hash-4",
  writer_role: "finops_api",
  created_at: stamp,
  criticality: "NON_PRODUCTION",
  statefulness: "UNKNOWN",
  high_seasonality: true,
  timezone: "Europe/London",
  min_replicas: 2,
  min_zones: 2,
  headroom: {
    cpu_free_ppm: 300000,
    memory_free_ppm: 250000,
    reserve_above_forecast_ppm: 300000,
  },
  saturation: { cpu_p99_ppm: 850000, memory_p99_ppm: 900000 },
  rto_seconds: 300,
  rpo_seconds: null,
  maintenance: [{ days: [0], start_time: "22:00", end_time: "24:00" }],
  recurring_blackouts: [],
  blackouts: [],
  demand_events: [],
  max_simultaneous_change_ppm: 250000,
  vm_cooldown_seconds: 86400,
};
const result: TelemetryEvaluationRecord = {
  id: "evaluation-1",
  connection_id: connection.id,
  config_hash: connection.config_hash,
  receipt_ids: ["native-receipt-1"],
  hash: "eval-hash",
  created_at: stamp,
  evaluation: {
    schema_version: "1",
    status: "BLOCKED",
    reason_codes: ["MEMORY_OBSERVATIONS_REQUIRED"],
    start: "2026-10-04T00:00:00Z",
    end: "2026-10-18T00:00:00Z",
    evaluated_at: stamp,
    hash: "eval-hash",
    history_days: 14,
    timezone: "Europe/London",
    metrics: [
      {
        definition_id: "cpu-v1",
        metric: "cpu_utilization",
        unit: "ratio",
        status: "BLOCKED",
        reason_codes: ["INTERVAL_MAXIMUM_NOT_DISTRIBUTION"],
        start: stamp,
        end: stamp,
        observed_samples: 1,
        expected_samples: 60,
        coverage_ppm: 16666,
        observed_duration_ns: 60000000000,
        unknown_duration_ns: 3540000000000,
        p50: null,
        p90: null,
        p95: null,
        p99: null,
        p999: null,
        maximum: "0.88",
        total: null,
        statistic: "INTERVAL_MAXIMUM",
        segment_ids: ["segment-preview-1"],
        segment_count: 60,
        segment_hash: "all-sixty-segments-hash",
        segment_ids_truncated: true,
      },
    ],
  },
};

function dashboard(): Dashboard {
  return {
    org: {
      id: "native-contract",
      name: "Native telemetry contract",
      version: 1,
      paused: false,
    },
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
        owner: "owner@example.test",
        environment: "NON_PRODUCTION",
        timezone: "Europe/London",
        incident: "UNKNOWN",
        deployment: "UNKNOWN",
        job: "UNKNOWN",
        signals_at: stamp,
      },
      {
        id: "workload-batch",
        version: 1,
        name: "Batch workload",
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
        id: "resource-api",
        version: 2,
        name: "native-api",
        provider: "AWS",
        provider_resource_id: "i-api",
        resource_type: "EC2",
        workload_id: "workload-api",
        environment: "NON_PRODUCTION",
        state: "running",
        configuration_authority: "TERRAFORM",
        hourly_effective_cost: null,
        monthly_effective_cost: null,
        currency: null,
        eligibility: "BLOCKED",
        blockers: ["MEMORY_OBSERVATIONS_REQUIRED"],
      },
    ],
  };
}
type Write = {
  path: string;
  body: Record<string, unknown>;
  headers: Record<string, string>;
};
type Handler = (route: Route, url: URL) => Promise<boolean>;
async function open(page: Page, view: "native" | "safety", handler?: Handler) {
  const writes: Write[] = [];
  const reads: string[] = [];
  await page.route("**/.well-known/openid-configuration", (route) => {
    const origin = new URL(page.url()).origin;
    return route.fulfill({
      json: {
        authorization_endpoint: `${origin}/__native/authorize`,
        token_endpoint: `${origin}/__native/token`,
      },
    });
  });
  await page.route("**/__native/authorize?**", (route) => {
    const params = new URL(route.request().url()).searchParams;
    const redirect = new URL(params.get("redirect_uri")!);
    redirect.searchParams.set("code", "native-contract");
    redirect.searchParams.set("state", params.get("state")!);
    return route.fulfill({
      status: 302,
      headers: { location: redirect.toString() },
    });
  });
  await page.route("**/__native/token", (route) =>
    route.fulfill({
      json: {
        access_token: `test.${Buffer.from(JSON.stringify({ name: "Native operator" })).toString("base64url")}.test`,
        expires_in: 3600,
      },
    }),
  );
  await page.route("**/v1/**", async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    const path = url.pathname;
    if (request.method() === "GET") reads.push(`${path}${url.search}`);
    else
      writes.push({
        path,
        body: request.postDataJSON() as Record<string, unknown>,
        headers: request.headers(),
      });
    if (handler && (await handler(route, url))) return;
    if (path === "/v1/dashboard") return route.fulfill({ json: dashboard() });
    if (request.method() !== "GET")
      return route.fulfill({
        status: 201,
        json: { id: "saved-1", version: 1 },
      });
    if (path === "/v1/telemetry-connections")
      return route.fulfill({
        json: {
          items:
            url.searchParams.get("workload_id") === "workload-api"
              ? [connection]
              : [],
          next_cursor: null,
        },
      });
    if (path === `/v1/telemetry-connections/${connection.id}`)
      return route.fulfill({ json: connection });
    if (path === "/v1/metric-definitions")
      return route.fulfill({
        json: {
          items: [definition],
          next_cursor: null,
          connection_id: connection.id,
          config_hash: connection.config_hash,
        },
      });
    if (path.endsWith("/safety-profiles"))
      return route.fulfill({
        json: { version: 0, latest: null, items: [], next_cursor: null },
      });
    if (path.endsWith("/safety-evaluation"))
      return route.fulfill({
        json: {
          workload_id: "workload-api",
          status: "BLOCKED",
          reason_codes: ["SAFETY_PROFILE_REQUIRED"],
        },
      });
    if (path.endsWith("/evaluations") || path.endsWith("/receipts"))
      return route.fulfill({ json: { items: [], next_cursor: null } });
    return route.fulfill({
      status: 404,
      json: { message: "No presentation evidence registered" },
    });
  });
  await page.goto("/");
  await page.getByRole("button", { name: "Sign in to your workspace" }).click();
  await expect(
    page.getByRole("heading", { name: "Cost operations overview." }),
  ).toBeVisible();
  await page
    .getByRole("link", {
      name:
        view === "native" ? "Connections & quality" : "Workloads & resources",
    })
    .click();
  return { writes, reads };
}
async function inspect(page: Page) {
  await page
    .getByRole("button", { name: `Inspect native telemetry ${connection.id}` })
    .click();
  return page.getByRole("dialog", { name: "Native telemetry evidence" });
}

test("native evidence pagination preserves missing quantiles and bounded immutable references", async ({
  page,
}, testInfo) => {
  const receipt = {
    id: "native-receipt-1",
    batch_id: "batch-1",
    connection_id: connection.id,
    revision_id: "revision-3",
    config_hash: connection.config_hash,
    binding: connection.binding,
    source_kind: "PROMETHEUS",
    raw_sha256: "raw-hash",
    canonical_hash: "canonical-hash",
    collected_at: stamp,
    start: stamp,
    end: stamp,
    sample_count: 1,
    rejection_count: 2,
    warning_count: 1,
    active_source: true,
    created_at: stamp,
  };
  const { reads, writes } = await open(page, "native", async (route, url) => {
    if (url.pathname.endsWith("/receipts")) {
      await route.fulfill({
        json: {
          items: [
            {
              ...receipt,
              id: url.searchParams.has("cursor")
                ? "native-receipt-2"
                : receipt.id,
            },
          ],
          next_cursor: url.searchParams.has("cursor")
            ? null
            : "receipt /+opaque=",
        },
      });
      return true;
    }
    if (url.pathname.endsWith("/evaluations")) {
      await route.fulfill({
        json: {
          items: [
            url.searchParams.has("cursor")
              ? { ...result, id: "evaluation-2" }
              : {
                  ...result,
                  evaluation: {
                    ...result.evaluation,
                    metrics: [
                      ...result.evaluation.metrics,
                      {
                        ...result.evaluation.metrics[0],
                        definition_id: "latency-v1",
                        metric: "latency",
                        unit: "milliseconds",
                        statistic: "EXPLICIT_BUCKET_POPULATION",
                        histogram: {
                          count: "9007199254740993",
                          bounds: ["100"],
                          bucket_counts: ["9007199254740993", "0"],
                        },
                      },
                    ],
                  },
                },
          ],
          next_cursor: url.searchParams.has("cursor")
            ? null
            : "evaluation /+opaque=",
        },
      });
      return true;
    }
    return false;
  });
  const dialog = await inspect(page);
  const evaluation = dialog.getByRole("region", {
    name: "Native evaluation evaluation-1",
    exact: true,
  });
  await expect(evaluation).toContainText("INTERVAL_MAXIMUM");
  const row = evaluation
    .getByRole("row")
    .filter({ has: page.getByText("Cpu utilization", { exact: true }) });
  await expect(row.getByRole("cell").nth(3)).toHaveText(
    "Unavailable / Unavailable",
  );
  await expect(row.getByRole("cell").nth(5)).toContainText("0.88");
  await evaluation
    .getByText("Evaluation and source references", { exact: true })
    .click();
  await expect(evaluation).toContainText("60 total · truncated preview");
  await expect(evaluation).toContainText("all-sixty-segments-hash");
  await expect(evaluation).toContainText("Histogram count 9007199254740993");
  await dialog
    .getByRole("button", { name: "Load more telemetry receipts" })
    .click();
  await expect(
    dialog.getByRole("cell", { name: /^native-receipt-2 / }),
  ).toBeVisible();
  await dialog
    .getByRole("button", { name: "Load more telemetry evaluations" })
    .click();
  await expect(
    dialog.getByRole("region", {
      name: "Native evaluation evaluation-2",
      exact: true,
    }),
  ).toBeVisible();
  expect(reads).toContain(
    "/v1/telemetry-connections?workload_id=workload-api&limit=20",
  );
  expect(
    reads.some((url) => url.includes("cursor=receipt%20%2F%2Bopaque%3D")),
  ).toBeTruthy();
  expect(writes).toHaveLength(0);
  await dialog.evaluate((element) => {
    element.scrollTop = 0;
  });
  await page.evaluate(() => window.scrollTo(0, 0));
  await page.screenshot({
    path: testInfo.outputPath("native-evidence-desktop.png"),
    fullPage: false,
    animations: "disabled",
  });
  await page.setViewportSize({ width: 390, height: 844 });
  await expect
    .poll(() =>
      page
        .locator(".sidebar")
        .evaluate((element) => element.getBoundingClientRect().right),
    )
    .toBeLessThanOrEqual(0);
  await dialog.evaluate((element) => {
    element.scrollTop = 0;
  });
  await expect
    .poll(() =>
      page.evaluate(
        () => document.documentElement.scrollWidth - window.innerWidth,
      ),
    )
    .toBeLessThanOrEqual(1);
  await page.screenshot({
    path: testInfo.outputPath("native-evidence-mobile.png"),
    fullPage: false,
    animations: "disabled",
  });
});

test("native controls bind current versions and show durable publication without claiming coverage", async ({
  page,
}) => {
  const { writes } = await open(page, "native", async (route, url) => {
    if (url.pathname.endsWith("/sync") && route.request().method() === "POST") {
      await route.fulfill({ status: 202, json: { id: "sync-1" } });
      return true;
    }
    if (url.pathname.endsWith("/sync/sync-1")) {
      await route.fulfill({
        json: {
          id: "sync-1",
          connection_id: connection.id,
          status: "COMPLETED",
          history_days: 90,
          attempts: 2,
          start: "2026-07-20T00:00:00Z",
          end: stamp,
          receipt_ids: ["published-query"],
          reason_code: null,
        },
      });
      return true;
    }
    return false;
  });
  const dialog = await inspect(page);
  await dialog.getByRole("button", { name: "Synchronize history" }).click();
  const sync = dialog.getByRole("region", {
    name: "Durable native synchronization",
  });
  await expect(sync).toContainText("Completed");
  await expect(sync).toContainText("observed coverage is evaluated separately");
  await dialog
    .getByRole("button", { name: "Evaluate history", exact: true })
    .click();
  await dialog.getByRole("button", { name: "Evaluate current window" }).click();
  await dialog
    .getByRole("button", { name: "Revoke source", exact: true })
    .click();
  await dialog
    .getByLabel("Reason for revoking this telemetry source")
    .fill("Collector rotated after review");
  await dialog
    .getByRole("button", { name: "Confirm source revocation" })
    .click();
  await expect.poll(() => writes.length).toBe(4);
  for (const write of writes) {
    expect(write.headers["if-match"]).toBe('"3"');
    expect(write.headers["idempotency-key"]).toMatch(/^[0-9a-f-]{36}$/);
  }
  expect(writes.map((write) => write.body)).toEqual([
    {},
    { mode: "history" },
    { mode: "window" },
    { reason: "Collector rotated after review" },
  ]);
});

test("OTLP registration submits definitions without source evidence or server identity", async ({
  page,
}) => {
  const { writes } = await open(page, "native");
  await page.getByRole("button", { name: "Register native source" }).click();
  const dialog = page.getByRole("dialog", {
    name: "Register native telemetry connection",
  });
  await dialog.getByLabel("Telemetry resource").selectOption("resource-api");
  await dialog.getByLabel("Native protocol").selectOption("OTLP");
  await dialog
    .getByLabel("Exact OTLP machine subject")
    .fill("service-account-native-collector");
  await dialog
    .getByRole("button", { name: "Add metric definition", exact: true })
    .click();
  await dialog.getByLabel("Canonical metric 1").selectOption("latency");
  await dialog
    .getByLabel("Native metric name 1")
    .fill("http.server.request.duration");
  await dialog.getByLabel("Definition ID 1").fill("latency-native");
  await dialog.getByLabel("Definition version 1").fill("1");
  await dialog.getByLabel("Metric unit 1").fill("s");
  await dialog
    .getByRole("button", { name: "Save telemetry configuration" })
    .click();
  await expect(dialog).not.toBeVisible();
  expect(writes).toHaveLength(1);
  expect(writes[0].body).toEqual({
    resource_id: "resource-api",
    kind: "OTLP",
    subject: "service-account-native-collector",
    definitions: [
      {
        ...definition,
        id: "latency-native",
        metric: "latency",
        name: "http.server.request.duration",
        unit: "s",
        type: "HISTOGRAM",
      },
    ],
  });
  expect(writes[0].headers["if-match"]).toBeUndefined();
  expect(JSON.stringify(writes[0].body)).not.toContain("samples");
  expect(JSON.stringify(writes[0].body)).not.toContain("issuer");
});

test("a concurrent telemetry revision stays open and does not silently retry stale authority", async ({
  page,
}) => {
  const { writes } = await open(page, "native", async (route, url) => {
    if (url.pathname.endsWith("/revisions")) {
      await route.fulfill({
        status: 409,
        json: { message: "Connection version changed" },
      });
      return true;
    }
    return false;
  });
  const details = await inspect(page);
  await details.getByRole("button", { name: "Revise configuration" }).click();
  const dialog = page.getByRole("dialog", {
    name: "Revise native telemetry connection",
  });
  await dialog
    .getByLabel("Native metric name 1")
    .fill("updated_native_cpu_ratio");
  await dialog
    .getByRole("button", { name: "Save telemetry configuration" })
    .click();
  await expect(dialog.getByRole("alert")).toContainText(
    "Configuration not saved",
  );
  await expect(dialog.getByLabel("Native metric name 1")).toHaveValue(
    "updated_native_cpu_ratio",
  );
  expect(writes).toHaveLength(1);
  expect(writes[0].headers["if-match"]).toBe('"3"');
});

async function fillRequirements(page: Page) {
  await page
    .getByRole("button", { name: "Configure safety requirements" })
    .click();
  const dialog = page.getByRole("dialog", {
    name: "Configure workload safety requirements",
  });
  await dialog
    .getByLabel("Workload criticality")
    .selectOption("NON_PRODUCTION");
  const values = {
    "Minimum healthy replicas": "2",
    "Minimum healthy zones": "2",
    "CPU unused capacity (ppm)": "300000",
    "Memory unused capacity (ppm)": "250000",
    "Reserve above forecast (ppm)": "300000",
    "CPU p99 rollback ceiling (ppm)": "850000",
    "Memory p99 rollback ceiling (ppm)": "900000",
    "Recovery time target (seconds)": "300",
    "Maximum simultaneous disruptive change (ppm)": "250000",
    "VM change cooldown (seconds)": "86400",
  };
  for (const [label, value] of Object.entries(values))
    await dialog.getByLabel(label, { exact: true }).fill(value);
  return dialog;
}

test("initial requirements preserve explicit null RPO, overnight calendar and known 4x demand event", async ({
  page,
}) => {
  const { writes } = await open(page, "safety");
  const dialog = await fillRequirements(page);
  await dialog
    .getByRole("button", { name: "Add maintenance windows", exact: true })
    .click();
  const window = dialog.getByRole("group", {
    name: "Maintenance windows 1",
    exact: true,
  });
  await window.getByLabel("Sun", { exact: true }).check();
  await window.getByLabel("Maintenance windows 1 start").fill("22:00");
  await window.getByLabel("Maintenance windows 1 end").fill("24:00");
  await dialog
    .getByRole("button", { name: "Add demand event", exact: true })
    .click();
  await dialog.getByLabel("Demand event 1 reason").fill("Seasonal launch");
  await dialog
    .getByLabel("Demand event 1 start (UTC)")
    .fill("2026-11-01T00:00");
  await dialog.getByLabel("Demand event 1 end (UTC)").fill("2026-11-02T00:00");
  await dialog.getByLabel("Demand event 1 multiplier (ppm)").fill("4000000");
  await dialog
    .getByRole("button", { name: "Save safety requirements" })
    .click();
  await expect(dialog).not.toBeVisible();
  expect(writes).toHaveLength(1);
  expect(writes[0].headers["if-match"]).toBe('"0"');
  expect(writes[0].headers["idempotency-key"]).toBeTruthy();
  expect(writes[0].body).toMatchObject({
    schema_version: "1",
    high_seasonality: false,
    rpo_seconds: null,
    statefulness: "UNKNOWN",
    headroom: profile.headroom,
    saturation: profile.saturation,
    maintenance: [{ days: [0], start_time: "22:00", end_time: "24:00" }],
    recurring_blackouts: [],
    blackouts: [],
    demand_events: [
      {
        reason: "Seasonal launch",
        start: "2026-11-01T00:00:00.000Z",
        end: "2026-11-02T00:00:00.000Z",
        demand_multiplier_ppm: 4000000,
      },
    ],
  });
  expect(writes[0].body).not.toHaveProperty("workload_id");
  expect(writes[0].body).not.toHaveProperty("recovery_evidence");
});

test("requirements history and zero RPO target never masquerade as achieved recovery", async ({
  page,
}) => {
  const { reads, writes } = await open(page, "safety", async (route, url) => {
    if (url.pathname.endsWith("/safety-profiles")) {
      await route.fulfill({
        json: {
          version: 4,
          latest: profile,
          items: [
            url.searchParams.has("cursor")
              ? { ...profile, id: "requirements-3", version: 3, rpo_seconds: 0 }
              : profile,
          ],
          next_cursor: url.searchParams.has("cursor")
            ? null
            : "history /+opaque=",
        },
      });
      return true;
    }
    if (url.pathname.endsWith("/safety-evaluation")) {
      await route.fulfill({
        json: {
          workload_id: "workload-api",
          status: "BLOCKED",
          reason_codes: ["RECOVERY_EVIDENCE_REQUIRED", "STATEFULNESS_UNKNOWN"],
          requirements_only: true,
          execution_authorized: false,
          recovery_evidence_status: "UNAVAILABLE",
        },
      });
      return true;
    }
    return false;
  });
  const assessment = page.getByRole("region", {
    name: "Safety assessment for Development API",
  });
  await expect(assessment).toContainText("Not authorized by this view");
  await expect(assessment).toContainText("UNAVAILABLE");
  await expect(assessment).toContainText("90 days · high seasonality");
  await expect(assessment).toContainText("Recovery evidence required");
  await page.getByRole("button", { name: "Load more safety history" }).click();
  const history = page.getByRole("region", {
    name: "Immutable safety requirement history",
  });
  await expect(history).toContainText("Revision 3");
  await expect(history).toContainText("RPO 0s");
  expect(
    reads.some((url) => url.includes("cursor=history%20%2F%2Bopaque%3D")),
  ).toBeTruthy();
  expect(writes).toHaveLength(0);
});

test("source read failures and scoped workload switching stay unavailable without changing authority", async ({
  page,
}) => {
  const { reads, writes } = await open(page, "native", async (route, url) => {
    if (
      url.pathname === "/v1/telemetry-connections" &&
      url.searchParams.get("workload_id") === "workload-api"
    ) {
      await route.fulfill({
        status: 503,
        json: { message: "Source reader unavailable" },
      });
      return true;
    }
    return false;
  });
  await expect(
    page
      .getByRole("alert")
      .filter({ hasText: "Native telemetry connections unavailable" }),
  ).toBeVisible();
  await expect(
    page.getByText("No native telemetry connections", { exact: true }),
  ).not.toBeVisible();
  await page
    .getByLabel("Native telemetry workload")
    .selectOption("workload-batch");
  await expect(
    page.getByText("No native telemetry connections", { exact: true }),
  ).toBeVisible();
  expect(reads).toContain(
    "/v1/telemetry-connections?workload_id=workload-batch&limit=20",
  );
  expect(
    reads
      .filter((url) => url.startsWith("/v1/telemetry-connections?"))
      .every((url) => url.includes("workload_id=")),
  ).toBeTruthy();
  expect(writes).toHaveLength(0);
});

test("malformed source pagination cannot become an empty evidence claim", async ({
  page,
}) => {
  const { writes } = await open(page, "native", async (route, url) => {
    if (url.pathname === "/v1/telemetry-connections") {
      await route.fulfill({ json: { items: null, next_cursor: null } });
      return true;
    }
    return false;
  });
  await expect(
    page
      .getByRole("alert")
      .filter({ hasText: "API returned an incomplete page" }),
  ).toBeVisible();
  await expect(
    page.getByText("No native telemetry connections", { exact: true }),
  ).not.toBeVisible();
  expect(writes).toHaveLength(0);
});

test("requirements version conflict preserves declarations and never offers execution approval", async ({
  page,
}) => {
  const { writes } = await open(page, "safety", async (route, url) => {
    if (
      url.pathname.endsWith("/safety-profiles") &&
      route.request().method() === "POST"
    ) {
      await route.fulfill({
        status: 409,
        json: { message: "Safety profile version changed" },
      });
      return true;
    }
    return false;
  });
  const dialog = await fillRequirements(page);
  await dialog.getByLabel("Declare a specific RPO requirement").check();
  await dialog.getByLabel("Recovery point target (seconds)").fill("0");
  await dialog
    .getByRole("button", { name: "Save safety requirements" })
    .click();
  await expect(dialog.getByRole("alert")).toContainText(
    "Requirements not saved",
  );
  await expect(
    dialog.getByLabel("Recovery point target (seconds)"),
  ).toHaveValue("0");
  expect(writes).toHaveLength(1);
  expect(writes[0].body.rpo_seconds).toBe(0);
  expect(writes[0].headers["if-match"]).toBe('"0"');
  await expect(
    dialog.getByRole("button", { name: /approve|execute/i }),
  ).toHaveCount(0);
});

test("capacity assessment binds the selected source and safety version while missing catalog and money stay unavailable", async ({
  page,
}) => {
  let recorded = false;
  const assessment: components["schemas"]["CapacityAssessment"] = {
    schema_version: "1",
    id: "capacity-blocked-1",
    workload_id: "workload-api",
    resource_id: "resource-api",
    connection_id: connection.id,
    connection_version: connection.version,
    revision_id: connection.revision_id,
    config_hash: connection.config_hash,
    safety_profile_id: profile.id,
    safety_profile_version: profile.version,
    safety_profile_hash: profile.hash,
    population_hash: "population-full-native-hash",
    receipt_ids: ["native-receipt-1"],
    source_refs: [],
    history: {
      start: "2026-07-20T00:00:00Z",
      end: "2026-10-18T00:00:00Z",
      days: 90,
      timezone: "Europe/London",
      environment: "NON_PRODUCTION",
    },
    native_evaluation: result.evaluation,
    status: "BLOCKED",
    reason_codes: [
      "BLOCKED_NATIVE_CAPACITY_CATALOG_REQUIRED",
      "NATIVE_PRICE_UNAVAILABLE",
    ],
    execution_authorized: false,
    hardware_catalog_status: "UNAVAILABLE",
    native_price_status: "UNAVAILABLE",
    estimated_saving: null,
    verified_saving: null,
    hash: "assessment-hash",
    created_at: stamp,
    writer_role: "finops_api",
  };
  const { writes } = await open(page, "native", async (route, url) => {
    if (url.pathname.endsWith("/safety-profiles")) {
      await route.fulfill({
        json: {
          version: 4,
          latest: profile,
          items: [profile],
          next_cursor: null,
        },
      });
      return true;
    }
    if (url.pathname.endsWith("/capacity-assessments")) {
      if (route.request().method() === "POST") {
        recorded = true;
        await route.fulfill({ status: 201, json: assessment });
      } else
        await route.fulfill({
          json: { items: recorded ? [assessment] : [], next_cursor: null },
        });
      return true;
    }
    return false;
  });
  const dialog = await inspect(page);
  await dialog
    .getByText("Assess historical capacity evidence", { exact: true })
    .click();
  await dialog
    .getByRole("button", { name: "Assess capacity evidence", exact: true })
    .click();
  const evidence = dialog.getByRole("region", {
    name: "Capacity assessment capacity-blocked-1",
    exact: true,
  });
  await expect(evidence).toContainText(
    "Blocked native capacity catalog required",
  );
  await expect(evidence).toContainText("Unavailable / Unavailable");
  await expect(evidence).toContainText("Not authorized by this assessment");
  await evidence
    .getByText("Frozen source and requirements references", { exact: true })
    .click();
  await expect(evidence).toContainText("population-full-native-hash");
  expect(writes).toHaveLength(1);
  expect(writes[0].headers["if-match"]).toBe('"4"');
  expect(writes[0].body).toEqual({ connection_id: connection.id });
  await expect(
    evidence.getByRole("button", { name: /approve|execute/i }),
  ).toHaveCount(0);
});
