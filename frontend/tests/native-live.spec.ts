import { test, expect } from "@playwright/test";
import type { components } from "../src/api.generated";

test("real OIDC and UI register exact native units and inspect persisted telemetry without inventing history", async ({
  page,
}) => {
  test.setTimeout(180_000);
  const errors: string[] = [];
  page.on("pageerror", (error) => errors.push(error.message));
  await page.goto("/");
  await page.getByRole("button", { name: "Sign in to your workspace" }).click();
  await page
    .getByRole("textbox", { name: /username/i })
    .fill(process.env.FINOPS_E2E_USER || "owner");
  await page
    .getByLabel("Password", { exact: true })
    .fill(process.env.FINOPS_E2E_PASSWORD || "local-pilot-demo");
  const [initial] = await Promise.all([
    page.waitForResponse(
      (response) => response.url().endsWith("/v1/dashboard") && response.ok(),
    ),
    page.getByRole("button", { name: "Sign In", exact: true }).click(),
  ]);
  expect(
    (await initial.json()).fixture,
    "This acceptance test is restricted to the local fixture stack.",
  ).toBe(true);
  const authorization = initial.request().headers().authorization;
  expect(authorization).toMatch(/^Bearer /);

  await page.getByRole("link", { name: "Workloads & resources" }).click();
  await page
    .getByLabel("Safety requirements workload")
    .selectOption("workload-dev");
  await page
    .getByRole("button", { name: "Configure safety requirements" })
    .click();
  const requirements = page.getByRole("dialog", {
    name: "Configure workload safety requirements",
  });
  await requirements
    .getByLabel("Workload criticality")
    .selectOption("NON_PRODUCTION");
  await requirements
    .getByLabel("Workload statefulness")
    .selectOption("UNKNOWN");
  await requirements
    .getByLabel("High seasonality requires at least 90 complete days")
    .uncheck();
  await requirements.getByLabel("Safety policy timezone").fill("Europe/London");
  for (const [label, value] of Object.entries({
    "Minimum healthy replicas": "1",
    "Minimum healthy zones": "1",
    "CPU unused capacity (ppm)": "300000",
    "Memory unused capacity (ppm)": "250000",
    "Reserve above forecast (ppm)": "300000",
    "CPU p99 rollback ceiling (ppm)": "850000",
    "Memory p99 rollback ceiling (ppm)": "900000",
    "Recovery time target (seconds)": "300",
    "Maximum simultaneous disruptive change (ppm)": "250000",
    "VM change cooldown (seconds)": "86400",
  }))
    await requirements.getByLabel(label, { exact: true }).fill(value);
  await requirements.getByLabel("Declare a specific RPO requirement").uncheck();
  await requirements
    .getByRole("button", { name: "Save safety requirements" })
    .click();
  await expect(requirements).not.toBeVisible();
  const assessment = page.getByRole("region", {
    name: /Safety assessment for/,
  });
  await expect(assessment).toContainText("Not authorized by this view");
  await expect(assessment).toContainText("Recovery evidence required");

  await page.getByRole("link", { name: "Connections & quality" }).click();
  await page
    .getByLabel("Native telemetry workload")
    .selectOption("workload-dev");
  await page.getByRole("button", { name: "Register native source" }).click();
  const dialog = page.getByRole("dialog", {
    name: "Register native telemetry connection",
  });
  await dialog
    .getByLabel("Telemetry resource")
    .selectOption("resource-dev-api");
  await dialog
    .getByLabel("Approved Prometheus read binding ID")
    .fill("fixture-prometheus-dev-api");
  await dialog
    .getByRole("button", { name: "Add metric definition", exact: true })
    .click();
  await dialog.getByLabel("Canonical metric 1").selectOption("request_count");
  await dialog
    .getByLabel("Native metric name 1")
    .fill("finops_gateway_requests_total");
  await dialog
    .getByLabel("Definition ID 1")
    .fill(`ui-served-requests-${Date.now()}`);
  await dialog.getByLabel("Definition version 1").fill("1");
  await dialog.getByLabel("Metric unit 1").fill("requests");
  await dialog.getByLabel("Expected cadence 1 (seconds)").fill("15");
  await dialog.getByLabel("Maximum gap 1 (seconds)").fill("30");
  await dialog
    .getByLabel("Counter epoch metric 1")
    .fill("process_start_time_seconds");
  const registered = page.waitForResponse(
    (response) =>
      response.url().endsWith("/v1/telemetry-connections") &&
      response.request().method() === "POST",
  );
  await dialog
    .getByRole("button", { name: "Save telemetry configuration" })
    .click();
  const created = await registered;
  expect(created.status()).toBe(201);
  const source =
    (await created.json()) as components["schemas"]["TelemetryConnection"];
  expect(source.definitions[0].unit).toBe("requests");
  expect(source.binding.resource_id).toBe("resource-dev-api");
  expect(source.definitions[0].attributes.finops_resource_id).toBe(
    "resource-dev-api",
  );
  await expect(dialog).not.toBeVisible();
  await page
    .getByRole("button", { name: `Inspect native telemetry ${source.id}` })
    .click();
  const evidence = page.getByRole("dialog", {
    name: "Native telemetry evidence",
  });
  await expect(
    evidence.getByRole("region", {
      name: "Scrollable registered metric definitions",
    }),
  ).toContainText("SUM · requests");
  await evidence
    .getByRole("button", { name: "Synchronize history", exact: true })
    .click();
  const sync = evidence.getByRole("region", {
    name: "Durable native synchronization",
  });
  await expect(sync.getByText("Completed", { exact: true })).toBeVisible({
    timeout: 90_000,
  });
  await expect(sync).toContainText("observed coverage is evaluated separately");
  const evaluated = page.waitForResponse(
    (response) =>
      response.url().endsWith(`/telemetry-connections/${source.id}/evaluate`) &&
      response.request().method() === "POST",
  );
  await evidence
    .getByRole("button", { name: "Evaluate history", exact: true })
    .click();
  const evaluatedResponse = await evaluated;
  expect(evaluatedResponse.status()).toBe(201);
  const record =
    (await evaluatedResponse.json()) as components["schemas"]["TelemetryEvaluationRecord"];
  expect(record.evaluation.status).toBe("BLOCKED");
  expect(
    record.evaluation.metrics.some((metric) => metric.coverage_ppm < 1_000_000),
  ).toBe(true);
  const evaluation = evidence.getByRole("region", {
    name: `Native evaluation ${record.id}`,
    exact: true,
  });
  await expect(evaluation).toContainText("Blocked");
  await expect(evaluation).toContainText(
    "missing observations remain unavailable",
  );
  await expect
    .poll(
      async () => {
        const response = await page.request.get(
          `/v1/telemetry-connections/${source.id}/receipts?limit=100`,
          { headers: { Authorization: authorization } },
        );
        expect(response.ok()).toBe(true);
        const pageOfReceipts =
          (await response.json()) as components["schemas"]["TelemetryReceiptPage"];
        return pageOfReceipts.items.some(
          (receipt) =>
            receipt.sample_count > 0 &&
            receipt.active_source &&
            /^[a-f0-9]{64}$/.test(receipt.canonical_hash),
        );
      },
      { timeout: 45_000 },
    )
    .toBe(true);
  await evidence
    .getByText("Assess historical capacity evidence", { exact: true })
    .click();
  const assessed = page.waitForResponse(
    (response) =>
      response.url().endsWith("/workloads/workload-dev/capacity-assessments") &&
      response.request().method() === "POST",
  );
  await evidence
    .getByRole("button", { name: "Assess capacity evidence", exact: true })
    .click();
  const capacityResponse = await assessed;
  expect(capacityResponse.status()).toBe(201);
  const capacity =
    (await capacityResponse.json()) as components["schemas"]["CapacityAssessment"];
  expect(capacity.status).toBe("BLOCKED");
  expect(capacity.execution_authorized).toBe(false);
  expect(capacity.estimated_saving).toBeNull();
  expect(capacity.verified_saving).toBeNull();
  expect(capacity.reason_codes).toContain(
    "BLOCKED_NATIVE_CAPACITY_CATALOG_REQUIRED",
  );
  expect(capacity.reason_codes).toContain("NATIVE_PRICE_UNAVAILABLE");
  expect(capacity.population_hash).toMatch(/^[a-f0-9]{64}$/);
  expect(capacity.receipt_ids.length).toBeGreaterThan(0);
  expect(capacity.source_refs.map((ref) => ref.receipt_id)).toEqual(
    capacity.receipt_ids,
  );
  const capacityView = evidence.getByRole("region", {
    name: `Capacity assessment ${capacity.id}`,
    exact: true,
  });
  await expect(capacityView).toContainText("Not authorized by this assessment");
  await expect(capacityView).toContainText("Unavailable / Unavailable");
  await evidence.getByRole("button", { name: "Close dialog" }).click();
  await page.getByRole("button", { name: "Refresh native sources" }).click();
  await expect(
    page.getByRole("button", { name: `Inspect native telemetry ${source.id}` }),
  ).toBeVisible();
  expect(errors).toEqual([]);
});
