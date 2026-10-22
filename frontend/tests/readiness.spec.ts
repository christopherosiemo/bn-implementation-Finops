import { expect, test, type Page } from "@playwright/test";
import type { Dashboard } from "../src/types";

// These are presentation-contract tests. Only the dashboard and OIDC transport
// are stubbed; the real fixture operating-loop suite separately tests the stack.
function dashboard(): Dashboard {
  return {
    org: {
      id: "ui-contract",
      version: 1,
      name: "Readiness contract",
      paused: false,
    },
    fixture: false,
    cloud_accounts: [],
    policies: [],
    schedules: [],
    change_plans: [],
    executions: [],
    audit: [],
    data_quality: [],
    workloads: [
      {
        id: "workload-ui",
        version: 1,
        name: "Engineering sandbox",
        environment: "NON_PRODUCTION",
        owner: "platform@example.test",
        timezone: "Europe/London",
        incident: "CLEAR",
        deployment: "CLEAR",
        job: "CLEAR",
        signals_at: "2026-10-17T12:00:00Z",
      },
    ],
    resources: [
      {
        id: "resource-ui",
        version: 1,
        name: "dev-api-ready",
        provider: "AWS",
        resource_type: "EC2",
        provider_resource_id: "i-ui-contract",
        workload_id: "workload-ui",
        environment: "NON_PRODUCTION",
        state: "running",
        configuration_authority: "TERRAFORM",
        hourly_effective_cost: "0.480000000000",
        monthly_effective_cost: "350.400000000000",
        currency: "GBP",
        eligibility: "ELIGIBLE",
        blockers: [],
      },
    ],
    recommendations: [
      {
        id: "recommendation-ui",
        version: 1,
        resource_id: "resource-ui",
        workload_id: "workload-ui",
        title: "Schedule the evidenced idle window",
        category: "NON_PRODUCTION_SCHEDULING",
        risk_class: "R1",
        status: "VALIDATED",
        reason_code: "VERIFICATION_WINDOW_INCOMPLETE",
        pre_execution_ready: true,
        verification_status: "MEASURING",
        baseline_id: "baseline-v2",
        measurement_id: null,
        evidence_refs: ["cur-v2/source-14-days", "workload-samples/v2"],
        monthly_saving: "144.000000000000",
        annual_saving: "1728.000000000000",
        currency: "GBP",
        confidence: "HIGH",
        evidence: "A validated pre-activation baseline authorizes this cycle.",
      },
    ],
    readiness: [
      {
        id: "readiness-v2",
        version: 1,
        resource_id: "resource-ui",
        workload_id: "workload-ui",
        status: "READY",
        pre_execution_ready: true,
        verification_status: "MEASURING",
        reason_code: "VERIFICATION_WINDOW_INCOMPLETE",
        baseline_id: "baseline-v2",
        measurement_id: null,
        blockers: [],
        checked_at: "2026-10-17T12:00:00Z",
        expires_at: "2026-10-17T12:05:00Z",
        binding: {
          tenant_id: "ui-contract",
          resource_id: "resource-ui",
          provider_resource_id: "i-ui-contract",
          account_id: "111122223333",
          region: "eu-west-1",
          currency: "GBP",
        },
      },
    ],
    savings: [
      {
        id: "saving-ui",
        version: 1,
        execution_id: "execution-ui",
        status: "MEASURING",
        verification_status: "MEASURING",
        pre_execution_ready: true,
        baseline_id: "baseline-v2",
        measurement_id: "measurement-v2",
        verified_saving: null,
        expected_baseline_cost: "67.200000000000",
        actual_cost: null,
        currency: "GBP",
        reason_code: "VERIFICATION_WINDOW_INCOMPLETE",
        evidence_refs: ["cur-v2/source-14-days"],
      },
    ],
  };
}

async function openContract(page: Page, data: Dashboard) {
  const writes: string[] = [];
  page.on("request", (request) => {
    if (
      request.method() !== "GET" &&
      new URL(request.url()).pathname.startsWith("/v1/")
    )
      writes.push(request.url());
  });
  await page.route("**/.well-known/openid-configuration", async (route) => {
    const origin = new URL(page.url()).origin;
    await route.fulfill({
      json: {
        authorization_endpoint: `${origin}/__test-oidc/authorize`,
        token_endpoint: `${origin}/__test-oidc/token`,
      },
    });
  });
  await page.route("**/__test-oidc/authorize?**", async (route) => {
    const query = new URL(route.request().url()).searchParams;
    const redirect = new URL(query.get("redirect_uri")!);
    redirect.searchParams.set("code", "presentation-test");
    redirect.searchParams.set("state", query.get("state")!);
    await route.fulfill({
      status: 302,
      headers: { location: redirect.toString() },
    });
  });
  await page.route("**/__test-oidc/token", (route) =>
    route.fulfill({
      json: {
        access_token: `test.${Buffer.from(JSON.stringify({ name: "UI contract reader" })).toString("base64url")}.test`,
        expires_in: 3600,
      },
    }),
  );
  await page.route("**/v1/dashboard", (route) => route.fulfill({ json: data }));
  await page.goto("/");
  await page.getByRole("button", { name: "Sign in to your workspace" }).click();
  await expect(
    page.getByRole("heading", { name: "Cost operations overview." }),
  ).toBeVisible();
  return writes;
}

test("trusted source and collector gaps remain visible without implying zero spend", async ({
  page,
}) => {
  const data = dashboard();
  data.source_connections = [
    {
      id: "source-v3",
      version: 2,
      kind: "AWS_CUR2",
      payer_account_id: "111122223333",
      usage_account_ids: ["111122223333"],
      region: "eu-west-1",
      export_arn: "arn:aws:bcm-data-exports:us-east-1:111122223333:export/cur",
      read_role_binding_id: "approved-read",
      bucket: "regional-cur-evidence",
      bucket_owner: "111122223333",
      prefix: "cur/",
      enabled: true,
      status: "DEGRADED",
      reason_code: "SOURCE_MANIFEST_FILES_REQUIRED",
    },
  ];
  data.activity_sources = [
    {
      id: "collector-v3",
      version: 1,
      resource_id: "resource-ui",
      subject: "independent-machine",
      status: "UNKNOWN",
      reason_code: "ACTIVITY_COVERAGE_GAP",
    },
  ];
  data.readiness![0].status = "BLOCKED";
  data.readiness![0].pre_execution_ready = false;
  data.readiness![0].reason_code = "WORKLOAD_EVIDENCE_MISSING";
  const writes = await openContract(page, data);
  await page.getByRole("link", { name: "Connections & quality" }).click();
  await expect(
    page.getByRole("heading", { name: "Trusted billing sources" }),
  ).toBeVisible();
  await expect(
    page.getByText("Source manifest files required", { exact: true }),
  ).toBeVisible();
  await expect(
    page.getByText("Activity coverage gap", { exact: true }),
  ).toBeVisible();
  await page.getByRole("button", { name: "Register billing source" }).click();
  const dialog = page.getByRole("dialog", {
    name: "Register trusted billing source",
  });
  await expect(dialog.getByLabel("Approved read binding ID")).toBeVisible();
  await expect(dialog.getByLabel("Versioned delivery bucket")).toBeVisible();
  await dialog.getByRole("button", { name: "Cancel", exact: true }).click();
  expect(writes).toEqual([]);
});

test("a ready baseline permits plan creation while savings are still measuring", async ({
  page,
}) => {
  const data = dashboard();
  data.savings.push({
    id: "legacy-saving",
    version: 1,
    execution_id: "legacy-execution",
    status: "VERIFIED",
    verified_saving: "999999.000000000000",
    expected_baseline_cost: "1000000.000000000000",
    actual_cost: "1.000000000000",
    currency: "GBP",
  });
  const writes = await openContract(page, data);
  const verifiedMetric = page
    .locator(".metric")
    .filter({ hasText: "Verified period savings" });
  await expect(verifiedMetric).toContainText("Unavailable");
  await page
    .getByRole("link", { name: "Recommendations", exact: false })
    .click();
  const recommendation = page.locator(".recommendation-card");
  await expect(recommendation).toContainText("Ready to execute");
  await expect(recommendation).toContainText("Measuring");
  await expect(
    recommendation.getByRole("button", { name: "Create change plan" }),
  ).toBeEnabled();
  await recommendation
    .getByRole("button", { name: "Create change plan" })
    .click();
  const plan = page.getByRole("dialog", {
    name: "Create immutable change plan",
  });
  await expect(plan.getByText("baseline-v2", { exact: true })).toBeVisible();
  await expect(plan).toContainText("Savings remain measuring");
  await plan.getByRole("checkbox").check();
  await expect(
    plan.getByRole("button", { name: "Create signed plan" }),
  ).toBeEnabled();
  await plan.getByRole("button", { name: "Close dialog" }).click();
  await page.getByRole("link", { name: "Savings evidence" }).click();
  await expect(page.getByRole("table")).toContainText("Measuring");
  await expect(page.getByRole("table")).not.toContainText(
    "Verified measurement period",
  );
  await expect(page.getByRole("table")).toContainText(
    "Legacy / unbound history",
  );
  await page.getByRole("button", { name: "Inspect saving-ui" }).click();
  await expect(page.getByRole("dialog")).toContainText("measurement-v2");
  expect(writes).toEqual([]);
});

test("baseline blockers and legacy missing flags remain non-actionable despite VALIDATED status", async ({
  page,
}) => {
  const data = dashboard();
  data.recommendations[0].pre_execution_ready = false;
  data.recommendations[0].baseline_id = null;
  data.recommendations[0].reason_code = "BASELINE_WINDOW_INCOMPLETE";
  data.readiness![0].pre_execution_ready = false;
  data.readiness![0].status = "BLOCKED";
  data.change_plans.push({
    id: "legacy-plan",
    version: 1,
    resource_id: "resource-ui",
    recommendation_id: "recommendation-ui",
    schedule_id: "",
    status: "APPROVED",
    risk_class: "R1",
    operations: [],
    expires_at: "2026-10-18T12:00:00Z",
    payload: { schema_version: "1" },
  });
  const writes = await openContract(page, data);
  await page.getByRole("link", { name: "Recommendations" }).click();
  await expect(page.locator(".recommendation-card")).toContainText("Validated");
  await expect(page.locator(".recommendation-card")).toContainText(
    "Execution blocked",
  );
  await expect(
    page.getByRole("button", { name: "Create change plan" }),
  ).toBeDisabled();
  delete data.recommendations[0].pre_execution_ready;
  data.readiness![0].pre_execution_ready = true;
  data.readiness![0].status = "READY";
  await page.getByRole("button", { name: "Refresh data" }).click();
  await expect(
    page.getByRole("button", { name: "Create change plan" }),
  ).toBeDisabled();
  await page.getByRole("link", { name: "Schedules & policies" }).click();
  await expect(
    page.getByRole("button", { name: "Execute approved plan" }),
  ).toBeDisabled();
  expect(writes).toEqual([]);
});

test("unknown live costs stay unavailable in inventory, estimates, and totals", async ({
  page,
}) => {
  const data = dashboard();
  data.resources[0].hourly_effective_cost = null;
  data.resources[0].monthly_effective_cost = null;
  data.resources[0].currency = null;
  data.recommendations[0].monthly_saving = null;
  data.recommendations[0].annual_saving = null;
  data.recommendations[0].currency = null;
  data.recommendations[0].pre_execution_ready = false;
  data.recommendations[0].reason_code = "PRICING_EVIDENCE_UNAVAILABLE";
  data.readiness![0].pre_execution_ready = false;
  data.readiness![0].status = "BLOCKED";
  const writes = await openContract(page, data);
  await expect(
    page.locator(".metric").filter({ hasText: "Monthly opportunity" }),
  ).toContainText("Unavailable");
  await expect(
    page.getByText("FIXTURE MODE", { exact: true }),
  ).not.toBeVisible();
  await page.getByRole("link", { name: "Workloads & resources" }).click();
  const resource = page.getByRole("row").filter({ hasText: "dev-api-ready" });
  await expect(resource).toContainText("Unavailable");
  await expect(resource).not.toContainText("£0.00");
  await page.getByRole("link", { name: "Recommendations" }).click();
  const recommendation = page.locator(".recommendation-card");
  await expect(recommendation.locator(".recommendation-value")).toContainText(
    "Unavailable",
  );
  await expect(recommendation).not.toContainText("£0.00");
  await expect(
    page.getByRole("button", { name: "Create change plan" }),
  ).toBeDisabled();
  expect(writes).toEqual([]);
});

test("verified totals preserve negative results while excluding legacy and superseded history", async ({
  page,
}) => {
  const data = dashboard();
  data.savings = [
    {
      ...data.savings[0],
      id: "legacy-usd",
      status: "VERIFIED",
      baseline_id: null,
      measurement_id: null,
      verified_saving: "900000.000000000000",
      currency: "USD",
    },
    {
      ...data.savings[0],
      id: "old-gbp-claim",
      status: "VERIFIED",
      verified_saving: "144.000000000000",
      is_current: false,
    },
    {
      ...data.savings[0],
      id: "current-gbp-claim",
      status: "VERIFIED",
      verification_status: "VERIFIED",
      verified_saving: "-5.160000000000",
      actual_cost: "72.360000000000",
      supersedes_id: "old-gbp-claim",
    },
  ];
  const writes = await openContract(page, data);
  await expect(
    page.locator(".metric").filter({ hasText: "Verified period savings" }),
  ).toContainText("-£5.16");
  await page.getByRole("link", { name: "Savings evidence" }).click();
  await expect(
    page
      .locator(".metric")
      .filter({ hasText: "Verified period savings · GBP" }),
  ).toContainText("-£5.16");
  await expect(
    page
      .locator(".metric")
      .filter({ hasText: "Verified period savings · USD" }),
  ).toContainText("Unavailable");
  await expect(page.getByRole("table")).toContainText(
    "Superseded · retained history",
  );
  await expect(page.getByRole("table")).toContainText(
    "Legacy / unbound history",
  );
  expect(writes).toEqual([]);
});
