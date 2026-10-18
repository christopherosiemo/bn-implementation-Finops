import { expect, test } from "@playwright/test";

test("OIDC sign-in and the complete fixture operating loop", async ({
  page,
}) => {
  test.setTimeout(240_000);
  const javascriptErrors: string[] = [];
  page.on("pageerror", (error) => javascriptErrors.push(error.message));
  await page.goto("/");
  const dashboardResponse = page.waitForResponse(
    (response) => response.url().endsWith("/v1/dashboard") && response.ok(),
  );
  await page.getByRole("button", { name: "Sign in to your workspace" }).click();
  await page
    .getByRole("textbox", { name: /username/i })
    .fill(process.env.FINOPS_E2E_USER || "owner");
  await page
    .getByLabel("Password", { exact: true })
    .fill(process.env.FINOPS_E2E_PASSWORD || "local-pilot-demo");
  await page.getByRole("button", { name: "Sign In", exact: true }).click();
  const response = await dashboardResponse;
  const authorization = response.request().headers()["authorization"];
  expect(authorization).toMatch(/^Bearer /);
  await expect(
    page.getByRole("heading", { name: "Cost operations overview." }),
  ).toBeVisible();
  await expect(page.getByText("FIXTURE MODE", { exact: true })).toBeVisible();
  const reset = await page.request.post("/v1/demo/reset", {
    headers: {
      Authorization: authorization,
      "Idempotency-Key": crypto.randomUUID(),
    },
    data: {},
  });
  expect(reset.ok()).toBeTruthy();
  await page.getByRole("button", { name: "Refresh data" }).click();

  await page.getByRole("link", { name: "Connections & quality" }).click();
  await page
    .getByRole("button", { name: "Connect AWS account", exact: true })
    .click();
  const connect = page.getByRole("dialog", { name: "Connect an AWS account" });
  await connect.getByLabel("Connection name").fill("Acceptance sandbox");
  await connect.getByLabel("AWS account ID").fill("555566667777");
  await connect.getByRole("button", { name: "Connect & discover" }).click();
  await expect(connect).not.toBeVisible();
  await expect(
    page.getByText("Acceptance sandbox", { exact: true }),
  ).toBeVisible();

  await page.getByRole("link", { name: "Workloads & resources" }).click();
  await expect(
    page.getByRole("heading", { name: "Know what you run." }),
  ).toBeVisible();
  const inventory = page.getByRole("table").filter({
    has: page.getByRole("columnheader", {
      name: "Monthly compute",
      exact: true,
    }),
  });
  await expect(
    inventory.getByRole("cell").filter({
      has: page.getByText("dev-api-01", { exact: true }),
    }),
  ).toBeVisible();
  const workload = page.locator(".workload-card").filter({
    has: page.getByRole("heading", {
      name: "Developer API sandbox",
      exact: true,
    }),
  });
  await workload.getByRole("button", { name: "Update signals" }).click();
  const signals = page.getByRole("dialog", { name: "Update workload signals" });
  for (const label of ["Incident", "Deployment", "Job"])
    await signals.getByLabel(label, { exact: true }).selectOption("CLEAR");
  await signals.getByRole("button", { name: "Publish signals" }).click();
  await expect(signals).not.toBeVisible();

  await page.getByRole("link", { name: "Recommendations" }).click();
  await expect
    .poll(
      async () => {
        const generated = page.waitForResponse(
          (response) =>
            response.url().endsWith("/v1/recommendations") &&
            response.request().method() === "POST" &&
            response.ok(),
        );
        await page
          .getByRole("button", { name: "Generate recommendations" })
          .click();
        const body = (await (await generated).json()) as {
          recommendations?: {
            pre_execution_ready?: boolean;
            verification_status?: string;
            baseline_id?: string;
          }[];
        };
        return body.recommendations?.some(
          (row) =>
            row.pre_execution_ready === true &&
            row.verification_status === "MEASURING" &&
            row.baseline_id,
        );
      },
      {
        timeout: 60_000,
        intervals: [1000, 2000, 4000],
        message:
          "ordinary fixture ingestion seals a valid baseline before new plans become actionable",
      },
    )
    .toBeTruthy();
  await page
    .getByRole("button", { name: "Create change plan" })
    .and(page.locator(":enabled"))
    .click();
  const plan = page.getByRole("dialog", {
    name: "Create immutable change plan",
  });
  await plan.screenshot({
    path: "test-results/readiness-plan-desktop.png",
    animations: "disabled",
  });
  await expect(
    plan.getByRole("button", { name: "Create signed plan" }),
  ).toBeDisabled();
  await plan.getByRole("checkbox").check();
  const planResponse = page.waitForResponse(
    (response) =>
      response.url().endsWith("/v1/change-plans") &&
      response.request().method() === "POST" &&
      response.ok(),
  );
  await plan.getByRole("button", { name: "Create signed plan" }).click();
  const createdPlan = (await (await planResponse).json()) as { id: string };
  await expect(
    page.getByRole("heading", { name: "Set the right rhythm." }),
  ).toBeVisible();
  const planRow = page.getByRole("row").filter({
    has: page.getByRole("button", {
      name: `Inspect ${createdPlan.id}`,
      exact: true,
    }),
  });
  await planRow.getByRole("button", { name: "Review & approve" }).click();
  const approval = page.getByRole("dialog", {
    name: "Review & approve change plan",
  });
  await approval.getByRole("checkbox").check();
  await approval.getByRole("button", { name: "Approve plan" }).click();
  await expect(approval).not.toBeVisible();
  const executionResponse = page.waitForResponse(
    (response) =>
      response.url().endsWith("/v1/executions") &&
      response.request().method() === "POST" &&
      response.ok(),
  );
  await planRow.getByRole("button", { name: "Execute approved plan" }).click();
  const execution = (await (await executionResponse).json()) as { id: string };
  await expect(
    page.getByRole("heading", { name: "Every change, in view." }),
  ).toBeVisible();
  const executionCard = page.locator(".execution-card").filter({
    has: page.getByRole("button", {
      name: `Inspect ${execution.id}`,
      exact: true,
    }),
  });
  await expect(
    executionCard.getByText("Execution completed · evidence retained", {
      exact: true,
    }),
  ).toBeVisible({ timeout: 90_000 });

  await page
    .getByRole("button", { name: "Pause new stops", exact: true })
    .click();
  await expect(
    page.getByText(
      "New stops are paused across this workspace. Owned restoration and health checks continue.",
    ),
  ).toBeVisible();
  await page
    .getByRole("button", { name: "Resume new stops", exact: true })
    .click();
  await expect(
    page.getByRole("button", { name: "Pause new stops", exact: true }),
  ).toBeVisible();

  await page.getByRole("link", { name: "Savings evidence" }).click();
  await expect(
    page.getByText("Fixture financial clock · logical time", { exact: true }),
  ).toBeVisible();
  let verifiedSavingId = "";
  await expect
    .poll(
      async () => {
        const result = page.waitForResponse(
          (response) =>
            response.url().endsWith("/v1/savings/verify") &&
            response.request().method() === "POST" &&
            response.ok(),
        );
        await page
          .getByRole("button", { name: "Verify savings", exact: true })
          .click();
        const body = (await (await result).json()) as {
          savings?: {
            id: string;
            execution_id: string;
            status: string;
            baseline_id?: string;
            measurement_id?: string;
          }[];
        };
        const verified = body.savings?.find(
          (row) =>
            row.execution_id === execution.id &&
            row.status === "VERIFIED" &&
            row.baseline_id &&
            row.measurement_id,
        );
        verifiedSavingId = verified?.id || "";
        return Boolean(verified);
      },
      {
        timeout: 120_000,
        intervals: [1000, 2000, 4000],
        message:
          "the actual cycle receives a sealed post-activation measurement before claiming verified savings",
      },
    )
    .toBeTruthy();
  await expect(page.getByRole("table")).toBeVisible();
  const verifiedRow = page.getByRole("row").filter({
    has: page.getByRole("button", {
      name: `Inspect ${verifiedSavingId}`,
      exact: true,
    }),
  });
  await expect(verifiedRow).toContainText("Verified measurement period");
  await page.screenshot({
    path: "test-results/savings-desktop.png",
    fullPage: true,
    animations: "disabled",
  });
  await page.getByRole("link", { name: "Audit trail", exact: true }).click();
  await expect(
    page.getByRole("heading", { name: "An unbroken trail." }),
  ).toBeVisible();
  const auditRefresh = page.waitForResponse(
    (response) => response.url().endsWith("/v1/dashboard") && response.ok(),
  );
  await page.getByRole("button", { name: "Refresh data" }).click();
  const auditData = (await (await auditRefresh).json()) as {
    audit: { id: string; action: string; resource: string }[];
  };
  const approvalAudit = auditData.audit.find(
    (item) =>
      item.action === "approval.completed" && item.resource === createdPlan.id,
  );
  expect(approvalAudit).toBeDefined();
  const approvalRow = page.getByRole("row").filter({
    has: page.getByRole("button", {
      name: `Inspect ${approvalAudit!.id}`,
      exact: true,
    }),
  });
  await expect(approvalRow).toContainText("Approval.completed");
  const download = page.waitForEvent("download");
  await page.getByRole("button", { name: "Export visible records" }).click();
  expect((await download).suggestedFilename()).toMatch(/^finops-audit-/);
  await page.getByRole("link", { name: "Overview", exact: true }).click();
  const notification = page.getByRole("button", {
    name: "Dismiss notification",
  });
  if (await notification.isVisible()) await notification.click();
  await page.screenshot({
    path: "test-results/overview-desktop.png",
    fullPage: true,
    animations: "disabled",
  });
  await page.setViewportSize({ width: 390, height: 844 });
  await expect(
    page.getByRole("link", { name: "Overview", exact: true }),
  ).not.toBeInViewport();
  await page.screenshot({
    path: "test-results/overview-mobile.png",
    fullPage: true,
    animations: "disabled",
  });
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= window.innerWidth,
    ),
  ).toBeTruthy();
  await page.getByRole("button", { name: "Open navigation" }).click();
  await page.getByRole("link", { name: "Savings evidence" }).click();
  await expect(
    page.getByRole("heading", { name: "Savings you can stand behind." }),
  ).toBeVisible();
  expect(javascriptErrors).toEqual([]);
});
