import { test, expect, type Browser, type Page } from "@playwright/test";
import type { components } from "../src/api.generated";

async function signIn(page: Page, username: string) {
  await page.goto("/");
  await page.getByRole("button", { name: "Sign in to your workspace" }).click();
  await page.getByRole("textbox", { name: /username/i }).fill(username);
  await page
    .getByLabel("Password", { exact: true })
    .fill(process.env.FINOPS_E2E_PASSWORD || "local-pilot-demo");
  const [response] = await Promise.all([
    page.waitForResponse(
      (response) => response.url().endsWith("/v1/dashboard") && response.ok(),
    ),
    page.getByRole("button", { name: "Sign In", exact: true }).click(),
  ]);
  expect(
    (await response.json()).fixture,
    "Allocation browser acceptance is restricted to the local deterministic fixture stack.",
  ).toBe(true);
  const authorization = response.request().headers().authorization;
  expect(authorization).toMatch(/^Bearer /);
  return authorization;
}

async function isolatedLogin(browser: Browser, user: string) {
  const context = await browser.newContext();
  const page = await context.newPage();
  return { context, page, authorization: await signIn(page, user) };
}

test("real OIDC allocation policy and persisted fixture report preserve evidence pagination and financial tenant scope", async ({
  page,
  browser,
}) => {
  test.setTimeout(240_000);
  const errors: string[] = [];
  page.on("pageerror", (error) => errors.push(error.message));
  await signIn(page, process.env.FINOPS_E2E_USER || "owner");
  await page
    .getByRole("link", { name: "Cost allocation", exact: true })
    .click();
  await page
    .getByRole("button", { name: /^(Create|Revise) allocation policy$/ })
    .click();
  const editor = page.getByRole("dialog", {
    name: "Save allocation policy revision",
  });
  await editor
    .getByLabel("Allocation policy name")
    .fill(`Browser observed ownership ${Date.now()}`);
  const existingRules = editor.getByRole("button", {
    name: /^Remove rule \d+$/,
  });
  while (await existingRules.count()) await existingRules.last().click();
  const policyResponse = page.waitForResponse(
    (response) =>
      response.url().endsWith("/v1/allocation-policies") &&
      response.request().method() === "POST",
  );
  await editor
    .getByRole("button", { name: "Save policy revision", exact: true })
    .click();
  const savedPolicy = await policyResponse;
  expect(savedPolicy.status()).toBe(201);
  const policy =
    (await savedPolicy.json()) as components["schemas"]["AllocationPolicy"];
  expect(policy.definition.rules).toEqual([]);
  expect(savedPolicy.request().headers()["if-match"]).toBe(
    `"${policy.version - 1}"`,
  );
  await expect(editor).not.toBeVisible();

  await page
    .getByRole("button", { name: "Create allocation report", exact: true })
    .click();
  const creator = page.getByRole("dialog", {
    name: "Create allocation report",
  });
  const imports = creator.getByLabel("Persisted allocation import");
  await expect(imports).toBeVisible();
  const jobID = await imports
    .locator("option:not([disabled])")
    .evaluateAll((options) =>
      options
        .map((option) => (option as HTMLOptionElement).value)
        .find(Boolean),
    );
  expect(
    jobID,
    "An actual PERSISTED fixture billing job is required; no caller billing payload is manufactured.",
  ).toBeTruthy();
  await imports.selectOption(jobID!);
  const reportResponse = page.waitForResponse(
    (response) =>
      response.url().endsWith("/v1/allocation-reports") &&
      response.request().method() === "POST",
  );
  await creator.getByRole("button", { name: "Seal allocation report" }).click();
  const sealed = await reportResponse;
  expect(sealed.status()).toBe(201);
  expect(sealed.request().postDataJSON()).toEqual({
    policy_id: policy.id,
    source: { kind: "CUSTOMER_IMPORT", ingestion_job_id: jobID },
  });
  expect(sealed.request().headers()["if-match"]).toBe(`"${policy.version}"`);
  const report =
    (await sealed.json()) as components["schemas"]["AllocationReport"];
  expect(report.source.kind).toBe("DETERMINISTIC_FIXTURE");
  expect(report.source.coverage).toBe("UNKNOWN");
  expect(report.execution_authorized).toBe(false);
  expect(report.verified_saving).toBeNull();
  expect(report.basis).toBe("CURRENT_OWNERSHIP_VIEW");
  expect(report.record_count).toBeGreaterThan(20);
  const details = page.getByRole("dialog", {
    name: "Allocation report evidence",
  });
  await expect(
    details.getByText("FIXTURE DATA", { exact: true }),
  ).toBeVisible();
  await expect(details).toContainText("Coverage: Unknown · finality: Unproven");
  await expect(details).toContainText(report.source.ingestion_job_id);
  const entries = details.getByRole("region", {
    name: "Scrollable derived allocation entries",
  });
  await expect(entries.getByRole("row")).toHaveCount(21);
  const linesResponse = page.waitForResponse(
    (response) =>
      response.url().includes(`/v1/allocation-reports/${report.id}/lines?`) &&
      response.url().includes("cursor=") &&
      response.ok(),
  );
  await details
    .getByRole("button", { name: "Load more allocation entries", exact: true })
    .click();
  await linesResponse;
  await expect(entries.getByRole("row")).toHaveCount(41);
  const observations = details.getByRole("region", {
    name: "Scrollable original billing observations",
  });
  await expect(observations.getByRole("row")).toHaveCount(21);
  await details
    .getByRole("button", {
      name: "Load more billing observations",
      exact: true,
    })
    .click();
  await expect(observations.getByRole("row")).toHaveCount(41);
  await details.getByRole("button", { name: "Close dialog" }).click();
  await page.evaluate(() => window.scrollTo(0, 0));
  await page.screenshot({
    path: "test-results/allocation-desktop.png",
    fullPage: true,
    animations: "disabled",
  });
  await page.setViewportSize({ width: 390, height: 844 });
  await page.evaluate(() => window.scrollTo(0, 0));
  await page.screenshot({
    path: "test-results/allocation-mobile.png",
    fullPage: true,
    animations: "disabled",
  });
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= window.innerWidth,
    ),
  ).toBe(true);
  expect(errors).toEqual([]);

  const foreign = await isolatedLogin(browser, "other");
  try {
    const denied = await foreign.page.request.get(
      `/v1/allocation-reports/${report.id}`,
      { headers: { Authorization: foreign.authorization } },
    );
    expect(denied.status()).toBe(404);
    expect(JSON.stringify(await denied.json())).not.toContain(
      report.input_hash,
    );
    const linesDenied = await foreign.page.request.get(
      `/v1/allocation-reports/${report.id}/lines?limit=20`,
      { headers: { Authorization: foreign.authorization } },
    );
    expect(linesDenied.status()).toBe(404);
  } finally {
    await foreign.context.close();
  }
  const viewer = await isolatedLogin(browser, "viewer");
  try {
    await viewer.page
      .getByRole("link", { name: "Cost allocation", exact: true })
      .click();
    await expect(
      viewer.page.getByRole("heading", { name: "Financial scope unavailable" }),
    ).toBeVisible();
    await expect(
      viewer.page.getByRole("button", {
        name: "Create allocation report",
        exact: true,
      }),
    ).not.toBeVisible();
    const deniedWrite = await viewer.page.request.post(
      "/v1/allocation-reports",
      {
        headers: {
          Authorization: viewer.authorization,
          "Idempotency-Key": crypto.randomUUID(),
          "If-Match": `"${policy.version}"`,
        },
        data: {
          policy_id: policy.id,
          source: { kind: "CUSTOMER_IMPORT", ingestion_job_id: jobID },
        },
      },
    );
    expect(deniedWrite.status()).toBe(403);
  } finally {
    await viewer.context.close();
  }
});
