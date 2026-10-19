import { expect, test, type Browser, type Page } from "@playwright/test";
import type { components } from "../src/api.generated";
import type {
  Dashboard,
  FleetDemandDefinition,
  FleetHistoryRegistration,
  FleetHistoryScope,
} from "../src/types";

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
  const dashboard = (await response.json()) as Dashboard;
  expect(
    dashboard.fixture,
    "Connected history acceptance runs only against the deterministic local stack.",
  ).toBe(true);
  const authorization = response.request().headers().authorization;
  expect(Boolean(authorization?.startsWith("Bearer "))).toBe(true);
  return { dashboard, authorization };
}
async function otherSession(browser: Browser, user: string) {
  const context = await browser.newContext();
  const page = await context.newPage();
  return { context, page, ...(await signIn(page, user)) };
}

test("real OIDC fleet history registration and independent Completed declaration produce a persisted blocked scope without fabricated observations", async ({
  page,
  browser,
}) => {
  test.setTimeout(240_000);
  const errors: string[] = [];
  page.on("pageerror", (error) => errors.push(error.message));
  const { dashboard, authorization } = await signIn(
    page,
    process.env.FINOPS_E2E_USER || "owner",
  );
  const workload = dashboard.workloads.find((row) => row.id === "workload-dev");
  expect(
    workload,
    "The existing real fixture onboarding must provide the owned development workload.",
  ).toBeTruthy();
  const activity = dashboard.activity_sources?.find(
    (row) =>
      row.enabled === true &&
      row.workload_id === workload!.id &&
      row.region === "eu-west-1",
  );
  expect(
    activity,
    "Reuse a registered independent collector; the browser must not manufacture receipt evidence.",
  ).toBeTruthy();
  const account = String(activity!.account_id);
  let source = dashboard.source_connections?.find(
    (row) =>
      row.kind === "AWS_CUR2" &&
      row.enabled === true &&
      row.region === "eu-west-1" &&
      (row.payer_account_id === account ||
        row.usage_account_ids.includes(account)),
  );
  if (!source) {
    // These are the public deterministic fixture registration coordinates from
    // source.FixtureRegistration. Registration publishes no native receipt;
    // deliberately do not synchronize or manufacture membership/history.
    expect(account).toBe("111122223333");
    await page
      .getByRole("link", { name: "Connections & quality", exact: true })
      .click();
    await page
      .getByRole("button", { name: "Register billing source", exact: true })
      .click();
    const setup = page.getByRole("dialog", {
      name: "Register trusted billing source",
      exact: true,
    });
    for (const [label, value] of Object.entries({
      "Payer account ID": account,
      "Usage account IDs (comma separated)": account,
      "CUR 2.0 export ARN": `arn:aws:bcm-data-exports:us-east-1:${account}:export/fixture-export`,
      "Approved read binding ID": "fixture-payer",
      "Versioned delivery bucket": "finops-fixture-cur2",
      "Bucket owner account ID": account,
      "Delivery prefix": "cur/",
    }))
      await setup.getByLabel(label, { exact: true }).fill(value);
    const sourceResponse = page.waitForResponse(
      (response) =>
        response.url().endsWith("/v1/source-connections") &&
        response.request().method() === "POST",
    );
    await setup
      .getByRole("button", { name: "Register source", exact: true })
      .click();
    const registeredSource = await sourceResponse;
    expect(registeredSource.status()).toBe(201);
    source = (await registeredSource.json()) as NonNullable<
      Dashboard["source_connections"]
    >[number];
    expect(source.enabled).toBe(true);
    expect(source.status).toBe("REGISTERED");
    await expect(setup).not.toBeVisible();
  }
  expect(
    source,
    "An enabled approved AWS read source is required; no credentials or native observation payloads are supplied by this journey.",
  ).toBeTruthy();
  const fleet = `browser-history-${Date.now()}`;
  const asg = `arn:aws:autoscaling:eu-west-1:${account}:autoScalingGroup:12345678-1234-1234-1234-123456789abc:autoScalingGroupName/${fleet}`;
  await page
    .getByRole("link", { name: "Workloads & resources", exact: true })
    .click();
  await page
    .getByRole("combobox", { name: "Fleet history workload", exact: true })
    .selectOption(workload!.id);
  await page
    .getByRole("button", { name: "Register fleet history", exact: true })
    .click();
  const editor = page.getByRole("dialog", {
    name: "Register fleet history",
    exact: true,
  });
  await editor.getByLabel("Fleet identifier", { exact: true }).fill(fleet);
  await editor.getByLabel("Exact ASG ARN", { exact: true }).fill(asg);
  await editor
    .getByLabel("Approved AWS source connection")
    .selectOption(source!.id);
  const registeredResponse = page.waitForResponse(
    (response) =>
      response.url().endsWith("/v1/fleet-history-registrations") &&
      response.request().method() === "POST",
  );
  await editor
    .getByRole("button", { name: "Save fleet registration", exact: true })
    .click();
  const registered = await registeredResponse;
  expect(registered.status()).toBe(201);
  expect(registered.request().headers()["if-match"]).toBe('"0"');
  const registration = (await registered.json()) as FleetHistoryRegistration;
  expect(registration.registration.binding.workload_id).toBe(workload!.id);
  expect(registration.registration.asg_arn).toBe(asg);
  expect(registration.registration.source_config_hash).toMatch(
    /^[a-f0-9]{64}$/,
  );
  expect(registered.request().postDataJSON()).toEqual({
    workload_id: workload!.id,
    fleet_id: fleet,
    asg_arn: asg,
    source_connection_id: source!.id,
    cadence_seconds: 60,
    max_gap_seconds: 120,
  });
  let dialog = page.getByRole("dialog", {
    name: "Fleet history evidence",
    exact: true,
  });
  await expect(dialog).toContainText(
    "No native membership point has been published",
  );
  await dialog
    .getByRole("button", {
      name: "Declare completed-work definition",
      exact: true,
    })
    .click();
  const definitionEditor = page.getByRole("dialog", {
    name: "Declare completed-work definition",
    exact: true,
  });
  await definitionEditor
    .getByRole("combobox", {
      name: "Independent completed-work source",
      exact: true,
    })
    .selectOption(activity!.id);
  await definitionEditor
    .getByLabel("Completed business operation")
    .fill("Fixture operations completed — declared meaning");
  await definitionEditor
    .getByLabel("Semantic contract ID", { exact: true })
    .fill(`fixture-declaration-${fleet}`);
  const declaredHash = "b".repeat(64);
  await definitionEditor
    .getByLabel("Declared semantic contract SHA-256")
    .fill(declaredHash);
  const definedResponse = page.waitForResponse(
    (response) =>
      response.url().endsWith("/v1/fleet-demand-definitions") &&
      response.request().method() === "POST",
  );
  await definitionEditor
    .getByRole("button", {
      name: "Save completed-work definition",
      exact: true,
    })
    .click();
  const defined = await definedResponse;
  expect(defined.status()).toBe(201);
  const definition = (await defined.json()) as FleetDemandDefinition;
  expect(definition.definition.metric).toBe("activity.Completed");
  expect(definition.definition.value_field).toBe("COMPLETED");
  expect(definition.definition.temporality).toBe("DELTA");
  expect(definition.definition.source_system).toBe("ACTIVITY_SOURCE");
  expect("source_registration_version" in definition.definition).toBe(false);
  expect(defined.request().headers()["if-match"]).toBe('"0"');
  expect(Object.keys(defined.request().postDataJSON()).sort()).toEqual([
    "activity_source_id",
    "business_operation",
    "registration_id",
    "semantic_contract_hash",
    "semantic_contract_id",
  ]);
  dialog = page.getByRole("dialog", {
    name: "Fleet history evidence",
    exact: true,
  });
  const capturedResponse = page.waitForResponse(
    (response) =>
      response.url().endsWith("/v1/fleet-history-scopes") &&
      response.request().method() === "POST",
  );
  await dialog
    .getByRole("button", {
      name: "Capture scope for Fixture operations completed — declared meaning",
      exact: true,
    })
    .click();
  const captured = await capturedResponse;
  expect(captured.status()).toBe(201);
  expect(captured.request().postDataJSON()).toEqual({
    registration_id: registration.id,
    definition_id: definition.id,
    definition_version: definition.version,
  });
  expect(captured.request().headers()["if-match"]).toBe(
    `"${registration.version}"`,
  );
  const scope = (await captured.json()) as FleetHistoryScope;
  expect(scope.status).toBe("BLOCKED");
  expect(scope.membership_status).toBe("INTERVAL_OWNERSHIP_UNPROVEN");
  expect(Date.parse(scope.end) - Date.parse(scope.start)).toBe(14 * 86400000);
  expect(scope.end).toMatch(/T00:00:00Z$/);
  expect(scope.demand.window_units).toBeNull();
  expect(scope.demand.meaning_basis).toBe("DECLARED_COMPLETED_WORK_SEMANTICS");
  expect(scope.observation_count).toBe(0);
  expect("verified_saving" in scope || "execution_authorized" in scope).toBe(
    false,
  );
  const evidence = dialog.getByRole("region", {
    name: `Immutable fleet history scope ${scope.id}`,
    exact: true,
  });
  await expect(evidence).toContainText(
    "Historical membership interval ownership is unproven",
  );
  await expect(
    evidence.locator("dl > div").filter({ hasText: "Complete-window total" }),
  ).toContainText("Unavailable");
  await expect(evidence).toContainText(scope.reference_root);
  await expect(
    dialog.getByRole("button", { name: /approve|execute|verify savings/i }),
  ).toHaveCount(0);

  // Exercise real opaque reference pagination independently of its compact UI
  // preview; no observation, historical receipt or completeness is manufactured.
  const ids: string[] = [];
  let cursor: string | null = null;
  do {
    const response = await page.request.get(
      `/v1/fleet-history-scopes/${scope.id}/references?limit=1${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ""}`,
      { headers: { Authorization: authorization } },
    );
    expect(response.status()).toBe(200);
    const body =
      (await response.json()) as components["schemas"]["FleetHistoryReferencePage"];
    ids.push(
      ...body.items.map((ref) => `${ref.ordinal}:${ref.kind}:${ref.id}`),
    );
    expect(body.next_cursor === null || body.next_cursor !== cursor).toBe(true);
    cursor = body.next_cursor;
    expect(ids.length).toBeLessThanOrEqual(scope.reference_count);
  } while (cursor);
  expect(ids).toHaveLength(scope.reference_count);
  expect(new Set(ids).size).toBe(ids.length);
  const persisted = await page.request.get(
    `/v1/fleet-history-scopes/${scope.id}`,
    { headers: { Authorization: authorization } },
  );
  expect(await persisted.json()).toEqual(scope);
  await page.screenshot({
    path: "test-results/fleet-history-evidence-desktop.png",
    fullPage: true,
    animations: "disabled",
  });
  await dialog.getByRole("button", { name: "Close dialog" }).click();
  await page.evaluate(() => window.scrollTo(0, 0));
  await page.screenshot({
    path: "test-results/fleet-history-desktop.png",
    fullPage: true,
    animations: "disabled",
  });
  await page.setViewportSize({ width: 390, height: 844 });
  await page.evaluate(() => window.scrollTo(0, 0));
  await page.screenshot({
    path: "test-results/fleet-history-mobile.png",
    fullPage: true,
    animations: "disabled",
  });
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= innerWidth,
    ),
  ).toBe(true);
  expect(errors).toEqual([]);

  const foreign = await otherSession(browser, "other");
  try {
    for (const path of [
      `/fleet-history-registrations/${registration.id}`,
      `/fleet-demand-definitions/${definition.id}`,
      `/fleet-history-scopes/${scope.id}`,
      `/fleet-history-scopes/${scope.id}/references?limit=1`,
    ]) {
      const response = await foreign.page.request.get(`/v1${path}`, {
        headers: { Authorization: foreign.authorization },
      });
      expect(response.status()).toBe(404);
      expect(JSON.stringify(await response.json())).not.toContain(
        scope.input_hash,
      );
    }
  } finally {
    await foreign.context.close();
  }
  const viewer = await otherSession(browser, "viewer");
  try {
    const response = await viewer.page.request.post(
      "/v1/fleet-history-scopes",
      {
        headers: {
          Authorization: viewer.authorization,
          "Idempotency-Key": crypto.randomUUID(),
          "If-Match": `"${registration.version}"`,
        },
        data: {
          registration_id: registration.id,
          definition_id: definition.id,
          definition_version: definition.version,
        },
      },
    );
    expect(response.status()).toBe(403);
  } finally {
    await viewer.context.close();
  }
});
