import { expect, test, type Page } from "@playwright/test";
import { lstatSync, readFileSync } from "node:fs";
import type { components } from "../src/api.generated";
import type { Resource } from "../src/types";

// Commissioned normal-console journey. No routes, tokens, observations or
// assessment results are fabricated here. Native/source authenticity is also
// independently checked by the Go fixture that issues these resource IDs.
type S = components["schemas"];
type Record = S["DatabaseAssessmentRecord"];
const shortId = (id: string) => id.length > 25 ? `${id.slice(0, 12)}…${id.slice(-6)}` : id;
const decimal = /^-?(0|[1-9][0-9]*)(\.[0-9]+)?$/;

async function signIn(page: Page) {
  await page.goto("/");
  const dashboard = page.waitForResponse(response => new URL(response.url()).pathname === "/v1/dashboard" && response.request().method() === "GET");
  await page.getByRole("button", { name: "Sign in to your workspace", exact: true }).click();
  const username = page.getByRole("textbox", { name: /username/i });
  // A fresh code+PKCE exchange may reuse the real identity-provider SSO cookie
  // after reload; a displayed login form still uses the commissioned account.
  await Promise.race([username.waitFor({ state: "visible" }), dashboard]);
  if (await username.isVisible()) {
    await username.fill(process.env.FINOPS_E2E_USER || "owner");
    await page.getByLabel("Password", { exact: true }).fill(process.env.FINOPS_E2E_PASSWORD || "local-pilot-demo");
    await page.getByRole("button", { name: "Sign In", exact: true }).click();
  }
  const response = await dashboard;
  expect(response.status()).toBe(200);
  const authorization = response.request().headers().authorization;
  expect(authorization).toMatch(/^Bearer /);
  await expect(page.getByRole("heading", { name: "Cost operations overview.", exact: true })).toBeVisible();
  return authorization;
}

async function inspectHistory(page: Page, id: string) {
  await page.getByRole("link", { name: "Workloads & resources", exact: true }).click();
  const first = page.waitForResponse(response => new URL(response.url()).pathname === "/v1/database-assessments" && response.request().method() === "GET");
  await page.getByText("Database assessment history", { exact: true }).click();
  let response = await first;
  const cursors = new Set<string>();
  for (let count = 0; count < 100; count++) {
    expect(response.status()).toBe(200);
    const value = await response.json() as S["DatabaseAssessmentPage"];
    if (value.items.some(item => item.id === id)) {
      await page.getByRole("button", { name: `Inspect database assessment ${shortId(id)}`, exact: true }).click();
      return;
    }
    expect(value.next_cursor, "The actual persisted request must remain in scoped history").not.toBeNull();
    expect(cursors.has(value.next_cursor!)).toBe(false);
    cursors.add(value.next_cursor!);
    const cursor = value.next_cursor!;
    const next = page.waitForResponse(item => {
      const url = new URL(item.url());
      return url.pathname === "/v1/database-assessments" && url.searchParams.get("cursor") === cursor;
    });
    await page.getByRole("button", { name: "Load more database assessments", exact: true }).click();
    response = await next;
  }
  throw new Error("DATABASE_PERSISTED_REQUEST_NOT_IN_BOUNDED_HISTORY");
}

test("commissioned native database assessments persist through normal OIDC, recommendations and reload without execution authority", async ({ page }, testInfo) => {
  expect(process.env.FINOPS_DATABASE_COMMISSIONED).toBe("true");
  const positive = process.env.FINOPS_DATABASE_RESOURCE_ID;
  const blocked = process.env.FINOPS_DATABASE_BLOCKED_RESOURCE_ID;
  expect(positive, "Actual Go fixture must issue the positive resource ID").toBeTruthy();
  expect(blocked, "Actual Go fixture must issue the blocked resource ID").toBeTruthy();
  expect(positive).not.toBe(blocked);
  const resources = [positive!, blocked!, ...(process.env.FINOPS_DATABASE_NO_CHANGE_RESOURCE_ID ? [process.env.FINOPS_DATABASE_NO_CHANGE_RESOURCE_ID] : [])];
  const readyFile = process.env.FINOPS_DATABASE_READY_FILE;
  if (readyFile) {
    const stat = lstatSync(readyFile);
    expect(stat.isFile() && !stat.isSymbolicLink() && stat.size > 0 && stat.size <= 8192).toBe(true);
    const ready = JSON.parse(readFileSync(readyFile, "utf8")) as { schema_version: string; tenant_id: string; resource_ids: string[] };
    expect(Object.keys(ready).sort()).toEqual(["resource_ids", "schema_version", "tenant_id"]);
    expect(ready.schema_version).toBe("1");
    expect(ready.tenant_id).toBeTruthy();
    expect(Array.isArray(ready.resource_ids)).toBe(true);
    for (const id of resources) expect(ready.resource_ids).toContain(id);
  }
  const errors: string[] = [];
  page.on("pageerror", error => errors.push(error.message));
  let authorization = await signIn(page);
  const read = async <T,>(path: string): Promise<T> => {
    const response = await page.request.get(path, { headers: { Authorization: authorization } });
    expect(response.status()).toBe(200);
    return response.json() as Promise<T>;
  };
  const issued: Record[] = [];
  for (const [index, resourceID] of resources.entries()) {
    const resource = await read<Resource>(`/v1/resources/${encodeURIComponent(resourceID)}`);
    expect(["RDS_INSTANCE", "RDS_CLUSTER"]).toContain(resource.resource_type);
    await page.getByRole("link", { name: "Workloads & resources", exact: true }).click();
    const row = page.getByRole("row").filter({ has: page.getByText(resource.provider_resource_id, { exact: true }) });
    await expect(row).toHaveCount(1);
    const response = page.waitForResponse(item => new URL(item.url()).pathname === "/v1/database-assessments" && item.request().method() === "POST");
    await row.getByRole("button", { name: `Assess database ${resource.name || resource.provider_resource_id}`, exact: true }).click();
    const queuedResponse = await response;
    expect(queuedResponse.status()).toBe(202);
    const request = queuedResponse.request();
    expect(request.postDataJSON()).toEqual({ resource_id: resourceID });
    expect(request.headers()["if-match"]).toBe('"0"');
    const key = request.headers()["idempotency-key"];
    expect(key).toBeTruthy();
    const queued = await queuedResponse.json() as Record;
    expect(queued.resource_id).toBe(resourceID);
    const replay = await page.request.post("/v1/database-assessments", { headers: { Authorization: authorization, "If-Match": '"0"', "Idempotency-Key": key }, data: { resource_id: resourceID } });
    expect(replay.status()).toBe(202);
    expect((await replay.json() as Record).id).toBe(queued.id);
    let result: Record = queued;
    await expect.poll(async () => {
      result = await read<Record>(`/v1/database-assessments/${encodeURIComponent(queued.id)}`);
      return result.status;
    }, { timeout: 60_000, intervals: [250, 500, 1000], message: "Actual separately credentialed analyst must publish a persisted terminal result" }).toMatch(/^(ASSESSED|BLOCKED|FAILED)$/);
    expect(result.status).not.toBe("FAILED");
    expect(result.assessment).not.toBeNull();
    const assessment = result.assessment!;
    expect(assessment.proposal).toEqual({ risk_class: "R3", executable: false, execution_authorized: false });
    expect(assessment.verified_saving).toBeNull();
    expect(assessment.assessment_hash).toMatch(/^[a-f0-9]{64}$/);
    if (index === 1) {
      expect(result.status).toBe("BLOCKED");
      expect(assessment.status).toBe("BLOCKED");
      expect(assessment.blockers.length).toBeGreaterThan(0);
    } else {
      expect(result.status).toBe("ASSESSED");
      expect(result.current).toBe(true);
      expect(assessment.status).toBe(index === 0 ? "RECOMMENDED" : "NO_CHANGE");
      expect(assessment.evidence_window).not.toBeNull();
      expect(assessment.source_refs.length).toBeGreaterThan(0);
      expect(assessment.economics.current_hourly_cost).toMatch(decimal);
      expect(assessment.economics.currency).toMatch(/^[A-Z]{3}$/);
      if (index === 0) {
        expect(assessment.economics.estimated_monthly_saving).toMatch(decimal);
        expect(assessment.economics.estimated_monthly_saving).not.toMatch(/^(-|0(?:\.0*)?$)/);
      }
    }
    const dialog = page.getByRole("dialog", { name: "Database assessment", exact: true });
    await dialog.getByRole("button", { name: "Refresh selected database assessment", exact: true }).click();
    await expect(dialog).toContainText("R3 · Read-only proposal");
    await expect(dialog.getByRole("button", { name: /Create.*plan|Execute|Approve/ })).toHaveCount(0);
    await dialog.getByRole("button", { name: "Close dialog", exact: true }).click();
    issued.push(result);
  }
  await page.reload();
  authorization = await signIn(page);
  await inspectHistory(page, issued[0].id);
  const retained = await read<Record>(`/v1/database-assessments/${encodeURIComponent(issued[0].id)}`);
  expect(retained.assessment).toEqual(issued[0].assessment);
  const dialog = page.getByRole("dialog", { name: "Database assessment", exact: true });
  await expect(dialog).toContainText("Estimated monthly saving");
  await dialog.screenshot({ path: testInfo.outputPath("database-assessment-persisted.png"), animations: "disabled" });
  await dialog.getByRole("button", { name: "Close dialog", exact: true }).click();
  const recommendations = await read<S["DatabaseRecommendationPage"]>(`/v1/recommendations?model_kind=DATABASE_ASSESSMENT_V1&resource_id=${encodeURIComponent(positive!)}&limit=100`);
  const recommendation = recommendations.items.find(item => item.database_assessment_id === issued[0].id);
  expect(recommendation).toBeTruthy();
  expect(recommendation!.id).toBeTruthy();
  expect(recommendation!.pre_execution_ready).toBe(false);
  await page.getByRole("navigation", { name: "Main navigation", exact: true }).locator('a[href="#recommendations"]').click();
  const card = page.locator(".recommendation-card").filter({ has: page.getByRole("button", { name: `Inspect database recommendation ${shortId(recommendation!.id!)}`, exact: true }) });
  await expect(card).toContainText("R3 · Database proposal");
  await expect(card.getByRole("button", { name: "Create change plan", exact: true })).toHaveCount(0);
  await page.getByRole("link", { name: "Connections & quality", exact: true }).click();
  const coverageResponse = page.waitForResponse(response => new URL(response.url()).pathname === "/v1/coverage");
  await page.getByText("Inspect assessed and unsupported spend", { exact: true }).click();
  const coverageHTTP = await coverageResponse;
  expect(coverageHTTP.status()).toBe(200);
  const coverage = await coverageHTTP.json() as S["AssessmentCoverage"];
  expect(coverage.groups.length).toBeGreaterThan(0);
  for (const group of coverage.groups) {
    expect(group.basis).toBe("POSITIVE_BILLED_CHARGES");
    if (!group.complete || group.detected_spend === "0") expect(group.analysed_percent).toBeNull();
  }
  await expect(page.getByRole("region", { name: "All AWS assessment spend coverage", exact: true })).toBeVisible();
  expect(errors).toEqual([]);
  await testInfo.attach("database-persisted-ids", { contentType: "application/json", body: JSON.stringify({ schema_version: "1", assessment_ids: issued.map(item => item.id), resource_ids: resources, proposal_execution_authorized: false, verified_saving: null }) });
});
