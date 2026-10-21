import { expect, test, type Page } from "@playwright/test";
import { lstatSync, readFileSync } from "node:fs";
import type { components } from "../src/api.generated";
import type { Resource } from "../src/types";

// The existing native provider/Go fixture supplies immutable issued IDs. Every
// request below uses the actual API, OIDC and independently persisted result.
// No route, financial or source response is mocked.
type S = components["schemas"];
type Record = S["NetworkAssessmentRecord"];
type Ready = { schema_version: string; tenant_id: string; resource_ids: string[]; policy_ids: string[] };
const decimal = /^-?(0|[1-9][0-9]*)(\.[0-9]+)?$/;
const shortId = (id: string) => id.length > 25 ? `${id.slice(0, 12)}…${id.slice(-6)}` : id;
const navigation = (page: Page, hash: string) => page.getByRole("navigation", { name: "Main navigation", exact: true }).locator(`a[href="#${hash}"]`).click();
async function signIn(page: Page) {
  await page.goto("/"); const dashboard = page.waitForResponse(response => new URL(response.url()).pathname === "/v1/dashboard" && response.request().method() === "GET");
  await page.getByRole("button", { name: "Sign in to your workspace", exact: true }).click(); const username = page.getByRole("textbox", { name: /username/i });
  await Promise.race([username.waitFor({ state: "visible" }), dashboard]);
  if (await username.isVisible()) { await username.fill(process.env.FINOPS_E2E_USER || "owner"); await page.getByLabel("Password", { exact: true }).fill(process.env.FINOPS_E2E_PASSWORD || "local-pilot-demo"); await page.getByRole("button", { name: "Sign In", exact: true }).click(); }
  const response = await dashboard; expect(response.status()).toBe(200); const authorization = response.request().headers().authorization; expect(authorization).toMatch(/^Bearer /);
  await expect(page.getByRole("heading", { name: "Cost operations overview.", exact: true })).toBeVisible(); return authorization;
}
test("commissioned network evidence persists through ordinary OIDC, IDs-only assessment, economics, recommendations and coverage", async ({ page }, testInfo) => {
  expect(process.env.FINOPS_NETWORK_COMMISSIONED).toBe("true"); const file = process.env.FINOPS_NETWORK_EXPECTED_JSON; expect(file).toBeTruthy();
  const stat = lstatSync(file!); expect(stat.isFile() && !stat.isSymbolicLink() && stat.size > 0 && stat.size <= 16384).toBe(true);
  const ready = JSON.parse(readFileSync(file!, "utf8")) as Ready;
  expect(Object.keys(ready).sort()).toEqual(["policy_ids", "resource_ids", "schema_version", "tenant_id"]); expect(ready.schema_version).toBe("1"); expect(ready.tenant_id).toBe("tenant-demo");
  expect(ready.resource_ids.length).toBeGreaterThan(0); expect(ready.resource_ids.length).toBeLessThanOrEqual(16); expect(ready.policy_ids).toHaveLength(ready.resource_ids.length); expect(new Set(ready.resource_ids).size).toBe(ready.resource_ids.length);
  const errors: string[] = []; page.on("pageerror", error => errors.push(error.message)); let authorization = await signIn(page);
  const read = async <T,>(path: string): Promise<T> => { const response = await page.request.get(path, { headers: { Authorization: authorization } }); expect(response.status()).toBe(200); return response.json() as Promise<T>; };
  const issued: Record[] = [];
  for (const [index, resourceID] of ready.resource_ids.entries()) {
    const [resource, policy] = await Promise.all([read<Resource>(`/v1/resources/${encodeURIComponent(resourceID)}`), read<S["NetworkPolicy"]>(`/v1/network-policies/${encodeURIComponent(ready.policy_ids[index])}`)]);
    expect(resource.network_configuration).toBeTruthy(); expect(policy.resource_id).toBe(resourceID); await navigation(page, "workloads");
    const inventory = page.getByRole("region", { name: "Scoped network inventory", exact: true });
    if (!await page.getByRole("combobox", { name: "Network resource type", exact: true }).isVisible()) await page.getByText("Inspect network inventory", { exact: true }).click();
    await page.getByRole("combobox", { name: "Network resource type", exact: true }).selectOption(resource.resource_type);
    const row = inventory.getByRole("row").filter({ has: page.getByText(resource.provider_resource_id, { exact: true }) }); await expect(row).toHaveCount(1);
    await row.getByRole("button", { name: `Inspect network ${resource.name || resource.provider_resource_id}`, exact: true }).click();
    const context = page.getByRole("dialog", { name: "Network resource and requirements", exact: true }); await expect(context.getByRole("region", { name: "Registered network requirements", exact: true })).toBeVisible();
    const response = page.waitForResponse(value => new URL(value.url()).pathname === "/v1/network-assessments" && value.request().method() === "POST");
    await context.getByRole("button", { name: `Assess with policy ${policy.name}`, exact: true }).click();
    const queuedResponse = await response; expect(queuedResponse.status()).toBe(202); const request = queuedResponse.request(), body = { resource_id: resourceID, policy_id: policy.id };
    expect(request.postDataJSON()).toEqual(body); expect(request.headers()["if-match"]).toBe('"0"'); const key = request.headers()["idempotency-key"]; expect(key).toBeTruthy();
    const queued = await queuedResponse.json() as Record; expect(queued.resource_id).toBe(resourceID);
    const replay = await page.request.post("/v1/network-assessments", { headers: { Authorization: authorization, "If-Match": '"0"', "Idempotency-Key": key }, data: body }); expect(replay.status()).toBe(202); expect((await replay.json() as Record).id).toBe(queued.id);
    let result = queued; await expect.poll(async () => { result = await read<Record>(`/v1/network-assessments/${encodeURIComponent(queued.id)}`); return result.status; }, { timeout: 60_000, intervals: [250, 500, 1000], message: "The separately credentialed network assessor must publish its actual result" }).toMatch(/^(ASSESSED|BLOCKED|FAILED)$/);
    expect(result.status).not.toBe("FAILED"); expect(result.assessment).not.toBeNull(); expect(result.assessment!.model_kind).toBe("NETWORK_ASSESSMENT_V1"); expect(result.assessment!.execution_authorized).toBe(false); expect(result.assessment!.pre_execution_ready).toBe(false); expect(result.assessment!.verified_saving).toBeNull();
    if ("denominators" in result.assessment!) {
      const assessment = result.assessment!; expect(assessment.assessment_hash).toMatch(/^[a-f0-9]{64}$/); expect(assessment.source_refs.length).toBeGreaterThan(0); expect(assessment.economics.estimated_monthly_saving).toBeNull();
      for (const candidate of assessment.candidates) { expect(candidate.security_impact.effects.length).toBeGreaterThan(0); expect(candidate.economics.estimated_annual_saving).toBeNull(); if (candidate.economics.estimated_monthly_saving !== null) expect(candidate.economics.estimated_monthly_saving).toMatch(decimal); }
    } else expect(result.assessment!.blockers.length).toBeGreaterThan(0);
    const dialog = page.getByRole("dialog", { name: "Network assessment", exact: true }); await dialog.getByRole("button", { name: "Refresh selected network assessment", exact: true }).click();
    await expect(dialog.getByRole("button", { name: /Execute|Approve|Release|Delete|Create.*endpoint|Change.*route|Create.*plan/ })).toHaveCount(0); await dialog.getByRole("button", { name: "Close dialog", exact: true }).click(); issued.push(result);
  }
  const accepted = issued.find(row => row.assessment && "denominators" in row.assessment && row.assessment.candidates.some(candidate => candidate.family === "A" && candidate.kind === "GATEWAY_ENDPOINT_REVIEW" && candidate.status === "RECOMMENDED" && candidate.economics.nat_hourly_retained === true && candidate.economics.estimated_window_saving !== null && Number(candidate.economics.estimated_window_saving) > 0)); expect(accepted, "The collected same-region S3 traffic must justify a gateway review while preserving NAT hourly obligations").toBeTruthy();
  if (ready.resource_ids.length === 1) {
    const assessment = accepted!.assessment!; expect("denominators" in assessment).toBe(true);
    if (!("denominators" in assessment)) throw new Error("Native network economics were not persisted");
    expect(accepted!.status).toBe("ASSESSED"); expect(assessment.economics.currency).toBe("GBP"); expect(assessment.economics.detected_native_cost).toBe("97.200000000000"); expect(assessment.economics.estimated_monthly_saving).toBeNull(); expect(assessment.candidates).toHaveLength(2);
    for (const candidate of assessment.candidates) {
      expect(candidate.family).toBe("A"); expect(candidate.kind).toBe("GATEWAY_ENDPOINT_REVIEW"); expect(candidate.status).toBe("RECOMMENDED"); expect(candidate.blockers).toEqual([]);
      expect(candidate.economics.current_window_cost).toBe("48.600000000000"); expect(candidate.economics.candidate_window_cost).toBe("16.200000000000"); expect(candidate.economics.estimated_window_saving).toBe("32.400000000000"); expect(candidate.economics.estimated_monthly_saving).toBe("32.850000000000"); expect(candidate.economics.nat_hourly_retained).toBe(true);
      expect(candidate.economics.component_costs).toContainEqual(expect.objectContaining({ component: "NAT_HOURLY", current_window_cost: "16.200000000000", candidate_window_cost: "16.200000000000", avoided_window_cost: "0.000000000000" }));
    }
  }
  await page.reload(); authorization = await signIn(page); const retained = await read<Record>(`/v1/network-assessments/${encodeURIComponent(accepted!.id)}`); expect(retained.assessment).toEqual(accepted!.assessment); expect(retained.current).toBe(true);
  await navigation(page, "recommendations"); await page.getByText("Inspect all network recommendations", { exact: true }).click();
  const publications = await read<S["DatabaseRecommendationPage"]>(`/v1/recommendations?model_kind=NETWORK_ASSESSMENT_V1&resource_id=${encodeURIComponent(accepted!.resource_id)}&limit=100`); const publication = publications.items.find(item => item.network_assessment_id === accepted!.id); expect(publication?.id).toBeTruthy(); expect(publication!.pre_execution_ready).toBe(false);
  const button = page.getByRole("button", { name: `Inspect network recommendation ${shortId(publication!.id!)}`, exact: true }); await expect(button.first()).toBeVisible(); await button.first().click();
  const dialog = page.getByRole("dialog", { name: "Network assessment", exact: true }); await expect(dialog.getByRole("region", { name: "Network traffic cohorts", exact: true }).first()).toBeVisible(); await expect(dialog).toContainText("Security and recovery impact"); await dialog.screenshot({ path: testInfo.outputPath("network-persisted-assessment.png"), animations: "disabled" }); await dialog.getByRole("button", { name: "Close dialog", exact: true }).click();
  await navigation(page, "connections"); const response = page.waitForResponse(value => new URL(value.url()).pathname === "/v1/coverage"); await page.getByText("Inspect assessed and unsupported spend", { exact: true }).click(); expect((await response).status()).toBe(200);
  await expect(page.getByRole("region", { name: "All AWS assessment spend coverage", exact: true })).toBeVisible(); await expect(page.getByRole("region", { name: "Network assessment spend coverage", exact: true })).toBeVisible(); expect(errors).toEqual([]);
  await testInfo.attach("network-persisted-ids", { contentType: "application/json", body: JSON.stringify({ schema_version: "1", assessment_ids: issued.map(row => row.id), resource_ids: ready.resource_ids, policy_ids: ready.policy_ids, execution_authorized: false, verified_saving: null }) });
});
