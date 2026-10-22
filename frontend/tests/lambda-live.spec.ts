import { expect, test, type Page } from "@playwright/test";
import { lstatSync, readFileSync } from "node:fs";
import type { components } from "../src/api.generated";
import type { Resource, Recommendation } from "../src/types";

// Existing native provider workflow fixture supplies the actual issued IDs.
// This journey uses normal OIDC and actual API/persistence; no route interception.
type S = components["schemas"];
type Record = S["LambdaAssessmentRecord"];
type Ready = { schema_version: string; tenant_id: string; resource_ids: string[]; policy_ids: string[]; qualifiers: string[] };
const decimal = /^-?(0|[1-9][0-9]*)(\.[0-9]+)?$/;
const positiveDecimal = (value: string | null) => value !== null && decimal.test(value) && BigInt(value.replace(".", "")) > 0n;
const shortId = (id: string) => id.length > 25 ? id.slice(0, 12) + "…" + id.slice(-6) : id;
const navigation = (page: Page, hash: string) => page.getByRole("navigation", { name: "Main navigation", exact: true }).locator('a[href="#' + hash + '"]').click();
async function signIn(page: Page) {
  await page.goto("/"); const dashboard = page.waitForResponse(response => new URL(response.url()).pathname === "/v1/dashboard" && response.request().method() === "GET");
  await page.getByRole("button", { name: "Sign in to your workspace", exact: true }).click(); const username = page.getByRole("textbox", { name: /username/i });
  await Promise.race([username.waitFor({ state: "visible" }), dashboard]);
  if (await username.isVisible()) { await username.fill(process.env.FINOPS_E2E_USER || "owner"); await page.getByLabel("Password", { exact: true }).fill(process.env.FINOPS_E2E_PASSWORD || "local-pilot-demo"); await page.getByRole("button", { name: "Sign In", exact: true }).click(); }
  const response = await dashboard; expect(response.status()).toBe(200); const authorization = response.request().headers().authorization; expect(authorization).toMatch(/^Bearer /);
  await expect(page.getByRole("heading", { name: "Cost operations overview.", exact: true })).toBeVisible(); return authorization;
}
test("commissioned Lambda native evidence reaches ordinary OIDC assessments, customer economics and coverage", async ({ page }, testInfo) => {
  expect(process.env.FINOPS_LAMBDA_COMMISSIONED).toBe("true"); const file = process.env.FINOPS_LAMBDA_EXPECTED_JSON; expect(file).toBeTruthy();
  const stat = lstatSync(file!); expect(stat.isFile() && !stat.isSymbolicLink() && stat.size > 0 && stat.size <= 16384).toBe(true);
  const ready = JSON.parse(readFileSync(file!, "utf8")) as Ready;
  expect(Object.keys(ready).sort()).toEqual(["policy_ids", "qualifiers", "resource_ids", "schema_version", "tenant_id"]); expect(ready.schema_version).toBe("1"); expect(ready.tenant_id).toBe("tenant-demo"); expect(ready.resource_ids.length).toBeGreaterThan(0); expect(ready.resource_ids.length).toBeLessThanOrEqual(16); expect(ready.policy_ids).toHaveLength(ready.resource_ids.length); expect(ready.qualifiers).toHaveLength(ready.resource_ids.length);
  const errors: string[] = []; page.on("pageerror", error => errors.push(error.message)); let authorization = await signIn(page);
  const read = async <T,>(path: string): Promise<T> => { const response = await page.request.get(path, { headers: { Authorization: authorization } }); expect(response.status()).toBe(200); return response.json() as Promise<T>; };
  const issued: Record[] = [];
  for (const [index, resourceID] of ready.resource_ids.entries()) {
    const [resource, policy] = await Promise.all([read<Resource>(`/v1/resources/${encodeURIComponent(resourceID)}`), read<S["LambdaPolicy"]>(`/v1/lambda-policies/${encodeURIComponent(ready.policy_ids[index])}`)]);
    expect(resource.resource_type).toBe("LAMBDA_FUNCTION"); expect(resource.lambda_configuration).toBeTruthy(); expect(policy.resource_id).toBe(resourceID);
    await navigation(page, "workloads"); if (!await page.getByRole("region", { name: "Scoped Lambda inventory", exact: true }).isVisible()) await page.getByText("Inspect Lambda inventory", { exact: true }).click();
    const inventory = page.getByRole("region", { name: "Scoped Lambda inventory", exact: true }), row = inventory.getByRole("row").filter({ has: page.getByText(resource.provider_resource_id, { exact: true }) }); await expect(row).toHaveCount(1);
    await row.getByRole("button", { name: `Inspect Lambda ${resource.name || resource.provider_resource_id}`, exact: true }).click(); const context = page.getByRole("dialog", { name: "Lambda resource and requirements", exact: true });
    await context.getByLabel("Lambda serving qualifier", { exact: true }).selectOption(ready.qualifiers[index]); await expect(context.getByRole("region", { name: "Registered Lambda requirements", exact: true })).toBeVisible();
    const response = page.waitForResponse(value => new URL(value.url()).pathname === "/v1/lambda-assessments" && value.request().method() === "POST"); await context.getByRole("button", { name: `Assess with policy ${policy.name}`, exact: true }).click();
    const queuedResponse = await response; expect(queuedResponse.status()).toBe(202); const request = queuedResponse.request(), body = { resource_id: resourceID, qualifier: ready.qualifiers[index], policy_id: policy.id };
    expect(request.postDataJSON()).toEqual(body); expect(request.headers()["if-match"]).toBe('"0"'); const key = request.headers()["idempotency-key"]; expect(key).toBeTruthy(); const queued = await queuedResponse.json() as Record;
    const replay = await page.request.post("/v1/lambda-assessments", { headers: { Authorization: authorization, "If-Match": '"0"', "Idempotency-Key": key }, data: body }); expect(replay.status()).toBe(202); expect((await replay.json() as Record).id).toBe(queued.id);
    let result = queued; await expect.poll(async () => { result = await read<Record>(`/v1/lambda-assessments/${encodeURIComponent(queued.id)}`); return result.status; }, { timeout: 60_000, intervals: [250, 500, 1000], message: "The separate read-only Lambda assessor must publish its actual persisted result" }).toMatch(/^(ASSESSED|BLOCKED|FAILED)$/);
    expect(result.status).not.toBe("FAILED"); expect(result.assessment).not.toBeNull(); const assessment = result.assessment!;
    expect(assessment.model_kind).toBe("LAMBDA_ASSESSMENT_V1"); expect(assessment.pre_execution_ready).toBe(false); expect(assessment.execution_authorized).toBe(false); expect(assessment.verified_saving).toBeNull(); expect(assessment.assessment_hash).toMatch(/^[a-f0-9]{64}$/);
    for (const candidate of assessment.candidates) { expect(candidate.pre_execution_ready).toBe(false); expect(candidate.execution_authorized).toBe(false); expect(candidate.verified_saving).toBeNull(); expect(candidate.economics.estimated_annual_saving).toBeNull(); if (candidate.economics.estimated_monthly_saving !== null) expect(candidate.economics.estimated_monthly_saving).toMatch(decimal); }
    const dialog = page.getByRole("dialog", { name: "Lambda assessment", exact: true }); await dialog.getByRole("button", { name: "Refresh selected Lambda assessment", exact: true }).click(); await expect(dialog.getByRole("button", { name: /Execute|Approve|Resize|Deploy|Shift|Create.*plan/ })).toHaveCount(0); await dialog.getByRole("button", { name: "Close dialog", exact: true }).click(); issued.push(result);
  }
  const accepted = issued.find(row => row.assessment?.candidates.some(candidate => candidate.family === "MEMORY" && candidate.status === "RECOMMENDED" && candidate.physical_status === "PASS" && positiveDecimal(candidate.economics.estimated_window_saving) && positiveDecimal(candidate.economics.estimated_monthly_saving)));
  expect(accepted, "The collected native population, V2 benchmark and canonical customer rates must justify one persisted positive memory recommendation").toBeTruthy();
  const memory = accepted!.assessment!.candidates.find(candidate => candidate.family === "MEMORY" && candidate.status === "RECOMMENDED" && positiveDecimal(candidate.economics.estimated_window_saving))!;
  expect(memory.decision).toMatch(/^(REDUCE_MEMORY|INCREASE_MEMORY_FOR_LOWER_COST)$/); expect(memory.checks.length).toBeGreaterThan(0); expect(memory.checks.every(check => check.status === "PASS")).toBe(true);
  expect(memory.performance.source_receipt_ids).toHaveLength(2); expect(new Set(memory.performance.source_receipt_ids).size).toBe(2); expect(memory.economics.pricing_basis).toBe("NATIVE_CUSTOMER_NET_ONLY"); expect(memory.economics.estimated_annual_saving).toBeNull();
  await page.reload(); authorization = await signIn(page); const retained = await read<Record>(`/v1/lambda-assessments/${encodeURIComponent(accepted!.id)}`); expect(retained.assessment).toEqual(accepted!.assessment); expect(retained.current).toBe(true);
  await navigation(page, "recommendations"); await page.getByText("Inspect all Lambda recommendations", { exact: true }).click(); const publications = await read<{ items: Recommendation[] }>(`/v1/recommendations?model_kind=LAMBDA_ASSESSMENT_V1&resource_id=${encodeURIComponent(accepted!.resource_id)}&limit=100`), publication = publications.items.find(item => item.lambda_assessment_id === accepted!.id); expect(publication?.id).toBeTruthy();
  const button = page.getByRole("button", { name: `Inspect Lambda recommendation ${shortId(publication!.id)}`, exact: true }); await expect(button.first()).toBeVisible(); await button.first().click(); const dialog = page.getByRole("dialog", { name: "Lambda assessment", exact: true }); await expect(dialog.getByRole("region", { name: "Lambda customer economics", exact: true })).toBeVisible(); await expect(dialog).toContainText("Billed duration (ms)"); await dialog.screenshot({ path: testInfo.outputPath("lambda-persisted-assessment.png"), animations: "disabled" }); await dialog.getByRole("button", { name: "Close dialog", exact: true }).click();
  await navigation(page, "connections"); const coverageResponse = page.waitForResponse(value => new URL(value.url()).pathname === "/v1/coverage"); await page.getByText("Inspect assessed and unsupported spend", { exact: true }).click(); expect((await coverageResponse).status()).toBe(200); await expect(page.getByRole("region", { name: "All AWS assessment spend coverage", exact: true })).toBeVisible(); await expect(page.getByRole("region", { name: "Lambda assessment spend coverage", exact: true })).toBeVisible(); expect(errors).toEqual([]);
  await testInfo.attach("lambda-persisted-ids", { contentType: "application/json", body: JSON.stringify({ schema_version: "1", assessment_ids: issued.map(row => row.id), resource_ids: ready.resource_ids, policy_ids: ready.policy_ids, qualifiers: ready.qualifiers, execution_authorized: false, verified_saving: null }) });
});
