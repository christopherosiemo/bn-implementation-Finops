import { expect, test, type Page } from "@playwright/test";
import { lstatSync, readFileSync } from "node:fs";
import type { components } from "../src/api.generated";
import type { Resource } from "../src/types";

// The existing Go/provider fixture commissions actual immutable evidence and
// issues resource/dataset IDs. No browser route or financial response is mocked.
type S = components["schemas"];
type Record = S["ObjectStorageAssessmentRecord"];
type Ready = { schema_version: string; tenant_id: string; resource_ids: string[]; dataset_ids: string[] };
const shortId = (id: string) => id.length > 25 ? `${id.slice(0, 12)}…${id.slice(-6)}` : id;
const decimal = /^-?(0|[1-9][0-9]*)(\.[0-9]+)?$/;
const navigation = (page: Page, hash: string) => page.getByRole("navigation", { name: "Main navigation", exact: true }).locator(`a[href="#${hash}"]`).click();

async function signIn(page: Page) {
  await page.goto("/");
  const dashboard = page.waitForResponse(response => new URL(response.url()).pathname === "/v1/dashboard" && response.request().method() === "GET");
  await page.getByRole("button", { name: "Sign in to your workspace", exact: true }).click();
  const username = page.getByRole("textbox", { name: /username/i });
  await Promise.race([username.waitFor({ state: "visible" }), dashboard]);
  if (await username.isVisible()) {
    await username.fill(process.env.FINOPS_E2E_USER || "owner");
    await page.getByLabel("Password", { exact: true }).fill(process.env.FINOPS_E2E_PASSWORD || "local-pilot-demo");
    await page.getByRole("button", { name: "Sign In", exact: true }).click();
  }
  const response = await dashboard; expect(response.status()).toBe(200);
  const authorization = response.request().headers().authorization; expect(authorization).toMatch(/^Bearer /);
  await expect(page.getByRole("heading", { name: "Cost operations overview.", exact: true })).toBeVisible();
  return authorization;
}

test("commissioned S3 policies persist through normal OIDC, independent economics, recommendations and truthful coverage", async ({ page }, testInfo) => {
  expect(process.env.FINOPS_OBJECT_STORAGE_COMMISSIONED).toBe("true");
  const readyPath = process.env.FINOPS_OBJECT_STORAGE_READY_FILE; expect(readyPath).toBeTruthy();
  const stat = lstatSync(readyPath!); expect(stat.isFile() && !stat.isSymbolicLink() && stat.size > 0 && stat.size <= 16384).toBe(true);
  const ready = JSON.parse(readFileSync(readyPath!, "utf8")) as Ready;
  expect(Object.keys(ready).sort()).toEqual(["dataset_ids", "resource_ids", "schema_version", "tenant_id"]);
  expect(ready.schema_version).toBe("1"); expect(ready.tenant_id).toBe("tenant-demo");
  expect(ready.resource_ids).toHaveLength(3); expect(ready.dataset_ids).toHaveLength(3);
  expect(new Set(ready.resource_ids).size).toBe(3); expect(new Set(ready.dataset_ids).size).toBe(3);
  const errors: string[] = []; page.on("pageerror", error => errors.push(error.message));
  let authorization = await signIn(page);
  const read = async <T,>(path: string): Promise<T> => { const response = await page.request.get(path, { headers: { Authorization: authorization } }); expect(response.status()).toBe(200); return response.json() as Promise<T>; };
  const issued: Record[] = [];
  for (const [index, resourceID] of ready.resource_ids.entries()) {
    const [resource, dataset] = await Promise.all([read<Resource>(`/v1/resources/${encodeURIComponent(resourceID)}`), read<S["ObjectStorageDataset"]>(`/v1/object-storage-datasets/${encodeURIComponent(ready.dataset_ids[index])}`)]);
    expect(resource.resource_type).toBe("S3_BUCKET"); expect(resource.object_storage_configuration).toBeTruthy(); expect(dataset.resource_id).toBe(resourceID);
    await navigation(page, "workloads");
    const row = page.getByRole("row").filter({ has: page.getByText(resource.provider_resource_id, { exact: true }) }); await expect(row).toHaveCount(1);
    await row.getByRole("button", { name: `Inspect S3 ${resource.name || resource.provider_resource_id}`, exact: true }).click();
    const context = page.getByRole("dialog", { name: "S3 bucket and datasets", exact: true });
    await expect(context.getByRole("region", { name: "S3 native configuration read states", exact: true })).toBeVisible();
    const response = page.waitForResponse(item => new URL(item.url()).pathname === "/v1/object-storage-assessments" && item.request().method() === "POST");
    await context.getByRole("button", { name: `Assess dataset ${dataset.name}`, exact: true }).click();
    const queuedResponse = await response; expect(queuedResponse.status()).toBe(202);
    const request = queuedResponse.request(), body = { resource_id: resourceID, dataset_id: dataset.id };
    expect(request.postDataJSON()).toEqual(body); expect(request.headers()["if-match"]).toBe('"0"');
    const key = request.headers()["idempotency-key"]; expect(key).toBeTruthy();
    const queued = await queuedResponse.json() as Record; expect(queued.resource_id).toBe(resourceID); expect(queued.dataset_id).toBe(dataset.id);
    const replay = await page.request.post("/v1/object-storage-assessments", { headers: { Authorization: authorization, "If-Match": '"0"', "Idempotency-Key": key }, data: body });
    expect(replay.status()).toBe(202); expect((await replay.json() as Record).id).toBe(queued.id);
    let result = queued;
    await expect.poll(async () => { result = await read<Record>(`/v1/object-storage-assessments/${encodeURIComponent(queued.id)}`); return result.status; }, { timeout: 60_000, intervals: [250, 500, 1000], message: "The actual restricted object-storage analyst must publish a persisted result" }).toMatch(/^(ASSESSED|BLOCKED|FAILED)$/);
    expect(result.status).not.toBe("FAILED"); expect(result.assessment).not.toBeNull();
    const assessment = result.assessment!;
    expect(assessment.schema_version).toBe("1"); expect(assessment.model_kind).toBe("OBJECT_STORAGE_ASSESSMENT_V1"); expect(assessment.model_version).toBe("object-storage-v1");
    expect(assessment.proposal).toEqual({ risk_class: "R3", executable: false, execution_authorized: false });
    expect(assessment.pre_execution_ready).toBe(false); expect(assessment.execution_authorized).toBe(false); expect(assessment.verified_saving).toBeNull();
    expect(assessment.assessment_hash).toMatch(/^[a-f0-9]{64}$/); expect(assessment.source_refs.length).toBeGreaterThan(0);
    expect(assessment.status).toBe(["RECOMMENDED", "BLOCKED", "OBSERVATION_ONLY"][index]);
    if (index === 0) {
      expect(result.current).toBe(true); expect(assessment.cohorts.length).toBeGreaterThan(0);
      const candidate = assessment.candidates.find(item => item.status === "RECOMMENDED"); expect(candidate).toBeTruthy();
      expect(candidate!.economics.basis).toBe("AWS_CUR_NET_USAGE"); expect(candidate!.economics.current_monthly_cost).toMatch(decimal); expect(candidate!.economics.estimated_monthly_saving).toMatch(decimal);
      expect(candidate!.economics.component_costs.length).toBeGreaterThan(0); expect(candidate!.economics.estimated_monthly_saving).not.toMatch(/^(-|0(?:\.0*)?$)/);
    } else if (index === 1) {
      expect(result.status).toBe("BLOCKED"); expect(assessment.blockers.length).toBeGreaterThan(0);
      expect(assessment.candidates.every(item => item.economics.estimated_monthly_saving === null)).toBe(true);
    } else {
      expect(assessment.candidates.some(item => item.recommendation_kind === "S3_NONCURRENT_VERSION_REVIEW" || item.recommendation_kind === "S3_MULTIPART_UPLOAD_REVIEW")).toBe(true);
      expect(assessment.candidates.every(item => item.execution_authorized === false && item.verified_saving === null)).toBe(true);
    }
    const dialog = page.getByRole("dialog", { name: "S3 assessment", exact: true });
    await dialog.getByRole("button", { name: "Refresh selected S3 assessment", exact: true }).click(); await expect(dialog).toContainText("R3 · Read-only S3 proposal");
    if (index === 0) {
      const candidate = assessment.candidates.find(item => item.status === "RECOMMENDED")!;
      await dialog.getByText(`Inspect economics for ${candidate.candidate_storage_class ?? candidate.recommendation_kind} · ${shortId(candidate.id)}`, { exact: true }).click();
      await expect(dialog.getByRole("region", { name: "S3 storage access and continuing cost components", exact: true })).toBeVisible();
      await dialog.screenshot({ path: testInfo.outputPath("object-storage-persisted.png"), animations: "disabled" });
    }
    await expect(dialog.getByRole("button", { name: /Create.*plan|Execute|Approve|Delete|Archive objects|Update lifecycle/ })).toHaveCount(0);
    await dialog.getByRole("button", { name: "Close dialog", exact: true }).click(); issued.push(result);
  }
  await page.reload(); authorization = await signIn(page);
  const retained = await read<Record>(`/v1/object-storage-assessments/${encodeURIComponent(issued[0].id)}`); expect(retained.current).toBe(true); expect(retained.assessment).toEqual(issued[0].assessment);
  await navigation(page, "workloads"); await page.getByText("S3 assessment history", { exact: true }).click();
  const seen = new Set<string>();
  for (let n = 0; n < 100; n++) {
    const button = page.getByRole("button", { name: `Inspect S3 assessment ${shortId(issued[0].id)}`, exact: true });
    if (await button.count()) { await button.click(); break; }
    const more = page.getByRole("button", { name: "Load more s3 assessments", exact: true }); await expect(more).toBeVisible();
    const response = page.waitForResponse(item => new URL(item.url()).pathname === "/v1/object-storage-assessments" && new URL(item.url()).searchParams.has("cursor"));
    await more.click(); const next = await response; expect(next.status()).toBe(200); expect(seen.has(next.url())).toBe(false); seen.add(next.url());
  }
  await expect(page.getByRole("dialog", { name: "S3 assessment", exact: true })).toBeVisible();
  await page.getByRole("dialog", { name: "S3 assessment", exact: true }).getByRole("button", { name: "Close dialog", exact: true }).click();
  const recommendations = await read<S["DatabaseRecommendationPage"]>(`/v1/recommendations?model_kind=OBJECT_STORAGE_ASSESSMENT_V1&resource_id=${encodeURIComponent(ready.resource_ids[0])}&limit=100`);
  const recommendation = recommendations.items.find(item => item.object_storage_assessment_id === issued[0].id); expect(recommendation?.id).toBeTruthy(); expect(recommendation!.pre_execution_ready).toBe(false);
  await navigation(page, "recommendations"); const card = page.locator(".recommendation-card").filter({ has: page.getByRole("button", { name: `Inspect S3 recommendation ${shortId(recommendation!.id!)}`, exact: true }) });
  await expect(card).toContainText("R3 · S3 proposal"); await expect(card.getByRole("button", { name: "Create change plan", exact: true })).toHaveCount(0);
  await navigation(page, "connections"); const coverageResponse = page.waitForResponse(response => new URL(response.url()).pathname === "/v1/coverage");
  await page.getByText("Inspect assessed and unsupported spend", { exact: true }).click(); const coverageHTTP = await coverageResponse; expect(coverageHTTP.status()).toBe(200);
  const coverage = await coverageHTTP.json() as S["AssessmentCoverage"]; expect(coverage.object_storage_groups?.length).toBeGreaterThan(0);
  for (const group of [...coverage.groups, ...(coverage.object_storage_groups ?? [])]) if (!group.complete || group.detected_spend === "0") expect(group.analysed_percent).toBeNull();
  await expect(page.getByRole("region", { name: "All AWS assessment spend coverage", exact: true })).toBeVisible(); await expect(page.getByRole("region", { name: "S3 assessment spend coverage", exact: true })).toBeVisible(); expect(errors).toEqual([]);
  await testInfo.attach("object-storage-persisted-ids", { contentType: "application/json", body: JSON.stringify({ schema_version: "1", assessment_ids: issued.map(item => item.id), resource_ids: ready.resource_ids, dataset_ids: ready.dataset_ids, execution_authorized: false, verified_saving: null }) });
});
