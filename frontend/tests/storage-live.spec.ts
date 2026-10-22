import { expect, test, type Page } from "@playwright/test";
import { lstatSync, readFileSync } from "node:fs";
import type { components } from "../src/api.generated";
import type { Resource } from "../src/types";

// Commissioned normal-console journey. It supplies only issued resource IDs;
// OIDC, queue/results, pricing and evidence are actual application responses.
// The Go fixture independently checks provenance and these new persisted IDs.
type S = components["schemas"];
type Record = S["StorageAssessmentRecord"];
type RecommendationPage = S["DatabaseRecommendationPage"]; // Existing shared publication-page response shape.
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
  const response = await dashboard;
  expect(response.status()).toBe(200);
  const authorization = response.request().headers().authorization;
  expect(authorization).toMatch(/^Bearer /);
  await expect(page.getByRole("heading", { name: "Cost operations overview.", exact: true })).toBeVisible();
  return authorization;
}

async function inspectHistory(page: Page, id: string) {
  await navigation(page, "workloads");
  const first = page.waitForResponse(response => new URL(response.url()).pathname === "/v1/storage-assessments" && response.request().method() === "GET");
  await page.getByText("Storage assessment history", { exact: true }).click();
  let response = await first;
  const cursors = new Set<string>();
  for (let count = 0; count < 100; count++) {
    expect(response.status()).toBe(200);
    const value = await response.json() as S["StorageAssessmentPage"];
    if (value.items.some(item => item.id === id)) {
      await page.getByRole("button", { name: `Inspect storage assessment ${shortId(id)}`, exact: true }).click();
      return;
    }
    expect(value.next_cursor, "The issued request must remain in actual scoped history").not.toBeNull();
    expect(cursors.has(value.next_cursor!)).toBe(false);
    cursors.add(value.next_cursor!);
    const next = page.waitForResponse(item => { const url = new URL(item.url()); return url.pathname === "/v1/storage-assessments" && url.searchParams.get("cursor") === value.next_cursor; });
    await page.getByRole("button", { name: "Load more storage assessments", exact: true }).click();
    response = await next;
  }
  throw new Error("STORAGE_PERSISTED_REQUEST_NOT_IN_BOUNDED_HISTORY");
}

test("commissioned storage assessments persist through normal OIDC, recommendations and coverage with no mutation authority", async ({ page }, testInfo) => {
  expect(process.env.FINOPS_STORAGE_COMMISSIONED).toBe("true");
  const resources = [process.env.FINOPS_STORAGE_RESOURCE_ID, process.env.FINOPS_STORAGE_BLOCKED_RESOURCE_ID, process.env.FINOPS_STORAGE_UNATTACHED_RESOURCE_ID];
  for (const id of resources) expect(id, "The actual Go fixture must issue each resource ID").toBeTruthy();
  expect(new Set(resources).size).toBe(3);
  const readyFile = process.env.FINOPS_STORAGE_READY_FILE;
  expect(readyFile, "The owned native fixture must publish its READY document").toBeTruthy();
  const stat = lstatSync(readyFile!);
  expect(stat.isFile() && !stat.isSymbolicLink() && stat.size > 0 && stat.size <= 8192).toBe(true);
  const ready = JSON.parse(readFileSync(readyFile!, "utf8")) as { schema_version: string; tenant_id: string; resource_ids: string[] };
  expect(Object.keys(ready).sort()).toEqual(["resource_ids", "schema_version", "tenant_id"]);
  expect(ready.schema_version).toBe("1"); expect(ready.tenant_id).toBe("tenant-demo"); expect(ready.resource_ids).toEqual(resources);
  const errors: string[] = [];
  page.on("pageerror", error => errors.push(error.message));
  let authorization = await signIn(page);
  const read = async <T,>(path: string): Promise<T> => {
    const response = await page.request.get(path, { headers: { Authorization: authorization } });
    expect(response.status()).toBe(200);
    return response.json() as Promise<T>;
  };
  const issued: Record[] = [];
  for (const [index, resourceID] of ready.resource_ids.entries()) {
    const resource = await read<Resource>(`/v1/resources/${encodeURIComponent(resourceID)}`);
    expect(resource.resource_type).toBe("EBS_VOLUME");
    expect(resource.storage_configuration).toBeTruthy();
    await navigation(page, "workloads");
    const row = page.getByRole("row").filter({ has: page.getByText(resource.provider_resource_id, { exact: true }) });
    await expect(row).toHaveCount(1);
    const response = page.waitForResponse(item => new URL(item.url()).pathname === "/v1/storage-assessments" && item.request().method() === "POST");
    await row.getByRole("button", { name: `Assess storage ${resource.name || resource.provider_resource_id}`, exact: true }).click();
    const queuedResponse = await response;
    expect(queuedResponse.status()).toBe(202);
    const request = queuedResponse.request();
    expect(request.postDataJSON()).toEqual({ resource_id: resourceID }); expect(request.headers()["if-match"]).toBe('"0"');
    const key = request.headers()["idempotency-key"]; expect(key).toBeTruthy();
    const queued = await queuedResponse.json() as Record;
    expect(queued.resource_id).toBe(resourceID);
    const replay = await page.request.post("/v1/storage-assessments", { headers: { Authorization: authorization, "If-Match": '"0"', "Idempotency-Key": key }, data: { resource_id: resourceID } });
    expect(replay.status()).toBe(202); expect((await replay.json() as Record).id).toBe(queued.id);
    let result: Record = queued;
    await expect.poll(async () => { result = await read<Record>(`/v1/storage-assessments/${encodeURIComponent(queued.id)}`); return result.status; }, { timeout: 60_000, intervals: [250, 500, 1000], message: "The actual separately credentialed storage analyst must publish the persisted result" }).toMatch(/^(ASSESSED|BLOCKED|FAILED)$/);
    expect(result.status).not.toBe("FAILED"); expect(result.assessment).not.toBeNull();
    const assessment = result.assessment!;
    expect(assessment.schema_version).toBe("1"); expect(assessment.model_version).toBe("storage-observed-demand-v1");
    expect(assessment.proposal).toEqual({ risk_class: "R3", executable: false, execution_authorized: false }); expect(assessment.verified_saving).toBeNull();
    expect(assessment.assessment_hash).toMatch(/^[a-f0-9]{64}$/); expect(assessment.model_assessment_hash).toMatch(/^[a-f0-9]{64}$/);
    expect(assessment.status).toBe(["RECOMMENDED", "BLOCKED", "OBSERVATION_ONLY"][index]);
    if (index === 1) {
      expect(result.status).toBe("BLOCKED"); expect(assessment.blockers.length).toBeGreaterThan(0);
    } else {
      expect(result.status).toBe("ASSESSED"); expect(result.current).toBe(true); expect(assessment.source_refs.length).toBeGreaterThan(0);
      expect(assessment.economics.currency).toBe("USD"); expect(assessment.economics.current_monthly_cost).toMatch(decimal);
      if (index === 0) {
        expect(assessment.recommendation_kind).toBe("STORAGE_GP2_TO_GP3"); expect(assessment.evidence_window).not.toBeNull(); expect(assessment.metric_distributions.length).toBeGreaterThan(0);
        expect(assessment.economics.estimated_monthly_saving).toMatch(decimal); expect(assessment.economics.estimated_monthly_saving).not.toMatch(/^(-|0(?:\.0*)?$)/);
        expect(assessment.economics.component_costs.some(component => component.continuing)).toBe(true);
      } else {
        expect(assessment.recommendation_kind).toBe("STORAGE_UNATTACHED_REVIEW"); expect(assessment.candidate_configuration).toBeNull();
        expect(assessment.economics.estimated_monthly_saving).toBeNull(); expect(assessment.unattached_review?.deletion_recommended).toBe(false);
      }
    }
    const dialog = page.getByRole("dialog", { name: "Storage assessment", exact: true });
    await dialog.getByRole("button", { name: "Refresh selected storage assessment", exact: true }).click();
    await expect(dialog).toContainText("R3 · Read-only proposal");
    await expect(dialog.getByRole("button", { name: /Create.*plan|Execute|Approve|Delete|Detach|ModifyVolume/ })).toHaveCount(0);
    await dialog.getByRole("button", { name: "Close dialog", exact: true }).click(); issued.push(result);
  }
  await page.reload(); authorization = await signIn(page);
  await inspectHistory(page, issued[0].id);
  const retained = await read<Record>(`/v1/storage-assessments/${encodeURIComponent(issued[0].id)}`);
  expect(retained.current).toBe(true); expect(retained.assessment).toEqual(issued[0].assessment);
  const dialog = page.getByRole("dialog", { name: "Storage assessment", exact: true });
  await expect(dialog).toContainText("Estimated monthly saving"); await expect(dialog.getByRole("region", { name: "Storage cost components", exact: true })).toBeVisible();
  await dialog.screenshot({ path: testInfo.outputPath("storage-assessment-persisted.png"), animations: "disabled" });
  await dialog.getByRole("button", { name: "Close dialog", exact: true }).click();
  const recommendations = await read<RecommendationPage>(`/v1/recommendations?model_kind=STORAGE_ASSESSMENT_V1&resource_id=${encodeURIComponent(ready.resource_ids[0])}&limit=100`);
  const recommendation = recommendations.items.find(item => item.storage_assessment_id === issued[0].id);
  expect(recommendation).toBeTruthy(); expect(recommendation!.id).toBeTruthy(); expect(recommendation!.pre_execution_ready).toBe(false);
  await navigation(page, "recommendations");
  const card = page.locator(".recommendation-card").filter({ has: page.getByRole("button", { name: `Inspect storage recommendation ${shortId(recommendation!.id!)}`, exact: true }) });
  await expect(card).toContainText("R3 · Storage proposal"); await expect(card.getByRole("button", { name: "Create change plan", exact: true })).toHaveCount(0);
  await navigation(page, "connections");
  const coverageResponse = page.waitForResponse(response => new URL(response.url()).pathname === "/v1/coverage");
  await page.getByText("Inspect assessed and unsupported spend", { exact: true }).click();
  const coverageHTTP = await coverageResponse; expect(coverageHTTP.status()).toBe(200);
  const coverage = await coverageHTTP.json() as S["AssessmentCoverage"];
  expect(coverage.groups.some(group => group.currency === "USD")).toBe(true);
  for (const group of coverage.groups) {
    expect(group.basis).toBe("POSITIVE_BILLED_CHARGES");
    if (!group.complete || group.detected_spend === "0") expect(group.analysed_percent).toBeNull();
  }
  await expect(page.getByRole("region", { name: "All AWS assessment spend coverage", exact: true })).toBeVisible(); expect(errors).toEqual([]);
  await testInfo.attach("storage-persisted-ids", { contentType: "application/json", body: JSON.stringify({ schema_version: "1", assessment_ids: issued.map(item => item.id), resource_ids: ready.resource_ids, proposal_execution_authorized: false, verified_saving: null }) });
});
