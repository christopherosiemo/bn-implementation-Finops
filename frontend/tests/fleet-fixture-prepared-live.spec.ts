import { expect, test, type Response, type Page } from "@playwright/test";
import type { components } from "../src/api.generated";
import type { Dashboard } from "../src/types";

type Record = components["schemas"]["FleetFixtureProposalRecord"];
type Prepared = components["schemas"]["FleetFixturePreparedProgram"];
const uuid = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const sha = /^[a-f0-9]{64}$/;

async function signIn(page: Page, username: string) {
  await page.goto("/");
  await page.getByRole("button", { name: "Sign in to your workspace", exact: true }).click();
  await page.getByRole("textbox", { name: /username/i }).fill(username);
  await page.getByLabel("Password", { exact: true }).fill(process.env.FINOPS_E2E_PASSWORD || "local-pilot-demo");
  const [response] = await Promise.all([
    page.waitForResponse(reply => new URL(reply.url()).pathname === "/v1/dashboard" && reply.ok()),
    page.getByRole("button", { name: "Sign In", exact: true }).click(),
  ]);
  const dashboard = await response.json() as Dashboard;
  expect(dashboard.fixture, "Only the explicitly labelled retained local fixture is accepted.").toBe(true);
  const authorization = response.request().headers().authorization;
  expect(authorization).toMatch(/^Bearer /);
  return { dashboard, authorization };
}

async function inspectProposal(page: Page, id: string) {
  await page.getByRole("link", { name: "Workloads & resources", exact: true }).click();
  const [first] = await Promise.all([
    page.waitForResponse(reply => {
      const u = new URL(reply.url());
      return u.pathname === "/v1/fleet-fixture-proposals" && u.searchParams.get("workload_id") === "workload-dev" && !u.searchParams.has("cursor") && reply.ok();
    }),
    page.getByRole("combobox", { name: "Fleet history workload", exact: true }).selectOption("workload-dev"),
  ]);
  let current = await first.json() as components["schemas"]["FleetFixtureProposalPage"];
  const section = page.getByRole("region", { name: "Isolated group fixture proposals", exact: true });
  const inspect = section.getByRole("button", { name: `Inspect fixture proposal ${id.slice(0, 12)}…${id.slice(-6)}`, exact: true });
  const cursors = new Set<string>();
  while (!current.items.some(row => row.id === id)) {
    expect(current.next_cursor, "Actual cursor pages must expose this authorized persisted proposal.").toBeTruthy();
    const cursor = current.next_cursor!;
    expect(cursors.has(cursor)).toBe(false); cursors.add(cursor);
    const [response] = await Promise.all([
      page.waitForResponse(reply => {
        const u = new URL(reply.url());
        return u.pathname === "/v1/fleet-fixture-proposals" && u.searchParams.get("cursor") === cursor && reply.ok();
      }),
      section.getByRole("button", { name: "Load more fixture proposals", exact: true }).click(),
    ]);
    current = await response.json() as components["schemas"]["FleetFixtureProposalPage"];
    expect(current.items.length).toBeGreaterThan(0);
    await expect(section.getByRole("button", { name: `Inspect fixture proposal ${current.items.at(-1)!.id.slice(0, 12)}…${current.items.at(-1)!.id.slice(-6)}`, exact: true })).toBeVisible();
  }
  await inspect.click();
  return page.getByRole("dialog", { name: "Isolated group fixture proposal", exact: true });
}

// Only the documented source-sync busy response may be retried, with the
// identical request body, If-Match and idempotency key. No Playwright retry or
// generic409/503 retry can create a second approval or hide an authority error.
async function settleSourceBusy(page: Page, response: Response, authorization: string, source: string) {
  if (response.status() !== 503) return response;
  const body = await response.json();
  expect(body.error).toBe("FLEET_FIXTURE_SOURCE_BUSY");
  const request = response.request();
  const headers = request.headers(), data = request.postDataJSON();
  expect(data).toEqual({});
  await expect.poll(async () => {
    const current = await page.request.get(`/v1/source-connections/${source}`, { headers: { Authorization: authorization } });
    expect(current.status()).toBe(200);
    return (await current.json()).status;
  }).toBe("HEALTHY");
  return page.request.post(new URL(request.url()).pathname, { headers: { Authorization: authorization, "If-Match": headers["if-match"], "Idempotency-Key": headers["idempotency-key"] }, data });
}

test("real OIDC privately prepared fixture program receives an independent exact-program approval without execution authority", async ({ page, browser }) => {
  const proposalID = process.env.FINOPS_E2E_PREPARED_PROPOSAL_ID || "";
  const preparedID = process.env.FINOPS_E2E_PREPARED_PROGRAM_ID || "";
  const programHash = process.env.FINOPS_E2E_PREPARED_PROGRAM_SHA256 || "";
  expect(proposalID, "The private preparer harness must select the actual persisted proposal; no optional skip.").toMatch(uuid);
  expect(preparedID).toMatch(uuid); expect(programHash).toMatch(sha);
  const errors: string[] = []; page.on("pageerror", error => errors.push(error.message));
  const owner = await signIn(page, "owner");
  const get = async (p: Page, auth: string, suffix = "") => {
    const result = await p.request.get(`/v1/fleet-fixture-proposals/${proposalID}${suffix}`, { headers: { Authorization: auth } });
    expect(result.status()).toBe(200); return result;
  };
  const original = await (await get(page, owner.authorization)).json() as Record;
  expect(original.status).toBe("AWAITING_APPROVAL"); expect(original.approval).toBeNull();
  expect(original.prepared_program!.id).toBe(preparedID);
  const prepared = await (await get(page, owner.authorization, "/prepared-program")).json() as Prepared;
  expect(prepared.id).toBe(preparedID); expect(prepared.program_hash).toBe(programHash);
  expect(prepared.producer_role).toBe("finops_group_fixture"); expect(prepared.program.manifest.entries).toHaveLength(26);
  expect(prepared.program.realm.kind).toBe("ISOLATED_FIXTURE");
  expect(prepared.program.binding).toEqual(original.proposal.binding);
  const source = original.proposal.binding.old.source_id;
  expect(original.proposal.binding.candidate.source_id).toBe(source);
  const review = await inspectProposal(page, proposalID);
  const exact = review.getByRole("region", { name: "Exact prepared fixture program", exact: true });
  await expect(exact.getByText(programHash, { exact: true })).toBeVisible();
  await expect(exact.getByText(prepared.manifest_hash, { exact: true })).toBeVisible();
  await expect(exact.getByText(prepared.journal_review_hash, { exact: true })).toBeVisible();
  await expect(exact.getByRole("region", { name: "Complete prepared fixture Git manifest", exact: true }).locator("tbody tr")).toHaveCount(26);
  await expect(review.getByText(/Customer execution remains disabled/)).toBeVisible();
  await review.getByRole("checkbox", { name: /I reviewed this exact fixture program/ }).check();
  const [self] = await Promise.all([
    page.waitForResponse(reply => new URL(reply.url()).pathname === `/v1/fleet-fixture-proposals/${proposalID}/approvals` && reply.request().method() === "POST"),
    review.getByRole("button", { name: "Approve exact fixture program", exact: true }).click(),
  ]);
  const selfResult = await settleSourceBusy(page, self, owner.authorization, source);
  expect(selfResult.status()).toBe(403); expect((await selfResult.json()).error).toBe("FLEET_FIXTURE_INDEPENDENT_APPROVER_REQUIRED");
  expect((await (await get(page, owner.authorization)).json()).approval).toBeNull();

  // Console bearer tokens cannot upload a prepared program or manufacture a
  // private authorization draft, even when they have broad console roles.
  for (const suffix of ["/prepared-program", "/authorization-drafts"]) {
    const refused = await page.request.post(`/v1/fleet-fixture-proposals/${proposalID}${suffix}`, { headers: { Authorization: owner.authorization, "If-Match": `"${original.version}"`, "Idempotency-Key": crypto.randomUUID() }, data: {} });
    expect(refused.status()).toBe(404);
  }
  const context = await browser.newContext();
  try {
    const approverPage = await context.newPage(); approverPage.on("pageerror", error => errors.push(error.message));
    const approver = await signIn(approverPage, "approver");
    const dialog = await inspectProposal(approverPage, proposalID);
    const exactReview = dialog.getByRole("region", { name: "Exact prepared fixture program", exact: true });
    await expect(exactReview.getByText(programHash, { exact: true })).toBeVisible();
    await expect(exactReview.getByText(prepared.journal_review.pipeline_key_sha256, { exact: true })).toBeVisible();
    await expect(exactReview.getByText(prepared.journal_review.ledger_key_sha256, { exact: true })).toBeVisible();
    await dialog.getByRole("checkbox", { name: /I reviewed this exact fixture program/ }).check();
    const [approvalResponse] = await Promise.all([
      approverPage.waitForResponse(reply => new URL(reply.url()).pathname === `/v1/fleet-fixture-proposals/${proposalID}/approvals` && reply.request().method() === "POST"),
      dialog.getByRole("button", { name: "Approve exact fixture program", exact: true }).click(),
    ]);
    expect(approvalResponse.request().postDataJSON()).toEqual({});
    expect(approvalResponse.request().headers()["if-match"]).toBe(`"${original.version}"`);
    const approvedResponse = await settleSourceBusy(approverPage, approvalResponse, approver.authorization, source);
    expect(approvedResponse.status()).toBe(201);
    const approved = await approvedResponse.json() as Record;
    expect(approved.version).toBe(original.version + 1); expect(approved.status).toBe("APPROVED");
    expect(approved.approval!.actor_id).not.toBe(original.proposal.creator_id);
    expect(approved.approval!.role).toBe("fleet_approver");
    expect(approved.approval!.approval_scope).toBe("EXACT_FIXTURE_PROGRAM_AND_JOURNAL_REVIEW");
    expect(approved.approval!.program_hash).toBe(programHash); expect(approved.approval!.manifest_hash).toBe(prepared.manifest_hash);
    expect(approved.approval!.journal_review_hash).toBe(prepared.journal_review_hash);
    expect(approved.approval!.customer_execution_authorized).toBe(false); expect(approved.approval!.verified_saving).toBeNull();
    await dialog.getByRole("button", { name: "Refresh fixture proposal", exact: true }).click();
    await expect(dialog.getByRole("heading", { name: "Independent program approval", exact: true })).toBeVisible();
    await expect(dialog.getByText(`Approved by ${approved.approval!.actor_id}`, { exact: false })).toBeVisible();
    await expect(dialog.getByRole("button", { name: "Approve exact fixture program", exact: true })).toHaveCount(0);
    const persisted = await (await get(approverPage, approver.authorization)).json() as Record;
    expect(persisted.approval).toEqual(approved.approval);
    expect(persisted.prepared_program).toEqual(approved.prepared_program);
    expect((await (await get(approverPage, approver.authorization, "/authorization-drafts")).json()).items).toEqual([]);
    const runs = await (await get(approverPage, approver.authorization, "/runs")).json() as components["schemas"]["FleetFixtureRunPage"];
    expect(runs.items).toEqual([]); expect(runs.status).toBe("UNAVAILABLE");
    const run = await page.request.post(`/v1/fleet-fixture-proposals/${proposalID}/runs`, { headers: { Authorization: owner.authorization, "If-Match": `"${approved.version}"`, "Idempotency-Key": crypto.randomUUID() }, data: {} });
    expect(run.status()).toBe(503); expect((await run.json()).error).toBe("FLEET_FIXTURE_RUNTIME_NOT_CONNECTED");
    expect((await (await get(page, owner.authorization)).json()).approval).toEqual(approved.approval);
    await test.info().attach("actual-fixture-program-approval.json", { body: JSON.stringify({ proposal_id: proposalID, prepared_program_id: preparedID, program_sha256: programHash, manifest_sha256: prepared.manifest_hash, approval_id: approved.approval!.id, approval_sha256: approved.approval!.hash, actual_oidc_independent_approval: true, journal_authorization_approved: false, customer_execution_authorized: false, verified_saving: null }), contentType: "application/json" });
  } finally { await context.close(); }
  expect(errors).toEqual([]);
});
