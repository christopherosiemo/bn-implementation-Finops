import { expect, type Page } from "@playwright/test";
import { test } from "./presentation";

// Presentation doubles. Actual repository/native producer acceptance is a
// separate gate; these rows do not authenticate observations or authority.
const hash = "a".repeat(64), stamp = "2026-10-19T13:00:00Z";
const selection = { safety_profile: { id: "profile", version: 3, sha256: hash }, groups: {} };
const scenario = (difference: string | null = "0.16") => ({
  status: difference === null ? "UNAVAILABLE" : "OBSERVED_CONDITIONAL", currency: difference === null ? null : "USD", rate_basis: "OBSERVED_NET_ACCOUNT_RATE",
  member_count: difference === null ? 0 : 2, old_hourly_rate: difference === null ? null : "0.20", candidate_hourly_rate: difference === null ? null : "0.12",
  old_hourly_compute: difference === null ? null : "0.40", candidate_hourly_compute: difference === null ? null : "0.24", hourly_compute_difference: difference,
  contracted_avoidable_cost: null, estimated_saving: null, verified_saving: null, hard_spend_cap: false, excluded_costs: ["COMMITMENTS"],
});
const result = (difference: string | null = "0.16") => ({
  schema_version: "1", id: "decision-one", request_id: "request-one", selection, observed_at: stamp,
  inputs: [{ id: "assessment-issued", sha256: hash }, { id: "scope-issued", sha256: hash }, { id: "batch-issued", sha256: hash }],
  members: [{ instance_id: "i-original-one", result: { id: "member-result", sha256: hash }, status: "FAIL", dimensions: [
    { name: "cpu", unit: "vCPU", status: "PASS", candidate_capacity: "2", required_with_reserve: "1.3", reason_codes: [] },
    { name: "memory", unit: "bytes", status: "FAIL", candidate_capacity: "8589934592", required_with_reserve: "21217138442.24", reason_codes: ["MEMORY_P95_PLANNING_LIMIT"] },
    { name: "network", unit: "bytes/second", status: "UNKNOWN", candidate_capacity: null, required_with_reserve: null, reason_codes: ["REQUIRED_PHYSICAL_STATISTICS_UNAVAILABLE"] },
    { name: "storage_iops", unit: "operations/second", status: "PASS", candidate_capacity: "3000", required_with_reserve: "0", reason_codes: [] },
    { name: "storage_throughput", unit: "bytes/second", status: "UNKNOWN", candidate_capacity: null, required_with_reserve: null, reason_codes: ["REQUIRED_PHYSICAL_CHECK_UNAVAILABLE"] },
  ] }], physical_status: "FAIL", scenario: scenario(difference), contracted_avoidable_cost: null, estimated_saving: null, verified_saving: null,
  status: "BLOCKED", group_capacity_authorized: false, completed_business_work_preserved: null, plan_eligible: false, execution_authorized: false, change_plan_id: null,
  reason_codes: ["PLAN_AND_EXECUTION_NOT_AUTHORIZED"],
});
async function setup(page: Page, options: { difference?: string | null; denied?: boolean; queued?: boolean; conflict?: boolean; refused?: boolean } = {}) {
  const calls: { path: string; search: string; body?: unknown; version?: string; key?: string }[] = [];
  let queued = options.queued ?? false, profile = 3, conflicted = false;
  const row = (id = "request-one", detail = false) => ({
    schema_version: "1", id, version: 1, workload_id: "workload-one", creator_id: "owner", assessment_request_id: "assessment-issued", capacity_batch_request_id: "batch-issued",
    selection, input_refs: result().inputs, execution_authorized: false, verified_saving: null, created_at: stamp, status: options.refused ? "REFUSED" : queued ? "QUEUED" : "ASSESSED",
    decision: detail && !queued && !options.refused ? result(options.difference) : null, refusal: options.refused ? {schema_version:"1",id:"refusal-one",request_id:id,reason_codes:["RATE_ARITHMETIC_OR_UNSUPPORTED_PRECISION"],observed_at:stamp,execution_authorized:false,verified_saving:null} : null,
    decision_summary: detail || queued || options.refused ? null : { id: "decision-one", physical_status: "FAIL", status: "BLOCKED", member_count: 1, scenario: scenario(options.difference), execution_authorized: false, verified_saving: null },
  });
  await page.addInitScript(() => { sessionStorage.setItem("finops.oidc.state", "presentation-state"); sessionStorage.setItem("finops.oidc.verifier", "presentation-verifier"); });
  await page.route("**/.well-known/openid-configuration", route => route.fulfill({ json: { authorization_endpoint: "http://127.0.0.1:4177/unused", token_endpoint: "http://127.0.0.1:4177/__joint-token" } }));
  await page.route("**/__joint-token", route => route.fulfill({ json: { access_token: "presentation-only", expires_in: 3600 } }));
  await page.route("**/v1/**", route => {
    const req = route.request(), url = new URL(req.url()), path = url.pathname;
    calls.push({ path, search: url.search, ...(req.method() === "POST" ? { body: req.postDataJSON(), version: req.headers()["if-match"], key: req.headers()["idempotency-key"] } : {}) });
    const reply = (json: unknown, status = 200) => route.fulfill({ json, status });
    if (options.denied) return reply({ message: "Current workload access required." }, 403);
    if (path.endsWith("/safety-profiles")) return reply({ latest: { id: "profile", version: profile }, items: [], next_cursor: null });
    if (path.endsWith("/fleet-native-assessments") || path.endsWith("/fleet-native-capacity-batches")) {
      const id = path.endsWith("/fleet-native-assessments") ? "assessment-issued" : "batch-issued";
      return reply({ items: [{ id: url.searchParams.has("cursor") ? id : `queued-${id}`, status: url.searchParams.has("cursor") ? "ASSESSED" : "QUEUED", created_at: stamp }], next_cursor: url.searchParams.has("cursor") ? null : `opaque-${id}` });
    }
    if (path.endsWith("/fleet-joint-decisions")) {
      if (req.method() === "POST") {
        if (options.conflict && !conflicted) { conflicted = true; profile = 4; return reply({ message: "Safety profile changed.", reason_code: "VERSION_CONFLICT" }, 412); }
        queued = true; return reply(row("request-one", true), 202);
      }
      return reply({ items: [row(url.searchParams.has("cursor") ? "request-two" : "request-one")], next_cursor: url.searchParams.has("cursor") ? null : "opaque-joint-page" });
    }
    if (path.startsWith("/v1/fleet-joint-decisions/")) return reply(row(path.split("/").at(-1), true));
    return reply({ message: "Unmocked presentation request." }, 501);
  });
  await page.goto("/tests/fixtures/fleet-joint-decision.html?code=presentation-code&state=presentation-state");
  await page.getByText("Joint fleet evidence", { exact: true }).click();
  return { calls, complete: () => { queued = false; } };
}
async function selectIssued(page: Page) {
  await page.getByRole("button", { name: "Combine fleet analysis", exact: true }).click();
  await page.getByRole("button", { name: "Load more issued native assessments" }).click();
  await page.getByRole("radio", { name: /assessment-issued.*Assessed/ }).check();
  await page.getByRole("button", { name: "Load more issued capacity batches" }).click();
  await page.getByRole("radio", { name: /batch-issued.*Assessed/ }).check();
}

test("joint evidence loads details lazily and retains all five tri-state physical checks", async ({ page }) => {
  const state = await setup(page);
  await expect(page.getByText("Physical observations: FAIL", { exact: true })).toBeVisible();
  expect(state.calls.some(call => call.path === "/v1/fleet-joint-decisions/request-one")).toBe(false);
  await page.getByRole("button", { name: "Inspect joint decision request-one" }).click();
  await expect(page.getByText("0.16 USD/hour", { exact: true })).toBeVisible();
  await page.getByText("i-original-one · physical checks FAIL", { exact: true }).click();
  const table = page.getByRole("region", { name: "Physical dimensions for i-original-one" }).getByRole("table");
  await expect(table.getByRole("row")).toHaveCount(6);
  await expect(table.getByRole("row").filter({ hasText: "Network" })).toContainText("UNKNOWN");
  await expect(table.getByRole("row").filter({ hasText: "Storage iops" })).toContainText("0");
  await expect(page.getByText("Execution disabled. No change plan is authorized.")).toBeVisible();
});

for (const difference of ["0", "-0.16", "99999999999999999999999999.123456789012", null]) test(`joint scenario preserves ${difference ?? "unknown"} without a savings claim`, async ({ page }) => {
  await setup(page, { difference });
  await page.getByRole("button", { name: "Inspect joint decision request-one" }).click();
  const table = page.getByRole("region", { name: "Joint conditional hourly scenario" }).getByRole("table");
  await expect(table.getByRole("row").filter({ hasText: "Conditional hourly compute difference" })).toContainText(difference === null ? "Unavailable" : `${difference} USD/hour`);
  for (const label of ["Contracted avoidable cost", "Estimated savings", "Verified savings"]) await expect(table.getByRole("row").filter({ hasText: label })).toContainText("Unavailable");
});

test("joint request follows scoped issued pages and persists a queued result through refresh", async ({ page }) => {
  const state = await setup(page);
  await selectIssued(page);
  await page.getByRole("button", { name: "Request joint fleet analysis", exact: true }).click();
  const write = state.calls.find(call => call.body !== undefined)!;
  expect(write.body).toEqual({ assessment_request_id: "assessment-issued", capacity_batch_request_id: "batch-issued" });
  expect(write.version).toBe('"3"'); expect(write.key).toBeTruthy();
  await expect(page.getByText("Queued for the analysis worker.", { exact: false })).toBeVisible();
  state.complete(); await page.getByRole("button", { name: "Refresh selected joint decision" }).click();
  await expect(page.getByText("0.16 USD/hour", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Load more joint fleet decisions" }).click();
  await expect(page.getByRole("button", { name: "Inspect joint decision request-two" })).toBeVisible();
  expect(state.calls.filter(call => call.search.includes("cursor=")).every(call => call.search.includes("limit=10"))).toBe(true);
});

test("joint profile CAS refusal preserves selections and requires a fresh profile read", async ({ page }) => {
  const state = await setup(page, { conflict: true });
  await selectIssued(page); await page.getByRole("button", { name: "Request joint fleet analysis", exact: true }).click();
  await expect(page.getByText("Request could not be confirmed.", { exact: false })).toBeVisible();
  await page.getByRole("button", { name: "Refresh safety profile" }).click();
  await expect(page.getByText("Safety profile revision 4.", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Request joint fleet analysis", exact: true }).click();
  const writes = state.calls.filter(call => call.body !== undefined);
  expect(writes.map(write => write.version)).toEqual(['"3"', '"4"']);
  expect(writes[0].key).not.toBe(writes[1].key);
});

test("joint history access refusal exposes no analytical result", async ({ page }) => {
  await setup(page, { denied: true });
  await expect(page.getByRole("alert")).toContainText("Current workload access required");
  await expect(page.getByRole("button", { name: /Inspect joint decision/ })).toHaveCount(0);
});

test("joint terminal refusal is explicit and contains no analytical result",async({page})=>{await setup(page,{refused:true});await page.getByRole("button",{name:"Inspect joint decision request-one"}).click();await expect(page.getByRole("alert")).toContainText("Joint analysis refused");await expect(page.getByRole("alert")).toContainText("Rate arithmetic or unsupported precision");await expect(page.getByText("Per-member physical checks",{exact:true})).toHaveCount(0);});
