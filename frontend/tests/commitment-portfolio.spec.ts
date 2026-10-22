import { expect, type Page } from "@playwright/test";
import { test } from "./presentation";
import type { components } from "../src/api.generated";

// Explicit presentation doubles. These checks cannot authenticate native AWS,
// receipt readback, financial provenance or connected worker acceptance.
type S = components["schemas"];
const stamp = "2026-10-19T16:00:00Z", hash = "a".repeat(64);
const period = { start: "2026-10-01T00:00:00Z", end: "2026-10-15T00:00:00Z" };
const selection = { source_id: "source-issued", commitment_receipt_id: "commitment-issued", billing_receipt_ids: ["billing-issued"], period };
const ref = { kind: "AWS_COMMITMENT", id: "commitment-issued", sha256: hash };
function position(id: string, sparse = false): S["CommitmentPortfolioPositionAnalysis"] {
  return {
    expiry: { status: sparse ? "UNKNOWN" : "ACTIVE", remaining_seconds: sparse ? null : "2591999", within_days: 30, expires_within_window: sparse ? null : true },
    position: { reserved_instance_terms: null, id, account_id: "111122223333", class: sparse ? "EC2_RI_UNCLASSIFIED" : "COMPUTE_SAVINGS_PLAN", state: "active",
      region: sparse ? "eu-west-1" : null, instance_family: null, currency: sparse ? null : "USD", start: null, end: stamp,
      term_seconds: sparse ? null : "31536000", hourly_commitment: sparse ? null : "2.000000000000000001",
      upfront_amount: sparse ? null : "999999999999999999.123456789", recurring_amount: null, recurring_amount_unit: "UNAVAILABLE",
      payment_option: null, native_ref: ref, reason_codes: sparse ? ["RI_TERMS_UNAVAILABLE"] : [] },
    allocated_cost_basis: null, commitment_cost_basis: sparse ? "UNAVAILABLE" : "NATIVE_SP_HOURLY_TOTAL_AND_USED_COMMITMENT",
    observed_billed_cost: sparse ? null : "0", observed_allocated_cost: null, observed_committed_cost: sparse ? null : "10",
    observed_used_commitment: sparse ? null : "6", observed_unused_commitment: sparse ? null : "4", utilization: sparse ? null : "0.6", coverage: null, effective_discount: null,
    downside_if_zero_usage_observed_window: null, break_even_utilization: null, remaining_value: null, cash_requirement: null,
    expected_utilization: null, confidence_interval: null, status: sparse ? "UNKNOWN" : "OBSERVED_PARTIAL", reason_codes: ["COVERAGE_UNAVAILABLE"],
  };
}
function analysis(unavailable = false): S["CommitmentPortfolioAnalysis"] {
  return { schema_version: "1", id: "analysis-issued", request_id: "request-issued", selection, input_refs: [ref], observed_at: stamp,
    inventory_status: unavailable ? "UNAVAILABLE" : "COMPLETE_POINT_IN_TIME", billing_status: "PARTIAL",
    positions: unavailable ? [] : [position("sp-observed"), position("ri-sparse", true)],
    unmatched_billing: unavailable ? [] : [{ commitment_id: "retired-sp-unobserved", account_id: "444455556666", currency: "EUR", line_ids: ["issued-line-a"], observed_billed_cost: "3.25", reason_codes: ["COMMITMENT_NOT_IN_SELECTED_NATIVE_POINT"] }],
    partitions: unavailable ? [] : [
      { class: "COMPUTE_SAVINGS_PLAN", currency: "USD", account_id: "111122223333", region: null, instance_family: null, position_ids: ["sp-observed"], position_count: 1, observed_billed_cost: "0", observed_committed_cost: "10", observed_used_commitment: "6", observed_unused_commitment: "4", utilization: "0.6", expiring_position_ids: ["sp-observed"], hourly_commitment_rate: "2.000000000000000001", hourly_commitment_rate_unit: "currency/hour", position_shares: [{ position_id: "sp-observed", share: "1" }], concentration_basis: "NATIVE_HOURLY_COMMITMENT_RATE" },
      { class: "EC2_RI_UNCLASSIFIED", currency: "EUR", account_id: "444455556666", region: "eu-west-1", instance_family: null, position_ids: ["ri-sparse"], position_count: 1, observed_billed_cost: "2.30", observed_committed_cost: null, observed_used_commitment: null, observed_unused_commitment: null, utilization: null, expiring_position_ids: [], hourly_commitment_rate: null, hourly_commitment_rate_unit: "currency/hour", position_shares: [{ position_id: "ri-sparse", share: null }], concentration_basis: "NATIVE_HOURLY_COMMITMENT_RATE" },
    ], optimization_order: (["REMOVE_IDLE", "SCHEDULE", "RIGHTSIZE", "AUTOSCALE", "RECALCULATE_STABLE_DEMAND"] as const).map(stage => ({
      stage, status: "BLOCKED", decision_ref: null, outcome_ref: null, scope_sha256: null, reason_codes: ["EXACT_SCOPED_OUTCOME_REQUIRED"],
    })), recommendation_status: "BLOCKED", reason_codes: ["PURCHASE_NOT_AUTHORIZED"], expected_savings: null, estimated_saving: null,
    verified_saving: null, recommendation_authorized: false, purchase_authorized: false, execution_authorized: false };
}
async function setup(page: Page, mode: "normal" | "unavailable" | "refused" | "denied" = "normal") {
  const calls: { path: string; method: string; body?: unknown; version?: string; key?: string }[] = [];
  let queued = false;
  const row = (detail = false): S["CommitmentPortfolioRecord"] => ({ id: "request-issued", version: 1, creator_id: "finance",
    status: mode === "refused" ? "REFUSED" : queued ? "QUEUED" : "ASSESSED", selection, input_refs: [ref],
    analysis: detail && !queued && mode !== "refused" ? analysis(mode === "unavailable") : null,
    refusal: mode === "refused" ? { reason_code: "PORTFOLIO_INPUTS_CHANGED", observed_at: stamp } : null,
    created_at: stamp, execution_authorized: false, verified_saving: null });
  await page.addInitScript(() => { sessionStorage.setItem("finops.oidc.state", "presentation-state"); sessionStorage.setItem("finops.oidc.verifier", "presentation-verifier"); });
  await page.route("**/.well-known/openid-configuration", route => route.fulfill({ json: { token_endpoint: "http://127.0.0.1:4177/__portfolio-token" } }));
  await page.route("**/__portfolio-token", route => route.fulfill({ json: { access_token: "presentation-only", expires_in: 3600 } }));
  await page.route("**/v1/**", route => {
    const request = route.request(), url = new URL(request.url()), path = url.pathname;
    calls.push({ path, method: request.method(), ...(request.method() === "POST" ? { body: request.postDataJSON(), version: request.headers()["if-match"], key: request.headers()["idempotency-key"] } : {}) });
    const reply = (value: unknown, status = 200) => route.fulfill({ json: value, status });
    if (mode === "denied") return reply({ message: "Portfolio finance permission required." }, 403);
    if (path === "/v1/commitment-portfolio-sources") return reply({ items: [{ id: url.searchParams.has("cursor") ? "source-issued" : "source-other",
      version: 3, status: "HEALTHY", payer_account_id: "111122223333", usage_account_count: 1, region: "eu-west-1", commitment_receipt_id: "commitment-issued" }], next_cursor: url.searchParams.has("cursor") ? null : "opaque-source" });
    if (path.endsWith("/receipts")) {
      const native = url.searchParams.get("kind") === "AWS_COMMITMENT", id = native ? "commitment-issued" : "billing-issued";
      return reply({ items: [{ id: url.searchParams.has("cursor") ? id : id + "-old", kind: native ? "AWS_COMMITMENT" : "AWS_CUR2", source_id: "source-issued",
        observed_at: stamp, current: url.searchParams.has("cursor"), period: native ? null : period, proof_state: "COMPLETE" }], next_cursor: url.searchParams.has("cursor") ? null : "opaque-" + id });
    }
    if (path === "/v1/commitment-portfolio-analyses") {
      if (request.method() === "POST") { queued = true; return reply(row(true), 202); }
      return reply({ items: [{ ...row(), analysis: null, analysis_summary: queued || mode === "refused" ? null : { id: "analysis-issued", inventory_status: analysis(mode === "unavailable").inventory_status, billing_status: "PARTIAL", position_count: mode === "unavailable" ? 0 : 2, recommendation_status: "BLOCKED", execution_authorized: false, verified_saving: null } }], next_cursor: null });
    }
    if (path === "/v1/commitment-portfolio-analyses/request-issued") return reply(row(true));
    return reply({ message: "Unmocked presentation request." }, 501);
  });
  await page.goto("/tests/fixtures/commitment-portfolio.html?code=presentation-code&state=presentation-state");
  return { calls, complete: () => { queued = false; } };
}
async function inspect(page: Page) {
  await page.getByText("Commitment portfolio evidence", { exact: true }).click();
  await page.getByRole("button", { name: "Inspect commitment analysis request-issued", exact: true }).click();
}

test("portfolio retains exact zero and observed utilization, expiry, concentration and sparse RI unknown", async ({ page }) => {
  const state = await setup(page);
  expect(state.calls).toEqual([]);
  await inspect(page);
  await expect(page.getByRole("region", { name: "Observed commitment partitions", exact: true })).toContainText("0 USD");
  await expect(page.getByRole("region", { name: "Observed commitment partitions", exact: true })).toContainText("2.30 EUR");
  await page.locator("summary").filter({ hasText: "sp-observed" }).click();
  const metrics = page.getByRole("region", { name: "Observed commitment metrics sp-observed", exact: true });
  await expect(metrics.getByRole("row").filter({ hasText: /^Utilization/ })).toContainText("0.6 (fraction)");
  await expect(metrics.getByRole("row").filter({ hasText: /^Coverage/ })).toContainText("Unavailable");
  await expect(metrics.getByRole("row").filter({ hasText: /^Observed unused commitment/ })).toContainText("4 USD");
  await expect(page.getByRole("region", { name: "Commitment expiry sp-observed", exact: true })).toContainText("2591999");
  await page.getByText("Partition observations · 111122223333", { exact: false }).click();
  await expect(page.getByRole("region", { name: /^Native commitment concentration/ }).getByRole("row").filter({ hasText: "sp-observed" })).toContainText("1 (fraction)");
  await page.getByText("Observed native terms", { exact: true }).click();
  await expect(page.getByRole("region", { name: "Native commitment terms sp-observed", exact: true })).toContainText("999999999999999999.123456789 USD");
  await page.locator("summary").filter({ hasText: "ri-sparse" }).click();
  await expect(page.getByRole("region", { name: "Observed commitment metrics ri-sparse", exact: true })).not.toContainText("0 USD");
  await expect(page.getByRole("region", { name: "Commitment optimization prerequisites", exact: true }).locator("ol > li")).toHaveCount(5);
  await expect(page.getByRole("region", { name: "Unmatched observed commitment costs", exact: true })).toContainText("3.25 EUR");
  await expect(page.getByText("Recommendation, purchase and execution disabled.", { exact: false })).toBeVisible();
});

test("portfolio selects paged issued IDs and queues with initial CAS then refreshes persisted detail", async ({ page }) => {
  const state = await setup(page);
  await page.getByText("Commitment portfolio evidence", { exact: true }).click();
  await page.getByRole("button", { name: "Analyze commitment portfolio", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "Analyze commitment portfolio", exact: true });
  await dialog.getByRole("button", { name: "Load more commitment portfolio sources", exact: true }).click();
  // The production label has adjacent inline ID/account text. Whitespace is
  // not part of its accessible-name contract; choose the exact issued ID child.
  await expect(dialog.getByRole("radio", { name: /^source-issued\s/ })).toHaveCount(0);
  await dialog.locator("label.choice-card").filter({ has: page.getByText("source-issued", { exact: true }) }).getByRole("radio").check();
  await dialog.getByRole("button", { name: "Load more native commitment receipts", exact: true }).click();
  await dialog.locator("label.choice-card").filter({ has: page.getByText("commitment-issued", { exact: true }) }).getByRole("radio").check();
  await dialog.getByRole("button", { name: "Load more canonical billing receipts", exact: true }).click();
  await dialog.locator("label.choice-card").filter({ has: page.getByText("billing-issued", { exact: true }) }).getByRole("checkbox").check();
  await dialog.getByLabel("Portfolio interval start", { exact: true }).fill("2026-10-01");
  await dialog.getByLabel("Portfolio interval end (exclusive)", { exact: true }).fill("2026-10-15");
  await dialog.getByRole("button", { name: "Request commitment analysis", exact: true }).click();
  await expect(page.getByText("Queued for the read-only analysis worker.", { exact: false })).toBeVisible();
  const submitted = state.calls.find(row => row.method === "POST");
  expect(submitted?.body).toEqual(selection);
  expect(submitted?.version).toBe('"0"');
  expect(submitted?.key).toBeTruthy();
  state.complete();
  await page.getByRole("button", { name: "Refresh selected commitment analysis", exact: true }).click();
  await expect(page.getByRole("region", { name: "Observed commitment positions", exact: true })).toBeVisible();
  await page.goto("/tests/fixtures/commitment-portfolio.html?code=presentation-code&state=presentation-state");
  await inspect(page);
  await expect(page.getByText("Analysis analysis-issued", { exact: false })).toBeVisible();
});

test("unavailable portfolio population is never displayed as an observed zero", async ({ page }) => {
  await setup(page, "unavailable"); await inspect(page);
  await expect(page.getByText("Position population unavailable.", { exact: false })).toBeVisible();
  await expect(page.getByText("0 observed positions", { exact: true })).toHaveCount(0);
  await expect(page.getByText("Partition observations unavailable.", { exact: true })).toBeVisible();
});

test("refused and finance-denied portfolio reads expose no usable analysis or authority", async ({ page }) => {
  await setup(page, "refused"); await inspect(page);
  await expect(page.getByRole("alert").filter({ hasText: "Analysis refused." })).toContainText("Portfolio inputs changed");
  await expect(page.getByRole("region", { name: "Observed commitment positions", exact: true })).toHaveCount(0);
  await setup(page, "denied");
  await page.getByText("Commitment portfolio evidence", { exact: true }).click();
  await expect(page.getByRole("alert")).toContainText("Portfolio finance permission required");
});
