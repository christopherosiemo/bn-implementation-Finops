import { expect, type Page } from "@playwright/test";
import { test } from "./presentation";
import type { components } from "../src/api.generated";

// Supplementary presentation doubles. Authentic offers, account PAYG rates,
// model provenance and independent Finance enforcement require the real path.
type S = components["schemas"];
const stamp = "2026-10-19T18:00:00Z", hash = "a".repeat(64), fullHash = "b".repeat(64);
const period = { start: "2026-10-01T00:00:00Z", end: "2026-10-15T00:00:00Z" };
const projection = { start: "2026-10-20T00:00:00Z", end: "2027-10-20T00:00:00Z" };
const selection = { portfolio_analysis_request_id: "portfolio-issued", offer_receipt_id: "offer-issued", post_optimization_assessment_id: "optimization-issued", forecast_id: "forecast-issued" };
const ref = { kind: "ISSUED_NATIVE", id: "receipt-issued", sha256: hash };
const kinds = [
  ["PORTFOLIO_ANALYSIS", "portfolio-issued", "Portfolio analysis"], ["OFFER", "offer-issued", "Native offer receipt"],
  ["POST_OPTIMIZATION_ASSESSMENT", "optimization-issued", "Post-optimization assessment"], ["FORECAST", "forecast-issued", "Issued forecast"],
] as const;
function metric(value: string | null, unit: S["CommitmentDecisionMetric"]["unit"] = "fraction", basis = "ISSUED_OBSERVED_BASIS", span = period): S["CommitmentDecisionMetric"] {
  return { status: value === null ? "UNAVAILABLE" : "AVAILABLE", value, unit, currency: unit === "currency" || unit === "currency/hour" ? "USD" : null, basis, period: span, reason_codes: value === null ? ["ISSUED_CALIBRATION_REQUIRED"] : [], input_refs: [ref] };
}
function decision(status: S["CommitmentDecision"]["status"] = "RECOMMEND_PURCHASE_PENDING_FINANCE"): S["CommitmentDecision"] {
  const blocked = status === "BLOCKED";
  const downside = metric(blocked ? null : "12345.6789", "currency", "HELD_CURRENT_NATIVE_NET_RATE", projection);
  const cashPeriod = { start: stamp, end: projection.end };
  return { schema_version: "2", id: "decision-content-id", request_id: "decision-request", selection,
    scope: { tenant_id: "tenant-presentation", workload_id: "workload-issued", payer_account_id: "111122223333", usage_account_ids: ["111122223333"], resource_ids: ["resource-issued"], class: "COMPUTE_SAVINGS_PLAN", currency: "USD", configuration_sha256: hash, ownership_ref: ref, history_period: period, projection_period: projection, sha256: hash },
    input_refs: [ref], status, observed_coverage: metric(blocked ? null : "0"), observed_effective_discount: metric(blocked ? null : "0.333333333333333333"), observed_unused_exposure: metric(blocked ? null : "0", "currency"),
    computation_policy: "DECIMAL80_INTERMEDIATE_HALF_EVEN_12_FINAL", proposed_hourly_commitment: metric(blocked ? null : "999999999999999999.123456789", "currency/hour", "HELD_CURRENT_NATIVE_NET_RATE", projection), proposed_term_obligation: metric(blocked ? null : "12345.6789", "currency", "HELD_CURRENT_NATIVE_NET_RATE", projection), expected_utilization: metric(blocked ? null : "0.9", "fraction", "ISSUED_SCOPED_FORECAST", projection), break_even_utilization: metric(blocked ? null : "0.7", "fraction", "HELD_CURRENT_NATIVE_NET_RATE", projection), expected_savings: metric(blocked ? null : status === "DO_NOT_PURCHASE" ? "-1.000000000000000001" : "12.34567890123456789", "currency", "HELD_CURRENT_NATIVE_NET_RATE", projection),
    downside_exposure: downside, cash_requirement: metric(blocked ? null : "0", "currency", "HELD_CURRENT_NATIVE_NET_RATE", projection), remaining_contractual_obligation: metric(null, "currency", "UNAVAILABLE_NATIVE_PROOF", cashPeriod), paid_unamortized_value: metric(null, "currency", "UNAVAILABLE_NATIVE_PROOF", cashPeriod), forward_price_assumption: "HELD_CURRENT_NATIVE_NET_RATE",
    price_change_stress: { status: blocked ? "UNAVAILABLE" : "AVAILABLE", assumption: "HELD_CURRENT_NATIVE_NET_RATE", break_even_payg_rate_drop_fraction: blocked ? null : "0.15", zero_usage_loss: downside, reason_codes: [] },
    confidence: blocked
      ? { status: "UNAVAILABLE", lower_expected_savings: null, upper_expected_savings: null, coverage: null, method: null, calibration_ref: null, reason_codes: ["ISSUED_CALIBRATION_REQUIRED"] }
      : { status: "AVAILABLE", lower_expected_savings: status === "DO_NOT_PURCHASE" ? "-2" : "5", upper_expected_savings: status === "DO_NOT_PURCHASE" ? "0" : "20", coverage: "0.9", method: "ROLLING_ORIGIN_TERM_BLOCK_V1", calibration_ref: { kind: "FORECAST_CALIBRATION", id: "calibration-issued", sha256: hash }, reason_codes: ["DEPENDENT_EMPIRICAL_TERM_WINDOWS"] },
    optimization_order: (["REMOVE_IDLE", "SCHEDULE", "RIGHTSIZE", "AUTOSCALE", "RECALCULATE_STABLE_DEMAND"] as const).map(stage => ({ stage, disposition: "EVIDENCED_NO_CHANGE", decision_ref: ref, outcome_ref: ref, scope_sha256: hash, completed_at: stamp, reason_codes: [] })),
    reason_codes: blocked ? ["FORECAST_EVIDENCE_UNAVAILABLE"] : [], observed_at: stamp, finance_approval_required: true, purchase_authorized: false, execution_authorized: false, verified_saving: null };
}

async function setup(page: Page, mode: "positive" | "negative" | "blocked" | "review" | "review403" | "reviewstale" = "positive") {
  const calls: { path: string; method: string; body?: unknown; version?: string; key?: string }[] = [];
  let queued = false, reviewed = false, approvalAttempts = 0, reviewWithdrawn = false, preparationComplete = false;
  const finance = mode.startsWith("review");
  const value = decision(mode === "negative" ? "DO_NOT_PURCHASE" : mode === "blocked" ? "BLOCKED" : "RECOMMEND_PURCHASE_PENDING_FINANCE");
  const row = (detail = false): S["CommitmentDecisionRecord"] => ({ id: "decision-request", version: queued ? 1 : reviewed ? 3 : 2, workload_id: "workload-issued", creator_id: "maker", status: queued ? "QUEUED" : "ASSESSED", selection, input_refs: [ref], input_sha256: queued ? null : hash, decision_sha256: queued ? null : fullHash, decision: detail && !queued ? value : null, decision_summary: null, refusal: null,
    finance_review: reviewed ? { id: "approval-issued", actor_id: "independent-finance", decision_id: value.id, decision_sha256: fullHash, input_sha256: hash, approved_at: stamp, approval_scope: "COMMITMENT_RECOMMENDATION_REVIEW_NO_PURCHASE", purchase_authorized: false, execution_authorized: false } : null,
    can_finance_review: finance && !reviewed && !queued && !reviewWithdrawn, review_reason_codes: reviewWithdrawn ? [mode === "review403" ? "FINANCE_REQUIRED" : "ISSUED_INPUTS_CHANGED"] : finance ? [] : ["INDEPENDENT_FINANCE_REVIEW_REQUIRED"], created_at: stamp, execution_authorized: false, verified_saving: null });
  const preparation = (): S["CommitmentDecisionPreparationRecord"] => ({ id: "preparation-request", version: preparationComplete ? 2 : 1, workload_id: "workload-issued", creator_id: "maker", status: preparationComplete ? "ASSESSED" : "QUEUED", selection: { portfolio_analysis_request_id: "portfolio-issued", offer_receipt_id: "offer-issued" }, post_optimization_assessment_id: preparationComplete ? "optimization-issued" : null, forecast_id: preparationComplete ? "forecast-issued" : null, input_refs: [ref], reason_codes: preparationComplete ? ["FORECAST_CALIBRATION_UNAVAILABLE"] : [], created_at: stamp, execution_authorized: false, verified_saving: null });
  await page.addInitScript(() => { sessionStorage.setItem("finops.oidc.state", "presentation-state"); sessionStorage.setItem("finops.oidc.verifier", "presentation-verifier"); });
  await page.route("**/.well-known/openid-configuration", route => route.fulfill({ json: { token_endpoint: "http://127.0.0.1:4177/__decision-token" } }));
  await page.route("**/__decision-token", route => route.fulfill({ json: { access_token: "presentation-only", expires_in: 3600 } }));
  await page.route("**/v1/**", route => {
    const request = route.request(), url = new URL(request.url()), path = url.pathname;
    calls.push({ path, method: request.method(), ...(request.method() === "POST" ? { body: request.postDataJSON(), version: request.headers()["if-match"], key: request.headers()["idempotency-key"] } : {}) });
    const reply = (json: unknown, status = 200) => route.fulfill({ json, status });
    if (path.includes("/workload-other/")) return reply({ items: [], next_cursor: null });
    if (path.endsWith("/commitment-decision-inputs")) {
      if (request.method() === "POST") return reply(preparation(), 202);
      if (!url.searchParams.has("kind")) return reply({ items: [preparation()], next_cursor: null });
      const kind = kinds.find(([kind]) => kind === url.searchParams.get("kind"))!;
      const current = url.searchParams.has("cursor");
      return reply({ items: [{ id: kind[1] + (current ? "" : "-stale"), kind: kind[0], label: kind[2], status: current ? "CURRENT" : "STALE", scope_sha256: hash, period, input_refs: [ref], reason_codes: current ? [] : ["INPUT_REPLACED"] }], next_cursor: current ? null : "opaque-" + kind[0] });
    }
    if (path === "/v1/workloads/workload-issued/commitment-decisions") {
      if (request.method() === "POST") { queued = true; return reply(row(true), 202); }
      return reply({ items: [{ ...row(), decision_summary: queued ? null : { id: value.id, status: value.status, currency: "USD", proposed_hourly_commitment: value.proposed_hourly_commitment.value, expected_savings: value.expected_savings.value, reason_codes: value.reason_codes, finance_status: reviewed ? "REVIEWED" : "PENDING" } }], next_cursor: null });
    }
    if (path === "/v1/commitment-decisions/decision-request") return reply(row(true));
    if (path === "/v1/commitment-decision-inputs/preparation-request") return reply(preparation());
    if (path === "/v1/approvals") {
      if (mode === "review403" || mode === "reviewstale") {
        reviewWithdrawn = true;
        return reply({ message: mode === "review403" ? "Finance role required." : "Commitment decision inputs changed." }, mode === "review403" ? 403 : 409);
      }
      if (++approvalAttempts === 1) return reply({ message: "Temporary review transport failure." }, 503);
      reviewed = true;
      return reply({ approval: row().finance_review, recommendation: row(true), id: "decision-request", version: 3 }, 201);
    }
    return reply({ message: "Unmocked presentation request." }, 501);
  });
  await page.goto("/tests/fixtures/commitment-decision.html?code=presentation-code&state=presentation-state");
  return { calls, complete: () => { queued = false; }, completePreparation: () => { preparationComplete = true; } };
}
async function open(page: Page) {
  await page.getByText("Commitment decision evidence", { exact: true }).click();
  await page.getByRole("combobox", { name: "Commitment decision workload", exact: true }).selectOption("workload-issued");
}
async function inspect(page: Page) {
  await open(page);
  await page.getByRole("button", { name: "Inspect commitment decision decision-request", exact: true }).click();
}

test("conditional decision distinguishes exact observed zero, projections, downside and calibrated confidence", async ({ page }) => {
  const state = await setup(page);
  expect(state.calls).toEqual([]);
  await inspect(page);
  const metrics = page.getByRole("region", { name: "Commitment decision metrics", exact: true });
  await expect(metrics.getByRole("row").filter({ hasText: /^Observed coverage/ })).toContainText("0fraction");
  await expect(metrics).toContainText("999999999999999999.123456789");
  await expect(metrics).toContainText("12.34567890123456789");
  await expect(page.getByRole("region", { name: "Commitment decision confidence", exact: true })).toContainText("0.9 (fraction)");
  await expect(page.getByRole("region", { name: "Commitment decision confidence", exact: true })).not.toContainText("Calibration reference unavailable");
  await expect(page.getByRole("region", { name: "Commitment decision optimization order", exact: true }).locator("ol > li")).toHaveCount(5);
  await expect(page.getByRole("button", { name: "Review commitment recommendation", exact: true })).toHaveCount(0);
  await expect(page.getByText("Independent finance review required", { exact: true })).toBeVisible();
  expect(state.calls.some(call => call.path === "/v1/approvals")).toBe(false);
});

for (const mode of ["review403", "reviewstale"] as const) test("Finance review preserves server " + (mode === "review403" ? "403 Finance-role refusal" : "409 changed-proof refusal"), async ({ page }) => {
  const state = await setup(page, mode); await inspect(page);
  await page.getByRole("button", { name: "Review commitment recommendation", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "Review commitment recommendation", exact: true });
  await dialog.getByRole("checkbox").check();
  await dialog.getByRole("button", { name: "Record Finance review", exact: true }).click();
  await expect(dialog.getByRole("alert")).toContainText("could not be confirmed");
  await expect(page.getByRole("region", { name: "Recorded Finance review", exact: true })).toHaveCount(0);
  await dialog.getByRole("button", { name: "Close dialog", exact: true }).click();
  await page.getByRole("button", { name: "Refresh issued commitment decision", exact: true }).click();
  await expect(page.getByRole("button", { name: "Review commitment recommendation", exact: true })).toHaveCount(0);
  expect(state.calls.filter(call => call.path === "/v1/approvals")).toHaveLength(1);
  expect(state.calls.some(call => call.path.includes("executions"))).toBe(false);
});

test("uneconomic and blocked decisions retain signed negative amounts and unavailable values", async ({ page }) => {
  await setup(page, "negative"); await inspect(page);
  await expect(page.getByRole("region", { name: "Issued commitment decision", exact: true })).toContainText("Do not purchase");
  await expect(page.getByRole("region", { name: "Commitment decision metrics", exact: true })).toContainText("-1.000000000000000001");
  await expect(page.getByRole("button", { name: "Review commitment recommendation", exact: true })).toHaveCount(0);
  await page.unroute("**/v1/**");
  await setup(page, "blocked"); await inspect(page);
  const rows = page.getByRole("region", { name: "Commitment decision metrics", exact: true });
  await expect(rows).toContainText("Unavailable");
  await expect(rows).not.toContainText("0currency");
  await expect(page.getByRole("region", { name: "Commitment decision confidence", exact: true })).toContainText("Calibration reference unavailable");
  await expect(page.getByRole("button", { name: "Review commitment recommendation", exact: true })).toHaveCount(0);
});

test("four paged current IDs queue using quoted initial CAS and refresh persisted result", async ({ page }) => {
  const state = await setup(page); await open(page);
  await page.getByRole("button", { name: "Evaluate commitment decision", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "Evaluate commitment decision", exact: true });
  for (const [, id, title] of kinds) {
    const group = dialog.getByRole("group", { name: title, exact: true });
    await expect(group.getByRole("radio")).toBeDisabled();
    await group.getByRole("button", { name: "Load more " + title.toLowerCase() + " choices", exact: true }).click();
    await group.locator("label.choice-card").filter({ has: page.getByText(id, { exact: true }) }).getByRole("radio").check();
  }
  await dialog.getByRole("button", { name: "Request commitment decision", exact: true }).click();
  await expect(page.getByRole("region", { name: "Issued commitment decision", exact: true })).toContainText("Awaiting the dedicated analyst");
  const submitted = state.calls.find(call => call.method === "POST")!;
  expect(submitted.body).toEqual(selection); expect(submitted.version).toBe('"0"'); expect(submitted.key).toBeTruthy();
  state.complete();
  await page.getByRole("button", { name: "Refresh issued commitment decision", exact: true }).click();
  await expect(page.getByRole("region", { name: "Commitment decision metrics", exact: true })).toBeVisible();
  await page.getByRole("combobox", { name: "Commitment decision workload", exact: true }).selectOption("workload-other");
  await expect(page.getByRole("region", { name: "Issued commitment decision", exact: true })).toHaveCount(0);
  expect(state.calls.some(call => call.path.includes("/workload-other/"))).toBe(true);
});

test("two-ID evidence preparation preserves issued forecast gaps before a separate decision request", async ({ page }) => {
  const state = await setup(page); await open(page);
  await page.getByRole("button", { name: "Prepare commitment decision evidence", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "Prepare commitment decision evidence", exact: true });
  for (const [, id, title] of [kinds[0], kinds[1]]) {
    const group = dialog.getByRole("group", { name: title, exact: true });
    await group.getByRole("button", { name: "Load more " + title.toLowerCase() + " choices", exact: true }).click();
    await group.locator("label.choice-card").filter({ has: page.getByText(id, { exact: true }) }).getByRole("radio").check();
  }
  await dialog.getByRole("button", { name: "Request evidence preparation", exact: true }).click();
  const detail = page.getByRole("region", { name: "Issued decision evidence preparation", exact: true });
  await expect(detail).toContainText("Awaiting the dedicated analyst");
  state.completePreparation();
  await detail.getByRole("button", { name: "Refresh issued evidence preparation", exact: true }).click();
  await expect(detail).toContainText("optimization-issued"); await expect(detail).toContainText("forecast-issued");
  await expect(detail).toContainText("Forecast calibration unavailable");
  await expect(detail).toContainText("Issued IDs may describe blocked outcomes");
  const submitted = state.calls.filter(call => call.method === "POST");
  expect(submitted).toHaveLength(1);
  expect(submitted[0].body).toEqual({ portfolio_analysis_request_id: "portfolio-issued", offer_receipt_id: "offer-issued" });
  expect(submitted[0].version).toBe('"0"');
  await expect(page.getByRole("button", { name: "Review commitment recommendation", exact: true })).toHaveCount(0);
});

test("Finance review echoes full server hash and version through existing approvals with same-key retry", async ({ page }) => {
  const state = await setup(page, "review"); await inspect(page);
  await page.getByRole("button", { name: "Review commitment recommendation", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "Review commitment recommendation", exact: true });
  await expect(dialog).toContainText(fullHash);
  await expect(dialog.getByRole("button", { name: "Record Finance review", exact: true })).toBeDisabled();
  await dialog.getByRole("checkbox").check();
  await dialog.getByRole("button", { name: "Record Finance review", exact: true }).click();
  await expect(dialog.getByRole("alert")).toContainText("could not be confirmed");
  await dialog.getByRole("button", { name: "Record Finance review", exact: true }).click();
  await expect(page.getByRole("region", { name: "Recorded Finance review", exact: true })).toContainText("Purchase and execution remain disabled");
  const posts = state.calls.filter(call => call.path === "/v1/approvals");
  expect(posts).toHaveLength(2);
  expect(posts[0].body).toEqual({ commitment_decision_id: "decision-request", decision_sha256: fullHash });
  expect(posts[0].version).toBe('"2"'); expect(posts[1].key).toBe(posts[0].key);
  expect(JSON.stringify(posts[0].body)).not.toContain("change_plan_id");
  await page.reload();
  // The product keeps bearer tokens in memory. Re-enter this explicit mock
  // callback after a fresh document; the mocked server's review remains stored.
  // Real PKCE/session behavior belongs to the separate connected acceptance.
  await page.goto("/tests/fixtures/commitment-decision.html?code=presentation-code&state=presentation-state");
  await inspect(page);
  await expect(page.getByRole("region", { name: "Recorded Finance review", exact: true })).toContainText("independent-finance");
  await expect(page.getByRole("button", { name: "Review commitment recommendation", exact: true })).toHaveCount(0);
});
