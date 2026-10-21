import { expect, type Page } from "@playwright/test";
import { test } from "./presentation";
import type { components } from "../src/api.generated";
import type { Dashboard, Recommendation, Resource } from "../src/types";

// Supplementary presentation only; these route doubles are not native acceptance.
type S = components["schemas"];
const stamp = "2026-10-21T00:00:00Z";
const resource: Resource = { id: "service-resource", version: 1, name: "orders-service", provider: "AWS", resource_type: "ECS_SERVICE", provider_resource_id: "arn:aws:ecs:eu-west-1:111122223333:service/orders/orders", account_id: "111122223333", region: "eu-west-1", service_family: "ECS", aws_service_configuration: { launchType: "FARGATE", desiredCount: 3 }, workload_id: "orders", owner: "orders-team", environment: "NON_PRODUCTION", state: "ACTIVE", configuration_authority: "TERRAFORM", hourly_effective_cost: null, monthly_effective_cost: null, currency: null, eligibility: "OBSERVE_ONLY", blockers: [] };
function assessment(blocked = false): S["AWSServiceAssessment"] {
  const economics: S["AWSServiceAssessmentEconomics"] = { status: blocked ? "ECONOMICS_UNAVAILABLE" : "NATIVE_CUSTOMER_ECONOMICS", currency: "GBP", current_window_cost: "200.000000000001", candidate_window_cost: blocked ? null : "220.000000000001", estimated_window_saving: blocked ? null : "-20.000000000000", conditional_monthly_run_rate: null, basis: "NATIVE_CUSTOMER_NET_MARGINAL" };
  return { schema_version: "1", model_version: "aws-service-v1", model_kind: "AWS_SERVICE_ASSESSMENT_V1", family: "ECS", resource_id: resource.id, status: blocked ? "BLOCKED" : "NO_CHANGE", recommendation_kind: "FARGATE_TASK_RIGHTSIZE", decision_code: blocked ? "MISSING_MEMORY_OBSERVATIONS" : "DO_NOT_PROCEED", current_configuration: { cpu: "1024", memory: "2048", configuration_authority: "TERRAFORM" }, proposed_configuration: { cpu: "512", memory: "1024" }, evidence_window: { start: "2026-10-07T00:00:00Z", end: stamp }, metric_distributions: [{ metric: "cpu", peak: "0.25", unit: "FRACTION" }, { metric: "memory", peak: "0.8", unit: "FRACTION" }], reason_codes: [blocked ? "MEMORY_EVIDENCE_UNAVAILABLE" : "CANDIDATE_NOT_CHEAPER"], blockers: blocked ? ["NATIVE_METRIC_PERIODS_INCOMPLETE"] : [], confidence: { status: blocked ? "UNAVAILABLE" : "BOUNDED_EVIDENCE", reason_codes: ["OBSERVED_SCREEN_NOT_FORECAST_GUARANTEE"] }, economics, candidates: [{ id: "smaller-task", recommendation_kind: "FARGATE_TASK_RIGHTSIZE", status: blocked ? "BLOCKED" : "NO_CHANGE", decision_code: "DO_NOT_PROCEED", reason_codes: ["CANDIDATE_NOT_CHEAPER"], current_configuration: { cpu: "1024", memory: "2048" }, proposed_configuration: { cpu: "512", memory: "1024" }, economics, confidence: { status: "BOUNDED_EVIDENCE", reason_codes: [] } }], source_refs: [{ kind: "AWS_SERVICE_NATIVE_V1", id: "native-snapshot", version: "version-1" }], risk_class: "R3", read_only: true, pre_execution_ready: false, execution_authorized: false, verified_saving: null };
}
function record(blocked = false): S["AWSServiceAssessmentRecord"] { return { id: "service-assessment", version: 1, resource_id: resource.id, workload_id: "orders", family: "ECS", status: blocked ? "BLOCKED" : "ASSESSED", created_at: stamp, current: false, currentness_blockers: ["AWS_SERVICE_SOURCE_CHANGED"], assessment: assessment(blocked) }; }
async function setup(page: Page, blocked = false) {
  const writes: { path: string; body: unknown; key?: string; version?: string }[] = [];
  const recommendation: Recommendation = { id: "service-advice", version: 1, title: "Keep current Orders task configuration", model_kind: "AWS_SERVICE_ASSESSMENT_V1", aws_service_assessment_id: "service-assessment", resource_id: resource.id, workload_id: "orders", category: "AWS_SERVICE_ASSESSMENT", risk_class: "R3", status: blocked ? "BLOCKED" : "NO_CHANGE", monthly_saving: null, annual_saving: null, confidence: "BOUNDED_EVIDENCE", evidence: {} };
  const dashboard: Dashboard = { org: { id: "org", version: 1, name: "AWS service assessment presentation", paused: false }, fixture: false, resources: [resource], recommendations: [recommendation], workloads: [], cloud_accounts: [], policies: [], schedules: [], change_plans: [], executions: [], savings: [], audit: [], data_quality: [] };
  await page.addInitScript(() => { sessionStorage.setItem("finops.oidc.state", "service-assessment-presentation"); sessionStorage.setItem("finops.oidc.verifier", "service-assessment-presentation"); });
  await page.route("**/.well-known/openid-configuration", route => route.fulfill({ json: { token_endpoint: "http://127.0.0.1:4177/__assessment-token" } }));
  await page.route("**/__assessment-token", route => route.fulfill({ json: { access_token: "presentation-only", expires_in: 3600 } }));
  await page.route("**/v1/**", route => {
    const request = route.request(), path = new URL(request.url()).pathname, reply = (json: unknown, status = 200) => route.fulfill({ json, status });
    if (request.method() === "POST") writes.push({ path, body: request.postDataJSON(), key: request.headers()["idempotency-key"], version: request.headers()["if-match"] });
    if (path === "/v1/dashboard") return reply(dashboard);
    if (path === "/v1/aws-service-assessments") return request.method() === "POST" ? reply(record(blocked), 202) : reply({ items: [record(blocked)], next_cursor: null });
    if (path === "/v1/aws-service-assessments/service-assessment") return reply(record(blocked));
    if (path.endsWith("/aws-service-evidence")) return reply({ resource_id: resource.id, current: false, reason_codes: ["AWS_SERVICE_SOURCE_CHANGED"], snapshot: { source_version: "version-1" } });
    if (path === "/v1/recommendations") return reply({ items: [recommendation], next_cursor: null });
    return reply({ message: "No presentation evidence registered" }, 404);
  });
  const go = (hash: string) => page.goto(`/?code=presentation&state=service-assessment-presentation#${hash}`); await go("workloads"); return { writes, go };
}
test("ordinary AWS service assessment sends resource identity only and preserves negative economics", async ({ page }) => {
  const state = await setup(page); await page.getByRole("button", { name: "Inspect AWS service orders-service", exact: true }).click(); await page.getByRole("dialog", { name: "AWS service resource", exact: true }).getByRole("button", { name: "Assess AWS service orders-service", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "AWS service assessment", exact: true }); await expect(dialog).toBeVisible(); await expect(page.getByRole("dialog", { name: "AWS service resource", exact: true })).toHaveCount(0); expect(state.writes).toHaveLength(1); expect(state.writes[0]).toMatchObject({ path: "/v1/aws-service-assessments", version: '"0"', body: { resource_id: resource.id } }); expect(state.writes[0].key).toBeTruthy(); await expect(dialog).toContainText("-20.000000000000 GBP"); await expect(dialog.getByRole("alert")).toContainText("Aws service source changed"); await expect(dialog.getByRole("button", { name: /Execute|Approve|Delete|Resize|Create.*plan/ })).toHaveCount(0);
});
test("AWS service recommendation keeps known current cost visible while candidate savings are unavailable", async ({ page }) => {
  const state = await setup(page, true); await state.go("recommendations"); await page.getByRole("button", { name: "Inspect AWS service recommendation service-advice", exact: true }).click(); const dialog = page.getByRole("dialog", { name: "AWS service assessment", exact: true }); await expect(dialog).toContainText("200.000000000001 GBP"); await expect(dialog).toContainText("Native metric periods incomplete"); await expect(dialog.getByRole("row", { name: "Candidate window cost Unavailable", exact: true })).toHaveCount(2); await expect(dialog.getByRole("row", { name: "Verified savings Unavailable", exact: true })).toHaveCount(2); expect(state.writes).toHaveLength(0);
});

test("currentness presentation separates historical advice from changed evidence", async ({ page }) => {
  const state = await setup(page);
  let changed = false;
  const historical = record().assessment;
  await page.route("**/v1/aws-service-assessments/service-assessment", route => route.fulfill({ json: {
    ...record(), current: !changed, historical_status: "ASSESSED", assessment: historical,
    currentness: { schema_version: "1", status: changed ? "STALE" : "CURRENT", checked_at: stamp,
      reason_codes: changed ? ["STALE_RECOMMENDATION", "BILLING_SOURCE_CHANGED", "IAC_REVISION_CHANGED"] : [],
      changes: changed ? [{ dimension: "BILLING", reason_code: "BILLING_SOURCE_CHANGED", detected_at: stamp }] : [],
      economics_recompute: changed, telemetry_recollect: false, iac_changed: changed,
      next_action: changed ? "REANALYSE_CURRENT_EVIDENCE" : "NONE", execution_ready: false },
  } }));
  await state.go("recommendations");
  await page.getByRole("button", { name: "Inspect AWS service recommendation service-advice", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "AWS service assessment", exact: true });
  const currentness = dialog.getByRole("region", { name: "Recommendation currentness", exact: true });
  await expect(currentness).toHaveAttribute("data-currentness", "CURRENT");
  changed = true;
  await dialog.getByRole("button", { name: "Refresh selected AWS service assessment", exact: true }).click();
  await expect(currentness).toHaveAttribute("data-currentness", "STALE");
  await expect(currentness).toContainText("Historical result: Assessed");
  await expect(currentness).toContainText("Recompute economics");
  await expect(currentness).toContainText("Billing source changed");
  await expect(currentness).toContainText("Review the configured repository revision");
  await expect(dialog).toContainText("-20.000000000000 GBP");
  expect(state.writes).toHaveLength(0);
});
