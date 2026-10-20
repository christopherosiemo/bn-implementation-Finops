import { expect, type Page } from "@playwright/test";
import { test } from "./presentation";
import type { components } from "../src/api.generated";
import type { Dashboard, Recommendation, Resource } from "../src/types";

// Presentation-only route doubles. Native ingestion and authenticated persisted
// acceptance use lambda-live.spec.ts; these cases add no maturity credit.
type S = components["schemas"];
const stamp = "2026-10-20T00:00:00Z";
const resource: Resource = { id: "lambda-resource", version: 1, name: "image-resizer-prod", provider: "AWS", resource_type: "LAMBDA_FUNCTION", provider_resource_id: "arn:aws:lambda:eu-west-1:111122223333:function:image-resizer", account_id: "111122223333", region: "eu-west-1", workload_id: "images", environment: "PRODUCTION", state: "Active", configuration_authority: "TERRAFORM", hourly_effective_cost: null, monthly_effective_cost: null, currency: null, eligibility: "OBSERVE_ONLY", blockers: [], lambda_configuration: { version: "$LATEST", architecture: "x86_64", memory_size_mb: 2048, versions: [{ version: "7", memory_size_mb: 2048 }], aliases: [{ name: "live", function_version: "7", routing_weights: { "8": "0.1" } }], reserved_concurrency: 20 } };
const policy: S["LambdaPolicy"] = { id: "lambda-policy", version: 1, resource_id: resource.id, name: "Images latency", created_at: stamp, policy: { owner: "images", configuration_authority: "TERRAFORM", criticality: "PRODUCTION", requires_warm_capacity: null } };
function assessment(): S["LambdaAssessment"] {
  return { schema_version: "1", model_version: "lambda-v1", model_kind: "LAMBDA_ASSESSMENT_V1", binding: { resource_id: resource.id }, qualifier: "live", status: "RECOMMENDED", reason_codes: [], candidates: [{ id: "memory-1536", family: "MEMORY", status: "RECOMMENDED", decision: "REDUCE_MEMORY", memory_size_mb: 1536, architecture: "x86_64", provisioned_concurrency: null, physical_status: "FEASIBLE", checks: [], performance: { duration_ms: "120", billed_duration_ms: "130", p95_duration_ms: "150", p99_duration_ms: "160", successful_work: "9007199254740993", errors: "0", throttles: "0", peak_concurrency: "8" }, economics: { status: "MODELLED_NATIVE_CUSTOMER_ECONOMICS", currency: "GBP", pricing_basis: "NATIVE_CUSTOMER_NET_ONLY", current_window_cost: "200.000000000001", candidate_window_cost: "150.000000000001", estimated_window_saving: "50", estimated_monthly_saving: "50.000000000001", estimated_annual_saving: null, component_costs: [{ component: "DURATION", current_cost: "200.000000000001", candidate_cost: "150.000000000001" }] }, reason_codes: [], confidence: { status: "LIMITED", reasons: ["MEMORY_ENVIRONMENT_REUSE_SEMANTICS"] }, implementation_method: "DECLARATIVE_REMEDIATION_REVIEW", read_only: true, pre_execution_ready: false, execution_authorized: false, verified_saving: null }], observations: { start: "2026-09-20T00:00:00Z", end: stamp, history_days: "30", metrics_summary: {}, report_summary: { status: "OBSERVED", count: "9007199254740993", total_duration_ms: "100", total_billed_duration_ms: "110", max_memory_used_mb: "950", init_duration_ms: null, memory_semantics: "ENVIRONMENT_REUSE_MAXIMUM" } }, economics: { status: "OBSERVED", currency: "GBP", observed_billed_cost: "215.000000000001", current_request_cost: "10", current_compute_cost: "200.000000000001", current_provisioned_capacity_cost: "0", continuing_cost: "5", credits: "-1", pricing_basis: "NATIVE_CUSTOMER_NET_ONLY" }, confidence: { status: "LIMITED", reasons: [] }, difference: "DIFFERS", reason_for_difference: ["PROVIDER_PUBLIC_PRICING_NOT_CUSTOMER_NET"], configuration_authority: "TERRAFORM", implementation_method: "DECLARATIVE_REMEDIATION_REVIEW", source_refs: [{ id: "immutable-native-source" }], read_only: true, pre_execution_ready: false, execution_authorized: false, verified_saving: null };
}
const record = (): S["LambdaAssessmentRecord"] => ({ id: "lambda-assessment", version: 1, resource_id: resource.id, qualifier: "live", policy_id: policy.id, status: "ASSESSED", created_at: stamp, current: false, currentness_blockers: ["LAMBDA_CONFIGURATION_CHANGED"], assessment: assessment() });
const recommendation: Recommendation = { id: "lambda-advice", version: 1, resource_id: resource.id, workload_id: "images", title: "Review image processing memory", model_kind: "LAMBDA_ASSESSMENT_V1", lambda_assessment_id: "lambda-assessment", category: "LAMBDA_ASSESSMENT", risk_class: "R2", status: "RECOMMENDED", monthly_saving: null, annual_saving: null, confidence: "LIMITED", evidence: {}, pre_execution_ready: false };
async function setup(page: Page) {
  const writes: { path: string; body: unknown; version?: string; key?: string }[] = [];
  const dashboard: Dashboard = { org: { id: "org", version: 1, name: "Lambda presentation", paused: false }, fixture: false, resources: [resource], recommendations: [recommendation], workloads: [], cloud_accounts: [], policies: [], schedules: [], change_plans: [], executions: [], savings: [], audit: [], data_quality: [] };
  await page.addInitScript(() => { sessionStorage.setItem("finops.oidc.state", "lambda-presentation"); sessionStorage.setItem("finops.oidc.verifier", "lambda-presentation"); });
  await page.route("**/.well-known/openid-configuration", route => route.fulfill({ json: { token_endpoint: "http://127.0.0.1:4177/__lambda-token" } }));
  await page.route("**/__lambda-token", route => route.fulfill({ json: { access_token: "presentation-only", expires_in: 3600 } }));
  await page.route("**/v1/**", route => {
    const request = route.request(), path = new URL(request.url()).pathname, reply = (json: unknown, status = 200) => route.fulfill({ json, status });
    if (request.method() === "POST") writes.push({ path, body: request.postDataJSON(), version: request.headers()["if-match"], key: request.headers()["idempotency-key"] });
    if (path === "/v1/dashboard") return reply(dashboard);
    if (path === "/v1/resources") return reply({ items: [resource], next_cursor: null });
    if (path === "/v1/lambda-policies") return reply({ items: [policy], next_cursor: null });
    if (path === "/v1/lambda-policies/lambda-policy/revisions") return reply({ ...policy, ...request.postDataJSON(), version: 2 }, 201);
    if (path === "/v1/lambda-assessments") return request.method() === "POST" ? reply(record(), 202) : reply({ items: [record()], next_cursor: null });
    if (path === "/v1/lambda-assessments/lambda-assessment") return reply(record());
    if (path === "/v1/source-connections") return reply({ ...request.postDataJSON(), id: "lambda-source", version: 1 }, 201);
    if (path === "/v1/coverage") { const group: S["AssessmentCoverageGroup"] = { currency: "GBP", basis: "POSITIVE_BILLED_CHARGES", complete: false, detected_spend: "1000000", analysed_spend: "200", observation_only_spend: "300", blocked_spend: "400", unsupported_spend: "999100", credits: "-500", net_spend: "999500", analysed_percent: null }; return reply({ period: { start: stamp, end: stamp }, groups: [group], lambda_groups: [{ ...group, detected_spend: "1000", unsupported_spend: "100" }], blockers: [] }); }
    return reply({ message: "No presentation evidence registered." }, 404);
  });
  const go = (hash: string) => page.goto(`/?code=presentation&state=lambda-presentation#${hash}`); await go("workloads"); return { writes, go };
}
test("Lambda resource requires an explicit serving qualifier and sends IDs only with no financial inputs", async ({ page }) => {
  const state = await setup(page); await page.getByRole("button", { name: "Inspect Lambda image-resizer-prod", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "Lambda resource and requirements", exact: true }); await expect(dialog.getByRole("button", { name: "Assess selected Lambda qualifier", exact: true })).toBeDisabled();
  await dialog.getByLabel("Lambda serving qualifier", { exact: true }).selectOption("live"); await dialog.getByRole("button", { name: "Assess with policy Images latency", exact: true }).click();
  expect(state.writes).toHaveLength(1); expect(state.writes[0]).toMatchObject({ path: "/v1/lambda-assessments", version: '"0"', body: { resource_id: resource.id, qualifier: "live", policy_id: policy.id } }); expect(state.writes[0].key).toBeTruthy();
  await expect(page.getByRole("dialog", { name: "Lambda assessment", exact: true })).toBeVisible();
});
test("Lambda ordinary recommendation preserves exact decimals, memory evidence and read-only refusals", async ({ page }) => {
  const state = await setup(page); await state.go("recommendations"); await page.getByRole("button", { name: "Inspect Lambda recommendation lambda-advice", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "Lambda assessment", exact: true }); await expect(dialog.getByRole("alert")).toContainText("Lambda configuration changed"); await expect(dialog).toContainText("9007199254740993"); await expect(dialog).toContainText("50.000000000001 GBP"); await expect(dialog).toContainText("annual saving: Unavailable"); await expect(dialog).toContainText("Handler duration (ms)"); await expect(dialog).toContainText("Billed duration (ms)");
  await expect(dialog).toContainText("Reserved concurrency is a scaling boundary"); await expect(dialog.getByRole("button", { name: /Execute|Approve|Resize|Deploy|Shift|Create.*plan/ })).toHaveCount(0); expect(state.writes).toHaveLength(0);
});
test("Lambda coverage retains all-AWS denominator and source registration supplies no observations", async ({ page }) => {
  const state = await setup(page); await state.go("connections"); await page.getByText("Inspect assessed and unsupported spend", { exact: true }).click(); await expect(page.getByRole("region", { name: "All AWS assessment spend coverage", exact: true })).toContainText("1000000 GBP"); await expect(page.getByRole("region", { name: "Lambda assessment spend coverage", exact: true })).toContainText("1000 GBP");
  await page.getByRole("button", { name: "Register Lambda evidence", exact: true }).click(); const form = page.getByRole("dialog", { name: "Register Lambda evidence", exact: true });
  for (const [label, value] of [["Lambda source name", "Existing function metrics"], ["Lambda AWS account ID", "111122223333"], ["Unqualified Lambda function ARN", resource.provider_resource_id], ["Registered serving qualifier", "live"], ["Approved Lambda read binding ID", "lambda-reader"]]) await form.getByLabel(label, { exact: true }).fill(value);
  await form.getByRole("button", { name: "Register existing Lambda evidence", exact: true }).click(); expect(state.writes).toHaveLength(1); expect(state.writes[0]).toMatchObject({ path: "/v1/source-connections", body: { kind: "AWS_LAMBDA_NATIVE_V1", qualifier: "live", read_role_binding_id: "lambda-reader" } });
});
