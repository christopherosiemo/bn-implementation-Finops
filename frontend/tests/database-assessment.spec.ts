import { expect, type Page } from "@playwright/test";
import { test } from "./presentation";
import type { components } from "../src/api.generated";
import type { Dashboard, Recommendation } from "../src/types";

// Normal App presentation contracts with explicit route doubles. These do not
// prove OIDC validation, native AWS data, persistence or economic provenance.
type S = components["schemas"];
const stamp = "2026-10-20T00:00:00Z";
const period = { start: "2026-10-06T00:00:00Z", end: stamp };
function assessment(): S["DatabaseAssessment"] {
  return { schema_version: "1", resource_kind: "RDS_INSTANCE", engine: "postgres", current_configuration: { db_instance_class: "db.m6g.large", multi_az: true }, candidate_configuration: null,
    evidence_window: period, metric_distributions: [
      { metric: "cpu_utilization", member_id: "orders-postgres", unit: "Percent", statistic: "HOURLY_MAXIMUM_OF_NATIVE_PERIOD_VALUES", status: "COMPLETE", expected_hours: 336, observed_hours: 336, expected_sample_count: 4032, sample_count: 4032, expected_native_sample_count: 20160, native_sample_count: "20160", minimum: "0", maximum: "10", p50_of_period_statistics: "0", p95_of_period_statistics: "3.25", p99_of_period_statistics: "7.5" },
      { metric: "freeable_memory", member_id: "orders-postgres", unit: "Bytes", statistic: "HOURLY_MINIMUM_OF_NATIVE_PERIOD_VALUES", status: "INCOMPLETE", expected_hours: 336, observed_hours: 0, expected_sample_count: 4032, sample_count: 0, expected_native_sample_count: 20160, native_sample_count: "0", minimum: null, maximum: null, p50_of_period_statistics: null, p95_of_period_statistics: null, p99_of_period_statistics: null },
    ], economics: { current_hourly_cost: "0", current_monthly_cost: "0", candidate_hourly_cost: null, candidate_monthly_cost: null, estimated_monthly_saving: null, estimated_annual_saving: null, currency: "USD", basis: "NATIVE_BILLED_RATE" },
    source_refs: [{ kind: "RDS_INVENTORY", id: "native-issued", sha256: "a".repeat(64) }], blockers: ["MEMORY_EVIDENCE_UNAVAILABLE"], confidence: { status: "LOW", reasons: ["MEMORY_EVIDENCE_UNAVAILABLE"] },
    proposal: { risk_class: "R3", executable: false, execution_authorized: false }, verified_saving: null, candidates: [], recommendation_kind: "DATABASE_INSTANCE_RIGHTSIZE", status: "BLOCKED" };
}
function record(queued = false): S["DatabaseAssessmentRecord"] {
  return { id: "database-request-1", version: queued ? 1 : 2, resource_id: "database-1", workload_id: "workload-1", status: queued ? "QUEUED" : "BLOCKED", created_at: stamp, current: !queued, currentness_blockers: [], assessment: queued ? null : assessment() };
}
function dashboard(): Dashboard {
  const resource = { id: "database-1", version: 1, name: "orders-db", provider: "AWS", resource_type: "RDS_INSTANCE", provider_resource_id: "orders-postgres", workload_id: "workload-1", environment: "PRODUCTION", state: "available", configuration_authority: "TERRAFORM", hourly_effective_cost: null, monthly_effective_cost: null, currency: null, eligibility: "OBSERVATION_ONLY", blockers: ["DATABASE_EXECUTION_NOT_SUPPORTED"] };
  const database: Recommendation = { id: "recommendation-db", version: 1, resource_id: resource.id, workload_id: resource.workload_id, title: "Review orders database capacity", category: "DATABASE_INSTANCE_RIGHTSIZE", risk_class: "R3", status: "BLOCKED", monthly_saving: null, annual_saving: null, currency: "USD", confidence: "LOW", evidence: {}, model_kind: "DATABASE_ASSESSMENT_V1", database_assessment_id: record().id, pre_execution_ready: false };
  return { org: { id: "org", version: 1, name: "Database contract", paused: false }, fixture: false, cloud_accounts: [], workloads: [{ id: "workload-1", version: 1, name: "Orders", environment: "PRODUCTION", owner: "Owner", timezone: "UTC", incident: "UNKNOWN", deployment: "UNKNOWN", job: "UNKNOWN", signals_at: stamp }],
    resources: [resource, { ...resource, id: "ec2-1", name: "orders-worker", resource_type: "EC2", provider_resource_id: "i-example" }], recommendations: [database, { ...database, id: "recommendation-ec2", title: "Review idle worker", risk_class: "R1", category: "SCHEDULE", resource_id: "ec2-1", model_kind: undefined, database_assessment_id: undefined }],
    policies: [], schedules: [], change_plans: [], executions: [], savings: [], audit: [], data_quality: [], readiness: [] };
}
async function setup(page: Page, denied = false) {
  const writes: { path: string; body: unknown; version?: string; key?: string }[] = [];
  let queued = false;
  await page.addInitScript(() => { sessionStorage.setItem("finops.oidc.state", "database-presentation"); sessionStorage.setItem("finops.oidc.verifier", "database-presentation"); });
  await page.route("**/.well-known/openid-configuration", route => route.fulfill({ json: { token_endpoint: "http://127.0.0.1:4177/__database-token" } }));
  await page.route("**/__database-token", route => route.fulfill({ json: { access_token: "presentation-only", expires_in: 3600 } }));
  await page.route("**/v1/**", route => {
    const request = route.request(), url = new URL(request.url()), path = url.pathname;
    const reply = (json: unknown, status = 200) => route.fulfill({ json, status });
    if (request.method() === "POST") writes.push({ path, body: request.postDataJSON(), version: request.headers()["if-match"], key: request.headers()["idempotency-key"] });
    if (path === "/v1/dashboard") return reply(dashboard());
    if (path === "/v1/database-assessments") {
      if (denied) return reply({ message: "Database scope denied." }, 403);
      if (request.method() === "POST") { queued = true; return reply(record(true), 202); }
      return reply({ items: [url.searchParams.has("cursor") ? record() : { ...record(), id: "database-old" }], next_cursor: url.searchParams.has("cursor") ? null : "opaque-next" });
    }
    if (path === "/v1/database-assessments/database-request-1") return reply(record(queued));
    if (path === "/v1/coverage") {
      if (denied) return reply({ message: "Financial scope denied." }, 403);
      const group = { currency: "USD", detected_spend: "100", analysed_spend: "25", observation_only_spend: "10", blocked_spend: "5", unsupported_spend: "60", credits: "-2", net_spend: "98", analysed_percent: "25", basis: "POSITIVE_BILLED_CHARGES", complete: true };
      return reply({ period, groups: [group, { ...group, currency: "EUR", detected_spend: "0", analysed_spend: "0", analysed_percent: null, complete: false }], blockers: ["UNSUPPORTED_AWS_SERVICES_REMAIN_IN_DENOMINATOR"] });
    }
    return reply({ message: "No presentation evidence registered." }, 404);
  });
  const go = (hash: string) => page.goto(`/?code=presentation&state=database-presentation#${hash}`);
  await go("workloads");
  return { writes, go, complete: () => { queued = false; } };
}

test("database inventory requests only an issued resource ID and retains persisted zero versus unknown evidence", async ({ page }) => {
  const state = await setup(page);
  const database = page.getByRole("row").filter({ hasText: "orders-db" });
  await expect(database.getByText("Read-only · R3", { exact: true })).toBeVisible();
  await expect(database.getByRole("button", { name: "Refresh assessment", exact: true })).toHaveCount(0);
  await expect(page.getByRole("row").filter({ hasText: "orders-worker" }).getByRole("button", { name: "Refresh assessment", exact: true })).toHaveCount(1);
  await database.getByRole("button", { name: "Assess database orders-db", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "Database assessment", exact: true });
  await expect(dialog.getByRole("status")).toContainText("assessment in progress");
  expect(state.writes).toHaveLength(1);
  expect(state.writes[0]).toMatchObject({ path: "/v1/database-assessments", body: { resource_id: "database-1" }, version: '"0"' });
  expect(state.writes[0].key).toBeTruthy();
  state.complete();
  await dialog.getByRole("button", { name: "Refresh selected database assessment", exact: true }).click();
  const metrics = dialog.getByRole("region", { name: "Database metric distributions", exact: true });
  await expect(metrics.getByRole("row").filter({ hasText: "cpu_utilization" }).getByRole("cell").nth(1)).toHaveText("0");
  await expect(metrics.getByRole("row").filter({ hasText: "freeable_memory" }).getByRole("cell").nth(1)).toHaveText("Unavailable");
  await expect(dialog.getByRole("region", { name: "Database assessment economics", exact: true }).getByRole("row").filter({ hasText: /^Current hourly cost/ })).toContainText("0 USD");
  await expect(dialog.getByRole("button", { name: /Create.*plan/ })).toHaveCount(0);
  await state.go("workloads");
  await page.getByText("Database assessment history", { exact: true }).click();
  await page.getByRole("button", { name: "Load more database assessments", exact: true }).click();
  await page.getByRole("button", { name: "Inspect database assessment database-request-1", exact: true }).click();
  await expect(page.getByRole("region", { name: "Database evidence quality", exact: true })).toContainText("Evidence quality: Low");
});

test("database recommendations cannot enter the existing EC2 change-plan flow", async ({ page }) => {
  const state = await setup(page); await state.go("recommendations");
  const db = page.locator(".recommendation-card").filter({ hasText: "Review orders database capacity" });
  await expect(db).toContainText("R3 · Database proposal");
  await expect(db.getByRole("button", { name: "Create change plan", exact: true })).toHaveCount(0);
  await expect(page.locator(".recommendation-card").filter({ hasText: "Review idle worker" }).getByRole("button", { name: "Create change plan", exact: true })).toHaveCount(1);
  await db.getByRole("button", { name: "Inspect database recommendation recommendation-db", exact: true }).click();
  await expect(page.getByRole("dialog", { name: "Database assessment", exact: true })).toContainText("Memory evidence unavailable");
  expect(state.writes).toHaveLength(0);
});

test("coverage keeps all AWS spend and currencies separate and never converts an unknown percentage to zero", async ({ page }) => {
  const state = await setup(page); await state.go("connections");
  await page.getByText("Inspect assessed and unsupported spend", { exact: true }).click();
  const table = page.getByRole("region", { name: "All AWS assessment spend coverage", exact: true });
  await expect(table.getByRole("row").filter({ hasText: "USD" })).toContainText("60 USD");
  await expect(table.getByRole("row").filter({ hasText: "EUR" }).getByRole("cell").last()).toHaveText("Unavailable");
  await expect(table.getByRole("row").filter({ hasText: "USD" })).toContainText("-2 USD");
  await expect(table).toContainText("POSITIVE_BILLED_CHARGES");
  await expect(page.getByText("Unsupported aws services remain in denominator", { exact: true })).toBeVisible();
  expect(state.writes).toHaveLength(0);
});

test("denied database and coverage reads remain unavailable without a usable result", async ({ page }) => {
  const state = await setup(page, true);
  await page.getByText("Database assessment history", { exact: true }).click();
  await expect(page.getByRole("alert").filter({ hasText: "Database assessments unavailable" })).toBeVisible();
  await state.go("connections");
  await page.getByText("Inspect assessed and unsupported spend", { exact: true }).click();
  await expect(page.getByRole("alert").filter({ hasText: "Assessment coverage unavailable" })).toContainText("Financial scope denied");
  expect(state.writes).toHaveLength(0);
});
