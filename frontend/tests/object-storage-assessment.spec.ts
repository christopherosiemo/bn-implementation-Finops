import { expect, type Page } from "@playwright/test";
import { test } from "./presentation";
import type { components } from "../src/api.generated";
import type { Dashboard, Recommendation, Resource } from "../src/types";

// Supplemental normal-App presentation checks only. Route doubles do not
// establish native AWS provenance, machine OIDC, persistence or actual savings.
type S = components["schemas"];
const stamp = "2026-10-20T00:00:00Z";
const bucket: Resource = { id: "bucket-one", version: 1, name: "analytics-store", provider: "AWS", resource_type: "S3_BUCKET", provider_resource_id: "arn:aws:s3:::analytics-store", workload_id: "", environment: "NON_PRODUCTION", state: "OBSERVED", configuration_authority: "TERRAFORM", hourly_effective_cost: null, monthly_effective_cost: null, currency: null, eligibility: "OBSERVATION_ONLY", blockers: [], object_storage_configuration: { name: "analytics-store", arn: "arn:aws:s3:::analytics-store", account_id: "111122223333", region: "eu-west-1", observed_at: stamp, created_at: null, configurations: { lifecycle: { status: "UNAVAILABLE", reason_code: "ACCESS_DENIED", value: null }, replication: { status: "ABSENT", value: null }, object_lock: { status: "OBSERVED", value: { ObjectLockEnabled: "Enabled" } } } } };
const policy: S["ObjectStorageDatasetPolicy"] = { criticality: "NON_PRODUCTION", high_seasonality: false, remaining_lifetime_days: null, rto_seconds: null, retention_known: false, compliance_clear: false, recovery_known: false, allow_onezone: null, dependencies_reviewed: null };
const dataset: S["ObjectStorageDataset"] = { id: "dataset-one", version: 1, resource_id: bucket.id, name: "Analytics logs", selector: { kind: "PREFIX", prefix: "analytics/logs/" }, policy, created_at: stamp };
function result(): S["ObjectStorageAssessment"] {
  const economics: S["ObjectStorageEconomics"] = { status: "AVAILABLE", basis: "AWS_CUR_NET_USAGE", currency: "GBP", current_monthly_cost: "100.125", candidate_monthly_cost: "60.125", estimated_monthly_saving: "-5.000", estimated_annual_saving: null, net_horizon_saving: "-10", transition_cost: "90", current_minimum_duration_penalty: "0", candidate_minimum_duration_penalty: "0", tier_initialization_cost: "0", horizon_days: "60", current_horizon_cost: "200.25", candidate_horizon_cost: "210.25", recurring_monthly_saving: "40", component_costs: [{ component: "storage", current_monthly_cost: "90", candidate_monthly_cost: "40" }, { component: "retrieval", current_monthly_cost: "0", candidate_monthly_cost: "10.125" }, { component: "continuing", current_monthly_cost: "10.125", candidate_monthly_cost: "10" }], verified_saving: null };
  return { schema_version: "1", model_version: "object-storage-v1", model_kind: "OBJECT_STORAGE_ASSESSMENT_V1", binding: { resource_id: bucket.id }, status: "NO_CHANGE", reason_code: "S3_COHORT_ASSESSMENT_COMPLETED", blockers: [], cohorts: [{ id: "cohort-one", label: "analytics/logs/", source_class: "STANDARD", access_tier: null, state: "CURRENT", object_count: "9007199254740993", total_bytes: "9007199254740993", size_bands: [{ count: "9007199254740993", total_bytes: "9007199254740993", min_bytes: "1", max_bytes: "1" }], age_days_min: "100", age_days_max: "120", population_hash: "a".repeat(64), access_state: "AGE_OBSERVED", evidence_window: { start: null, end: null }, lifecycle_state: "KNOWN", candidate_ids: ["candidate-one"], blockers: ["S3_ACCESS_PATTERN_UNKNOWN"], inventory_complete: false }], candidates: [{ id: "candidate-one", cohort_id: "cohort-one", recommendation_kind: "S3_STANDARD_TO_STANDARD_IA", candidate_storage_class: "STANDARD_IA", status: "NO_CHANGE", reason_code: "S3_DO_NOT_TRANSITION", blockers: ["S3_TOTAL_ECONOMICS_DO_NOT_JUSTIFY_TRANSITION"], economics, risk_class: "R3", executable: false, execution_authorized: false, verified_saving: null }], economics: { ...economics, status: "UNAVAILABLE", current_monthly_cost: null, candidate_monthly_cost: null, estimated_monthly_saving: null, component_costs: [], groups: [{ currency: "GBP", status: "CANDIDATE_COMPARISONS_ONLY", estimated_monthly_saving: null, estimated_annual_saving: null }] }, confidence: { status: "UNAVAILABLE", meaning: "EVIDENCE_COVERAGE_NOT_A_CALIBRATED_PROBABILITY", reasons: ["S3_ACCESS_PATTERN_UNKNOWN"] }, configuration_authority: "TERRAFORM", implementation_method: "DECLARATIVE_REMEDIATION_REVIEW", proposal: { risk_class: "R3", executable: false, execution_authorized: false }, pre_execution_ready: false, execution_authorized: false, verified_saving: null, source_refs: [{ kind: "AWS_S3_INVENTORY", id: "issued-inventory", version: "1", sha256: "b".repeat(64) }], model_assumptions: ["Alternative candidates are not additive savings."], assessment_hash: "c".repeat(64) };
}
function record(assessment = result()): S["ObjectStorageAssessmentRecord"] { return { id: "s3-assessment-one", version: 1, resource_id: bucket.id, dataset_id: dataset.id, status: "ASSESSED", created_at: stamp, current: false, currentness_blockers: ["S3_SOURCE_REVISION_CHANGED"], assessment }; }
function dashboard(): Dashboard {
  const recommendation: Recommendation = { id: "s3-advice-one", version: 1, model_kind: "OBJECT_STORAGE_ASSESSMENT_V1", object_storage_assessment_id: "s3-assessment-one", resource_id: bucket.id, workload_id: null, title: "Review analytics storage policy", category: "S3_STANDARD_TO_STANDARD_IA", risk_class: "R3", status: "NO_CHANGE", monthly_saving: null, annual_saving: null, confidence: "UNAVAILABLE", evidence: {}, pre_execution_ready: false };
  return { org: { id: "org", version: 1, name: "S3 presentation", paused: false }, fixture: false, resources: [bucket], recommendations: [recommendation], workloads: [], cloud_accounts: [], policies: [], schedules: [], change_plans: [], executions: [], savings: [], audit: [], data_quality: [], readiness: [] };
}
async function setup(page: Page) {
  const writes: { path: string; body: unknown; version?: string; key?: string }[] = [];
  await page.addInitScript(() => { sessionStorage.setItem("finops.oidc.state", "s3-presentation"); sessionStorage.setItem("finops.oidc.verifier", "s3-presentation"); });
  await page.route("**/.well-known/openid-configuration", route => route.fulfill({ json: { token_endpoint: "http://127.0.0.1:4177/__s3-token" } }));
  await page.route("**/__s3-token", route => route.fulfill({ json: { access_token: "presentation-only", expires_in: 3600 } }));
  await page.route("**/v1/**", route => {
    const request = route.request(), path = new URL(request.url()).pathname;
    if (request.method() === "POST") writes.push({ path, body: request.postData() ? request.postDataJSON() : null, version: request.headers()["if-match"], key: request.headers()["idempotency-key"] });
    const reply = (json: unknown, status = 200) => route.fulfill({ json, status });
    if (path === "/v1/dashboard") return reply(dashboard());
    if (path === "/v1/object-storage-datasets") return request.method() === "POST" ? reply({ ...dataset, ...request.postDataJSON(), id: "dataset-created", version: 1 }, 201) : reply({ items: [dataset], next_cursor: null });
    if (path === "/v1/object-storage-datasets/dataset-one/revisions") return reply({ ...dataset, ...request.postDataJSON(), version: 2 }, 201);
    if (path === "/v1/object-storage-assessments") return request.method() === "POST" ? reply(record(), 202) : reply({ items: [record()], next_cursor: null });
    if (path === "/v1/object-storage-assessments/s3-assessment-one") return reply(record());
    if (path === "/v1/object-storage-access-sources") return request.method() === "POST" ? reply({ ...request.postDataJSON(), id: "collector-issued", version: 1, dataset_version: 1, provider_resource_id: bucket.provider_resource_id, account_id: "111122223333", region: "eu-west-1", issuer: "https://machine.example.invalid", enabled: true, created_at: stamp }, 201) : reply({ items: [], next_cursor: null });
    if (path === "/v1/source-connections" && request.method() === "POST") return reply({ ...request.postDataJSON(), id: "s3-source-created", version: 1 }, 201);
    if (path === "/v1/coverage") {
      const group = { currency: "GBP", basis: "POSITIVE_BILLED_CHARGES", complete: false, detected_spend: "1000000", analysed_spend: "10", observation_only_spend: "20", blocked_spend: "30", unsupported_spend: "999940", credits: "-100", net_spend: "999900", analysed_percent: null };
      return reply({ period: { start: "2026-10-01T00:00:00Z", end: stamp }, groups: [group], object_storage_groups: [{ ...group, detected_spend: "1000", analysed_spend: "0", unsupported_spend: "950", net_spend: "900" }], blockers: ["S3_ACCESS_PATTERN_UNKNOWN"] });
    }
    return reply({ message: "No presentation evidence registered." }, 404);
  });
  const go = (hash: string) => page.goto(`/?code=presentation&state=s3-presentation#${hash}`);
  await go("workloads"); return { writes, go };
}

test("S3 inventory retains denied reads and dataset revisions declare requirements without observations", async ({ page }) => {
  const state = await setup(page); await page.getByRole("button", { name: "Inspect S3 analytics-store", exact: true }).click();
  const context = page.getByRole("dialog", { name: "S3 bucket and datasets", exact: true });
  const native = context.getByRole("region", { name: "S3 native configuration read states", exact: true });
  await expect(native.getByRole("row").filter({ hasText: "Lifecycle" })).toContainText("Unavailable");
  await expect(native.getByRole("row").filter({ hasText: "Replication" })).toContainText("Absent");
  await context.getByRole("button", { name: "Revise dataset Analytics logs", exact: true }).click();
  const form = page.getByRole("dialog", { name: "Revise S3 dataset", exact: true });
  await form.getByLabel("Expected remaining lifetime (days)", { exact: true }).fill("365");
  await form.getByLabel("Required recovery time (seconds)", { exact: true }).fill("18000");
  await form.getByRole("button", { name: "Save dataset requirements", exact: true }).click();
  expect(state.writes).toHaveLength(1); expect(state.writes[0]).toMatchObject({ path: "/v1/object-storage-datasets/dataset-one/revisions", version: '"1"', body: { resource_id: bucket.id, name: dataset.name, selector: dataset.selector, policy: { ...policy, remaining_lifetime_days: "365", rto_seconds: "18000" } } }); expect(state.writes[0].key).toBeTruthy();
  await expect(context.getByRole("button", { name: "Assess dataset Analytics logs", exact: true })).toBeVisible();
  await context.getByRole("button", { name: "Assess dataset Analytics logs", exact: true }).click();
  expect(state.writes[1]).toMatchObject({ path: "/v1/object-storage-assessments", version: '"0"', body: { resource_id: bucket.id, dataset_id: dataset.id } });
  await expect(page.getByRole("dialog", { name: "S3 assessment", exact: true })).toBeVisible();
});

test("S3 advice preserves exact large populations, age-only unknowns, signed economics and no mutation controls", async ({ page }) => {
  const state = await setup(page); await state.go("recommendations");
  const card = page.locator(".recommendation-card").filter({ hasText: "Review analytics storage policy" }); await expect(card).toContainText("R3 · S3 proposal");
  await expect(card.getByRole("button", { name: "Create change plan", exact: true })).toHaveCount(0);
  await card.getByRole("button", { name: "Inspect S3 recommendation s3-advice-one", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "S3 assessment", exact: true });
  await expect(dialog.getByRole("alert")).toContainText("S3 source revision changed");
  const cohort = dialog.getByRole("region", { name: "S3 dataset populations and access evidence", exact: true });
  await expect(cohort).toContainText("9007199254740993 objects"); await expect(cohort).toContainText("Age observed"); await expect(cohort).toContainText("Incomplete object inventory");
  await dialog.getByText("Inspect economics for STANDARD_IA · candidate-one", { exact: true }).click();
  const economics = dialog.getByRole("region", { name: "S3 candidate economic comparison", exact: true });
  await expect(economics.getByRole("row").filter({ hasText: /^Estimated monthly saving including transition/ })).toContainText("-5.000 GBP");
  await expect(economics.getByRole("row").filter({ hasText: /^Estimated annual saving/ })).toContainText("Unavailable");
  await expect(economics.getByRole("row").filter({ hasText: /^Current-class minimum-duration obligation/ })).toContainText("0 GBP");
  await expect(dialog.getByRole("button", { name: /Delete|Execute|Approve|Create.*plan|Archive objects|Update lifecycle/ })).toHaveCount(0); expect(state.writes).toHaveLength(0);
});

test("S3 coverage supplements the all-AWS denominator and report registration accepts issued dataset IDs only", async ({ page }) => {
  const state = await setup(page); await state.go("connections"); await page.getByText("Inspect assessed and unsupported spend", { exact: true }).click();
  const all = page.getByRole("region", { name: "All AWS assessment spend coverage", exact: true }), s3 = page.getByRole("region", { name: "S3 assessment spend coverage", exact: true });
  await expect(all).toContainText("1000000 GBP"); await expect(s3).toContainText("1000 GBP"); await expect(s3).toContainText("0 GBP"); await expect(s3).toContainText("Unavailable");
  await page.getByRole("button", { name: "Register S3 evidence source", exact: true }).click();
  const form = page.getByRole("dialog", { name: "Register S3 evidence source", exact: true });
  for (const [name, value] of [["Source AWS account ID", "111122223333"], ["Source bucket", "analytics-store"], ["Existing report delivery bucket", "existing-reports"], ["Report bucket owner account ID", "111122223333"], ["Report delivery prefix", "inventory/"], ["Approved read-role binding ID", "binding-issued"], ["Inventory configuration ID", "inventory-native"], ["Issued dataset identifiers, comma separated", "dataset-one"]]) await form.getByLabel(name, { exact: true }).fill(value);
  await form.getByRole("button", { name: "Register S3 source", exact: true }).click();
  expect(state.writes).toHaveLength(1); expect(state.writes[0].body).toEqual({ kind: "AWS_S3_INVENTORY", account_id: "111122223333", region: "eu-west-1", bucket: "analytics-store", report_bucket: "existing-reports", report_owner: "111122223333", prefix: "inventory/", read_role_binding_id: "binding-issued", inventory_id: "inventory-native", dataset_ids: ["dataset-one"] }); expect(state.writes[0].key).toBeTruthy();
});

test("S3 collector registration declares a machine identity without supplying activity or historical evidence", async ({ page }) => {
  const state = await setup(page); await state.go("connections");
  await page.getByRole("combobox", { name: "S3 bucket for access collectors", exact: true }).selectOption(bucket.id);
  await page.getByRole("button", { name: "Register independent S3 collector", exact: true }).click();
  const form = page.getByRole("dialog", { name: "Register S3 access collector", exact: true });
  for (const [name, value] of [["Issued dataset identifier", dataset.id], ["Machine OIDC subject", "collector-subject"], ["Metric definition identifier", "dataset-get-access"], ["Metric definition version", "1"]]) await form.getByLabel(name, { exact: true }).fill(value);
  await form.getByLabel("Customer declares this collector covers the selected dataset's reads", { exact: true }).check();
  await expect(form).toContainText("Console tokens cannot submit observations");
  await form.getByRole("button", { name: "Register independent S3 collector", exact: true }).click();
  expect(state.writes).toHaveLength(1); expect(state.writes[0]).toMatchObject({ path: "/v1/object-storage-access-sources", version: '"0"', body: { resource_id: bucket.id, dataset_id: dataset.id, subject: "collector-subject", metric_definition: { id: "dataset-get-access", version: "1", unit: "s3-get-requests-and-bytes" }, authoritative_access_scope: true } });
  expect(Object.keys(state.writes[0].body as object).sort()).toEqual(["authoritative_access_scope", "dataset_id", "metric_definition", "resource_id", "subject"]); expect(state.writes[0].key).toBeTruthy();
  await expect(form).toHaveCount(0);
});
