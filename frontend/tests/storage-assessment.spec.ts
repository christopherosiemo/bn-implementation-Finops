import { expect, type Page } from "@playwright/test";
import { test } from "./presentation";
import type { components } from "../src/api.generated";
import type { Dashboard, Recommendation } from "../src/types";

// Normal App presentation with explicit route doubles. These cases do not
// establish OIDC, native AWS provenance, persistence, prices or safe execution.
type S = components["schemas"];
const stamp = "2026-10-20T00:00:00Z";
const period = { start: "2026-10-06T00:00:00Z", end: stamp, observed_utc_days: 14, required_utc_days: 14, expected_hours: 336, observed_hours: 336, coverage_basis: "ACTUAL_NATIVE_BINS_AND_SAMPLE_COUNTS_NO_INTERPOLATION" as const };
function assessment(): S["StorageAssessment"] {
  const result: S["StorageAssessment"] = { schema_version: "1", model_version: "storage-observed-demand-v1", binding: { resource_id: "volume-1", workload_id: "workload-1" }, resource_kind: "EBS_VOLUME", status: "BLOCKED", recommendation_kind: "STORAGE_GP2_TO_GP3", decision_code: "EVIDENCE_OR_COMPATIBILITY_BLOCKED", assessment_hash: "a".repeat(64),
    current_configuration: { volume_type: "gp2", size_gib: "100", encrypted: true, multi_attach_enabled: false, attachments: [{ instance_id: "i-orders", device: "/dev/sdf", state: "attached", delete_on_termination: false }] }, candidate_configuration: { volume_type: "gp3", size_gib: "100", iops: "3000", throughput_mib_per_second: "125" },
    evidence_window: period, metric_distributions: [
      { metric: "read_iops", unit: "Count/Second", statistic: "MAXIMUM_OF_NATIVE_PERIOD_RATES", status: "COMPLETE", expected_hours: 336, observed_hours: 336, expected_sample_count: 4032, sample_count: 4032, expected_native_sample_count: 20160, native_sample_count: "20160", minimum: "0", maximum: "0", p50_of_period_statistics: "0", p95_of_period_statistics: "0", p99_of_period_statistics: "0", zero_operation_hours: 336 },
      { metric: "read_latency", unit: "Seconds", statistic: "MAXIMUM_OF_NATIVE_PERIOD_OPERATION_MEANS", status: "COMPLETE_ZERO_OPERATIONS", expected_hours: 336, observed_hours: 336, expected_sample_count: 4032, sample_count: 4032, expected_native_sample_count: 20160, native_sample_count: "20160", minimum: null, maximum: null, p50_of_period_statistics: null, p95_of_period_statistics: null, p99_of_period_statistics: null, zero_operation_hours: 336 },
    ], economics: { current_hourly_cost: "0", current_monthly_cost: "0", candidate_hourly_cost: null, candidate_monthly_cost: null, estimated_monthly_saving: null, estimated_annual_saving: null, currency: "USD", basis: "HELD_NATIVE_CUR_NET_COMPONENT_RATES_730H_MONTH_8760H_YEAR", status: "UNAVAILABLE", component_costs: [], verified_saving: null },
    checks: [{ dimension: "iops", status: "BLOCKED", unit: "Count/Second", observed_demand: "0", required_with_reserve: "0", available: null, planning_limit: null, basis: "OBSERVED_NATIVE_PERIOD_PEAK_WITH_EXPLICIT_HEADROOM" }],
    blockers: ["STORAGE_ATTACHED_INSTANCE_SUSTAINED_BUDGET_UNKNOWN"], confidence: { status: "UNAVAILABLE", meaning: "OBSERVED_DEMAND_SCREEN_NOT_STATISTICAL_CONFIDENCE", reasons: ["TARGET_VALIDATION_REQUIRED"] }, proposal: { risk_class: "R3", executable: false, execution_authorized: false }, verified_saving: null,
    configuration_authority: "TERRAFORM", implementation_method: "DECLARATIVE_REMEDIATION_REVIEW", unattached_review: null, snapshot_reviews: [], source_refs: [{ kind: "EBS_INVENTORY", id: "source-issued", version: "1", sha256: "b".repeat(64) }], candidates: [], model_assumptions: ["No calibrated forecast, mutation or verified saving"] };
  result.candidates = [{ id: "gp3-candidate", status: result.status, recommendation_kind: result.recommendation_kind, decision_code: result.decision_code, candidate_configuration: result.candidate_configuration, checks: result.checks, economics: result.economics, blockers: result.blockers, target_validation_required: true, execution_authorized: false, verified_saving: null }];
  return result;
}
function record(value: S["StorageAssessment"], queued = false): S["StorageAssessmentRecord"] {
  return { id: "storage-request-1", version: queued ? 1 : 2, resource_id: "volume-1", workload_id: "workload-1", status: queued ? "QUEUED" : value.status === "BLOCKED" ? "BLOCKED" : "ASSESSED", created_at: stamp, current: true, currentness_blockers: [], assessment: queued ? null : value };
}
function safety(): S["WorkloadSafetyProfile"] {
  return { id: "profile-1", workload_id: "workload-1", version: 1, hash: "c".repeat(64), schema_version: "1", criticality: "NON_PRODUCTION", statefulness: "STATEFUL", high_seasonality: false, timezone: "UTC", min_replicas: 1, min_zones: 1, headroom: { cpu_free_ppm: 200000, memory_free_ppm: 200000, reserve_above_forecast_ppm: 300000 }, saturation: { cpu_p99_ppm: 900000, memory_p99_ppm: 900000 }, rto_seconds: 300, rpo_seconds: null, maintenance: [], recurring_blackouts: [], blackouts: [], demand_events: [], max_simultaneous_change_ppm: 100000, vm_cooldown_seconds: 300,
    database: { connections_max_fraction: "0.8", iops_max_fraction: "0.8", throughput_max_fraction: "0.8", storage_max_fraction: "0.8", max_read_latency_seconds: "0.01", max_write_latency_seconds: "0.01", max_disk_queue_depth: "2", max_replica_lag_seconds: "1" } };
}
function dashboard(): Dashboard {
  const volume = { id: "volume-1", version: 1, name: "orders-data", provider: "AWS", resource_type: "EBS_VOLUME", provider_resource_id: "vol-orders", workload_id: "workload-1", environment: "PRODUCTION", state: "in-use", configuration_authority: "TERRAFORM", hourly_effective_cost: null, monthly_effective_cost: null, currency: null, eligibility: "OBSERVATION_ONLY", blockers: ["STORAGE_EXECUTION_NOT_SUPPORTED"], storage_configuration: { volume_id: "vol-orders", volume_type: "gp2", size_gib: "100", attachments: [{ instance_id: "i-orders", device: "/dev/sdf", state: "attached", delete_on_termination: false }] } };
  const advice: Recommendation = { id: "storage-advice", version: 1, resource_id: volume.id, workload_id: volume.workload_id, title: "Review orders storage performance", category: "STORAGE_GP2_TO_GP3", risk_class: "R3", status: "BLOCKED", monthly_saving: null, annual_saving: null, currency: "USD", confidence: "UNAVAILABLE", evidence: {}, model_kind: "STORAGE_ASSESSMENT_V1", storage_assessment_id: "storage-request-1", pre_execution_ready: false };
  return { org: { id: "org", version: 1, name: "Storage presentation", paused: false }, fixture: false, cloud_accounts: [], workloads: [{ id: "workload-1", version: 1, name: "Orders", environment: "PRODUCTION", owner: "Owner", timezone: "UTC", incident: "UNKNOWN", deployment: "UNKNOWN", job: "UNKNOWN", signals_at: stamp }],
    resources: [volume, { ...volume, id: "snapshot-1", name: "orders-backup", resource_type: "EBS_SNAPSHOT", provider_resource_id: "snap-orders", state: "completed", storage_configuration: { snapshot_id: "snap-orders", volume_id: "vol-orders", storage_tier: "standard", encrypted: true } }, { ...volume, id: "ec2-1", name: "orders-worker", resource_type: "EC2", provider_resource_id: "i-orders" }],
    recommendations: [advice, { ...advice, id: "ec2-advice", title: "Review idle worker", risk_class: "R1", category: "SCHEDULE", resource_id: "ec2-1", model_kind: undefined, storage_assessment_id: undefined }], policies: [], schedules: [], change_plans: [], executions: [], savings: [], audit: [], data_quality: [], readiness: [] };
}
async function setup(page: Page, selected = assessment(), denied = false, stale = false) {
  const writes: { path: string; body: unknown; version?: string; key?: string }[] = [];
  let queued = false;
  await page.addInitScript(() => { sessionStorage.setItem("finops.oidc.state", "storage-presentation"); sessionStorage.setItem("finops.oidc.verifier", "storage-presentation"); });
  await page.route("**/.well-known/openid-configuration", route => route.fulfill({ json: { token_endpoint: "http://127.0.0.1:4177/__storage-token" } }));
  await page.route("**/__storage-token", route => route.fulfill({ json: { access_token: "presentation-only", expires_in: 3600 } }));
  await page.route("**/v1/**", route => {
    const request = route.request(), url = new URL(request.url()), path = url.pathname;
    const reply = (json: unknown, status = 200) => route.fulfill({ json, status });
    if (request.method() === "POST") writes.push({ path, body: request.postDataJSON(), version: request.headers()["if-match"], key: request.headers()["idempotency-key"] });
    if (path === "/v1/dashboard") return reply(dashboard());
    if (path === "/v1/storage-assessments") {
      if (denied) return reply({ message: "Storage scope denied." }, 403);
      if (request.method() === "POST") { queued = true; return reply(record(selected, true), 202); }
      return reply({ items: [url.searchParams.has("cursor") ? record(selected) : { ...record(selected), id: "older-storage-request" }], next_cursor: url.searchParams.has("cursor") ? null : "opaque-next" });
    }
    if (path === "/v1/storage-assessments/storage-request-1") return reply({ ...record(selected, queued), current: !stale, currentness_blockers: stale ? ["STORAGE_NATIVE_SOURCE_CHANGED"] : [] });
    if (path === "/v1/workloads/workload-1/safety-profiles") return request.method() === "POST" ? reply({ id: "profile-2", version: 2 }, 201) : reply({ latest: safety(), items: [safety()], next_cursor: null, version: 1 });
    if (path === "/v1/workloads/workload-1/safety-evaluation") return reply({ status: "BLOCKED", reason_codes: ["OBSERVED_PROOF_REQUIRED"] });
    return reply({ message: "No presentation evidence registered." }, 404);
  });
  const go = (hash: string) => page.goto(`/?code=presentation&state=storage-presentation#${hash}`);
  await go("workloads");
  return { writes, go, complete: () => { queued = false; } };
}

test("storage inventory uses only its resource ID and retains persisted zero, undefined latency and native attachments", async ({ page }) => {
  const state = await setup(page), row = page.getByRole("row").filter({ hasText: "orders-data" });
  await row.getByRole("button", { name: "Inspect storage orders-data", exact: true }).click();
  const context = page.getByRole("dialog", { name: "Storage resource", exact: true });
  await context.getByText("Attachments", { exact: true }).click();
  await expect(context).toContainText("/dev/sdf"); await expect(context).toContainText('"delete_on_termination": false');
  await context.getByRole("button", { name: "Close dialog", exact: true }).click();
  await row.getByRole("button", { name: "Assess storage orders-data", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "Storage assessment", exact: true });
  await expect(dialog.getByRole("status")).toContainText("assessment in progress");
  expect(state.writes).toHaveLength(1); expect(state.writes[0]).toMatchObject({ path: "/v1/storage-assessments", body: { resource_id: "volume-1" }, version: '"0"' }); expect(state.writes[0].key).toBeTruthy();
  state.complete(); await dialog.getByRole("button", { name: "Refresh selected storage assessment", exact: true }).click();
  const metrics = dialog.getByRole("region", { name: "Storage metric distributions", exact: true });
  await expect(metrics.getByRole("row").filter({ hasText: "read_iops" }).getByRole("cell").nth(1)).toHaveText("0");
  await expect(metrics.getByRole("row").filter({ hasText: "read_latency" }).getByRole("cell").nth(1)).toHaveText("Unavailable");
  await expect(dialog.getByRole("region", { name: "Storage assessment economics", exact: true }).getByRole("row").filter({ hasText: /^Current hourly cost/ })).toContainText("0 USD");
  await expect(dialog.getByRole("button", { name: /delete|detach|modify|create.*plan/i })).toHaveCount(0);
  await state.go("workloads"); await page.getByText("Storage assessment history", { exact: true }).click(); await page.getByRole("button", { name: "Load more storage assessments", exact: true }).click(); await page.getByRole("button", { name: "Inspect storage assessment storage-request-1", exact: true }).click();
  await expect(page.getByRole("region", { name: "Storage evidence quality", exact: true })).toContainText("Evidence quality: Unavailable");
});

test("storage recommendations stay outside EC2 execution and retain stale-source blockers", async ({ page }) => {
  const state = await setup(page, assessment(), false, true); await state.go("recommendations");
  const advice = page.locator(".recommendation-card").filter({ hasText: "Review orders storage performance" });
  await expect(advice).toContainText("R3 · Storage proposal"); await expect(advice.getByRole("button", { name: "Create change plan", exact: true })).toHaveCount(0);
  await expect(page.locator(".recommendation-card").filter({ hasText: "Review idle worker" }).getByRole("button", { name: "Create change plan", exact: true })).toHaveCount(1);
  await advice.getByRole("button", { name: "Inspect storage recommendation storage-advice", exact: true }).click();
  await expect(page.getByRole("alert").filter({ hasText: "stored assessment no longer matches" })).toContainText("Storage native source changed"); expect(state.writes).toHaveLength(0);
});

test("snapshot and unattached reviews preserve unknown dependencies and never recommend deletion or saving", async ({ page }) => {
  const value = assessment(); value.resource_kind = "EBS_SNAPSHOT"; value.recommendation_kind = "STORAGE_SNAPSHOT_RETENTION_REVIEW"; value.status = "OBSERVATION_ONLY"; value.candidate_configuration = null; value.evidence_window = null; value.metric_distributions = []; value.candidates = [];
  value.unattached_review = { owner: null, age_days: null, prior_attachment_context: "UNKNOWN_NOT_INFERRED_FROM_CURRENT_ABSENCE", backup_observed: null, quarantine_days: null, next_action: "REVIEW_SNAPSHOT_DEPENDENCIES_AND_RETENTION", deletion_recommended: false };
  value.snapshot_reviews = [{ snapshot_id: "snap-orders", source_volume_id: "vol-orders", classification: "UNKNOWN_DEPENDENCY", age_days: 40, monthly_carrying_cost: null, currency: null, dependency_state: null, ami_ids: null, restore_references: null, next_action: "ESTABLISH_DEPENDENCY_AND_RETENTION_POLICY", blockers: ["SNAPSHOT_DEPENDENCIES_UNKNOWN"], deletion_recommended: false, execution_authorized: false, estimated_saving: null }];
  const state = await setup(page, value); await state.go("recommendations"); await page.getByRole("button", { name: "Inspect storage recommendation storage-advice", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "Storage assessment", exact: true });
  await expect(dialog).toContainText("Evidence window unavailable"); await expect(dialog.getByRole("region", { name: "Unattached storage review", exact: true })).toContainText("Backup observed: Unknown");
  const snapshots = dialog.getByRole("region", { name: "Snapshot dependency and retention findings", exact: true }); await expect(snapshots).toContainText("Unknown dependency"); await expect(snapshots).toContainText("AMI references: Unknown"); await expect(snapshots).toContainText("Unavailable");
  await expect(dialog.getByRole("button", { name: /delete|restore|archive|create.*plan/i })).toHaveCount(0); expect(state.writes).toHaveLength(0);
});

test("smaller GiB targets remain a separate six-step migration with no in-place action", async ({ page }) => {
  const value = assessment(); value.recommendation_kind = "MIGRATION_OPPORTUNITY"; value.status = "OBSERVATION_ONLY"; value.candidate_configuration = { size_gib: "50" }; value.migration_requirements = ["NEW_VOLUME", "DATA_MIGRATION", "FILESYSTEM_HANDLING", "VALIDATION", "CUTOVER", "ROLLBACK"];
  const state = await setup(page, value); await state.go("recommendations"); await page.getByRole("button", { name: "Inspect storage recommendation storage-advice", exact: true }).click();
  const migration = page.getByRole("region", { name: "Separate storage migration requirements", exact: true }); await expect(migration.getByRole("listitem")).toHaveCount(6); await expect(migration).toContainText("not an in-place storage change");
  expect(state.writes).toHaveLength(0);
});

test("optional customer storage policy preserves null booleans and existing database policy", async ({ page }) => {
  const state = await setup(page); await page.getByRole("button", { name: "Configure safety requirements", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "Configure workload safety requirements", exact: true });
  await dialog.getByLabel("Declare storage requirements for this workload", { exact: true }).check();
  for (const [label, value] of [["Maximum IOPS capacity fraction", "0.8"], ["Maximum throughput capacity fraction", "0.7"], ["Maximum read latency (seconds)", "0.01"], ["Maximum write latency (seconds)", "0.02"], ["Maximum disk queue depth", "2"], ["Minimum burst balance (percent)", "20"], ["Snapshot retention requirement (days)", "30"], ["Unattached-volume quarantine requirement (days)", "7"]]) await dialog.getByLabel(label, { exact: true }).fill(value);
  await dialog.getByRole("combobox", { name: "Durability reduction allowed", exact: true }).selectOption("false"); await dialog.getByRole("button", { name: "Save safety requirements", exact: true }).click();
  await expect(dialog).not.toBeVisible(); const write = state.writes.find(item => item.path.endsWith("/safety-profiles")); expect(write?.version).toBe('"1"'); expect(write?.body).toMatchObject({ database: safety().database, storage: { iops_max_fraction: "0.8", throughput_max_fraction: "0.7", snapshot_retention_days: 30, quarantine_days: 7, backup_required: null, allow_durability_reduction: false, require_multi_attach: null, filesystem_review_required: null } });
});

test("denied storage history remains unavailable and does not create a usable result", async ({ page }) => {
  const state = await setup(page, assessment(), true); await page.getByText("Storage assessment history", { exact: true }).click(); await expect(page.getByRole("alert").filter({ hasText: "Storage assessments unavailable" })).toContainText("Storage scope denied"); expect(state.writes).toHaveLength(0);
});
