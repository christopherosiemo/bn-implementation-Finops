import { expect, type Page } from "@playwright/test";
import { test } from "./presentation";
import type { components } from "../src/api.generated";
import type { Dashboard, Resource, Recommendation } from "../src/types";

// Supplemental checks through the normal App only. Route doubles establish
// presentation, IDs-only requests and unavailable-value semantics, not AWS,
// OIDC authenticity, immutable persistence or financial acceptance.
type S = components["schemas"];
const stamp = "2026-10-20T00:00:00Z";
const resource: Resource = { id: "nat-resource", version: 1, name: "payments-egress", provider: "AWS", resource_type: "NAT_GATEWAY", provider_resource_id: "nat-native", workload_id: "payments-prod", environment: "PRODUCTION", state: "AVAILABLE", configuration_authority: "TERRAFORM", hourly_effective_cost: null, monthly_effective_cost: null, currency: null, eligibility: "OBSERVATION_ONLY", blockers: ["NETWORK_FLOW_SCOPE_INCOMPLETE"], network_configuration: { account_id: "111122223333", region: "eu-west-1", vpc_id: "vpc-native", subnet_id: null, availability_mode: "regional", availability_zone: null, connectivity_type: "public", last_seen: stamp, topology_hash: "a".repeat(64) } };
const policy: S["NetworkPolicy"] = { id: "network-policy", version: 1, resource_id: resource.id, name: "Payments resilience", policy: { owner: "payments", configuration_authority: "TERRAFORM", criticality: "PRODUCTION", required_azs: 2, public_access_required: null, security_reviewed: null }, created_at: stamp };
function assessment(): S["NetworkAssessment"] {
  const economics: S["NetworkEconomics"] = { status: "MODELLED_NATIVE_CUSTOMER_ECONOMICS", currency: "GBP", observed_allocated_cost: "100.000000000001", current_window_cost: "100.000000000001", candidate_window_cost: "150.000000000001", estimated_window_saving: "-50", estimated_monthly_saving: "-50.000000000001", estimated_annual_saving: null, nat_hourly_retained: true, pricing_basis: "NATIVE_CUSTOMER_NET_ONLY", allocation_basis: "EXCLUSIVE_COHORT_ALLOCATION", component_costs: [{ component: "NAT_PROCESSING", current_window_cost: "100.000000000001", candidate_window_cost: "150.000000000001", avoided_window_cost: "-50", attribution_basis: "MODELLED_EXCLUSIVE_ALLOCATION_OF_NATIVE_BILLING" }] };
  return { schema_version: "1", contract_version: 1, model_version: "network-v1", model_kind: "NETWORK_ASSESSMENT_V1", semantics_version: "aws-network-2026-10-20", semantics_sha256: "b".repeat(64), binding: { resource_id: resource.id }, status: "NO_CHANGE", reason_code: "NETWORK_ASSESSMENT_COMPLETED", blockers: ["NETWORK_FLOW_SCOPE_INCOMPLETE"], window_start: "2026-09-20T00:00:00Z", window_end: stamp, history_days: "30", topology_hash: "a".repeat(64), configuration_authority: "TERRAFORM", cohorts: [{ id: "cohort-native", family: "B", bytes: "9007199254740993", destination_service: "secretsmanager", destination_region: "eu-west-1", attribution_complete: false, traffic_complete: false, current_path: ["payments-prod", "nat-native", "secretsmanager"], target_path: ["payments-prod", "interface-endpoint", "secretsmanager"], candidate_id: "candidate-native", blockers: ["NETWORK_FLOW_SCOPE_INCOMPLETE"] }], candidates: [{ id: "candidate-native", cohort_id: "cohort-native", family: "B", kind: "INTERFACE_ENDPOINT_REVIEW", decision: "DO_NOT_CREATE_ENDPOINT", status: "NO_CHANGE", reason_code: "NETWORK_DO_NOT_CREATE_ENDPOINT", blockers: [], classification: null, current_path: ["payments-prod", "nat-native", "secretsmanager"], target_path: ["payments-prod", "interface-endpoint", "secretsmanager"], route_table_ids: ["rtb-native"], economics, confidence: { status: "LIMITED", reasons: ["NETWORK_FLOW_SCOPE_INCOMPLETE"], meaning: "EVIDENCE_COVERAGE_NOT_A_CALIBRATED_PROBABILITY" }, security_impact: { classification: "REVIEW_REQUIRED", effects: ["DNS_BEHAVIOUR_CHANGES", "ENDPOINT_SECURITY_GROUP_IMPACT"], reviewed: false }, configuration_authority: "TERRAFORM", implementation_method: "DECLARATIVE_REMEDIATION_REVIEW", read_only: true, pre_execution_ready: false, execution_authorized: false, verified_saving: null }], economics: { currency: "GBP", detected_native_cost: "100.000000000001", estimated_monthly_saving: null, estimated_annual_saving: null, status: "INDEPENDENT_CANDIDATES_NEVER_SUMMED" }, denominators: { native_processed_bytes: null, observed_processed_bytes: "9007199254740993", attributed_cohort_bytes: "9007199254740993", unattributed_bytes: null, observation_complete: false, flow_complete: false, billing_complete: true, billing_scope_complete: false }, read_only: true, pre_execution_ready: false, execution_authorized: false, verified_saving: null, evidence_refs: [], source_refs: [], model_assumptions: ["NAT hourly obligations continue."], assessment_hash: "c".repeat(64) };
}
const record = (): S["NetworkAssessmentRecord"] => ({ id: "network-assessment", version: 1, resource_id: resource.id, policy_id: policy.id, status: "ASSESSED", created_at: stamp, current: false, currentness_blockers: ["NETWORK_TOPOLOGY_CHANGED"], assessment: assessment() });
function dashboard(): Dashboard {
  const recommendation: Recommendation = { id: "network-advice", version: 1, model_kind: "NETWORK_ASSESSMENT_V1", network_assessment_id: "network-assessment", resource_id: resource.id, workload_id: null, title: "Review payments endpoint economics", category: "NETWORK_ASSESSMENT", risk_class: "R3", status: "NO_CHANGE", monthly_saving: null, annual_saving: null, confidence: "LIMITED", evidence: {}, pre_execution_ready: false };
  return { org: { id: "org", version: 1, name: "Network presentation", paused: false }, fixture: false, resources: [resource], recommendations: [recommendation], workloads: [], cloud_accounts: [], policies: [], schedules: [], change_plans: [], executions: [], savings: [], audit: [], data_quality: [] };
}
async function setup(page: Page) {
  const writes: { path: string; body: unknown; version?: string; key?: string }[] = [], reads: string[] = [];
  await page.addInitScript(() => { sessionStorage.setItem("finops.oidc.state", "network-presentation"); sessionStorage.setItem("finops.oidc.verifier", "network-presentation"); });
  await page.route("**/.well-known/openid-configuration", route => route.fulfill({ json: { token_endpoint: "http://127.0.0.1:4177/__network-token" } }));
  await page.route("**/__network-token", route => route.fulfill({ json: { access_token: "presentation-only", expires_in: 3600 } }));
  await page.route("**/v1/**", route => {
    const request = route.request(), path = new URL(request.url()).pathname, reply = (json: unknown, status = 200) => route.fulfill({ json, status });
    reads.push(path);
    if (request.method() === "POST") writes.push({ path, body: request.postDataJSON(), version: request.headers()["if-match"], key: request.headers()["idempotency-key"] });
    if (path === "/v1/dashboard") return reply(dashboard());
    if (path === "/v1/resources") return reply({ items: [resource], next_cursor: null });
    if (path === "/v1/network-policies") return request.method() === "POST" ? reply({ ...policy, ...request.postDataJSON() }, 201) : reply({ items: [policy], next_cursor: null });
    if (path === "/v1/network-policies/network-policy/revisions") return reply({ ...policy, ...request.postDataJSON(), version: 2 }, 201);
    if (path === "/v1/network-assessments") return request.method() === "POST" ? reply(record(), 202) : reply({ items: [record()], next_cursor: null });
    if (path === "/v1/network-assessments/network-assessment") return reply(record());
    if (path === "/v1/source-connections") return reply({ ...request.postDataJSON(), id: "flow-source", version: 1 }, 201);
    if (path === "/v1/coverage") {
      const group: S["AssessmentCoverageGroup"] = { currency: "GBP", basis: "POSITIVE_BILLED_CHARGES", complete: false, detected_spend: "1000000", analysed_spend: "100", observation_only_spend: "200", blocked_spend: "300", unsupported_spend: "999400", credits: "-500", net_spend: "999500", analysed_percent: null };
      return reply({ period: { start: "2026-09-20T00:00:00Z", end: stamp }, groups: [group], network_groups: [{ ...group, detected_spend: "1000", unsupported_spend: "400", net_spend: "500" }], blockers: ["NETWORK_BILLING_SCOPE_INCOMPLETE"] });
    }
    return reply({ message: "No presentation evidence registered." }, 404);
  });
  const go = (hash: string) => page.goto(`/?code=presentation&state=network-presentation#${hash}`); await go("workloads"); return { writes, reads, go };
}
test("network details preserve regional topology and IDs-only requests without converting missing requirements into false", async ({ page }) => {
  const state = await setup(page); expect(state.reads).not.toContain("/v1/network-assessments");
  await page.getByRole("button", { name: "Inspect network payments-egress", exact: true }).click();
  const context = page.getByRole("dialog", { name: "Network resource and requirements", exact: true }); await expect(context).toContainText("regional"); await expect(context).toContainText("Unknown");
  await context.getByRole("button", { name: "Revise network policy Payments resilience", exact: true }).click();
  const form = page.getByRole("dialog", { name: "Revise network requirements", exact: true }); await expect(form.getByRole("combobox", { name: "Public connectivity required", exact: true })).toHaveValue("UNKNOWN");
  await form.getByRole("button", { name: "Save network requirements", exact: true }).click(); expect(state.writes[0]).toMatchObject({ path: "/v1/network-policies/network-policy/revisions", version: '"1"', body: { resource_id: resource.id, name: policy.name, policy: policy.policy } });
  await context.getByRole("button", { name: "Assess with policy Payments resilience", exact: true }).click(); expect(state.writes[1]).toMatchObject({ path: "/v1/network-assessments", version: '"0"', body: { resource_id: resource.id, policy_id: policy.id } }); expect(state.writes.every(write => write.key)).toBe(true);
  await expect(page.getByRole("dialog", { name: "Network assessment", exact: true })).toBeVisible();
});
test("normal network recommendations retain signed economics, partial attribution, security review and no execution controls", async ({ page }) => {
  const state = await setup(page); await state.go("recommendations");
  const card = page.locator(".recommendation-card").filter({ hasText: "Review payments endpoint economics" }); await expect(card.getByRole("button", { name: "Create change plan", exact: true })).toHaveCount(0);
  await card.getByRole("button", { name: "Inspect network recommendation network-advice", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "Network assessment", exact: true }); await expect(dialog.getByRole("alert")).toContainText("Network topology changed");
  await expect(dialog.getByRole("region", { name: "Network traffic cohorts", exact: true }).first()).toContainText("9007199254740993"); await expect(dialog).toContainText("Do not create endpoint"); await expect(dialog).toContainText("Dns behaviour changes"); await expect(dialog).toContainText("Declarative remediation review"); await expect(dialog).toContainText("Limited");
  await dialog.getByText("Inspect network economics candidate-native", { exact: true }).click(); const table = dialog.getByRole("region", { name: "Network economic comparison", exact: true });
  await expect(table.getByRole("row").filter({ hasText: /^Estimated monthly run-rate/ })).toContainText("-50.000000000001 GBP"); await expect(table.getByRole("row").filter({ hasText: /^Estimated annual saving/ })).toContainText("Unavailable");
  await expect(dialog.getByRole("button", { name: /Execute|Approve|Release|Delete|Create.*endpoint|Change.*route/ })).toHaveCount(0); expect(state.writes).toHaveLength(0);
});
test("network coverage keeps all-AWS denominator and registers only an existing commissioned Flow Log", async ({ page }) => {
  const state = await setup(page); await state.go("connections"); await page.getByText("Inspect assessed and unsupported spend", { exact: true }).click();
  await expect(page.getByRole("region", { name: "All AWS assessment spend coverage", exact: true })).toContainText("1000000 GBP"); const coverage = page.getByRole("region", { name: "Network assessment spend coverage", exact: true }); await expect(coverage).toContainText("1000 GBP"); await expect(coverage).toContainText("-500 GBP"); await expect(coverage).toContainText("Unavailable");
  await page.getByRole("button", { name: "Register network Flow Logs", exact: true }).click(); const form = page.getByRole("dialog", { name: "Register network Flow Logs", exact: true });
  for (const [label, value] of [["Source AWS account ID", "111122223333"], ["Existing Flow Log ID", "fl-existing"], ["Approved network read-role binding ID", "network-read-binding"], ["Versioned Flow Log delivery bucket", "network-logs"], ["Delivery bucket owner account ID", "111122223333"], ["Registered delivery prefix", "logs/"], ["Native VPC, subnet or interface IDs, comma separated", "vpc-native, subnet-native"], ["Native log-format fields, in order", "version account-id interface-id bytes packets start end action log-status flow-direction pkt-dst-aws-service traffic-path"]]) await form.getByLabel(label, { exact: true }).fill(value);
  await form.getByRole("button", { name: "Register commissioned Flow Logs", exact: true }).click(); expect(state.writes).toHaveLength(1); expect(state.writes[0]).toMatchObject({ path: "/v1/source-connections", version: '"0"', body: { kind: "AWS_VPC_FLOW_LOGS", account_id: "111122223333", region: "eu-west-1", report_region: "eu-west-1", flow_log_id: "fl-existing", resource_ids: ["vpc-native", "subnet-native"], traffic_type: "ALL", max_aggregation_seconds: 60 } }); expect(state.writes[0].key).toBeTruthy();
});
