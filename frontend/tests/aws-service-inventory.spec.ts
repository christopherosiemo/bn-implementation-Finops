import { expect, type Page } from "@playwright/test";
import { test } from "./presentation";
import type { components } from "../src/api.generated";
import type { Dashboard, Resource } from "../src/types";

// Presentation doubles only. Native ingestion and persisted OIDC acceptance are
// separate gates; these cases prove no provider/customer maturity.
type S = components["schemas"];
const resources = [
  ["ECS", "ECS_SERVICE", "orders-fargate", { launch_type: "FARGATE", desired_count: 3, running_count: 3, pending_count: 0 }],
  ["EKS", "EKS_CLUSTER", "orders-eks", { version: "1.35" }],
  ["ELASTICACHE", "ELASTICACHE_REPLICATION_GROUP", "orders-cache", { engine: "valkey", multi_az: true }],
  ["DYNAMODB", "DYNAMODB_TABLE", "orders-table", { billing_mode: "PAY_PER_REQUEST" }],
  ["ELB", "LOAD_BALANCER", "orders-alb", { subtype: "application", scheme: "internal" }],
].map(([family, kind, name, configuration], index) => ({ id: `aws-service-${index}`, version: 1, name, provider: "AWS", resource_type: kind, provider_resource_id: `arn:aws:synthetic:eu-west-1:111122223333:resource/${name}`, account_id: "111122223333", region: "eu-west-1", workload_id: "orders", owner: null, environment: "NON_PRODUCTION", state: "OBSERVED", configuration_authority: "UNKNOWN", hourly_effective_cost: null, monthly_effective_cost: null, currency: null, eligibility: "OBSERVE_ONLY", blockers: ["AWS_SERVICE_OPTIONAL_READ_DENIED"], service_family: family, aws_service_configuration: configuration, spend_coverage: "OBSERVATION_ONLY", provider_relationships: [{ type: "MEMBER_OF", analytical: true }] })) as Resource[];
async function setup(page: Page) {
  const writes: { path: string; body: unknown; key?: string; version?: string }[] = [], reads: string[] = [];
  const dashboard: Dashboard = { org: { id: "org", version: 1, name: "AWS service presentation", paused: false }, fixture: false, resources, workloads: [{ id: "orders", version: 1, name: "Orders", owner: "owner", timezone: "UTC", environment: "NON_PRODUCTION", incident: "UNKNOWN", deployment: "UNKNOWN", job: "UNKNOWN", signals_at: "2026-10-21T00:00:00Z" }], recommendations: [], cloud_accounts: [], policies: [], schedules: [], change_plans: [], executions: [], savings: [], audit: [], data_quality: [] };
  await page.addInitScript(() => { sessionStorage.setItem("finops.oidc.state", "aws-service-presentation"); sessionStorage.setItem("finops.oidc.verifier", "aws-service-presentation"); });
  await page.route("**/.well-known/openid-configuration", route => route.fulfill({ json: { token_endpoint: "http://127.0.0.1:4177/__service-token" } }));
  await page.route("**/__service-token", route => route.fulfill({ json: { access_token: "presentation-only", expires_in: 3600 } }));
  await page.route("**/v1/**", route => {
    const request = route.request(), url = new URL(request.url()), path = url.pathname, reply = (json: unknown, status = 200) => route.fulfill({ json, status }); reads.push(path + url.search);
    if (request.method() === "POST") writes.push({ path, body: request.postDataJSON(), key: request.headers()["idempotency-key"], version: request.headers()["if-match"] });
    if (path === "/v1/dashboard") return reply(dashboard);
    if (path === "/v1/resources") return reply({ items: resources.filter(item => item.resource_type === url.searchParams.get("resource_type")), next_cursor: null });
    if (path.endsWith("/aws-service-evidence")) return reply({ resource_id: path.split("/")[3], current: false, reason_codes: ["AWS_SERVICE_OPTIONAL_READ_DENIED"], snapshot: { source_version: "native-projection-version", collection_complete: false } });
    if (path === "/v1/source-connections") return reply({ ...request.postDataJSON(), id: "source", version: 1 }, 201);
    if (path === "/v1/coverage") { const group: S["AssessmentCoverageGroup"] = { currency: "GBP", basis: "POSITIVE_BILLED_CHARGES", complete: false, detected_spend: "100.000000000001", analysed_spend: "0", observation_only_spend: "80", blocked_spend: "0", unsupported_spend: "20.000000000001", credits: "-5", net_spend: "95.000000000001", analysed_percent: null }; return reply({ period: { start: "2026-10-01T00:00:00Z", end: "2026-10-21T00:00:00Z" }, groups: [group], service_groups: [{ service: "AmazonECS", groups: [group] }], blockers: [] }); }
    return reply({ message: "No presentation evidence registered" }, 404);
  });
  const go = (hash: string) => page.goto(`/?code=presentation&state=aws-service-presentation#${hash}`); await go("workloads"); return { writes, reads, go };
}
test("native AWS service inventory retains unknown cost, placement, workload scope and read-only detail", async ({ page }) => {
  const state = await setup(page); await page.getByText("Inspect AWS service inventory", { exact: true }).click();
  const inventory = page.getByRole("region", { name: "Scoped AWS service inventory", exact: true }); await expect(inventory).toContainText("FARGATE"); await expect(inventory).toContainText("Unavailable");
  await inventory.getByRole("button", { name: "Inspect AWS service orders-fargate", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "AWS service resource", exact: true }); await expect(dialog).toContainText("Desired count: 3"); await expect(dialog).toContainText("Pending count: 0"); await expect(dialog).toContainText("Aws service optional read denied"); await expect(dialog.getByRole("button", { name: /Execute|Approve|Delete|Resize|Refresh assessment/ })).toHaveCount(0); await dialog.getByRole("button", { name: "Close dialog", exact: true }).click();
  for (const family of ["EKS", "ELASTICACHE", "DYNAMODB", "ELB"]) { await page.getByLabel("AWS service family", { exact: true }).selectOption(family); await expect(inventory.getByRole("button", { name: /^Inspect AWS service / })).toHaveCount(1); }
  await page.getByLabel("AWS service workload", { exact: true }).selectOption("orders"); await expect.poll(() => state.reads.some(path => path.includes("workload_id=orders"))).toBe(true); expect(state.writes).toHaveLength(0);
});
test("AWS service sources register only native scope and service coverage preserves signed spend", async ({ page }) => {
  const state = await setup(page); await state.go("connections"); await page.getByText("Inspect assessed and unsupported spend", { exact: true }).click(); const coverage = page.getByRole("region", { name: "AWS service spend partitions", exact: true }); await expect(coverage).toContainText("100.000000000001 GBP"); await expect(coverage).toContainText("-5 GBP"); await expect(coverage).toContainText("Unavailable");
  await page.getByRole("button", { name: "Register AWS service inventory", exact: true }).click(); const form = page.getByRole("dialog", { name: "Register AWS service inventory", exact: true }); for (const [label, value] of [["AWS service source name", "Existing service inventory"], ["AWS service account ID", "111122223333"], ["Approved AWS service read binding ID", "service-reader"]]) await form.getByLabel(label, { exact: true }).fill(value); await form.getByLabel("DynamoDB", { exact: true }).check(); await form.getByRole("button", { name: "Register existing AWS service source", exact: true }).click(); expect(state.writes).toHaveLength(1); expect(state.writes[0]).toMatchObject({ path: "/v1/source-connections", version: '"0"', body: { kind: "AWS_SERVICE_NATIVE_V1", account_id: "111122223333", region: "eu-west-1", read_role_binding_id: "service-reader", scope_mode: "ACCOUNT", service_families: ["ECS", "DYNAMODB"], root_resource_arns: [] } }); expect(state.writes[0].key).toBeTruthy();
});
