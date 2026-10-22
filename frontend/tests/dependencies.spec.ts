import { expect, test, type Page, type Route } from "@playwright/test";
import type { Dashboard, DependencyReview } from "../src/types";

// Presentation-contract tests use an isolated OIDC/dashboard transport. Real
// dependency authorization, graph binding and provider safety have Go tests.
function dashboard(): Dashboard {
  return {
    org: {
      id: "dependency-ui",
      version: 1,
      name: "Dependency safety",
      paused: false,
    },
    fixture: false,
    cloud_accounts: [],
    policies: [],
    schedules: [],
    change_plans: [],
    executions: [],
    savings: [],
    audit: [],
    data_quality: [],
    recommendations: [],
    workloads: [
      {
        id: "workload-api",
        version: 2,
        name: "Development API",
        owner: "api-owner@example.test",
        environment: "NON_PRODUCTION",
        timezone: "UTC",
        incident: "CLEAR",
        deployment: "CLEAR",
        job: "CLEAR",
        signals_at: "2026-10-18T10:00:00Z",
      },
    ],
    resources: [
      {
        id: "api",
        version: 7,
        name: "dev-api",
        provider: "AWS",
        resource_type: "EC2",
        provider_resource_id: "i-api",
        workload_id: "workload-api",
        environment: "NON_PRODUCTION",
        state: "running",
        configuration_authority: "TERRAFORM",
        hourly_effective_cost: null,
        monthly_effective_cost: null,
        currency: null,
        eligibility: "BLOCKED",
        blockers: ["DEPENDENCY_EXTERNAL_CONSUMER"],
      },
    ],
    readiness: [
      {
        id: "readiness-api",
        version: 1,
        resource_id: "api",
        status: "BLOCKED",
        pre_execution_ready: false,
        verification_status: "MEASURING",
        dependency_status: "BLOCKED",
        dependency_reasons: ["DEPENDENCY_EXTERNAL_CONSUMER"],
        dependency_review_id: null,
        dependency_graph_hash: "graph-v3",
        checked_at: "2026-10-18T10:00:00Z",
        expires_at: "2026-10-18T10:05:00Z",
        binding: {
          tenant_id: "dependency-ui",
          resource_id: "api",
          provider_resource_id: "i-api",
          account_id: "111122223333",
          region: "eu-west-1",
          currency: null,
        },
      },
    ],
    dependency_graph: {
      version: 3,
      inventory_hash: "inventory-v3",
      graph_hash: "graph-v3",
      status: "DECLARED",
      reasons: [],
      reviews: [],
      nodes: [
        {
          id: "workload:workload-api",
          kind: "WORKLOAD",
          workload_id: "workload-api",
          name: "Development API",
          owner: "api-owner@example.test",
          environment: "NON_PRODUCTION",
        },
        {
          id: "resource:api",
          kind: "RESOURCE",
          resource_id: "api",
          workload_id: "workload-api",
          name: "dev-api",
          owner: "api-owner@example.test",
          environment: "NON_PRODUCTION",
          provider: "AWS",
          provider_resource_id: "i-api",
          account_id: "111122223333",
          region: "eu-west-1",
          configuration_authority: "TERRAFORM",
        },
        {
          id: "workload:consumer",
          kind: "WORKLOAD",
          workload_id: "consumer",
          name: "Shared consumer",
          owner: "consumer-owner@example.test",
          environment: "PRODUCTION",
        },
      ],
      edges: [
        {
          from: "workload:workload-api",
          to: "resource:api",
          type: "RUNS_ON",
          source: "DISCOVERED_MAPPING",
        },
        {
          from: "workload:consumer",
          to: "resource:api",
          type: "DEPENDS_ON",
          source: "OPERATOR_DECLARED",
        },
      ],
    },
  };
}

async function openGraph(
  page: Page,
  data: Dashboard,
  mutate?: (route: Route) => Promise<void>,
) {
  const writes: {
    path: string;
    body: Record<string, unknown>;
    headers: Record<string, string>;
  }[] = [];
  await page.route("**/.well-known/openid-configuration", (route) => {
    const origin = new URL(page.url()).origin;
    return route.fulfill({
      json: {
        authorization_endpoint: `${origin}/__dependency-oidc/authorize`,
        token_endpoint: `${origin}/__dependency-oidc/token`,
      },
    });
  });
  await page.route("**/__dependency-oidc/authorize?**", (route) => {
    const query = new URL(route.request().url()).searchParams;
    const redirect = new URL(query.get("redirect_uri")!);
    redirect.searchParams.set("code", "dependency-contract");
    redirect.searchParams.set("state", query.get("state")!);
    return route.fulfill({
      status: 302,
      headers: { location: redirect.toString() },
    });
  });
  await page.route("**/__dependency-oidc/token", (route) =>
    route.fulfill({
      json: {
        access_token: `test.${Buffer.from(JSON.stringify({ name: "Dependency reviewer" })).toString("base64url")}.test`,
        expires_in: 3600,
      },
    }),
  );
  await page.route("**/v1/**", async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    if (request.method() === "GET" && path === "/v1/dashboard")
      return route.fulfill({ json: data });
    if (request.method() !== "GET") {
      writes.push({
        path,
        body: request.postDataJSON() as Record<string, unknown>,
        headers: request.headers(),
      });
      if (mutate) return mutate(route);
    }
    return route.fulfill({
      status: 500,
      json: { message: "Unexpected presentation-contract request" },
    });
  });
  await page.goto("/");
  await page.getByRole("button", { name: "Sign in to your workspace" }).click();
  await expect(
    page.getByRole("heading", { name: "Cost operations overview." }),
  ).toBeVisible();
  await page.getByRole("link", { name: "Workloads & resources" }).click();
  return writes;
}

test("dependency mappings and declarations show owners and blockers without claiming complete discovery", async ({
  page,
}, testInfo) => {
  const writes = await openGraph(page, dashboard());
  await expect(
    page.getByRole("heading", { name: "Dependency safety", exact: true }),
  ).toBeVisible();
  await expect(
    page.getByText("Manual review is a trust boundary."),
  ).toBeVisible();
  const nodes = page.getByRole("region", { name: "Dependency graph nodes" });
  await expect(nodes.getByRole("table")).toContainText(
    "consumer-owner@example.test",
  );
  await expect(nodes.getByRole("table")).toContainText("Production");
  const edges = page.getByRole("region", { name: "Dependency graph edges" });
  await expect(edges.getByRole("table")).toContainText("Discovered mapping");
  await expect(edges.getByRole("table")).toContainText("Operator declared");
  await expect(edges.getByRole("table")).toContainText("Hard dependency");
  const review = page.getByRole("region", { name: "Dependency review status" });
  await expect(review).toContainText("Dependency external consumer");
  await expect(review).toContainText("No recorded dependency review");
  await page.screenshot({
    path: testInfo.outputPath("dependencies-desktop.png"),
    fullPage: true,
  });
  await page.setViewportSize({ width: 390, height: 844 });
  await page
    .getByRole("heading", { name: "Dependency safety", exact: true })
    .scrollIntoViewIfNeeded();
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= window.innerWidth,
    ),
  ).toBe(true);
  const scroller = nodes.getByRole("region", {
    name: "Scrollable graph inventory",
  });
  await scroller.focus();
  await page.keyboard.press("ArrowRight");
  await expect
    .poll(() => scroller.evaluate((element) => element.scrollLeft))
    .toBeGreaterThan(0);
  await scroller.evaluate((element) => {
    element.scrollLeft = 0;
  });
  await page.screenshot({
    path: testInfo.outputPath("dependencies-mobile.png"),
    fullPage: true,
  });
  expect(writes).toEqual([]);
});

test("explicit review binds resource version, graph and at most 24 hours while preserving blocked results", async ({
  page,
}) => {
  const data = dashboard();
  const writes = await openGraph(page, data, async (route) => {
    const body = route.request().postDataJSON() as {
      valid_until: string;
      note: string;
    };
    const review: DependencyReview = {
      id: "review-api",
      resource_id: "api",
      graph_version: 3,
      graph_hash: "graph-v3",
      inventory_hash: "inventory-v3",
      reviewed_by: "platform-admin",
      reviewed_at: new Date().toISOString(),
      expires_at: body.valid_until,
      note: body.note,
      status: "BLOCKED",
      reasons: ["DEPENDENCY_EXTERNAL_CONSUMER"],
    };
    data.dependency_graph!.reviews.push(review);
    data.readiness![0].dependency_review_id = review.id;
    await route.fulfill({ status: 201, json: review });
  });
  await page
    .getByRole("button", { name: "Review dependencies for dev-api" })
    .click();
  const dialog = page.getByRole("dialog", {
    name: "Review resource dependencies",
  });
  const submit = dialog.getByRole("button", {
    name: "Record dependency review",
  });
  await expect(submit).toBeDisabled();
  await dialog
    .getByLabel("Dependency review note")
    .fill("Reviewed downstream consumers with the workload owners.");
  await dialog
    .getByLabel(
      "I reviewed discovered mappings, declared dependencies, and external consumers for this resource.",
    )
    .check();
  await dialog.getByLabel("Review validity in hours").fill("25");
  await expect(submit).toBeDisabled();
  await dialog.getByLabel("Review validity in hours").fill("24");
  const before = Date.now();
  await submit.click();
  await expect(dialog).not.toBeVisible();
  expect(writes).toHaveLength(1);
  expect(writes[0].path).toBe("/v1/resources/api/dependency-reviews");
  expect(writes[0].headers["if-match"]).toBe('"7"');
  expect(writes[0].headers["idempotency-key"]).toMatch(/^[a-f0-9-]{36}$/);
  expect(writes[0].body.graph_version).toBe(3);
  expect(writes[0].body.acknowledgement).toBe(
    "REVIEWED_DISCOVERED_AND_EXTERNAL_DEPENDENCIES",
  );
  const expiry = Date.parse(String(writes[0].body.valid_until));
  expect(expiry).toBeGreaterThanOrEqual(before + 24 * 3_600_000);
  expect(expiry).toBeLessThanOrEqual(Date.now() + 24 * 3_600_000);
  expect(String(writes[0].body.valid_until)).toMatch(/Z$/);
  await expect(
    page.getByRole("region", { name: "Dependency review status" }),
  ).toContainText("Recorded result: Blocked");
});

test("initial graph version zero sends If-Match and only existing-node hard edge declarations", async ({
  page,
}) => {
  const data = dashboard();
  data.dependency_graph!.version = 0;
  data.dependency_graph!.status = "UNKNOWN";
  data.dependency_graph!.reasons = ["DEPENDENCY_GRAPH_NOT_DECLARED"];
  data.dependency_graph!.edges = data.dependency_graph!.edges.filter(
    (edge) => edge.source === "DISCOVERED_MAPPING",
  );
  const writes = await openGraph(page, data, async (route) => {
    const body = route.request().postDataJSON() as {
      edges: { from: string; to: string; type: "DEPENDS_ON" }[];
    };
    data.dependency_graph!.version = 1;
    data.dependency_graph!.status = "DECLARED";
    data.dependency_graph!.edges.push(
      ...body.edges.map((edge) => ({
        ...edge,
        source: "OPERATOR_DECLARED" as const,
      })),
    );
    await route.fulfill({ status: 201, json: data.dependency_graph });
  });
  await page
    .getByRole("button", { name: "Declare dependencies", exact: true })
    .click();
  const dialog = page.getByRole("dialog", { name: "Declare dependency graph" });
  await dialog.getByRole("button", { name: "Add declared dependency" }).click();
  await dialog.getByLabel("Source node 1").selectOption("workload:consumer");
  await dialog.getByLabel("Destination node 1").selectOption("resource:api");
  await expect(
    dialog.getByLabel("Dependency type 1").locator("option"),
  ).toHaveCount(11);
  await dialog.getByLabel("Dependency type 1").selectOption("DEPENDS_ON");
  await dialog
    .getByLabel("Reason for this graph revision")
    .fill("Record the shared consumer as a hard dependency.");
  await dialog.getByRole("button", { name: "Save graph revision" }).click();
  await expect(dialog).not.toBeVisible();
  expect(writes).toHaveLength(1);
  expect(writes[0].path).toBe("/v1/resource-graph");
  expect(writes[0].headers["if-match"]).toBe('"0"');
  expect(writes[0].body.edges).toEqual([
    { from: "workload:consumer", to: "resource:api", type: "DEPENDS_ON" },
  ]);
  await expect(
    page.getByText("Graph revision 1", { exact: true }),
  ).toBeVisible();
  await expect(
    page.getByRole("region", { name: "Dependency review status" }),
  ).toContainText("Blocked");
});

test("a rejected dependency review stays visible and never approves or executes a plan", async ({
  page,
}) => {
  const writes = await openGraph(page, dashboard(), (route) =>
    route.fulfill({
      status: 403,
      json: { message: "PLATFORM_ADMIN is required for dependency review." },
    }),
  );
  await page
    .getByRole("button", { name: "Review dependencies for dev-api" })
    .click();
  const dialog = page.getByRole("dialog", {
    name: "Review resource dependencies",
  });
  await dialog
    .getByLabel("Dependency review note")
    .fill("Reviewed visible graph and external dependencies.");
  await dialog.getByRole("checkbox").check();
  await dialog
    .getByRole("button", { name: "Record dependency review" })
    .click();
  await expect(dialog.getByRole("alert")).toContainText("Review not recorded");
  await expect(dialog).toBeVisible();
  expect(writes).toHaveLength(1);
  expect(writes[0].path).toBe("/v1/resources/api/dependency-reviews");
});

test("a scoped empty graph remains unknown rather than implying no dependencies", async ({
  page,
}) => {
  const data = dashboard();
  data.dependency_graph = {
    version: 0,
    nodes: [],
    edges: [],
    graph_hash: "",
    inventory_hash: "",
    status: "UNKNOWN",
    reasons: ["WORKLOAD_SCOPE_DENIED"],
    reviews: [],
  };
  const writes = await openGraph(page, data);
  await expect(
    page.getByText("Workload scope denied", { exact: true }),
  ).toBeVisible();
  await expect(
    page.getByText(/Dependency safety remains unknown/),
  ).toBeVisible();
  await expect(
    page.getByRole("button", { name: "Declare dependencies", exact: true }),
  ).toBeDisabled();
  await expect(
    page.getByRole("button", { name: "Review dependencies for dev-api" }),
  ).toBeDisabled();
  expect(writes).toEqual([]);
});

test("schema-three plans need dependency binding while fixture schema two remains usable", async ({
  page,
}) => {
  const data = dashboard();
  data.readiness![0].pre_execution_ready = true;
  data.readiness![0].status = "READY";
  data.readiness![0].dependency_status = "READY";
  data.readiness![0].dependency_reasons = [];
  data.readiness![0].dependency_review_id = "review-api";
  data.change_plans = [
    {
      id: "plan-v3",
      version: 1,
      recommendation_id: "rec-api",
      resource_id: "api",
      schedule_id: "",
      status: "APPROVED",
      risk_class: "R1",
      operations: [],
      expires_at: "2026-10-19T00:00:00Z",
      baseline_id: "baseline",
      measurement_id: "measurement",
      readiness_id: "readiness-api",
      payload: { schema_version: "3", proof_set_id: "proof-set" },
    },
  ];
  const writes = await openGraph(page, data);
  await page.getByRole("link", { name: "Schedules & policies" }).click();
  const execute = page.getByRole("button", { name: "Execute approved plan" });
  await expect(execute).toBeDisabled();
  data.change_plans[0].payload = {
    schema_version: "3",
    proof_set_id: "proof-set",
    dependency_review_id: "review-api",
    dependency_graph_hash: "graph-v3",
    slo_objective_id: "objective-api",
    slo_objective_version: 1,
    slo_objective_hash: "objective-hash",
    slo_evaluation_id: "evaluation-api",
    slo_evaluation_hash: "evaluation-hash",
  };
  await page.getByRole("button", { name: "Refresh data" }).click();
  await expect(execute).toBeEnabled();
  data.change_plans[0].payload = { schema_version: "2" };
  await page.getByRole("button", { name: "Refresh data" }).click();
  await expect(execute).toBeEnabled();
  expect(writes).toEqual([]);
});
