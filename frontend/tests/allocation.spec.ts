import { test, expect, type Page, type Route } from "@playwright/test";
import type { components } from "../src/api.generated";
import type { Dashboard } from "../src/types";

type Policy = components["schemas"]["AllocationPolicy"];
type Report = components["schemas"]["AllocationReport"];
const stamp = "2026-10-18T12:00:00Z";
const policy: Policy = {
  id: "allocation-policy-1",
  version: 1,
  hash: "policy-hash",
  definition: {
    schema_version: "1",
    name: "Current analytical ownership",
    rules: [],
  },
  created_by: "finance",
  created_at: stamp,
};
const source: Report["source"] = {
  kind: "CUSTOMER_IMPORT",
  coverage: "UNKNOWN",
  finality: "UNPROVEN",
  provenance: "CUSTOMER_IMPORT",
  reason_code: "CUSTOMER_REPORTED_COVERAGE_UNKNOWN",
  ingestion_job_id: "import-a",
  source_id: "customer-report",
  source_version: "pinned-version",
  raw_hash: "raw-hash",
  canonical_hash: "canonical-hash",
  execution_authorized: false,
  verified_saving: null,
};
const report: Report = {
  id: "report-a",
  version: 1,
  schema_version: "1",
  status: "PARTIAL_OBSERVATIONS",
  basis: "CURRENT_OWNERSHIP_VIEW",
  reason_codes: [
    "PROVISIONAL_ALLOCATION_ONLY",
    "HISTORICAL_OWNERSHIP_NOT_ASSERTED",
    "VERIFIED_SAVINGS_NOT_ASSERTED",
  ],
  policy_id: policy.id,
  source,
  mapping_as_of: stamp,
  mapping_hash: "inventory-map-hash",
  input_hash: "input-hash",
  result_hash: "result-hash",
  record_count: 3,
  line_count: 4,
  totals: [
    {
      currency: "GBP",
      observed_billed_total: null,
      known_billed_subtotal: "99999999999999999999999999.999999999999",
      allocated_subtotal: "99999999999999999999999999.999999999999",
      unallocated_subtotal: "0.000000000000",
      unknown_record_count: 1,
    },
    {
      currency: "USD",
      observed_billed_total: "-1.000000000001",
      known_billed_subtotal: "-1.000000000001",
      allocated_subtotal: "0.000000000000",
      unallocated_subtotal: "-1.000000000001",
      unknown_record_count: 0,
    },
  ],
  execution_authorized: false,
  verified_saving: null,
  created_at: stamp,
};
const line: components["schemas"]["AllocationLine"] = {
  id: "line-a",
  record_id: "record-a",
  source_id: source.source_id,
  source_version: source.source_version,
  resource_id: "resource-a",
  provider_resource_id: "i-a",
  workload_id: "workload-a",
  currency: "GBP",
  allocated_billed_cost: "0.000000000001",
  method: "POLICY_FIXED_SHARE",
  reason_code: "CURRENT_POLICY_MAPPING",
};
const observation: components["schemas"]["AllocationObservation"] = {
  id: "observation-a",
  record_id: "record-a",
  source_id: source.source_id,
  source_version: source.source_version,
  provider: "AWS",
  account_id: "111122223333",
  region: "eu-west-1",
  provider_resource_id: "i-a",
  currency: "GBP",
  observed_billed_cost: "0.000000000001",
};
const importSource: components["schemas"]["AllocationImportSource"] = {
  id: "import-a",
  status: "PERSISTED",
  provenance: "CUSTOMER_IMPORT",
  source_id: source.source_id,
  source_version: source.source_version,
  created_at: stamp,
  coverage: "UNKNOWN",
  execution_authorized: false,
  verified_saving: null,
};
function dashboard(): Dashboard {
  return {
    org: {
      id: "tenant-a",
      version: 1,
      name: "Allocation contract",
      paused: false,
    },
    fixture: true,
    cloud_accounts: [],
    workloads: ["a", "b"].map((id) => ({
      id: `workload-${id}`,
      version: 1,
      name: `Workload ${id.toUpperCase()}`,
      owner: "owner@example.test",
      environment: "NON_PRODUCTION",
      timezone: "UTC",
      incident: "CLEAR",
      job: "CLEAR",
      deployment: "CLEAR",
      signals_at: stamp,
    })),
    resources: [
      {
        id: "resource-a",
        version: 1,
        name: "Resource A",
        provider: "AWS",
        provider_resource_id: "i-a",
        resource_type: "EC2",
        workload_id: "workload-a",
        environment: "NON_PRODUCTION",
        state: "running",
        configuration_authority: "UNKNOWN",
        hourly_effective_cost: null,
        monthly_effective_cost: null,
        eligibility: "BLOCKED",
        blockers: [],
      },
    ],
    recommendations: [],
    policies: [],
    schedules: [],
    change_plans: [],
    executions: [],
    savings: [],
    audit: [],
    data_quality: [],
  };
}
type Write = {
  path: string;
  body: Record<string, unknown>;
  headers: Record<string, string>;
};
type Handler = (route: Route, url: URL) => Promise<boolean>;
async function open(
  page: Page,
  latest: Policy | null = policy,
  handler?: Handler,
) {
  const writes: Write[] = [],
    reads: string[] = [];
  let current = latest;
  await page.route("**/.well-known/openid-configuration", (route) => {
    const origin = new URL(page.url()).origin;
    return route.fulfill({
      json: {
        authorization_endpoint: `${origin}/__allocation/authorize`,
        token_endpoint: `${origin}/__allocation/token`,
      },
    });
  });
  await page.route("**/__allocation/authorize?**", (route) => {
    const params = new URL(route.request().url()).searchParams;
    const redirect = new URL(params.get("redirect_uri")!);
    redirect.searchParams.set("code", "allocation-contract");
    redirect.searchParams.set("state", params.get("state")!);
    return route.fulfill({
      status: 302,
      headers: { location: redirect.toString() },
    });
  });
  await page.route("**/__allocation/token", (route) =>
    route.fulfill({
      json: {
        access_token: `test.${Buffer.from(JSON.stringify({ name: "Finance operator" })).toString("base64url")}.test`,
        expires_in: 3600,
      },
    }),
  );
  await page.route("**/v1/**", async (route) => {
    const request = route.request(),
      url = new URL(request.url()),
      path = url.pathname;
    if (request.method() === "GET") reads.push(`${path}${url.search}`);
    else
      writes.push({
        path,
        body: request.postDataJSON(),
        headers: request.headers(),
      });
    if (handler && (await handler(route, url))) return;
    if (path === "/v1/dashboard") return route.fulfill({ json: dashboard() });
    if (path === "/v1/allocation-policies") {
      if (request.method() === "POST") {
        current = {
          ...policy,
          id: "policy-new",
          version: (current?.version ?? 0) + 1,
          definition: request.postDataJSON(),
        };
        return route.fulfill({ status: 201, json: current });
      }
      return route.fulfill({
        json: {
          items: current ? [current] : [],
          next_cursor: null,
          version: current?.version ?? 0,
          latest: current,
        },
      });
    }
    if (path === "/v1/allocation-policies/allocation-policy-1")
      return route.fulfill({ json: policy });
    if (path === "/v1/allocation-reports")
      return route.fulfill({
        status: request.method() === "POST" ? 201 : 200,
        json:
          request.method() === "POST"
            ? report
            : { items: [report], next_cursor: null },
      });
    if (path === "/v1/allocation-sources")
      return route.fulfill({
        json: { items: [importSource], next_cursor: null },
      });
    if (path === "/v1/allocation-reports/report-a")
      return route.fulfill({ json: report });
    if (path.endsWith("/lines"))
      return route.fulfill({ json: { items: [line], next_cursor: null } });
    if (path.endsWith("/observations"))
      return route.fulfill({
        json: { items: [observation], next_cursor: null },
      });
    return route.fulfill({
      status: 404,
      json: { message: "No contract data" },
    });
  });
  await page.goto("/");
  await page.getByRole("button", { name: "Sign in to your workspace" }).click();
  await expect(
    page.getByRole("heading", { name: "Cost operations overview." }),
  ).toBeVisible();
  await page
    .getByRole("link", { name: "Cost allocation", exact: true })
    .click();
  return { writes, reads };
}

test("allocation displays exact signed currency amounts and distinguishes unknown from explicit zero", async ({
  page,
}) => {
  await open(page);
  await page
    .getByRole("button", { name: "Inspect allocation report report-a" })
    .click();
  const details = page.getByRole("dialog", {
    name: "Allocation report evidence",
  });
  const totals = details.getByRole("region", {
    name: "Scrollable allocation currency totals",
  });
  const gbp = totals
    .getByRole("row")
    .filter({ has: page.getByRole("rowheader", { name: "GBP", exact: true }) });
  await expect(gbp).toContainText("Unavailable");
  await expect(gbp).toContainText(
    "GBP 99,999,999,999,999,999,999,999,999.999999999999",
  );
  await expect(gbp).toContainText("GBP 0.00");
  await expect(totals).toContainText("USD -1.000000000001");
  await expect(
    details.getByRole("region", {
      name: "Scrollable derived allocation entries",
    }),
  ).toContainText("GBP 0.000000000001");
  await expect(details).toContainText("Coverage: Unknown · finality: Unproven");
  await expect(details).toContainText("CURRENT_OWNERSHIP_VIEW");
  await expect(details).toContainText("no verified savings");
});

test("allocation policy typed fixed shares bind initial version zero and send no authority or money", async ({
  page,
}) => {
  const { writes } = await open(page, null);
  await page
    .getByRole("button", { name: "Create allocation policy", exact: true })
    .click();
  const editor = page.getByRole("dialog", {
    name: "Save allocation policy revision",
  });
  await editor
    .getByLabel("Allocation policy name")
    .fill("Split shared development");
  await editor
    .getByRole("button", { name: "Add fixed share rule", exact: true })
    .click();
  await editor.getByLabel("Resources for rule 1").selectOption("resource-a");
  await editor
    .getByRole("combobox", { name: "Rule 1 recipient 1", exact: true })
    .selectOption("workload-a");
  await editor
    .getByRole("spinbutton", { name: "Rule 1 share 1 (ppm)", exact: true })
    .fill("600000");
  await editor.getByRole("button", { name: "Add recipient to rule 1" }).click();
  await editor
    .getByRole("combobox", { name: "Rule 1 recipient 2", exact: true })
    .selectOption("workload-b");
  await editor
    .getByRole("spinbutton", { name: "Rule 1 share 2 (ppm)", exact: true })
    .fill("400000");
  await editor
    .getByRole("button", { name: "Save policy revision", exact: true })
    .click();
  await expect(editor).not.toBeVisible();
  expect(writes).toHaveLength(1);
  expect(writes[0].headers["if-match"]).toBe('"0"');
  expect(writes[0].headers["idempotency-key"]).toMatch(/^[a-f0-9-]{36}$/);
  expect(writes[0].body).toEqual({
    schema_version: "1",
    name: "Split shared development",
    rules: [
      {
        resource_ids: ["resource-a"],
        recipients: [
          { workload_id: "workload-a", weight_ppm: 600000 },
          { workload_id: "workload-b", weight_ppm: 400000 },
        ],
      },
    ],
  });
});

test("allocation policy rejects incomplete shares before mutation and surfaces optimistic conflict", async ({
  page,
}) => {
  const { writes } = await open(page, policy, async (route) => {
    if (route.request().method() === "POST") {
      await route.fulfill({
        status: 409,
        json: { message: "Current allocation policy changed" },
      });
      return true;
    }
    return false;
  });
  await page.getByRole("button", { name: "Revise allocation policy" }).click();
  const editor = page.getByRole("dialog", {
    name: "Save allocation policy revision",
  });
  await editor
    .getByRole("button", { name: "Add fixed share rule", exact: true })
    .click();
  await editor.getByLabel("Resources for rule 1").selectOption("resource-a");
  await editor
    .getByRole("combobox", { name: "Rule 1 recipient 1", exact: true })
    .selectOption("workload-a");
  await editor
    .getByRole("spinbutton", { name: "Rule 1 share 1 (ppm)", exact: true })
    .fill("999999");
  await editor
    .getByRole("button", { name: "Save policy revision", exact: true })
    .click();
  await expect(editor.getByRole("alert")).toContainText(
    "exactly 1,000,000 ppm",
  );
  expect(writes).toHaveLength(0);
  await editor
    .getByRole("spinbutton", { name: "Rule 1 share 1 (ppm)", exact: true })
    .fill("1000000");
  await editor
    .getByRole("button", { name: "Save policy revision", exact: true })
    .click();
  await expect(
    page
      .getByRole("alert")
      .filter({ hasText: "Current allocation policy changed" }),
  ).toBeVisible();
  await expect(editor).toBeVisible();
  expect(writes[0].headers["if-match"]).toBe('"1"');
});

test("allocation collections paginate independently and report selection never submits billing payloads", async ({
  page,
}) => {
  const { writes, reads } = await open(page, policy, async (route, url) => {
    const cursor = url.searchParams.get("cursor");
    if (url.pathname.endsWith("/lines")) {
      await route.fulfill({
        json: {
          items: [
            cursor
              ? {
                  ...line,
                  id: "line-b",
                  record_id: "record-b",
                  workload_id: null,
                  method: "UNALLOCATED",
                  allocated_billed_cost: null,
                }
              : line,
          ],
          next_cursor: cursor ? null : "lines:opaque/+",
        },
      });
      return true;
    }
    if (url.pathname.endsWith("/observations")) {
      await route.fulfill({
        json: {
          items: [
            cursor
              ? {
                  ...observation,
                  id: "observation-b",
                  record_id: "record-b",
                  observed_billed_cost: null,
                }
              : observation,
          ],
          next_cursor: cursor ? null : "observations:opaque/+",
        },
      });
      return true;
    }
    if (
      url.pathname === "/v1/allocation-reports" &&
      route.request().method() === "GET"
    ) {
      await route.fulfill({
        json: {
          items: [cursor ? { ...report, id: "report-history" } : report],
          next_cursor: cursor ? null : "reports:opaque/+",
        },
      });
      return true;
    }
    return false;
  });
  await page
    .getByRole("button", { name: "Load more allocation reports", exact: true })
    .click();
  await expect(
    page.getByRole("button", {
      name: "Inspect allocation report report-history",
    }),
  ).toBeVisible();
  await page
    .getByRole("button", { name: "Create allocation report", exact: true })
    .click();
  const create = page.getByRole("dialog", { name: "Create allocation report" });
  await create
    .getByLabel("Persisted allocation import")
    .selectOption("import-a");
  await create.getByRole("button", { name: "Seal allocation report" }).click();
  const details = page.getByRole("dialog", {
    name: "Allocation report evidence",
  });
  await expect(details).toBeVisible();
  expect(writes[0].body).toEqual({
    policy_id: policy.id,
    source: { kind: "CUSTOMER_IMPORT", ingestion_job_id: "import-a" },
  });
  expect(writes[0].headers["if-match"]).toBe('"1"');
  await details
    .getByRole("button", { name: "Load more allocation entries", exact: true })
    .click();
  await expect(
    details.getByRole("region", {
      name: "Scrollable derived allocation entries",
    }),
  ).toContainText("Unallocated");
  await expect(
    details.getByRole("button", {
      name: "Load more billing observations",
      exact: true,
    }),
  ).toBeVisible();
  await details
    .getByRole("button", {
      name: "Load more billing observations",
      exact: true,
    })
    .click();
  expect(
    reads.some((path) =>
      path.includes("lines?limit=20&cursor=lines%3Aopaque%2F%2B"),
    ),
  ).toBe(true);
  expect(
    reads.some((path) =>
      path.includes("observations?limit=20&cursor=observations%3Aopaque%2F%2B"),
    ),
  ).toBe(true);
  expect(
    reads.some((path) =>
      path.includes("reports?limit=10&cursor=reports%3Aopaque%2F%2B"),
    ),
  ).toBe(true);
  expect(reads.every((path) => !path.includes("ingestion-jobs"))).toBe(true);
});

test("allocation financial scope errors remain distinct from empty financial evidence", async ({
  page,
}) => {
  await open(page, null, async (route, url) => {
    if (url.pathname.startsWith("/v1/allocation-")) {
      await route.fulfill({
        status: 403,
        json: { message: "Financial organization scope is required" },
      });
      return true;
    }
    return false;
  });
  await expect(
    page.getByRole("heading", { name: "Financial scope unavailable" }),
  ).toBeVisible();
  await expect(page.getByRole("alert")).toContainText(
    "Financial organization scope is required",
  );
  await expect(
    page.getByRole("button", { name: "Create allocation report", exact: true }),
  ).not.toBeVisible();
  await expect(
    page.getByText("No allocation reports", { exact: true }),
  ).not.toBeVisible();
});
