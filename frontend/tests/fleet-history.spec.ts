import { expect, test, type Page, type Route } from "@playwright/test";
import type { components } from "../src/api.generated";
import type {
  Dashboard,
  FleetDemandDefinition,
  FleetHistoryRegistration,
  FleetHistoryScope,
} from "../src/types";

// Presentation contracts supplement restricted-PostgreSQL/API/native producer
// acceptance. These mocked transports establish no source or execution authority.
const stamp = "2026-10-18T12:00:00Z";
const hash = "a".repeat(64);
const binding = {
  tenant_id: "history-ui",
  workload_id: "workload-api",
  provider: "AWS" as const,
  account_id: "111122223333",
  region: "eu-west-1" as const,
};
const registration: FleetHistoryRegistration = {
  id: "history-one",
  version: 1,
  hash,
  created_at: stamp,
  writer_role: "finops_api",
  registration: {
    schema_version: "1",
    id: "history-one",
    version: 1,
    binding,
    fleet_id: "api-fleet",
    asg_arn:
      "arn:aws:autoscaling:eu-west-1:111122223333:autoScalingGroup:12345678-1234-1234-1234-123456789abc:autoScalingGroupName/api",
    source_id: "aws-source",
    source_system: "AWS_SOURCE_CONNECTION",
    source_registration_version: 2,
    source_config_hash: hash,
    cadence_seconds: 60,
    max_gap_seconds: 120,
  },
};
const definition: FleetDemandDefinition = {
  id: "completed-definition",
  version: 1,
  registration_id: registration.id,
  registration_version: 1,
  hash,
  created_at: stamp,
  writer_role: "finops_api",
  definition: {
    schema_version: "1",
    id: "completed-definition",
    version: 1,
    binding,
    aggregation: "SINGLE_EXTERNAL_TOTAL",
    meaning: "COMPLETED_WORK",
    business_operation: "Orders completed",
    unit: "orders",
    metric: "activity.Completed",
    metric_definition_id: "orders-interval",
    metric_definition_version: "3",
    value_field: "COMPLETED",
    origin: "INDEPENDENT_EXTERNAL_SYSTEM",
    semantic_contract_id: "orders-v1",
    semantic_contract_hash: hash,
    source_id: "independent-source",
    source_system: "ACTIVITY_SOURCE",
    source_config_hash: hash,
    temporality: "DELTA",
    cadence_seconds: 60,
    max_gap_seconds: 60,
  },
};
const emptyPreview = { count: 0, hash, preview: [], truncated: false };
const gapPreview = {
  count: 1,
  hash,
  preview: [
    {
      start: "2026-10-04T00:00:00Z",
      end: "2026-10-18T00:00:00Z",
      reason_code: "INTERVAL_OWNERSHIP_UNPROVEN",
    },
  ],
  truncated: false,
};
const scope: FleetHistoryScope = {
  schema_version: "1",
  id: "scope-one",
  purpose: "READ_ONLY_FLEET_HISTORY_ANALYSIS",
  status: "BLOCKED",
  binding,
  fleet_id: "api-fleet",
  asg_arn: registration.registration.asg_arn,
  registration_id: registration.id,
  registration_version: 1,
  registration_hash: hash,
  definition_id: definition.id,
  definition_version: 1,
  definition_hash: hash,
  input_hash: hash,
  analysis_hash: hash,
  start: "2026-10-04T00:00:00Z",
  end: "2026-10-18T00:00:00Z",
  as_of: stamp,
  membership_status: "INTERVAL_OWNERSHIP_UNPROVEN",
  reference_root: hash,
  reference_count: 5,
  observation_count: 1,
  selected_observation_count: 1,
  demand_receipt_count: 1,
  membership_gaps: gapPreview,
  observation_gaps: gapPreview,
  issues: emptyPreview,
  superseded_ids: { ...emptyPreview, count: 1, preview: ["old-point"] },
  reason_codes: ["INTERVAL_OWNERSHIP_UNPROVEN", "DEMAND_HISTORY_INCOMPLETE"],
  demand: {
    status: "UNKNOWN",
    meaning_basis: "DECLARED_COMPLETED_WORK_SEMANTICS",
    unit: "orders",
    observed_units: "0",
    window_units: null,
    segments: {
      count: 1,
      hash,
      truncated: false,
      preview: [
        {
          start: "2026-10-17T12:00:00Z",
          end: "2026-10-17T12:01:00Z",
          status: "OBSERVED",
          units: "0",
          sample_ids: ["guarded-receipt"],
          reason_code: "COMPLETED_FIELD_OBSERVED",
        },
      ],
    },
    gaps: gapPreview,
    reason_codes: ["DEMAND_HISTORY_INCOMPLETE"],
  },
  hash,
  created_at: stamp,
  writer_role: "finops_api",
};
const point: components["schemas"]["FleetHistoryObservationRecord"] = {
  id: "native-point",
  registration_id: registration.id,
  registration_version: registration.version,
  hash,
  created_at: stamp,
  writer_role: "finops_ingester",
  observation: {
    schema_version: "1",
    id: "native-point",
    registration_id: registration.id,
    registration_version: 1,
    registration_hash: hash,
    asg_arn: registration.registration.asg_arn,
    observed_at: "2026-10-17T12:00:00Z",
    received_at: "2026-10-17T12:00:04Z",
    corrects_id: "old-point",
    source: {
      kind: "AWS_FLEET_MEMBERSHIP",
      binding,
      source_id: "aws-source",
      source_system: "AWS_SOURCE_CONNECTION",
      source_registration_version: 2,
      revision_id: "native-revision",
      config_hash: hash,
      receipt_id: "native-receipt",
      target: registration.registration.asg_arn,
      raw_sha256: hash,
      canonical_hash: hash,
      captured_at: "2026-10-17T12:00:00Z",
      storage_kind: "VERSIONED_OBJECT",
      archive: {
        bucket: "evidence",
        key: "history-ui/membership",
        version_id: "pinned-version",
        sha256: hash,
      },
    },
    members: [
      {
        instance_id: "i-one",
        launch_time: null,
        launch_template_id: "lt-one",
        launch_template_version: 7,
        hardware: null,
      },
    ],
  },
};
const dashboard: Dashboard = {
  org: {
    id: binding.tenant_id,
    version: 1,
    name: "Fleet history presentation",
    paused: false,
  },
  fixture: false,
  cloud_accounts: [],
  resources: [],
  recommendations: [],
  policies: [],
  schedules: [],
  change_plans: [],
  executions: [],
  savings: [],
  audit: [],
  data_quality: [],
  workloads: [
    {
      id: binding.workload_id,
      version: 1,
      name: "API workload",
      owner: "api@example.test",
      environment: "NON_PRODUCTION",
      timezone: "UTC",
      incident: "UNKNOWN",
      deployment: "UNKNOWN",
      job: "UNKNOWN",
      signals_at: stamp,
    },
  ],
  source_connections: [
    {
      id: "aws-source",
      version: 2,
      kind: "AWS_CUR2",
      name: "Approved AWS",
      payer_account_id: binding.account_id,
      usage_account_ids: [binding.account_id],
      region: binding.region,
      enabled: true,
      status: "HEALTHY",
      export_arn:
        "arn:aws:bcm-data-exports:eu-west-1:111122223333:export:read-only",
      read_role_binding_id: "approved-read-binding",
      bucket: "native-evidence",
      bucket_owner: binding.account_id,
      prefix: "exports/",
    },
  ],
  activity_sources: [
    {
      id: "independent-source",
      version: 1,
      workload_id: binding.workload_id,
      resource_id: "resource-api",
      provider_resource_id: "i-api",
      account_id: binding.account_id,
      region: binding.region,
      enabled: true,
      metric_definition: {
        id: "orders-interval",
        version: "3",
        unit: "orders",
      },
    },
  ],
};
type Write = {
  path: string;
  body: unknown;
  version?: string;
  idempotency?: string;
};
type Handler = (route: Route, url: URL) => Promise<boolean>;
async function open(page: Page, extra?: Handler) {
  const writes: Write[] = [];
  const queries: string[] = [];
  let registered = structuredClone(registration);
  let definitions = [structuredClone(definition)];
  await page.route("**/.well-known/openid-configuration", (route) => {
    const origin = new URL(page.url()).origin;
    return route.fulfill({
      json: {
        authorization_endpoint: `${origin}/__history/authorize`,
        token_endpoint: `${origin}/__history/token`,
      },
    });
  });
  await page.route("**/__history/authorize?**", (route) => {
    const params = new URL(route.request().url()).searchParams;
    const location = new URL(params.get("redirect_uri")!);
    location.searchParams.set("code", "presentation");
    location.searchParams.set("state", params.get("state")!);
    return route.fulfill({
      status: 302,
      headers: { location: location.toString() },
    });
  });
  await page.route("**/__history/token", (route) =>
    route.fulfill({
      json: { access_token: "presentation-only", expires_in: 3600 },
    }),
  );
  await page.route("**/v1/**", async (route) => {
    const url = new URL(route.request().url());
    const path = url.pathname;
    if (route.request().method() === "POST") {
      writes.push({
        path,
        body: route.request().postDataJSON(),
        version: route.request().headers()["if-match"],
        idempotency: route.request().headers()["idempotency-key"],
      });
    } else queries.push(`${path}${url.search}`);
    if (extra && (await extra(route, url))) return;
    const fulfill = (json: unknown, status = 200) =>
      route.fulfill({ status, json });
    if (path === "/v1/dashboard") return fulfill(dashboard);
    if (route.request().method() === "POST") {
      if (
        path === "/v1/fleet-history-registrations" ||
        (path.endsWith("/revisions") &&
          path.includes("fleet-history-registrations"))
      ) {
        const body = route
          .request()
          .postDataJSON() as components["schemas"]["FleetHistoryRegistrationRequest"];
        const version = path.endsWith("/revisions")
          ? registered.version + 1
          : 1;
        registered = {
          ...registration,
          version,
          registration: {
            ...registration.registration,
            version,
            fleet_id: body.fleet_id,
            asg_arn: body.asg_arn,
            cadence_seconds: body.cadence_seconds,
            max_gap_seconds: body.max_gap_seconds,
          },
        };
        return fulfill(registered, 201);
      }
      if (path === "/v1/fleet-demand-definitions") {
        const body = route
          .request()
          .postDataJSON() as components["schemas"]["FleetDemandDefinitionRequest"];
        definitions = [
          {
            ...definition,
            definition: {
              ...definition.definition,
              business_operation: body.business_operation,
              semantic_contract_id: body.semantic_contract_id,
              semantic_contract_hash: body.semantic_contract_hash,
            },
          },
        ];
        return fulfill(definitions[0], 201);
      }
      if (path === "/v1/fleet-history-scopes") return fulfill(scope, 201);
      return fulfill({ message: "Unexpected presentation mutation" }, 422);
    }
    if (path === "/v1/fleet-history-registrations")
      return fulfill({ items: [registered], next_cursor: null });
    if (path === `/v1/fleet-history-registrations/${registration.id}`)
      return fulfill(registered);
    if (path.endsWith("/observations"))
      return fulfill({ items: [point], next_cursor: null });
    if (path === "/v1/fleet-demand-definitions")
      return fulfill({ items: definitions, next_cursor: null });
    if (path === "/v1/fleet-history-scopes")
      return fulfill({ items: [scope], next_cursor: null });
    if (path === `/v1/fleet-history-scopes/${scope.id}`) return fulfill(scope);
    if (path.endsWith("/references"))
      return fulfill({ items: [], next_cursor: null });
    if (path.endsWith("/safety-profiles"))
      return fulfill({
        version: 0,
        latest: null,
        items: [],
        next_cursor: null,
      });
    return fulfill({ message: "No presentation evidence registered" }, 404);
  });
  await page.goto("/");
  await page.getByRole("button", { name: "Sign in to your workspace" }).click();
  await expect(
    page.getByRole("heading", { name: "Cost operations overview." }),
  ).toBeVisible();
  await page
    .getByRole("link", { name: "Workloads & resources", exact: true })
    .click();
  const inspect = async () => {
    await page
      .getByRole("button", {
        name: "Inspect fleet history api-fleet",
        exact: true,
      })
      .click();
    return page.getByRole("dialog", {
      name: "Fleet history evidence",
      exact: true,
    });
  };
  return { writes, queries, inspect };
}

test("fleet points retain unknown incarnations and corrected history while zero stays distinct from missing scope totals", async ({
  page,
}) => {
  const { inspect, writes } = await open(page);
  const dialog = await inspect();
  await dialog.getByText(/Native point native-point/).click();
  await expect(dialog).toContainText("Unknown launch incarnation");
  await expect(dialog).toContainText("Hardware unavailable");
  await expect(dialog).toContainText("Explicit correction of old-point");
  await expect(dialog).toContainText("pinned-version");
  await dialog
    .getByRole("button", {
      name: "Inspect history scope scope-one",
      exact: true,
    })
    .click();
  const evidence = dialog.getByRole("region", {
    name: "Immutable fleet history scope scope-one",
    exact: true,
  });
  await expect(
    evidence.locator("dl > div").filter({ hasText: "Observed subtotal" }),
  ).toContainText("0 orders");
  await expect(
    evidence.locator("dl > div").filter({ hasText: "Complete-window total" }),
  ).toContainText("Unavailable orders");
  await evidence
    .getByText("Observed completed-work intervals · 1", { exact: true })
    .click();
  await expect(
    evidence.getByRole("cell", { name: "0", exact: true }),
  ).toBeVisible();
  await expect(evidence).toContainText(
    "Historical membership interval ownership is unproven",
  );
  await expect(
    dialog.getByRole("button", { name: /approve|execute|verify savings/i }),
  ).toHaveCount(0);
  expect(writes).toEqual([]);
});

test("fleet controls send only typed configuration and ID selectors with initial and current optimistic versions", async ({
  page,
}) => {
  const { writes } = await open(page);
  await page
    .getByRole("button", { name: "Register fleet history", exact: true })
    .click();
  let editor = page.getByRole("dialog", {
    name: "Register fleet history",
    exact: true,
  });
  await editor
    .getByLabel("Fleet identifier", { exact: true })
    .fill("api-fleet");
  await editor
    .getByLabel("Exact ASG ARN", { exact: true })
    .fill(registration.registration.asg_arn);
  await editor
    .getByLabel("Approved AWS source connection")
    .selectOption("aws-source");
  await editor
    .getByRole("button", { name: "Save fleet registration", exact: true })
    .click();
  let dialog = page.getByRole("dialog", {
    name: "Fleet history evidence",
    exact: true,
  });
  await expect(dialog).toBeVisible();
  expect(writes[0]).toMatchObject({
    path: "/v1/fleet-history-registrations",
    version: '"0"',
    body: {
      workload_id: binding.workload_id,
      fleet_id: "api-fleet",
      asg_arn: registration.registration.asg_arn,
      source_connection_id: "aws-source",
      cadence_seconds: 60,
      max_gap_seconds: 120,
    },
  });
  await dialog
    .getByRole("button", {
      name: "Declare completed-work definition",
      exact: true,
    })
    .click();
  editor = page.getByRole("dialog", {
    name: "Declare completed-work definition",
    exact: true,
  });
  await expect(editor).toContainText(
    "does not authenticate its meaning or prove that work was preserved",
  );
  await editor
    .getByRole("combobox", {
      name: "Independent completed-work source",
      exact: true,
    })
    .selectOption("independent-source");
  await editor
    .getByLabel("Completed business operation")
    .fill("Orders completed");
  await editor
    .getByLabel("Semantic contract ID", { exact: true })
    .fill("orders-v1");
  await editor.getByLabel("Declared semantic contract SHA-256").fill(hash);
  await editor
    .getByRole("button", {
      name: "Save completed-work definition",
      exact: true,
    })
    .click();
  dialog = page.getByRole("dialog", {
    name: "Fleet history evidence",
    exact: true,
  });
  await dialog
    .getByRole("button", {
      name: "Capture scope for Orders completed",
      exact: true,
    })
    .click();
  await expect(
    dialog.getByRole("region", {
      name: "Immutable fleet history scope scope-one",
      exact: true,
    }),
  ).toBeVisible();
  expect(writes[1]).toMatchObject({
    path: "/v1/fleet-demand-definitions",
    version: '"0"',
    body: {
      registration_id: registration.id,
      activity_source_id: "independent-source",
      business_operation: "Orders completed",
      semantic_contract_id: "orders-v1",
      semantic_contract_hash: hash,
    },
  });
  expect(writes[2]).toMatchObject({
    path: "/v1/fleet-history-scopes",
    version: '"1"',
    body: {
      registration_id: registration.id,
      definition_id: definition.id,
      definition_version: 1,
    },
  });
  await dialog
    .getByRole("button", {
      name: "Revise observation configuration",
      exact: true,
    })
    .click();
  editor = page.getByRole("dialog", {
    name: "Revise fleet history registration",
    exact: true,
  });
  await expect(
    editor.getByLabel("Fleet identifier", { exact: true }),
  ).toHaveAttribute("readonly", "");
  await expect(
    editor.getByLabel("Exact ASG ARN", { exact: true }),
  ).toHaveAttribute("readonly", "");
  await editor.getByLabel("Maximum point gap (seconds)").fill("180");
  await editor
    .getByRole("button", { name: "Save registration revision", exact: true })
    .click();
  await expect(
    page.getByRole("dialog", { name: "Fleet history evidence", exact: true }),
  ).toContainText("revision 2");
  expect(writes[3].version).toBe('"1"');
  for (const write of writes)
    expect(write.idempotency).toMatch(/^[a-f0-9-]{36}$/);
});

test("history reference pagination stays bound to scope and kind while source lifecycle remains frozen at capture", async ({
  page,
}) => {
  const ref = (
    id: string,
    ordinal: number,
    status: "ACTIVE" | "REVOKED",
  ): components["schemas"]["FleetHistoryScopeReference"] => ({
    id,
    ordinal,
    cursor: String(ordinal),
    kind: "SOURCE_STATE",
    reference: {
      source_system: "ACTIVITY_SOURCE",
      source_id: id,
      config_hash: hash,
      binding,
      status,
      checked_at: stamp,
    },
    hash,
    created_at: stamp,
  });
  const { inspect, queries, writes } = await open(page, async (route, url) => {
    if (!url.pathname.endsWith("/references")) return false;
    const kind = url.searchParams.get("kind");
    await route.fulfill({
      json:
        kind === "SOURCE_STATE"
          ? {
              items: [
                url.searchParams.has("cursor")
                  ? ref("activity-old", 5, "REVOKED")
                  : ref("activity-live", 4, "ACTIVE"),
              ],
              next_cursor: url.searchParams.has("cursor")
                ? null
                : "opaque-scope-kind-cursor",
            }
          : { items: [], next_cursor: null },
    });
    return true;
  });
  const dialog = await inspect();
  await dialog
    .getByRole("button", {
      name: "Inspect history scope scope-one",
      exact: true,
    })
    .click();
  const evidence = dialog.getByRole("region", {
    name: "Immutable fleet history scope scope-one",
    exact: true,
  });
  await evidence
    .getByRole("button", {
      name: "Load more fleet history references",
      exact: true,
    })
    .click();
  await expect(evidence).toContainText(
    "ACTIVITY_SOURCE · activity-old · Revoked",
  );
  await expect(evidence).toContainText(
    "No registry version exists for guarded activity",
  );
  await expect(evidence).toContainText(
    "Reading this snapshot does not refresh currentness",
  );
  await evidence
    .getByLabel("History reference kind")
    .selectOption("DEMAND_RECEIPT");
  await expect(evidence).toContainText(
    "No references of this kind are recorded",
  );
  expect(queries).toContain(
    "/v1/fleet-history-scopes/scope-one/references?kind=SOURCE_STATE&limit=10&cursor=opaque-scope-kind-cursor",
  );
  expect([
    ...new Set(queries.filter((url) => url.includes("kind=DEMAND_RECEIPT"))),
  ]).toEqual([
    "/v1/fleet-history-scopes/scope-one/references?kind=DEMAND_RECEIPT&limit=10",
  ]);
  expect(writes).toEqual([]);
});

test("history source failures stay distinct from empty evidence and stale revisions cannot look saved", async ({
  page,
}) => {
  const { inspect } = await open(page, async (route, url) => {
    if (url.pathname.endsWith("/observations")) {
      await route.fulfill({
        status: 503,
        json: {
          reason_code: "SOURCE_UNAVAILABLE",
          message: "Native membership source is unavailable",
        },
      });
      return true;
    }
    if (
      url.pathname.endsWith("/revisions") &&
      route.request().method() === "POST"
    ) {
      await route.fulfill({
        status: 409,
        json: {
          reason_code: "VERSION_CONFLICT",
          message: "Registration was revised by another operator",
        },
      });
      return true;
    }
    return false;
  });
  const dialog = await inspect();
  await expect(dialog.getByRole("alert")).toContainText(
    "Native membership source is unavailable",
  );
  await expect(
    dialog.getByText("No fleet native point observations", { exact: true }),
  ).toHaveCount(0);
  await dialog
    .getByRole("button", {
      name: "Revise observation configuration",
      exact: true,
    })
    .click();
  const editor = page.getByRole("dialog", {
    name: "Revise fleet history registration",
    exact: true,
  });
  await editor
    .getByRole("button", { name: "Save registration revision", exact: true })
    .click();
  await expect(editor).toBeVisible();
  await expect(
    page
      .getByRole("alert")
      .filter({ hasText: "Registration was revised by another operator" }),
  ).toContainText("Refresh the view and retry");
});
