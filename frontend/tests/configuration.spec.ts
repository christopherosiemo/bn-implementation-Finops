import { expect, test, type Page, type Route } from "@playwright/test";
import type { components } from "../src/api.generated";
import type {
  ConfigurationAuthority,
  Dashboard,
  WorkloadSafetyProfile,
} from "../src/types";

// Presentation contracts only; PostgreSQL boundary tests and the real connected
// journey separately validate authoritative persistence and permissions.
const stamp = "2026-10-18T12:00:00Z";
const binding = {
  tenant_id: "configuration-ui",
  workload_id: "workload-api",
  resource_id: "resource-api",
  provider: "AWS",
  provider_resource_id: "i-api",
  account_id: "111122223333",
  region: "eu-west-1",
  resource_version: 3,
  resource_snapshot_hash: "resource-snapshot-hash",
};
const declaration: components["schemas"]["ConfigurationAuthorityRequest"] = {
  schema_version: "1",
  authority: "TERRAFORM",
  repository: {
    url: "https://github.com/example/infrastructure.git",
    ref: "main",
    directory: "envs/dev",
  },
  pipeline: {
    system: "GITHUB_ACTIONS",
    identity: {
      issuer: "https://token.actions.githubusercontent.com",
      audience: "finops-deployment-observer",
      subject: "repo:example/infrastructure:ref:refs/heads/main",
      pipeline_id: ".github/workflows/deploy.yml",
    },
  },
  terraform: {
    workspace: "dev-eu",
    state_lineage: "0f5a34b0-a480-4cda-9f6a-9b205ced7937",
    addresses: ['module.api["dev"].aws_instance.api[0]'],
  },
};
const authority: ConfigurationAuthority = {
  ...declaration,
  id: "authority-1",
  version: 1,
  binding,
  status: "DECLARED_NOT_ATTESTED",
  reason_codes: [
    "PIPELINE_ATTESTATION_REQUIRED",
    "CONFIGURATION_STATE_UNOBSERVED",
  ],
  execution_authorized: false,
  observed_commit: null,
  observed_state_serial: null,
  declared_by: "platform-operator",
  hash: "authority-hash",
  created_at: stamp,
  writer_role: "finops_api",
};
const profile: WorkloadSafetyProfile = {
  schema_version: "1",
  id: "profile-4",
  version: 4,
  workload_id: binding.workload_id,
  criticality: "NON_PRODUCTION",
  statefulness: "UNKNOWN",
  timezone: "UTC",
  high_seasonality: false,
  min_replicas: 1,
  min_zones: 1,
  headroom: {
    cpu_free_ppm: 300000,
    memory_free_ppm: 250000,
    reserve_above_forecast_ppm: 300000,
  },
  saturation: { cpu_p99_ppm: 850000, memory_p99_ppm: 900000 },
  rto_seconds: 300,
  rpo_seconds: null,
  maintenance: [],
  recurring_blackouts: [],
  blackouts: [],
  demand_events: [],
  max_simultaneous_change_ppm: 250000,
  vm_cooldown_seconds: 86400,
  hash: "profile-hash",
  writer_role: "finops_api",
  created_at: stamp,
};
const assessment: components["schemas"]["CapacityAssessment"] = {
  schema_version: "1",
  id: "assessment-1",
  workload_id: binding.workload_id,
  resource_id: binding.resource_id,
  connection_id: "native-1",
  connection_version: 2,
  revision_id: "native-revision-2",
  config_hash: "native-hash",
  safety_profile_id: profile.id,
  safety_profile_version: profile.version,
  safety_profile_hash: profile.hash,
  population_hash: "population-hash",
  receipt_ids: [],
  source_refs: [],
  history: {
    start: "2026-10-04T00:00:00Z",
    end: "2026-10-18T00:00:00Z",
    days: 14,
    timezone: "UTC",
    environment: "NON_PRODUCTION",
  },
  native_evaluation: {
    schema_version: "1",
    status: "BLOCKED",
    reason_codes: ["TELEMETRY_HISTORY_INCOMPLETE"],
    start: "2026-10-04T00:00:00Z",
    end: "2026-10-18T00:00:00Z",
    evaluated_at: stamp,
    hash: "evaluation-hash",
    metrics: [],
  },
  status: "BLOCKED",
  reason_codes: [
    "BLOCKED_NATIVE_CAPACITY_CATALOG_REQUIRED",
    "NATIVE_PRICE_UNAVAILABLE",
  ],
  execution_authorized: false,
  hardware_catalog_status: "UNAVAILABLE",
  native_price_status: "UNAVAILABLE",
  estimated_saving: null,
  verified_saving: null,
  hash: "assessment-hash",
  created_at: stamp,
  writer_role: "finops_api",
};
function dashboard(): Dashboard {
  return {
    org: {
      id: binding.tenant_id,
      version: 1,
      name: "Configuration declaration contract",
      paused: false,
    },
    fixture: false,
    cloud_accounts: [],
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
        name: "Development API",
        environment: "NON_PRODUCTION",
        owner: "platform@example.test",
        timezone: "UTC",
        incident: "CLEAR",
        deployment: "CLEAR",
        job: "CLEAR",
        signals_at: stamp,
      },
    ],
    resources: [
      {
        id: binding.resource_id,
        version: 3,
        name: "dev-api",
        provider: "AWS",
        provider_resource_id: binding.provider_resource_id,
        resource_type: "EC2",
        workload_id: binding.workload_id,
        environment: "NON_PRODUCTION",
        state: "running",
        configuration_authority: "TERRAFORM",
        hourly_effective_cost: null,
        monthly_effective_cost: null,
        currency: null,
        eligibility: "BLOCKED",
        blockers: ["CONFIGURATION_STATE_UNOBSERVED"],
      },
    ],
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
  latest: ConfigurationAuthority | null,
  handler?: Handler,
) {
  const writes: Write[] = [],
    reads: string[] = [];
  let current = latest;
  await page.route("**/.well-known/openid-configuration", (route) => {
    const origin = new URL(page.url()).origin;
    return route.fulfill({
      json: {
        authorization_endpoint: `${origin}/__configuration/authorize`,
        token_endpoint: `${origin}/__configuration/token`,
      },
    });
  });
  await page.route("**/__configuration/authorize?**", (route) => {
    const params = new URL(route.request().url()).searchParams;
    const redirect = new URL(params.get("redirect_uri")!);
    redirect.searchParams.set("code", "configuration-contract");
    redirect.searchParams.set("state", params.get("state")!);
    return route.fulfill({
      status: 302,
      headers: { location: redirect.toString() },
    });
  });
  await page.route("**/__configuration/token", (route) =>
    route.fulfill({
      json: {
        access_token: `test.${Buffer.from(JSON.stringify({ name: "Configuration operator" })).toString("base64url")}.test`,
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
    if (path.endsWith("/configuration-authorities")) {
      if (request.method() === "POST") {
        current = {
          ...authority,
          ...request.postDataJSON(),
          version: (current?.version ?? 0) + 1,
        };
        return route.fulfill({ status: 201, json: current });
      }
      return route.fulfill({
        json: {
          version: current?.version ?? 0,
          latest: current,
          items: current ? [current] : [],
          next_cursor: null,
        },
      });
    }
    if (path.endsWith("/configuration-proposals"))
      return route.fulfill({ json: { items: [], next_cursor: null } });
    if (path.endsWith("/safety-profiles"))
      return route.fulfill({
        json: {
          version: profile.version,
          latest: profile,
          items: [profile],
          next_cursor: null,
        },
      });
    if (path.endsWith("/capacity-assessments"))
      return route.fulfill({
        json: {
          items: [
            assessment,
            {
              ...assessment,
              id: "assessment-historical",
              safety_profile_id: "old-profile",
              safety_profile_version: 2,
            },
          ],
          next_cursor: null,
        },
      });
    return route.fulfill({
      status: 404,
      json: { message: "No presentation evidence registered" },
    });
  });
  await page.goto("/");
  await page.getByRole("button", { name: "Sign in to your workspace" }).click();
  await expect(
    page.getByRole("heading", { name: "Cost operations overview." }),
  ).toBeVisible();
  await page.getByRole("link", { name: "Workloads & resources" }).click();
  return {
    writes,
    reads,
    panel: page.locator(".panel").filter({
      has: page.getByRole("heading", {
        name: "Configuration ownership & proposal evidence",
        exact: true,
      }),
    }),
  };
}
async function fillDeclaration(page: Page) {
  const dialog = page.getByRole("dialog", {
    name: "Declare Terraform configuration authority",
  });
  for (const [label, value] of Object.entries({
    "Repository HTTPS URL": declaration.repository.url,
    "Declared Git branch or tag": declaration.repository.ref,
    "Repository relative directory": declaration.repository.directory,
    "Pipeline issuer HTTPS URL": declaration.pipeline.identity.issuer,
    "Exact pipeline machine subject": declaration.pipeline.identity.subject,
    "Stable pipeline identifier": declaration.pipeline.identity.pipeline_id,
    "Terraform workspace": declaration.terraform.workspace,
    "Declared Terraform state lineage UUID":
      declaration.terraform.state_lineage,
    "Managed Terraform resource addresses":
      declaration.terraform.addresses.join("\n"),
  }))
    await dialog.getByLabel(label, { exact: true }).fill(value);
  await dialog.getByRole("checkbox", { name: /I acknowledge/ }).check();
  return dialog;
}

test("initial Terraform declaration sends version zero and metadata only without attested authority", async ({
  page,
}) => {
  const { writes, panel } = await open(page, null);
  await expect(
    panel.getByText("Configuration ownership is unobserved", { exact: true }),
  ).toBeVisible();
  await panel
    .getByRole("button", { name: "Declare Terraform ownership", exact: true })
    .click();
  const dialog = await fillDeclaration(page);
  await expect(dialog.getByLabel("Dedicated pipeline audience")).toHaveValue(
    "finops-deployment-observer",
  );
  await dialog
    .getByRole("button", { name: "Save ownership declaration" })
    .click();
  await expect(dialog).not.toBeVisible();
  expect(writes).toHaveLength(1);
  expect(writes[0].body).toEqual(declaration);
  expect(writes[0].headers["if-match"]).toBe('"0"');
  expect(writes[0].headers["idempotency-key"]).toBeTruthy();
  await expect(
    panel
      .locator(".readiness-summary")
      .getByText("Declared, unattested", { exact: true }),
  ).toBeVisible();
  await expect(
    panel.getByText("Unavailable — independent machine observation required", {
      exact: true,
    }),
  ).toBeVisible();
  expect(
    writes.some((item) => /approvals|executions|change-plans/.test(item.path)),
  ).toBe(false);
});

test("configuration declaration evidence preserves exact resource and state bindings without inferring observations", async ({
  page,
}, testInfo) => {
  const { panel, writes } = await open(page, authority);
  const table = panel.getByRole("region", {
    name: "Scrollable configuration authority binding",
  });
  await expect(table).toContainText(binding.resource_snapshot_hash);
  await expect(table).toContainText(declaration.terraform.state_lineage);
  await expect(table).toContainText(declaration.terraform.addresses[0]);
  await expect(table).toContainText(
    "Unavailable — independent machine observation required",
  );
  await expect(panel).toContainText("Pipeline attestation required");
  await expect(panel).toContainText("Configuration state unobserved");
  await expect(
    panel.getByRole("button", { name: /Approve|Execute|Merge/ }),
  ).toHaveCount(0);
  expect(writes).toHaveLength(0);
  await page.evaluate(() => window.scrollTo(0, 0));
  await page.waitForTimeout(350);
  await panel.screenshot({
    path: testInfo.outputPath("configuration-desktop.png"),
  });
  await page.setViewportSize({ width: 390, height: 844 });
  await page.waitForTimeout(350);
  await panel.screenshot({
    path: testInfo.outputPath("configuration-mobile.png"),
  });
});

test("a declaration version conflict preserves entered metadata and never retries silently", async ({
  page,
}) => {
  const { panel, writes } = await open(page, authority, async (route, url) => {
    if (
      url.pathname.endsWith("/configuration-authorities") &&
      route.request().method() === "POST"
    ) {
      await route.fulfill({
        status: 409,
        json: {
          error: "VERSION_CONFLICT",
          message: "Declaration revision changed",
        },
      });
      return true;
    }
    return false;
  });
  await panel
    .getByRole("button", { name: "Revise ownership declaration" })
    .click();
  const dialog = await fillDeclaration(page);
  await dialog
    .getByLabel("Declared Git branch or tag")
    .fill("release/safe-capacity");
  await dialog
    .getByRole("button", { name: "Save ownership declaration" })
    .click();
  await expect(dialog.getByRole("alert")).toContainText(
    "Declaration was not saved",
  );
  await expect(dialog.getByLabel("Declared Git branch or tag")).toHaveValue(
    "release/safe-capacity",
  );
  expect(writes).toHaveLength(1);
  expect(writes[0].headers["if-match"]).toBe('"1"');
});

test("blocked proposals select existing current assessment IDs and preserve null savings and immutable references", async ({
  page,
}) => {
  let recorded = false;
  const proposal = {
    schema_version: "1",
    id: "proposal-1",
    binding,
    workload_id: binding.workload_id,
    resource_id: binding.resource_id,
    authority_id: authority.id,
    authority_version: authority.version,
    authority_hash: authority.hash,
    capacity_assessment_id: assessment.id,
    capacity_assessment_hash: assessment.hash,
    population_hash: assessment.population_hash,
    connection_id: assessment.connection_id,
    connection_version: assessment.connection_version,
    revision_id: assessment.revision_id,
    config_hash: assessment.config_hash,
    safety_profile_id: profile.id,
    safety_profile_version: profile.version,
    safety_profile_hash: profile.hash,
    status: "BLOCKED",
    reason_codes: ["DECLARED_NOT_ATTESTED", "NATIVE_PRICE_UNAVAILABLE"],
    execution_authorized: false,
    estimated_saving: null,
    verified_saving: null,
    change_plan_id: null,
    proposed_by: "platform-operator",
    hash: "proposal-hash",
    created_at: stamp,
    writer_role: "finops_api",
  };
  const { panel, writes } = await open(page, authority, async (route, url) => {
    if (url.pathname.endsWith("/configuration-proposals")) {
      if (route.request().method() === "POST") {
        recorded = true;
        await route.fulfill({ status: 201, json: proposal });
      } else
        await route.fulfill({
          json: { items: recorded ? [proposal] : [], next_cursor: null },
        });
      return true;
    }
    return false;
  });
  await panel.getByRole("button", { name: "Review proposal evidence" }).click();
  const dialog = page.getByRole("dialog", {
    name: "Record a blocked configuration proposal",
  });
  await expect(
    dialog.getByRole("radio", {
      name: "Select capacity assessment assessment-historical",
      exact: true,
    }),
  ).toBeDisabled();
  await dialog
    .getByRole("radio", {
      name: `Select capacity assessment ${assessment.id}`,
      exact: true,
    })
    .check();
  await dialog
    .getByRole("button", { name: "Record blocked proposal", exact: true })
    .click();
  await expect(dialog).not.toBeVisible();
  expect(writes).toHaveLength(1);
  expect(writes[0].body).toEqual({
    authority_id: authority.id,
    capacity_assessment_id: assessment.id,
  });
  expect(writes[0].headers["if-match"]).toBe('"1"');
  const row = panel.getByRole("row").filter({ hasText: "proposal-1" });
  await expect(row).toContainText("Estimated savings: unavailable");
  await expect(row).toContainText("Verified savings: unavailable");
  await expect(row).toContainText("Execution disabled");
  await row
    .getByText("Evidence bindings and blockers", { exact: true })
    .click();
  await expect(row).toContainText(assessment.hash);
  await expect(row).toContainText("Native price unavailable");
});

test("API rejection of a historical assessment leaves proposal selection visible and cannot mint a plan", async ({
  page,
}) => {
  const { panel, writes } = await open(page, authority, async (route, url) => {
    if (
      url.pathname.endsWith("/configuration-proposals") &&
      route.request().method() === "POST"
    ) {
      await route.fulfill({
        status: 422,
        json: {
          error: "CONFIGURATION_PROPOSAL_BINDING_INVALID",
          message: "Source was revoked",
        },
      });
      return true;
    }
    return false;
  });
  await panel.getByRole("button", { name: "Review proposal evidence" }).click();
  const dialog = page.getByRole("dialog", {
    name: "Record a blocked configuration proposal",
  });
  await dialog
    .getByRole("radio", {
      name: `Select capacity assessment ${assessment.id}`,
      exact: true,
    })
    .check();
  await dialog
    .getByRole("button", { name: "Record blocked proposal", exact: true })
    .click();
  await expect(dialog.getByRole("alert")).toContainText(
    "Proposal was not recorded",
  );
  await expect(
    dialog.getByRole("radio", {
      name: `Select capacity assessment ${assessment.id}`,
      exact: true,
    }),
  ).toBeChecked();
  expect(writes).toHaveLength(1);
});

test("a denied configuration read remains unavailable and exposes no declaration action", async ({
  page,
}) => {
  const { panel, writes } = await open(page, null, async (route, url) => {
    if (url.pathname.endsWith("/configuration-authorities")) {
      await route.fulfill({
        status: 403,
        json: {
          error: "WORKLOAD_SCOPE_DENIED",
          message: "Workload scope denied",
        },
      });
      return true;
    }
    return false;
  });
  await expect(panel.getByRole("alert")).toContainText(
    "Configuration authority unavailable",
  );
  await expect(
    panel.getByRole("button", {
      name: "Declare Terraform ownership",
      exact: true,
    }),
  ).toHaveCount(0);
  expect(writes).toHaveLength(0);
});
