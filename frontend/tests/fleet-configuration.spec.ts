import { expect, test, type Page, type Route } from "@playwright/test";
import type { components } from "../src/api.generated";
import type {
  Dashboard,
  FleetHistoryRegistration,
  FleetHistoryScope,
} from "../src/types";

// Explicit presentation fixtures. Real OIDC/API/restricted-PG acceptance is a
// separate journey; these route doubles cannot establish any source authority.
type Declaration = components["schemas"]["FleetConfigurationDeclaration"];
type Proposal = components["schemas"]["FleetConfigurationProposal"];
type Metadata = components["schemas"]["FleetDeclarationInput"];
const stamp = "2026-10-19T12:00:00Z",
  hash = "a".repeat(64);
const binding = {
  tenant_id: "presentation-tenant",
  workload_id: "workload-api",
  provider: "AWS" as const,
  account_id: "111122223333",
  region: "eu-west-1" as const,
};
const registration: FleetHistoryRegistration = {
  id: "history-api",
  version: 2,
  hash,
  created_at: stamp,
  writer_role: "finops_api",
  registration: {
    schema_version: "1",
    id: "history-api",
    version: 2,
    fleet_id: "presentation-api",
    binding,
    asg_arn:
      "arn:aws:autoscaling:eu-west-1:111122223333:autoScalingGroup:12345678-1234-1234-1234-123456789abc:autoScalingGroupName/presentation-api",
    source_id: "source-native",
    source_system: "AWS_SOURCE_CONNECTION",
    source_registration_version: 2,
    source_config_hash: hash,
    cadence_seconds: 60,
    max_gap_seconds: 120,
  },
};
const metadata: Metadata = {
  schema_version: "1",
  authority: "TERRAFORM",
  repository: {
    url: "https://github.com/example/infrastructure",
    ref: "main",
    directory: "infra/api",
  },
  pipeline: {
    system: "GITHUB_ACTIONS",
    identity: {
      issuer: "https://token.actions.githubusercontent.com",
      audience: "finops-deployment-observer",
      subject: "repo:example/infrastructure:ref:refs/heads/main",
      pipeline_id: "deploy-api",
    },
  },
  terraform: {
    workspace: "development",
    state_lineage: "12345678-1234-1234-1234-123456789abc",
    asg_address: "module.api.aws_autoscaling_group.api",
    launch_template_address: "module.api.aws_launch_template.api",
  },
};
const declaration: Declaration = {
  schema_version: "1",
  id: "declaration-three",
  version: 3,
  registration_id: registration.id,
  registration_version: registration.version,
  registration_hash: hash,
  fleet_id: registration.registration.fleet_id,
  asg_arn: registration.registration.asg_arn,
  binding,
  source_id: "source-native",
  source_registration_version: 2,
  source_config_hash: hash,
  metadata,
  status: "DECLARED_NOT_ATTESTED",
  reason_codes: [
    "CONFIGURATION_ADDRESS_MAPPING_UNVERIFIED",
    "PIPELINE_ATTESTATION_REQUIRED",
    "DECLARED_NOT_ATTESTED",
  ],
  execution_authorized: false,
  estimated_saving: null,
  verified_saving: null,
  declared_by: "presentation-admin",
  hash,
  created_at: stamp,
  writer_role: "finops_api",
};
const empty = { count: 0, hash, preview: [], truncated: false };
const gaps = {
  count: 1,
  hash,
  preview: [
    {
      start: "2026-10-05T00:00:00Z",
      end: "2026-10-19T00:00:00Z",
      reason_code: "INTERVAL_OWNERSHIP_UNPROVEN",
    },
  ],
  truncated: false,
};
const scope: FleetHistoryScope = {
  schema_version: "1",
  id: "scope-current",
  purpose: "READ_ONLY_FLEET_HISTORY_ANALYSIS",
  status: "BLOCKED",
  binding,
  fleet_id: registration.registration.fleet_id,
  asg_arn: registration.registration.asg_arn,
  registration_id: registration.id,
  registration_version: registration.version,
  registration_hash: hash,
  definition_id: "definition-completed",
  definition_version: 1,
  definition_hash: hash,
  input_hash: hash,
  analysis_hash: hash,
  start: "2026-10-05T00:00:00Z",
  end: "2026-10-19T00:00:00Z",
  as_of: stamp,
  membership_status: "INTERVAL_OWNERSHIP_UNPROVEN",
  reference_root: hash,
  reference_count: 4,
  observation_count: 0,
  selected_observation_count: 0,
  demand_receipt_count: 1,
  membership_gaps: gaps,
  observation_gaps: gaps,
  issues: empty,
  superseded_ids: empty,
  reason_codes: ["HISTORICAL_MEMBERSHIP_INTERVAL_OWNERSHIP_UNPROVEN"],
  demand: {
    status: "UNKNOWN",
    meaning_basis: "DECLARED_COMPLETED_WORK_SEMANTICS",
    unit: "orders",
    observed_units: "0",
    window_units: null,
    segments: empty,
    gaps,
    reason_codes: ["DEMAND_HISTORY_INCOMPLETE"],
  },
  hash,
  created_at: stamp,
  writer_role: "finops_api",
};
const proposal: Proposal = {
  schema_version: "1",
  id: "proposal-one",
  purpose: "FLEET_CONFIGURATION_PROPOSAL",
  registration_id: registration.id,
  registration_version: registration.version,
  registration_hash: hash,
  binding,
  fleet_id: registration.registration.fleet_id,
  asg_arn: registration.registration.asg_arn,
  declaration_id: declaration.id,
  declaration_version: declaration.version,
  declaration_hash: hash,
  scope_id: scope.id,
  scope_hash: hash,
  scope_reference_root: hash,
  definition_id: scope.definition_id,
  definition_version: 1,
  definition_hash: hash,
  history_start: scope.start,
  history_end: scope.end,
  membership_status: "INTERVAL_OWNERSHIP_UNPROVEN",
  observation_count: 0,
  selected_observation_count: 0,
  source_states: [
    {
      source_system: "AWS_SOURCE_CONNECTION",
      source_id: "source-native",
      source_registration_version: 2,
      config_hash: hash,
      binding,
      status: "DEGRADED",
      checked_at: stamp,
    },
    {
      source_system: "ACTIVITY_SOURCE",
      source_id: "source-completed",
      config_hash: hash,
      binding,
      status: "ACTIVE",
      checked_at: stamp,
    },
  ],
  as_of: stamp,
  status: "BLOCKED",
  reason_codes: [
    "FLEET_CAPACITY_UNPROVEN",
    "GROUP_MEMBERSHIP_UNOBSERVED",
    "FLEET_CONFIGURATION_SOURCE_NOT_HEALTHY",
  ],
  execution_authorized: false,
  estimated_saving: null,
  verified_saving: null,
  change_plan_id: null,
  proposed_by: "presentation-admin",
  hash,
  created_at: stamp,
  writer_role: "finops_api",
};
const dashboard: Dashboard = {
  org: {
    id: binding.tenant_id,
    version: 1,
    name: "Fleet configuration presentation fixtures",
    paused: false,
  },
  fixture: true,
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
      owner: "owner@example.test",
      environment: "NON_PRODUCTION",
      timezone: "UTC",
      incident: "UNKNOWN",
      deployment: "UNKNOWN",
      job: "UNKNOWN",
      signals_at: stamp,
    },
  ],
};
const base = `/v1/fleet-history-registrations/${registration.id}`;
type Handler = (route: Route, url: URL) => Promise<boolean>;
type Write = {
  path: string;
  body: unknown;
  version?: string;
  idempotency?: string;
};

async function open(
  page: Page,
  options: {
    latest?: Declaration | null;
    proposals?: Proposal[];
    override?: Handler;
  } = {},
) {
  let latest = structuredClone(
    options.latest === undefined ? declaration : options.latest,
  );
  let proposals = structuredClone(options.proposals ?? []);
  const writes: Write[] = [],
    queries: string[] = [];
  await page.route("**/.well-known/openid-configuration", (route) => {
    const origin = new URL(page.url()).origin;
    return route.fulfill({
      json: {
        authorization_endpoint: `${origin}/__fleet-config/authorize`,
        token_endpoint: `${origin}/__fleet-config/token`,
      },
    });
  });
  await page.route("**/__fleet-config/authorize?**", (route) => {
    const params = new URL(route.request().url()).searchParams,
      location = new URL(params.get("redirect_uri")!);
    location.searchParams.set("code", "presentation-only");
    location.searchParams.set("state", params.get("state")!);
    return route.fulfill({
      status: 302,
      headers: { location: location.toString() },
    });
  });
  await page.route("**/__fleet-config/token", (route) =>
    route.fulfill({
      json: { access_token: "presentation-only", expires_in: 3600 },
    }),
  );
  await page.route("**/v1/**", async (route) => {
    const request = route.request(),
      url = new URL(request.url()),
      path = url.pathname;
    if (request.method() === "POST")
      writes.push({
        path,
        body: request.postDataJSON(),
        version: request.headers()["if-match"],
        idempotency: request.headers()["idempotency-key"],
      });
    else queries.push(path + url.search);
    if (options.override && (await options.override(route, url))) return;
    const reply = (json: unknown, status = 200) =>
      route.fulfill({ json, status });
    if (path === "/v1/dashboard") return reply(dashboard);
    if (path === `${base}/configuration-authorities`) {
      if (request.method() === "POST") {
        if (request.headers()["if-match"] !== `"${latest?.version ?? 0}"`)
          return reply(
            {
              error: "VERSION_CONFLICT",
              message: "Declaration version changed",
            },
            409,
          );
        latest = {
          ...declaration,
          id: `declaration-${(latest?.version ?? 0) + 1}`,
          version: (latest?.version ?? 0) + 1,
          metadata: request.postDataJSON() as Metadata,
        };
        return reply(latest, 201);
      }
      return reply({
        items: latest ? [latest] : [],
        next_cursor: null,
        latest,
        version: latest?.version ?? 0,
      });
    }
    if (path === `${base}/configuration-proposals`) {
      if (request.method() === "POST") {
        const selection =
          request.postDataJSON() as components["schemas"]["FleetProposalSelection"];
        const created = {
          ...proposal,
          declaration_id: selection.declaration_id,
          declaration_version: latest!.version,
          scope_id: selection.scope_id,
        };
        proposals = [created, ...proposals];
        return reply(created, 201);
      }
      return reply({ items: proposals, next_cursor: null });
    }
    if (path.startsWith(`${base}/configuration-proposals/`))
      return reply(
        proposals.find((item) => item.id === path.split("/").at(-1)) ??
          proposal,
      );
    if (path === "/v1/fleet-history-registrations")
      return reply({ items: [registration], next_cursor: null });
    if (path === base) return reply(registration);
    if (path === "/v1/fleet-history-scopes")
      return reply({ items: [scope], next_cursor: null });
    if (
      path.endsWith("/observations") ||
      path === "/v1/fleet-demand-definitions"
    )
      return reply({ items: [], next_cursor: null });
    if (path.endsWith("/safety-profiles"))
      return reply({ items: [], version: 0, latest: null, next_cursor: null });
    return reply({ message: "No presentation fixture for this route" }, 404);
  });
  await page.goto("/");
  await page
    .getByRole("button", { name: "Sign in to your workspace", exact: true })
    .click();
  await expect(
    page.getByRole("heading", {
      name: "Cost operations overview.",
      exact: true,
    }),
  ).toBeVisible();
  await page
    .getByRole("link", { name: "Workloads & resources", exact: true })
    .click();
  await page
    .getByRole("button", {
      name: "Inspect fleet history presentation-api",
      exact: true,
    })
    .click();
  const dialog = page.getByRole("dialog", {
    name: "Fleet history evidence",
    exact: true,
  });
  await expect(dialog).toContainText(registration.registration.asg_arn);
  const beforeConfigurationQueries = queries.filter((query) =>
    query.includes("/configuration-"),
  ).length;
  expect(beforeConfigurationQueries).toBe(0);
  await dialog
    .getByText("Fleet configuration declarations & blocked proposals", {
      exact: true,
    })
    .click();
  const section = dialog
    .locator("details")
    .filter({
      has: page.locator(":scope > summary", {
        hasText: "Fleet configuration declarations & blocked proposals",
      }),
    });
  return { writes, queries, section, beforeConfigurationQueries };
}

async function fillDeclaration(page: Page) {
  const values = {
    "Fleet repository HTTPS URL": metadata.repository.url,
    "Fleet declared Git branch or tag": metadata.repository.ref,
    "Fleet repository relative directory": metadata.repository.directory,
    "Fleet pipeline issuer HTTPS URL": metadata.pipeline.identity.issuer,
    "Fleet exact pipeline machine subject": metadata.pipeline.identity.subject,
    "Fleet stable pipeline identifier": metadata.pipeline.identity.pipeline_id,
    "Fleet Terraform workspace": metadata.terraform.workspace,
    "Fleet declared state lineage UUID": metadata.terraform.state_lineage,
    "Fleet ASG Terraform resource address": metadata.terraform.asg_address,
    "Fleet launch-template Terraform resource address":
      metadata.terraform.launch_template_address,
  };
  for (const [label, value] of Object.entries(values))
    await page.getByLabel(label, { exact: true }).fill(value);
  await page
    .getByLabel("I acknowledge that this declaration is unattested", {
      exact: false,
    })
    .check();
}

test("fleet declaration form binds typed metadata with initial zero and latest revision CAS without observed authority fields", async ({
  page,
}) => {
  const { writes, section, queries, beforeConfigurationQueries } = await open(
    page,
    { latest: null },
  );
  await expect(section).toContainText("No fleet configuration declaration");
  await section
    .getByRole("button", {
      name: "Declare fleet Terraform metadata",
      exact: true,
    })
    .click();
  await fillDeclaration(page);
  await page
    .getByLabel(
      "Declare an optional listener rule and two target-group mappings",
    )
    .check();
  await page
    .getByLabel("Fleet listener-rule Terraform resource address", {
      exact: true,
    })
    .fill("module.api.aws_lb_listener_rule.api");
  await page
    .getByLabel("Fleet first target-group Terraform resource address", {
      exact: true,
    })
    .fill("module.api.aws_lb_target_group.blue");
  await page
    .getByLabel("Fleet second target-group Terraform resource address", {
      exact: true,
    })
    .fill("module.api.aws_lb_target_group.green");
  await expect(
    page.getByLabel("Fleet dedicated pipeline audience", { exact: true }),
  ).toHaveAttribute("readonly", "");
  await section
    .getByRole("button", { name: "Save fleet declaration", exact: true })
    .click();
  await expect(section).toContainText("Declaration revision 1");
  expect(writes[0].version).toBe('"0"');
  expect(writes[0].path).toBe(`${base}/configuration-authorities`);
  expect(writes[0].body).toEqual({
    ...metadata,
    terraform: {
      ...metadata.terraform,
      traffic: {
        listener_rule_address: "module.api.aws_lb_listener_rule.api",
        target_group_addresses: [
          "module.api.aws_lb_target_group.blue",
          "module.api.aws_lb_target_group.green",
        ],
      },
    },
  });
  await expect(section).toContainText(
    "Unavailable · independent attestation required",
  );
  await section
    .getByRole("button", { name: "Revise fleet declaration", exact: true })
    .click();
  await page
    .getByLabel("Fleet declared Git branch or tag", { exact: true })
    .fill("reviewed-branch");
  await page
    .getByLabel("I acknowledge that this declaration is unattested", {
      exact: false,
    })
    .check();
  await section
    .getByRole("button", { name: "Save fleet declaration", exact: true })
    .click();
  await expect(section).toContainText("Declaration revision 2");
  expect(writes[1].version).toBe('"1"');
  for (const write of writes) {
    expect(Object.keys(write.body as object).sort()).toEqual([
      "authority",
      "pipeline",
      "repository",
      "schema_version",
      "terraform",
    ]);
    expect(write.idempotency).toMatch(/^[a-f0-9-]{36}$/);
  }
  await test
    .info()
    .attach("mock-source-query-counts", {
      body: JSON.stringify({
        before_expand: beforeConfigurationQueries,
        after_expand: queries.filter((query) =>
          query.includes("/configuration-"),
        ).length,
        fixtures: "PRESENTATION_ONLY",
      }),
      contentType: "application/json",
    });
});

test("blocked scope selection is registration-bound and sends only immutable IDs with the declaration CAS", async ({
  page,
}) => {
  const stale = { ...scope, id: "scope-stale", registration_version: 1 };
  const { writes, section, queries } = await open(page, {
    override: async (route, url) => {
      if (url.pathname !== "/v1/fleet-history-scopes") return false;
      await route.fulfill({
        json: {
          items: url.searchParams.has("cursor") ? [scope] : [stale],
          next_cursor: url.searchParams.has("cursor")
            ? null
            : "scope-options-opaque",
        },
      });
      return true;
    },
  });
  await section
    .getByRole("button", {
      name: "Review fleet proposal evidence",
      exact: true,
    })
    .click();
  await expect(
    section.getByLabel("Select fleet proposal scope scope-stale", {
      exact: true,
    }),
  ).toBeDisabled();
  await section
    .getByRole("button", {
      name: "Load more fleet proposal scope options",
      exact: true,
    })
    .click();
  await expect(
    section.getByLabel("Select fleet proposal scope scope-current", {
      exact: true,
    }),
  ).toBeEnabled();
  await expect(section).toContainText(
    "Complete-window total: Unavailable orders",
  );
  await section
    .getByLabel("Select fleet proposal scope scope-current", { exact: true })
    .check();
  await section
    .getByRole("button", { name: "Record blocked fleet proposal", exact: true })
    .click();
  const evidence = section.getByRole("region", {
    name: "Immutable fleet configuration proposal proposal-one",
    exact: true,
  });
  await expect(evidence).toContainText(
    "No executable plan or savings claim was created",
  );
  expect(writes).toHaveLength(1);
  expect(writes[0].body).toEqual({
    declaration_id: declaration.id,
    scope_id: scope.id,
  });
  expect(writes[0].version).toBe('"3"');
  expect(queries).toContain(
    `/v1/fleet-history-scopes?registration_id=${registration.id}&limit=10&cursor=scope-options-opaque`,
  );
  await evidence
    .getByText("Source state captured for this proposal", { exact: true })
    .click();
  await expect(evidence).toContainText("Degraded");
  await expect(evidence).toContainText(
    "Guarded activity has no registry version",
  );
  await expect(
    evidence.getByRole("button", { name: /approve|execute|verify/i }),
  ).toHaveCount(0);
});

test("fleet declaration and proposal histories paginate independently and retained stale declarations remain read-only", async ({
  page,
}) => {
  const staleDeclaration = { ...declaration, registration_version: 1 };
  const prior = { ...staleDeclaration, id: "declaration-one", version: 1 };
  const olderProposal = { ...proposal, id: "proposal-older" };
  const { section, queries, writes } = await open(page, {
    latest: staleDeclaration,
    override: async (route, url) => {
      if (url.pathname === `${base}/configuration-authorities`) {
        await route.fulfill({
          json: {
            items: url.searchParams.has("cursor")
              ? [prior]
              : [staleDeclaration],
            next_cursor: url.searchParams.has("cursor")
              ? null
              : "declaration-opaque",
            latest: staleDeclaration,
            version: staleDeclaration.version,
          },
        });
        return true;
      }
      if (url.pathname === `${base}/configuration-proposals`) {
        await route.fulfill({
          json: {
            items: url.searchParams.has("cursor")
              ? [olderProposal]
              : [proposal],
            next_cursor: url.searchParams.has("cursor")
              ? null
              : "proposal-opaque",
          },
        });
        return true;
      }
      return false;
    },
  });
  await expect(section).toContainText("different registration revision");
  await expect(
    section.getByRole("button", {
      name: "Review fleet proposal evidence",
      exact: true,
    }),
  ).toBeDisabled();
  await section
    .getByText("Immutable fleet declaration history", { exact: true })
    .click();
  await section
    .getByRole("button", {
      name: "Load more fleet declaration revisions",
      exact: true,
    })
    .click();
  await section
    .getByRole("button", {
      name: "Load more blocked fleet configuration proposals",
      exact: true,
    })
    .click();
  expect(queries).toContain(
    `${base}/configuration-authorities?limit=10&cursor=declaration-opaque`,
  );
  expect(queries).toContain(
    `${base}/configuration-proposals?limit=10&cursor=proposal-opaque`,
  );
  await expect(section).toContainText(prior.id);
  await expect(section).toContainText(olderProposal.id);
  await expect(section).toContainText("Verified savings: unavailable");
  expect(writes).toEqual([]);
});

test("fleet source errors stay distinct from empty history and stale writes cannot appear saved", async ({
  page,
}) => {
  let unavailable = true;
  const { section, writes } = await open(page, {
    override: async (route, url) => {
      if (url.pathname !== `${base}/configuration-authorities`) return false;
      if (route.request().method() === "POST") {
        await route.fulfill({
          status: 409,
          json: {
            error: "VERSION_CONFLICT",
            message: "Declaration version changed",
          },
        });
        return true;
      }
      if (unavailable) {
        await route.fulfill({
          status: 503,
          json: {
            error: "SOURCE_UNAVAILABLE",
            message: "Fleet source unavailable",
          },
        });
        return true;
      }
      return false;
    },
  });
  await expect(section).toContainText("Fleet source unavailable");
  await expect(
    section.getByText("No fleet configuration declaration", { exact: true }),
  ).toHaveCount(0);
  unavailable = false;
  await section
    .getByRole("button", { name: "Retry fleet configuration", exact: true })
    .click();
  await section
    .getByRole("button", { name: "Revise fleet declaration", exact: true })
    .click();
  await page
    .getByLabel("Fleet declared Git branch or tag", { exact: true })
    .fill("new-branch");
  await page
    .getByLabel("I acknowledge that this declaration is unattested", {
      exact: false,
    })
    .check();
  await section
    .getByRole("button", { name: "Save fleet declaration", exact: true })
    .click();
  await expect(section).toContainText("Declaration was not saved");
  await expect(
    page.getByText("Declaration version changed Refresh the view and retry.", {
      exact: true,
    }),
  ).toBeVisible();
  await expect(section).toContainText("Declaration revision 3");
  expect(writes).toHaveLength(1);
  expect(writes[0].version).toBe('"3"');
});
