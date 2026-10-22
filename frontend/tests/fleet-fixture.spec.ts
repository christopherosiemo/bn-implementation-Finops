import { expect, test, type Page } from "@playwright/test";
import type { components } from "../src/api.generated";
import type { Dashboard, FleetHistoryRegistration } from "../src/types";

// Presentation-only route fixtures. They cannot install a producer, create
// genuine Git objects or establish native/runtime/customer evidence authority.
type Profile = components["schemas"]["FleetFixtureProfile"];
type Record = components["schemas"]["FleetFixtureProposalRecord"];
type Prepared = components["schemas"]["FleetFixturePreparedProgram"];
const hash = "a".repeat(64),
  stamp = "2026-10-19T12:00:00Z";
const target = (name: string) => ({
  tenant_id: "presentation",
  workload_id: "workload-api",
  provider: "AWS" as const,
  account_id: "111122223333",
  region: "eu-west-1" as const,
  fleet_id: name,
  asg_arn: `arn:aws:autoscaling:eu-west-1:111122223333:autoScalingGroup:12345678-1234-1234-1234-123456789abc:autoScalingGroupName/${name}`,
});
const binding = (name: string) => ({
  target: target(name),
  registration: { id: `registration-${name}`, version: 1, sha256: hash },
  declaration: { id: `declaration-${name}`, version: 1, sha256: hash },
  scope: { id: `scope-${name}`, sha256: hash },
  source_id: "source-native",
  source_registration_version: 1,
  source_config_sha256: hash,
});
const profile: Profile = {
  schema_version: "1",
  id: "installed-presentation",
  generation: "presentation-generation",
  name: "Presentation-only installed fixture",
  realm_kind: "ISOLATED_FIXTURE",
  model_kind: "TERRAFORM_BUILTIN_FIXTURE",
  model_version: "5.1",
  model_sha256: hash,
  runtime_available: false,
  model: {
    old_template: {
      id: "lt-12345678",
      version: 1,
      instance_type: "fixture-old",
      sha256: hash,
    },
    candidate_template: {
      id: "lt-87654321",
      version: 1,
      instance_type: "fixture-candidate",
      sha256: hash,
    },
    budget: {
      cost_basis: "FIXTURE_MODEL_COST",
      currency: "USD",
      baseline_count: 20,
      max_in_flight: 2,
      max_unavailable: 0,
      max_blast_radius_ppm: 100000,
      max_surge_count: 20,
      old_hourly_cost: "0.5",
      candidate_hourly_cost: "0.3",
      maximum_model_cost: "100",
      maximum_duration_seconds: 21600,
    },
    policy: {
      id: "fixture-policy",
      version: 1,
      sha256: hash,
      approver_role: "fleet_approver",
    },
  },
  installation: {
    template_id: "builtin-group-fixture-v1",
    toolchain_image_sha256: hash,
    terraform_version: "1.16.0",
    receipt_id: "presentation-installation",
    source_sha256: hash,
  },
};
const record: Record = {
  id: "fixture-selection",
  version: 1,
  status: "WAITING_FOR_PROGRAM",
  proposal: {
    schema_version: "1",
    id: "fixture-selection",
    purpose: "ISOLATED_GROUP_FIXTURE_PROPOSAL",
    creator_id: "creator",
    workload_id: "workload-api",
    profile,
    realm: {
      kind: "ISOLATED_FIXTURE",
      fixture_id: profile.id,
      generation: profile.generation,
      model_sha256: hash,
    },
    binding: { old: binding("old"), candidate: binding("candidate") },
    old_configuration_proposal: {
      id: "configuration-old",
      sha256: hash,
      scope_reference_root: hash,
      customer_status: "BLOCKED",
      customer_reasons: ["HISTORICAL_MEMBERSHIP_INTERVAL_OWNERSHIP_UNPROVEN"],
    },
    candidate_configuration_proposal: {
      id: "configuration-candidate",
      sha256: hash,
      scope_reference_root: hash,
      customer_status: "BLOCKED",
      customer_reasons: ["WORK_PRESERVATION_UNPROVEN"],
    },
    customer_execution_authorized: false,
    estimated_saving: null,
    verified_saving: null,
  },
  hash,
  created_at: stamp,
  writer_role: "finops_api",
  prepared_program: null,
  approval: null,
  readiness: {
    status: "BLOCKED",
    runtime_available: false,
    customer_execution_authorized: false,
    reason_codes: [
      "PROGRAM_NOT_PREPARED",
      "FLEET_FIXTURE_RUNTIME_NOT_CONNECTED",
    ],
    estimated_saving: null,
    verified_saving: null,
  },
};
const registrations: FleetHistoryRegistration[] = ["old", "candidate"].map(
  (name) => ({
    id: `registration-${name}`,
    version: 1,
    hash,
    writer_role: "finops_api",
    created_at: stamp,
    registration: {
      schema_version: "1",
      id: `registration-${name}`,
      version: 1,
      fleet_id: name,
      binding: {
        tenant_id: "presentation",
        workload_id: "workload-api",
        provider: "AWS",
        account_id: "111122223333",
        region: "eu-west-1",
      },
      asg_arn: target(name).asg_arn,
      source_id: "source-native",
      source_system: "AWS_SOURCE_CONNECTION",
      source_registration_version: 1,
      source_config_hash: hash,
      cadence_seconds: 60,
      max_gap_seconds: 120,
    },
  }),
);
const dashboard: Dashboard = {
  org: {
    id: "presentation",
    version: 1,
    name: "Explicit fixture presentation",
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
      id: "workload-api",
      version: 1,
      name: "API workload",
      owner: "creator",
      environment: "NON_PRODUCTION",
      timezone: "UTC",
      incident: "UNKNOWN",
      deployment: "UNKNOWN",
      job: "UNKNOWN",
      signals_at: stamp,
    },
  ],
};
function prepared(): Prepared {
  const revision = {
      commit: "b".repeat(40),
      tree: "c".repeat(40),
      configuration_sha256: hash,
      desired_sha256: hash,
    },
    state = {
      binding_sha256: hash,
      realm_sha256: hash,
      old_count: 20,
      candidate_count: 0,
      candidate_traffic_percent: 0,
    };
  const artifact = {
    kind: "TERRAFORM_BUILTIN_FIXTURE" as const,
    provider_source: "terraform.io/builtin/terraform" as const,
    repository_id: record.id,
    git_commit: revision.commit,
    git_tree: revision.tree,
    configuration_sha256: hash,
    toolchain_image_sha256: hash,
    terraform_version: "1.16.0",
    pipeline_id: "fixture-pipeline",
    workspace: "default",
    state_lineage: "presentation-lineage",
    initial_state_serial: 1,
    mapping: {
      old_declared_asg: "aws_autoscaling_group.old",
      candidate_declared_asg: "aws_autoscaling_group.candidate",
      declared_listener_rule: "aws_lb_listener_rule.app",
      old_model: "terraform_data.old",
      candidate_model: "terraform_data.candidate",
      traffic_model: "terraform_data.traffic",
    },
  };
  return {
    id: "prepared-one",
    proposal_id: record.id,
    program_hash: hash,
    manifest_hash: hash,
    journal_review_hash: hash,
    proof_hash: hash,
    producer_role: "finops_group_fixture",
    created_at: stamp,
    program: {
      schema_version: "5.1",
      kind: "STATELESS_GROUP_RIGHTSIZING",
      id: "program-one",
      binding: record.proposal.binding,
      realm: record.proposal.realm,
      creator_id: "creator",
      environment: "NON_PRODUCTION",
      policy: profile.model.policy,
      artifact_context: artifact,
      manifest: {
        schema_version: "1",
        ref: "refs/heads/controlled-fixture",
        base: revision,
        entries: [
          {
            sequence: 1,
            stage_id: "PREPARE_CANDIDATE",
            stage_sha256: hash,
            predecessor_commit: revision.commit,
            revision,
            before: state,
            after: state,
            minimum_observation_seconds: 0,
          },
        ],
      },
      manifest_sha256: hash,
      old_template: profile.model.old_template,
      candidate_template: profile.model.candidate_template,
      budget: profile.model.budget,
      stages: [],
      evidence: [],
      created_at: stamp,
      expires_at: "2026-10-19T20:00:00Z",
      nonce: "presentation-nonce",
    },
    journal_review: {
      schema_version: "1",
      policy: profile.model.policy,
      ref: "refs/heads/controlled-fixture",
      pipeline_id: "fixture-pipeline",
      pipeline_key_sha256: "d".repeat(64),
      ledger_key_sha256: "e".repeat(64),
      base: {
        revision,
        state_lineage: artifact.state_lineage,
        state_serial: 1,
        state_sha256: hash,
        model: state,
      },
      max_effects: 32,
      max_records: 512,
      expires_at: "2026-10-19T20:00:00Z",
    },
  };
}

async function open(
  page: Page,
  options: {
    uninstalled?: boolean;
    existing?: Record;
    conflict?: boolean;
    prepared?: Prepared;
    paginate?: boolean;
  } = {},
) {
  const writes: {
      path: string;
      body: unknown;
      version?: string;
      key?: string;
    }[] = [],
    cursors: string[] = [];
  let selected = options.existing ? structuredClone(options.existing) : null;
  await page.route("**/.well-known/openid-configuration", (route) =>
    route.fulfill({
      json: {
        authorization_endpoint: `${new URL(page.url()).origin}/__fixture/authorize`,
        token_endpoint: `${new URL(page.url()).origin}/__fixture/token`,
      },
    }),
  );
  await page.route("**/__fixture/authorize?**", (route) => {
    const args = new URL(route.request().url()).searchParams,
      url = new URL(args.get("redirect_uri")!);
    url.searchParams.set("code", "presentation");
    url.searchParams.set("state", args.get("state")!);
    return route.fulfill({
      status: 302,
      headers: { location: url.toString() },
    });
  });
  await page.route("**/__fixture/token", (route) =>
    route.fulfill({
      json: { access_token: "presentation-only", expires_in: 3600 },
    }),
  );
  await page.route("**/v1/**", async (route) => {
    const request = route.request(),
      url = new URL(request.url()),
      path = url.pathname;
    const reply = (json: unknown, status = 200) =>
      route.fulfill({ json, status });
    if (request.method() === "POST")
      writes.push({
        path,
        body: request.postDataJSON(),
        version: request.headers()["if-match"],
        key: request.headers()["idempotency-key"],
      });
    if (path === "/v1/dashboard") return reply(dashboard);
    if (path === "/v1/fleet-fixture-profiles") {
      if (url.searchParams.has("cursor")) {
        cursors.push(url.searchParams.get("cursor")!);
        return reply({ items: [profile], next_cursor: null });
      }
      return reply({
        items: options.uninstalled
          ? []
          : options.paginate
            ? [
                {
                  ...profile,
                  id: "installed-earlier-page",
                  generation: "earlier-generation",
                },
              ]
            : [profile],
        next_cursor: options.paginate ? "opaque-profile-page-2" : null,
      });
    }
    if (path === "/v1/fleet-fixture-proposals") {
      if (request.method() === "POST") {
        if (options.conflict)
          return reply(
            {
              error: "FLEET_FIXTURE_CURRENT_BINDING_REQUIRED",
              message:
                "The selected declaration or source binding changed. Refresh before continuing.",
            },
            422,
          );
        selected = structuredClone(record);
        return reply(selected, 201);
      }
      return reply({ items: selected ? [selected] : [], next_cursor: null });
    }
    if (path === `/v1/fleet-fixture-proposals/${record.id}`)
      return reply(selected ?? record);
    if (path.endsWith("/prepared-program"))
      return reply(options.prepared ?? prepared());
    if (path.endsWith("/approvals"))
      return reply(
        {
          error: "FLEET_FIXTURE_INDEPENDENT_APPROVER_REQUIRED",
          message:
            "The approver must be a different authenticated person from the proposal creator.",
        },
        403,
      );
    if (path === "/v1/fleet-history-registrations") {
      if (options.paginate && !url.searchParams.has("cursor"))
        return reply({
          items: [registrations[0]],
          next_cursor: "opaque-page-2",
        });
      if (url.searchParams.has("cursor"))
        cursors.push(url.searchParams.get("cursor")!);
      return reply({
        items: options.paginate ? [registrations[1]] : registrations,
        next_cursor: null,
      });
    }
    if (path.endsWith("/configuration-proposals")) {
      const name = path.includes("registration-candidate")
        ? "candidate"
        : "old";
      return reply({
        items: [
          {
            id: `configuration-${name}`,
            registration_id: `registration-${name}`,
            registration_version: 1,
            asg_arn: target(name).asg_arn,
            status: "BLOCKED",
            membership_status: "INTERVAL_OWNERSHIP_UNPROVEN",
            as_of: stamp,
          },
        ],
        next_cursor: null,
      });
    }
    if (path.endsWith("/safety-profiles"))
      return reply({ items: [], latest: null, version: 0, next_cursor: null });
    return reply(
      {
        error: "PRESENTATION_ROUTE_UNAVAILABLE",
        message: "No presentation evidence for this route.",
      },
      404,
    );
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
  return { writes, cursors };
}
async function selectPair(page: Page, paginate = false) {
  await page
    .getByRole("button", {
      name: "Propose isolated group fixture",
      exact: true,
    })
    .click();
  const modal = page.getByRole("dialog", {
    name: "Propose an isolated group fixture",
    exact: true,
  });
  if (paginate) {
    const generation = modal.getByRole("combobox", {
      name: "Installed fixture generation",
      exact: true,
    });
    await expect(generation).toBeVisible();
    await expect(
      generation.locator(`option[value="${profile.id}"]`),
    ).toHaveCount(0);
    await modal
      .getByRole("button", {
        name: "Load more installed fixture generations",
        exact: true,
      })
      .click();
    await expect(
      generation.locator(`option[value="${profile.id}"]`),
    ).toHaveCount(1);
  }
  await modal
    .getByRole("combobox", {
      name: "Installed fixture generation",
      exact: true,
    })
    .selectOption(profile.id);
  await modal
    .getByRole("button", { name: "Use original group old", exact: true })
    .click();
  await modal
    .getByRole("button", {
      name: "Select original proposal configuration-old",
      exact: true,
    })
    .click();
  if (paginate)
    await modal
      .getByRole("button", {
        name: "Load more candidate group choices",
        exact: true,
      })
      .click();
  await modal
    .getByRole("button", { name: "Use candidate group candidate", exact: true })
    .click();
  await modal
    .getByRole("button", {
      name: "Select candidate proposal configuration-candidate",
      exact: true,
    })
    .click();
  return modal;
}

test("uninstalled producer cannot become a fake ready fixture or expose authority upload controls", async ({
  page,
}) => {
  const { writes } = await open(page, { uninstalled: true });
  await page
    .getByRole("button", {
      name: "Propose isolated group fixture",
      exact: true,
    })
    .click();
  const modal = page.getByRole("dialog", {
    name: "Propose an isolated group fixture",
    exact: true,
  });
  await expect(
    modal.getByText("No installed fixture generations", { exact: true }),
  ).toBeVisible();
  await expect(
    modal.getByRole("button", {
      name: "Record isolated fixture proposal",
      exact: true,
    }),
  ).toHaveCount(0);
  await expect(modal.locator('input[type="file"]')).toHaveCount(0);
  expect(writes).toEqual([]);
});
test("cursor-paged real group selectors post IDs only with initial CAS and preserve blocked history", async ({
  page,
}) => {
  const { writes, cursors } = await open(page, { paginate: true });
  const modal = await selectPair(page, true);
  await modal
    .getByRole("button", {
      name: "Record isolated fixture proposal",
      exact: true,
    })
    .click();
  const details = page.getByRole("dialog", {
    name: "Isolated group fixture proposal",
    exact: true,
  });
  await expect(
    details.getByText("Waiting for private program preparation", {
      exact: true,
    }),
  ).toBeVisible();
  await expect(
    details.getByRole("button", {
      name: "Approve exact fixture program",
      exact: true,
    }),
  ).toHaveCount(0);
  await expect(details).toContainText("Customer execution remains disabled");
  await details
    .getByText("Preserved customer evidence blockers", { exact: true })
    .click();
  await expect(details).toContainText(
    "Historical membership interval ownership unproven",
  );
  expect(cursors).toContain("opaque-page-2");
  expect(cursors).toContain("opaque-profile-page-2");
  expect(writes).toHaveLength(1);
  expect(writes[0]).toMatchObject({
    path: "/v1/fleet-fixture-proposals",
    body: {
      old_configuration_proposal_id: "configuration-old",
      candidate_configuration_proposal_id: "configuration-candidate",
      fixture_profile_id: profile.id,
    },
    version: '"0"',
  });
  expect(writes[0].key?.length).toBeGreaterThan(7);
});
test("stale registered source or declaration selection is an explicit error and creates no apparent program", async ({
  page,
}) => {
  const { writes } = await open(page, { conflict: true });
  const modal = await selectPair(page);
  await modal
    .getByRole("button", {
      name: "Record isolated fixture proposal",
      exact: true,
    })
    .click();
  await expect(
    page.getByText(
      "The selected declaration or source binding changed. Refresh before continuing.",
      { exact: true },
    ),
  ).toBeVisible();
  await expect(modal).toBeVisible();
  expect(writes).toHaveLength(1);
  await expect(
    page.getByRole("button", {
      name: "Approve exact fixture program",
      exact: true,
    }),
  ).toHaveCount(0);
});
test("exact program review exposes manifest and key scope while independent approval uses empty body and current version", async ({
  page,
}) => {
  const row = structuredClone(record);
  row.version = 2;
  row.status = "AWAITING_APPROVAL";
  row.prepared_program = {
    id: "prepared-one",
    program_hash: hash,
    manifest_hash: hash,
    journal_review_hash: hash,
    proof_hash: hash,
    created_at: stamp,
    producer_role: "finops_group_fixture",
    expires_at: "2026-10-19T20:00:00Z",
  };
  const { writes } = await open(page, { existing: row, prepared: prepared() });
  await page
    .getByRole("button", {
      name: "Inspect fixture proposal fixture-selection",
      exact: true,
    })
    .click();
  const modal = page.getByRole("dialog", {
    name: "Isolated group fixture proposal",
    exact: true,
  });
  await expect(
    modal.getByRole("region", {
      name: "Complete prepared fixture Git manifest",
    }),
  ).toBeVisible();
  await expect(modal).toContainText("Pipeline key pin");
  await expect(modal).toContainText("Ledger key pin");
  await expect(modal).toContainText(/future exact journal authorization/i);
  await expect(
    modal.getByRole("button", {
      name: "Approve exact fixture program",
      exact: true,
    }),
  ).toBeDisabled();
  await modal.getByRole("checkbox").check();
  await modal
    .getByRole("button", { name: "Approve exact fixture program", exact: true })
    .click();
  await expect(
    page.getByText(
      "The approver must be a different authenticated person from the proposal creator.",
      { exact: true },
    ),
  ).toBeVisible();
  expect(writes).toHaveLength(1);
  expect(writes[0]).toMatchObject({
    path: `/v1/fleet-fixture-proposals/${record.id}/approvals`,
    version: '"2"',
    body: {},
  });
  await expect(modal).toContainText(
    "Private runtime gates govern commands and restoration. Inspect persisted execution and recovery duties below when available.",
  );
});
